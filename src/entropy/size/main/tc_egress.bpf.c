/***** This program might blow the recv window size of the remote server as the TCP state doesn't know about the tail padding this program does. *****/
/***** This program currently ignores special packets from padding like pure-ACKs, 3-way handshake packets, etc. *****/
/***** This program doesn't skip GSO/TSO packets. It expects you to disable them prior. *****/
/***** This program doesn't skip GRO/LRO packets (but some devices disable it automatically when XDP is set). It expects you to disable them prior. *****/
/**** If hardware checksum offload is enabled, might need to create a new path in code ****/
/*****
 *This program computes checksum manually in software. To prevent hardware checksum computation again, it is advisable to turn TX/RX checksum off.
 *It is also possible to skip hardware checksum by passing certain flags, but it is not generally guaranteed.
 *Alternatively, it is possible to send *CHECKSUM_MANGLED* flag to let the hardware compute the checksum for your modified packet without doing it manually in this program.
 *****/
/***** If your networking environment supports VLAN-tagged IPv4 frames (802.1Q/AD or IEEE 802.1Q), then it should be disabled for proper functioning as this program assumes eth->h_proto == 0x0800 without skipping any VLAN headers when parsing. *****/
/***** This program expects you to hardcode the Device MTU in its DEVICE_MTU macro prior to running as PMTU is very salient for this program. *****/
/***** This program doesn't fix SEQ Nums or ACKs of *RETRANSMIT* packets but pads it as usual *****/
/**** PAD_BYTES should be max 1460 bytes on pure ACK packets with zero payload ****/

/***** REMOVE bpf_printk()s IN PROD *****/

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2  /* IPv4 code instead of importing */
#define ETH_P_IP 0x0800  /* IPv4 packet */

#define TC_ACT_OK 0  /* Terminate the packet processing pipeline and allows the packet to proceed */
#define TC_ACT_SHOT 2  /* Terminate the packet processing pipeline and drops the packet */

#define DEVICE_MTU 1500  // I always need to verify the device's MTU prior for this program to work perfectly
#define MAX_PAD (DEVICE_MTU)

#define RAND_BUF_SZ 2048  // Only for verifier; actual sz = 1500

#define PAD_MAGIC16 0xA55A

// Universal Key //
struct flow {
    // Network-order
    __be32 saddr, daddr;
    __be16 sport, dport;
};

/* LRU HashMap to fix ingress ACKs */
struct ack_ingress_info {
    // Can use __be32 ack directly without wrapping inside a struct, but might add more fields in future
    __be32 ack_ingress;  // To fix ingress ACK to original
};
struct {  // To revert Ingress ACK to original
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct ack_ingress_info);
} ack_ingress_fix SEC(".maps");

/* LRU HashMap for modifying ACKs on current packet */
struct ack_egress_info {
    __be32 ack_egress;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct ack_egress_info);
} ack_egress_fix SEC(".maps");

/* LRU HashMap for modifying SEQ_NUM on current packet */
struct seq_egress_info {
    __be32 seq_egress;  // translated_seq
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct seq_egress_info);
} seq_egress_fix SEC(".maps");

/* LRU HashMap for TC-Egress to maintain seq_nums for retransmits */
// Key //
// struct retransmit_key {
//     // Network-order
//     __be32 saddr, daddr;
//     __be16 sport, dport;
//     __be32 orig_seq;
// };
// // Value //
// struct retransmit_info {
//     __be32 translated_seq;  // network-order
// };
// // Map Setup //
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, 8192);
//     __type(key, struct retransmit_key);
//     __type(value, struct retransmit_info);
// } retransmit_map SEC(".maps");

/* BPF_MAP_TYPE_ARRAY for Random bytes padding */
// Value //
struct rand_byte_buff {
    __u8 bytes[RAND_BUF_SZ];
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rand_byte_buff);
    __uint(max_entries, 1);
} rand_byte_map SEC(".maps");

/* Tail for all *modified* packets */
struct pad_magic_tail {
    __be16 magic;
    __be16 pad_len;
} __attribute__((packed));

/* BPF_MAP_TYPE_PERCPU_ARRAY for storing pad_bytes */
struct pad_state {
    __u32 pad_bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pad_state);
} pad_state_map SEC(".maps");

// Function for checking pointer arithmetic for verifier
static __always_inline bool verifier_checker(void *data, void *data_end, __u32 need) {
    return data + need <= data_end;
}

// Helper function to check if the packet is TCP and IPv4  ## METHOD 1 - Easy
static __always_inline bool is_tcp_ipv4(void *data, void *data_end) {

    const __u32 need = sizeof(struct ethhdr) + offsetof(struct iphdr, protocol) + 1;
    if (data + need > data_end) {
        return false;
    }
    struct ethhdr *eth = data;
    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    // Check if the protocol is TCP
    if ((ip->protocol) != IPPROTO_TCP) {
        return false;
    }
    // bpf_printk("The packet is TCP-IPv4!\n");
    return true;
}

/* To check if a packet is handshake or just ACK or other */
static __always_inline bool is_HS_ACK(struct tcphdr *tcp, __u32 payload_len) {
    /* 3-way handshake */
    if (tcp->syn && !tcp->ack && !tcp->rst)  return true;  // SYN
    if (tcp->syn && tcp->ack && !tcp->rst)   return true;  // SYN-ACK (On Client-Egress, I don't need this check)

    /* Only ACKs */
    // if (!tcp->syn && tcp->ack && payload_len == 0)  return true;  // Any simple ACK (includes handshake ACK too)
    /* Only Resets */
    if (tcp->rst)   return true;  // Reset flag found; don't touch
    /* Only FIN */
    if (tcp->fin)   return true;  // FIN/implicit ACK; don't touch
    // Maybe I can ignore URG packets too
    return false;
}

static __always_inline __s64 csum_diff_u8_buf(const __u8 *buf, __u32 len, __u32 seed) {
    __u32 n4 = len & ~3u;   // multiple of 4
    __u32 rem = len & 3u;   // 0..3
    __s64 diff = 0;
    if (n4) {
        diff = bpf_csum_diff(0, 0, (__be32 *)buf, n4, seed);
        if (diff < 0)
            return diff;
        seed = (__u32)diff;
    }
    if (rem) {
        __u32 last = 0; // zero-padded
        if (rem >= 1) ((__u8 *)&last)[0] = buf[n4 + 0];
        if (rem >= 2) ((__u8 *)&last)[1] = buf[n4 + 1];
        if (rem >= 3) ((__u8 *)&last)[2] = buf[n4 + 2];

        diff = bpf_csum_diff(0, 0, (__be32 *)&last, 4, seed);
        if (diff < 0)
            return diff;
    }
    return diff;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) {

    /*** This TC-Egress program is for padding the packets' tail to the full size of the PMTU. ***/

    /* I disabled TSO/GSO on all network profiles */
    // Ignore GSO/TSO Packets still; *SHOULDN'T* see them in trace files
    if (ctx->gso_segs > 1 || ctx->gso_size) {
        // bpf_printk("Packet is TSO/GSO; Ignoring.\n");
        return TC_ACT_OK;
    }

    // I need this function to unclone the linear part of skb for writing
    if (bpf_skb_pull_data(ctx, 0)) {  // Returns 0 on success
        bpf_printk("Failed to pull data at bpf_skb_pull_data.\n");
        return TC_ACT_OK;
    }

    void *data = (void *) (__u64) ctx->data;  // (unsigned long) == (__u64)
    void *data_end = (void *) (__u64) ctx->data_end;

    // Grab ETH Header
    struct ethhdr *eth = data;
    if (!verifier_checker(eth + 1, data_end, 0)) {
        return TC_ACT_SHOT;
    }
    // Grab IP Header
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if (!verifier_checker(ip + 1, data_end, 0)) {
        return TC_ACT_SHOT;
    }
    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
        return TC_ACT_OK;
    }
    if (ip->ihl < 5) {  // Malformed IP header
        return TC_ACT_SHOT;
    }
    // Calculate IP Header length
    int ip_hl = ip->ihl * 4;
    if (!verifier_checker(ip, data_end, ip_hl)) {
        return TC_ACT_SHOT;
    }
    // Grab TCP Header
    struct tcphdr *tcp = (struct tcphdr *) ((void *) ip + ip_hl);
    if (!verifier_checker(tcp + 1, data_end, 0)) {
        return TC_ACT_SHOT;
    }
    if (tcp->doff < 5) {  // Malformed TCP header
        return TC_ACT_SHOT;
    }
    // Calculate TCP Header length
    int tcp_hl = tcp->doff * 4;
    if (!verifier_checker(tcp, data_end, tcp_hl)) {
        return TC_ACT_SHOT;
    }
    // Don't touch SSH traffic for remote VM
    if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22)) {
        return TC_ACT_OK;
    }
    // Windows RDP
    if (tcp->dest== bpf_htons(3389) || tcp->source == bpf_htons(3389))
        return TC_ACT_OK;

    __u16 ip_len = bpf_ntohs(ip->tot_len);  // IP total length field
    if (ip_len < ip_hl + tcp_hl) {
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 tcp_payload_len = ip_len - ip_hl - tcp_hl;  // all host-byte order

    /* Ignore special packets */
    if (is_HS_ACK(tcp, tcp_payload_len)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }
    // bpf_printk("Initial packet length is: %u\n", init_pkt_len);  // whole packet including L2 (Eth)

    /* Start of Padding code */
    /* Create ACK key to revert ingress ACK to original */
    struct flow ack_ingress_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };
    /* Create SEQ key to translate egress SEQ to *modified* on current packet */
    struct flow seq_egress_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };
    /* Create ACK key to translate egress ACK to *modified* on current packet */
    struct flow ack_egress_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    // Store highest sequence of data that got sent
    __u32 highest_sent_data_len = 0;
    struct ack_ingress_info *is_retransmit = bpf_map_lookup_elem(&ack_ingress_fix, &ack_ingress_key);
    if (is_retransmit) {
        highest_sent_data_len = is_retransmit->ack_ingress;
    }

    // Always add packet SEQ + data_sent to map to serve as ACK on Ingress
    struct ack_ingress_info ack_ingress_val = {
        .ack_ingress = tcp->seq + bpf_htonl(tcp_payload_len),  // network-byte order
    };
    bpf_map_update_elem(&ack_ingress_fix, &ack_ingress_key, &ack_ingress_val, BPF_ANY);

    __be32 curr_seq_num = tcp->seq;  // actual seq_num of current pkt (not updated)
    __be32 translated_seq_num = tcp->seq;  // *modified* seq_num of current pkt (will be updated)

    // Grab Path MTU
    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.ifindex = ctx->ifindex;
    fib.tos = ip->tos;
    fib.l4_protocol = IPPROTO_TCP;
    fib.sport = tcp->source;
    fib.dport = tcp->dest;
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;
    fib.tot_len = bpf_htons(ip_len + (DEVICE_MTU - ip_len));  // Always push it to trigger FIB_FRAGMENTATION_NEEDED

    long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);

    __u32 p_mtu = 0;
    if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED || ret == 0) {
        // Use only when it returns successfully; don't use when it fails and *may* contain garbage value as MTU
        p_mtu = fib.mtu_result;
    }
    if (p_mtu <= 0) {
        bpf_printk("Something went wrong with FIB_MTU lookup.");
        // return TC_ACT_SHOT;
    }
    // bpf_printk("The Fib-MTU is: %u\n", fib_mtu);
    p_mtu = p_mtu ?: DEVICE_MTU;  // p_mtu is the TARGET I want to pad till.
    
    __u32 pad_bytes = 0;
    if (p_mtu && (p_mtu > ip_len)) {
        pad_bytes = (p_mtu - ip_len);  // max legally can be 1460
    } else {
        pad_bytes = 0;
    }

    if (pad_bytes > MAX_PAD)
        pad_bytes = MAX_PAD;

    __u32 k0 = 0;
    struct pad_state *pad_st = bpf_map_lookup_elem(&pad_state_map, &k0);
    if (!pad_st) return TC_ACT_SHOT;

    pad_st->pad_bytes = pad_bytes;

    // Get current packet length including L2 (Ethernet) header size
    __u32 init_pkt_len = ctx->len;
    
    if (pad_bytes >= 4) {  // Need minimum of 4 bytes available for encoding original length | I can shrink the packet and add the leftover to next packet too.
        // bpf_printk("Pad Bytes: %u. Packet length is < PMTU. Padding.\n", pad_bytes);
        if (bpf_skb_change_tail(ctx, init_pkt_len + pad_bytes, 0)) {  // NTC BPF_F_INVALIDATE_HASH flag here; I can also skip bpf_set_hash_invalid() because this is not TC-Ingress RX path
            bpf_printk("Error with changing tail to the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;  // (unsigned long) == (u64)
        data_end = (void *) (__u64) ctx->data_end;  // This should point to payload end because bpf_skb_change_tail internally linearizes the whole packet

        // Grab ETH Header
        eth = data;
        if (!verifier_checker(eth + 1, data_end, 0)) {
            return TC_ACT_SHOT;
        }
        // Grab IP Header
        ip = (struct iphdr *) (eth + 1);
        if (!verifier_checker(ip + 1, data_end, 0)) {
            return TC_ACT_SHOT;
        }
        // Calculate IP Header length
        ip_hl = ip->ihl * 4;
        if (!verifier_checker(ip, data_end, ip_hl)) {
            return TC_ACT_SHOT;
        }
        // Grab TCP Header
        tcp = (struct tcphdr *) ((void *) ip + ip_hl);
        if (!verifier_checker(tcp + 1, data_end, 0)) {
            return TC_ACT_SHOT;
        }
        // Calculate TCP Header length
        tcp_hl = tcp->doff * 4;
        if (!verifier_checker(tcp, data_end, tcp_hl)) {
            return TC_ACT_SHOT;
        }
        // u8 *tail = (u8 *)data + init_pkt_len;
        // if (!verifier_checker(tail, data_end, pad_bytes))
        //     return TC_ACT_SHOT;
        
        __u16 new_ip_len = ip_len + pad_bytes;
        if (new_ip_len > 65535) {  // Something went wrong
            return TC_ACT_SHOT;
        }

        /* Update all fields first before actual writing */
        // IPv4 tot_len fix
        ip->tot_len = bpf_htons(new_ip_len);

        __u32 tcp_payload_len_modified = new_ip_len - ip_hl - tcp_hl;  // all host-byte order

        // TCP SEQ FIX 
        struct seq_egress_info *seq_egress_info = bpf_map_lookup_elem(&seq_egress_fix, &seq_egress_key);
        if (seq_egress_info) {  // seq_num exists in the map already; update it and fix current pkt seq_num
            // Check if the current packet is retransmit
            if (highest_sent_data_len && !(bpf_ntohl(tcp->seq) < highest_sent_data_len)) {  // packet is *NOT* retransmit
                tcp->seq = seq_egress_info->seq_egress;  // No htonl as its already __be32
                translated_seq_num = seq_egress_info->seq_egress;
                struct seq_egress_info nxt_seq_val = {
                    .seq_egress = seq_egress_info->seq_egress + bpf_htonl(tcp_payload_len_modified),
                };
                bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_EXIST);  // only update
            }
        } else {  // First packet entry that needs padding
            struct seq_egress_info nxt_seq_val = {
                .seq_egress = tcp->seq + bpf_htonl(tcp_payload_len_modified),  // network-byte order
            };
            bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_NOEXIST);  // BPF_NOEXIST secondary defense
        }

        // TCP ACK FIX
        // Check if the ACK is what I expect with ==, if it is < what I expect, it could mean data is lost and next pkt would be retransmit


        /* Write random payload to packet but leave last 4 bytes */
        __s64 tot_diff = 0;

        __u32 pb = pad_st->pad_bytes;
        if (pb > MAX_PAD) 
            pb = MAX_PAD;

        if (pb > 4) {
            pb = pb - 4;  // leave last 4 bytes for original length
            __u32 key = 0;
            struct rand_byte_buff *rbb = bpf_map_lookup_elem(&rand_byte_map, &key);
            if (!rbb) 
                return TC_ACT_SHOT;
            // // Random offset of bytes for randomizing
            // __u32 space = MAX_PAD - max_load;
            // __u32 rand_off = 0;
            // if (space)
            //     rand_off = bpf_get_prandom_u32() % (space);
            // if (rand_off > MAX_PAD - max_load)
            //     rand_off = 0;
            if (bpf_skb_store_bytes(ctx, init_pkt_len, rbb->bytes, pb, 0)) {
                return TC_ACT_SHOT;
            }
            tot_diff = csum_diff_u8_buf(rbb->bytes, pb, 0);  // Random payload csum diff
            if (tot_diff < 0) {  // Returns negative code in failure
                return TC_ACT_SHOT;
            }
        }

        /* Encode original length to the last 4 bytes of the payload */
        struct pad_magic_tail mtail = {
            .magic = bpf_htons(PAD_MAGIC16),
            .pad_len = bpf_htons((__u16)pad_bytes)
        };
        __s64 d2 = bpf_csum_diff(0, 0, (__be32 *)&mtail, sizeof(mtail), (__u32)tot_diff);  // sizeof(mtail) = 4
        if (d2 < 0) 
            return TC_ACT_SHOT;
        tot_diff = d2;

        // Get *modified* packet length
        __u32 mdf_pkt_len = ctx->len;

        if (mdf_pkt_len < (int)sizeof(mtail))
            return TC_ACT_SHOT;
        // Only need to copy pad_bytes which I can use to undo every change I made
        if (bpf_skb_store_bytes(ctx, (mdf_pkt_len - sizeof(mtail)), &mtail, sizeof(mtail), 0)) {
            return TC_ACT_SHOT;
        }

        // bpf_printk("Modified packet length is: %u\n", mdf_pkt_len);

        /* If hardware checksum offload is enabled */
        // Different code here  // NTC THIS PATH TOO AS IT COULD BE FASTER

        /* If hardware checksum offload is disabled */
        // L3-IP checksum replace
        if (bpf_l3_csum_replace(ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), bpf_htons(ip_len), bpf_htons(new_ip_len), sizeof(__u16))) {
            // Failed because bpf_l3_csum_replace returns 0 if success
            bpf_printk("Something went wrong with IP l3_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP PAYLOAD checksum replace
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), 0, (__u64)tot_diff, 0)) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with PAYLOAD l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP SEQ checksum replace
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), curr_seq_num, translated_seq_num, 4)) {  // all network-byte order
            bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP PSEUDO-header (Pseudo-IP) checksum replace
        __u16 old_tcp_len = ip_len - ip_hl;
        __u16 new_tcp_len = new_ip_len - ip_hl;
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), bpf_htons(old_tcp_len), bpf_htons(new_tcp_len), BPF_F_PSEUDO_HDR | 2)) {  // Change specifically for the Pseudo-header of TCP
            bpf_printk("Something went wrong with PSEUDO l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }

    } else {
        /* Might need to see what to do here for the 1-3 last bytes which is not big enough for padding */
        // bpf_printk("Packet length is >= PMTU. Don't Pad.\n");

        // TCP SEQ FIX 
        // Check if the packet is the first packet of this flow
        struct seq_egress_info *seq_egress_info = bpf_map_lookup_elem(&seq_egress_fix, &seq_egress_key);
        if (seq_egress_info) {  // seq_num exists in the map already; not the first ever packet of this flow
            /* No need to check for retransmit because I can't change anything else */
            tcp->seq = seq_egress_info->seq_egress;
            translated_seq_num = seq_egress_info->seq_egress;
            struct seq_egress_info nxt_seq_val = {
                .seq_egress = seq_egress_info->seq_egress + bpf_htonl(tcp_payload_len),
            };
            bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_EXIST);
            // L4-TCP SEQ checksum replace
            if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), curr_seq_num, translated_seq_num, 4)) {  // all network-byte order
                bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
                return TC_ACT_SHOT;
            }
        } // else: first ever packet of this flow that doesn't have enough space to pad
        
        // TCP ACK FIX 

    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";