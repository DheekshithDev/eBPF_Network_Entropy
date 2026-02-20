/**** The eBPF program to undo all the changes made by client before sending the packet to the server ****/
/**** Should disable TSO/GSO, LRO/GRO on all interfaces just to be safe even when strictly forwarding packets ****/
/**** PAD_BYTES should be max 1460 bytes on pure ACK packets with zero payload ****/

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2  /* IPv4 code instead of importing */
#define ETH_P_IP 0x0800  /* IPv4 packet */

#define TC_ACT_OK 0  /* Terminate the packet processing pipeline and allows the packet to proceed */
#define TC_ACT_SHOT 2  /* Terminate the packet processing pipeline and drops the packet */

// Wireguard MTU is 1420
#define DEVICE_MTU 1500
#define MAX_PAD (DEVICE_MTU)

#define CLIENT_IP 0x0A000002  // "10.0.0.2"

#define RAND_BUF_SZ 2048  // Only for verifier; actual sz = 1500

#define PAD_MAGIC16 0xA55A

// Universal Key //
struct flow {
    // Network-order
    __be32 saddr, daddr;
    __be16 sport, dport;
};

/* LRU HashMap to modify egress ACKs */
struct ack_egress_info {
    __be32 ack_egress;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct ack_egress_info);
} ack_egress_fix SEC(".maps");

/* LRU HashMap for TC-Ingress to fix seq_num of current packet to original */
struct seq_ingress_info {
    __be32 seq_ingress;  // orig_seq
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct seq_ingress_info);
} seq_ingress_fix SEC(".maps");

/* HAD to use this BPF_MAP_TYPE_PERCPU_ARRAY for csum recomputation */
// Value //
struct rand_byte_buff_holder {
    __u8 bytes[RAND_BUF_SZ];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // PERCPU because of concurrent packet writes
    __type(key, __u32);
    __type(value, struct rand_byte_buff_holder);
    __uint(max_entries, 1);
} rand_byte_holder_map_ig SEC(".maps");

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

/* Helper function to check if the packet is TCP and IPv4  ## METHOD 1 - Easy */
static __always_inline bool is_tcp_ipv4(void *data, void *data_end) {

    if (data + sizeof(struct ethhdr) + offsetof(struct iphdr, protocol) + 1 > data_end) {
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

static __always_inline __s64 csum_sub_u8_buf(const __u8 *buf, __u32 len, __u32 seed) {  // Subtraction
    __u32 n4 = len & ~3u;   // multiple of 4
    __u32 rem = len & 3u;   // 0..3
    __s64 diff = 0;
    if (n4) {
        diff = bpf_csum_diff((__be32 *)buf, n4, 0, 0, seed);  // Subtract
        if (diff < 0)
            return diff;
        seed = (__u32)diff;
    }
    if (rem) {
        __u32 last = 0; // zero-padded
        if (rem >= 1) ((__u8 *)&last)[0] = buf[n4 + 0];
        if (rem >= 2) ((__u8 *)&last)[1] = buf[n4 + 1];
        if (rem >= 3) ((__u8 *)&last)[2] = buf[n4 + 2];

        diff = bpf_csum_diff((__be32 *)&last, 4, 0, 0, seed);
        if (diff < 0)
            return diff;
    }
    return diff;
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {

    /* Need to disable TSO/GSO on all network profiles */
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

    void *data = (void *) (__u64) ctx->data;
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

    // Only use this program on client-proxy traffic
    if (ip->saddr != bpf_htonl(CLIENT_IP)) {
        return TC_ACT_OK;
    }

    // IP total length field
    __u16 ip_len_modified = bpf_ntohs(ip->tot_len);
    if (ip_len_modified < ip_hl + tcp_hl) {
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 tcp_payload_len_modified = ip_len_modified - ip_hl - tcp_hl;  // all host-byte order

    /* Ignore special packets */
    if (is_HS_ACK(tcp, tcp_payload_len_modified)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }

    // bpf_printk("Initial packet length (modified) is: %u\n", mdf_pkt_len);  // whole packet including L2 (Eth)

    /* Create ACK key to modify egress ACK to translated */
    struct flow ack_egress_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };
    /* Create SEQ key to fix ingress SEQ to original on current packet */
    struct flow seq_ingress_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    // Store highest *modified* sequence of data that got received
    __be32 highest_mdf_sent_data_len = 0;
    struct ack_egress_info *is_retransmit = bpf_map_lookup_elem(&ack_egress_fix, &ack_egress_key);
    if (is_retransmit) {
        highest_mdf_sent_data_len = is_retransmit->ack_egress;
    }

    // Always add *modified* packet SEQ + data_sent to map to serve as ACK on Egress
    struct ack_egress_info ack_egress_val = {
        .ack_egress = tcp->seq + bpf_htonl(tcp_payload_len_modified),  // network-byte order
    };
    bpf_map_update_elem(&ack_egress_fix, &ack_egress_key, &ack_egress_val, BPF_ANY);

    // *Modified* packet length
    __u32 mdf_pkt_len = ctx->len;

    /* Start of *UNDO* Padding code */
    // Read the last 4 bytes of the packet for original length of packet
    struct pad_magic_tail mtail;
    if (mdf_pkt_len < (int)sizeof(mtail))
        return TC_ACT_SHOT;

    if (bpf_skb_load_bytes(ctx, (mdf_pkt_len - sizeof(mtail)), &mtail, sizeof(mtail))) {
        return TC_ACT_SHOT;
    }

    __be32 translated_seq_num = tcp->seq;  // *modified* seq_num of current pkt
    __be32 orig_seq_num = tcp->seq;  // *actual* seq_num of current pkt (will be updated)
    
    if (bpf_ntohs(mtail.magic) == PAD_MAGIC16) {  // magic seq found; packet is tampered
        __u32 pad_bytes = (__u32)bpf_ntohs(mtail.pad_len);

        __u32 k0 = 0;
        struct pad_state *pad_st = bpf_map_lookup_elem(&pad_state_map, &k0);
        if (!pad_st) return TC_ACT_SHOT;
        pad_st->pad_bytes = pad_bytes;

        // Store the random padded bytes to BPF_MAP for csum calc
        __u32 i_key = 0;  // index key
        struct rand_byte_buff_holder *rbb = bpf_map_lookup_elem(&rand_byte_holder_map_ig, &i_key);
        if (!rbb) 
            return TC_ACT_SHOT;

        __u32 pb = pad_st->pad_bytes;
        if (pb > MAX_PAD)   // corrupted
            return TC_ACT_SHOT;
        if (pb > mdf_pkt_len)   // corrupted
            return TC_ACT_SHOT;
        if (pb == 0)   // corrupted
            return TC_ACT_SHOT;
        
        if (bpf_skb_load_bytes(ctx, mdf_pkt_len - pb, rbb->bytes, pb)) {
            return TC_ACT_SHOT;
        }

        // UNDO padding
        if (bpf_skb_change_tail(ctx, mdf_pkt_len - pb, BPF_F_INVALIDATE_HASH)) {  // NTC BPF_F_INVALIDATE_HASH flag here;
            bpf_printk("Error with changing tail of the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;
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

        // Original ip len
        __u16 ip_len = ip_len_modified - pb;
        if (ip_len > 65535) {  // Something went wrong
            return TC_ACT_SHOT;
        }

        /* Update all fields first before actual writing */
        // IPv4 tot_len fix to original
        ip->tot_len = bpf_htons(ip_len);

        __u32 tcp_payload_len_orig = ip_len - ip_hl - tcp_hl;  // all host-byte order

        // TCP SEQ FIX 
        struct seq_ingress_info *seq_ingress_info = bpf_map_lookup_elem(&seq_ingress_fix, &seq_ingress_key);
        if (seq_ingress_info) {  // seq_num exists in the map already; revert it to orig pkt seq_num
            // Check if the current packet is retransmit
            if (highest_mdf_sent_data_len && !(tcp->seq < highest_mdf_sent_data_len)) {  // packet is *NOT* retransmit
                tcp->seq = seq_ingress_info->seq_ingress;
                orig_seq_num = seq_ingress_info->seq_ingress;
                struct seq_ingress_info nxt_seq_val = {
                    .seq_ingress = seq_ingress_info->seq_ingress + bpf_htonl(tcp_payload_len_orig),
                };
                bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_EXIST);  // only update
            }
        } else {  // First packet entry
            struct seq_ingress_info nxt_seq_val = {
                .seq_ingress = tcp->seq + bpf_htonl(tcp_payload_len_orig),  // network-byte order
            };
            bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_NOEXIST);  // BPF_NOEXIST secondary defense
        }

        // TCP ACK FIX
        // Check if the ACK is what I expect with ==, if it is < what I expect, it could mean data is lost and next pkt would be retransmit
        
        // Get original packet length
        // __u32 init_pkt_len = ctx->len;
        // bpf_printk("Updated packet length (original) is: %u\n", init_pkt_len);

        __s64 tot_diff = csum_sub_u8_buf(rbb->bytes, pb, 0);  // Random payload csum diff for *removal*
        if (tot_diff < 0) {
            return TC_ACT_SHOT;
        }

        // L3-IP checksum replace to original
        if (bpf_l3_csum_replace(ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), bpf_htons(ip_len_modified), bpf_htons(ip_len), sizeof(__u16))) {
            bpf_printk("Something went wrong with IP l3_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP Padded PAYLOAD checksum revert to original
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), 0, (__u64)tot_diff, 0)) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with PAYLOAD l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP SEQ checksum replace to original
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), translated_seq_num, orig_seq_num, 4)) {  // all network-byte order
            bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP PSEUDO-header (Pseudo-IP) checksum replace to original
        __u16 modified_tcp_len = ip_len_modified - ip_hl;
        __u16 orig_tcp_len = ip_len - ip_hl;
        if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), bpf_htons(modified_tcp_len), bpf_htons(orig_tcp_len), BPF_F_PSEUDO_HDR | 2)) {  // Change specifically for the Pseudo-header of TCP
            bpf_printk("Something went wrong with PSEUDO l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }

    } else {  // Un-padded packet
        // TCP SEQ FIX 
        // Check if the packet is the first packet of this flow
        struct seq_ingress_info *seq_ingress_info = bpf_map_lookup_elem(&seq_ingress_fix, &seq_ingress_key);
        if (seq_ingress_info) {
            /* No need to check for retransmit because I can't change anything else */
            tcp->seq = seq_ingress_info->seq_ingress;
            orig_seq_num = seq_ingress_info->seq_ingress;
            struct seq_ingress_info nxt_seq_val = {
                .seq_ingress = seq_ingress_info->seq_ingress + bpf_htonl(tcp_payload_len_modified),  // this is not modified as the pkt is already full size
            };
            bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_EXIST);  // only update
            // L4-TCP SEQ checksum replace to original
            if (bpf_l4_csum_replace(ctx, sizeof(struct ethhdr) + ip_hl + offsetof(struct tcphdr, check), translated_seq_num, orig_seq_num, 4)) {  // all network-byte order
                bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
                return TC_ACT_SHOT;
            }
        }  // else: first ever packet of this flow; do nothing

        // TCP ACK FIX 

    }

    return TC_ACT_OK;

}


char __license[] SEC("license") = "GPL";