//
// Created by ArthurK-5080 on 8/11/2025.
//
/***** This program might blow the recv window size of the remote server as the TCP state doesn't know about the tail padding this program does. *****/
/***** This program currently ignores special packets from padding like pure-ACKs, 3-way handshake packets, etc. *****/
/***** This program doesn't skip GSO/TSO packets. It expects you to disable them prior. *****/
/***** This program doesn't skip GRO/LRO packets (but some devices disable it automatically when XDP is set). It expects you to disable them prior. *****/
/*****
 *This program computes checksum manually in software. To prevent hardware checksum computation again, it is advisable to turn TX/RX checksum off.
 *It is also possible to skip hardware checksum by passing certain flags, but it is not generally guaranteed.
 *Alternatively, it is possible to send CHECKSUM_MANGLED flag to let the hardware compute the checksum for your modified packet without doing it manually in this program.
 *****/
/***** If your networking environment supports VLAN-tagged IPv4 frames (802.1Q/AD or IEEE 802.1Q), then it should be disabled for proper functioning as this program assumes eth->h_proto == 0x0800 without skipping any VLAN headers when parsing. *****/
/***** This program expects you to hardcode the Device MTU in its DEVICE_MTU macro prior to running as PMTU is very salient for this program. *****/

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

#define PAD_BYTES 100  // No need to define any hexadecimal or other data because I'm padding zeroes

/* LRU HashMap for XDP to fix ingress ack_seq */
// Key //
struct flow {
    // Network-order
    __be32 saddr, daddr;
    __be16 sport, dport;
};
// Value //
struct ack_info {
    // Can use __be32 ack directly without wrapping inside a struct, but might add more fields in future
    __be32 ack;  // network-order ACK (tcp->ack_seq)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow);
    __type(value, struct ack_info);
} ack_map SEC(".maps");

/* LRU HashMap for TC-Egress to fix seq_num */
// Key //
struct seq_key {
    // Network-order
    __be32 saddr, daddr;
    __be16 sport, dport;
};
// Value //
struct seq_info {
    // Can use __be32 seq directly without wrapping inside a struct, but might add more fields in future
    __be32 seq;  // network-order SEQ (tcp->seq)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct seq_key);
    __type(value, struct seq_info);
} seq_map SEC(".maps");

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
    if (tcp->syn && tcp->ack && !tcp->rst)   return true;  // SYN-ACK (On Egress, I don't need this check)

    /* Only ACKs */
    if (!tcp->syn && tcp->ack && payload_len == 0)  return true;  // Any simple ACK (includes handshake ACK too)

    /* Only Resets */
    if (tcp->rst)   return true;  // Reset flag found; don't touch

    /* Only FIN */
    if (tcp->fin)   return true;  // FIN/implicit ACK; don't touch

    // Maybe I can ignore URG packets too

    return false;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) {

    /*****
     * This TC-Egress program is for padding the packets' tail to the full size of the PMTU.
     *****/

    /** I disabled TSO/GSO on all network profiles **/
    // /* Ignore GSO/TSO Packets FOR NOW */
    // if (ctx->gso_segs > 1 || ctx->gso_size) {
    //     bpf_printk("Packet is TSO/GSO; Ignoring.\n");
    //     return TC_ACT_OK;
    // }

    // I need this function to unclone the linear part of skb for writing
    if (bpf_skb_pull_data(ctx, 0)) {  // Returns 0 on success
        bpf_printk("Failed to pull data at bpf_skb_pull_data.\n");
        return TC_ACT_OK;
    }

    void *data = (void *) (__u64) ctx->data;  // (unsigned long) == (__u64)
    void *data_end = (void *) (__u64) ctx->data_end;

    // Get current packet length
    __u32 init_pkt_len = ctx->len;

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

    /* Check if packet is part of 3-way handshake or ACK packet without payload */
    __u16 old_ip_len = bpf_ntohs(ip->tot_len);  // IP total length field

    if (old_ip_len < ip_hl + tcp_hl) {
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 pkt_payload = (int) old_ip_len - ip_hl - tcp_hl;

    /* Ignore special packets */
    if (is_HS_ACK(tcp, pkt_payload)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }

    bpf_printk("Initial packet length is: %u\n", init_pkt_len);

    /* Add Initial packet SEQ to map to serve as ACK on Ingress*/
    u32 tcp_payload_len_only_orig = bpf_ntohs(ip->tot_len) - ip_hl - tcp_hl;  // all host-byte order
    struct flow ack_key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };
    struct ack_info ack_val = {
        // The original seq_num of pkt will be correct ack returning from remote
        .ack = tcp->seq + bpf_htonl(tcp_payload_len_only_orig),  // Store Network-order
    };

    bpf_map_update_elem(&ack_map, &ack_key, &ack_val, BPF_ANY);

    /** Start of Padding code **/
    /* Grab Path MTU */
    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.ifindex = ctx->ifindex;
    fib.tos = ip->tos;
    fib.l4_protocol = IPPROTO_TCP;
    fib.sport = tcp->source;
    fib.dport = tcp->dest;
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;
    fib.tot_len = bpf_htons(old_ip_len + (DEVICE_MTU - old_ip_len));  // Always push it to trigger FIB_FRAGMENTATION_NEEDED

    long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);

    u32 pad_bytes = 0;
    u32 fib_mtu = 0;

    if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED || ret == 0) {
        // Use only when it returns successfully; don't use when it fails and *may* contain garbage value as MTU
        fib_mtu = fib.mtu_result;
    }

    if (fib_mtu <= 0) {
        bpf_printk("Something went wrong with FIB_MTU lookup.");
        // return TC_ACT_SHOT;
    }
    bpf_printk("The Fib-MTU is: %u\n", fib_mtu);

    __u32 p_mtu = fib_mtu ?: DEVICE_MTU;  // p_mtu is the TARGET I want to pad till.

    /* bpf_skb_change_tail */
    if (p_mtu && (p_mtu > old_ip_len)) {
        pad_bytes = (p_mtu - old_ip_len);
    } else {
        pad_bytes = 0;
    }

    if (pad_bytes) {
        bpf_printk("Pad Bytes: %u. Packet length is < PMTU. Padding.\n", pad_bytes);
        if (bpf_skb_change_tail(ctx, init_pkt_len + pad_bytes, 0)) {
            /* Failed */
            bpf_printk("Error with changing tail to the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;  // (unsigned long) == (__u64)
        data_end = (void *) (__u64) ctx->data_end;

        // Get current packet length
        __u32 mdf_pkt_len = ctx->len;

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

        bpf_printk("Modified packet length is: %u\n", mdf_pkt_len);

        /*** FIXES FOR INCREASING PACKET LENGTH ***/
        /** IP START **/
        /* Update IPv4 tot_len field */
        __u16 new_ip_len = old_ip_len + pad_bytes;
        if (new_ip_len > 65535) {  // Something went wrong
            return TC_ACT_SHOT;
        }
        ip->tot_len = bpf_htons(new_ip_len);

        /* L3-IP checksum replace */
        bpf_l3_csum_replace(ctx, offsetof(struct iphdr, check), bpf_htons(old_ip_len), bpf_htons(new_ip_len), sizeof(__u16));
        /** IP END **/

        /** TCP START **/
        /* SEQ Num Fix - START */
        // If I don't fix seq_num, it *may* overload the recv_window_size of the receiver
        u32 tcp_payload_len_only_new = new_ip_len - ip_hl - tcp_hl;  // all host-byte order
        struct seq_key s_key = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .sport = tcp->source,
            .dport = tcp->dest,
        };
        __be32 curr_pkt_seq_num = tcp->seq;  // seq_num of current pkt (not updated)
        struct seq_info *prev_pkt_info = bpf_map_lookup_elem(&seq_map, &s_key);  // seq_num of previous pkt
        if (prev_pkt_info) {  // seq_num exists in the map already; update it and fix current pkt seq_num
            __be32 prev_pkt_seq_num = prev_pkt_info->seq;
            tcp->seq = prev_pkt_seq_num;  // No need for htonl coz of __be32
            struct seq_info s_val = {
                .seq = prev_pkt_seq_num + bpf_htonl(tcp_payload_len_only_new),  // network-byte order
            };
            bpf_map_update_elem(&seq_map, &s_key, &s_val, BPF_EXIST);
        } else {  // First entry
            struct seq_info s_val = {
                .seq = tcp->seq + bpf_htonl(tcp_payload_len_only_new),  // network-byte order
            };
            bpf_map_update_elem(&seq_map, &s_key, &s_val, BPF_NOEXIST);  // BPF_NOEXIST secondary defense
        }
        // /* L4-TCP checksum replace */
        long l4_csum_success = bpf_l4_csum_replace(ctx, offsetof(struct tcphdr, check), curr_pkt_seq_num, tcp->seq, 4);  // all network-byte order
        if (l4_csum_success) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with l4_csum_replace().\n");
        }
        /* SEQ Num Fix - END */

        /* TCP Pseudo-header (IP) Fix - START */
        __u16 old_tcp_len = old_ip_len - ip_hl;
        __u16 new_tcp_len = new_ip_len - ip_hl;
        long l4_csum_pseudo_success = bpf_l4_csum_replace(ctx, offsetof(struct tcphdr, check), bpf_htons(old_tcp_len), bpf_htons(new_tcp_len), BPF_F_PSEUDO_HDR | 2);  // Change specifically for the Pseudo-header of TCP
        if (l4_csum_pseudo_success) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with pseudo l4_csum_replace().\n");
        }
        /* TCP Pseudo-header (IP) Fix - END */
        /** TCP END **/
        /*** FIXES FOR INCREASING PACKET LENGTH ***/

    } else {
        bpf_printk("Packet length is >= PMTU. Don't Pad.\n");
    }

    return TC_ACT_OK;
}

/** XDP is only for fixing ACKs (not for fixing padding) **/
SEC("xdp")
int xdp_padding(struct xdp_md *ctx) {
    /*****
     * This XDP program is for fixing ACKs only (reverting ACKs to their original) to maintain TCP state due to padding done at TC-Egress.
     * Padded packets travel on-wire to the remote and it acks the padded payload length too. Host stack doesn't know about the padding and since to maintain the state, this XDP program is designed.
     *****/
    // Pointers to packet data
    void *data = (void *) (unsigned long) ctx->data;
    void *data_end = (void *) (unsigned long) ctx->data_end;

    // Get current packet length
    __u32 init_pkt_size = data_end - data;

    // Grab ETH Header
    struct ethhdr *eth = data;
    if (!verifier_checker(eth + 1, data_end, 0)) {
        return XDP_DROP;
    }

    // Grab IP Header
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if (!verifier_checker(ip + 1, data_end, 0)) {
        return XDP_DROP;
    }

    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
        return XDP_PASS;
    }

    if (ip->ihl < 5) {  // Malformed IP header
        return XDP_DROP;
    }

    // Calculate IP Header length
    int ip_hl = ip->ihl * 4;
    if (!verifier_checker(ip, data_end, ip_hl)) {
        return XDP_DROP;
    }

    // Grab TCP Header
    struct tcphdr *tcp = (struct tcphdr *) ((void *) ip + ip_hl);
    if (!verifier_checker(tcp + 1, data_end, 0)) {
        return XDP_DROP;
    }

    if (tcp->doff < 5) {  // Malformed TCP header
        return XDP_DROP;
    }

    // Calculate TCP Header length
    int tcp_hl = tcp->doff * 4;
    if (!verifier_checker(tcp, data_end, tcp_hl)) {
        return XDP_DROP;
    }

    /** ACK Fix Ingress - START **/
    // Need packets with a pure ACK or ACK w.payload only
    bool has_ack = tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst;

    if (has_ack) {
        // Access LRU map
        struct flow key = {
            .saddr = ip->daddr,
            .daddr = ip->saddr,
            .sport = tcp->dest,
            .dport = tcp->source,
        };

        struct ack_info *value_p = bpf_map_lookup_elem(&ack_map, &key);
        if (!value_p) {
            return XDP_PASS;
        }

        // Save old ACK value
        __be32 orig_ack = tcp->ack_seq;
        // Save new ACK value
        __be32 fixed_ack = value_p->ack;

        // Update with new ACK
        tcp->ack_seq = fixed_ack;

        /* Checksum fix for modified ACK - START */
        __u64 csum_diff = bpf_csum_diff(&orig_ack, 4, &fixed_ack, 4, ~tcp->check);  // returns __s64 on success
        if (csum_diff < 0) {
            // bpf_csum_diff returns negative err code when fails
            bpf_printk("Something went wrong with bpf_csum_diff().\n");
            // From Documentation: "The XDP_ABORTED action is not something a functional program should ever use as a return code."
            return XDP_ABORTED;  // Only use XDP_ABORTED when there is an eBPF program error.
        }
        tcp->check = ~(__be16)csum_diff;
        /* Checksum fix for modified ACK - END */
    }
    /** ACK Fix Ingress - END **/
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";