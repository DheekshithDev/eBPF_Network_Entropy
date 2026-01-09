#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <linux/types.h>
// #include <netinet/in.h>

#define AF_INET 2  /* IPv4 code instead of importing */
#define ETH_P_IP 0x0800  /* IPv4 packet */

#define TC_ACT_OK 0  /* Terminate the packet processing pipeline and allows the packet to proceed */
#define TC_ACT_SHOT 2  /* Terminate the packet processing pipeline and drops the packet */

#define DEVICE_MTU 1500

#define PAD_BYTES 100  // No need to define any hexadecimal or other data because I'm padding zeroes

/***** REMOVE bpf_printk()s IN PROD *****/

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

    bpf_printk("The packet is TCP-IPv4!\n");
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

    /* Ignore GSO/TSO Packets */
    if (ctx->gso_segs > 1 || ctx->gso_size) {
        bpf_printk("Packet is TSO/GSO; Ignoring.\n");
        return TC_ACT_OK;
    }

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

    // Don't touch SSH traffic for remote VM
    if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22)) {
        // bpf_printk("Bypassing SSH traffic (port 22)");
        return TC_ACT_OK;
    }

    /* Check if packet is part of 3-way handshake or ACK packet without payload */
    __u16 old_ip_len = bpf_ntohs(ip->tot_len);  // IP total length field

    if (old_ip_len < ip_hl + tcp_hl) {
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 pkt_payload = old_ip_len - ip_hl - tcp_hl;

    /* Ignore special packets */
    if (is_HS_ACK(tcp, pkt_payload)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }

    bpf_printk("Initial packet length is: %u\n", init_pkt_len);
    // bpf_printk("WIRE LEN is: %u\n", ctx->wire_len);

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

    __u32 pad_bytes = 0;

    if (old_ip_len < DEVICE_MTU) {
        fib.tot_len = bpf_htons(old_ip_len + (DEVICE_MTU - old_ip_len));
    } else {
        fib.tot_len = bpf_htons(old_ip_len);
    }

    long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);

    __u32 fib_mtu = 0;

    if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {  // Fragmentation needed
        bpf_printk("bpf_fib_lookup needs fragmentation!\n");
        fib_mtu = fib.mtu_result;
    } else if (ret == 0) {  // Success
        bpf_printk("bpf_fib_lookup was a success!\n");
        fib_mtu = fib.mtu_result;  // Could be 0
    } else {
        bpf_printk("bpf_fib_lookup failed: %ld\n", ret);
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

                /** TCP START **/
        /* SEQ Num Fix - START */
        __be32 old_seq_num = bpf_ntohl(tcp->seq);
        __be32 new_seq_num = old_seq_num + bpf_htonl(pad_bytes);  // If I dont fix seq_num, it might overload the recv_window_size of the receiver
        tcp->seq = new_seq_num;  // No need for htonl coz of __be32
        
        /* L3-IP checksum replace */
        bpf_l3_csum_replace(ctx, offsetof(struct iphdr, check), bpf_htons(old_ip_len), bpf_htons(new_ip_len), sizeof(__u16));
        /** IP END **/
        

        
        // /* L4-TCP checksum replace */
        // __s64 seq_diff = bpf_csum_diff(&old_seq_num, sizeof(old_seq_num), &new_seq_num, sizeof(new_seq_num), tcp->check);
        
        /* Padding actual bytes than 0s (Optional) - START */
        // I need this step if I am padding bytes other than 0s.
        //__s64 payload_diff = bpf_csum_diff(NULL, 0, &pad_bytes, __aligned_be64(sizeof(pad_bytes), 4), tcp->check);  // Since I am appending only 0s, pad_bytes won't have any data; I dont need this step.
        // __u32 tcp_check_offset = &tcp->check - data;
        /* Padding actual bytes than 0s (Optional) - END */
        
        // I can't combine these two calls into a single bpf_csum_diff and do bpf_l4_csum_replace once because of BPF_F_PSEUDO_HDR flag
        // bpf_l4_csum_replace(ctx, offsetof(struct tcphdr, check), 0, seq_diff, 0);
        /* SEQ Num Fix - END */
        
        __u16 old_tcp_len = old_ip_len - ip_hl;
        __u16 new_tcp_len = new_ip_len - ip_hl;
        bpf_l4_csum_replace(ctx, offsetof(struct tcphdr, check), bpf_htons(old_tcp_len), bpf_htons(new_tcp_len), BPF_F_PSEUDO_HDR | 2);  // Change specifically for the Pseudo-header of TCP
        
        /** TCP END **/
        /*** FIXES FOR INCREASING PACKET LENGTH ***/

    } else {
        bpf_printk("Packet length is >= PMTU. Don't Pad.\n");
    }

    return TC_ACT_OK;
}

// SEC("tc")
// int tc_ingress(struct __sk_buff *ctx) {
//
//     return TC_ACT_OK;
// }


char __license[] SEC("license") = "GPL";