/**** The eBPF program to undo all the changes made by client before sending the packet to the server ****/
/**** Should disable TSO/GSO, LRO/GRO on all interfaces just to be safe even when strictly forwarding packets ****/
/**** PAD_BYTES should be max 1460 bytes on pure ACK packets with zero payload ****/

/** Wireguard encapsulation overhead is ~60 bytes: Outer IPv4 header=20 + UDP header=8 + WireGuard data header w. crypto=~32 **/

#include "tc_proxy.h"

/* Declare *SHARED* maps once on main file */
// struct ack_ingress_fix_map ack_ingress_fix SEC(".maps");
// struct ack_egress_fix_map ack_egress_fix SEC(".maps");

/* LRU HashMap to fix seq_num of current packet to original */
// struct seq_ingress_info {
//     __be32 seq_ingress;  // orig_seq
// };
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, 12292);
//     __type(key, struct flow);
//     __type(value, struct seq_ingress_info);
// } seq_ingress_fix SEC(".maps");

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

/* BPF_MAP_TYPE_PERCPU_ARRAY for storing pad_bytes */
struct pad_state_map pad_state_map SEC(".maps");

// Ring buffer map
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24);  // 16 MB Buffer
// }rb SEC(".maps");

// struct record {
//     __u16 tcp_checksum;
//     // __u32 orig_len;
//     __u32 pad_bytes;
// };

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {

    /* Need to disable TSO/GSO on all network profiles */
    // Ignore GSO/TSO Packets still; *SHOULDN'T* see them in trace files
    // if (ctx->gso_segs > 1 || ctx->gso_size) {
    //     // bpf_printk("Packet is TSO/GSO; Ignoring.\n");
    //     return TC_ACT_OK;
    // }

    // I need this function to unclone the linear part of skb for writing
    if (bpf_skb_pull_data(ctx, 0)) {  // Returns 0 on success
        bpf_printk("Failed to pull data at bpf_skb_pull_data.\n");
        return TC_ACT_OK;
    }

    void *data = (void *) (__u64) ctx->data;
    void *data_end = (void *) (__u64) ctx->data_end;

    // // Grab ETH Header
    // struct ethhdr *eth = data;
    // if (!verifier_checker(eth + 1, data_end, 0)) {
    //     return TC_ACT_SHOT;
    // }
    // Grab IP Header
    struct iphdr *ip = data;
    if (!verifier_checker(ip + 1, data_end, 0)) {
        bpf_printk("Failed at iphr.\n");
        return TC_ACT_SHOT;
    }
    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        return TC_ACT_OK;
    }
    if (ip->ihl < 5) {  // Malformed IP header
        bpf_printk("Failed at malformed ip.\n");
        return TC_ACT_SHOT;
    }
    // Calculate IP Header length
    int ip_hl = ip->ihl * 4;
    if (!verifier_checker(ip, data_end, ip_hl)) {
        bpf_printk("Failed at iphr hl.\n");
        return TC_ACT_SHOT;
    }
    // Grab TCP Header
    struct tcphdr *tcp = (struct tcphdr *) ((void *) ip + ip_hl);
    if (!verifier_checker(tcp + 1, data_end, 0)) {
        bpf_printk("Failed at tcphdr.\n");
        return TC_ACT_SHOT;
    }
    if (tcp->doff < 5) {  // Malformed TCP header
        bpf_printk("Failed at malformed tcp.\n");
        return TC_ACT_SHOT;
    }
    // Calculate TCP Header length
    int tcp_hl = tcp->doff * 4;
    if (!verifier_checker(tcp, data_end, tcp_hl)) {
        bpf_printk("Failed at tcphdr doff.\n");
        return TC_ACT_SHOT;
    }
    // Don't touch SSH traffic for remote VM
    if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22)) {
        return TC_ACT_OK;
    }
    // Windows RDP
    if (tcp->dest== bpf_htons(3389) || tcp->source == bpf_htons(3389))
        return TC_ACT_OK;

    // Only use this program on client-proxy traffic  *CRITICAL*
    // if (ip->saddr != bpf_htonl(CLIENT_IP) || ip->daddr != bpf_htonl(TARGET_SITE)) {
    //     return TC_ACT_OK;
    // }

    // if (ip->saddr != bpf_htonl(CLIENT_IP) || tcp->dest != bpf_htons(4443)) {
    //     return TC_ACT_OK;
    // }

    // IP total length field
    __u16 ip_len_modified = bpf_ntohs(ip->tot_len);  // could be untampered normal packet too
    if (ip_len_modified < ip_hl + tcp_hl) {
        bpf_printk("Failed at ip totlen.\n");
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 tcp_payload_len_modified = ip_len_modified - ip_hl - tcp_hl;  // all host-byte order

    /* Ignore special packets */
    if (is_HS_ACK(tcp, tcp_payload_len_modified)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }

    // /* Create ACK key to modify egress ACK to translated */
    // struct flow ack_egress_key = {
    //     .saddr = ip->saddr,
    //     .daddr = ip->daddr,
    //     .sport = tcp->source,
    //     .dport = tcp->dest,
    // };
    // /* Create SEQ key to fix ingress SEQ to original on current packet */
    // struct flow seq_ingress_key = {
    //     .saddr = ip->saddr,
    //     .daddr = ip->daddr,
    //     .sport = tcp->source,
    //     .dport = tcp->dest,
    // };

    // Store highest *modified* sequence of data that got received
    // __be32 highest_mdf_sent_data_len = 0;
    // struct ack_egress_info *is_retransmit = bpf_map_lookup_elem(&ack_egress_fix, &ack_egress_key);
    // if (is_retransmit) {
    //     highest_mdf_sent_data_len = is_retransmit->ack_egress;
    // }

    // Always add *modified* packet SEQ + data_sent to map to serve as ACK on Egress
    // struct ack_egress_info ack_egress_val = {
    //     .ack_egress = bpf_htonl(bpf_ntohl(tcp->seq) + tcp_payload_len_modified),  // network-byte order
    // };
    // bpf_map_update_elem(&ack_egress_fix, &ack_egress_key, &ack_egress_val, BPF_ANY);

    // __be32 translated_seq_num = tcp->seq;  // *modified* seq_num of current pkt
    // __be32 orig_seq_num = tcp->seq;  // *actual* seq_num of current pkt (will be updated)

    /* Decrypt Seq and Ack num */
    __u8 ack_set = tcp->ack; 
    __u32 trans_seq = bpf_ntohl(tcp->seq);
    __u16 seq_hi16 = (__u16)(trans_seq >> 16);
    __u16 seq_lo16 = (__u16)(trans_seq & 0xFFFF);
    rc5_16_decrypt(&seq_hi16, &seq_lo16);
    // Recombine and assign
    __u32 seq = ((__u32)seq_hi16 << 16) | seq_lo16;
    tcp->seq = bpf_htonl(seq);

    __u32 trans_ack = bpf_ntohl(tcp->ack_seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);
    if (ack_set) {
        __u16 ack_hi16 = (__u16)(trans_ack >> 16);
        __u16 ack_lo16 = (__u16)(trans_ack & 0xFFFF);
        rc5_16_decrypt(&ack_hi16, &ack_lo16);
        ack = ((__u32)ack_hi16 << 16) | ack_lo16;
        tcp->ack_seq = bpf_htonl(ack);
    }

    // *Modified* packet length
    __u32 mdf_pkt_len = ctx->len;  // could be untampered normal packets too

    /* Start of *UNDO* Padding code */
    // Read the last 4 bytes of the packet for original length of packet
    struct pad_magic_tail mtail;
    if (mdf_pkt_len < (int)sizeof(mtail)) {
        bpf_printk("Failed at mtail mdf_pkt_len.\n");
        return TC_ACT_SHOT;
    }
    if (bpf_skb_load_bytes(ctx, (mdf_pkt_len - sizeof(mtail)), &mtail, sizeof(mtail))) {
        bpf_printk("Failed at load bytes mtail.\n");
        return TC_ACT_SHOT;
    }

    // RC5 Decrypt
    __u16 a = bpf_ntohs(mtail.magic);
    __u16 b = bpf_ntohs(mtail.pad_len);
    rc5_16_decrypt(&a, &b);
    
    if (a == PAD_MAGIC16) {  // magic seq found; packet is tampered
        __u32 pad_bytes = (__u32)b;
        // bpf_printk("Pad Bytes (PROXY): %u.\n", pad_bytes);

        __u32 k0 = 0;
        struct pad_state *pad_st = bpf_map_lookup_elem(&pad_state_map, &k0);
        if (!pad_st) return TC_ACT_SHOT;
        pad_st->pad_bytes = pad_bytes;

        __u32 i_key = 0;  // index key
        struct rand_byte_buff_holder *rbbh = bpf_map_lookup_elem(&rand_byte_holder_map_ig, &i_key);
        if (!rbbh) {
            bpf_printk("Failed at rbbh.\n");
            return TC_ACT_SHOT;
        }

        __u32 pb = pad_st->pad_bytes;
        if (pb > MAX_PAD)   // corrupted
            return TC_ACT_SHOT;
        if (pb > mdf_pkt_len)   // corrupted
            return TC_ACT_SHOT;
        if (pb == 0)   // corrupted
            return TC_ACT_SHOT;

        // Store the random padded bytes to BPF_MAP for csum calc
        if (bpf_skb_load_bytes(ctx, mdf_pkt_len - pb, rbbh->bytes, pb)) {
            bpf_printk("Failed at load bytes rbbh.\n");
            return TC_ACT_SHOT;
        }

        // UNDO padding
        if (bpf_skb_change_tail(ctx, mdf_pkt_len - pb, 0)) {  // NTC BPF_F_INVALIDATE_HASH flag here;
            bpf_printk("Error with changing tail of the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;
        data_end = (void *) (__u64) ctx->data_end;  // This should point to payload end because bpf_skb_change_tail internally linearizes the whole packet

        // // Grab ETH Header
        // eth = data;
        // if (!verifier_checker(eth + 1, data_end, 0)) {
        //     return TC_ACT_SHOT;
        // }
        // Grab IP Header
        ip = data;
        if (!verifier_checker(ip + 1, data_end, 0)) {
            bpf_printk("Failed at mod iphr.\n");
            return TC_ACT_SHOT;
        }
        // Calculate IP Header length
        ip_hl = ip->ihl * 4;
        if (!verifier_checker(ip, data_end, ip_hl)) {
            bpf_printk("Failed at mod iphr hl.\n");
            return TC_ACT_SHOT;
        }
        // Grab TCP Header
        tcp = (struct tcphdr *) ((void *) ip + ip_hl);
        if (!verifier_checker(tcp + 1, data_end, 0)) {
            bpf_printk("Failed at mod tcphdr.\n");
            return TC_ACT_SHOT;
        }
        // Calculate TCP Header length
        tcp_hl = tcp->doff * 4;
        if (!verifier_checker(tcp, data_end, tcp_hl)) {
            bpf_printk("Failed at mod tcp hl.\n");
            return TC_ACT_SHOT;
        }

        // tcp->check = mtail.checksum;
        // bpf_printk("The original checksum is: 0x%04x\n", bpf_ntohs(mtail.checksum));
        // struct record *ringbuf_rec = bpf_ringbuf_reserve(&rb, sizeof(struct record), 0);
        // if (!ringbuf_rec) {
        //     return TC_ACT_OK;
        // }
        // ringbuf_rec->tcp_checksum = bpf_ntohs(tcp->check);
        // ringbuf_rec->pad_bytes = pb;
        // // Submit data to ring buffer
        // bpf_ringbuf_submit(ringbuf_rec, 0);

        // Original ip len
        __u16 ip_len = ip_len_modified - pb;
        if (ip_len > 65535) {  // Something went wrong
            bpf_printk("Failed at mod iplen.\n");
            return TC_ACT_SHOT;
        }

        /* Update all fields first before actual writing */
        // IPv4 tot_len fix to original
        ip->tot_len = bpf_htons(ip_len);

        // bpf_printk("Initial IP length (original) is: %u\n", bpf_ntohs(ip->tot_len));

        __u32 tcp_payload_len_orig = ip_len - ip_hl - tcp_hl;  // all host-byte order

        // TCP SEQ FIX 
        // struct seq_ingress_info *seq_ingress_info = bpf_map_lookup_elem(&seq_ingress_fix, &seq_ingress_key);
        // if (seq_ingress_info) {  // seq_num exists in the map already; revert it to orig pkt seq_num
        //     __be32 orig_seq = seq_ingress_info->seq_ingress;
        //     // Check if the current packet is retransmit
        //     if (highest_mdf_sent_data_len && !(tcp->seq < highest_mdf_sent_data_len)) {  // packet is *NOT* retransmit
        //         // tcp->seq = orig_seq;
        //         orig_seq_num = orig_seq;
        //         struct seq_ingress_info nxt_seq_val = {
        //             .seq_ingress = bpf_htonl(bpf_ntohl(orig_seq) + tcp_payload_len_orig),
        //         };
        //         bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_ANY);  // only update
        //     }
        // } else {  // First packet entry
        //     struct seq_ingress_info nxt_seq_val = {
        //         .seq_ingress = bpf_htonl(bpf_ntohl(tcp->seq) + tcp_payload_len_orig),  // network-byte order
        //     };
        //     bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_NOEXIST);  // BPF_NOEXIST secondary defense
        // }

        // TCP ACK FIX
        // Check if the ACK is what I expect with ==, if it is < what I expect, it could mean data is lost and next pkt would be retransmit
        
        // Get original packet length
        __u32 init_pkt_len = ctx->len;

        __s64 tot_diff = 0;

        if (tcp_payload_len_orig & 1) {
            __u8 last = 0;
            if (bpf_skb_load_bytes(ctx, init_pkt_len - 1, &last, 1))  // last byte of actual payload
                return TC_ACT_SHOT;

            __u8 pad0 = rbbh->bytes[0];

            // __u8 oldb[2] = { last, pad0 };
            // __u8 newb[2] = { last, 0x00 };
            // bpf_csum_diff only accepts multiples of 4 for length param
            __be32 old32 = bpf_htonl(((__u32)last << 24) | ((__u32)pad0 << 16));
            __be32 new32 = bpf_htonl(((__u32)last << 24) | ((__u32)0x00 << 16));

            tot_diff = bpf_csum_diff(&old32, 4, &new32, 4, 0);
            if (tot_diff < 0) {
                bpf_printk("Failed bridge diff\n");
                return TC_ACT_SHOT;
            }

            tot_diff = csum_sub_u8_buf(&rbbh->bytes[1], pb - 1, (__u32)tot_diff);
        
        } else {
            tot_diff = csum_sub_u8_buf(rbbh->bytes, pb, 0);
        }

        if (tot_diff < 0) {
            bpf_printk("Failed at tot_diff\n");
            return TC_ACT_SHOT;
        }
        
        // tot_diff = csum_sub_u8_buf(rbbh->bytes, pb - 4, 0);  // Random payload csum diff for *removal*
        // if (tot_diff < 0) {
        //     bpf_printk("Failed at tot_diff.\n");
        //     return TC_ACT_SHOT;
        // }

        // L3-IP checksum replace to original
        if (bpf_l3_csum_replace(ctx, offsetof(struct iphdr, check), bpf_htons(ip_len_modified), bpf_htons(ip_len), 2)) {
            bpf_printk("Something went wrong with IP l3_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP Padded PAYLOAD checksum revert to original
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), 0, (__u64)tot_diff, 0)) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with PAYLOAD l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP SEQ checksum replace to original
        // if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), translated_seq_num, orig_seq_num, 4)) {  // all network-byte order
        //     bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
        //     return TC_ACT_SHOT;
        // }
        // L4-TCP PSEUDO-header (Pseudo-IP) checksum replace to original
        __u16 modified_tcp_len = ip_len_modified - ip_hl;
        __u16 orig_tcp_len = ip_len - ip_hl;
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), bpf_htons(modified_tcp_len), bpf_htons(orig_tcp_len), BPF_F_PSEUDO_HDR | 2)) {  // Change specifically for the Pseudo-header of TCP
            bpf_printk("Something went wrong with PSEUDO l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
    } 
    // else {  // Un-padded packet
    //     // TCP SEQ FIX 
    //     // Check if the packet is the first packet of this flow
    //     struct seq_ingress_info *seq_ingress_info = bpf_map_lookup_elem(&seq_ingress_fix, &seq_ingress_key);
    //     if (seq_ingress_info) {
    //         __be32 orig_seq = seq_ingress_info->seq_ingress;
    //         // Check if the current packet is retransmit
    //         if (highest_mdf_sent_data_len && !(tcp->seq < highest_mdf_sent_data_len)) {
    //             // tcp->seq = orig_seq;
    //             orig_seq_num = orig_seq;
    //             struct seq_ingress_info nxt_seq_val = {
    //                 .seq_ingress = bpf_htonl(bpf_ntohl(orig_seq) + tcp_payload_len_modified),  // this is not modified as the pkt is already full size
    //             };
    //             bpf_map_update_elem(&seq_ingress_fix, &seq_ingress_key, &nxt_seq_val, BPF_ANY);  // only update
    //             // L4-TCP SEQ checksum replace to original
    //             // if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), translated_seq_num, orig_seq_num, 4)) {  // all network-byte order
    //             //     bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
    //             //     return TC_ACT_SHOT;
    //             // }
    //         }
    //     }  // else: first ever packet of this flow; do nothing

    //     // TCP ACK FIX 

    // }

    // L4-TCP SEQ checksum replace
    if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), bpf_htonl(trans_seq), bpf_htonl(seq), 4)) {  // all network-byte order
        bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
        return TC_ACT_SHOT;
    }
    // L4-TCP ACK checksum replace
    if (ack_set) {
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), bpf_htonl(trans_ack), bpf_htonl(ack), 4)) {  // all network-byte order
            bpf_printk("Something went wrong with TCP->ACK_SEQ l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";