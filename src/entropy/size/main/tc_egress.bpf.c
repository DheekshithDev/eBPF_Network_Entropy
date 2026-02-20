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
/**** PAD_BYTES should be max 1420 bytes on pure ACK packets with zero payload ****/

/***** REMOVE bpf_printk()s IN PROD *****/

/** Wireguard encapsulation overhead is ~60 bytes: Outer IPv4 header=20 + UDP header=8 + WireGuard data header w. crypto=~32 **/

#include "tc.h"

/* Declare *SHARED* maps once on main file */
struct ack_ingress_fix_map ack_ingress_fix SEC(".maps");
struct ack_egress_fix_map ack_egress_fix SEC(".maps");

/* LRU HashMap for modifying SEQ_NUM on current packet */
struct seq_egress_info {
    __be32 seq_egress;  // translated_seq
};
struct {  // I maintain this for myself
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 12292);
    __type(key, struct flow);
    __type(value, struct seq_egress_info);
} seq_egress_fix SEC(".maps");

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
} rand_byte_holder_map_eg SEC(".maps");

/* BPF_MAP_TYPE_PERCPU_ARRAY for storing pad_bytes (shared map but unique to each) */
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
int tc_egress(struct __sk_buff *ctx) {

    // return TC_ACT_OK;

    /*** This TC-Egress program is for padding the packets' tail to the full size of the PMTU. ***/

    /* I disabled TSO/GSO on all network profiles */
    // Ignore GSO/TSO Packets still; *SHOULDN'T* see them in trace files
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

    // // Grab ETH Header
    // struct ethhdr *eth = data;
    // if (!verifier_checker(eth + 1, data_end, 0)) {
    //     return TC_ACT_SHOT;
    // }
    // if (ctx->protocol == bpf_htons(ETH_P_IP)) {
    //     bpf_printk("Packet is IPv4. \n");
    //     // return TC_ACT_OK;
    // }
    // Grab IP Header
    struct iphdr *ip = data;
    if (!verifier_checker(ip + 1, data_end, 0)) {
        bpf_printk("Failed at iphr.\n");
        return TC_ACT_SHOT;
    }
    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
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

    // if (tcp->dest != 443) {
    //     return TC_ACT_OK;
    // }

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
    __u16 ip_len = bpf_ntohs(ip->tot_len);  
    if (ip_len < ip_hl + tcp_hl) {
        bpf_printk("Failed at ip totlen.\n");
        return TC_ACT_SHOT;  // Malformed packet
    }

    __u32 tcp_payload_len = ip_len - ip_hl - tcp_hl;  // all host-byte order

    /* Ignore special packets */
    if (is_HS_ACK(tcp, tcp_payload_len)) {
        return TC_ACT_OK;  // I don't need this packet; simply pass it
    }

    /* Start of Padding code */
    /* Create ACK key to revert client ingress ACK to original */
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
        .saddr = ip->daddr,
        .daddr = ip->saddr,
        .sport = tcp->dest,
        .dport = tcp->source,
    };

    // Store highest sequence of data that got sent
    __be32 highest_sent_data_len = 0;
    struct ack_ingress_info *is_retransmit = bpf_map_lookup_elem(&ack_ingress_fix, &ack_ingress_key);
    if (is_retransmit) {
        highest_sent_data_len = is_retransmit->ack_ingress;
    }

    // Always add packet SEQ + data_sent to map to serve as ACK on Client Ingress
    struct ack_ingress_info ack_ingress_val = {
        .ack_ingress = bpf_htonl(bpf_ntohl(tcp->seq) + tcp_payload_len),  // network-byte order
    };
    bpf_map_update_elem(&ack_ingress_fix, &ack_ingress_key, &ack_ingress_val, BPF_ANY);

    __be32 curr_seq_num = tcp->seq;  // actual seq_num of current pkt (not updated)
    __be32 translated_seq_num = tcp->seq;  // *modified* seq_num of current pkt (will be updated)

    __be32 curr_ack_num = tcp->ack_seq;  // actual ack_num of current pkt (not updated)
    __be32 translated_ack_num = tcp->ack_seq;  // *modified* ack_num of current pkt (will be updated)

    // // Grab Path MTU
    // struct bpf_fib_lookup fib = {};
    // fib.family = AF_INET;
    // fib.ifindex = ctx->ifindex;
    // fib.tos = ip->tos;
    // fib.l4_protocol = IPPROTO_TCP;
    // fib.sport = tcp->source;
    // fib.dport = tcp->dest;
    // fib.ipv4_src = ip->saddr;
    // fib.ipv4_dst = ip->daddr;
    // fib.tot_len = bpf_htons(ip_len + (DEVICE_MTU - ip_len));  // Always push it to trigger FIB_FRAGMENTATION_NEEDED

    // long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);

    // __u32 p_mtu = 0;
    // if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED || ret == 0) {
    //     // Use only when it returns successfully; don't use when it fails and *may* contain garbage value as MTU
    //     p_mtu = fib.mtu_result;
    // }
    // if (p_mtu <= 0) {
    //     bpf_printk("Something went wrong with FIB_MTU lookup.");
    //     // return TC_ACT_SHOT;
    // }
    // p_mtu = p_mtu ?: DEVICE_MTU;  // p_mtu is the TARGET I want to pad till.
    // bpf_printk("The PMTU is: %u\n", p_mtu);

    // bool tcp_csum_recompute = false;  // Do full TCP CSUM compute from scratch

    __u32 p_mtu = DEVICE_MTU;
    
    __u32 pad_bytes = 0;
    if (p_mtu && (p_mtu > ip_len)) {
        pad_bytes = (p_mtu - ip_len);  // max legally can be 1420
    } else {
        pad_bytes = 0;
    }

    if (pad_bytes > MAX_PAD)
        pad_bytes = MAX_PAD;

    __u32 k0 = 0;
    struct pad_state *pad_st = bpf_map_lookup_elem(&pad_state_map, &k0);
    if (!pad_st) return TC_ACT_SHOT;
    pad_st->pad_bytes = pad_bytes;

    // Get current packet length from L3 for WireGuard
    __u32 init_pkt_len = ctx->len;
    
    if (pad_bytes >= 4) {  // Need minimum of 4 bytes available for encoding original length | I can shrink the packet and add the leftover to next packet too.
        // bpf_printk("Pad Bytes: %u.\n", pad_bytes);
        // struct record *ringbuf_rec = bpf_ringbuf_reserve(&rb, sizeof(struct record), 0);
        // if (!ringbuf_rec) {
        //     return TC_ACT_OK;
        // }
        // ringbuf_rec->tcp_checksum = bpf_ntohs(tcp->check);
        // ringbuf_rec->pad_bytes = pad_bytes;
        // // Submit data to ring buffer
        // bpf_ringbuf_submit(ringbuf_rec, 0);

        if (bpf_skb_change_tail(ctx, init_pkt_len + pad_bytes, 0)) {  // NTC BPF_F_INVALIDATE_HASH flag here; I can also skip bpf_set_hash_invalid() because this is not TC-Ingress RX path
            bpf_printk("Error with changing tail to the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;  // (unsigned long) == (u64)
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
        // u8 *tail = (u8 *)data + init_pkt_len;
        // if (!verifier_checker(tail, data_end, pad_bytes))
        //     return TC_ACT_SHOT;
        
        __u16 new_ip_len = ip_len + pad_bytes;
        if (new_ip_len > 65535) {  // Something went wrong
            bpf_printk("Failed at mod iplen.\n");
            return TC_ACT_SHOT;
        }
        
        /* Update all fields first before actual writing */
        // IPv4 tot_len fix
        ip->tot_len = bpf_htons(new_ip_len);
        
        __u32 tcp_payload_len_modified = new_ip_len - ip_hl - tcp_hl;  // all host-byte order

        // TCP SEQ FIX 
        struct seq_egress_info *seq_egress_info = bpf_map_lookup_elem(&seq_egress_fix, &seq_egress_key);
        if (seq_egress_info) {  // seq_num exists in the map already; update it and fix current pkt seq_num
            __be32 mdf_seq = seq_egress_info->seq_egress;
            // Check if the current packet is retransmit
            if (highest_sent_data_len && !(tcp->seq < highest_sent_data_len)) {  // packet is *NOT* retransmit
                tcp->seq = mdf_seq;  // No htonl as its already __be32
                translated_seq_num = mdf_seq;
                struct seq_egress_info nxt_seq_val = {
                    .seq_egress = bpf_htonl(bpf_ntohl(mdf_seq) + tcp_payload_len_modified),
                };
                bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_ANY);  // only update

                // TCP ACK FIX
                // if (tcp->ack) {  // Only if ACK bit is set
                //     struct ack_egress_info *ack_egress_info = bpf_map_lookup_elem(&ack_egress_fix, &ack_egress_key);
                //     if (ack_egress_info) {
                //         __be32 orig_ack = ack_egress_info->ack_egress_orig;
                //         __be32 mdf_ack = ack_egress_info->ack_egress;
                //         if (tcp->ack_seq == orig_ack) {  // check if the ACK is what I expect with ==
                //             if (orig_ack != mdf_ack) {  // no update needed for unpadded packets on Client Ingress
                //                 tcp->ack_seq = mdf_ack;
                //                 translated_ack_num = mdf_ack;
                //             }
                            
                //         } else {  // (tcp->ack_seq *SHOULD NEVER* be > than orig_ack)
                //             // tcp->ack_seq is < orig_ack; pkt is dropped and next pkt from me would be retransmit;
                //             bpf_printk("Data lost. Next pkt will be retransmit.\n");
                //         }

                //     }
                // }
            }
        } else {  // First packet entry that needs padding
            struct seq_egress_info nxt_seq_val = {
                .seq_egress = bpf_htonl(bpf_ntohl(tcp->seq) + tcp_payload_len_modified),  // network-byte order
            };
            bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_NOEXIST);  // BPF_NOEXIST secondary defense
        }

        /* Write random payload to packet but leave last 4 bytes */
        __u32 key = 0;
        struct rand_byte_buff *rbb = bpf_map_lookup_elem(&rand_byte_map, &key);
        if (!rbb) { 
            bpf_printk("Failed at rbb.\n");
            return TC_ACT_SHOT;
        }
        // CAN RUN THIS BY DOING THIS BEFORE ACCESSING PAD_BYTES MAP
        // // Random offset of bytes for randomizing
        // __u32 space = MAX_PAD - max_load;
        // __u32 rand_off = 0;
        // if (space)
        //     rand_off = bpf_get_prandom_u32() % (space);
        // if (rand_off > MAX_PAD - max_load)
        //     rand_off = 0;

        __u32 pb = pad_st->pad_bytes;
        if (pb > MAX_PAD) 
            pb = MAX_PAD;
        if (pb > 4) {
            if (bpf_skb_store_bytes(ctx, init_pkt_len, rbb->bytes, pb - 4, 0)) {  // leave last 4 bytes for original length
                bpf_printk("Failed at store bytes rbb.\n");
                return TC_ACT_SHOT;
            }
        }

        // RC5 Encrypt
        __u16 a = PAD_MAGIC16;
        __u16 b = (__u16)pb;
        rc5_16_encrypt(&a, &b);

        /* Encode original length to the last 4 bytes of the payload */
        struct pad_magic_tail mtail = {
            .magic = bpf_htons(a),
            .pad_len = bpf_htons(b),
        };

        // Get *modified* packet length
        __u32 mdf_pkt_len = ctx->len;
        if (mdf_pkt_len < (int)sizeof(mtail)) {
            bpf_printk("Failed at mdf_len.\n");
            return TC_ACT_SHOT;
        }
        // Only need to copy pad_bytes which I can use to undo every change I made
        if (bpf_skb_store_bytes(ctx, (mdf_pkt_len - sizeof(mtail)), &mtail, sizeof(mtail), 0)) {
            bpf_printk("Failed at store bytes mtail.\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again x2 */
        data = (void *) (__u64) ctx->data;  // (unsigned long) == (u64)
        data_end = (void *) (__u64) ctx->data_end;  // This should point to payload end because bpf_skb_change_tail internally linearizes the whole packet
        
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

        // Setup temp buffer for csum calc
        __u32 i_key = 0;  // index key
        struct rand_byte_buff_holder *rbbh = bpf_map_lookup_elem(&rand_byte_holder_map_eg, &i_key);
        if (!rbbh) {
            bpf_printk("Failed at rbb.\n");
            return TC_ACT_SHOT;
        }

        __s64 tot_diff = 0;
        // __u32 len = pb;

        __u32 pb1 = pad_st->pad_bytes;
        if (pb1 > MAX_PAD) 
            pb1 = MAX_PAD;
        if (pb1 == 0)
            return TC_ACT_SHOT;

        if (tcp_payload_len & 1) {
            __u8 last = 0;
            if (bpf_skb_load_bytes(ctx, init_pkt_len - 1, &last, 1))  // last byte of actual payload
                return TC_ACT_SHOT;

            if (bpf_skb_load_bytes(ctx, init_pkt_len, rbbh->bytes, pb1)) {
                bpf_printk("Failed at load bytes rbbh 1.\n");
                return TC_ACT_SHOT;
            }
            
            // __u8 last = rbbh->bytes[0];
            // if (bpf_skb_load_bytes(ctx, init_pkt_len - 1, &last, 1) < 0) {
            //     bpf_printk("Failed load last payload byte\n");
            //     return TC_ACT_SHOT;
            // }

            __u8 pad0 = rbbh->bytes[0];
            // if (bpf_skb_load_bytes(ctx, init_pkt_len, &pad0, 1) < 0)
            //     return TC_ACT_SHOT;

            // __u8 oldb[2] = { last, 0x00 };
            // __u8 newb[2] = { last, pad0 };
            // bpf_csum_diff only accepts multiples of 4 for length param
            __be32 old32 = bpf_htonl(((__u32)last << 24) | ((__u32)0x00 << 16));
            __be32 new32 = bpf_htonl(((__u32)last << 24) | ((__u32)pad0 << 16));
            
            tot_diff = bpf_csum_diff(&old32, 4, &new32, 4, 0);
            if (tot_diff < 0) {
                bpf_printk("Failed bridge diff\n");
                return TC_ACT_SHOT;
            }

            tot_diff = csum_diff_u8_buf(&rbbh->bytes[1], pb1 - 1, (__u32)tot_diff);

        } else {
            if (bpf_skb_load_bytes(ctx, init_pkt_len, rbbh->bytes, pb1)) {
                bpf_printk("Failed at load bytes rbbh 2.\n");
                return TC_ACT_SHOT;
            }
            tot_diff = csum_diff_u8_buf(rbbh->bytes, pb1, 0);
        }

        if (tot_diff < 0) {
            bpf_printk("Failed at tot_diff\n");
            return TC_ACT_SHOT;
        }

        // __s64 d2 = bpf_csum_diff(0, 0, (__be32 *)&mtail, sizeof(mtail), (__u32)tot_diff);  // sizeof(mtail) = 4
        // if (d2 < 0) {
        //     bpf_printk("Failed at d2.\n");
        //     return TC_ACT_SHOT;
        // }
        // tot_diff = d2;
        
        /* If hardware checksum offload is enabled */
        // Different code here  // NTC THIS PATH TOO AS IT COULD BE FASTER

        /* If hardware checksum offload is disabled */
        // L3-IP checksum replace
        if (bpf_l3_csum_replace(ctx, offsetof(struct iphdr, check), bpf_htons(ip_len), bpf_htons(new_ip_len), 2)) {
            // Failed because bpf_l3_csum_replace returns 0 if success
            bpf_printk("Something went wrong with IP l3_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP PAYLOAD checksum replace
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), 0, (__u64)tot_diff, 0)) {
            // Failed because bpf_l4_csum_replace returns 0 if success
            bpf_printk("Something went wrong with PAYLOAD l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP SEQ checksum replace
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), curr_seq_num, translated_seq_num, 4)) {  // all network-byte order
            bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
            return TC_ACT_SHOT;
        }
        // L4-TCP PSEUDO-header (Pseudo-IP) checksum replace
        __u16 old_tcp_len = ip_len - ip_hl;
        __u16 new_tcp_len = new_ip_len - ip_hl;
        if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), bpf_htons(old_tcp_len), bpf_htons(new_tcp_len), BPF_F_PSEUDO_HDR | 2)) {  // Change specifically for the Pseudo-header of TCP
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
            __be32 mdf_seq = seq_egress_info->seq_egress;
            // Check if the current packet is retransmit
            if (highest_sent_data_len && !(tcp->seq < highest_sent_data_len)) { 
                tcp->seq = mdf_seq;
                translated_seq_num = mdf_seq;
                struct seq_egress_info nxt_seq_val = {
                    .seq_egress = bpf_htonl(bpf_ntohl(mdf_seq) + tcp_payload_len),
                };
                bpf_map_update_elem(&seq_egress_fix, &seq_egress_key, &nxt_seq_val, BPF_ANY);
                // L4-TCP SEQ checksum replace
                if (bpf_l4_csum_replace(ctx, ip_hl + offsetof(struct tcphdr, check), curr_seq_num, translated_seq_num, 4)) {  // all network-byte order
                    bpf_printk("Something went wrong with TCP->SEQ l4_csum_replace().\n");
                    return TC_ACT_SHOT;
                }
            }
        } // else: first ever packet of this flow that doesn't have enough space to pad
        
        // TCP ACK FIX 
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";