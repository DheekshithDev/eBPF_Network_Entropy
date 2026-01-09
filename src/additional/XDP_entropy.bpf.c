//
// Created by DheekshithDev on 7/24/25.
//
/* If I am also doing full XDP where I fix the tot_len on ingress, then I would need to fix TCP Pseudo Header checksum and other checksums manually on XDP without any eBPF helpers */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>

#include <stdbool.h>


#define ETH_P_IP		0x0800
// #define IPPROTO_TCP		6
#define PAD_BYTES 100  // No need to define any hexadecimal or other data because I'm padding zeroes

// Header bytes 14 + 60 + 60 = 134; const max round-up safety for ringbuf reserve for verifier.
// #define MAX_HDR_COPY 160

// Ring buffer map
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24);  // 16 MB Buffer
// }rb SEC(".maps");
//
// struct pcap_record {
//     __u32 ts_sec;
//     __u32 ts_usec;
//     __u32 incl_len;
//     __u32 orig_len;
//     __u8 data[];
// };

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

    // bpf_printk("The packet is TCP-IPv4!");
    return true;
}

SEC("xdp")
int xdp_padding(struct xdp_md *ctx) {
    __u32 l3_len_or_mtu;

    // Number of bytes I want to capture from the TCP header
    // const int tcp_header_bytes = sizeof(struct tcphdr);  // = 32; // I only need 8 bytes since I am only grabbing TCP_SEQ_NUM

    // Pointers to packet data
    void *data = (void *) (unsigned long) ctx->data;
    void *data_end = (void *) (unsigned long) ctx->data_end;
    // Get current packet length
    __u32 init_pkt_size = data_end - data;

    // Grab ETH Header
    struct ethhdr *eth = data;
    if (!verifier_checker(eth + 1, data_end, 0)) {
        return XDP_ABORTED;
    }

    // Grab IP Header
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if (!verifier_checker(ip + 1, data_end, 0)) {
        return XDP_ABORTED;
    }

    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
        return XDP_PASS;
    }

    // Calculate IP Header length
    int ip_hdr_len = ip->ihl * 4;
    if (!verifier_checker(ip, data_end, ip_hdr_len)) {
        return XDP_ABORTED;
    }

    // Grab TCP Header
    struct tcphdr *tcp = (struct tcphdr *) ((void *) ip + ip_hdr_len); // not casting ip to (unsigned char *) as (void *) does the same on GNU-GCC and Clang but not ISO strict C.
    if (!verifier_checker(tcp + 1, data_end, 0)) {
        return XDP_ABORTED;
    }

    if (tcp->doff < 5) {  // Malformed TCP header
        return XDP_ABORTED;
    }

    // Calculate TCP Header length
    int tcp_hdr_len = tcp->doff * 4;
    if (!verifier_checker(tcp, data_end, tcp_hdr_len)) {
        return XDP_ABORTED;
    }

    // Don't touch SSH traffic for remote VM
    if (tcp->dest == bpf_htons(22) || tcp->source == bpf_htons(22)) {
        // bpf_printk("Bypassing SSH traffic (port 22)");
        return XDP_PASS;
    }

    // CODE FOR ACCURATE PADDING OR SHRINKING BY GRABBING ROUTE MTU
    // struct bpf_fib_lookup fib = {};
    //
    // long r = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0); // Not using BPF_FIB_LOOKUP_DIRECT as a flag
    //
    // if (r) {  // if r is not 0 and failed
    //
    // }
    //
    // __u32 mtu = fib.mtu;

    l3_len_or_mtu = 0;
    int r = bpf_check_mtu(ctx, 0, &l3_len_or_mtu, +PAD_BYTES, 0);

    if (r < 0) {
        bpf_printk("There is an Error with check MTU!");
        return XDP_ABORTED;
    }

    bpf_printk("The init_pkt_size is: %u", init_pkt_size);
    bpf_printk("The MTU value is: %u", l3_len_or_mtu);

    if (init_pkt_size < l3_len_or_mtu) {  // I can pad since there is space
         __u32 pad_bytes = (l3_len_or_mtu - init_pkt_size);

        bpf_printk("Pad Bytes: %u", pad_bytes);

        // Might need to check bpf_check_mtu() again here.

        // This function itself will memset with 0 for the adjusted tail pointer; if not I'll have to use __builtin_memset() with zeroes.
        // This function also checks xdp_hard_end-tail room so I don't have to check it myself.
        if (bpf_xdp_adjust_tail(ctx, pad_bytes) < 0) {
            bpf_printk("Unable to add padding to the correct packet");
            return XDP_ABORTED;
        }

        // DO VERIFIER POINTER ARITHMETIC CHECKS AGAIN
        data = (void *)(unsigned long)ctx->data;
        data_end = (void *)(unsigned long)ctx->data_end;
        // Get modified packet length
        __u32 mdf_pkt_size = data_end - data;

        if (!verifier_checker(data, data_end, mdf_pkt_size)) {
            return XDP_ABORTED;
        }

        eth = data;
        if (!verifier_checker(eth + 1, data_end, 0)) {
            return XDP_ABORTED;
        }

        ip = (struct iphdr *)(eth + 1);
        if (!verifier_checker(ip + 1, data_end, 0)) {
            return XDP_ABORTED;
        }

        ip_hdr_len = ip->ihl * 4;
        if (!verifier_checker(ip, data_end, ip_hdr_len)) {
            return XDP_ABORTED;
        }

        tcp = (struct tcphdr *)((void *)ip + ip_hdr_len); // not casting ip to (unsigned char *) as (void *) does the same on GNU-GCC and Clang but not ISO strict C.
        if (!verifier_checker(tcp + 1, data_end, 0)) {
            return XDP_ABORTED;
        }

        tcp_hdr_len = tcp->doff * 4;
        if (!verifier_checker(tcp, data_end, tcp_hdr_len)) {
            return XDP_ABORTED;
        }

        __u32 all_hdr_lens = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
        if (!verifier_checker(data, data_end, all_hdr_lens)) {
            return XDP_ABORTED;
        }

        // CAN USE THIS INSTEAD OF bpf_ringbuf_reserve and bpf_ringbuf_submit
        // int ret = bpf_ringbuf_output(ringbuf_space, tcp, tcp_header_bytes, 0);

        // // Get current time
        // __u64 now_ns = bpf_ktime_get_ns();
        //
        // // Reserve space in ring buffer
        // struct pcap_record *ringbuf_rec = bpf_ringbuf_reserve(&rb, sizeof(struct pcap_record) + MAX_HDR_COPY, 0);
        // if (!ringbuf_rec) {
        //     return XDP_PASS;  // If ringbuf reservation fails, skip processing this packet
        // }
        //
        // ringbuf_rec->ts_sec = now_ns / 1000000000ULL;
        // ringbuf_rec->ts_usec = (now_ns % 1000000000ULL) / 1000;
        // ringbuf_rec->incl_len = all_hdr_lens;
        // ringbuf_rec->orig_len = mdf_pkt_size;
        //
        // // Copy TCP header bytes into the ringbuf without using a verifier-friendly loop // Using full TCP header size but I don't need all, I just need TCP_SEQ_NUM
        // // __builtin_memcpy(ringbuf_rec->data, data, all_hdr_lens);
        // // bpf_probe_read_kernel(ringbuf_rec->data, all_hdr_lens, data);
        // if (bpf_xdp_load_bytes(ctx, 0, ringbuf_rec->data, all_hdr_lens) < 0) {
        //     bpf_ringbuf_discard(ringbuf_rec, 0);
        //     bpf_printk("There is an Error with load bytes. Discarded ringbuf.");
        //     return XDP_PASS;
        // }
        //
        // // Submit data to ring buffer
        // bpf_ringbuf_submit(ringbuf_rec, 0);

        bpf_printk("Packet padded successfully with zeroes!");

    } else if (init_pkt_size >= l3_len_or_mtu) {  // I can't pad since packet size is already > or = interface MTU.
        // I SHOULD SHRINK LIKE THE OTHER METHOD HERE
        bpf_printk("Packer size too large to pad!");
        return XDP_PASS;
    }

    return XDP_PASS;

}

// Force only TCP and IPv4 connections on main interface  ## METHOD 2 - Hard

char __license[] SEC("license") = "GPL";
/* If I am also doing full XDP where I fix the tot_len on ingress, then I would need to fix TCP Pseudo Header checksum and other checksums manually on XDP without any eBPF helpers */