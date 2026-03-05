#pragma once
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2  /* IPv4 code instead of importing */
// #define ETH_P_IP 0x0800  /* IPv4 packet */
#define TC_ACT_OK 0  /* Terminate the packet processing pipeline and allows the packet to proceed */
#define TC_ACT_SHOT 2  /* Terminate the packet processing pipeline and drops the packet */
#define DEVICE_MTU 1420u  // *CRITICAL*
#define MAX_PAD (DEVICE_MTU)
#define CLIENT_IP 0x0A000002  // "10.0.0.2" host-order
#define TARGET_SITE 0xC0002B08  // "192.0.43.8" IANA site host-order
#define TARGET_PORT 4443
#define RAND_BUF_SZ 2048u  // Only for verifier; actual sz = 1500
#define PAD_MAGIC16 0xA55A
/* Chunk-wise CSUM calc */
#define CSUM_CHUNK 500u   // multiple of 4
#define MAX_CHUNKS 3u     // 3*500 = 1500 coverage; 1500 is enough
/* Simple RC5 */
#define RC5_R 12u
#define RC5_T (2 * (RC5_R + 1))  // 16-bit words

_Static_assert(MAX_CHUNKS * CSUM_CHUNK >= MAX_PAD, "CSUM chunking too small. Failing!");

/*** DATA TYPES ***/
/* Tail for all *modified* packets */
struct pad_magic_tail {
    __be16 magic;
    __be16 pad_len;
} __attribute__((packed));

/*** BPF MAPS ***/
// Universal Key //
// struct flow {
//     // Network-order
//     __be32 saddr, daddr;
//     __be16 sport, dport;
// };

// /* LRU HashMap to fix ingress ACKs on current packet */
// struct ack_ingress_info {
//     __be32 ack_ingress;  // To fix ingress ACK to original
// };
// struct ack_ingress_fix_map {  // proxy egress gives this to me
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, 12292);
//     __type(key, struct flow);
//     __type(value, struct ack_ingress_info);
// };
// extern struct ack_ingress_fix_map ack_ingress_fix SEC(".maps");

// /* LRU HashMap to modify proxy egress ACKs */
// struct ack_egress_info {
//     __be32 ack_egress_orig;
//     __be32 ack_egress;
// };
// struct ack_egress_fix_map {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, 12292);
//     __type(key, struct flow);
//     __type(value, struct ack_egress_info);
// };
// extern struct ack_egress_fix_map ack_egress_fix SEC(".maps");

/* BPF_MAP_TYPE_PERCPU_ARRAY for storing pad_bytes */
struct pad_state {
    __u32 pad_bytes;
};
struct pad_state_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct pad_state);
};
extern struct pad_state_map pad_state_map SEC(".maps");

/*** FUNCTIONS ***/
/* Function for checking pointer arithmetic for verifier */
static __always_inline bool verifier_checker(void *data, void *data_end, __u32 need) {
    return data + need <= data_end;
}

/* Helper function to check if the packet is TCP and IPv4  ## METHOD 1 - Easy */
static __always_inline bool is_tcp_ipv4(void *data, void *data_end) {

    if (data + offsetof(struct iphdr, protocol) + 1 > data_end)
        return false;

    struct iphdr *ip = (struct iphdr *)data;
    // Only handle IPv4 packets
    if (ip->version != 4)
        return false;

    // Check if the protocol is TCP
    if ((ip->protocol) != IPPROTO_TCP) {
        return false;
    }

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

/* CSUM diff calculator for non-multiple of 4 lengths (in chunks)*/
static __always_inline __s64 csum_diff_u8_buf(const __u8 *buf, __u32 len, __u32 seed) {
    __s64 diff = seed;
    __u32 n;

    #if MAX_CHUNKS > 0
        n = len;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff(0, 0, (__be32 *)(buf + 0), n, (__wsum)diff);
            if (diff < 0) return diff;
        }
    #endif

    #if MAX_CHUNKS > 1
        // chunk 1
        n = (len > CSUM_CHUNK) ? (len - CSUM_CHUNK) : 0;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff(0, 0, (__be32 *)(buf + CSUM_CHUNK), n, (__wsum)diff);
            if (diff < 0) return diff;
        }
    #endif

    #if MAX_CHUNKS > 2
        // chunk 2
        n = (len > 2*CSUM_CHUNK) ? (len - 2*CSUM_CHUNK) : 0;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff(0, 0, (__be32 *)(buf + 2*CSUM_CHUNK), n, (__wsum)diff);
            if (diff < 0) return diff;
        }
    #endif

    __u32 n4 = (len & ~3u);      // last 4-aligned boundary
    __u32 rem = len & 3u;
    if (rem) {
        __u32 last = 0;
        if (rem >= 1) ((__u8 *)&last)[0] = buf[n4 + 0];
        if (rem >= 2) ((__u8 *)&last)[1] = buf[n4 + 1];
        if (rem >= 3) ((__u8 *)&last)[2] = buf[n4 + 2];
        diff = bpf_csum_diff(0, 0, (__be32 *)&last, 4, (__wsum)diff);
        if (diff < 0) return diff;
    }

    return diff;
}

/* CSUM SUBTRACT diff calculator for non-multiple of 4 lengths (in chunks) */
static __always_inline __s64 csum_sub_u8_buf(const __u8 *buf, __u32 len, __u32 seed) {  // Subtraction
    __s64 diff = seed;
    __u32 n;

    #if MAX_CHUNKS > 0
        n = len;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff((__be32 *)(buf + 0), n, 0, 0, (__wsum)diff);  // Subtract 
            if (diff < 0) return diff;
        }
    #endif

    #if MAX_CHUNKS > 1
        // chunk 1
        n = (len > CSUM_CHUNK) ? (len - CSUM_CHUNK) : 0;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff((__be32 *)(buf + CSUM_CHUNK), n, 0, 0, (__wsum)diff);
            if (diff < 0) return diff;
        }
    #endif

    #if MAX_CHUNKS > 2
        // chunk 2
        n = (len > 2*CSUM_CHUNK) ? (len - 2*CSUM_CHUNK) : 0;
        if (n > CSUM_CHUNK) n = CSUM_CHUNK;
        n &= ~3u;
        if (n) {
            diff = bpf_csum_diff((__be32 *)(buf + 2*CSUM_CHUNK), n, 0, 0, (__wsum)diff);
            if (diff < 0) return diff;
        }
    #endif

    // tail (0..3)
    __u32 n4 = (len & ~3u);      // last 4-aligned boundary
    __u32 rem = len & 3u;
    if (rem) {
        __u32 last = 0;
        if (rem >= 1) ((__u8 *)&last)[0] = buf[n4 + 0];
        if (rem >= 2) ((__u8 *)&last)[1] = buf[n4 + 1];
        if (rem >= 3) ((__u8 *)&last)[2] = buf[n4 + 2];
        diff = bpf_csum_diff((__be32 *)&last, 4, 0, 0, (__wsum)diff);
        if (diff < 0) return diff;
    }

    return diff;
}

/* RC5 */
static const __u16 rc5_S[RC5_T] = {
    0xDE08, 0xEC8C, 0x37ED, 0x6F24, 0x33A7, 0xE067, 0x378C, 0xA6B3, 0x6D6B, 
    0xFD5E, 0x186E, 0xB494, 0x4B53, 0x0550, 0xEFBF, 0x985A, 0x624A, 0xFC2E, 
    0xA169, 0x184C, 0xE193, 0x9DEB, 0xB685, 0x270B, 0x267F, 0x574D
};

static __always_inline __u16 rol16(__u16 x, __u16 r) {
    r &= 15;
    return (__u16)((x << r) | (x >> ((16 - r) & 15)));
}

static __always_inline __u16 ror16(__u16 x, __u16 r) {
    r &= 15;
    return (__u16)((x >> r) | (x << ((16 - r) & 15)));
}

static __always_inline void rc5_16_encrypt(__u16 *A, __u16 *B) {
    __u16 a = *A, b = *B;

    a = (__u16)(a + rc5_S[0]);
    b = (__u16)(b + rc5_S[1]);

#pragma unroll
    for (int i = 1; i <= RC5_R; i++) {
        a = (__u16)(rol16((__u16)(a ^ b), b) + rc5_S[2*i]);
        b = (__u16)(rol16((__u16)(b ^ a), a) + rc5_S[2*i + 1]);
    }

    *A = a; *B = b;
}

static __always_inline void rc5_16_decrypt(__u16 *A, __u16 *B) {
    __u16 a = *A, b = *B;

#pragma unroll
    for (int i = RC5_R; i > 0; i--) {
        b = (ror16((__u16)(b - rc5_S[2*i + 1]), a) ^ a);
        a = (ror16((__u16)(a - rc5_S[2*i]), b) ^ b);
    }

    b = (__u16)(b - rc5_S[1]);
    a = (__u16)(a - rc5_S[0]);

    *A = a; *B = b;
}