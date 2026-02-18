            // Bounded loop (can use bpf_loop if it is faster)
            // for (int i = 0; i < max_load; i = i + 4) {
            //     u32 remain = max_load - i;
            //     u32 rnd = bpf_get_prandom_u32();  // 4 bytes
            //     u32 off = init_pkt_len + i;
            //     if (remain >= 4) {
            //         bpf_skb_store_bytes(ctx, off, &rnd, 4, 0);
            //         // tail[i + 0] = rnd & 0xff;
            //         // tail[i + 1] = (rnd >> 8) & 0xff;
            //         // tail[i + 2] = (rnd >> 16) & 0xff;
            //         // tail[i + 3] = (rnd >> 24) & 0xff;
            //     } 
            //     // else {
            //     //     if (remain >= 1) tail[i + 0] = rnd & 0xff;
            //     //     if (remain >= 2) tail[i + 1] = (rnd >> 8) & 0xff;
            //     //     if (remain >= 3) tail[i + 2] = (rnd >> 16) & 0xff;
            //     // }
            // }


// NTC if pad_bytes being a non-multiple of 4 throws an error:
// 1. can try rounding up pad_bytes only for checksum calculation (might lead to reading beyond data_end).
// 2. can make pad_bytes a multiple of 4 mainly.
// 3. can leave few bytes as 0 without random padding as 0s won't contribute to checksum and shift orig_len encoding from last 4 bytes to before.
        


/* Encode original length to the last 4 bytes of the payload */
// u8 *last4 = (u8 *)data_end - 4;  // Hoping data_end is linearized
// // u8 *last4 = (u8 *)data + (mdf_pkt_len - 4);
// if (!verifier_checker(last4, data_end, 4))
//     return TC_ACT_SHOT;
// __builtin_memcpy(last4, &pad_bytes, 4); 

// static __always_inline __s64 csum_diff_u8_buf(const __u8 *buf, __u32 len, __u32 seed) { 
// __u32 n4 = len & ~3u; // multiple of 4 // __u32 rem = len & 3u; // 0..3 // __s64 diff = 0; 
// if (n4) { // diff = bpf_csum_diff(0, 0, (__be32 *)buf, n4, seed); // if (diff < 0) // return diff; 
// seed = (__u32)diff; // } // if (rem) { // __u32 last = 0; // zero-padded // if (rem >= 1) ((__u8 *)&last)[0] = buf[n4 + 0]; 
// if (rem >= 2) ((__u8 *)&last)[1] = buf[n4 + 1]; // if (rem >= 3) ((__u8 *)&last)[2] = buf[n4 + 2]; 
// diff = bpf_csum_diff(0, 0, (__be32 *)&last, 4, seed); // if (diff < 0) // return diff; // } // return diff; // }

    // __u32 off = 0;
    // __s64 diff = 0;

// #pragma unroll  // Loop for iterating in chunk sizes as bpf_csum_diff can't accept bytes > ~500
    // for (__u32 i = 0; i < MAX_CHUNKS; i++) {
    //     if (off >= len)
    //         break;

    //     __u32 n = len - off;
    //     if (n > CSUM_CHUNK)
    //         n = CSUM_CHUNK;

    //     n &= ~3u;  // multiple of 4; optional as I don't need it explicitly
    //     if (!n)
    //         break;

    //     diff = bpf_csum_diff(0, 0, (__be32 *)(buf + off), n, seed);  // initial seed is 0 always
    //     if (diff < 0)
    //         return diff;

    //     seed = (__u32)diff;
    //     off += n;
    // }

    // __u32 rem = len - off;
    // if (rem) {
    //     __u32 last = 0; // zero-padded
    //     if (rem >= 1) ((__u8 *)&last)[0] = buf[off + 0];
    //     if (rem >= 2) ((__u8 *)&last)[1] = buf[off + 1];
    //     if (rem >= 3) ((__u8 *)&last)[2] = buf[off + 2];

    //     diff = bpf_csum_diff(0, 0, (__be32 *)&last, 4, seed);
    //     if (diff < 0)
    //         return diff;
    // }
    // return diff;

    //     __u32 off = 0;
//     __s64 diff = 0;

// // #pragma unroll  // Loop for iterating in chunk sizes as bpf_csum_diff can't accept bytes > ~500
//     for (__u32 i = 0; i < MAX_CHUNKS; i++) {
//         if (off >= len)
//             break;

//         __u32 n = len - off;
//         if (n > CSUM_CHUNK)
//             n = CSUM_CHUNK;

//         n &= ~3u;  // multiple of 4; optional as I don't need it explicitly
//         if (!n)
//             break;

//         diff = bpf_csum_diff((__be32 *)(buf + off), n, 0, 0, seed);  // Subtract // initial seed is 0 always
//         if (diff < 0)
//             return diff;

//         seed = (__u32)diff;
//         off += n;
//     }

//     __u32 rem = len - off;
//     if (rem) {
//         __u32 last = 0; // zero-padded
//         if (rem >= 1) ((__u8 *)&last)[0] = buf[off + 0];
//         if (rem >= 2) ((__u8 *)&last)[1] = buf[off + 1];
//         if (rem >= 3) ((__u8 *)&last)[2] = buf[off + 2];

//         diff = bpf_csum_diff((__be32 *)&last, 4, 0, 0, seed);
//         if (diff < 0)
//             return diff;
//     }
//     return diff;