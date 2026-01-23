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