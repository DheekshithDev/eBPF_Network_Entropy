// /** XDP is only for fixing ACKs (not for fixing padding) **/
// SEC("xdp")
// int xdp_padding(struct xdp_md *ctx) {
//     /*****
//      * This XDP program is for fixing ACKs only (reverting ACKs to their original) to maintain TCP state due to padding done at TC-Egress.
//      * Padded packets travel on-wire to the remote and it acks the padded payload length too. Host stack doesn't know about the padding and since to maintain the state, this XDP program is designed.
//      *****/
//     // Pointers to packet data
//     void *data = (void *) (unsigned long) ctx->data;
//     void *data_end = (void *) (unsigned long) ctx->data_end;
//
//     // Get current packet length
//     __u32 init_pkt_size = data_end - data;
//
//     // Grab ETH Header
//     struct ethhdr *eth = data;
//     if (!verifier_checker(eth + 1, data_end, 0)) {
//         return XDP_DROP;
//     }
//
//     // Grab IP Header
//     struct iphdr *ip = (struct iphdr *) (eth + 1);
//     if (!verifier_checker(ip + 1, data_end, 0)) {
//         return XDP_DROP;
//     }
//
//     // Check if the packet is a TCP packet
//     if (!is_tcp_ipv4(data, data_end)) {
//         // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
//         return XDP_PASS;
//     }
//
//     if (ip->ihl < 5) {  // Malformed IP header
//         return XDP_DROP;
//     }
//
//     // Calculate IP Header length
//     int ip_hl = ip->ihl * 4;
//     if (!verifier_checker(ip, data_end, ip_hl)) {
//         return XDP_DROP;
//     }
//
//     // Grab TCP Header
//     struct tcphdr *tcp = (struct tcphdr *) ((void *) ip + ip_hl);
//     if (!verifier_checker(tcp + 1, data_end, 0)) {
//         return XDP_DROP;
//     }
//
//     if (tcp->doff < 5) {  // Malformed TCP header
//         return XDP_DROP;
//     }
//
//     // Calculate TCP Header length
//     int tcp_hl = tcp->doff * 4;
//     if (!verifier_checker(tcp, data_end, tcp_hl)) {
//         return XDP_DROP;
//     }
//
//     /** ACK Fix Ingress - START **/
//     // Need packets with a pure ACK or ACK w.payload only
//     bool has_ack = tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst;
//
//     if (has_ack) {
//         // Access LRU map
//         struct flow key = {
//             .saddr = ip->daddr,
//             .daddr = ip->saddr,
//             .sport = tcp->dest,
//             .dport = tcp->source,
//         };
//
//         struct ack_info *value_p = bpf_map_lookup_elem(&ack_map, &key);
//         if (!value_p) {
//             return XDP_PASS;
//         }
//
//         // Save old ACK value
//         __be32 orig_ack = tcp->ack_seq;
//         // Save new ACK value
//         __be32 fixed_ack = value_p->ack;
//
//         // Update with new ACK
//         tcp->ack_seq = fixed_ack;
//
//         /* Checksum fix for modified ACK - START */
//         __u64 csum_diff = bpf_csum_diff(&orig_ack, 4, &fixed_ack, 4, ~tcp->check);  // returns __s64 on success
//         if (csum_diff < 0) {
//             // bpf_csum_diff returns negative err code when fails
//             bpf_printk("Something went wrong with bpf_csum_diff().\n");
//             // From Documentation: "The XDP_ABORTED action is not something a functional program should ever use as a return code."
//             return XDP_ABORTED;  // Only use XDP_ABORTED when there is an eBPF program error.
//         }
//         tcp->check = ~(__be16)csum_diff;
//         /* Checksum fix for modified ACK - END */
//     }
//     /** ACK Fix Ingress - END **/
//     return XDP_PASS;
// }