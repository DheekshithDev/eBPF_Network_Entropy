#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tc_proxy.bpf.skel.h"  // Generated skeleton header with Clang

#define PKT_COUNT 1000  // Only for 1000 iterations (not packets)
#define DEVICE_MTU 1500  // I always need to verify the device's MTU prior for this program to work perfectly
#define MAX_PAD (DEVICE_MTU)

static volatile sig_atomic_t exiting = 0;
static void sig_int(int signo) {
    exiting = 1;
}

// // Userspace side data structures
// struct record {
//     __u16 tcp_checksum;
//     // __u32 orig_len;
//     __u32 pad_bytes;
// };

// static int handle_event(void *ctx, void *data, size_t data_sz) {
//     if (data_sz < sizeof(struct record)) {
//         // No data
//         fprintf(stderr, "No data to read error\n");
//         return 0;
//     }

//     const struct record *rec = data;

//     printf("The pad_bytes is: %u\n", rec->pad_bytes);
//     printf("The original checksum is: 0x%04x\n", rec->tcp_checksum);

//     return 0;
// }

static __u64 nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

struct rand_byte_buff {
    __u8 bytes[MAX_PAD];
};

static ssize_t getrandom_full(void *buff, size_t len) {
    uint8_t *p = buff;
    size_t off = 0;

    while (off < len) {
        ssize_t n = getrandom(p + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

int initialize_array(int fd) {
    __u32 key = 0;
    struct rand_byte_buff val;
    if (getrandom_full(&val, sizeof(val)) < 0) {
        fprintf(stderr, "Failed at getrandom(): %s\n", strerror(errno));
        return -1;
    }
    if (bpf_map_update_elem(fd, &key, &val, BPF_EXIST) < 0) {
        fprintf(stderr, "Failed at bpf_map_update_elem(): %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    // struct ring_buffer *rb = NULL;
    struct tc_proxy_bpf *skel = NULL;
    int ifindex, err = 0;
    int fd = -1;
    bool hook_in_created = false, hook_eg_created = false;
    bool in_attached = false, eg_attached = false;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    // Open BPF application
    skel = tc_proxy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }

    // Load and Verify BPF programs
    err = tc_proxy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify skel %d\n", err);
        goto cleanup;
    }

    /* INGRESS hook */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_in, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    err = bpf_tc_hook_create(&hook_in);
    if (!err)
        hook_in_created = true;
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC Ingress Hook: %d\n", err);
        goto cleanup;
    }
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opt_in, .handle = 1, .priority = 1);
    opt_in.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    err = bpf_tc_attach(&hook_in, &opt_in);
    if (err) {
        fprintf(stderr, "Failed to attach TC Ingress: %d\n", err);
        goto cleanup;
    }
    in_attached = true;

    /* EGRESS hook */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook_eg, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    err = bpf_tc_hook_create(&hook_eg);
    if (!err)
        hook_eg_created = true;
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC Egress Hook: %d\n", err);
        goto cleanup;
    }
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opt_eg, .handle = 1, .priority = 1);
    opt_eg.prog_fd = bpf_program__fd(skel->progs.tc_egress);
    err = bpf_tc_attach(&hook_eg, &opt_eg);
    if (err) {
        fprintf(stderr, "Failed to attach TC Egress: %d\n", err);
        goto cleanup;
    }
    eg_attached = true;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    // Random bytes code
    fd = bpf_map__fd(skel->maps.rand_byte_map);
    if (fd < 0) {err = 1; goto cleanup;}
    if (initialize_array(fd) != 0) {
        err = 1;
        goto cleanup;
    }

    printf("Successfully attached TC program! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF program.\n");
           
    // // Setup the ring buffer
    // rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    // if (!rb) {
    //     fprintf(stderr, "Failed to create rb\n");
    //     err = -1;
    //     goto cleanup;
    // }
    
    // printf("Start polling the ring buffer\n");
    
    // // Ring buffer poll
    // int i = 0;
    // while (i <= PKT_COUNT) {
    //     err = ring_buffer__poll(rb, -1); // No timeout
    
    //     if (err == -EINTR) continue;
    
    //     if (err < 0) {
    //         fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
    //         break;
    //     }
    //     i++;
    // }

    /* Loop to stop program from terminating */
    int i = 0;
    __u64 init_time = nsec_now();
    __u64 curr_time = 0;
    while(!exiting && i < PKT_COUNT) {
        fprintf(stderr, "*********\n");
        sleep(2);  // Need to remove this in production
        i++;
        curr_time = nsec_now();
        if (curr_time - init_time > 10ull * 1000000000ull) {
            if (initialize_array(fd) == 0) {
                init_time = curr_time; 
            }
        }
    }

cleanup:
    // if (rb) ring_buffer__free(rb);
    if (in_attached) {
        opt_in.prog_fd = 0;
        opt_in.prog_id = 0;
        opt_in.flags = 0;
        int derr = bpf_tc_detach(&hook_in, &opt_in);
        if (derr)
            fprintf(stderr, "Warning: failed to detach ingress: %d\n", derr);
    }

    if (eg_attached) {
        opt_eg.prog_fd = 0;
        opt_eg.prog_id = 0;
        opt_eg.flags = 0;
        int derr = bpf_tc_detach(&hook_eg, &opt_eg);
        if (derr)
            fprintf(stderr, "Warning: failed to detach egress: %d\n", derr);
    }

    if (hook_in_created) {
        int derr = bpf_tc_hook_destroy(&hook_in);
        if (derr)
            fprintf(stderr, "Warning: failed to destroy ingress hook: %d\n", derr);
    }

    if (hook_eg_created) {
        int derr = bpf_tc_hook_destroy(&hook_eg);
        if (derr)
            fprintf(stderr, "Warning: failed to destroy egress hook: %d\n", derr);
    }

    tc_proxy_bpf__destroy(skel);
    return err ? 1 : 0;
}