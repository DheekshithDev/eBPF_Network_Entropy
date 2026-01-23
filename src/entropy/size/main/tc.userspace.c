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

#include "tc_egress.bpf.skel.h"  // Generated skeleton header with Clang

#define PKT_COUNT 1000  // Only for 1000 iterations (not packets)
#define DEVICE_MTU 1500  // I always need to verify the device's MTU prior for this program to work perfectly
#define MAX_PAD (DEVICE_MTU)

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
}

struct rand_byte_buff {
    __u8 bytes[MAX_PAD];
};
// int create_rand_bytes_array() {
//     int fd;
//     LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);

//     fd = bpf_map_create(BPF_MAP_TYPE_ARRAY,
//                         "rand_buff",       /* name */
//                         sizeof(__u32),         /* key size */
//                         sizeof(struct rand_byte_buff),          /* value size */
//                         1,                   /* max entries */
//                         &opts);                /* create opts */
//     return fd;
// }

static __u64 nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

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
    struct tc_egress_bpf *skel = NULL;
    bool hook_created = false;
    int ifindex, err = 0;
    int fd = -1;

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

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

    // Open BPF application
    skel = tc_egress_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }

    // Load and Verify BPF programs
    err = tc_egress_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify skel %d\n", err);
        goto cleanup;
    }

    // Random bytes code
    fd = bpf_map__fd(skel->maps.rand_byte_map);
    if (fd < 0) {err = 1; goto cleanup;}
    if (initialize_array(fd) != 0) {
        err = 1;
        goto cleanup;
    }

    err = bpf_tc_hook_create(&tc_hook);
    if (!err)
        hook_created = true;
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_egress);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC: %d\n", err);
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached TC-Egress program! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF program.\n");

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

    /* End */
    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to detach TC: %d\n", err);
        goto cleanup;
    }

cleanup:
    if (hook_created)
        bpf_tc_hook_destroy(&tc_hook);
    if (skel) tc_egress_bpf__destroy(skel);
    printf("Successfully destroyed TC-Egress program!\n");
    return -err;
}