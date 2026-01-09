//
// Created by ArthurK-5080 on 8/11/2025.
//
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "TC_entropy.bpf.skel.h"  // Generated skeleton header with Clang


#define PKT_COUNT 1000  // Only for 1000 packets


static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv) {
    struct TC_entropy_bpf *skel;
    bool hook_created = false;
    int ifindex, err = 0;

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
    skel = TC_entropy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }

    // Load and Verify BPF programs
    err = TC_entropy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify skel %d\n", err);
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
    while(!exiting && i <= PKT_COUNT) {
        fprintf(stderr, "*********");
        sleep(2);
        i++;
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
    TC_entropy_bpf__destroy(skel);
    printf("Successfully destroyed TC-Egress program!\n");
    return -err;
}