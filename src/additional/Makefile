# Makefile for TC — build and clean

BPF_SRC    := TC_entropy.bpf.c
USER_SRC   := TC_entropy.userspace.c

BPF_OBJ    := $(BPF_SRC:.c=.o)
USER_OBJ   := $(USER_SRC:.c=.o)
SKEL_HDR   := $(basename $(BPF_SRC)).skel.h
USER_BIN   := tc_run_additional

CLANG      ?= clang
GCC        ?= gcc

# Common flags
CFLAGS     ?= -O2 -g
INCLUDES   := -I . -I ../../include

# libbpf cflags/libs
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

# libpcap cflags/libs (try libpcap, then pcap; fall back to -lpcap)
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null || pkg-config --cflags pcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null || pkg-config --libs pcap 2>/dev/null || echo -lpcap)

# Extra libs needed by libbpf
EXTRA_LIBS := -lelf -lz

all: $(USER_BIN)

# Build eBPF object
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $< -o $@

# Generate skeleton header
$(SKEL_HDR): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# Build userspace object
$(USER_OBJ): $(USER_SRC) $(SKEL_HDR)
	$(GCC) $(CFLAGS) $(INCLUDES) $(LIBBPF_CFLAGS) $(PCAP_CFLAGS) -c $< -o $@

# Link userspace binary (order matters: objects first, then libs)
$(USER_BIN): $(USER_OBJ)
	$(GCC) $(CFLAGS) -o $@ $^ $(LIBBPF_LIBS) $(PCAP_LIBS) $(EXTRA_LIBS)

clean:
	rm -f $(BPF_OBJ) $(USER_OBJ) $(SKEL_HDR) $(USER_BIN)

.PHONY: all clean
