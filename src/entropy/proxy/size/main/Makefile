# Makefile for TC — build and clean

BPF_SRCS   := tc_ingress_proxy.bpf.c tc_egress_proxy.bpf.c
USER_SRC   := tc_proxy.userspace.c

BPF_OBJS   := $(BPF_SRCS:.bpf.c=.bpf.o)

BPF_COMBINED := tc_proxy.bpf.o
SKEL_HDR   := tc_proxy.bpf.skel.h

USER_OBJ   := $(USER_SRC:.c=.o)
USER_BIN   := tc_proxy_run

CLANG      ?= clang
GCC        ?= gcc
CFLAGS     ?= -O2 -g
INCLUDES   := -I . -I ../../../../../include  # Need to change this everytime

# libbpf cflags/libs
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

# Extra libs needed by libbpf
EXTRA_LIBS := -lelf -lz

all: $(SKEL_HDR) $(USER_BIN)

# Build eBPF object
%.bpf.o: %.bpf.c tc_proxy.h
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $< -o $@

# Static linking
$(BPF_COMBINED): $(BPF_OBJS)
	bpftool gen object $@ $^

# Generate skeleton header
$(SKEL_HDR): $(BPF_COMBINED)
	bpftool gen skeleton $< > $@

# Build userspace object
$(USER_OBJ): $(USER_SRC) $(SKEL_HDR)
	$(GCC) $(CFLAGS) $(INCLUDES) $(LIBBPF_CFLAGS) -c $< -o $@

# Link userspace binary (order matters: objects first, then libs)
$(USER_BIN): $(USER_OBJ)
	$(GCC) $(CFLAGS) -o $@ $^ $(LIBBPF_LIBS) $(EXTRA_LIBS)

clean:
	rm -f $(BPF_OBJS) $(BPF_COMBINED) $(USER_OBJ) $(SKEL_HDR) $(USER_BIN)

.PHONY: all clean
