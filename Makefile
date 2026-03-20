# SPDX-License-Identifier: GPL-2.0
#
# Prerequisites:
#   clang, bpftool, libbpf-dev
#
# Usage:
#   make
#   sudo ./rcu_tasks_deadlock

OUTPUT  := .output
CLANG   ?= clang
ARCH    := $(shell uname -m \
             | sed 's/x86_64/x86/' \
             | sed 's/aarch64/arm64/' \
             | sed 's/powerpc64le/powerpc/')

VMLINUX_H := $(OUTPUT)/vmlinux.h
BPF_OBJ   := $(OUTPUT)/rcu_tasks_deadlock.bpf.o
SKEL_H    := $(OUTPUT)/rcu_tasks_deadlock.skel.h
BIN       := rcu_tasks_deadlock

LIBBPF_CFLAGS  :=
LIBBPF_LDFLAGS := -lbpf -lelf -lz

# vmlinux.h provides all kernel types (including __u64) for the BPF program.
# It must be generated before the BPF source is compiled, hence the explicit
# dependency below.
BPF_CFLAGS := \
	-g -O2 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I$(OUTPUT) \
	-I/usr/include/x86_64-linux-gnu

USER_CFLAGS := \
	-g -Wall \
	-I$(OUTPUT) \
	$(LIBBPF_CFLAGS)

.PHONY: all clean

all: $(BIN)

$(OUTPUT):
	mkdir -p $@

# Generate vmlinux.h from the running kernel's BTF.
# This must happen before $(BPF_OBJ) is built.
$(VMLINUX_H): | $(OUTPUT)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program.  Explicit dependency on $(VMLINUX_H) ensures it is
# generated first so that #include "vmlinux.h" resolves.
$(BPF_OBJ): rcu_tasks_deadlock.bpf.c $(VMLINUX_H) | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate libbpf skeleton.
$(SKEL_H): $(BPF_OBJ) | $(OUTPUT)
	bpftool gen skeleton $< > $@

# Compile userspace loader.
$(BIN): rcu_tasks_deadlock.c $(SKEL_H)
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBBPF_LDFLAGS)

clean:
	rm -rf $(OUTPUT) $(BIN)
