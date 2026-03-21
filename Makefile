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
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m \
             | sed 's/x86_64/x86/' \
             | sed 's/aarch64/arm64/' \
             | sed 's/powerpc64le/powerpc/')

BPF_OBJ := $(OUTPUT)/rcu_tasks_deadlock.bpf.o
SKEL_H  := $(OUTPUT)/rcu_tasks_deadlock.skel.h
BIN     := rcu_tasks_deadlock

LIBBPF_LDFLAGS := -lbpf -lelf -lz

BPF_CFLAGS := \
	-g -O2 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/x86_64-linux-gnu

USER_CFLAGS := \
	-g -Wall \
	-I$(OUTPUT)

.PHONY: all clean

all: $(BIN)

$(OUTPUT):
	mkdir -p $@

$(BPF_OBJ): rcu_tasks_deadlock.bpf.c | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_OBJ) | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

$(BIN): rcu_tasks_deadlock.c $(SKEL_H)
	$(CC) $(USER_CFLAGS) -o $@ $< $(LIBBPF_LDFLAGS)

clean:
	rm -rf $(OUTPUT) $(BIN)
