// SPDX-License-Identifier: GPL-2.0
/*
 * rcu_tasks_deadlock.c  —  userspace loader
 *
 * Build:  make
 * Run:    sudo ./rcu_tasks_deadlock
 *
 * Loads and attaches the BPF program that triggers the RCU Tasks Trace /
 * timer-base-lock deadlock.  The kernel will hang when the deadlock fires.
 * Run only inside a VM.
 */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "rcu_tasks_deadlock.skel.h"

static volatile int exiting;

static void handle_sig(int sig)
{
	exiting = 1;
}

static int libbpf_quiet(enum libbpf_print_level level,
			const char *fmt, va_list ap)
{
	if (level <= LIBBPF_WARN)
		return vfprintf(stderr, fmt, ap);
	return 0;
}

int main(void)
{
	struct rcu_tasks_deadlock_bpf *skel;
	int err;

	libbpf_set_print(libbpf_quiet);

	signal(SIGINT,  handle_sig);
	signal(SIGTERM, handle_sig);

	skel = rcu_tasks_deadlock_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load BPF object: %s\n",
			strerror(errno));
		return 1;
	}

	err = rcu_tasks_deadlock_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach programs: %d\n", err);
		goto out;
	}

	fprintf(stderr,
		"BPF program attached.  Triggering deadlock...\n"
		"WARNING: the kernel will hang when the deadlock fires.\n"
		"Ctrl-C to detach before that happens.\n\n");

	while (!exiting)
		pause();

out:
	rcu_tasks_deadlock_bpf__destroy(skel);
	return err ? 1 : 0;
}
