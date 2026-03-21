// SPDX-License-Identifier: GPL-2.0
/*
 * rcu_tasks_deadlock.c  —  userspace loader
 *
 * Build:  make
 * Run:    sudo ./rcu_tasks_deadlock
 *
 * Loads and attaches the BPF program that triggers the RCU Tasks Trace /
 * timer-base-lock deadlock.  Polls the per-CPU done map and exits when
 * call_rcu_tasks_trace() has completed on at least one CPU without
 * deadlocking.  If the system freezes instead, the deadlock fired.
 */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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
	int ncpus, done_fd, err = 0;
	__u64 *values;
	__u32 key = 0;

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

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		fprintf(stderr, "libbpf_num_possible_cpus: %d\n", ncpus);
		err = ncpus;
		goto out;
	}

	values = calloc(ncpus, sizeof(*values));
	if (!values) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		err = -ENOMEM;
		goto out;
	}

	int *reported = calloc(ncpus, sizeof(*reported));
	if (!reported) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		free(values);
		err = -ENOMEM;
		goto out;
	}

	done_fd = bpf_map__fd(skel->maps.done);

	fprintf(stderr,
		"BPF program attached.  Waiting for all %d CPUs to report...\n"
		"If the system freezes, the deadlock fired.\n"
		"Ctrl-C to detach.\n\n", ncpus);

	int ndone = 0;

	while (!exiting) {
		usleep(100 * 1000); /* 100 ms */

		if (bpf_map_lookup_elem(done_fd, &key, values) < 0)
			continue;

		for (int cpu = 0; cpu < ncpus; cpu++) {
			if (reported[cpu] || !values[cpu])
				continue;
			printf("CPU %d: call_rcu_tasks_trace() returned "
			       "(no deadlock) — triggered by pid %llu\n",
			       cpu, values[cpu] - 1);
			reported[cpu] = 1;
			ndone++;
		}

		if (ndone == ncpus)
			break;
	}

	if (ndone == ncpus)
		printf("\nAll %d CPUs reported no deadlock.\n", ncpus);

	free(reported);
	free(values);
out:
	rcu_tasks_deadlock_bpf__destroy(skel);
	return err ? 1 : 0;
}
