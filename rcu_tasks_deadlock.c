// SPDX-License-Identifier: GPL-2.0
/*
 * rcu_tasks_deadlock.c  —  userspace loader / event reporter
 *
 * Build:  make
 * Run:    sudo ./rcu_tasks_deadlock
 *
 * Interesting output:
 *
 *   EV_LOCK_WINDOW   mod_timer() was called from call_rcu_tasks_generic()
 *                    while rtpcp->lock is held; we deleted a task storage
 *                    element to trigger call_rcu_tasks_trace() from there.
 *
 *   EV_DEADLOCK_IMMI call_rcu_tasks_trace() was entered reentrant while
 *                    rtpcp->lock is already held on this CPU.  The next
 *                    raw_spin_lock(rtpcp) will spin forever.
 *                    The kernel will likely hang after this message.
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

#define EV_LOCK_WINDOW   1
#define EV_DEADLOCK_IMMI 2

struct event {
	__u32 type;
	__u32 cpu;
	__u32 pid;
	char  comm[16];
};

static volatile int exiting;

static void handle_sig(int sig)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	const struct event *e = data;

	switch (e->type) {
	case EV_LOCK_WINDOW:
		printf("[CPU %-2u  pid %-6u  %-16s]  mod_timer() called while "
		       "rtpcp->lock is held\n"
		       "                                   "
		       "-> bpf_task_storage_delete() will call "
		       "call_rcu_tasks_trace() ...\n",
		       e->cpu, e->pid, e->comm);
		break;

	case EV_DEADLOCK_IMMI:
		printf("[CPU %-2u  pid %-6u  %-16s]  *** DEADLOCK IMMINENT ***\n"
		       "                                   "
		       "call_rcu_tasks_trace() entered while rtpcp->lock "
		       "already held on this CPU.\n"
		       "                                   "
		       "raw_spin_trylock(rtpcp) will fail;\n"
		       "                                   "
		       "raw_spin_lock(rtpcp) will spin forever.\n",
		       e->cpu, e->pid, e->comm);
		fflush(stdout);
		break;

	default:
		fprintf(stderr, "unknown event type %u\n", e->type);
	}

	return 0;
}

/* Suppress debug-level libbpf chatter; keep warnings. */
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
	struct ring_buffer *rb;
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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			      handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		goto out;
	}

	fprintf(stderr,
		"Probing for RCU tasks-trace deadlock.\n"
		"  Watching : mod_timer() called from call_rcu_tasks_generic()\n"
		"  Canary   : reentrant call_rcu_tasks_trace() while lock held\n"
		"\n"
		"  WARNING  : EV_DEADLOCK_IMMI means the kernel will hang.\n"
		"             Run only inside a VM / throwaway environment.\n"
		"\n"
		"Ctrl-C to stop.\n\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 200 /* ms timeout */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring_buffer__poll: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
out:
	rcu_tasks_deadlock_bpf__destroy(skel);
	return err ? 1 : 0;
}
