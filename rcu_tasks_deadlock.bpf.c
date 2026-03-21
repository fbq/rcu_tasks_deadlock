// SPDX-License-Identifier: GPL-2.0
/*
 * rcu_tasks_deadlock.bpf.c
 *
 * Triggers the RCU Tasks Trace / timer-base-lock deadlock:
 *   https://lore.kernel.org/rcu/ab1u-AuqIbJakUYW@tardis.local/
 *
 * Scenario (kernel/time/timer.c + kernel/rcu/tasks.h):
 *
 *   __mod_timer()
 *     lock_timer_base()
 *       raw_spin_lock_irqsave(&base->lock)   <- base->lock ACQUIRED
 *     trace_timer_start(timer, bucket_expiry) <- tp_btf/timer_start fires here
 *       [probe_timer_start BPF program]
 *         bpf_task_storage_delete()
 *           bpf_selem_unlink(selem, false)
 *             bpf_selem_free(false)
 *               call_rcu_tasks_trace()
 *                 call_rcu_tasks_generic()
 *                   mod_timer(lazy_timer)    <- lazy_timer on this CPU's base
 *                     lock_timer_base()
 *                       raw_spin_lock_irqsave(&base->lock) <- DEADLOCK
 *
 * WARNING: Run only inside a VM. The kernel will hang on deadlock.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct;

char LICENSE[] SEC("license") = "GPL";

/*
 * Timer flags from include/linux/timer.h.  We only want timers that use
 * the current CPU's standard (BASE_STD) timer base, which is the same base
 * that call_rcu_tasks_generic() uses for rtpcp->lazy_timer.
 *
 * TIMER_DEFERRABLE timers go to BASE_DEF (different lock -> no deadlock).
 * TIMER_PINNED timers may be pinned to a different CPU's base.
 * Skip both so we only instrument timers on the current CPU's STD base.
 */
#define TIMER_PINNED		0x00000001
#define TIMER_DEFERRABLE	0x00000002

/*
 * Minimal struct timer_list covering the fields we read.
 * preserve_access_index lets libbpf CO-RE adjust offsets at load time.
 */
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct timer_list {
	struct hlist_node	entry;
	unsigned long		expires;
	void			(*function)(struct timer_list *);
	unsigned int		flags;
} __attribute__((preserve_access_index));

/*
 * Per-CPU one-shot flag: set to 1 after we successfully delete task storage
 * on this CPU (i.e. after call_rcu_tasks_trace() has been triggered here).
 * Using PERCPU_ARRAY lets each CPU fire independently, so every CPU gets
 * one chance to trigger the deadlock.  Prevents re-entry from the
 * mod_timer() call inside call_rcu_tasks_generic() on the same CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} done SEC(".maps");

/*
 * Task local storage: deleted inside tp_btf/timer_start (while base->lock
 * is held) to reach call_rcu_tasks_trace() via:
 *   bpf_selem_unlink(selem, reuse_now=false) -> bpf_selem_free(false)
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} task_storage SEC(".maps");

/*
 * tp_btf/timer_start fires inside __mod_timer() after lock_timer_base()
 * has acquired base->lock with IRQs disabled.
 *
 * Create task storage and immediately delete it in the same invocation.
 * The delete reaches call_rcu_tasks_trace() via:
 *   bpf_selem_unlink(selem, reuse_now=false) -> bpf_selem_free(false)
 * If call_rcu_tasks_trace() -> mod_timer(lazy_timer) tries to re-acquire
 * base->lock on this CPU -> DEADLOCK.  If it returns, store pid+1 in done
 * so userspace can detect the non-deadlock outcome.
 */
SEC("tp_btf/timer_start")
int BPF_PROG(probe_timer_start, struct timer_list *timer,
	     unsigned long bucket_expiry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 key = 0;
	__u64 *flag;

	/* Skip timers that won't use the current CPU's standard base. */
	if (timer->flags & (TIMER_PINNED | TIMER_DEFERRABLE))
		return 0;

	flag = bpf_map_lookup_elem(&done, &key);
	if (!flag || *flag)
		return 0;

	/* Create storage then immediately delete it to trigger call_rcu_tasks_trace(). */
	if (!bpf_task_storage_get(&task_storage, task, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;

	if (bpf_task_storage_delete(&task_storage, task) == 0) {
		__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
		*flag = (__u64)pid + 1;
	}

	return 0;
}
