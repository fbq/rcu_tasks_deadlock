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
struct rcu_head;
typedef void (*rcu_callback_t)(struct rcu_head *);

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
 * Per-CPU one-shot flag (key=0):
 *   0      not yet triggered on this CPU
 *   != 0   triggered; value encodes pid (pid = value - 1)
 *
 * PERCPU_ARRAY so each CPU fires independently.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} done SEC(".maps");

/*
 * Per-CPU flag: set while inside call_rcu_tasks_trace() on this CPU.
 *
 * call_rcu_tasks_generic() holds rtpcp->lock and calls mod_timer(lazy_timer),
 * which fires tp_btf/timer_start again.  Without this guard, probe_timer_start
 * would call bpf_task_storage_delete() -> call_rcu_tasks_trace() a second time
 * while rtpcp->lock is already held, causing a different deadlock instead of
 * the timer-base-lock deadlock we want to demonstrate.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} in_rcu_trace SEC(".maps");

/*
 * Task local storage: created and immediately deleted inside tp_btf/timer_start
 * (while base->lock is held) to reach call_rcu_tasks_trace() via:
 *   bpf_selem_unlink(selem, reuse_now=false) -> bpf_selem_free(false)
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} task_storage SEC(".maps");

/*
 * fentry/call_rcu_tasks_trace — set in_rcu_trace on entry, clear on exit.
 *
 * This guards probe_timer_start against triggering while already inside
 * call_rcu_tasks_trace() (i.e. from the mod_timer(lazy_timer) call inside
 * call_rcu_tasks_generic()), which would cause an rtpcp->lock deadlock
 * rather than the timer-base-lock deadlock we intend to trigger.
 */
SEC("fentry/call_rcu_tasks_trace")
int BPF_PROG(enter_rcu_tasks_trace, struct rcu_head *rhp, rcu_callback_t func)
{
	__u32 key = 0;
	__u64 *flag = bpf_map_lookup_elem(&in_rcu_trace, &key);

	if (flag)
		*flag = 1;
	return 0;
}

SEC("fexit/call_rcu_tasks_trace")
int BPF_PROG(exit_rcu_tasks_trace, struct rcu_head *rhp, rcu_callback_t func)
{
	__u32 key = 0;
	__u64 *flag = bpf_map_lookup_elem(&in_rcu_trace, &key);

	if (flag)
		*flag = 0;
	return 0;
}

/*
 * tp_btf/timer_start fires inside __mod_timer() after lock_timer_base()
 * has acquired base->lock with IRQs disabled.
 *
 * Create task storage and immediately delete it to trigger call_rcu_tasks_trace().
 * The delete reaches it via:
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

	/* Skip if we are already inside call_rcu_tasks_trace() on this CPU. */
	flag = bpf_map_lookup_elem(&in_rcu_trace, &key);
	if (!flag || *flag)
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
