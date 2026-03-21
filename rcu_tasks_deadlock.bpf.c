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
 *     trace_timer_start()                    <- tp_btf/timer_start fires here
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

struct timer_list;
struct task_struct;

char LICENSE[] SEC("license") = "GPL";

/*
 * Task local storage: deleted inside tp_btf/timer_start (while base->lock
 * is held) to trigger bpf_selem_free(false) -> call_rcu_tasks_trace() ->
 * call_rcu_tasks_generic() -> mod_timer(lazy_timer) -> DEADLOCK.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} task_storage SEC(".maps");

/*
 * tp_btf/timer_start fires inside __mod_timer() after lock_timer_base()
 * has acquired base->lock with IRQs disabled.  Deleting the task storage
 * entry here unconditionally reaches call_rcu_tasks_trace() via:
 *   bpf_selem_unlink(selem, reuse_now=false) -> bpf_selem_free(false)
 * Re-seeding ensures the next invocation can delete again.
 */
SEC("tp_btf/timer_start")
int BPF_PROG(probe_timer_start, struct timer_list *timer,
	     unsigned long expires, unsigned int flags)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 *val;

	bpf_task_storage_delete(&task_storage, task);

	val = bpf_task_storage_get(&task_storage, task, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val)
		*val = bpf_ktime_get_ns();

	return 0;
}
