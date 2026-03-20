// SPDX-License-Identifier: GPL-2.0
/*
 * rcu_tasks_deadlock.bpf.c
 *
 * Demonstrates the RCU Tasks Trace / timer-base-lock deadlock:
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
 *           bpf_selem_unlink(selem, false)   <- reuse_now=false [task_storage.c:170]
 *             bpf_selem_free(false)
 *               call_rcu_tasks_trace()       <- [canary fires -> EV_DEADLOCK_IMMI]
 *                 call_rcu_tasks_generic()
 *                   raw_spin_trylock(rtpcp)  <- succeeds (different lock)
 *                   mod_timer(lazy_timer)    <- lazy_timer is on this CPU's base
 *                     lock_timer_base()
 *                       raw_spin_lock_irqsave(&base->lock) <- SAME LOCK -> DEADLOCK
 *
 * WARNING: EV_DEADLOCK_IMMI means the kernel will hang. Run only inside a VM.
 */
/*
 * Use linux/bpf.h directly instead of vmlinux.h.  linux/bpf.h pulls in
 * linux/types.h -> asm/types.h (found via -I/usr/include/x86_64-linux-gnu)
 * which provides __u64, __be16, __be32, __wsum, and all BPF map/flag
 * constants without any conflict with bpf_helper_defs.h.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Forward declarations for kernel types referenced in fentry/tp_btf
 * prototypes.  We never dereference these pointers in BPF C code;
 * the verifier resolves the full types from BTF at load time.
 */
struct timer_list;
struct task_struct;
struct rcu_head;
typedef void (*rcu_callback_t)(struct rcu_head *);

char LICENSE[] SEC("license") = "GPL";

/*
 * Per-CPU flag: set while inside the tp_btf/timer_start handler,
 * i.e. while base->lock is held on this CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} in_timer_lock SEC(".maps");

/*
 * Task local storage: the object we delete to trigger call_rcu_tasks_trace().
 *
 * bpf_task_storage_delete()
 *   -> task_storage_delete() -> bpf_selem_unlink(selem, reuse_now=false)
 *                                                      ^^^^ hardcoded false
 *   -> bpf_selem_free(false) -> call_rcu_tasks_trace()
 *
 * Both use_kmalloc_nolock branches reach call_rcu_tasks_trace() with
 * reuse_now=false, so the call is unconditional.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} task_storage SEC(".maps");

/* Ring buffer for delivering events to userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} rb SEC(".maps");

#define EV_LOCK_WINDOW   1   /* timer_start fired; about to trigger delete */
#define EV_DEADLOCK_IMMI 2   /* call_rcu_tasks_trace while base->lock held */

struct event {
	__u32 type;
	__u32 cpu;
	__u32 pid;
	char  comm[16];
};

static __always_inline void emit(__u32 type)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	e->type = type;
	e->cpu  = bpf_get_smp_processor_id();
	e->pid  = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/*
 * tp_btf/timer_start
 *
 * Fires inside __mod_timer() after lock_timer_base() has acquired base->lock
 * with IRQs disabled (see kernel/time/timer.c).
 *
 * We set in_timer_lock[cpu] so the canary below can confirm the window,
 * then call bpf_task_storage_delete() to trigger call_rcu_tasks_trace().
 *
 * On the very first invocation per task there is no storage entry yet;
 * bpf_task_storage_delete() returns -ENOENT (no-op) and we only create one.
 * On subsequent invocations we delete (-> trigger) then recreate.
 */
SEC("tp_btf/timer_start")
int BPF_PROG(probe_timer_start, struct timer_list *timer,
	     unsigned long expires, unsigned int flags)
{
	struct task_struct *task;
	__u32 key = 0;
	__u64 *flag, *val;

	flag = bpf_map_lookup_elem(&in_timer_lock, &key);
	if (!flag)
		return 0;

	*flag = 1;
	emit(EV_LOCK_WINDOW);

	task = bpf_get_current_task_btf();

	/*
	 * Delete triggers: bpf_selem_unlink(selem, reuse_now=false)
	 *   -> bpf_selem_free(false) -> call_rcu_tasks_trace().
	 * -ENOENT on first call per task; that is fine.
	 */
	bpf_task_storage_delete(&task_storage, task);

	/* Re-seed so the next invocation can delete again. */
	val = bpf_task_storage_get(&task_storage, task, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val)
		*val = bpf_ktime_get_ns();

	*flag = 0;
	return 0;
}

/*
 * fentry/call_rcu_tasks_trace  —  canary
 *
 * If in_timer_lock[cpu] is set we are inside probe_timer_start with
 * base->lock held.  call_rcu_tasks_trace() is about to call
 * call_rcu_tasks_generic(), which may call mod_timer(&rtpcp->lazy_timer).
 * rtpcp->lazy_timer belongs to this CPU's timer base, so lock_timer_base()
 * will try to acquire base->lock again on the same CPU -> DEADLOCK.
 */
SEC("fentry/call_rcu_tasks_trace")
int BPF_PROG(canary_rcu_tasks_trace,
	     struct rcu_head *rhp, rcu_callback_t func)
{
	__u32 key = 0;
	__u64 *flag = bpf_map_lookup_elem(&in_timer_lock, &key);

	if (flag && *flag)
		emit(EV_DEADLOCK_IMMI);
	return 0;
}
