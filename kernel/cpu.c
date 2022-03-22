/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */
#include <linux/sched/mm.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/sched/signal.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/isolation.h>
#include <linux/sched/task.h>
#include <linux/sched/smt.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/kthread.h>
#include <linux/stop_machine.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/suspend.h>
#include <linux/lockdep.h>
#include <linux/tick.h>
#include <linux/irq.h>
#include <linux/nmi.h>
#include <linux/smpboot.h>
#include <linux/relay.h>
#include <linux/slab.h>
#include <linux/percpu-rwsem.h>
#include <linux/cpuset.h>

#include <trace/events/power.h>
#define CREATE_TRACE_POINTS
#include <trace/events/cpuhp.h>

#include "smpboot.h"

/**
 * cpuhp_cpu_state - Per cpu hotplug state storage
 * @state:	The current cpu state
 * @target:	The target state
 * @thread:	Pointer to the hotplug thread
 * @should_run:	Thread should execute
 * @rollback:	Perform a rollback
 * @single:	Single callback invocation
 * @bringup:	Single callback bringup or teardown selector
 * @cb_state:	The state for a single callback (install/uninstall)
 * @result:	Result of the operation
 * @done_up:	Signal completion to the issuer of the task for cpu-up
 * @done_down:	Signal completion to the issuer of the task for cpu-down
 */
struct cpuhp_cpu_state {
	/* 当前cpu的hp状态 */
	enum cpuhp_state	state;
	/* target hp状态 */
	enum cpuhp_state	target;
	enum cpuhp_state	fail;
#ifdef CONFIG_SMP
	/* 指向hp线程 */
	struct task_struct	*thread;
	/* 线程是否需要运行 */
	bool			should_run;
	/* 执行一次回滚 */
	bool			rollback;
	/* single回调触发 */
	bool			single;
	/* 单次回调bringup，或teardown选择器 */
	bool			bringup;
	int			cpu;
	struct hlist_node	*node;
	struct hlist_node	*last;
	/* 单个callback的状态 */
	enum cpuhp_state	cb_state;
	int			result;
	struct completion	done_up;
	struct completion	done_down;
#endif
};

static DEFINE_PER_CPU(struct cpuhp_cpu_state, cpuhp_state) = {
	.fail = CPUHP_INVALID,
};

#ifdef CONFIG_SMP
cpumask_t cpus_booted_once_mask;
#endif

#if defined(CONFIG_LOCKDEP) && defined(CONFIG_SMP)
static struct lockdep_map cpuhp_state_up_map =
	STATIC_LOCKDEP_MAP_INIT("cpuhp_state-up", &cpuhp_state_up_map);
static struct lockdep_map cpuhp_state_down_map =
	STATIC_LOCKDEP_MAP_INIT("cpuhp_state-down", &cpuhp_state_down_map);


static inline void cpuhp_lock_acquire(bool bringup)
{
	lock_map_acquire(bringup ? &cpuhp_state_up_map : &cpuhp_state_down_map);
}

static inline void cpuhp_lock_release(bool bringup)
{
	lock_map_release(bringup ? &cpuhp_state_up_map : &cpuhp_state_down_map);
}
#else

static inline void cpuhp_lock_acquire(bool bringup) { }
static inline void cpuhp_lock_release(bool bringup) { }

#endif

/**
 * cpuhp_step - Hotplug state machine step
 * @name:	Name of the step
 * @startup:	Startup function of the step
 * @teardown:	Teardown function of the step
 * @cant_stop:	Bringup/teardown can't be stopped at this step
 */
/* hotplug状态机step */
struct cpuhp_step {
	const char		*name;
	/* 该step的startip回调 */
	union {
		int		(*single)(unsigned int cpu);
		int		(*multi)(unsigned int cpu,
					 struct hlist_node *node);
	} startup;
	/* 该step的teardown回调 */
	union {
		int		(*single)(unsigned int cpu);
		int		(*multi)(unsigned int cpu,
					 struct hlist_node *node);
	} teardown;
	struct hlist_head	list;
	/* 在该step，Bringup/teardown不能停止 */
	bool			cant_stop;
	bool			multi_instance;
};

static DEFINE_MUTEX(cpuhp_state_mutex);
/* cpuhp状态数组 */
static struct cpuhp_step cpuhp_hp_states[];

/* 获取cpu state对应的hp step */
static struct cpuhp_step *cpuhp_get_step(enum cpuhp_state state)
{
	return cpuhp_hp_states + state;
}

/* 该step的回调函数是否为空 */
static bool cpuhp_step_empty(bool bringup, struct cpuhp_step *step)
{
	return bringup ? !step->startup.single : !step->teardown.single;
}

/**
 * cpuhp_invoke_callback _ Invoke the callbacks for a given state
 * @cpu:	The cpu for which the callback should be invoked
 * @state:	The state to do callbacks for
 * @bringup:	True if the bringup callback should be invoked
 * @node:	For multi-instance, do a single entry callback for install/remove
 * @lastp:	For multi-instance rollback, remember how far we got
 *
 * Called from cpu hotplug and from the state register machinery.
 */
/* 触发一个给定状态的回调 */
static int cpuhp_invoke_callback(unsigned int cpu, enum cpuhp_state state,
				 bool bringup, struct hlist_node *node,
				 struct hlist_node **lastp)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	/* 获取该状态对应的step */
	struct cpuhp_step *step = cpuhp_get_step(state);
	int (*cbm)(unsigned int cpu, struct hlist_node *node);
	int (*cb)(unsigned int cpu);
	int ret, cnt;

	if (st->fail == state) {
		st->fail = CPUHP_INVALID;
		return -EAGAIN;
	}

	/* 该step未设置回调函数，不处理 */
	if (cpuhp_step_empty(bringup, step)) {
		WARN_ON_ONCE(1);
		return 0;
	}

	/* 该step为非multi实例 */
	if (!step->multi_instance) {
		WARN_ON_ONCE(lastp && *lastp);
		/* 获取其single回调 */
		cb = bringup ? step->startup.single : step->teardown.single;

		/* 调用回调函数 */
		trace_cpuhp_enter(cpu, st->target, state, cb);
		ret = cb(cpu);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		return ret;
	}
	/* 获取其multi回调 */
	cbm = bringup ? step->startup.multi : step->teardown.multi;

	/* Single invocation for instance add/remove */
	/* 若给定了node，则只对该node调用回调函数 */
	if (node) {
		WARN_ON_ONCE(lastp && *lastp);
		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		return ret;
	}

	/* 若未指定node，则遍历step->list链表中的所有节点，并分别
	   对其调用回调函数
	*/
	/* State transition. Invoke on all instances */
	cnt = 0;
	hlist_for_each(node, &step->list) {
		if (lastp && node == *lastp)
			break;

		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		if (ret) {
			if (!lastp)
				goto err;

			*lastp = node;
			return ret;
		}
		cnt++;
	}
	if (lastp)
		*lastp = NULL;
	return 0;
err:
	/* Rollback the instances if one failed */
	/* 调用失败处理 */
	cbm = !bringup ? step->startup.multi : step->teardown.multi;
	if (!cbm)
		return ret;

	hlist_for_each(node, &step->list) {
		if (!cnt--)
			break;

		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		/*
		 * Rollback must not fail,
		 */
		WARN_ON_ONCE(ret);
	}
	return ret;
}

#ifdef CONFIG_SMP
/* 是否为ap状态 */
static bool cpuhp_is_ap_state(enum cpuhp_state state)
{
	/*
	 * The extra check for CPUHP_TEARDOWN_CPU is only for documentation
	 * purposes as that state is handled explicitly in cpu_down.
	 */
	return state > CPUHP_BRINGUP_CPU && state != CPUHP_TEARDOWN_CPU;
}

/* 等待bringup / down完成 */
static inline void wait_for_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	wait_for_completion(done);
}

static inline void complete_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	complete(done);
}

/*
 * The former STARTING/DYING states, ran with IRQs disabled and must not fail.
 */
/* 判断该hp状态是否是原子状态，即其是否需要关中断运行 */
static bool cpuhp_is_atomic_state(enum cpuhp_state state)
{
	return CPUHP_AP_IDLE_DEAD <= state && state < CPUHP_AP_ONLINE;
}

/* Serializes the updates to cpu_online_mask, cpu_present_mask */
static DEFINE_MUTEX(cpu_add_remove_lock);
bool cpuhp_tasks_frozen;
EXPORT_SYMBOL_GPL(cpuhp_tasks_frozen);

/*
 * The following two APIs (cpu_maps_update_begin/done) must be used when
 * attempting to serialize the updates to cpu_online_mask & cpu_present_mask.
 */
void cpu_maps_update_begin(void)
{
	mutex_lock(&cpu_add_remove_lock);
}

void cpu_maps_update_done(void)
{
	mutex_unlock(&cpu_add_remove_lock);
}

/*
 * If set, cpu_up and cpu_down will return -EBUSY and do nothing.
 * Should always be manipulated under cpu_add_remove_lock
 */
static int cpu_hotplug_disabled;

#ifdef CONFIG_HOTPLUG_CPU

DEFINE_STATIC_PERCPU_RWSEM(cpu_hotplug_lock);

void cpus_read_lock(void)
{
	percpu_down_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_lock);

int cpus_read_trylock(void)
{
	return percpu_down_read_trylock(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_trylock);

void cpus_read_unlock(void)
{
	percpu_up_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_unlock);

void cpus_write_lock(void)
{
	percpu_down_write(&cpu_hotplug_lock);
}

void cpus_write_unlock(void)
{
	percpu_up_write(&cpu_hotplug_lock);
}

void lockdep_assert_cpus_held(void)
{
	/*
	 * We can't have hotplug operations before userspace starts running,
	 * and some init codepaths will knowingly not take the hotplug lock.
	 * This is all valid, so mute lockdep until it makes sense to report
	 * unheld locks.
	 */
	if (system_state < SYSTEM_RUNNING)
		return;

	percpu_rwsem_assert_held(&cpu_hotplug_lock);
}

#ifdef CONFIG_LOCKDEP
int lockdep_is_cpus_held(void)
{
	return percpu_rwsem_is_held(&cpu_hotplug_lock);
}
#endif

static void lockdep_acquire_cpus_lock(void)
{
	rwsem_acquire(&cpu_hotplug_lock.dep_map, 0, 0, _THIS_IP_);
}

static void lockdep_release_cpus_lock(void)
{
	rwsem_release(&cpu_hotplug_lock.dep_map, _THIS_IP_);
}

/*
 * Wait for currently running CPU hotplug operations to complete (if any) and
 * disable future CPU hotplug (from sysfs). The 'cpu_add_remove_lock' protects
 * the 'cpu_hotplug_disabled' flag. The same lock is also acquired by the
 * hotplug path before performing hotplug operations. So acquiring that lock
 * guarantees mutual exclusion from any currently running hotplug operations.
 */
/* 关闭cpu hp */
void cpu_hotplug_disable(void)
{
	cpu_maps_update_begin();
	cpu_hotplug_disabled++;
	cpu_maps_update_done();
}
EXPORT_SYMBOL_GPL(cpu_hotplug_disable);

/* 使能cpu hp */
static void __cpu_hotplug_enable(void)
{
	if (WARN_ONCE(!cpu_hotplug_disabled, "Unbalanced cpu hotplug enable\n"))
		return;
	cpu_hotplug_disabled--;
}

/* 使能cpu hp */
void cpu_hotplug_enable(void)
{
	cpu_maps_update_begin();
	__cpu_hotplug_enable();
	cpu_maps_update_done();
}
EXPORT_SYMBOL_GPL(cpu_hotplug_enable);

#else

static void lockdep_acquire_cpus_lock(void)
{
}

static void lockdep_release_cpus_lock(void)
{
}

#endif	/* CONFIG_HOTPLUG_CPU */

/*
 * Architectures that need SMT-specific errata handling during SMT hotplug
 * should override this.
 */
void __weak arch_smt_update(void) { }

#ifdef CONFIG_HOTPLUG_SMT
enum cpuhp_smt_control cpu_smt_control __read_mostly = CPU_SMT_ENABLED;

void __init cpu_smt_disable(bool force)
{
	if (!cpu_smt_possible())
		return;

	if (force) {
		pr_info("SMT: Force disabled\n");
		cpu_smt_control = CPU_SMT_FORCE_DISABLED;
	} else {
		pr_info("SMT: disabled\n");
		cpu_smt_control = CPU_SMT_DISABLED;
	}
}

/*
 * The decision whether SMT is supported can only be done after the full
 * CPU identification. Called from architecture code.
 */
void __init cpu_smt_check_topology(void)
{
	if (!topology_smt_supported())
		cpu_smt_control = CPU_SMT_NOT_SUPPORTED;
}

static int __init smt_cmdline_disable(char *str)
{
	cpu_smt_disable(str && !strcmp(str, "force"));
	return 0;
}
early_param("nosmt", smt_cmdline_disable);

/* 是否允许smt */
static inline bool cpu_smt_allowed(unsigned int cpu)
{
	if (cpu_smt_control == CPU_SMT_ENABLED)
		return true;

	if (topology_is_primary_thread(cpu))
		return true;

	/*
	 * On x86 it's required to boot all logical CPUs at least once so
	 * that the init code can get a chance to set CR4.MCE on each
	 * CPU. Otherwise, a broadcasted MCE observing CR4.MCE=0b on any
	 * core will shutdown the machine.
	 */
	return !cpumask_test_cpu(cpu, &cpus_booted_once_mask);
}

/* Returns true if SMT is not supported of forcefully (irreversibly) disabled */
bool cpu_smt_possible(void)
{
	return cpu_smt_control != CPU_SMT_FORCE_DISABLED &&
		cpu_smt_control != CPU_SMT_NOT_SUPPORTED;
}
EXPORT_SYMBOL_GPL(cpu_smt_possible);
#else
static inline bool cpu_smt_allowed(unsigned int cpu) { return true; }
#endif

/* 设置cpu的状态 */
static inline enum cpuhp_state
cpuhp_set_state(struct cpuhp_cpu_state *st, enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;
	bool bringup = st->state < target;

	st->rollback = false;
	st->last = NULL;

	st->target = target;
	st->single = false;
	st->bringup = bringup;
	if (cpu_dying(st->cpu) != !bringup)
		set_cpu_dying(st->cpu, !bringup);

	return prev_state;
}

static inline void
cpuhp_reset_state(struct cpuhp_cpu_state *st, enum cpuhp_state prev_state)
{
	bool bringup = !st->bringup;

	st->target = prev_state;

	/*
	 * Already rolling back. No need invert the bringup value or to change
	 * the current state.
	 */
	if (st->rollback)
		return;

	st->rollback = true;

	/*
	 * If we have st->last we need to undo partial multi_instance of this
	 * state first. Otherwise start undo at the previous state.
	 */
	if (!st->last) {
		if (st->bringup)
			st->state--;
		else
			st->state++;
	}

	st->bringup = bringup;
	if (cpu_dying(st->cpu) != !bringup)
		set_cpu_dying(st->cpu, !bringup);
}

/* Regular hotplug invocation of the AP hotplug thread */
/* 触发ap的hotplug线程 */
static void __cpuhp_kick_ap(struct cpuhp_cpu_state *st)
{
	if (!st->single && st->state == st->target)
		return;

	st->result = 0;
	/*
	 * Make sure the above stores are visible before should_run becomes
	 * true. Paired with the mb() above in cpuhp_thread_fun()
	 */
	smp_mb();
	st->should_run = true;
	/* 唤醒该cpu的hotplug线程 */
	wake_up_process(st->thread);
	/* 等待该线程处理完成 */
	wait_for_ap_thread(st, st->bringup);
}

/* 将st对应cpu的状态修改为target，若修改失败，则恢复成先前状态 */
static int cpuhp_kick_ap(struct cpuhp_cpu_state *st, enum cpuhp_state target)
{
	enum cpuhp_state prev_state;
	int ret;

	/* 状态修改流程：
       先将需要修改的状态写到st的target成员中，然后kick该cpu的hotplug线程运行，
       在hotplug线程中执行实际的状态修改，修改完成后通过完成量通知完成
	*/
	prev_state = cpuhp_set_state(st, target);
	__cpuhp_kick_ap(st);
	/* 若状态修改失败，恢复为先前状态 */
	if ((ret = st->result)) {
		cpuhp_reset_state(st, prev_state);
		__cpuhp_kick_ap(st);
	}

	return ret;
}

static int bringup_wait_for_ap(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

	/* Wait for the CPU to reach CPUHP_AP_ONLINE_IDLE */
	/* 等待cpu   bringup时状态修改完成 */
	wait_for_ap_thread(st, true);
	/* 若cpu不是处于online状态。返回错误 */
	if (WARN_ON_ONCE((!cpu_online(cpu))))
		return -ECANCELED;

	/* Unpark the hotplug thread of the target cpu */
	/* unpark该cpu的hotplug线程 */
	kthread_unpark(st->thread);

	/*
	 * SMT soft disabling on X86 requires to bring the CPU out of the
	 * BIOS 'wait for SIPI' state in order to set the CR4.MCE bit.  The
	 * CPU marked itself as booted_once in notify_cpu_starting() so the
	 * cpu_smt_allowed() check will now return false if this is not the
	 * primary sibling.
	 */
	/* x86超线程特性 */
	if (!cpu_smt_allowed(cpu))
		return -ECANCELED;

	if (st->target <= CPUHP_AP_ONLINE_IDLE)
		return 0;

	/* 修改该cpu的状态为target */
	return cpuhp_kick_ap(st, st->target);
}

static int bringup_cpu(unsigned int cpu)
{
	/* 获取该cpu的idle线程 */
	struct task_struct *idle = idle_thread_get(cpu);
	int ret;

	/*
	 * Some architectures have to walk the irq descriptors to
	 * setup the vector space for the cpu which comes online.
	 * Prevent irq alloc/free across the bringup.
	 */
	irq_lock_sparse();

	/* Arch-specific enabling code. */
	ret = __cpu_up(cpu, idle);
	irq_unlock_sparse();
	if (ret)
		return ret;
	return bringup_wait_for_ap(cpu);
}

static int finish_cpu(unsigned int cpu)
{
	struct task_struct *idle = idle_thread_get(cpu);
	struct mm_struct *mm = idle->active_mm;

	/*
	 * idle_task_exit() will have switched to &init_mm, now
	 * clean up any remaining active_mm state.
	 */
	if (mm != &init_mm)
		idle->active_mm = &init_mm;
	mmdrop(mm);
	return 0;
}

/*
 * Hotplug state machine related functions
 */

/*
 * Get the next state to run. Empty ones will be skipped. Returns true if a
 * state must be run.
 *
 * st->state will be modified ahead of time, to match state_to_run, as if it
 * has already ran.
 */
/* 查找下一个需要执行的state */
static bool cpuhp_next_state(bool bringup,
			     enum cpuhp_state *state_to_run,
			     struct cpuhp_cpu_state *st,
			     enum cpuhp_state target)
{
	do {
		if (bringup) {
			if (st->state >= target)
				return false;

			*state_to_run = ++st->state;
		} else {
			if (st->state <= target)
				return false;

			*state_to_run = st->state--;
		}

		if (!cpuhp_step_empty(bringup, cpuhp_get_step(*state_to_run)))
			break;
	} while (true);

	return true;
}

/* 触发cpu两个状态之间的回调函数 */
static int cpuhp_invoke_callback_range(bool bringup,
				       unsigned int cpu,
				       struct cpuhp_cpu_state *st,
				       enum cpuhp_state target)
{
	enum cpuhp_state state;
	int err = 0;

	/* 遍历st->state到target之间的状态，并分别触发其
 	   对应的回调函数
 	   根据是否是bringup，遍历顺序相反
	*/
	while (cpuhp_next_state(bringup, &state, st, target)) {
		err = cpuhp_invoke_callback(cpu, state, bringup, NULL, NULL);
		if (err)
			break;
	}

	return err;
}

static inline bool can_rollback_cpu(struct cpuhp_cpu_state *st)
{
	if (IS_ENABLED(CONFIG_HOTPLUG_CPU))
		return true;
	/*
	 * When CPU hotplug is disabled, then taking the CPU down is not
	 * possible because takedown_cpu() and the architecture and
	 * subsystem specific mechanisms are not available. So the CPU
	 * which would be completely unplugged again needs to stay around
	 * in the current state.
	 */
	return st->state <= CPUHP_BRINGUP_CPU;
}

/* 处理cpu hotplug回调 */
static int cpuhp_up_callbacks(unsigned int cpu, struct cpuhp_cpu_state *st,
			      enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;
	int ret = 0;

	/* 触发st->state到target之间的回调 */
	ret = cpuhp_invoke_callback_range(true, cpu, st, target);
	if (ret) {
		/* 处理失败，则reset状态 */
		cpuhp_reset_state(st, prev_state);
		if (can_rollback_cpu(st))
			WARN_ON(cpuhp_invoke_callback_range(false, cpu, st,
							    prev_state));
	}
	return ret;
}

/*
 * The cpu hotplug threads manage the bringup and teardown of the cpus
 */
/* cpu hp线程创建时调用的回调 */
static void cpuhp_create(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

	/* 初始化该cpu对应st的成员 */
	init_completion(&st->done_up);
	init_completion(&st->done_down);
	st->cpu = cpu;
}

/* 判断该线程是否应该运行 */
static int cpuhp_should_run(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	return st->should_run;
}

/*
 * Execute teardown/startup callbacks on the plugged cpu. Also used to invoke
 * callbacks when a state gets [un]installed at runtime.
 *
 * Each invocation of this function by the smpboot thread does a single AP
 * state callback.
 *
 * It has 3 modes of operation:
 *  - single: runs st->cb_state
 *  - up:     runs ++st->state, while st->state < st->target
 *  - down:   runs st->state--, while st->state > st->target
 *
 * When complete or on error, should_run is cleared and the completion is fired.
 */
/* cpu hp线程函数 */
static void cpuhp_thread_fun(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);
	bool bringup = st->bringup;
	enum cpuhp_state state;

	/* 判断是否要运行该线程 */
	if (WARN_ON_ONCE(!st->should_run))
		return;

	/*
	 * ACQUIRE for the cpuhp_should_run() load of ->should_run. Ensures
	 * that if we see ->should_run we also see the rest of the state.
	 */
	smp_mb();

	/*
	 * The BP holds the hotplug lock, but we're now running on the AP,
	 * ensure that anybody asserting the lock is held, will actually find
	 * it so.
	 */
	lockdep_acquire_cpus_lock();
	cpuhp_lock_acquire(bringup);

	/* 查找下一个需要执行的state */
	if (st->single) {
		state = st->cb_state;
		st->should_run = false;
	} else {
		st->should_run = cpuhp_next_state(bringup, &state, st, st->target);
		if (!st->should_run)
			goto end;
	}

	WARN_ON_ONCE(!cpuhp_is_ap_state(state));

	/* 执行该state的回调 */
	if (cpuhp_is_atomic_state(state)) {
		local_irq_disable();
		st->result = cpuhp_invoke_callback(cpu, state, bringup, st->node, &st->last);
		local_irq_enable();

		/*
		 * STARTING/DYING must not fail!
		 */
		WARN_ON_ONCE(st->result);
	} else {
		st->result = cpuhp_invoke_callback(cpu, state, bringup, st->node, &st->last);
	}

	/* 执行失败 */
	if (st->result) {
		/*
		 * If we fail on a rollback, we're up a creek without no
		 * paddle, no way forward, no way back. We loose, thanks for
		 * playing.
		 */
		WARN_ON_ONCE(st->rollback);
		st->should_run = false;
	}

end:
	/* 若should_run设置为false，则唤醒等待线程，并通过schedule
	   将本线程切换出去 
	*/
	cpuhp_lock_release(bringup);
	lockdep_release_cpus_lock();

	if (!st->should_run)
		complete_ap_thread(st, bringup);
}

/* Invoke a single callback on a remote cpu */
/* 在一个远程cpu上触发一个回调 */
static int
cpuhp_invoke_ap_callback(int cpu, enum cpuhp_state state, bool bringup,
			 struct hlist_node *node)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int ret;

	if (!cpu_online(cpu))
		return 0;

	cpuhp_lock_acquire(false);
	cpuhp_lock_release(false);

	cpuhp_lock_acquire(true);
	cpuhp_lock_release(true);

	/*
	 * If we are up and running, use the hotplug thread. For early calls
	 * we invoke the thread function directly.
	 */
	if (!st->thread)
		return cpuhp_invoke_callback(cpu, state, bringup, node, NULL);

	st->rollback = false;
	st->last = NULL;

	st->node = node;
	st->bringup = bringup;
	st->cb_state = state;
	st->single = true;

	__cpuhp_kick_ap(st);

	/*
	 * If we failed and did a partial, do a rollback.
	 */
	if ((ret = st->result) && st->last) {
		st->rollback = true;
		st->bringup = !bringup;

		__cpuhp_kick_ap(st);
	}

	/*
	 * Clean up the leftovers so the next hotplug operation wont use stale
	 * data.
	 */
	st->node = st->last = NULL;
	return ret;
}

/* kick ap的hp线程 */
static int cpuhp_kick_ap_work(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	enum cpuhp_state prev_state = st->state;
	int ret;

	cpuhp_lock_acquire(false);
	cpuhp_lock_release(false);

	cpuhp_lock_acquire(true);
	cpuhp_lock_release(true);

	trace_cpuhp_enter(cpu, st->target, prev_state, cpuhp_kick_ap_work);
	/* kick ap线程执行修改target流程 */
	ret = cpuhp_kick_ap(st, st->target);
	trace_cpuhp_exit(cpu, st->state, prev_state, ret);

	return ret;
}

/* cpu hp线程注册结构体 */
static struct smp_hotplug_thread cpuhp_threads = {
	/* task struct */
	.store			= &cpuhp_state.thread,
	.create			= &cpuhp_create,
	.thread_should_run	= cpuhp_should_run,
	.thread_fn		= cpuhp_thread_fun,
	/* 线程名 */
	.thread_comm		= "cpuhp/%u",
	/* 创建完成后，该线程处于park状态 */
	.selfparking		= true,
};

/* 初始化cpu hp线程 */
void __init cpuhp_threads_init(void)
{
	/* 为每个cpu注册hp线程 */
	BUG_ON(smpboot_register_percpu_thread(&cpuhp_threads));
	/* unpark本cpu的cpu hp线程 */
	kthread_unpark(this_cpu_read(cpuhp_state.thread));
}

/*
 *
 * Serialize hotplug trainwrecks outside of the cpu_hotplug_lock
 * protected region.
 *
 * The operation is still serialized against concurrent CPU hotplug via
 * cpu_add_remove_lock, i.e. CPU map protection.  But it is _not_
 * serialized against other hotplug related activity like adding or
 * removing of state callbacks and state instances, which invoke either the
 * startup or the teardown callback of the affected state.
 *
 * This is required for subsystems which are unfixable vs. CPU hotplug and
 * evade lock inversion problems by scheduling work which has to be
 * completed _before_ cpu_up()/_cpu_down() returns.
 *
 * Don't even think about adding anything to this for any new code or even
 * drivers. It's only purpose is to keep existing lock order trainwrecks
 * working.
 *
 * For cpu_down() there might be valid reasons to finish cleanups which are
 * not required to be done under cpu_hotplug_lock, but that's a different
 * story and would be not invoked via this.
 */
static void cpu_up_down_serialize_trainwrecks(bool tasks_frozen)
{
	/*
	 * cpusets delegate hotplug operations to a worker to "solve" the
	 * lock order problems. Wait for the worker, but only if tasks are
	 * _not_ frozen (suspend, hibernate) as that would wait forever.
	 *
	 * The wait is required because otherwise the hotplug operation
	 * returns with inconsistent state, which could even be observed in
	 * user space when a new CPU is brought up. The CPU plug uevent
	 * would be delivered and user space reacting on it would fail to
	 * move tasks to the newly plugged CPU up to the point where the
	 * work has finished because up to that point the newly plugged CPU
	 * is not assignable in cpusets/cgroups. On unplug that's not
	 * necessarily a visible issue, but it is still inconsistent state,
	 * which is the real problem which needs to be "fixed". This can't
	 * prevent the transient state between scheduling the work and
	 * returning from waiting for it.
	 */
	/* cpusets使用一个worker代理hotplug操作，以解决lock order问题。对于非
	   冻结的线程（suspend，hibernate），等待该worker完成，而冻结线程会使
	   其永远等待。
	*/
	if (!tasks_frozen)
		cpuset_wait_for_hotplug();
}

#ifdef CONFIG_HOTPLUG_CPU
#ifndef arch_clear_mm_cpumask_cpu
#define arch_clear_mm_cpumask_cpu(cpu, mm) cpumask_clear_cpu(cpu, mm_cpumask(mm))
#endif

/**
 * clear_tasks_mm_cpumask - Safely clear tasks' mm_cpumask for a CPU
 * @cpu: a CPU id
 *
 * This function walks all processes, finds a valid mm struct for each one and
 * then clears a corresponding bit in mm's cpumask.  While this all sounds
 * trivial, there are various non-obvious corner cases, which this function
 * tries to solve in a safe manner.
 *
 * Also note that the function uses a somewhat relaxed locking scheme, so it may
 * be called only for an already offlined CPU.
 */
/* 为一个cpu安全地清除task的mm_cpumask */
void clear_tasks_mm_cpumask(int cpu)
{
	struct task_struct *p;

	/*
	 * This function is called after the cpu is taken down and marked
	 * offline, so its not like new tasks will ever get this cpu set in
	 * their mm mask. -- Peter Zijlstra
	 * Thus, we may use rcu_read_lock() here, instead of grabbing
	 * full-fledged tasklist_lock.
	 */
	WARN_ON(cpu_online(cpu));
	rcu_read_lock();
	for_each_process(p) {
		struct task_struct *t;

		/*
		 * Main thread might exit, but other threads may still have
		 * a valid mm. Find one.
		 */
		t = find_lock_task_mm(p);
		if (!t)
			continue;
		arch_clear_mm_cpumask_cpu(cpu, t->mm);
		task_unlock(t);
	}
	rcu_read_unlock();
}

/* Take this CPU down. */
/* 将一个cpu take down */
static int take_cpu_down(void *_param)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);
	/* target值设置为st->target，或者CPUHP_AP_OFFLINE的较大值 */
	enum cpuhp_state target = max((int)st->target, CPUHP_AP_OFFLINE);
	int err, cpu = smp_processor_id();
	int ret;

	/* Ensure this CPU doesn't handle any more interrupts. */
	/* 关闭当前cpu之前的准备工作,
       包括将其从cpu拓扑、numa节点中移除，从online cpu位表中移除，
       关闭ppi中断以及迁移其它中断
	*/
	err = __cpu_disable();
	if (err < 0)
		return err;

	/*
	 * Must be called from CPUHP_TEARDOWN_CPU, which means, as we are going
	 * down, that the current state is CPUHP_TEARDOWN_CPU - 1.
	 */
	WARN_ON(st->state != (CPUHP_TEARDOWN_CPU - 1));

	/* Invoke the former CPU_DYING callbacks */
	/* 切换cpu状态 */
	ret = cpuhp_invoke_callback_range(false, cpu, st, target);

	/*
	 * DYING must not fail!
	 */
	WARN_ON_ONCE(ret);

	/* Give up timekeeping duties */
	/* 若do timercpu为当前cpu，则将其迁移到其它的cpu上
       即放弃本cpu的timekeeping职责
	*/
	tick_handover_do_timer();
	/* Remove CPU from timer broadcasting */
	/* 将该cpu从broadcast机制中移除 */
	tick_offline_cpu(cpu);
	/* Park the stopper thread */
	/* park该cpu的stop线程 */
	stop_machine_park(cpu);
	return 0;
}

/* 关闭一个cpu */
static int takedown_cpu(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int err;

	/* Park the smpboot threads */
	/* park该cpu的smpboot线程 */
	kthread_park(st->thread);

	/*
	 * Prevent irq alloc/free while the dying cpu reorganizes the
	 * interrupt affinities.
	 */
	irq_lock_sparse();

	/*
	 * So now all preempt/rcu users must observe !cpu_active().
	 */
	/* 由stop machine执行take_cpu_down函数 */
	err = stop_machine_cpuslocked(take_cpu_down, NULL, cpumask_of(cpu));
	if (err) {
		/* CPU refused to die */
		irq_unlock_sparse();
		/* Unpark the hotplug thread so we can rollback there */
		/* 执行失败，重新unpark hp线程 */
		kthread_unpark(st->thread);
		return err;
	}
	/* 再次确认该cpu是否online */
	BUG_ON(cpu_online(cpu));

	/*
	 * The teardown callback for CPUHP_AP_SCHED_STARTING will have removed
	 * all runnable tasks from the CPU, there's only the idle task left now
	 * that the migration thread is done doing the stop_machine thing.
	 *
	 * Wait for the stop thread to go away.
	 */
	/* 等待ap线程take cpu down完成，此时cpu hp状态被切换为
	   CPUHP_AP_IDLE_DEAD 
	*/
	wait_for_ap_thread(st, false);
	BUG_ON(st->state != CPUHP_AP_IDLE_DEAD);

	/* Interrupts are moved away from the dying cpu, reenable alloc/free */
	irq_unlock_sparse();

	/* 将tick broadcast cpu从deadcpu上移除 */
	hotplug_cpu__broadcast_tick_pull(cpu);
	/* This actually kills the CPU. */
	/* 实际关闭cpu */
	__cpu_die(cpu);

	/* 关闭该cpu的tick device */
	tick_cleanup_dead_cpu(cpu);
	/* 迁移rcu tree */
	rcutree_migrate_callbacks(cpu);
	return 0;
}

static void cpuhp_complete_idle_dead(void *arg)
{
	struct cpuhp_cpu_state *st = arg;

	complete_ap_thread(st, false);
}

void cpuhp_report_idle_dead(void)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	/* 只有本cpu处于CPUHP_AP_OFFLINE状态时，才能调用本接口 */
	BUG_ON(st->state != CPUHP_AP_OFFLINE);
	rcu_report_dead(smp_processor_id());
	/* 将状态修改为CPUHP_AP_IDLE_DEAD */
	st->state = CPUHP_AP_IDLE_DEAD;
	/*
	 * We cannot call complete after rcu_report_dead() so we delegate it
	 * to an online cpu.
	 */
	/* 对第一个online cpu发送ipi中断，以使其执行
	   cpuhp_complete_idle_dead函数 
	*/
	smp_call_function_single(cpumask_first(cpu_online_mask),
				 cpuhp_complete_idle_dead, st, 0);
}

/* 通过cpu down方式，由高向低转换cpu状态 */
static int cpuhp_down_callbacks(unsigned int cpu, struct cpuhp_cpu_state *st,
				enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;
	int ret = 0;

	/* 触发cpu两个状态之间的回调函数 */
	ret = cpuhp_invoke_callback_range(false, cpu, st, target);
	if (ret) {

		cpuhp_reset_state(st, prev_state);

		if (st->state < prev_state)
			WARN_ON(cpuhp_invoke_callback_range(true, cpu, st,
							    prev_state));
	}

	return ret;
}

/* Requires cpu_add_remove_lock to be held */
/* 通过cpu down流程，将该cpu的状态转换为target*/
static int __ref _cpu_down(unsigned int cpu, int tasks_frozen,
			   enum cpuhp_state target)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int prev_state, ret = 0;

	/* 最后一个online的cpu不能使用cpu down接口 */
	if (num_online_cpus() == 1)
		return -EBUSY;

	/* unpresent的cpu，直接返回错误 */
	if (!cpu_present(cpu))
		return -EINVAL;

	cpus_write_lock();

	cpuhp_tasks_frozen = tasks_frozen;

	/* 将cpu的hp状态设置为target */
	prev_state = cpuhp_set_state(st, target);
	/*
	 * If the current CPU state is in the range of the AP hotplug thread,
	 * then we need to kick the thread.
	 */
	/* 若当前状态 >      CPUHP_TEARDOWN_CPU, 唤醒该cpu的hp线程，
       使该线程调用CPUHP_TEARDOWN_CPU之上的回调
	*/
	if (st->state > CPUHP_TEARDOWN_CPU) {
		/* CPUHP_TEARDOWN_CPU之上的回调，由ap线程自身处理 */
		st->target = max((int)target, CPUHP_TEARDOWN_CPU);
		/* kick ap的hp线程 */
		ret = cpuhp_kick_ap_work(cpu);
		/*
		 * The AP side has done the error rollback already. Just
		 * return the error code..
		 */
		if (ret)
			goto out;

		/*
		 * We might have stopped still in the range of the AP hotplug
		 * thread. Nothing to do anymore.
		 */
		/* 将当前状态设置为CPUHP_TEARDOWN_CPU */
		if (st->state > CPUHP_TEARDOWN_CPU)
			goto out;

		/* 重新设置target，以让当前cpu处理剩余流程 */
		st->target = target;
	}
	/*
	 * The AP brought itself down to CPUHP_TEARDOWN_CPU. So we need
	 * to do the further cleanups.
	 */
	/* 当前cpu处理st->state到target之间的回调 */
	ret = cpuhp_down_callbacks(cpu, st, target);
	if (ret && st->state < prev_state) {
		/* 失败处理 */
		if (st->state == CPUHP_TEARDOWN_CPU) {
			cpuhp_reset_state(st, prev_state);
			__cpuhp_kick_ap(st);
		} else {
			WARN(1, "DEAD callback error for CPU%d", cpu);
		}
	}

out:
	cpus_write_unlock();
	/*
	 * Do post unplug cleanup. This is still protected against
	 * concurrent CPU hotplug via cpu_add_remove_lock.
	 */
	lockup_detector_cleanup();
	arch_smt_update();
	cpu_up_down_serialize_trainwrecks(tasks_frozen);
	return ret;
}

/* 通过cpu down方式，将该cpu的状态转换为target */
static int cpu_down_maps_locked(unsigned int cpu, enum cpuhp_state target)
{
	if (cpu_hotplug_disabled)
		return -EBUSY;
	/* 通过cpu down流程，将该cpu的状态转换为target*/
	return _cpu_down(cpu, 0, target);
}

/* 通过cpu down方式，将该cpu的状态转换为target */
static int cpu_down(unsigned int cpu, enum cpuhp_state target)
{
	int err;

	cpu_maps_update_begin();
	/* 通过cpu down方式，将该cpu的状态转换为target */
	err = cpu_down_maps_locked(cpu, target);
	cpu_maps_update_done();
	return err;
}

/**
 * cpu_device_down - Bring down a cpu device
 * @dev: Pointer to the cpu device to offline
 *
 * This function is meant to be used by device core cpu subsystem only.
 *
 * Other subsystems should use remove_cpu() instead.
 */
/* 将该cpu设备状态转换为CPUHP_OFFLINE
   它只能由cpu subsystem使用，其它子系统需要使用remove cpu接口
*/
int cpu_device_down(struct device *dev)
{
	return cpu_down(dev->id, CPUHP_OFFLINE);
}

/* 将该cpu设置为offline状态
   cpu子系统之外的模块，需要使用本接口offline一个cpu
*/
int remove_cpu(unsigned int cpu)
{
	int ret;

	lock_device_hotplug();
	/* 将该cpu切换为offline状态 */
	ret = device_offline(get_cpu_device(cpu));
	unlock_device_hotplug();

	return ret;
}
EXPORT_SYMBOL_GPL(remove_cpu);
/* 关闭非boot cpu */
void smp_shutdown_nonboot_cpus(unsigned int primary_cpu)
{
	unsigned int cpu;
	int error;

	cpu_maps_update_begin();

	/*
	 * Make certain the cpu I'm about to reboot on is online.
	 *
	 * This is inline to what migrate_to_reboot_cpu() already do.
	 */
	/* 若primary cpu未online，则选择第一个online cpu作为primary cpu */
	if (!cpu_online(primary_cpu))
		primary_cpu = cpumask_first(cpu_online_mask);

	/* 遍历所有online cpu，将primary cpu之外的cpu都切换为
	   CPUHP_OFFLINE状态 
	*/
	for_each_online_cpu(cpu) {
		if (cpu == primary_cpu)
			continue;

		error = cpu_down_maps_locked(cpu, CPUHP_OFFLINE);
		if (error) {
			pr_err("Failed to offline CPU%d - error=%d",
				cpu, error);
			break;
		}
	}

	/*
	 * Ensure all but the reboot CPU are offline.
	 */
	/* 确认online cpu数量 */
	BUG_ON(num_online_cpus() > 1);

	/*
	 * Make sure the CPUs won't be enabled by someone else after this
	 * point. Kexec will reboot to a new kernel shortly resetting
	 * everything along the way.
	 */
	cpu_hotplug_disabled++;

	cpu_maps_update_done();
}

#else
#define takedown_cpu		NULL
#endif /*CONFIG_HOTPLUG_CPU*/

/**
 * notify_cpu_starting(cpu) - Invoke the callbacks on the starting CPU
 * @cpu: cpu that just started
 *
 * It must be called by the arch code on the new cpu, before the new cpu
 * enables interrupts and before the "boot" cpu returns from __cpu_up().
 */
/* 在正在启动的cpu上触发回调
   它必须由运行在新cpu上的arch代码调用，且在新cpu使能中断，且boot cpu从
   __cpu_up返回之前调用
*/
void notify_cpu_starting(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	enum cpuhp_state target = min((int)st->target, CPUHP_AP_ONLINE);
	int ret;

	rcu_cpu_starting(cpu);	/* Enables RCU usage on this CPU. */
	/* 在该cpu的cpus_booted_once_mask中设置相应的bit */
	cpumask_set_cpu(cpu, &cpus_booted_once_mask);
	/* 将该cpu状态切换到CPUHP_AP_ONLINE，或者st->target */
	ret = cpuhp_invoke_callback_range(true, cpu, st, target);

	/*
	 * STARTING must not fail!
	 */
	WARN_ON_ONCE(ret);
}

/*
 * Called from the idle task. Wake up the controlling task which brings the
 * hotplug thread of the upcoming CPU up and then delegates the rest of the
 * online bringup to the hotplug thread.
 */
/* 由idle任务调用 */
void cpuhp_online_idle(enum cpuhp_state state)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	/* Happens for the boot cpu */
	if (state != CPUHP_AP_ONLINE_IDLE)
		return;

	/*
	 * Unpart the stopper thread before we start the idle loop (and start
	 * scheduling); this ensures the stopper task is always available.
	 */
	/* unpark当前cpu */
	stop_machine_unpark(smp_processor_id());

	/* 将状态设置idle */
	st->state = CPUHP_AP_ONLINE_IDLE;
	complete_ap_thread(st, true);
}

/* Requires cpu_add_remove_lock to be held */
/* 将cpu状态提升为target */
static int _cpu_up(unsigned int cpu, int tasks_frozen, enum cpuhp_state target)
{
	/* 获取当前的cpu hp状态 */
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	struct task_struct *idle;
	int ret = 0;

	cpus_write_lock();

	/* cpu处于unpresent状态 */
	if (!cpu_present(cpu)) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * The caller of cpu_up() might have raced with another
	 * caller. Nothing to do.
	 */
	/* target状态小于当前状态，不需要处理 */
	if (st->state >= target)
		goto out;

	/* 若当前状态为CPUHP_OFFLINE */
	if (st->state == CPUHP_OFFLINE) {
		/* Let it fail before we try to bring the cpu up */
		/* 获取该cpu的idle线程结构体 */
		idle = idle_thread_get(cpu);
		if (IS_ERR(idle)) {
			ret = PTR_ERR(idle);
			goto out;
		}
	}

	cpuhp_tasks_frozen = tasks_frozen;

	/* 将cpu状态设置为target状态，设置完成后还需要根据目标cpu的状态，
       确定唤醒目标cpu的线程，还是通过本cpu的函数，处理实际状态的修改。
	*/
	cpuhp_set_state(st, target);
	/*
	 * If the current CPU state is in the range of the AP hotplug thread,
	 * then we need to kick the thread once more.
	 */
	/* 当前状态大于CPUHP_BRINGUP_CPU，表明目标cpu已启动，唤醒该cpu处理
	   实际处理cpu状态修改流程的线程
	*/
	if (st->state > CPUHP_BRINGUP_CPU) {
		ret = cpuhp_kick_ap_work(cpu);
		/*
		 * The AP side has done the error rollback already. Just
		 * return the error code..
		 */
		if (ret)
			goto out;
	}

	/*
	 * Try to reach the target state. We max out on the BP at
	 * CPUHP_BRINGUP_CPU. After that the AP hotplug thread is
	 * responsible for bringing it up to the target state.
	 */
	/* 对于比CPUHP_BRINGUP_CPU小的状态，本cpu直接处理cpu状态改变流程。
       在此之后，将会由AP的hotplug线程处理状态转换，该线程根据cpuhp_set_state(st, target)
       中设置的状态，即可了解其实际需要提升的状态
	*/
	target = min((int)target, CPUHP_BRINGUP_CPU);
	/* 依次调用st->state到target之间的回调 */
	ret = cpuhp_up_callbacks(cpu, st, target);
out:
	cpus_write_unlock();
	arch_smt_update();
	cpu_up_down_serialize_trainwrecks(tasks_frozen);
	return ret;
}

/* cpu up流程 */
static int cpu_up(unsigned int cpu, enum cpuhp_state target)
{
	int err = 0;

	/* cpu校验 */
	if (!cpu_possible(cpu)) {
		pr_err("can't online cpu %d because it is not configured as may-hotadd at boot time\n",
		       cpu);
#if defined(CONFIG_IA64)
		pr_err("please check additional_cpus= boot parameter\n");
#endif
		return -EINVAL;
	}

	/* 将该cpu对应的numa节点切换为online状态 */
	err = try_online_node(cpu_to_node(cpu));
	if (err)
		return err;

	cpu_maps_update_begin();

	if (cpu_hotplug_disabled) {
		err = -EBUSY;
		goto out;
	}
	if (!cpu_smt_allowed(cpu)) {
		err = -EPERM;
		goto out;
	}

	/* 将该cpu切换为target状态 */
	err = _cpu_up(cpu, 0, target);
out:
	cpu_maps_update_done();
	return err;
}

/**
 * cpu_device_up - Bring up a cpu device
 * @dev: Pointer to the cpu device to online
 *
 * This function is meant to be used by device core cpu subsystem only.
 *
 * Other subsystems should use add_cpu() instead.
 */
/* 将一个cpu设备切换为online状态 */
int cpu_device_up(struct device *dev)
{
	return cpu_up(dev->id, CPUHP_ONLINE);
}

/* 添加cpu */
int add_cpu(unsigned int cpu)
{
	int ret;

	lock_device_hotplug();
	/* 将该cpu设置为online状态，并且触发对应的uevent事件 */
	ret = device_online(get_cpu_device(cpu));
	unlock_device_hotplug();

	return ret;
}
EXPORT_SYMBOL_GPL(add_cpu);

/**
 * bringup_hibernate_cpu - Bring up the CPU that we hibernated on
 * @sleep_cpu: The cpu we hibernated on and should be brought up.
 *
 * On some architectures like arm64, we can hibernate on any CPU, but on
 * wake up the CPU we hibernated on might be offline as a side effect of
 * using maxcpus= for example.
 */
/* bring up被hibernate的cpu */
int bringup_hibernate_cpu(unsigned int sleep_cpu)
{
	int ret;

	/* 若给定cpu不在线，则将其切换为在线状态 */
	if (!cpu_online(sleep_cpu)) {
		pr_info("Hibernated on a CPU that is offline! Bringing CPU up.\n");
		ret = cpu_up(sleep_cpu, CPUHP_ONLINE);
		if (ret) {
			pr_err("Failed to bring hibernate-CPU up!\n");
			return ret;
		}
	}
	return 0;
}

/* bringup所有的非boot cpu */
void bringup_nonboot_cpus(unsigned int setup_max_cpus)
{
	unsigned int cpu;

	/* 遍历所有的present cpu */
	for_each_present_cpu(cpu) {
		/* 若在线cpu数量达到了最大设定数量值，在返回 */
		if (num_online_cpus() >= setup_max_cpus)
			break;
		/* 否则，将该cpu切换为CPUHP_ONLINE状态 */
		if (!cpu_online(cpu))
			cpu_up(cpu, CPUHP_ONLINE);
	}
}

#ifdef CONFIG_PM_SLEEP_SMP
static cpumask_var_t frozen_cpus;

/* 冻结secondary cpu */
int freeze_secondary_cpus(int primary)
{
	int cpu, error = 0;

	cpu_maps_update_begin();
	if (primary == -1) {
		/* 未指定primary cpu，则将第一个online的cpu作为primary cpu */
		primary = cpumask_first(cpu_online_mask);
		if (!housekeeping_cpu(primary, HK_FLAG_TIMER))
			primary = housekeeping_any_cpu(HK_FLAG_TIMER);
	} else {
		/* 指定的primary cpu不在线，则指定第一个online cpu作为primary cpu */
		if (!cpu_online(primary))
			primary = cpumask_first(cpu_online_mask);
	}

	/*
	 * We take down all of the non-boot CPUs in one shot to avoid races
	 * with the userspace trying to use the CPU hotplug at the same time
	 */
	/* 清除frozen_cpus变量 */
	cpumask_clear(frozen_cpus);

	pr_info("Disabling non-boot CPUs ...\n");
	/* 遍历所有的online cpu */
	for_each_online_cpu(cpu) {
		/* 不处理primary cpu */
		if (cpu == primary)
			continue;

		/* 用于检查电源状态切换流程是否需要终止，
		   若当前处于wakeup pending状态，则终止cpu freeze流程
		*/
		if (pm_wakeup_pending()) {
			pr_info("Wakeup pending. Abort CPU freeze\n");
			error = -EBUSY;
			break;
		}

		trace_suspend_resume(TPS("CPU_OFF"), cpu, true);
		/* 将给定cpu设置为offline状态 */
		error = _cpu_down(cpu, 1, CPUHP_OFFLINE);
		trace_suspend_resume(TPS("CPU_OFF"), cpu, false);
		if (!error)
			/* 状态转换成功，设置该cpu在frozen_cpus中的标志位 */
			cpumask_set_cpu(cpu, frozen_cpus);
		else {
			pr_err("Error taking CPU%d down: %d\n", cpu, error);
			break;
		}
	}

	/* 若frozen成功后，online cpu数量还大于1，则出现了错误 */
	if (!error)
		BUG_ON(num_online_cpus() > 1);
	else
		pr_err("Non-boot CPUs are not disabled\n");

	/*
	 * Make sure the CPUs won't be enabled by someone else. We need to do
	 * this even in case of failure as all freeze_secondary_cpus() users are
	 * supposed to do thaw_secondary_cpus() on the failure path.
	 */
	/* 关闭cpu hp */
	cpu_hotplug_disabled++;

	cpu_maps_update_done();
	return error;
}

void __weak arch_thaw_secondary_cpus_begin(void)
{
}

void __weak arch_thaw_secondary_cpus_end(void)
{
}

/* 解冻secondary cpu */
void thaw_secondary_cpus(void)
{
	int cpu, error;

	/* Allow everyone to use the CPU hotplug again */
	cpu_maps_update_begin();
	/* 使能cpu hp */
	__cpu_hotplug_enable();
	/* 不存在已被冻结的cpu，直接返回 */
	if (cpumask_empty(frozen_cpus))
		goto out;

	pr_info("Enabling non-boot CPUs ...\n");

	arch_thaw_secondary_cpus_begin();

	/* 遍历所有被冻结的cpu */
	for_each_cpu(cpu, frozen_cpus) {
		trace_suspend_resume(TPS("CPU_ON"), cpu, true);
		/* 将cpu状态切换为online */
		error = _cpu_up(cpu, 1, CPUHP_ONLINE);
		trace_suspend_resume(TPS("CPU_ON"), cpu, false);
		if (!error) {
			pr_info("CPU%d is up\n", cpu);
			continue;
		}
		pr_warn("Error taking CPU%d up: %d\n", cpu, error);
	}

	arch_thaw_secondary_cpus_end();

	/* 清除frozen_cpus位表 */
	cpumask_clear(frozen_cpus);
out:
	cpu_maps_update_done();
}

/* 分配cpu冻结的cpumask结构体 */
static int __init alloc_frozen_cpus(void)
{
	if (!alloc_cpumask_var(&frozen_cpus, GFP_KERNEL|__GFP_ZERO))
		return -ENOMEM;
	return 0;
}
core_initcall(alloc_frozen_cpus);

/*
 * When callbacks for CPU hotplug notifications are being executed, we must
 * ensure that the state of the system with respect to the tasks being frozen
 * or not, as reported by the notification, remains unchanged *throughout the
 * duration* of the execution of the callbacks.
 * Hence we need to prevent the freezer from racing with regular CPU hotplug.
 *
 * This synchronization is implemented by mutually excluding regular CPU
 * hotplug and Suspend/Hibernate call paths by hooking onto the Suspend/
 * Hibernate notifications.
 */
/* pm时调用的cpu hp回调 */
static int
cpu_hotplug_pm_callback(struct notifier_block *nb,
			unsigned long action, void *ptr)
{
	/* 在pm的PM_SUSPEND_PREPARE和PM_HIBERNATION_PREPARE流程中，
       需要关闭cpu hp。
       在pm的PM_POST_SUSPEND和PM_POST_HIBERNATION流程中，需要
       使能cpu hp
       其它阶段，无须处理
	*/
	switch (action) {

	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
		cpu_hotplug_disable();
		break;

	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
		cpu_hotplug_enable();
		break;

	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

/* cpu hp的pm初始化*/
static int __init cpu_hotplug_pm_sync_init(void)
{
	/*
	 * cpu_hotplug_pm_callback has higher priority than x86
	 * bsp_pm_callback which depends on cpu_hotplug_pm_callback
	 * to disable cpu hotplug to avoid cpu hotplug race.
	 */
	/* 注册pm的通知函数，在pm流程的特定阶段，需要关闭或使能cpu的hp */
	pm_notifier(cpu_hotplug_pm_callback, 0);
	return 0;
}
core_initcall(cpu_hotplug_pm_sync_init);

#endif /* CONFIG_PM_SLEEP_SMP */

int __boot_cpu_id;

#endif /* CONFIG_SMP */

/* Boot processor state steps */
/* boot处理器预定义的状态step */
static struct cpuhp_step cpuhp_hp_states[] = {
	[CPUHP_OFFLINE] = {
		.name			= "offline",
		.startup.single		= NULL,
		.teardown.single	= NULL,
	},
#ifdef CONFIG_SMP
	[CPUHP_CREATE_THREADS]= {
		.name			= "threads:prepare",
		.startup.single		= smpboot_create_threads,
		.teardown.single	= NULL,
		.cant_stop		= true,
	},
	[CPUHP_PERF_PREPARE] = {
		.name			= "perf:prepare",
		.startup.single		= perf_event_init_cpu,
		.teardown.single	= perf_event_exit_cpu,
	},
	[CPUHP_WORKQUEUE_PREP] = {
		.name			= "workqueue:prepare",
		.startup.single		= workqueue_prepare_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_HRTIMERS_PREPARE] = {
		.name			= "hrtimers:prepare",
		.startup.single		= hrtimers_prepare_cpu,
		.teardown.single	= hrtimers_dead_cpu,
	},
	[CPUHP_SMPCFD_PREPARE] = {
		.name			= "smpcfd:prepare",
		.startup.single		= smpcfd_prepare_cpu,
		.teardown.single	= smpcfd_dead_cpu,
	},
	[CPUHP_RELAY_PREPARE] = {
		.name			= "relay:prepare",
		.startup.single		= relay_prepare_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_SLAB_PREPARE] = {
		.name			= "slab:prepare",
		.startup.single		= slab_prepare_cpu,
		.teardown.single	= slab_dead_cpu,
	},
	[CPUHP_RCUTREE_PREP] = {
		.name			= "RCU/tree:prepare",
		.startup.single		= rcutree_prepare_cpu,
		.teardown.single	= rcutree_dead_cpu,
	},
	/*
	 * On the tear-down path, timers_dead_cpu() must be invoked
	 * before blk_mq_queue_reinit_notify() from notify_dead(),
	 * otherwise a RCU stall occurs.
	 */
	[CPUHP_TIMERS_PREPARE] = {
		.name			= "timers:prepare",
		.startup.single		= timers_prepare_cpu,
		.teardown.single	= timers_dead_cpu,
	},
	/* Kicks the plugged cpu into life */
	[CPUHP_BRINGUP_CPU] = {
		.name			= "cpu:bringup",
		.startup.single		= bringup_cpu,
		.teardown.single	= finish_cpu,
		.cant_stop		= true,
	},
	/* Final state before CPU kills itself */
	[CPUHP_AP_IDLE_DEAD] = {
		.name			= "idle:dead",
	},
	/*
	 * Last state before CPU enters the idle loop to die. Transient state
	 * for synchronization.
	 */
	[CPUHP_AP_OFFLINE] = {
		.name			= "ap:offline",
		.cant_stop		= true,
	},
	/* First state is scheduler control. Interrupts are disabled */
	[CPUHP_AP_SCHED_STARTING] = {
		.name			= "sched:starting",
		.startup.single		= sched_cpu_starting,
		.teardown.single	= sched_cpu_dying,
	},
	[CPUHP_AP_RCUTREE_DYING] = {
		.name			= "RCU/tree:dying",
		.startup.single		= NULL,
		.teardown.single	= rcutree_dying_cpu,
	},
	[CPUHP_AP_SMPCFD_DYING] = {
		.name			= "smpcfd:dying",
		.startup.single		= NULL,
		.teardown.single	= smpcfd_dying_cpu,
	},
	/* Entry state on starting. Interrupts enabled from here on. Transient
	 * state for synchronsization */
	[CPUHP_AP_ONLINE] = {
		.name			= "ap:online",
	},
	/*
	 * Handled on control processor until the plugged processor manages
	 * this itself.
	 */
	[CPUHP_TEARDOWN_CPU] = {
		.name			= "cpu:teardown",
		.startup.single		= NULL,
		.teardown.single	= takedown_cpu,
		.cant_stop		= true,
	},

	[CPUHP_AP_SCHED_WAIT_EMPTY] = {
		.name			= "sched:waitempty",
		.startup.single		= NULL,
		.teardown.single	= sched_cpu_wait_empty,
	},

	/* Handle smpboot threads park/unpark */
	[CPUHP_AP_SMPBOOT_THREADS] = {
		.name			= "smpboot/threads:online",
		.startup.single		= smpboot_unpark_threads,
		.teardown.single	= smpboot_park_threads,
	},
	[CPUHP_AP_IRQ_AFFINITY_ONLINE] = {
		.name			= "irq/affinity:online",
		.startup.single		= irq_affinity_online_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_AP_PERF_ONLINE] = {
		.name			= "perf:online",
		.startup.single		= perf_event_init_cpu,
		.teardown.single	= perf_event_exit_cpu,
	},
	[CPUHP_AP_WATCHDOG_ONLINE] = {
		.name			= "lockup_detector:online",
		.startup.single		= lockup_detector_online_cpu,
		.teardown.single	= lockup_detector_offline_cpu,
	},
	[CPUHP_AP_WORKQUEUE_ONLINE] = {
		.name			= "workqueue:online",
		.startup.single		= workqueue_online_cpu,
		.teardown.single	= workqueue_offline_cpu,
	},
	[CPUHP_AP_RCUTREE_ONLINE] = {
		.name			= "RCU/tree:online",
		.startup.single		= rcutree_online_cpu,
		.teardown.single	= rcutree_offline_cpu,
	},
#endif
	/*
	 * The dynamically registered state space is here
	 */

#ifdef CONFIG_SMP
	/* Last state is scheduler control setting the cpu active */
	[CPUHP_AP_ACTIVE] = {
		.name			= "sched:active",
		.startup.single		= sched_cpu_activate,
		.teardown.single	= sched_cpu_deactivate,
	},
#endif

	/* CPU is fully up and running. */
	[CPUHP_ONLINE] = {
		.name			= "online",
		.startup.single		= NULL,
		.teardown.single	= NULL,
	},
};

/* Sanity check for callbacks */
/* 检查cpu hotplug的状态 */
static int cpuhp_cb_check(enum cpuhp_state state)
{
	/* 状态处于offline到online之间 */
	if (state <= CPUHP_OFFLINE || state >= CPUHP_ONLINE)
		return -EINVAL;
	return 0;
}

/*
 * Returns a free for dynamic slot assignment of the Online state. The states
 * are protected by the cpuhp_slot_states mutex and an empty slot is identified
 * by having no name assigned.
 */
/* 查找一个动态状态的空闲entry */
static int cpuhp_reserve_state(enum cpuhp_state state)
{
	enum cpuhp_state i, end;
	struct cpuhp_step *step;

	switch (state) {
	case CPUHP_AP_ONLINE_DYN:
		step = cpuhp_hp_states + CPUHP_AP_ONLINE_DYN;
		end = CPUHP_AP_ONLINE_DYN_END;
		break;
	case CPUHP_BP_PREPARE_DYN:
		step = cpuhp_hp_states + CPUHP_BP_PREPARE_DYN;
		end = CPUHP_BP_PREPARE_DYN_END;
		break;
	default:
		return -EINVAL;
	}

	for (i = state; i <= end; i++, step++) {
		if (!step->name)
			return i;
	}
	WARN(1, "No more dynamic states available for CPU hotplug\n");
	return -ENOSPC;
}

/* 设置cpu hobtplug对应状态的回调等信息 */
static int cpuhp_store_callbacks(enum cpuhp_state state, const char *name,
				 int (*startup)(unsigned int cpu),
				 int (*teardown)(unsigned int cpu),
				 bool multi_instance)
{
	/* (Un)Install the callbacks for further cpu hotplug operations */
	struct cpuhp_step *sp;
	int ret = 0;

	/*
	 * If name is NULL, then the state gets removed.
	 *
	 * CPUHP_AP_ONLINE_DYN and CPUHP_BP_PREPARE_DYN are handed out on
	 * the first allocation from these dynamic ranges, so the removal
	 * would trigger a new allocation and clear the wrong (already
	 * empty) state, leaving the callbacks of the to be cleared state
	 * dangling, which causes wreckage on the next hotplug operation.
	 */
	/* 对于动态状态，查询是否有空闲的entry，若没有则直接返回错误，
       否则，将其添加到空闲的entry中
	*/
	if (name && (state == CPUHP_AP_ONLINE_DYN ||
		     state == CPUHP_BP_PREPARE_DYN)) {
		ret = cpuhp_reserve_state(state);
		if (ret < 0)
			return ret;
		state = ret;
	}
	/* 获取该状态对应的step结构体 */
	sp = cpuhp_get_step(state);
	/* 若step已经被注册，返回空 */
	if (name && sp->name)
		return -EBUSY;

	/* 设置该状态的信息 */
	sp->startup.single = startup;
	sp->teardown.single = teardown;
	sp->name = name;
	sp->multi_instance = multi_instance;
	INIT_HLIST_HEAD(&sp->list);
	return ret;
}

/* 获取该step对应的teardown回调 */
static void *cpuhp_get_teardown_cb(enum cpuhp_state state)
{
	return cpuhp_get_step(state)->teardown.single;
}

/*
 * Call the startup/teardown function for a step either on the AP or
 * on the current CPU.
 */
/* 调用该状态对应的startup或teardown回调 */
static int cpuhp_issue_call(int cpu, enum cpuhp_state state, bool bringup,
			    struct hlist_node *node)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int ret;

	/*
	 * If there's nothing to do, we done.
	 * Relies on the union for multi_instance.
	 */
	/* 没有设置回调函数 */
	if (cpuhp_step_empty(bringup, sp))
		return 0;
	/*
	 * The non AP bound callbacks can fail on bringup. On teardown
	 * e.g. module removal we crash for now.
	 */
#ifdef CONFIG_SMP
	/* 调用该状态对应的回调
	   根据状态值，确定其是通过ipi触发远程cpu执行，还是在本cpu执行该操作。
       在cpu状态为CPUHP_BRINGUP_CPU之后，且不是CPUHP_TEARDOWN_CPU状态时，
       则远程cpu已经boot起来，回调将由远程cpu触发。否则，由本cpu触发回调，
       以将cpu启动起来
	*/
	if (cpuhp_is_ap_state(state))
		ret = cpuhp_invoke_ap_callback(cpu, state, bringup, node);
	else
		ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#else
	/* 对于单核系统，不存在远程cpu，因此只需调用当前cpu回调即可 */
	ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#endif
	BUG_ON(ret && !bringup);
	return ret;
}

/*
 * Called from __cpuhp_setup_state on a recoverable failure.
 *
 * Note: The teardown callbacks for rollback are not allowed to fail!
 */
 /* rollback cpu状态 */
static void cpuhp_rollback_install(int failedcpu, enum cpuhp_state state,
				   struct hlist_node *node)
{
	int cpu;

	/* Roll back the already executed steps on the other cpus */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpu >= failedcpu)
			break;

		/* Did we invoke the startup call on that cpu ? */
		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, node);
	}
}

/* 向给定状态添加cpu hp实例 */
int __cpuhp_state_add_instance_cpuslocked(enum cpuhp_state state,
					  struct hlist_node *node,
					  bool invoke)
{
	struct cpuhp_step *sp;
	int cpu;
	int ret;

	lockdep_assert_cpus_held();

	sp = cpuhp_get_step(state);
	if (sp->multi_instance == false)
		return -EINVAL;

	mutex_lock(&cpuhp_state_mutex);

	/* 若不需要触发，或该step不是multi实例，则直接添加节点即可 */
	if (!invoke || !sp->startup.multi)
		goto add_node;

	/*
	 * Try to call the startup callback for each present cpu
	 * depending on the hotplug state of the cpu.
	 */
	/* 根据状态值，对所有present cpu调用状态切换回调 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate < state)
			continue;

		ret = cpuhp_issue_call(cpu, state, true, node);
		if (ret) {
			if (sp->teardown.multi)
				cpuhp_rollback_install(cpu, state, node);
			goto unlock;
		}
	}
add_node:
	/* 向该链表添加实例节点 */
	ret = 0;
	hlist_add_head(node, &sp->list);
unlock:
	mutex_unlock(&cpuhp_state_mutex);
	return ret;
}

/* 向给定状态添加cpu hp实例 */
int __cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node,
			       bool invoke)
{
	int ret;

	cpus_read_lock();
	ret = __cpuhp_state_add_instance_cpuslocked(state, node, invoke);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(__cpuhp_state_add_instance);

/**
 * __cpuhp_setup_state_cpuslocked - Setup the callbacks for an hotplug machine state
 * @state:		The state to setup
 * @invoke:		If true, the startup function is invoked for cpus where
 *			cpu state >= @state
 * @startup:		startup callback function
 * @teardown:		teardown callback function
 * @multi_instance:	State is set up for multiple instances which get
 *			added afterwards.
 *
 * The caller needs to hold cpus read locked while calling this function.
 * Returns:
 *   On success:
 *      Positive state number if @state is CPUHP_AP_ONLINE_DYN
 *      0 for all other states
 *   On failure: proper (negative) error code
 */
/* 为一个hotplug状态机设置一个回调 */
int __cpuhp_setup_state_cpuslocked(enum cpuhp_state state,
				   const char *name, bool invoke,
				   int (*startup)(unsigned int cpu),
				   int (*teardown)(unsigned int cpu),
				   bool multi_instance)
{
	int cpu, ret = 0;
	bool dynstate;

	lockdep_assert_cpus_held();

	/* 检查cpu hotplug的状态 */
	if (cpuhp_cb_check(state) || !name)
		return -EINVAL;

	mutex_lock(&cpuhp_state_mutex);

	/* 设置cpu hotplug的回调信息 */
	ret = cpuhp_store_callbacks(state, name, startup, teardown,
				    multi_instance);

	/* 若为动态状态，更新state为实际的动态entry */
	dynstate = state == CPUHP_AP_ONLINE_DYN;
	if (ret > 0 && dynstate) {
		state = ret;
		ret = 0;
	}

	/* 不需要invoke startup函数，直接返回 */
	if (ret || !invoke || !startup)
		goto out;

	/* 为每个present cpu触发startup函数 */
	/*
	 * Try to call the startup callback for each present cpu
	 * depending on the hotplug state of the cpu.
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		/* cpustate < state，即其前面还有状态没有初始化，
		   则不能调用当前状态的回调。否则，可以调用当前
		   状态的回调函数
		*/
		if (cpustate < state)
			continue;

		/* 为给定cpu调用该状态对应的回调 */
		ret = cpuhp_issue_call(cpu, state, true, NULL);
		if (ret) {
			/* 若调用失败，则调用teardown回调 */
			if (teardown)
				cpuhp_rollback_install(cpu, state, NULL);
			cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
			goto out;
		}
	}
out:
	mutex_unlock(&cpuhp_state_mutex);
	/*
	 * If the requested state is CPUHP_AP_ONLINE_DYN, return the
	 * dynamically allocated state in case of success.
	 */
	/* 动态状态，特殊处理 */
	if (!ret && dynstate)
		return state;
	return ret;
}
EXPORT_SYMBOL(__cpuhp_setup_state_cpuslocked);

/* 设置cpu hotplug的状态对应的回调函数等信息 */
int __cpuhp_setup_state(enum cpuhp_state state,
			const char *name, bool invoke,
			int (*startup)(unsigned int cpu),
			int (*teardown)(unsigned int cpu),
			bool multi_instance)
{
	int ret;

	cpus_read_lock();
	ret = __cpuhp_setup_state_cpuslocked(state, name, invoke, startup,
					     teardown, multi_instance);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL(__cpuhp_setup_state);

/* 移除cpu hotplug的实例 */
int __cpuhp_state_remove_instance(enum cpuhp_state state,
				  struct hlist_node *node, bool invoke)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int cpu;

	/* 状态的合法性检查 */
	BUG_ON(cpuhp_cb_check(state));

	/* 对于非multi实例的step，返回错误 */
	if (!sp->multi_instance)
		return -EINVAL;

	cpus_read_lock();
	mutex_lock(&cpuhp_state_mutex);

	/* 不需要invoke，或该step不存在teardown回调，直接删除node节点 */
	if (!invoke || !cpuhp_get_teardown_cb(state))
		goto remove;
	/*
	 * Call the teardown callback for each present cpu depending
	 * on the hotplug state of the cpu. This function is not
	 * allowed to fail currently!
	 */
	/* 否则，对所有的present cpu，若其给定状态小于当前状态，都执行
	   这些状态的teardown回调
	*/
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, node);
	}

remove:
	hlist_del(node);
	mutex_unlock(&cpuhp_state_mutex);
	cpus_read_unlock();

	return 0;
}
EXPORT_SYMBOL_GPL(__cpuhp_state_remove_instance);

/**
 * __cpuhp_remove_state_cpuslocked - Remove the callbacks for an hotplug machine state
 * @state:	The state to remove
 * @invoke:	If true, the teardown function is invoked for cpus where
 *		cpu state >= @state
 *
 * The caller needs to hold cpus read locked while calling this function.
 * The teardown callback is currently not allowed to fail. Think
 * about module removal!
 */
void __cpuhp_remove_state_cpuslocked(enum cpuhp_state state, bool invoke)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int cpu;

	BUG_ON(cpuhp_cb_check(state));

	lockdep_assert_cpus_held();

	mutex_lock(&cpuhp_state_mutex);
	if (sp->multi_instance) {
		WARN(!hlist_empty(&sp->list),
		     "Error: Removing state %d which has instances left.\n",
		     state);
		goto remove;
	}

	if (!invoke || !cpuhp_get_teardown_cb(state))
		goto remove;

	/*
	 * Call the teardown callback for each present cpu depending
	 * on the hotplug state of the cpu. This function is not
	 * allowed to fail currently!
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, NULL);
	}
remove:
	cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
	mutex_unlock(&cpuhp_state_mutex);
}
EXPORT_SYMBOL(__cpuhp_remove_state_cpuslocked);

void __cpuhp_remove_state(enum cpuhp_state state, bool invoke)
{
	cpus_read_lock();
	__cpuhp_remove_state_cpuslocked(state, invoke);
	cpus_read_unlock();
}
EXPORT_SYMBOL(__cpuhp_remove_state);

#ifdef CONFIG_HOTPLUG_SMT
/* 修改cpu的offline状态 */
static void cpuhp_offline_cpu_device(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	dev->offline = true;
	/* Tell user space about the state change */
	kobject_uevent(&dev->kobj, KOBJ_OFFLINE);
}

/* 修改cpu设备的online状态 */
static void cpuhp_online_cpu_device(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	dev->offline = false;
	/* Tell user space about the state change */
	kobject_uevent(&dev->kobj, KOBJ_ONLINE);
}

/* 失能smt cpu，将其设置为CPUHP_OFFLINE状态，参数为其控制方式 */
int cpuhp_smt_disable(enum cpuhp_smt_control ctrlval)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	/* 遍历cpu */
	for_each_online_cpu(cpu) {
		/* 若为该topology的primary线程，不处理 */
		if (topology_is_primary_thread(cpu))
			continue;

		/* 将该cpu状态转变为CPUHP_OFFLINE状态 */
		ret = cpu_down_maps_locked(cpu, CPUHP_OFFLINE);
		if (ret)
			break;
		/*
		 * As this needs to hold the cpu maps lock it's impossible
		 * to call device_offline() because that ends up calling
		 * cpu_down() which takes cpu maps lock. cpu maps lock
		 * needs to be held as this might race against in kernel
		 * abusers of the hotplug machinery (thermal management).
		 *
		 * So nothing would update device:offline state. That would
		 * leave the sysfs entry stale and prevent onlining after
		 * smt control has been changed to 'off' again. This is
		 * called under the sysfs hotplug lock, so it is properly
		 * serialized against the regular offline usage.
		 */
		/* 设置cpu的offline状态，并触发uevent */
		cpuhp_offline_cpu_device(cpu);
	}
	if (!ret)
		cpu_smt_control = ctrlval;
	cpu_maps_update_done();
	return ret;
}

/* 使能smt cpu，将其设置为CPUHP_ONLINE状态 */
int cpuhp_smt_enable(void)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	cpu_smt_control = CPU_SMT_ENABLED;
	/* 遍历cpu */
	for_each_present_cpu(cpu) {
		/* Skip online CPUs and CPUs on offline nodes */
		/* 跳过online和其numa节点为offline的cpu */
		if (cpu_online(cpu) || !node_online(cpu_to_node(cpu)))
			continue;
		/* 调用cpu up接口将其设置为online状态 */
		ret = _cpu_up(cpu, 0, CPUHP_ONLINE);
		if (ret)
			break;
		/* See comment in cpuhp_smt_disable() */
		/* 设置cpu设备的online状态，并触发uevent */
		cpuhp_online_cpu_device(cpu);
	}
	cpu_maps_update_done();
	return ret;
}
#endif

#if defined(CONFIG_SYSFS) && defined(CONFIG_HOTPLUG_CPU)
/* 显示target状态 */
static ssize_t show_cpuhp_state(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	return sprintf(buf, "%d\n", st->state);
}
static DEVICE_ATTR(state, 0444, show_cpuhp_state, NULL);

/* 通过sysfs改变该cpu的cpu hp target */
static ssize_t write_cpuhp_target(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);
	struct cpuhp_step *sp;
	int target, ret;

	ret = kstrtoint(buf, 10, &target);
	if (ret)
		return ret;

#ifdef CONFIG_CPU_HOTPLUG_STATE_CONTROL
	if (target < CPUHP_OFFLINE || target > CPUHP_ONLINE)
		return -EINVAL;
#else
	if (target != CPUHP_OFFLINE && target != CPUHP_ONLINE)
		return -EINVAL;
#endif

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	mutex_lock(&cpuhp_state_mutex);
	sp = cpuhp_get_step(target);
	ret = !sp->name || sp->cant_stop ? -EINVAL : 0;
	mutex_unlock(&cpuhp_state_mutex);
	if (ret)
		goto out;

	/* 通过cpu up或cpu down将cpu状态切换为target状态 */
	if (st->state < target)
		ret = cpu_up(dev->id, target);
	else
		ret = cpu_down(dev->id, target);
out:
	unlock_device_hotplug();
	return ret ? ret : count;
}

/* 显示状态属性 */
static ssize_t show_cpuhp_target(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	/* 显示该cpu的targte状态 */
	return sprintf(buf, "%d\n", st->target);
}
static DEVICE_ATTR(target, 0644, show_cpuhp_target, write_cpuhp_target);

/* 修改cpu hp的fail状态 */
static ssize_t write_cpuhp_fail(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);
	struct cpuhp_step *sp;
	int fail, ret;

	ret = kstrtoint(buf, 10, &fail);
	if (ret)
		return ret;

	/* 修改该cpu对应的faile状态 */
	if (fail == CPUHP_INVALID) {
		st->fail = fail;
		return count;
	}

	/* 状态合法性检查 */
	if (fail < CPUHP_OFFLINE || fail > CPUHP_ONLINE)
		return -EINVAL;

	/*
	 * Cannot fail STARTING/DYING callbacks.
	 */
	if (cpuhp_is_atomic_state(fail))
		return -EINVAL;

	/*
	 * DEAD callbacks cannot fail...
	 * ... neither can CPUHP_BRINGUP_CPU during hotunplug. The latter
	 * triggering STARTING callbacks, a failure in this state would
	 * hinder rollback.
	 */
	if (fail <= CPUHP_BRINGUP_CPU && st->state > CPUHP_BRINGUP_CPU)
		return -EINVAL;

	/*
	 * Cannot fail anything that doesn't have callbacks.
	 */
	mutex_lock(&cpuhp_state_mutex);
	sp = cpuhp_get_step(fail);
	if (!sp->startup.single && !sp->teardown.single)
		ret = -EINVAL;
	mutex_unlock(&cpuhp_state_mutex);
	if (ret)
		return ret;

	st->fail = fail;

	return count;
}

/* 显示cpu hp的fail状态 */
static ssize_t show_cpuhp_fail(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	return sprintf(buf, "%d\n", st->fail);
}

static DEVICE_ATTR(fail, 0644, show_cpuhp_fail, write_cpuhp_fail);

static struct attribute *cpuhp_cpu_attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_target.attr,
	&dev_attr_fail.attr,
	NULL
};

static const struct attribute_group cpuhp_cpu_attr_group = {
	.attrs = cpuhp_cpu_attrs,
	.name = "hotplug",
	NULL
};

/* 显示cpu hotplug的状态 */
static ssize_t show_cpuhp_states(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	ssize_t cur, res = 0;
	int i;

	mutex_lock(&cpuhp_state_mutex);
	/* 遍历hp状态 */
	for (i = CPUHP_OFFLINE; i <= CPUHP_ONLINE; i++) {
		/* 获取其对应的hp step */
		struct cpuhp_step *sp = cpuhp_get_step(i);

		/* 若其名字存在，则显示该step的名字 */
		if (sp->name) {
			cur = sprintf(buf, "%3d: %s\n", i, sp->name);
			buf += cur;
			res += cur;
		}
	}
	mutex_unlock(&cpuhp_state_mutex);
	return res;
}
static DEVICE_ATTR(states, 0444, show_cpuhp_states, NULL);

static struct attribute *cpuhp_cpu_root_attrs[] = {
	&dev_attr_states.attr,
	NULL
};

static const struct attribute_group cpuhp_cpu_root_attr_group = {
	.attrs = cpuhp_cpu_root_attrs,
	.name = "hotplug",
	NULL
};

#ifdef CONFIG_HOTPLUG_SMT

/* smt的hotplug控制接口，对于smt拓扑，cpu的primary线程不能使用
   cpuhp_smt_disable关闭
*/
static ssize_t
__store_smt_control(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	int ctrlval, ret;

	if (sysfs_streq(buf, "on"))
		ctrlval = CPU_SMT_ENABLED;
	else if (sysfs_streq(buf, "off"))
		ctrlval = CPU_SMT_DISABLED;
	else if (sysfs_streq(buf, "forceoff"))
		ctrlval = CPU_SMT_FORCE_DISABLED;
	else
		return -EINVAL;

	if (cpu_smt_control == CPU_SMT_FORCE_DISABLED)
		return -EPERM;

	if (cpu_smt_control == CPU_SMT_NOT_SUPPORTED)
		return -ENODEV;

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	if (ctrlval != cpu_smt_control) {
		switch (ctrlval) {
		case CPU_SMT_ENABLED:
			/* 使能smt */
			ret = cpuhp_smt_enable();
			break;
		case CPU_SMT_DISABLED:
		case CPU_SMT_FORCE_DISABLED:
			/* 关闭smt */
			ret = cpuhp_smt_disable(ctrlval);
			break;
		}
	}

	unlock_device_hotplug();
	return ret ? ret : count;
}

#else /* !CONFIG_HOTPLUG_SMT */
static ssize_t
__store_smt_control(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	return -ENODEV;
}
#endif /* CONFIG_HOTPLUG_SMT */

static const char *smt_states[] = {
	[CPU_SMT_ENABLED]		= "on",
	[CPU_SMT_DISABLED]		= "off",
	[CPU_SMT_FORCE_DISABLED]	= "forceoff",
	[CPU_SMT_NOT_SUPPORTED]		= "notsupported",
	[CPU_SMT_NOT_IMPLEMENTED]	= "notimplemented",
};

/* 显示smt的控制属性 */
static ssize_t
show_smt_control(struct device *dev, struct device_attribute *attr, char *buf)
{
	const char *state = smt_states[cpu_smt_control];

	return snprintf(buf, PAGE_SIZE - 2, "%s\n", state);
}

/* 修改smt的控制属性 */
static ssize_t
store_smt_control(struct device *dev, struct device_attribute *attr,
		  const char *buf, size_t count)
{
	return __store_smt_control(dev, attr, buf, count);
}
static DEVICE_ATTR(control, 0644, show_smt_control, store_smt_control);

/* 显示smt的active状态 */
static ssize_t
show_smt_active(struct device *dev, struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE - 2, "%d\n", sched_smt_active());
}
static DEVICE_ATTR(active, 0444, show_smt_active, NULL);

/* smt 控制属性，smt active属性 */
static struct attribute *cpuhp_smt_attrs[] = {
	&dev_attr_control.attr,
	&dev_attr_active.attr,
	NULL
};

/* smt的属性 */
static const struct attribute_group cpuhp_smt_attr_group = {
	.attrs = cpuhp_smt_attrs,
	.name = "smt",
	NULL
};

/* smt的sysfs初始化 */
static int __init cpu_smt_sysfs_init(void)
{
	return sysfs_create_group(&cpu_subsys.dev_root->kobj,
				  &cpuhp_smt_attr_group);
}

/* cpuhp的sysfs初始化 */
static int __init cpuhp_sysfs_init(void)
{
	int cpu, ret;

	ret = cpu_smt_sysfs_init();
	if (ret)
		return ret;

	/* 创建cpu hp根属性 */
	ret = sysfs_create_group(&cpu_subsys.dev_root->kobj,
				 &cpuhp_cpu_root_attr_group);
	if (ret)
		return ret;

	/* 遍历cpu */
	for_each_possible_cpu(cpu) {
		struct device *dev = get_cpu_device(cpu);

		if (!dev)
			continue;
		/* 创建该cpu的hp属性 */
		ret = sysfs_create_group(&dev->kobj, &cpuhp_cpu_attr_group);
		if (ret)
			return ret;
	}
	return 0;
}
device_initcall(cpuhp_sysfs_init);
#endif /* CONFIG_SYSFS && CONFIG_HOTPLUG_CPU */

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)	[x+1][0] = (1UL << (x))
#define MASK_DECLARE_2(x)	MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)	MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)	MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

	MASK_DECLARE_8(0),	MASK_DECLARE_8(8),
	MASK_DECLARE_8(16),	MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
	MASK_DECLARE_8(32),	MASK_DECLARE_8(40),
	MASK_DECLARE_8(48),	MASK_DECLARE_8(56),
#endif
};
EXPORT_SYMBOL_GPL(cpu_bit_bitmap);

const DECLARE_BITMAP(cpu_all_bits, NR_CPUS) = CPU_BITS_ALL;
EXPORT_SYMBOL(cpu_all_bits);

#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __read_mostly
	= {CPU_BITS_ALL};
#else
struct cpumask __cpu_possible_mask __read_mostly;
#endif
EXPORT_SYMBOL(__cpu_possible_mask);

struct cpumask __cpu_online_mask __read_mostly;
EXPORT_SYMBOL(__cpu_online_mask);

struct cpumask __cpu_present_mask __read_mostly;
EXPORT_SYMBOL(__cpu_present_mask);

struct cpumask __cpu_active_mask __read_mostly;
EXPORT_SYMBOL(__cpu_active_mask);

struct cpumask __cpu_dying_mask __read_mostly;
EXPORT_SYMBOL(__cpu_dying_mask);

atomic_t __num_online_cpus __read_mostly;
EXPORT_SYMBOL(__num_online_cpus);

/* 将cpu present掩码初始化为src */
void init_cpu_present(const struct cpumask *src)
{
	cpumask_copy(&__cpu_present_mask, src);
}

/* 将cpu possible掩码初始化为src */
void init_cpu_possible(const struct cpumask *src)
{
	cpumask_copy(&__cpu_possible_mask, src);
}

/* 将cpu online掩码初始化为src */
void init_cpu_online(const struct cpumask *src)
{
	cpumask_copy(&__cpu_online_mask, src);
}

/* 设置cpu的online标志 */
void set_cpu_online(unsigned int cpu, bool online)
{
	/*
	 * atomic_inc/dec() is required to handle the horrid abuse of this
	 * function by the reboot and kexec code which invoke it from
	 * IPI/NMI broadcasts when shutting down CPUs. Invocation from
	 * regular CPU hotplug is properly serialized.
	 *
	 * Note, that the fact that __num_online_cpus is of type atomic_t
	 * does not protect readers which are not serialized against
	 * concurrent hotplug operations.
	 */
	if (online) {
		if (!cpumask_test_and_set_cpu(cpu, &__cpu_online_mask))
			atomic_inc(&__num_online_cpus);
	} else {
		if (cpumask_test_and_clear_cpu(cpu, &__cpu_online_mask))
			atomic_dec(&__num_online_cpus);
	}
}

/*
 * Activate the first processor.
 */
/* 激活第一个cpu */
void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();

	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	/* 设置其在线、active、present个possible位
	   possible：系统存在cpu位表，与devicetree中配置有关
	   present：当前存在的cpu位表，possible - unhotplug
	   online：处于运行状态的cpu
	   active：有active进程运行的cpu
	*/
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);

	/* 保存boot cpu id */
#ifdef CONFIG_SMP
	__boot_cpu_id = cpu;
#endif
}

/*
 * Must be called _AFTER_ setting up the per_cpu areas
 */
/* bootcpu 的hotplug初始化流程 */
void __init boot_cpu_hotplug_init(void)
{
#ifdef CONFIG_SMP
	cpumask_set_cpu(smp_processor_id(), &cpus_booted_once_mask);
#endif
	/* 将本cpu的hp状态设置为CPUHP_ONLINE */
	this_cpu_write(cpuhp_state.state, CPUHP_ONLINE);
}

/*
 * These are used for a global "mitigations=" cmdline option for toggling
 * optional CPU mitigations.
 */
enum cpu_mitigations {
	CPU_MITIGATIONS_OFF,
	CPU_MITIGATIONS_AUTO,
	CPU_MITIGATIONS_AUTO_NOSMT,
};

static enum cpu_mitigations cpu_mitigations __ro_after_init =
	CPU_MITIGATIONS_AUTO;

/* mitigation参数解析 */
static int __init mitigations_parse_cmdline(char *arg)
{
	if (!strcmp(arg, "off"))
		cpu_mitigations = CPU_MITIGATIONS_OFF;
	else if (!strcmp(arg, "auto"))
		cpu_mitigations = CPU_MITIGATIONS_AUTO;
	else if (!strcmp(arg, "auto,nosmt"))
		cpu_mitigations = CPU_MITIGATIONS_AUTO_NOSMT;
	else
		pr_crit("Unsupported mitigations=%s, system may still be vulnerable\n",
			arg);

	return 0;
}
early_param("mitigations", mitigations_parse_cmdline);

/* mitigations=off */
bool cpu_mitigations_off(void)
{
	return cpu_mitigations == CPU_MITIGATIONS_OFF;
}
EXPORT_SYMBOL_GPL(cpu_mitigations_off);

/* mitigations=auto,nosmt */
bool cpu_mitigations_auto_nosmt(void)
{
	return cpu_mitigations == CPU_MITIGATIONS_AUTO_NOSMT;
}
EXPORT_SYMBOL_GPL(cpu_mitigations_auto_nosmt);
