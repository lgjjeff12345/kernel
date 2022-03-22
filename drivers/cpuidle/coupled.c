// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * coupled.c - helper functions to enter the same idle state on multiple cpus
 *
 * Copyright (c) 2011 Google, Inc.
 *
 * Author: Colin Cross <ccross@android.com>
 */

#include <linux/kernel.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "cpuidle.h"

/**
 * DOC: Coupled cpuidle states
 *
 * On some ARM SMP SoCs (OMAP4460, Tegra 2, and probably more), the
 * cpus cannot be independently powered down, either due to
 * sequencing restrictions (on Tegra 2, cpu 0 must be the last to
 * power down), or due to HW bugs (on OMAP4460, a cpu powering up
 * will corrupt the gic state unless the other cpu runs a work
 * around).  Each cpu has a power state that it can enter without
 * coordinating with the other cpu (usually Wait For Interrupt, or
 * WFI), and one or more "coupled" power states that affect blocks
 * shared between the cpus (L2 cache, interrupt controller, and
 * sometimes the whole SoC).  Entering a coupled power state must
 * be tightly controlled on both cpus.
 *
 * This file implements a solution, where each cpu will wait in the
 * WFI state until all cpus are ready to enter a coupled state, at
 * which point the coupled state function will be called on all
 * cpus at approximately the same time.
 *
 * Once all cpus are ready to enter idle, they are woken by an smp
 * cross call.  At this point, there is a chance that one of the
 * cpus will find work to do, and choose not to enter idle.  A
 * final pass is needed to guarantee that all cpus will call the
 * power state enter function at the same time.  During this pass,
 * each cpu will increment the ready counter, and continue once the
 * ready counter matches the number of online coupled cpus.  If any
 * cpu exits idle, the other cpus will decrement their counter and
 * retry.
 *
 * requested_state stores the deepest coupled idle state each cpu
 * is ready for.  It is assumed that the states are indexed from
 * shallowest (highest power, lowest exit latency) to deepest
 * (lowest power, highest exit latency).  The requested_state
 * variable is not locked.  It is only written from the cpu that
 * it stores (or by the on/offlining cpu if that cpu is offline),
 * and only read after all the cpus are ready for the coupled idle
 * state are are no longer updating it.
 *
 * Three atomic counters are used.  alive_count tracks the number
 * of cpus in the coupled set that are currently or soon will be
 * online.  waiting_count tracks the number of cpus that are in
 * the waiting loop, in the ready loop, or in the coupled idle state.
 * ready_count tracks the number of cpus that are in the ready loop
 * or in the coupled idle state.
 *
 * To use coupled cpuidle states, a cpuidle driver must:
 *
 *    Set struct cpuidle_device.coupled_cpus to the mask of all
 *    coupled cpus, usually the same as cpu_possible_mask if all cpus
 *    are part of the same cluster.  The coupled_cpus mask must be
 *    set in the struct cpuidle_device for each cpu.
 *
 *    Set struct cpuidle_device.safe_state to a state that is not a
 *    coupled state.  This is usually WFI.
 *
 *    Set CPUIDLE_FLAG_COUPLED in struct cpuidle_state.flags for each
 *    state that affects multiple cpus.
 *
 *    Provide a struct cpuidle_state.enter function for each state
 *    that affects multiple cpus.  This function is guaranteed to be
 *    called on all cpus at approximately the same time.  The driver
 *    should ensure that the cpus all abort together if any cpu tries
 *    to abort once the function is called.  The function should return
 *    with interrupts still disabled.
 */

/* 在一些arm smp SOC中，cpu不能独立地上下电，可能因为sequencing限制
 （如tegra 2需要cpu 0最后下电），或者由于硬件bug（如omap4460，一个
   cpu上电会破坏gic状态，除非其它cpu运行workaround）。每个cpu含有
   一个不需要与其它cpu协调的power state（通常为WFI），以及一个或
   多个会影响cpu之间共享模块（L2 cache，中断控制器，有时是整个soc）
   的coupled power state。进入一个coupled power state，必须在相关
   cpu上都被紧密控制。

   本文件实现了一种解决方案，直到所有cpu准备好进入一个coupled状态之前，
   所有cpu都在WFI状态等待。对于所有相关的cpu，coupled状态函数将在接近
   相同的时间调用。

   在所有cpu准备好进入idle时，它们将被ipi唤醒。此时，一个cpu将选择不
   进入idle状态。只有所有cpu同时调用了power state enter函数，才能确保
   其最终通过。在这个过程中，每个cpu将增加其ready计数器，直到该计数器
   与所有online coupled cpu匹配。只要任意cpu退出idle，其它cpu将退出减少
   其计数，且重试。

   requested_state保存每个cpu已经ready的其最深coupled idle状态。
   它假定状态从shallowest（最高耗能，最低延迟），到deepest（最低
   耗能，最高延迟）indexed。
   
   有三个原子计数器被使用：
   alive_count跟踪coupled组中当前或马上将online的cpu数量。
   waiting_count跟踪在等待循环中，在ready循环中或在coupled idle状态的cpu数量。
   ready_count跟踪在ready loop，或在coupled idle状态的cpu数量。

   为了使用coupled cpuidle状态，一个cpuidle驱动必须：
   设置cpuidle_device.coupled_cpus结构，以mask所有coupled cpus。若所有
   cpu都是相同custer的一部分，它通常与cpu_possible_mask相同。coupled_cpus
   mask必须在每个cpu的cpuidle_device结构体重设置。

   对于不是coupled state的状态，设置cpuidle_device.safe_state结构，它通常用于
   WFI。

   在cpuidle_state.flags中为每个影响multiple cpu的状态设置CPUIDLE_FLAG_COUPLED。

   为每个影响multiple cpu的状态提供一个cpuidle_state.enter函数。该函数确保在所
   有cpu上几乎同时调用。驱动需要确保调用该函数时，只要一个cpu试图abort，则所有
   相关的cpu都要abort。在中断依然被关闭时，该函数也应该返回
*/

/**
 * struct cpuidle_coupled - data for set of cpus that share a coupled idle state
 * @coupled_cpus: mask of cpus that are part of the coupled set
 * @requested_state: array of requested states for cpus in the coupled set
 * @ready_waiting_counts: combined count of cpus  in ready or waiting loops
 * @abort_barrier: synchronisation point for abort cases
 * @online_count: count of cpus that are online
 * @refcnt: reference count of cpuidle devices that are using this struct
 * @prevent: flag to prevent coupled idle while a cpu is hotplugging
 */
/* 共享一个coupled idle状态的cpu组的数据：
   coupled_cpus：属于coupled组的cpu掩码
   requested_state：保存每个cpu已经ready的其最深coupled idle状态
   ready_waiting_counts：跟踪处在ready loop，或waiting loop状态的cpu数量
   abort_barrier：abort case的同步点
   online_count：online cpu的数量
   refcnt：使用本结构体的cpuidle设备引用计数
   prevent：当cpu正在hotplugging，该标志用于避免coupled idle
*/
struct cpuidle_coupled {
	cpumask_t coupled_cpus;
	int requested_state[NR_CPUS];
	atomic_t ready_waiting_counts;
	atomic_t abort_barrier;
	int online_count;
	int refcnt;
	int prevent;
};

#define WAITING_BITS 16
/* 最大的等待cpu数量：256个 */
#define MAX_WAITING_CPUS (1 << WAITING_BITS)
#define WAITING_MASK (MAX_WAITING_CPUS - 1)
#define READY_MASK (~WAITING_MASK)

#define CPUIDLE_COUPLED_NOT_IDLE	(-1)

static DEFINE_PER_CPU(call_single_data_t, cpuidle_coupled_poke_cb);

/*
 * The cpuidle_coupled_poke_pending mask is used to avoid calling
 * __smp_call_function_single with the per cpu call_single_data_t struct already
 * in use.  This prevents a deadlock where two cpus are waiting for each others
 * call_single_data_t struct to be available
 */
static cpumask_t cpuidle_coupled_poke_pending;

/*
 * The cpuidle_coupled_poked mask is used to ensure that each cpu has been poked
 * once to minimize entering the ready loop with a poke pending, which would
 * require aborting and retrying.
 */
static cpumask_t cpuidle_coupled_poked;

/**
 * cpuidle_coupled_parallel_barrier - synchronize all online coupled cpus
 * @dev: cpuidle_device of the calling cpu
 * @a:   atomic variable to hold the barrier
 *
 * No caller to this function will return from this function until all online
 * cpus in the same coupled group have called this function.  Once any caller
 * has returned from this function, the barrier is immediately available for
 * reuse.
 *
 * The atomic variable must be initialized to 0 before any cpu calls
 * this function, will be reset to 0 before any cpu returns from this function.
 *
 * Must only be called from within a coupled idle state handler
 * (state.enter when state.flags has CPUIDLE_FLAG_COUPLED set).
 *
 * Provides full smp barrier semantics before and after calling.
 */
void cpuidle_coupled_parallel_barrier(struct cpuidle_device *dev, atomic_t *a)
{
	int n = dev->coupled->online_count;

	smp_mb__before_atomic();
	atomic_inc(a);

	while (atomic_read(a) < n)
		cpu_relax();

	if (atomic_inc_return(a) == n * 2) {
		atomic_set(a, 0);
		return;
	}

	while (atomic_read(a) > n)
		cpu_relax();
}

/**
 * cpuidle_state_is_coupled - check if a state is part of a coupled set
 * @drv: struct cpuidle_driver for the platform
 * @state: index of the target state in drv->states
 *
 * Returns true if the target state is coupled with cpus besides this one
 */
/* 检查该状态是否是coupled的 */
bool cpuidle_state_is_coupled(struct cpuidle_driver *drv, int state)
{
	return drv->states[state].flags & CPUIDLE_FLAG_COUPLED;
}

/**
 * cpuidle_coupled_state_verify - check if the coupled states are correctly set.
 * @drv: struct cpuidle_driver for the platform
 *
 * Returns 0 for valid state values, a negative error code otherwise:
 *  * -EINVAL if any coupled state(safe_state_index) is wrongly set.
 */
int cpuidle_coupled_state_verify(struct cpuidle_driver *drv)
{
	int i;

	for (i = drv->state_count - 1; i >= 0; i--) {
		if (cpuidle_state_is_coupled(drv, i) &&
		    (drv->safe_state_index == i ||
		     drv->safe_state_index < 0 ||
		     drv->safe_state_index >= drv->state_count))
			return -EINVAL;
	}

	return 0;
}

/**
 * cpuidle_coupled_set_ready - mark a cpu as ready
 * @coupled: the struct coupled that contains the current cpu
 */
static inline void cpuidle_coupled_set_ready(struct cpuidle_coupled *coupled)
{
	atomic_add(MAX_WAITING_CPUS, &coupled->ready_waiting_counts);
}

/**
 * cpuidle_coupled_set_not_ready - mark a cpu as not ready
 * @coupled: the struct coupled that contains the current cpu
 *
 * Decrements the ready counter, unless the ready (and thus the waiting) counter
 * is equal to the number of online cpus.  Prevents a race where one cpu
 * decrements the waiting counter and then re-increments it just before another
 * cpu has decremented its ready counter, leading to the ready counter going
 * down from the number of online cpus without going through the coupled idle
 * state.
 *
 * Returns 0 if the counter was decremented successfully, -EINVAL if the ready
 * counter was equal to the number of online cpus.
 */
static
inline int cpuidle_coupled_set_not_ready(struct cpuidle_coupled *coupled)
{
	int all;
	int ret;

	all = coupled->online_count | (coupled->online_count << WAITING_BITS);
	ret = atomic_add_unless(&coupled->ready_waiting_counts,
		-MAX_WAITING_CPUS, all);

	return ret ? 0 : -EINVAL;
}

/**
 * cpuidle_coupled_no_cpus_ready - check if no cpus in a coupled set are ready
 * @coupled: the struct coupled that contains the current cpu
 *
 * Returns true if all of the cpus in a coupled set are out of the ready loop.
 */
static inline int cpuidle_coupled_no_cpus_ready(struct cpuidle_coupled *coupled)
{
	int r = atomic_read(&coupled->ready_waiting_counts) >> WAITING_BITS;
	return r == 0;
}

/**
 * cpuidle_coupled_cpus_ready - check if all cpus in a coupled set are ready
 * @coupled: the struct coupled that contains the current cpu
 *
 * Returns true if all cpus coupled to this target state are in the ready loop
 */
static inline bool cpuidle_coupled_cpus_ready(struct cpuidle_coupled *coupled)
{
	int r = atomic_read(&coupled->ready_waiting_counts) >> WAITING_BITS;
	return r == coupled->online_count;
}

/**
 * cpuidle_coupled_cpus_waiting - check if all cpus in a coupled set are waiting
 * @coupled: the struct coupled that contains the current cpu
 *
 * Returns true if all cpus coupled to this target state are in the wait loop
 */
static inline bool cpuidle_coupled_cpus_waiting(struct cpuidle_coupled *coupled)
{
	int w = atomic_read(&coupled->ready_waiting_counts) & WAITING_MASK;
	return w == coupled->online_count;
}

/**
 * cpuidle_coupled_no_cpus_waiting - check if no cpus in coupled set are waiting
 * @coupled: the struct coupled that contains the current cpu
 *
 * Returns true if all of the cpus in a coupled set are out of the waiting loop.
 */
static inline int cpuidle_coupled_no_cpus_waiting(struct cpuidle_coupled *coupled)
{
	int w = atomic_read(&coupled->ready_waiting_counts) & WAITING_MASK;
	return w == 0;
}

/**
 * cpuidle_coupled_get_state - determine the deepest idle state
 * @dev: struct cpuidle_device for this cpu
 * @coupled: the struct coupled that contains the current cpu
 *
 * Returns the deepest idle state that all coupled cpus can enter
 */
static inline int cpuidle_coupled_get_state(struct cpuidle_device *dev,
		struct cpuidle_coupled *coupled)
{
	int i;
	int state = INT_MAX;

	/*
	 * Read barrier ensures that read of requested_state is ordered after
	 * reads of ready_count.  Matches the write barriers
	 * cpuidle_set_state_waiting.
	 */
	smp_rmb();

	for_each_cpu(i, &coupled->coupled_cpus)
		if (cpu_online(i) && coupled->requested_state[i] < state)
			state = coupled->requested_state[i];

	return state;
}

static void cpuidle_coupled_handle_poke(void *info)
{
	int cpu = (unsigned long)info;
	cpumask_set_cpu(cpu, &cpuidle_coupled_poked);
	cpumask_clear_cpu(cpu, &cpuidle_coupled_poke_pending);
}

/**
 * cpuidle_coupled_poke - wake up a cpu that may be waiting
 * @cpu: target cpu
 *
 * Ensures that the target cpu exits it's waiting idle state (if it is in it)
 * and will see updates to waiting_count before it re-enters it's waiting idle
 * state.
 *
 * If cpuidle_coupled_poked_mask is already set for the target cpu, that cpu
 * either has or will soon have a pending IPI that will wake it out of idle,
 * or it is currently processing the IPI and is not in idle.
 */
static void cpuidle_coupled_poke(int cpu)
{
	call_single_data_t *csd = &per_cpu(cpuidle_coupled_poke_cb, cpu);

	if (!cpumask_test_and_set_cpu(cpu, &cpuidle_coupled_poke_pending))
		smp_call_function_single_async(cpu, csd);
}

/**
 * cpuidle_coupled_poke_others - wake up all other cpus that may be waiting
 * @this_cpu: target cpu
 * @coupled: the struct coupled that contains the current cpu
 *
 * Calls cpuidle_coupled_poke on all other online cpus.
 */
static void cpuidle_coupled_poke_others(int this_cpu,
		struct cpuidle_coupled *coupled)
{
	int cpu;

	for_each_cpu(cpu, &coupled->coupled_cpus)
		if (cpu != this_cpu && cpu_online(cpu))
			cpuidle_coupled_poke(cpu);
}

/**
 * cpuidle_coupled_set_waiting - mark this cpu as in the wait loop
 * @cpu: target cpu
 * @coupled: the struct coupled that contains the current cpu
 * @next_state: the index in drv->states of the requested state for this cpu
 *
 * Updates the requested idle state for the specified cpuidle device.
 * Returns the number of waiting cpus.
 */
static int cpuidle_coupled_set_waiting(int cpu,
		struct cpuidle_coupled *coupled, int next_state)
{
	coupled->requested_state[cpu] = next_state;

	/*
	 * The atomic_inc_return provides a write barrier to order the write
	 * to requested_state with the later write that increments ready_count.
	 */
	return atomic_inc_return(&coupled->ready_waiting_counts) & WAITING_MASK;
}

/**
 * cpuidle_coupled_set_not_waiting - mark this cpu as leaving the wait loop
 * @cpu: target cpu
 * @coupled: the struct coupled that contains the current cpu
 *
 * Removes the requested idle state for the specified cpuidle device.
 */
static void cpuidle_coupled_set_not_waiting(int cpu,
		struct cpuidle_coupled *coupled)
{
	/*
	 * Decrementing waiting count can race with incrementing it in
	 * cpuidle_coupled_set_waiting, but that's OK.  Worst case, some
	 * cpus will increment ready_count and then spin until they
	 * notice that this cpu has cleared it's requested_state.
	 */
	atomic_dec(&coupled->ready_waiting_counts);

	coupled->requested_state[cpu] = CPUIDLE_COUPLED_NOT_IDLE;
}

/**
 * cpuidle_coupled_set_done - mark this cpu as leaving the ready loop
 * @cpu: the current cpu
 * @coupled: the struct coupled that contains the current cpu
 *
 * Marks this cpu as no longer in the ready and waiting loops.  Decrements
 * the waiting count first to prevent another cpu looping back in and seeing
 * this cpu as waiting just before it exits idle.
 */
static void cpuidle_coupled_set_done(int cpu, struct cpuidle_coupled *coupled)
{
	cpuidle_coupled_set_not_waiting(cpu, coupled);
	atomic_sub(MAX_WAITING_CPUS, &coupled->ready_waiting_counts);
}

/**
 * cpuidle_coupled_clear_pokes - spin until the poke interrupt is processed
 * @cpu: this cpu
 *
 * Turns on interrupts and spins until any outstanding poke interrupts have
 * been processed and the poke bit has been cleared.
 *
 * Other interrupts may also be processed while interrupts are enabled, so
 * need_resched() must be tested after this function returns to make sure
 * the interrupt didn't schedule work that should take the cpu out of idle.
 *
 * Returns 0 if no poke was pending, 1 if a poke was cleared.
 */
static int cpuidle_coupled_clear_pokes(int cpu)
{
	if (!cpumask_test_cpu(cpu, &cpuidle_coupled_poke_pending))
		return 0;

	local_irq_enable();
	while (cpumask_test_cpu(cpu, &cpuidle_coupled_poke_pending))
		cpu_relax();
	local_irq_disable();

	return 1;
}

static bool cpuidle_coupled_any_pokes_pending(struct cpuidle_coupled *coupled)
{
	cpumask_t cpus;
	int ret;

	cpumask_and(&cpus, cpu_online_mask, &coupled->coupled_cpus);
	ret = cpumask_and(&cpus, &cpuidle_coupled_poke_pending, &cpus);

	return ret;
}

/**
 * cpuidle_enter_state_coupled - attempt to enter a state with coupled cpus
 * @dev: struct cpuidle_device for the current cpu
 * @drv: struct cpuidle_driver for the platform
 * @next_state: index of the requested state in drv->states
 *
 * Coordinate with coupled cpus to enter the target state.  This is a two
 * stage process.  In the first stage, the cpus are operating independently,
 * and may call into cpuidle_enter_state_coupled at completely different times.
 * To save as much power as possible, the first cpus to call this function will
 * go to an intermediate state (the cpuidle_device's safe state), and wait for
 * all the other cpus to call this function.  Once all coupled cpus are idle,
 * the second stage will start.  Each coupled cpu will spin until all cpus have
 * guaranteed that they will call the target_state.
 *
 * This function must be called with interrupts disabled.  It may enable
 * interrupts while preparing for idle, and it will always return with
 * interrupts enabled.
 */
/* 进入coupled状态 */
int cpuidle_enter_state_coupled(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int next_state)
{
	int entered_state = -1;
	struct cpuidle_coupled *coupled = dev->coupled;
	int w;

	if (!coupled)
		return -EINVAL;

	while (coupled->prevent) {
		cpuidle_coupled_clear_pokes(dev->cpu);
		if (need_resched()) {
			local_irq_enable();
			return entered_state;
		}
		entered_state = cpuidle_enter_state(dev, drv,
			drv->safe_state_index);
		local_irq_disable();
	}

	/* Read barrier ensures online_count is read after prevent is cleared */
	smp_rmb();

reset:
	cpumask_clear_cpu(dev->cpu, &cpuidle_coupled_poked);

	w = cpuidle_coupled_set_waiting(dev->cpu, coupled, next_state);
	/*
	 * If this is the last cpu to enter the waiting state, poke
	 * all the other cpus out of their waiting state so they can
	 * enter a deeper state.  This can race with one of the cpus
	 * exiting the waiting state due to an interrupt and
	 * decrementing waiting_count, see comment below.
	 */
	if (w == coupled->online_count) {
		cpumask_set_cpu(dev->cpu, &cpuidle_coupled_poked);
		cpuidle_coupled_poke_others(dev->cpu, coupled);
	}

retry:
	/*
	 * Wait for all coupled cpus to be idle, using the deepest state
	 * allowed for a single cpu.  If this was not the poking cpu, wait
	 * for at least one poke before leaving to avoid a race where
	 * two cpus could arrive at the waiting loop at the same time,
	 * but the first of the two to arrive could skip the loop without
	 * processing the pokes from the last to arrive.
	 */
	while (!cpuidle_coupled_cpus_waiting(coupled) ||
			!cpumask_test_cpu(dev->cpu, &cpuidle_coupled_poked)) {
		if (cpuidle_coupled_clear_pokes(dev->cpu))
			continue;

		if (need_resched()) {
			cpuidle_coupled_set_not_waiting(dev->cpu, coupled);
			goto out;
		}

		if (coupled->prevent) {
			cpuidle_coupled_set_not_waiting(dev->cpu, coupled);
			goto out;
		}

		entered_state = cpuidle_enter_state(dev, drv,
			drv->safe_state_index);
		local_irq_disable();
	}

	cpuidle_coupled_clear_pokes(dev->cpu);
	if (need_resched()) {
		cpuidle_coupled_set_not_waiting(dev->cpu, coupled);
		goto out;
	}

	/*
	 * Make sure final poke status for this cpu is visible before setting
	 * cpu as ready.
	 */
	smp_wmb();

	/*
	 * All coupled cpus are probably idle.  There is a small chance that
	 * one of the other cpus just became active.  Increment the ready count,
	 * and spin until all coupled cpus have incremented the counter. Once a
	 * cpu has incremented the ready counter, it cannot abort idle and must
	 * spin until either all cpus have incremented the ready counter, or
	 * another cpu leaves idle and decrements the waiting counter.
	 */

	cpuidle_coupled_set_ready(coupled);
	while (!cpuidle_coupled_cpus_ready(coupled)) {
		/* Check if any other cpus bailed out of idle. */
		if (!cpuidle_coupled_cpus_waiting(coupled))
			if (!cpuidle_coupled_set_not_ready(coupled))
				goto retry;

		cpu_relax();
	}

	/*
	 * Make sure read of all cpus ready is done before reading pending pokes
	 */
	smp_rmb();

	/*
	 * There is a small chance that a cpu left and reentered idle after this
	 * cpu saw that all cpus were waiting.  The cpu that reentered idle will
	 * have sent this cpu a poke, which will still be pending after the
	 * ready loop.  The pending interrupt may be lost by the interrupt
	 * controller when entering the deep idle state.  It's not possible to
	 * clear a pending interrupt without turning interrupts on and handling
	 * it, and it's too late to turn on interrupts here, so reset the
	 * coupled idle state of all cpus and retry.
	 */
	if (cpuidle_coupled_any_pokes_pending(coupled)) {
		cpuidle_coupled_set_done(dev->cpu, coupled);
		/* Wait for all cpus to see the pending pokes */
		cpuidle_coupled_parallel_barrier(dev, &coupled->abort_barrier);
		goto reset;
	}

	/* all cpus have acked the coupled state */
	next_state = cpuidle_coupled_get_state(dev, coupled);

	entered_state = cpuidle_enter_state(dev, drv, next_state);

	cpuidle_coupled_set_done(dev->cpu, coupled);

out:
	/*
	 * Normal cpuidle states are expected to return with irqs enabled.
	 * That leads to an inefficiency where a cpu receiving an interrupt
	 * that brings it out of idle will process that interrupt before
	 * exiting the idle enter function and decrementing ready_count.  All
	 * other cpus will need to spin waiting for the cpu that is processing
	 * the interrupt.  If the driver returns with interrupts disabled,
	 * all other cpus will loop back into the safe idle state instead of
	 * spinning, saving power.
	 *
	 * Calling local_irq_enable here allows coupled states to return with
	 * interrupts disabled, but won't cause problems for drivers that
	 * exit with interrupts enabled.
	 */
	local_irq_enable();

	/*
	 * Wait until all coupled cpus have exited idle.  There is no risk that
	 * a cpu exits and re-enters the ready state because this cpu has
	 * already decremented its waiting_count.
	 */
	while (!cpuidle_coupled_no_cpus_ready(coupled))
		cpu_relax();

	return entered_state;
}

static void cpuidle_coupled_update_online_cpus(struct cpuidle_coupled *coupled)
{
	cpumask_t cpus;
	cpumask_and(&cpus, cpu_online_mask, &coupled->coupled_cpus);
	coupled->online_count = cpumask_weight(&cpus);
}

/**
 * cpuidle_coupled_register_device - register a coupled cpuidle device
 * @dev: struct cpuidle_device for the current cpu
 *
 * Called from cpuidle_register_device to handle coupled idle init.  Finds the
 * cpuidle_coupled struct for this set of coupled cpus, or creates one if none
 * exists yet.
 */
/* 注册一个coupled cpuidle设备 */
int cpuidle_coupled_register_device(struct cpuidle_device *dev)
{
	int cpu;
	struct cpuidle_device *other_dev;
	call_single_data_t *csd;
	struct cpuidle_coupled *coupled;

	if (cpumask_empty(&dev->coupled_cpus))
		return 0;

	for_each_cpu(cpu, &dev->coupled_cpus) {
		other_dev = per_cpu(cpuidle_devices, cpu);
		if (other_dev && other_dev->coupled) {
			coupled = other_dev->coupled;
			goto have_coupled;
		}
	}

	/* No existing coupled info found, create a new one */
	coupled = kzalloc(sizeof(struct cpuidle_coupled), GFP_KERNEL);
	if (!coupled)
		return -ENOMEM;

	coupled->coupled_cpus = dev->coupled_cpus;

have_coupled:
	dev->coupled = coupled;
	if (WARN_ON(!cpumask_equal(&dev->coupled_cpus, &coupled->coupled_cpus)))
		coupled->prevent++;

	cpuidle_coupled_update_online_cpus(coupled);

	coupled->refcnt++;

	csd = &per_cpu(cpuidle_coupled_poke_cb, dev->cpu);
	INIT_CSD(csd, cpuidle_coupled_handle_poke, (void *)(unsigned long)dev->cpu);

	return 0;
}

/**
 * cpuidle_coupled_unregister_device - unregister a coupled cpuidle device
 * @dev: struct cpuidle_device for the current cpu
 *
 * Called from cpuidle_unregister_device to tear down coupled idle.  Removes the
 * cpu from the coupled idle set, and frees the cpuidle_coupled_info struct if
 * this was the last cpu in the set.
 */
/* 注销一个coupled cpuidle设备 */
void cpuidle_coupled_unregister_device(struct cpuidle_device *dev)
{
	struct cpuidle_coupled *coupled = dev->coupled;

	if (cpumask_empty(&dev->coupled_cpus))
		return;

	if (--coupled->refcnt)
		kfree(coupled);
	dev->coupled = NULL;
}

/**
 * cpuidle_coupled_prevent_idle - prevent cpus from entering a coupled state
 * @coupled: the struct coupled that contains the cpu that is changing state
 *
 * Disables coupled cpuidle on a coupled set of cpus.  Used to ensure that
 * cpu_online_mask doesn't change while cpus are coordinating coupled idle.
 */
static void cpuidle_coupled_prevent_idle(struct cpuidle_coupled *coupled)
{
	int cpu = get_cpu();

	/* Force all cpus out of the waiting loop. */
	coupled->prevent++;
	cpuidle_coupled_poke_others(cpu, coupled);
	put_cpu();
	while (!cpuidle_coupled_no_cpus_waiting(coupled))
		cpu_relax();
}

/**
 * cpuidle_coupled_allow_idle - allows cpus to enter a coupled state
 * @coupled: the struct coupled that contains the cpu that is changing state
 *
 * Enables coupled cpuidle on a coupled set of cpus.  Used to ensure that
 * cpu_online_mask doesn't change while cpus are coordinating coupled idle.
 */
static void cpuidle_coupled_allow_idle(struct cpuidle_coupled *coupled)
{
	int cpu = get_cpu();

	/*
	 * Write barrier ensures readers see the new online_count when they
	 * see prevent == 0.
	 */
	smp_wmb();
	coupled->prevent--;
	/* Force cpus out of the prevent loop. */
	cpuidle_coupled_poke_others(cpu, coupled);
	put_cpu();
}

/* CPUHP_CPUIDLE_COUPLED_PREPARE的teardown回调，
   或者CPUHP_AP_ONLINE_DYN的startup回调
*/
static int coupled_cpu_online(unsigned int cpu)
{
	struct cpuidle_device *dev;

	mutex_lock(&cpuidle_lock);

	dev = per_cpu(cpuidle_devices, cpu);
	if (dev && dev->coupled) {
		cpuidle_coupled_update_online_cpus(dev->coupled);
		cpuidle_coupled_allow_idle(dev->coupled);
	}

	mutex_unlock(&cpuidle_lock);
	return 0;
}

/* CPUHP_CPUIDLE_COUPLED_PREPARE的startup回调
   或者CPUHP_AP_ONLINE_DYN的teardown回调
*/
static int coupled_cpu_up_prepare(unsigned int cpu)
{
	struct cpuidle_device *dev;

	mutex_lock(&cpuidle_lock);

	dev = per_cpu(cpuidle_devices, cpu);
	if (dev && dev->coupled)
		cpuidle_coupled_prevent_idle(dev->coupled);

	mutex_unlock(&cpuidle_lock);
	return 0;
}

/* cpuidle coupled初始化函数 */
static int __init cpuidle_coupled_init(void)
{
	int ret;

	/* 设置cpu CPUHP_CPUIDLE_COUPLED_PREPARE状态对应的
	   回调函数等信息。若其满足条件，调用其startup回调
	*/
	ret = cpuhp_setup_state_nocalls(CPUHP_CPUIDLE_COUPLED_PREPARE,
					"cpuidle/coupled:prepare",
					coupled_cpu_up_prepare,
					coupled_cpu_online);
	if (ret)
		return ret;
	/* 设置cpu CPUHP_AP_ONLINE_DYN状态对应的回调函数等
	   信息。若其满足条件，调用其startup回调
	*/
	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"cpuidle/coupled:online",
					coupled_cpu_online,
					coupled_cpu_up_prepare);
	if (ret < 0)
		cpuhp_remove_state_nocalls(CPUHP_CPUIDLE_COUPLED_PREPARE);
	return ret;
}
core_initcall(cpuidle_coupled_init);
