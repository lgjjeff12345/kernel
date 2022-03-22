/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2011 Google, Inc.
 *
 * Author:
 *	Colin Cross <ccross@android.com>
 */

#ifndef _LINUX_CPU_PM_H
#define _LINUX_CPU_PM_H

#include <linux/kernel.h>
#include <linux/notifier.h>

/*
 * When a CPU goes to a low power state that turns off power to the CPU's
 * power domain, the contents of some blocks (floating point coprocessors,
 * interrupt controllers, caches, timers) in the same power domain can
 * be lost.  The cpm_pm notifiers provide a method for platform idle, suspend,
 * and hotplug implementations to notify the drivers for these blocks that
 * they may be reset.
 *
 * All cpu_pm notifications must be called with interrupts disabled.
 *
 * The notifications are split into two classes: CPU notifications and CPU
 * cluster notifications.
 *
 * CPU notifications apply to a single CPU and must be called on the affected
 * CPU.  They are used to save per-cpu context for affected blocks.
 *
 * CPU cluster notifications apply to all CPUs in a single power domain. They
 * are used to save any global context for affected blocks, and must be called
 * after all the CPUs in the power domain have been notified of the low power
 * state.
 */
 /* 当一个cpu进入低功耗状态，其将会关闭到power domain的电源，在相同power domain
    的一些模块将会丢失其内容（如浮点数协处理器，中断控制器，caches，timers）。
    cpm_pm通知链为平台idle，suspend以及hotplug实现提供了一种机制，以通知驱动
    这些模块可能会被reset。
    所有cpm_pm通知都必须在关中断的情形下被调用。
    通知被分成两种类型：cpu通知和cpu cluster通知。
    cpu通知应用于单个cpu，且必须在受影响的cpu上被调用，它们用于爆粗受影响模块的
    per-cpu上下文。
    cpu cluster通知用于个单独power domain的所有cpu，它们被用于保存所有受影响模块
    的全局上下文，且必须在power domain中的所有cpu被通知低功耗状态之后才调用
 */

/*
 * Event codes passed as unsigned long val to notifier calls
 */
/* cpu的pm事件 */
enum cpu_pm_event {
	/* A single cpu is entering a low power state */
	/* 一个单独的cpu正在进入低功耗状态 */
	CPU_PM_ENTER,

	/* A single cpu failed to enter a low power state */
	/* 一个单独的cpu进入低功耗状态失败 */
	CPU_PM_ENTER_FAILED,

	/* A single cpu is exiting a low power state */
	/* 一个单独的cpu正在退出低功耗状态 */
	CPU_PM_EXIT,

	/* A cpu power domain is entering a low power state */
	/* 一个cpu power domain正在进入低功耗状态 */
	CPU_CLUSTER_PM_ENTER,

	/* A cpu power domain failed to enter a low power state */
	/* 一个cpu power domain进入低功耗状态失败 */
	CPU_CLUSTER_PM_ENTER_FAILED,

	/* A cpu power domain is exiting a low power state */
	/* 一个cpu power domain正在退出低功耗状态 */
	CPU_CLUSTER_PM_EXIT,
};

#ifdef CONFIG_CPU_PM
int cpu_pm_register_notifier(struct notifier_block *nb);
int cpu_pm_unregister_notifier(struct notifier_block *nb);
int cpu_pm_enter(void);
int cpu_pm_exit(void);
int cpu_cluster_pm_enter(void);
int cpu_cluster_pm_exit(void);

#else

static inline int cpu_pm_register_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int cpu_pm_unregister_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int cpu_pm_enter(void)
{
	return 0;
}

static inline int cpu_pm_exit(void)
{
	return 0;
}

static inline int cpu_cluster_pm_enter(void)
{
	return 0;
}

static inline int cpu_cluster_pm_exit(void)
{
	return 0;
}
#endif
#endif
