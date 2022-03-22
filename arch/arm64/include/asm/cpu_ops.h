/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 ARM Ltd.
 */
#ifndef __ASM_CPU_OPS_H
#define __ASM_CPU_OPS_H

#include <linux/init.h>
#include <linux/threads.h>

/**
 * struct cpu_operations - Callback operations for hotplugging CPUs.
 *
 * @name:	Name of the property as appears in a devicetree cpu node's
 *		enable-method property. On systems booting with ACPI, @name
 *		identifies the struct cpu_operations entry corresponding to
 *		the boot protocol specified in the ACPI MADT table.
 * @cpu_init:	Reads any data necessary for a specific enable-method for a
 *		proposed logical id.
 * @cpu_prepare: Early one-time preparation step for a cpu. If there is a
 *		mechanism for doing so, tests whether it is possible to boot
 *		the given CPU.
 * @cpu_boot:	Boots a cpu into the kernel.
 * @cpu_postboot: Optionally, perform any post-boot cleanup or necessary
 *		synchronisation. Called from the cpu being booted.
 * @cpu_can_disable: Determines whether a CPU can be disabled based on
 *		mechanism-specific information.
 * @cpu_disable: Prepares a cpu to die. May fail for some mechanism-specific
 * 		reason, which will cause the hot unplug to be aborted. Called
 * 		from the cpu to be killed.
 * @cpu_die:	Makes a cpu leave the kernel. Must not fail. Called from the
 *		cpu being killed.
 * @cpu_kill:  Ensures a cpu has left the kernel. Called from another cpu.
 * @cpu_init_idle: Reads any data necessary to initialize CPU idle states for
 *		   a proposed logical id.
 * @cpu_suspend: Suspends a cpu and saves the required context. May fail owing
 *               to wrong parameters or error conditions. Called from the
 *               CPU being suspended. Must be called with IRQs disabled.
 */
/* hotplug cpu的回调函数 */
struct cpu_operations {
	/* enable-method，它会被写在devicetree中，可以为spin-table或psci */
	const char	*name;
	/* 为给定cpu特定enable-method读入所需的数据 */
	int		(*cpu_init)(unsigned int);
	/* 早期执行一次的cpu准备step */
	int		(*cpu_prepare)(unsigned int);
	/* 将一个cpu启动到kernel */
	int		(*cpu_boot)(unsigned int);
	/* 可选的回调，用于执行boot完成后的清理以及同步工作。
       由正在boot的cpu调用
	*/
	void		(*cpu_postboot)(void);
#ifdef CONFIG_HOTPLUG_CPU
	/* 确定一个基于特定机制的cpu是否可以被disable */
	bool		(*cpu_can_disable)(unsigned int cpu);
	/* 为一个cpu准备die，某些机制可能导致其会失败，而导致unplug aborted，
	   它由将要被kill的cpu调用
	*/
	int		(*cpu_disable)(unsigned int cpu);
	/* 使cpu离开kernel，该操作不能失败，由将要被kill的cpu调用 */
	void		(*cpu_die)(unsigned int cpu);
	/* 确认一个cpu已经离开kernel，它由另一个cpu调用 */
	int		(*cpu_kill)(unsigned int cpu);
#endif
#ifdef CONFIG_CPU_IDLE
	/* 为一个给定id的cpu，初始化cpu idle状态读取所需的数据 */
	int		(*cpu_init_idle)(unsigned int);
	/* suspend一个cpu，并且保存所需的上下文。该操作可能会由于错误参数
	   或错误条件失败。由将要被suspend的cpu调用。该调用必须在中断关闭状态下调用 */
	int		(*cpu_suspend)(unsigned long);
#endif
};

int __init init_cpu_ops(int cpu);
extern const struct cpu_operations *get_cpu_ops(int cpu);

/* 初始化boot cpu操作 */
static inline void __init init_bootcpu_ops(void)
{
	init_cpu_ops(0);
}

#endif /* ifndef __ASM_CPU_OPS_H */
