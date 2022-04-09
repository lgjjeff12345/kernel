// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Housekeeping management. Manage the targets for routine code that can run on
 *  any CPU: unbound workqueues, timers, kthreads and any offloadable work.
 *
 * Copyright (C) 2017 Red Hat, Inc., Frederic Weisbecker
 * Copyright (C) 2017-2018 SUSE, Frederic Weisbecker
 *
 */
#include "sched.h"

DEFINE_STATIC_KEY_FALSE(housekeeping_overridden);
EXPORT_SYMBOL_GPL(housekeeping_overridden);
static cpumask_var_t housekeeping_mask;
static unsigned int housekeeping_flags;

bool housekeeping_enabled(enum hk_flags flags)
{
	return !!(housekeeping_flags & flags);
}
EXPORT_SYMBOL_GPL(housekeeping_enabled);

int housekeeping_any_cpu(enum hk_flags flags)
{
	int cpu;

	if (static_branch_unlikely(&housekeeping_overridden)) {
		if (housekeeping_flags & flags) {
			cpu = sched_numa_find_closest(housekeeping_mask, smp_processor_id());
			if (cpu < nr_cpu_ids)
				return cpu;

			return cpumask_any_and(housekeeping_mask, cpu_online_mask);
		}
	}
	return smp_processor_id();
}
EXPORT_SYMBOL_GPL(housekeeping_any_cpu);

const struct cpumask *housekeeping_cpumask(enum hk_flags flags)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping_flags & flags)
			return housekeeping_mask;
	return cpu_possible_mask;
}
EXPORT_SYMBOL_GPL(housekeeping_cpumask);

void housekeeping_affine(struct task_struct *t, enum hk_flags flags)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping_flags & flags)
			set_cpus_allowed_ptr(t, housekeeping_mask);
}
EXPORT_SYMBOL_GPL(housekeeping_affine);

bool housekeeping_test_cpu(int cpu, enum hk_flags flags)
{
	if (static_branch_unlikely(&housekeeping_overridden))
		if (housekeeping_flags & flags)
			return cpumask_test_cpu(cpu, housekeeping_mask);
	return true;
}
EXPORT_SYMBOL_GPL(housekeeping_test_cpu);

/* housekeeping初始化 */
void __init housekeeping_init(void)
{
	if (!housekeeping_flags)
		return;

	static_branch_enable(&housekeeping_overridden);

	if (housekeeping_flags & HK_FLAG_TICK)
		sched_tick_offload_init();

	/* We need at least one CPU to handle housekeeping work */
	WARN_ON_ONCE(cpumask_empty(housekeeping_mask));
}

/* housekeeping设置函数
   该函数从输入字符串中解析nonhousekeeping cpu的掩码，然后根据
   该掩码与possible cpu的掩码共同及计算housekeeping cpu掩码。
*/
static int __init housekeeping_setup(char *str, enum hk_flags flags)
{
	cpumask_var_t non_housekeeping_mask;
	cpumask_var_t tmp;

	/* 从bootmem区域分配一个cpumask结构体 */
	alloc_bootmem_cpumask_var(&non_housekeeping_mask);
	/* 从用户传入的字符串中解析cpumask的值 */
	if (cpulist_parse(str, non_housekeeping_mask) < 0) {
		pr_warn("Housekeeping: nohz_full= or isolcpus= incorrect CPU range\n");
		free_bootmem_cpumask_var(non_housekeeping_mask);
		return 0;
	}

	alloc_bootmem_cpumask_var(&tmp);
	if (!housekeeping_flags) {
		/* 根据启动参数传入的mask与possible cpu共同计算housekeeping_mask */
		alloc_bootmem_cpumask_var(&housekeeping_mask);
		cpumask_andnot(housekeeping_mask,
			       cpu_possible_mask, non_housekeeping_mask);

		/* 判断该掩码是否至少包含一个present cpu */
		cpumask_andnot(tmp, cpu_present_mask, non_housekeeping_mask);
		if (cpumask_empty(tmp)) {
			pr_warn("Housekeeping: must include one present CPU, "
				"using boot CPU:%d\n", smp_processor_id());
			/* 若掩码不包含present cpu，则将当前cpu设置为present cpu */
			__cpumask_set_cpu(smp_processor_id(), housekeeping_mask);
			__cpumask_clear_cpu(smp_processor_id(), non_housekeeping_mask);
		}
	} else {
		/* nohz情况下，只在present cpu上支持housekeeping */
		cpumask_andnot(tmp, cpu_present_mask, non_housekeeping_mask);
		if (cpumask_empty(tmp))
			__cpumask_clear_cpu(smp_processor_id(), non_housekeeping_mask);
		cpumask_andnot(tmp, cpu_possible_mask, non_housekeeping_mask);
		if (!cpumask_equal(tmp, housekeeping_mask)) {
			pr_warn("Housekeeping: nohz_full= must match isolcpus=\n");
			free_bootmem_cpumask_var(tmp);
			free_bootmem_cpumask_var(non_housekeeping_mask);
			return 0;
		}
	}
	free_bootmem_cpumask_var(tmp);

	if ((flags & HK_FLAG_TICK) && !(housekeeping_flags & HK_FLAG_TICK)) {
		if (IS_ENABLED(CONFIG_NO_HZ_FULL)) {
			/* 只在non housekeeping的cpu上支持nohz模式 */
			tick_nohz_full_setup(non_housekeeping_mask);
		} else {
			pr_warn("Housekeeping: nohz unsupported."
				" Build with CONFIG_NO_HZ_FULL\n");
			free_bootmem_cpumask_var(non_housekeeping_mask);
			return 0;
		}
	}

	housekeeping_flags |= flags;

	free_bootmem_cpumask_var(non_housekeeping_mask);

	return 1;
}

/* nohz时需要设置以下的housekeeping标志 */
static int __init housekeeping_nohz_full_setup(char *str)
{
	unsigned int flags;

	flags = HK_FLAG_TICK | HK_FLAG_WQ | HK_FLAG_TIMER | HK_FLAG_RCU |
		HK_FLAG_MISC | HK_FLAG_KTHREAD;

	return housekeeping_setup(str, flags);
}
__setup("nohz_full=", housekeeping_nohz_full_setup);

/* housekeeping isol cpu设置 */
static int __init housekeeping_isolcpus_setup(char *str)
{
	unsigned int flags = 0;
	bool illegal = false;
	char *par;
	int len;

	while (isalpha(*str)) {
		/* 若配置了nohz，则设置HK_FLAG_TICK标志 */
		if (!strncmp(str, "nohz,", 5)) {
			str += 5;
			flags |= HK_FLAG_TICK;
			continue;
		}

		/* 若配置了domain，则设置HK_FLAG_DOMAIN */
		if (!strncmp(str, "domain,", 7)) {
			str += 7;
			flags |= HK_FLAG_DOMAIN;
			continue;
		}

		/* 若配置了managed_irq，则设置HK_FLAG_MANAGED_IRQ */
		if (!strncmp(str, "managed_irq,", 12)) {
			str += 12;
			flags |= HK_FLAG_MANAGED_IRQ;
			continue;
		}

		/*
		 * Skip unknown sub-parameter and validate that it is not
		 * containing an invalid character.
		 */
		/* 跳过不合法的参数 */
		for (par = str, len = 0; *str && *str != ','; str++, len++) {
			if (!isalpha(*str) && *str != '_')
				illegal = true;
		}

		if (illegal) {
			pr_warn("isolcpus: Invalid flag %.*s\n", len, par);
			return 0;
		}

		/* 循环以处理乱序参数 */
		pr_info("isolcpus: Skipped unknown flag %.*s\n", len, par);
		str++;
	}

	/* Default behaviour for isolcpus without flags */
	/* 若未设置flag，则将HK_FLAG_DOMAIN设置为其默认标志 */
	if (!flags)
		flags |= HK_FLAG_DOMAIN;

	return housekeeping_setup(str, flags);
}
__setup("isolcpus=", housekeeping_isolcpus_setup);
