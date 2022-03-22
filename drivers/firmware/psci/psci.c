// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2015 ARM Limited
 */

#define pr_fmt(fmt) "psci: " fmt

#include <linux/acpi.h>
#include <linux/arm-smccc.h>
#include <linux/cpuidle.h>
#include <linux/errno.h>
#include <linux/linkage.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/printk.h>
#include <linux/psci.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/suspend.h>

#include <uapi/linux/psci.h>

#include <asm/cpuidle.h>
#include <asm/cputype.h>
#include <asm/hypervisor.h>
#include <asm/system_misc.h>
#include <asm/smp_plat.h>
#include <asm/suspend.h>

/*
 * While a 64-bit OS can make calls with SMC32 calling conventions, for some
 * calls it is necessary to use SMC64 to pass or return 64-bit values.
 * For such calls PSCI_FN_NATIVE(version, name) will choose the appropriate
 * (native-width) function ID.
 */
#ifdef CONFIG_64BIT
#define PSCI_FN_NATIVE(version, name)	PSCI_##version##_FN64_##name
#else
#define PSCI_FN_NATIVE(version, name)	PSCI_##version##_FN_##name
#endif

/*
 * The CPU any Trusted OS is resident on. The trusted OS may reject CPU_OFF
 * calls to its resident CPU, so we must avoid issuing those. We never migrate
 * a Trusted OS even if it claims to be capable of migration -- doing so will
 * require cooperation with a Trusted OS driver.
 */
static int resident_cpu = -1;
struct psci_operations psci_ops;
static enum arm_smccc_conduit psci_conduit = SMCCC_CONDUIT_NONE;

bool psci_tos_resident_on(int cpu)
{
	return cpu == resident_cpu;
}

typedef unsigned long (psci_fn)(unsigned long, unsigned long,
				unsigned long, unsigned long);
static psci_fn *invoke_psci_fn;

static struct psci_0_1_function_ids psci_0_1_function_ids;

struct psci_0_1_function_ids get_psci_0_1_function_ids(void)
{
	return psci_0_1_function_ids;
}

#define PSCI_0_2_POWER_STATE_MASK		\
				(PSCI_0_2_POWER_STATE_ID_MASK | \
				PSCI_0_2_POWER_STATE_TYPE_MASK | \
				PSCI_0_2_POWER_STATE_AFFL_MASK)

#define PSCI_1_0_EXT_POWER_STATE_MASK		\
				(PSCI_1_0_EXT_POWER_STATE_ID_MASK | \
				PSCI_1_0_EXT_POWER_STATE_TYPE_MASK)

static u32 psci_cpu_suspend_feature;
static bool psci_system_reset2_supported;

static inline bool psci_has_ext_power_state(void)
{
	return psci_cpu_suspend_feature &
				PSCI_1_0_FEATURES_CPU_SUSPEND_PF_MASK;
}

/* 是否支持os初始化 */
bool psci_has_osi_support(void)
{
	return psci_cpu_suspend_feature & PSCI_1_0_OS_INITIATED;
}

static inline bool psci_power_state_loses_context(u32 state)
{
	const u32 mask = psci_has_ext_power_state() ?
					PSCI_1_0_EXT_POWER_STATE_TYPE_MASK :
					PSCI_0_2_POWER_STATE_TYPE_MASK;

	return state & mask;
}

bool psci_power_state_is_valid(u32 state)
{
	const u32 valid_mask = psci_has_ext_power_state() ?
			       PSCI_1_0_EXT_POWER_STATE_MASK :
			       PSCI_0_2_POWER_STATE_MASK;

	return !(state & ~valid_mask);
}

/* hvc触发方式 */
static unsigned long __invoke_psci_fn_hvc(unsigned long function_id,
			unsigned long arg0, unsigned long arg1,
			unsigned long arg2)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(function_id, arg0, arg1, arg2, 0, 0, 0, 0, &res);
	return res.a0;
}

/* smc触发方式 */
static unsigned long __invoke_psci_fn_smc(unsigned long function_id,
			unsigned long arg0, unsigned long arg1,
			unsigned long arg2)
{
	struct arm_smccc_res res;

	arm_smccc_smc(function_id, arg0, arg1, arg2, 0, 0, 0, 0, &res);
	return res.a0;
}

/* 错误码转换 */
static int psci_to_linux_errno(int errno)
{
	switch (errno) {
	case PSCI_RET_SUCCESS:
		return 0;
	case PSCI_RET_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case PSCI_RET_INVALID_PARAMS:
	case PSCI_RET_INVALID_ADDRESS:
		return -EINVAL;
	case PSCI_RET_DENIED:
		return -EPERM;
	}

	return -EINVAL;
}

/* 获取psci 0.1的版本 */
static u32 psci_0_1_get_version(void)
{
	return PSCI_VERSION(0, 1);
}

/* 获取psci的版本，可以为0.2或1.0 */
static u32 psci_0_2_get_version(void)
{
	return invoke_psci_fn(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);
}

/* 设置suspend模式，osi模式或pc模式 */
int psci_set_osi_mode(bool enable)
{
	unsigned long suspend_mode;
	int err;

	suspend_mode = enable ? PSCI_1_0_SUSPEND_MODE_OSI :
			PSCI_1_0_SUSPEND_MODE_PC;

	err = invoke_psci_fn(PSCI_1_0_FN_SET_SUSPEND_MODE, suspend_mode, 0, 0);
	return psci_to_linux_errno(err);
}

static int __psci_cpu_suspend(u32 fn, u32 state, unsigned long entry_point)
{
	int err;

	err = invoke_psci_fn(fn, state, entry_point, 0);
	return psci_to_linux_errno(err);
}

/* 0.1版本cpu suspend接口 */
static int psci_0_1_cpu_suspend(u32 state, unsigned long entry_point)
{
	return __psci_cpu_suspend(psci_0_1_function_ids.cpu_suspend,
				  state, entry_point);
}

/* 0.2版本cpu suspend接口 */
static int psci_0_2_cpu_suspend(u32 state, unsigned long entry_point)
{
	return __psci_cpu_suspend(PSCI_FN_NATIVE(0_2, CPU_SUSPEND),
				  state, entry_point);
}

static int __psci_cpu_off(u32 fn, u32 state)
{
	int err;

	err = invoke_psci_fn(fn, state, 0, 0);
	return psci_to_linux_errno(err);
}

/* 0.1版本cpu off接口 */
static int psci_0_1_cpu_off(u32 state)
{
	return __psci_cpu_off(psci_0_1_function_ids.cpu_off, state);
}

/* 0.2版本cpu off接口 */
static int psci_0_2_cpu_off(u32 state)
{
	return __psci_cpu_off(PSCI_0_2_FN_CPU_OFF, state);
}

static int __psci_cpu_on(u32 fn, unsigned long cpuid, unsigned long entry_point)
{
	int err;

	err = invoke_psci_fn(fn, cpuid, entry_point, 0);
	return psci_to_linux_errno(err);
}

/* 0.1版本cpu on接口 */
static int psci_0_1_cpu_on(unsigned long cpuid, unsigned long entry_point)
{
	return __psci_cpu_on(psci_0_1_function_ids.cpu_on, cpuid, entry_point);
}

/* 0.2版本cpu on接口 */
static int psci_0_2_cpu_on(unsigned long cpuid, unsigned long entry_point)
{
	return __psci_cpu_on(PSCI_FN_NATIVE(0_2, CPU_ON), cpuid, entry_point);
}

static int __psci_migrate(u32 fn, unsigned long cpuid)
{
	int err;

	err = invoke_psci_fn(fn, cpuid, 0, 0);
	return psci_to_linux_errno(err);
}

/* 0.1版本migrate接口 */
static int psci_0_1_migrate(unsigned long cpuid)
{
	return __psci_migrate(psci_0_1_function_ids.migrate, cpuid);
}

/* 0.2版本migrate接口 */
static int psci_0_2_migrate(unsigned long cpuid)
{
	return __psci_migrate(PSCI_FN_NATIVE(0_2, MIGRATE), cpuid);
}

/* 设置psci的affinity信息 */
static int psci_affinity_info(unsigned long target_affinity,
		unsigned long lowest_affinity_level)
{
	return invoke_psci_fn(PSCI_FN_NATIVE(0_2, AFFINITY_INFO),
			      target_affinity, lowest_affinity_level, 0);
}

/* 设置psci的affinity类型 */
static int psci_migrate_info_type(void)
{
	return invoke_psci_fn(PSCI_0_2_FN_MIGRATE_INFO_TYPE, 0, 0, 0);
}

/* 设置psci的affinity类型 */
static unsigned long psci_migrate_info_up_cpu(void)
{
	return invoke_psci_fn(PSCI_FN_NATIVE(0_2, MIGRATE_INFO_UP_CPU),
			      0, 0, 0);
}

/* 设置psci触发函数 */
static void set_conduit(enum arm_smccc_conduit conduit)
{
	switch (conduit) {
	case SMCCC_CONDUIT_HVC:
		invoke_psci_fn = __invoke_psci_fn_hvc;
		break;
	case SMCCC_CONDUIT_SMC:
		invoke_psci_fn = __invoke_psci_fn_smc;
		break;
	default:
		WARN(1, "Unexpected PSCI conduit %d\n", conduit);
	}

	psci_conduit = conduit;
}

/* 获取psci的method，可以为smc或hvc */
static int get_set_conduit_method(struct device_node *np)
{
	const char *method;

	pr_info("probing for conduit method from DT.\n");

	/* 获取method属性 */
	if (of_property_read_string(np, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return -ENXIO;
	}

	/* 根据设定值，设置psci触发函数 */
	if (!strcmp("hvc", method)) {
		set_conduit(SMCCC_CONDUIT_HVC);
	} else if (!strcmp("smc", method)) {
		set_conduit(SMCCC_CONDUIT_SMC);
	} else {
		pr_warn("invalid \"method\" property: %s\n", method);
		return -EINVAL;
	}
	return 0;
}

/* psci的系统重启回调函数 */
static int psci_sys_reset(struct notifier_block *nb, unsigned long action,
			  void *data)
{
	if ((reboot_mode == REBOOT_WARM || reboot_mode == REBOOT_SOFT) &&
	    psci_system_reset2_supported) {
		/*
		 * reset_type[31] = 0 (architectural)
		 * reset_type[30:0] = 0 (SYSTEM_WARM_RESET)
		 * cookie = 0 (ignored by the implementation)
		 */
		invoke_psci_fn(PSCI_FN_NATIVE(1_1, SYSTEM_RESET2), 0, 0, 0);
	} else {
		invoke_psci_fn(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
	}

	return NOTIFY_DONE;
}

/* psci的reset回调 */
static struct notifier_block psci_sys_reset_nb = {
	.notifier_call = psci_sys_reset,
	.priority = 129,
};

/* poweroff回调函数 */
static void psci_sys_poweroff(void)
{
	invoke_psci_fn(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
}

/* 获取psci feature */
static int __init psci_features(u32 psci_func_id)
{
	return invoke_psci_fn(PSCI_1_0_FN_PSCI_FEATURES,
			      psci_func_id, 0, 0);
}

#ifdef CONFIG_CPU_IDLE
/* psci的suspend函数 */
static int psci_suspend_finisher(unsigned long state)
{
	u32 power_state = state;
	phys_addr_t pa_cpu_resume = __pa_symbol(function_nocfi(cpu_resume));

	/* cpu的resume地址由参数传给bl31 */
	return psci_ops.cpu_suspend(power_state, pa_cpu_resume);
}

/* psci CPU进入suspend流程 */
int psci_cpu_suspend_enter(u32 state)
{
	int ret;

	if (!psci_power_state_loses_context(state)) {
		/* 没有lost context */
		struct arm_cpuidle_irq_context context;

		/* 保存中断上下文 */
		arm_cpuidle_save_irq_context(&context);
		/* 调用psci的cpu suspend回调 */
		ret = psci_ops.cpu_suspend(state, 0);
		/* 恢复中断上下文 */
		arm_cpuidle_restore_irq_context(&context);
	} else {
		/* lost context */
		ret = cpu_suspend(state, psci_suspend_finisher);
	}

	return ret;
}
#endif

static int psci_system_suspend(unsigned long unused)
{
	phys_addr_t pa_cpu_resume = __pa_symbol(function_nocfi(cpu_resume));

	return invoke_psci_fn(PSCI_FN_NATIVE(1_0, SYSTEM_SUSPEND),
			      pa_cpu_resume, 0, 0);
}

static int psci_system_suspend_enter(suspend_state_t state)
{
	return cpu_suspend(0, psci_system_suspend);
}

/* psci方式的suspend操作函数 */
static const struct platform_suspend_ops psci_suspend_ops = {
	.valid          = suspend_valid_only_mem,
	.enter          = psci_system_suspend_enter,
};

/* 初始化系统reset2 feature */
static void __init psci_init_system_reset2(void)
{
	int ret;

	/* 判断reset2特性是否支持 */
	ret = psci_features(PSCI_FN_NATIVE(1_1, SYSTEM_RESET2));

	if (ret != PSCI_RET_NOT_SUPPORTED)
		psci_system_reset2_supported = true;
}

/* 初始化系统suspend feature */
static void __init psci_init_system_suspend(void)
{
	int ret;

	/* 不支持suspend */
	if (!IS_ENABLED(CONFIG_SUSPEND))
		return;

	/* 判断系统suspend特性是否支持 */
	ret = psci_features(PSCI_FN_NATIVE(1_0, SYSTEM_SUSPEND));

	/* 若支持，则将suspend操作设置为psci_suspend_ops */
	if (ret != PSCI_RET_NOT_SUPPORTED)
		suspend_set_ops(&psci_suspend_ops);
}

/* 初始化cpu suspend feature */
static void __init psci_init_cpu_suspend(void)
{
	/* psci是否支持cpu suspend特性 */
	int feature = psci_features(PSCI_FN_NATIVE(0_2, CPU_SUSPEND));

	/* 保存suspend feature */
	if (feature != PSCI_RET_NOT_SUPPORTED)
		psci_cpu_suspend_feature = feature;
}

/*
 * Detect the presence of a resident Trusted OS which may cause CPU_OFF to
 * return DENIED (which would be fatal).
 */
/* 检测驻留的TOS是否存在，这可能会导致CPU_OFF返回拒绝 */
static void __init psci_init_migrate(void)
{
	unsigned long cpuid;
	int type, cpu = -1;

	type = psci_ops.migrate_info_type();

	if (type == PSCI_0_2_TOS_MP) {
		pr_info("Trusted OS migration not required\n");
		return;
	}

	if (type == PSCI_RET_NOT_SUPPORTED) {
		pr_info("MIGRATE_INFO_TYPE not supported.\n");
		return;
	}

	if (type != PSCI_0_2_TOS_UP_MIGRATE &&
	    type != PSCI_0_2_TOS_UP_NO_MIGRATE) {
		pr_err("MIGRATE_INFO_TYPE returned unknown type (%d)\n", type);
		return;
	}

	cpuid = psci_migrate_info_up_cpu();
	if (cpuid & ~MPIDR_HWID_BITMASK) {
		pr_warn("MIGRATE_INFO_UP_CPU reported invalid physical ID (0x%lx)\n",
			cpuid);
		return;
	}

	cpu = get_logical_index(cpuid);
	resident_cpu = cpu >= 0 ? cpu : -1;

	pr_info("Trusted OS resident on physical CPU 0x%lx\n", cpuid);
}

/* psci的smccc初始化 */
static void __init psci_init_smccc(void)
{
	u32 ver = ARM_SMCCC_VERSION_1_0;
	int feature;

	/* 获取psci feature */
	feature = psci_features(ARM_SMCCC_VERSION_FUNC_ID);

	if (feature != PSCI_RET_NOT_SUPPORTED) {
		u32 ret;
		/* 获取smccc的版本号 */
		ret = invoke_psci_fn(ARM_SMCCC_VERSION_FUNC_ID, 0, 0, 0);
		if (ret >= ARM_SMCCC_VERSION_1_1) {
			/* smccc的版本初始化 */
			arm_smccc_version_init(ret, psci_conduit);
			ver = ret;
		}
	}

	/*
	 * Conveniently, the SMCCC and PSCI versions are encoded the
	 * same way. No, this isn't accidental.
	 */
	pr_info("SMC Calling Convention v%d.%d\n",
		PSCI_VERSION_MAJOR(ver), PSCI_VERSION_MINOR(ver));

}

/* 设置psci 0.2的标准回调 */
static void __init psci_0_2_set_functions(void)
{
	pr_info("Using standard PSCI v0.2 function IDs\n");

	/* 设置psci 0.2的标准回调 */
	psci_ops = (struct psci_operations){
		.get_version = psci_0_2_get_version,
		.cpu_suspend = psci_0_2_cpu_suspend,
		.cpu_off = psci_0_2_cpu_off,
		.cpu_on = psci_0_2_cpu_on,
		.migrate = psci_0_2_migrate,
		.affinity_info = psci_affinity_info,
		.migrate_info_type = psci_migrate_info_type,
	};

	/* 设置psci的重启回调,它由reboot模块在系统重启时调用 */
	register_restart_handler(&psci_sys_reset_nb);

	/* 设置psci的下电回调,它由reboot模块在系统下电时调用 */
	pm_power_off = psci_sys_poweroff;
}

/*
 * Probe function for PSCI firmware versions >= 0.2
 */
/* psci probe函数 */
static int __init psci_probe(void)
{
	/* 获取版本号，版本号由bl31确定，最新的为1.0 */
	u32 ver = psci_0_2_get_version();

	pr_info("PSCIv%d.%d detected in firmware.\n",
			PSCI_VERSION_MAJOR(ver),
			PSCI_VERSION_MINOR(ver));

	if (PSCI_VERSION_MAJOR(ver) == 0 && PSCI_VERSION_MINOR(ver) < 2) {
		pr_err("Conflicting PSCI version detected.\n");
		return -EINVAL;
	}

	/* 设置psci 0.2的标准回调 */
	psci_0_2_set_functions();

	/* 检测驻留的TOS是否存在，这可能会导致CPU_OFF返回拒绝 */
	psci_init_migrate();

	/* 版本号大于等于1.x */
	if (PSCI_VERSION_MAJOR(ver) >= 1) {
		/* smccc的版本初始化 */
		psci_init_smccc();
		/* 初始化cpu suspend feature */
		psci_init_cpu_suspend();
		/* 初始化系统suspend feature */
		psci_init_system_suspend();
		/* 初始化系统reset2 */
		psci_init_system_reset2();
		/* 初始化hyp服务 */
		kvm_init_hyp_services();
	}

	return 0;
}

typedef int (*psci_initcall_t)(const struct device_node *);

/*
 * PSCI init function for PSCI versions >=0.2
 *
 * Probe based on PSCI PSCI_VERSION function
 */
/* psci 0.2协议初始化 */
static int __init psci_0_2_init(struct device_node *np)
{
	int err;

	/* 获取psci的method，可以为smc或hvc */
	err = get_set_conduit_method(np);
	if (err)
		return err;

	/*
	 * Starting with v0.2, the PSCI specification introduced a call
	 * (PSCI_VERSION) that allows probing the firmware version, so
	 * that PSCI function IDs and version specific initialization
	 * can be carried out according to the specific version reported
	 * by firmware
	 */
	return psci_probe();
}

/*
 * PSCI < v0.2 get PSCI Function IDs via DT.
 */
/* psci 0.1初始化函数 */
static int __init psci_0_1_init(struct device_node *np)
{
	u32 id;
	int err;

	/* 获取psci的method，可以为smc或hvc */
	err = get_set_conduit_method(np);
	if (err)
		return err;

	pr_info("Using PSCI v0.1 Function IDs from DT\n");

	/* 获取psci版本的回调 */
	psci_ops.get_version = psci_0_1_get_version;

	/* 获取特定操作的psci id 
       psci 0.1支持cpu suspend、off、on和migrate接口
	*/
	if (!of_property_read_u32(np, "cpu_suspend", &id)) {
		psci_0_1_function_ids.cpu_suspend = id;
		psci_ops.cpu_suspend = psci_0_1_cpu_suspend;
	}

	if (!of_property_read_u32(np, "cpu_off", &id)) {
		psci_0_1_function_ids.cpu_off = id;
		psci_ops.cpu_off = psci_0_1_cpu_off;
	}

	if (!of_property_read_u32(np, "cpu_on", &id)) {
		psci_0_1_function_ids.cpu_on = id;
		psci_ops.cpu_on = psci_0_1_cpu_on;
	}

	if (!of_property_read_u32(np, "migrate", &id)) {
		psci_0_1_function_ids.migrate = id;
		psci_ops.migrate = psci_0_1_migrate;
	}

	return 0;
}

/* psci 1.0协议初始化 */
static int __init psci_1_0_init(struct device_node *np)
{
	int err;

	/* psci 0.2协议初始化 */
	err = psci_0_2_init(np);
	if (err)
		return err;

	if (psci_has_osi_support()) {
		pr_info("OSI mode supported.\n");

		/* Default to PC mode. */
		psci_set_osi_mode(false);
	}

	return 0;
}

static const struct of_device_id psci_of_match[] __initconst = {
	{ .compatible = "arm,psci",	.data = psci_0_1_init},
	{ .compatible = "arm,psci-0.2",	.data = psci_0_2_init},
	{ .compatible = "arm,psci-1.0",	.data = psci_1_0_init},
	{},
};

/* 设备树初始化 */
int __init psci_dt_init(void)
{
	struct device_node *np;
	const struct of_device_id *matched_np;
	psci_initcall_t init_fn;
	int ret;

	/* 查找匹配的device node */
	np = of_find_matching_node_and_match(NULL, psci_of_match, &matched_np);

	/* 检查该设备是否可用 */
	if (!np || !of_device_is_available(np))
		return -ENODEV;

	/* 获取并调用特定版本的初始化函数 */
	init_fn = (psci_initcall_t)matched_np->data;
	ret = init_fn(np);

	of_node_put(np);
	return ret;
}

#ifdef CONFIG_ACPI
/*
 * We use PSCI 0.2+ when ACPI is deployed on ARM64 and it's
 * explicitly clarified in SBBR
 */
int __init psci_acpi_init(void)
{
	if (!acpi_psci_present()) {
		pr_info("is not implemented in ACPI.\n");
		return -EOPNOTSUPP;
	}

	pr_info("probing for conduit method from ACPI.\n");

	if (acpi_psci_use_hvc())
		set_conduit(SMCCC_CONDUIT_HVC);
	else
		set_conduit(SMCCC_CONDUIT_SMC);

	return psci_probe();
}
#endif
