/*
 * governor.c - governor support
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/pm_qos.h>

#include "cpuidle.h"

char param_governor[CPUIDLE_NAME_LEN];

/* cpuidle_governors链表头 */
LIST_HEAD(cpuidle_governors);
struct cpuidle_governor *cpuidle_curr_governor;
struct cpuidle_governor *cpuidle_prev_governor;

/**
 * cpuidle_find_governor - finds a governor of the specified name
 * @str: the name
 *
 * Must be called with cpuidle_lock acquired.
 */
/* 根据名字，查找cpuidle结构体 */
struct cpuidle_governor *cpuidle_find_governor(const char *str)
{
	struct cpuidle_governor *gov;

	/* 从cpuidle_governors链表中查找，是否有与给定governor匹配的entry */
	list_for_each_entry(gov, &cpuidle_governors, governor_list)
		if (!strncasecmp(str, gov->name, CPUIDLE_NAME_LEN))
			return gov;

	return NULL;
}

/**
 * cpuidle_switch_governor - changes the governor
 * @gov: the new target governor
 * Must be called with cpuidle_lock acquired.
 */
/* cpuidle governor切换 */
int cpuidle_switch_governor(struct cpuidle_governor *gov)
{
	struct cpuidle_device *dev;

	if (!gov)
		return -EINVAL;

	if (gov == cpuidle_curr_governor)
		return 0;

	/* 卸载cpuidle idle循环处理函数 */
	cpuidle_uninstall_idle_handler();

	if (cpuidle_curr_governor) {
		/* disable所有cpuidle_detected_devices上的cpuidle设备，
           它会调用当前governor的disable回调
		*/
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_disable_device(dev);
	}

	/* 切换governor */
	cpuidle_curr_governor = gov;

	if (gov) {
		/* 使能所有cpuidle_detected_devices上的cpuidle设备，
           它会调用新governor的enable回调
		*/
		list_for_each_entry(dev, &cpuidle_detected_devices, device_list)
			cpuidle_enable_device(dev);
		/* 安装cpuidle idle loop处理函数 */
		cpuidle_install_idle_handler();
		printk(KERN_INFO "cpuidle: using governor %s\n", gov->name);
	}

	return 0;
}

/**
 * cpuidle_register_governor - registers a governor
 * @gov: the governor
 */
/* 注册cpuidle   governor */
int cpuidle_register_governor(struct cpuidle_governor *gov)
{
	int ret = -EEXIST;

	if (!gov || !gov->select)
		return -EINVAL;

	/* cpuidle是否已使能 */
	if (cpuidle_disabled())
		return -ENODEV;

	mutex_lock(&cpuidle_lock);
	/* 该governor未被注册，则执行注册流程。
       否则，不做处理
	*/
	if (cpuidle_find_governor(gov->name) == NULL) {
		ret = 0;
		/* 将其加入全局链表 */
		list_add_tail(&gov->governor_list, &cpuidle_governors);
		/* 以下条件下，cpuidle governor切换为当前governor： 
		  （1）cur governor未设置
		  （2）该governor与param_governor指定的名字相同
		  （3）该governor的评分比cur governor高，且其与
		       param_governor指定的名字不同
		*/
		if (!cpuidle_curr_governor ||
		    !strncasecmp(param_governor, gov->name, CPUIDLE_NAME_LEN) ||
		    (cpuidle_curr_governor->rating < gov->rating &&
		     strncasecmp(param_governor, cpuidle_curr_governor->name,
				 CPUIDLE_NAME_LEN)))
			cpuidle_switch_governor(gov);
	}
	mutex_unlock(&cpuidle_lock);

	return ret;
}

/**
 * cpuidle_governor_latency_req - Compute a latency constraint for CPU
 * @cpu: Target CPU
 */
s64 cpuidle_governor_latency_req(unsigned int cpu)
{
	struct device *device = get_cpu_device(cpu);
	/* 获取其qos的resume latency */
	int device_req = dev_pm_qos_raw_resume_latency(device);
	/* 获取全局的latency值 */
	int global_req = cpu_latency_qos_limit();

	/* 显然，本cpu的latency值不能大于全局latency */
	if (device_req > global_req)
		device_req = global_req;

	/* 转换为ns */
	return (s64)device_req * NSEC_PER_USEC;
}
