/*
 * cpuidle.h - a generic framework for CPU idle power management
 *
 * (C) 2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *          Shaohua Li <shaohua.li@intel.com>
 *          Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#ifndef _LINUX_CPUIDLE_H
#define _LINUX_CPUIDLE_H

#include <linux/percpu.h>
#include <linux/list.h>
#include <linux/hrtimer.h>

/* 最大的cpuidle状态数量 */
#define CPUIDLE_STATE_MAX	10
#define CPUIDLE_NAME_LEN	16
#define CPUIDLE_DESC_LEN	32

struct module;

struct cpuidle_device;
struct cpuidle_driver;


/****************************
 * CPUIDLE DEVICE INTERFACE *
 ****************************/

#define CPUIDLE_STATE_DISABLED_BY_USER		BIT(0)
#define CPUIDLE_STATE_DISABLED_BY_DRIVER	BIT(1)

struct cpuidle_state_usage {
	unsigned long long	disable;
	unsigned long long	usage;
	u64			time_ns;
	unsigned long long	above; /* Number of times it's been too deep */
	unsigned long long	below; /* Number of times it's been too shallow */
	unsigned long long	rejected; /* Number of times idle entry was rejected */
#ifdef CONFIG_SUSPEND
	unsigned long long	s2idle_usage;
	unsigned long long	s2idle_time; /* in US */
#endif
};

/* cpuidle状态 */
struct cpuidle_state {
	/* 状态名字、描述 */
	char		name[CPUIDLE_NAME_LEN];
	char		desc[CPUIDLE_DESC_LEN];

	/* 该idle状态返回的latency，ns */
	s64		exit_latency_ns;
	/* 进入该idle状态期望的停留时间，ns */
	s64		target_residency_ns;
	/* 该状态的标志 */
	unsigned int	flags;
	/* 该idle状态返回的latency，ms */
	unsigned int	exit_latency; /* in US */
	/* cpu在该idle状态下的功耗，mw */
	int		power_usage; /* in mW */
	/* 进入该idle状态期望的停留时间，us */
	unsigned int	target_residency; /* in US */

	/* 进入idle回调 */
	int (*enter)	(struct cpuidle_device *dev,
			struct cpuidle_driver *drv,
			int index);
	/* cpu长时间不工作时（offline），可调用该回调 */
	int (*enter_dead) (struct cpuidle_device *dev, int index);

	/*
	 * CPUs execute ->enter_s2idle with the local tick or entire timekeeping
	 * suspended, so it must not re-enable interrupts at any point (even
	 * temporarily) or attempt to change states of clock event devices.
	 *
	 * This callback may point to the same function as ->enter if all of
	 * the above requirements are met by it.
	 */
	/* 执行该回调需要suspend本cpu tick，以及整个timekeeping，因此其不能
       在任何位置重新使能中断，或试图改变clock event设备的状态。
       在以上条件满足时，该回调可能与enter指向同一个函数
	*/
	int (*enter_s2idle)(struct cpuidle_device *dev,
			    struct cpuidle_driver *drv,
			    int index);
};

/* Idle State Flags */
#define CPUIDLE_FLAG_NONE       	(0x00)
/* polling状态 */
#define CPUIDLE_FLAG_POLLING		BIT(0) /* polling state */
/* 该状态会同时在多个cpu上起作用，软件需做同步 */
#define CPUIDLE_FLAG_COUPLED		BIT(1) /* state applies to multiple cpus */
/* 该状态下，timer会停止 */
#define CPUIDLE_FLAG_TIMER_STOP 	BIT(2) /* timer is stopped on this state */
/* 避免使用该状态 */
#define CPUIDLE_FLAG_UNUSABLE		BIT(3) /* avoid using this state */
/* 默认关闭该状态 */
#define CPUIDLE_FLAG_OFF		BIT(4) /* disable this state by default */
/* idle-state会刷tlb */
#define CPUIDLE_FLAG_TLB_FLUSHED	BIT(5) /* idle-state flushes TLBs */
/* idle-state会关注RCU */
#define CPUIDLE_FLAG_RCU_IDLE		BIT(6) /* idle-state takes care of RCU */

struct cpuidle_device_kobj;
struct cpuidle_state_kobj;
struct cpuidle_driver_kobj;

/* cpuidle设备结构体 */
struct cpuidle_device {
	/* 该cpuidle设备是否已注册 */
	unsigned int		registered:1;
	/* 该cpuidle设备是否已使能 */
	unsigned int		enabled:1;
	unsigned int		poll_time_limit:1;
	/* 其对应的cpu */
	unsigned int		cpu;
	ktime_t			next_hrtimer;

	/* 上一次进入idle的状态index */
	int			last_state_idx;
	/* 该设备上一次停留在idle状态的时间，单位为ns */
	u64			last_residency_ns;
	u64			poll_limit_ns;
	u64			forced_idle_latency_limit_ns;
	/* 该设备的统计值 */
	struct cpuidle_state_usage	states_usage[CPUIDLE_STATE_MAX];
	/* 用于sysfs */
	struct cpuidle_state_kobj *kobjs[CPUIDLE_STATE_MAX];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	/* 链表节点 */
	struct list_head 	device_list;

#ifdef CONFIG_ARCH_NEEDS_CPU_IDLE_COUPLED
	/* 与其相关的coupled cpus位表 */
	cpumask_t		coupled_cpus;
	struct cpuidle_coupled	*coupled;
#endif
};

DECLARE_PER_CPU(struct cpuidle_device *, cpuidle_devices);
DECLARE_PER_CPU(struct cpuidle_device, cpuidle_dev);

/****************************
 * CPUIDLE DRIVER INTERFACE *
 ****************************/
/* cpuidle驱动 */
struct cpuidle_driver {
	/* 驱动名 */
	const char		*name;
	struct module 		*owner;

    /* used by the cpuidle framework to setup the broadcast timer，
    */
	/* 由cpuidle框架使用，以设置broadcast定时器 
       用于指示在cpuidle driver注册和注销时，是否需要设置一个broadcast timer
	*/
	unsigned int            bctimer:1;
	/* states array must be ordered in decreasing power consumption */
	/* 该驱动支持的cpuidle状态，它以功耗从大到小的顺序排序 */
	struct cpuidle_state	states[CPUIDLE_STATE_MAX];
	/* 支持的状态数目 */
	int			state_count;
	/* 与coupled state有关 */
	int			safe_state_index;

	/* the driver handles the cpus in cpumask */
	/* 该驱动支持的cpu掩码 */
	struct cpumask		*cpumask;

	/* preferred governor to switch at register time */
	/* 注册时该驱动prefer的governor */
	const char		*governor;
};

#ifdef CONFIG_CPU_IDLE
extern void disable_cpuidle(void);
extern bool cpuidle_not_available(struct cpuidle_driver *drv,
				  struct cpuidle_device *dev);

extern int cpuidle_select(struct cpuidle_driver *drv,
			  struct cpuidle_device *dev,
			  bool *stop_tick);
extern int cpuidle_enter(struct cpuidle_driver *drv,
			 struct cpuidle_device *dev, int index);
extern void cpuidle_reflect(struct cpuidle_device *dev, int index);
extern u64 cpuidle_poll_time(struct cpuidle_driver *drv,
			     struct cpuidle_device *dev);

extern int cpuidle_register_driver(struct cpuidle_driver *drv);
extern struct cpuidle_driver *cpuidle_get_driver(void);
extern void cpuidle_driver_state_disabled(struct cpuidle_driver *drv, int idx,
					bool disable);
extern void cpuidle_unregister_driver(struct cpuidle_driver *drv);
extern int cpuidle_register_device(struct cpuidle_device *dev);
extern void cpuidle_unregister_device(struct cpuidle_device *dev);
extern int cpuidle_register(struct cpuidle_driver *drv,
			    const struct cpumask *const coupled_cpus);
extern void cpuidle_unregister(struct cpuidle_driver *drv);
extern void cpuidle_pause_and_lock(void);
extern void cpuidle_resume_and_unlock(void);
extern void cpuidle_pause(void);
extern void cpuidle_resume(void);
extern int cpuidle_enable_device(struct cpuidle_device *dev);
extern void cpuidle_disable_device(struct cpuidle_device *dev);
extern int cpuidle_play_dead(void);

extern struct cpuidle_driver *cpuidle_get_cpu_driver(struct cpuidle_device *dev);
static inline struct cpuidle_device *cpuidle_get_device(void)
{return __this_cpu_read(cpuidle_devices); }
#else
static inline void disable_cpuidle(void) { }
static inline bool cpuidle_not_available(struct cpuidle_driver *drv,
					 struct cpuidle_device *dev)
{return true; }
static inline int cpuidle_select(struct cpuidle_driver *drv,
				 struct cpuidle_device *dev, bool *stop_tick)
{return -ENODEV; }
static inline int cpuidle_enter(struct cpuidle_driver *drv,
				struct cpuidle_device *dev, int index)
{return -ENODEV; }
static inline void cpuidle_reflect(struct cpuidle_device *dev, int index) { }
static inline u64 cpuidle_poll_time(struct cpuidle_driver *drv,
			     struct cpuidle_device *dev)
{return 0; }
static inline int cpuidle_register_driver(struct cpuidle_driver *drv)
{return -ENODEV; }
static inline struct cpuidle_driver *cpuidle_get_driver(void) {return NULL; }
static inline void cpuidle_driver_state_disabled(struct cpuidle_driver *drv,
					       int idx, bool disable) { }
static inline void cpuidle_unregister_driver(struct cpuidle_driver *drv) { }
static inline int cpuidle_register_device(struct cpuidle_device *dev)
{return -ENODEV; }
static inline void cpuidle_unregister_device(struct cpuidle_device *dev) { }
static inline int cpuidle_register(struct cpuidle_driver *drv,
				   const struct cpumask *const coupled_cpus)
{return -ENODEV; }
static inline void cpuidle_unregister(struct cpuidle_driver *drv) { }
static inline void cpuidle_pause_and_lock(void) { }
static inline void cpuidle_resume_and_unlock(void) { }
static inline void cpuidle_pause(void) { }
static inline void cpuidle_resume(void) { }
static inline int cpuidle_enable_device(struct cpuidle_device *dev)
{return -ENODEV; }
static inline void cpuidle_disable_device(struct cpuidle_device *dev) { }
static inline int cpuidle_play_dead(void) {return -ENODEV; }
static inline struct cpuidle_driver *cpuidle_get_cpu_driver(
	struct cpuidle_device *dev) {return NULL; }
static inline struct cpuidle_device *cpuidle_get_device(void) {return NULL; }
#endif

#ifdef CONFIG_CPU_IDLE
extern int cpuidle_find_deepest_state(struct cpuidle_driver *drv,
				      struct cpuidle_device *dev,
				      u64 latency_limit_ns);
extern int cpuidle_enter_s2idle(struct cpuidle_driver *drv,
				struct cpuidle_device *dev);
extern void cpuidle_use_deepest_state(u64 latency_limit_ns);
#else
static inline int cpuidle_find_deepest_state(struct cpuidle_driver *drv,
					     struct cpuidle_device *dev,
					     u64 latency_limit_ns)
{return -ENODEV; }
static inline int cpuidle_enter_s2idle(struct cpuidle_driver *drv,
				       struct cpuidle_device *dev)
{return -ENODEV; }
static inline void cpuidle_use_deepest_state(u64 latency_limit_ns)
{
}
#endif

/* kernel/sched/idle.c */
extern void sched_idle_set_state(struct cpuidle_state *idle_state);
extern void default_idle_call(void);

#ifdef CONFIG_ARCH_NEEDS_CPU_IDLE_COUPLED
void cpuidle_coupled_parallel_barrier(struct cpuidle_device *dev, atomic_t *a);
#else
static inline void cpuidle_coupled_parallel_barrier(struct cpuidle_device *dev, atomic_t *a)
{
}
#endif

#if defined(CONFIG_CPU_IDLE) && defined(CONFIG_ARCH_HAS_CPU_RELAX)
void cpuidle_poll_state_init(struct cpuidle_driver *drv);
#else
static inline void cpuidle_poll_state_init(struct cpuidle_driver *drv) {}
#endif

/******************************
 * CPUIDLE GOVERNOR INTERFACE *
 ******************************/

/* cpuidle governor结构体 */
struct cpuidle_governor {
	/* governor名 */
	char			name[CPUIDLE_NAME_LEN];
	/* 将其加入全局链表的节点 */
	struct list_head 	governor_list;
	/* 该governor的评分 */
	unsigned int		rating;

	/* 操作回调 */
	int  (*enable)		(struct cpuidle_driver *drv,
					struct cpuidle_device *dev);
	void (*disable)		(struct cpuidle_driver *drv,
					struct cpuidle_device *dev);

	int  (*select)		(struct cpuidle_driver *drv,
					struct cpuidle_device *dev,
					bool *stop_tick);
	void (*reflect)		(struct cpuidle_device *dev, int index);
};

extern int cpuidle_register_governor(struct cpuidle_governor *gov);
extern s64 cpuidle_governor_latency_req(unsigned int cpu);

#define __CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter,			\
				idx,					\
				state,					\
				is_retention)				\
({									\
	int __ret = 0;							\
									\
	if (!idx) {							\
		cpu_do_idle();						\
		return idx;						\
	}								\
									\
	if (!is_retention)						\
		__ret =  cpu_pm_enter();				\
	if (!__ret) {							\
		__ret = low_level_idle_enter(state);			\
		if (!is_retention)					\
			cpu_pm_exit();					\
	}								\
									\
	__ret ? -1 : idx;						\
})

#define CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx)	\
	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 0)

#define CPU_PM_CPU_IDLE_ENTER_RETENTION(low_level_idle_enter, idx)	\
	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 1)

#define CPU_PM_CPU_IDLE_ENTER_PARAM(low_level_idle_enter, idx, state)	\
	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0)

#define CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(low_level_idle_enter, idx, state)	\
	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1)

#endif /* _LINUX_CPUIDLE_H */
