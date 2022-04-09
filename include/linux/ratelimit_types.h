/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RATELIMIT_TYPES_H
#define _LINUX_RATELIMIT_TYPES_H

#include <linux/bits.h>
#include <linux/param.h>
#include <linux/spinlock_types.h>

#define DEFAULT_RATELIMIT_INTERVAL	(5 * HZ)
#define DEFAULT_RATELIMIT_BURST		10

/* issue num suppressed message on exit */
#define RATELIMIT_MSG_ON_RELEASE	BIT(0)

/* ratelimit状态
   该结构体用于描述一个给定时间间隔内，最大可调用的次数不超过burst次。
   若超过则会被限制。
*/
struct ratelimit_state {
	raw_spinlock_t	lock;		/* protect the state */

	/* 给定的时间间隔 */
	int		interval;
	/* 一个时间间隔内最大的调用次数 */
	int		burst;
	/* 一个事件间隔内已调用的次数 */
	int		printed;
	/* 当前周期已丢失的次数 */
	int		missed;
	/* 当前这个周期的起始时间 */
	unsigned long	begin;
	unsigned long	flags;
};

/* 初始化ratelimit */
#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) {		\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

/* ratelimit初始化为disable状态 */
#define RATELIMIT_STATE_INIT_DISABLED					\
	RATELIMIT_STATE_INIT(ratelimit_state, 0, DEFAULT_RATELIMIT_BURST)

/* 定义ratelimit状态 */
#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);
#define __ratelimit(state) ___ratelimit(state, __func__)

#endif /* _LINUX_RATELIMIT_TYPES_H */
