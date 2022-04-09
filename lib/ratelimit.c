// SPDX-License-Identifier: GPL-2.0-only
/*
 * ratelimit.c - Do something with rate limit.
 *
 * Isolated from kernel/printk.c by Dave Young <hidave.darkstar@gmail.com>
 *
 * 2008-05-01 rewrite the function and use a ratelimit_state data struct as
 * parameter. Now every user can use their own standalone ratelimit_state.
 */

#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <linux/export.h>

/*
 * __ratelimit - rate limiting
 * @rs: ratelimit_state data
 * @func: name of calling function
 *
 * This enforces a rate limit: not more than @rs->burst callbacks
 * in every @rs->interval
 *
 * RETURNS:
 * 0 means callbacks will be suppressed.
 * 1 means go ahead and do it.
 */
/* 该函数强制一个ratelimit，在每个rs->interval时间间隔内，允许调用的
   次数不超过rs->burst次
*/
int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
	unsigned long flags;
	int ret;

	if (!rs->interval)
		return 1;

	/*
	 * If we contend on this state's lock then almost
	 * by definition we are too busy to print a message,
	 * in addition to the one that will be printed by
	 * the entity that is holding the lock already:
	 */
	if (!raw_spin_trylock_irqsave(&rs->lock, flags))
		return 0;

	/* 起始时间，若未指定则指定为当前时间 */
	if (!rs->begin)
		rs->begin = jiffies;

	/* 若结束时间比当前时间还要早
       即前一周期已结束，开始下一周期
	*/
	if (time_is_before_jiffies(rs->begin + rs->interval)) {
		/* 若上一周期含有missed的情形，则重置该计数 */
		if (rs->missed) {
			if (!(rs->flags & RATELIMIT_MSG_ON_RELEASE)) {
				printk_deferred(KERN_WARNING
						"%s: %d callbacks suppressed\n",
						func, rs->missed);
				rs->missed = 0;
			}
		}
		/* 开始下一个周期 */
		rs->begin   = jiffies;
		rs->printed = 0;
	}
	if (rs->burst && rs->burst > rs->printed) {
		/* 该周期的调用次数未超过设定的burst值，返回1 */
		rs->printed++;
		ret = 1;
	} else {
		/* 该周期的调用次数超过burst值，增加丢失次数，并返回0 */
		rs->missed++;
		ret = 0;
	}
	raw_spin_unlock_irqrestore(&rs->lock, flags);

	return ret;
}
EXPORT_SYMBOL(___ratelimit);
