// SPDX-License-Identifier: GPL-2.0-only
/*
 * menu.c - the menu idle governor
 *
 * Copyright (C) 2006-2007 Adam Belay <abelay@novell.com>
 * Copyright (C) 2009 Intel Corporation
 * Author:
 *        Arjan van de Ven <arjan@linux.intel.com>
 */

#include <linux/kernel.h>
#include <linux/cpuidle.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/math64.h>

#define BUCKETS 12
#define INTERVAL_SHIFT 3
#define INTERVALS (1UL << INTERVAL_SHIFT)
#define RESOLUTION 1024
#define DECAY 8
#define MAX_INTERESTING (50000 * NSEC_PER_USEC)

/*
 * Concepts and ideas behind the menu governor
 *
 * For the menu governor, there are 3 decision factors for picking a C
 * state:
 * 1) Energy break even point
 * 2) Performance impact
 * 3) Latency tolerance (from pmqos infrastructure)
 * These these three factors are treated independently.
 *
 * Energy break even point
 * -----------------------
 * C state entry and exit have an energy cost, and a certain amount of time in
 * the  C state is required to actually break even on this cost. CPUIDLE
 * provides us this duration in the "target_residency" field. So all that we
 * need is a good prediction of how long we'll be idle. Like the traditional
 * menu governor, we start with the actual known "next timer event" time.
 *
 * Since there are other source of wakeups (interrupts for example) than
 * the next timer event, this estimation is rather optimistic. To get a
 * more realistic estimate, a correction factor is applied to the estimate,
 * that is based on historic behavior. For example, if in the past the actual
 * duration always was 50% of the next timer tick, the correction factor will
 * be 0.5.
 *
 * menu uses a running average for this correction factor, however it uses a
 * set of factors, not just a single factor. This stems from the realization
 * that the ratio is dependent on the order of magnitude of the expected
 * duration; if we expect 500 milliseconds of idle time the likelihood of
 * getting an interrupt very early is much higher than if we expect 50 micro
 * seconds of idle time. A second independent factor that has big impact on
 * the actual factor is if there is (disk) IO outstanding or not.
 * (as a special twist, we consider every sleep longer than 50 milliseconds
 * as perfect; there are no power gains for sleeping longer than this)
 *
 * For these two reasons we keep an array of 12 independent factors, that gets
 * indexed based on the magnitude of the expected duration as well as the
 * "is IO outstanding" property.
 *
 * Repeatable-interval-detector
 * ----------------------------
 * There are some cases where "next timer" is a completely unusable predictor:
 * Those cases where the interval is fixed, for example due to hardware
 * interrupt mitigation, but also due to fixed transfer rate devices such as
 * mice.
 * For this, we use a different predictor: We track the duration of the last 8
 * intervals and if the stand deviation of these 8 intervals is below a
 * threshold value, we use the average of these intervals as prediction.
 *
 * Limiting Performance Impact
 * ---------------------------
 * C states, especially those with large exit latencies, can have a real
 * noticeable impact on workloads, which is not acceptable for most sysadmins,
 * and in addition, less performance has a power price of its own.
 *
 * As a general rule of thumb, menu assumes that the following heuristic
 * holds:
 *     The busier the system, the less impact of C states is acceptable
 *
 * This rule-of-thumb is implemented using a performance-multiplier:
 * If the exit latency times the performance multiplier is longer than
 * the predicted duration, the C state is not considered a candidate
 * for selection due to a too high performance impact. So the higher
 * this multiplier is, the longer we need to be idle to pick a deep C
 * state, and thus the less likely a busy CPU will hit such a deep
 * C state.
 *
 * Two factors are used in determing this multiplier:
 * a value of 10 is added for each point of "per cpu load average" we have.
 * a value of 5 points is added for each process that is waiting for
 * IO on this CPU.
 * (these values are experimentally determined)
 *
 * The load average factor gives a longer term (few seconds) input to the
 * decision, while the iowait value gives a cpu local instantanious input.
 * The iowait factor may look low, but realize that this is also already
 * represented in the system load average.
 *
 */

/* menu governor的原理
   对于menu governor，选择C状态有三个决定因素
  （1）能量平衡点
  （2）性能影响
  （3）latency容忍度
  
   能量平衡点：
   C状态进入和离开都有一定的energy成本，因此需要在c状态下保持一定的时间才能
   在这一成本上实现收支平衡。CPUIDLE通过target_residency成员提供其duration。
   因此我们需要良好地预测需要在idle状态的时间。与传统的menu governor类似，
   我们从实际已知的“下一个计时器事件”时间开始
   。
   由于除了下一次定时器事件外，还有其它的唤醒源（如中断），因此为了
   获取更加实际的估计，会对估计引入一个校正因数。它会基于其历史行为，
   如过去实际的周期总是next timer tick的50%，则校正因数为0.5。
   
   menu使用该校正系数的运行平均值，当然，它会使用一组系数，而不是单一的系数。
   这源于认识到该比率取决于预期持续时间的数量级，如果我们预期有500毫秒的空闲
   时间，那么很早就得到中断的可能性要比预期有50微秒的空闲时间的可能性高得多。
   第二个对实际因素有很大影响的独立因素是是否有（磁盘）IO未完成。我们认为每一
   个睡眠时间超过50毫秒是完美的；睡眠时间比这长，没有能量增益。

   由于以上两个原因，我们维护了一个包含12个独立系数的数组，它将根据预期持续时
   间的大小以及“is IO Understand”属性进行索引。

   可重复间隔检测器：
   在有些情况下，next timer是一个不可使用预测器，这些情况下，间隔是固定的，例如
   由于硬件中断缓解，但也由于固定的传输速率设备，如鼠标.
   这时，我们使用一个不同的预测器，我们跟踪最后8个间隔时间，若这8个间隔的偏离都
   低于门限值，则我们使用其平均值作为预测的间隔

   限制性能影响：
   对于有比较高退出延迟的c状态，会对workload产生比较大的影响，它对大部分的系统
   管理员是不可接受的，进一步地，低性能也有其自身的power成本。作为一般的经验法则，
   menu假设以下启发适用：
   系统越繁忙，C状态的影响就越小，这个经验法则是使用性能乘数实现的：
   如果exit延迟乘以性能乘数的时间长于预测的持续时间，则由于对性能的影响太大，C状
   态不被视为选择的候选状态。
   因此，这个乘数越大，我们选择一个deep c状态就需要更长的idle时间。因此更加繁忙的
   cpu达到这种深度c状态的可能性就越小。

   两个系数可被用于确定这个乘数：
  （1）我们含有的每个cpu负载平均值的每一个点都加10
  （2）在此CPU上等待IO的每个进程加上5分

   负载平均系数为决策提供更长的时间（几秒钟）输入，而iowait值为cpu本地瞬时输入。
   iowait因子看起来可能很低，但要意识到这也已经在系统平均负载中体现出来了。	
*/
struct menu_device {
	int             needs_update;
	int             tick_wakeup;

	u64		next_timer_ns;
	unsigned int	bucket;
	/* 校正系数 */
	unsigned int	correction_factor[BUCKETS];
	unsigned int	intervals[INTERVALS];
	int		interval_ptr;
};

static inline int which_bucket(u64 duration_ns, unsigned int nr_iowaiters)
{
	int bucket = 0;

	/*
	 * We keep two groups of stats; one with no
	 * IO pending, one without.
	 * This allows us to calculate
	 * E(duration)|iowait
	 */
	if (nr_iowaiters)
		bucket = BUCKETS/2;

	if (duration_ns < 10ULL * NSEC_PER_USEC)
		return bucket;
	if (duration_ns < 100ULL * NSEC_PER_USEC)
		return bucket + 1;
	if (duration_ns < 1000ULL * NSEC_PER_USEC)
		return bucket + 2;
	if (duration_ns < 10000ULL * NSEC_PER_USEC)
		return bucket + 3;
	if (duration_ns < 100000ULL * NSEC_PER_USEC)
		return bucket + 4;
	return bucket + 5;
}

/*
 * Return a multiplier for the exit latency that is intended
 * to take performance requirements into account.
 * The more performance critical we estimate the system
 * to be, the higher this multiplier, and thus the higher
 * the barrier to go to an expensive C state.
 */
static inline int performance_multiplier(unsigned int nr_iowaiters)
{
	/* for IO wait tasks (per cpu!) we add 10x each */
	return 1 + 10 * nr_iowaiters;
}

static DEFINE_PER_CPU(struct menu_device, menu_devices);

static void menu_update(struct cpuidle_driver *drv, struct cpuidle_device *dev);

/*
 * Try detecting repeating patterns by keeping track of the last 8
 * intervals, and checking if the standard deviation of that set
 * of points is below a threshold. If it is... then use the
 * average of these 8 points as the estimated value.
 */
static unsigned int get_typical_interval(struct menu_device *data,
					 unsigned int predicted_us)
{
	int i, divisor;
	unsigned int min, max, thresh, avg;
	uint64_t sum, variance;

	thresh = INT_MAX; /* Discard outliers above this value */

again:

	/* First calculate the average of past intervals */
	min = UINT_MAX;
	max = 0;
	sum = 0;
	divisor = 0;
	for (i = 0; i < INTERVALS; i++) {
		unsigned int value = data->intervals[i];
		if (value <= thresh) {
			sum += value;
			divisor++;
			if (value > max)
				max = value;

			if (value < min)
				min = value;
		}
	}

	/*
	 * If the result of the computation is going to be discarded anyway,
	 * avoid the computation altogether.
	 */
	if (min >= predicted_us)
		return UINT_MAX;

	if (divisor == INTERVALS)
		avg = sum >> INTERVAL_SHIFT;
	else
		avg = div_u64(sum, divisor);

	/* Then try to determine variance */
	variance = 0;
	for (i = 0; i < INTERVALS; i++) {
		unsigned int value = data->intervals[i];
		if (value <= thresh) {
			int64_t diff = (int64_t)value - avg;
			variance += diff * diff;
		}
	}
	if (divisor == INTERVALS)
		variance >>= INTERVAL_SHIFT;
	else
		do_div(variance, divisor);

	/*
	 * The typical interval is obtained when standard deviation is
	 * small (stddev <= 20 us, variance <= 400 us^2) or standard
	 * deviation is small compared to the average interval (avg >
	 * 6*stddev, avg^2 > 36*variance). The average is smaller than
	 * UINT_MAX aka U32_MAX, so computing its square does not
	 * overflow a u64. We simply reject this candidate average if
	 * the standard deviation is greater than 715 s (which is
	 * rather unlikely).
	 *
	 * Use this result only if there is no timer to wake us up sooner.
	 */
	if (likely(variance <= U64_MAX/36)) {
		if ((((u64)avg*avg > variance*36) && (divisor * 4 >= INTERVALS * 3))
							|| variance <= 400) {
			return avg;
		}
	}

	/*
	 * If we have outliers to the upside in our distribution, discard
	 * those by setting the threshold to exclude these outliers, then
	 * calculate the average and standard deviation again. Once we get
	 * down to the bottom 3/4 of our samples, stop excluding samples.
	 *
	 * This can deal with workloads that have long pauses interspersed
	 * with sporadic activity with a bunch of short pauses.
	 */
	if ((divisor * 4) <= INTERVALS * 3)
		return UINT_MAX;

	thresh = max - 1;
	goto again;
}

/**
 * menu_select - selects the next idle state to enter
 * @drv: cpuidle driver containing state data
 * @dev: the CPU
 * @stop_tick: indication on whether or not to stop the tick
 */
/* 选择下次进入的idle状态 */
static int menu_select(struct cpuidle_driver *drv, struct cpuidle_device *dev,
		       bool *stop_tick)
{
	/* 本cpu的menu device */
	struct menu_device *data = this_cpu_ptr(&menu_devices);
	/* 该cpu的对应qos的resume latency */
	s64 latency_req = cpuidle_governor_latency_req(dev->cpu);
	unsigned int predicted_us;
	u64 predicted_ns;
	u64 interactivity_req;
	unsigned int nr_iowaiters;
	ktime_t delta, delta_tick;
	int i, idx;

	/* 若需要更新数据 */
	if (data->needs_update) {
		menu_update(drv, dev);
		data->needs_update = 0;
	}

	/* determine the expected residency time, round up */
	delta = tick_nohz_get_sleep_length(&delta_tick);
	if (unlikely(delta < 0)) {
		delta = 0;
		delta_tick = 0;
	}
	data->next_timer_ns = delta;

	nr_iowaiters = nr_iowait_cpu(dev->cpu);
	data->bucket = which_bucket(data->next_timer_ns, nr_iowaiters);

	if (unlikely(drv->state_count <= 1 || latency_req == 0) ||
	    ((data->next_timer_ns < drv->states[1].target_residency_ns ||
	      latency_req < drv->states[1].exit_latency_ns) &&
	     !dev->states_usage[0].disable)) {
		/*
		 * In this case state[0] will be used no matter what, so return
		 * it right away and keep the tick running if state[0] is a
		 * polling one.
		 */
		*stop_tick = !(drv->states[0].flags & CPUIDLE_FLAG_POLLING);
		return 0;
	}

	/* Round up the result for half microseconds. */
	predicted_us = div_u64(data->next_timer_ns *
			       data->correction_factor[data->bucket] +
			       (RESOLUTION * DECAY * NSEC_PER_USEC) / 2,
			       RESOLUTION * DECAY * NSEC_PER_USEC);
	/* Use the lowest expected idle interval to pick the idle state. */
	predicted_ns = (u64)min(predicted_us,
				get_typical_interval(data, predicted_us)) *
				NSEC_PER_USEC;

	if (tick_nohz_tick_stopped()) {
		/*
		 * If the tick is already stopped, the cost of possible short
		 * idle duration misprediction is much higher, because the CPU
		 * may be stuck in a shallow idle state for a long time as a
		 * result of it.  In that case say we might mispredict and use
		 * the known time till the closest timer event for the idle
		 * state selection.
		 */
		if (predicted_ns < TICK_NSEC)
			predicted_ns = data->next_timer_ns;
	} else {
		/*
		 * Use the performance multiplier and the user-configurable
		 * latency_req to determine the maximum exit latency.
		 */
		interactivity_req = div64_u64(predicted_ns,
					      performance_multiplier(nr_iowaiters));
		if (latency_req > interactivity_req)
			latency_req = interactivity_req;
	}

	/*
	 * Find the idle state with the lowest power while satisfying
	 * our constraints.
	 */
	idx = -1;
	for (i = 0; i < drv->state_count; i++) {
		struct cpuidle_state *s = &drv->states[i];

		if (dev->states_usage[i].disable)
			continue;

		if (idx == -1)
			idx = i; /* first enabled state */

		if (s->target_residency_ns > predicted_ns) {
			/*
			 * Use a physical idle state, not busy polling, unless
			 * a timer is going to trigger soon enough.
			 */
			if ((drv->states[idx].flags & CPUIDLE_FLAG_POLLING) &&
			    s->exit_latency_ns <= latency_req &&
			    s->target_residency_ns <= data->next_timer_ns) {
				predicted_ns = s->target_residency_ns;
				idx = i;
				break;
			}
			if (predicted_ns < TICK_NSEC)
				break;

			if (!tick_nohz_tick_stopped()) {
				/*
				 * If the state selected so far is shallow,
				 * waking up early won't hurt, so retain the
				 * tick in that case and let the governor run
				 * again in the next iteration of the loop.
				 */
				predicted_ns = drv->states[idx].target_residency_ns;
				break;
			}

			/*
			 * If the state selected so far is shallow and this
			 * state's target residency matches the time till the
			 * closest timer event, select this one to avoid getting
			 * stuck in the shallow one for too long.
			 */
			if (drv->states[idx].target_residency_ns < TICK_NSEC &&
			    s->target_residency_ns <= delta_tick)
				idx = i;

			return idx;
		}
		if (s->exit_latency_ns > latency_req)
			break;

		idx = i;
	}

	if (idx == -1)
		idx = 0; /* No states enabled. Must use 0. */

	/*
	 * Don't stop the tick if the selected state is a polling one or if the
	 * expected idle duration is shorter than the tick period length.
	 */
	if (((drv->states[idx].flags & CPUIDLE_FLAG_POLLING) ||
	     predicted_ns < TICK_NSEC) && !tick_nohz_tick_stopped()) {
		*stop_tick = false;

		if (idx > 0 && drv->states[idx].target_residency_ns > delta_tick) {
			/*
			 * The tick is not going to be stopped and the target
			 * residency of the state to be returned is not within
			 * the time until the next timer event including the
			 * tick, so try to correct that.
			 */
			for (i = idx - 1; i >= 0; i--) {
				if (dev->states_usage[i].disable)
					continue;

				idx = i;
				if (drv->states[i].target_residency_ns <= delta_tick)
					break;
			}
		}
	}

	return idx;
}

/**
 * menu_reflect - records that data structures need update
 * @dev: the CPU
 * @index: the index of actual entered state
 *
 * NOTE: it's important to be fast here because this operation will add to
 *       the overall exit latency.
 */
/* 记录需要更新的数据结构
   在cpu退出idle状态后，menu governor会将将上一轮的进入idle状态的数据更新到
   menu driver中，作为下一次select的参数
*/
static void menu_reflect(struct cpuidle_device *dev, int index)
{
	/* 本cpu的menu设备结构体 */
	struct menu_device *data = this_cpu_ptr(&menu_devices);

	/* 该cpu最后一次进入状态对应的index，即上次进入idle时的深度 */
	dev->last_state_idx = index;
	/* 下次进入select流程时需要更新 */
	data->needs_update = 1;
	/* 上次被唤醒是否由tick唤醒 */
	data->tick_wakeup = tick_nohz_idle_got_tick();
}

/**
 * menu_update - attempts to guess what happened after entry
 * @drv: cpuidle driver containing state data
 * @dev: the CPU
 */
/* 更新统计数据 */
static void menu_update(struct cpuidle_driver *drv, struct cpuidle_device *dev)
{
	/* 本cpu的menu设备 */
	struct menu_device *data = this_cpu_ptr(&menu_devices);
	/* 设备上一次进入idle深度的index */
	int last_idx = dev->last_state_idx;
	struct cpuidle_state *target = &drv->states[last_idx];
	u64 measured_ns;
	unsigned int new_factor;

	/*
	 * Try to figure out how much time passed between entry to low
	 * power state and occurrence of the wakeup event.
	 *
	 * If the entered idle state didn't support residency measurements,
	 * we use them anyway if they are short, and if long,
	 * truncate to the whole expected time.
	 *
	 * Any measured amount of time will include the exit latency.
	 * Since we are interested in when the wakeup begun, not when it
	 * was completed, we must subtract the exit latency. However, if
	 * the measured amount of time is less than the exit latency,
	 * assume the state was never reached and the exit latency is 0.
	 */

	if (data->tick_wakeup && data->next_timer_ns > TICK_NSEC) {
		/*
		 * The nohz code said that there wouldn't be any events within
		 * the tick boundary (if the tick was stopped), but the idle
		 * duration predictor had a differing opinion.  Since the CPU
		 * was woken up by a tick (that wasn't stopped after all), the
		 * predictor was not quite right, so assume that the CPU could
		 * have been idle long (but not forever) to help the idle
		 * duration predictor do a better job next time.
		 */
		measured_ns = 9 * MAX_INTERESTING / 10;
	} else if ((drv->states[last_idx].flags & CPUIDLE_FLAG_POLLING) &&
		   dev->poll_time_limit) {
		/*
		 * The CPU exited the "polling" state due to a time limit, so
		 * the idle duration prediction leading to the selection of that
		 * state was inaccurate.  If a better prediction had been made,
		 * the CPU might have been woken up from idle by the next timer.
		 * Assume that to be the case.
		 */
		measured_ns = data->next_timer_ns;
	} else {
		/* measured value */
		measured_ns = dev->last_residency_ns;

		/* Deduct exit latency */
		if (measured_ns > 2 * target->exit_latency_ns)
			measured_ns -= target->exit_latency_ns;
		else
			measured_ns /= 2;
	}

	/* Make sure our coefficients do not exceed unity */
	if (measured_ns > data->next_timer_ns)
		measured_ns = data->next_timer_ns;

	/* Update our correction ratio */
	new_factor = data->correction_factor[data->bucket];
	new_factor -= new_factor / DECAY;

	if (data->next_timer_ns > 0 && measured_ns < MAX_INTERESTING)
		new_factor += div64_u64(RESOLUTION * measured_ns,
					data->next_timer_ns);
	else
		/*
		 * we were idle so long that we count it as a perfect
		 * prediction
		 */
		new_factor += RESOLUTION;

	/*
	 * We don't want 0 as factor; we always want at least
	 * a tiny bit of estimated time. Fortunately, due to rounding,
	 * new_factor will stay nonzero regardless of measured_us values
	 * and the compiler can eliminate this test as long as DECAY > 1.
	 */
	if (DECAY == 1 && unlikely(new_factor == 0))
		new_factor = 1;

	data->correction_factor[data->bucket] = new_factor;

	/* update the repeating-pattern data */
	data->intervals[data->interval_ptr++] = ktime_to_us(measured_ns);
	if (data->interval_ptr >= INTERVALS)
		data->interval_ptr = 0;
}

/**
 * menu_enable_device - scans a CPU's states and does setup
 * @drv: cpuidle driver
 * @dev: the CPU
 */
/* 使能设备 */
static int menu_enable_device(struct cpuidle_driver *drv,
				struct cpuidle_device *dev)
{
	struct menu_device *data = &per_cpu(menu_devices, dev->cpu);
	int i;

	memset(data, 0, sizeof(struct menu_device));

	/*
	 * if the correction factor is 0 (eg first time init or cpu hotplug
	 * etc), we actually want to start out with a unity factor.
	 */
	/* 校正系数初始化为1024 * 8 */
	for(i = 0; i < BUCKETS; i++)
		data->correction_factor[i] = RESOLUTION * DECAY;

	return 0;
}

/* governor定义 */
static struct cpuidle_governor menu_governor = {
	.name =		"menu",
	.rating =	20,
	.enable =	menu_enable_device,
	.select =	menu_select,
	.reflect =	menu_reflect,
};

/**
 * init_menu - initializes the governor
 */
/* 初始化menu governor */
static int __init init_menu(void)
{
	/* 注册该governor */
	return cpuidle_register_governor(&menu_governor);
}

postcore_initcall(init_menu);
