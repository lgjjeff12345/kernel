/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CACHEINFO_H
#define _LINUX_CACHEINFO_H

#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>

struct device_node;
struct attribute;

/* cache类型 */
enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = BIT(0),
	CACHE_TYPE_DATA = BIT(1),
	CACHE_TYPE_SEPARATE = CACHE_TYPE_INST | CACHE_TYPE_DATA,
	CACHE_TYPE_UNIFIED = BIT(2),
};

extern unsigned int coherency_max_size;

/**
 * struct cacheinfo - represent a cache leaf node
 * @id: This cache's id. It is unique among caches with the same (type, level).
 * @type: type of the cache - data, inst or unified
 * @level: represents the hierarchy in the multi-level cache
 * @coherency_line_size: size of each cache line usually representing
 *	the minimum amount of data that gets transferred from memory
 * @number_of_sets: total number of sets, a set is a collection of cache
 *	lines sharing the same index
 * @ways_of_associativity: number of ways in which a particular memory
 *	block can be placed in the cache
 * @physical_line_partition: number of physical cache lines sharing the
 *	same cachetag
 * @size: Total size of the cache
 * @shared_cpu_map: logical cpumask representing all the cpus sharing
 *	this cache node
 * @attributes: bitfield representing various cache attributes
 * @fw_token: Unique value used to determine if different cacheinfo
 *	structures represent a single hardware cache instance.
 * @disable_sysfs: indicates whether this node is visible to the user via
 *	sysfs or not
 * @priv: pointer to any private data structure specific to particular
 *	cache design
 *
 * While @of_node, @disable_sysfs and @priv are used for internal book
 * keeping, the remaining members form the core properties of the cache
 */
/* 代表一个cache的叶节点 
   id：cache id，在相同等级和level下该值是唯一地
   type：cache的类型，数据|指令|unified
   level：在多级cache中指示其层次结构
   coherency_line_size：cache line的size
   number_of_sets：总的cache sets，一个set表示共享相同index的cache line集合
   ways_of_associativity：在缓存中放置特定内存块的方式的数量
   physical_line_partition：共享相同cachetag的物理cache line数量
   size：cache的总size
   shared_cpu_map：共享该cache节点的所以cpumask
   attributes：表示不同cache属性的bitfield
   fw_token：用于确定不同cacheinfo结构是否代表单个硬件缓存实例的唯一值
   disable_sysfs：指示本节点是否在sysfs中可见
   priv：指向私有数据
*/
struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
#define CACHE_WRITE_THROUGH	BIT(0)
#define CACHE_WRITE_BACK	BIT(1)
#define CACHE_WRITE_POLICY_MASK		\
	(CACHE_WRITE_THROUGH | CACHE_WRITE_BACK)
#define CACHE_READ_ALLOCATE	BIT(2)
#define CACHE_WRITE_ALLOCATE	BIT(3)
#define CACHE_ALLOCATE_POLICY_MASK	\
	(CACHE_READ_ALLOCATE | CACHE_WRITE_ALLOCATE)
#define CACHE_ID		BIT(4)
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

/* cpu cacheinfo结构体 */
struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	/* cache级数 */
	unsigned int num_levels;
	/* 叶节点数量 */
	unsigned int num_leaves;
	bool cpu_map_populated;
};

/*
 * Helpers to make sure "func" is executed on the cpu whose cache
 * attributes are being detected
 */
/* 调用ipi在该cpu上执行该函数 */	
#define DEFINE_SMP_CALL_CACHE_FUNCTION(func)			\
static inline void _##func(void *ret)				\
{								\
	int cpu = smp_processor_id();				\
	*(int *)ret = __##func(cpu);				\
}								\
							\
int func(unsigned int cpu)					\
{								\
	int ret;						\
	smp_call_function_single(cpu, _##func, &ret, true);	\
	return ret;						\
}

struct cpu_cacheinfo *get_cpu_cacheinfo(unsigned int cpu);
int init_cache_level(unsigned int cpu);
int populate_cache_leaves(unsigned int cpu);
int cache_setup_acpi(unsigned int cpu);
#ifndef CONFIG_ACPI_PPTT
/*
 * acpi_find_last_cache_level is only called on ACPI enabled
 * platforms using the PPTT for topology. This means that if
 * the platform supports other firmware configuration methods
 * we need to stub out the call when ACPI is disabled.
 * ACPI enabled platforms not using PPTT won't be making calls
 * to this function so we need not worry about them.
 */
static inline int acpi_find_last_cache_level(unsigned int cpu)
{
	return 0;
}
#else
int acpi_find_last_cache_level(unsigned int cpu);
#endif

const struct attribute_group *cache_get_priv_group(struct cacheinfo *this_leaf);

/*
 * Get the id of the cache associated with @cpu at level @level.
 * cpuhp lock must be held.
 */
/* 获取在等级为level下，与cpu相关的cache id */
static inline int get_cpu_cacheinfo_id(int cpu, int level)
{
	/* 获取cpu的cache信息 */
	struct cpu_cacheinfo *ci = get_cpu_cacheinfo(cpu);
	int i;

	/* 遍历info_list中的所有子节点，查找与给定等级相等的信息，并返回其id值 */
	for (i = 0; i < ci->num_leaves; i++) {
		if (ci->info_list[i].level == level) {
			if (ci->info_list[i].attributes & CACHE_ID)
				return ci->info_list[i].id;
			return -1;
		}
	}

	return -1;
}

#endif /* _LINUX_CACHEINFO_H */
