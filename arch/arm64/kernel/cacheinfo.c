// SPDX-License-Identifier: GPL-2.0-only
/*
 *  ARM64 cacheinfo support
 *
 *  Copyright (C) 2015 ARM Ltd.
 *  All Rights Reserved
 */

#include <linux/acpi.h>
#include <linux/cacheinfo.h>
#include <linux/of.h>

/* arm64最高支持7级cache level */
#define MAX_CACHE_LEVEL			7	/* Max 7 level supported */
/* Ctypen, bits[3(n - 1) + 2 : 3(n - 1)], for n = 1 to 7 */
#define CLIDR_CTYPE_SHIFT(level)	(3 * (level - 1))
#define CLIDR_CTYPE_MASK(level)		(7 << CLIDR_CTYPE_SHIFT(level))
#define CLIDR_CTYPE(clidr, level)	\
	(((clidr) & CLIDR_CTYPE_MASK(level)) >> CLIDR_CTYPE_SHIFT(level))

int cache_line_size(void)
{
	if (coherency_max_size != 0)
		return coherency_max_size;

	return cache_line_size_of_cpu();
}
EXPORT_SYMBOL_GPL(cache_line_size);

/* 获取每个等级的cache type */
static inline enum cache_type get_cache_type(int level)
{
	u64 clidr;

	if (level > MAX_CACHE_LEVEL)
		return CACHE_TYPE_NOCACHE;
	/* 从cache level ID寄存器中读取cache配置信息 */
	clidr = read_sysreg(clidr_el1);
	/* 提取并返回该等级cache的type */
	return CLIDR_CTYPE(clidr, level);
}

static void ci_leaf_init(struct cacheinfo *this_leaf,
			 enum cache_type type, unsigned int level)
{
	this_leaf->level = level;
	this_leaf->type = type;
}

/* 初始化cpu的cache等级 */
static int __init_cache_level(unsigned int cpu)
{
	unsigned int ctype, level, leaves, fw_level;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);

	/* 遍历cache的每个level，并提取其cache type信息。
       并根据cache type和cache level计算一共需要多少个叶节点
	*/
	for (level = 1, leaves = 0; level <= MAX_CACHE_LEVEL; level++) {
		ctype = get_cache_type(level);
		if (ctype == CACHE_TYPE_NOCACHE) {
			level--;
			break;
		}
		/* Separate instruction and data caches */
		leaves += (ctype == CACHE_TYPE_SEPARATE) ? 2 : 1;
	}

	/* 从devicetree中查找最高的cache等级 */
	if (acpi_disabled)
		fw_level = of_find_last_cache_level(cpu);
	else
		fw_level = acpi_find_last_cache_level(cpu);

	/* 由于有些外部cache不会在CLIDR_EL1的信息中指定，它只能从devicetree
       中获取。因此从dt中获取fw_level，若其level高于从clidr_el1读取到的
       level等级，则更新为dt中的等级
	*/
	if (level < fw_level) {
		/*
		 * some external caches not specified in CLIDR_EL1
		 * the information may be available in the device tree
		 * only unified external caches are considered here
		 */
		leaves += (fw_level - level);
		level = fw_level;
	}

	/* 将level和leaves信息保存到percpu的cacheinfo结构中 */
	this_cpu_ci->num_levels = level;
	this_cpu_ci->num_leaves = leaves;
	return 0;
}

/* populate该cpu的cache leaves */
static int __populate_cache_leaves(unsigned int cpu)
{
	unsigned int level, idx;
	enum cache_type type;
	/* 获取该cpu对应的cacheinfo */
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	/* 该cpu的cache leaf entry */
	struct cacheinfo *this_leaf = this_cpu_ci->info_list;

	/* 遍历每个等级的cpu cache信息 */
	for (idx = 0, level = 1; level <= this_cpu_ci->num_levels &&
	     idx < this_cpu_ci->num_leaves; idx++, level++) {
	    /* 获取该等级的cache type */
		type = get_cache_type(level);
		/* 将其cache type和level信息保存到cacheinfo表中 */
		if (type == CACHE_TYPE_SEPARATE) {
			ci_leaf_init(this_leaf++, CACHE_TYPE_DATA, level);
			ci_leaf_init(this_leaf++, CACHE_TYPE_INST, level);
		} else {
			ci_leaf_init(this_leaf++, type, level);
		}
	}
	return 0;
}

DEFINE_SMP_CALL_CACHE_FUNCTION(init_cache_level)
DEFINE_SMP_CALL_CACHE_FUNCTION(populate_cache_leaves)
