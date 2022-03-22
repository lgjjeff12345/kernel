// SPDX-License-Identifier: GPL-2.0
/*
 * Memory subsystem support
 *
 * Written by Matt Tolentino <matthew.e.tolentino@intel.com>
 *            Dave Hansen <haveblue@us.ibm.com>
 *
 * This file provides the necessary infrastructure to represent
 * a SPARSEMEM-memory-model system's physical memory in /sysfs.
 * All arch-independent code that assumes MEMORY_HOTPLUG requires
 * SPARSEMEM should be contained here, or in mm/memory_hotplug.c.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/topology.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include <linux/atomic.h>
#include <linux/uaccess.h>

#define MEMORY_CLASS_NAME	"memory"

/* online类型 */
static const char *const online_type_to_str[] = {
	[MMOP_OFFLINE] = "offline",
	[MMOP_ONLINE] = "online",
	[MMOP_ONLINE_KERNEL] = "online_kernel",
	[MMOP_ONLINE_MOVABLE] = "online_movable",
};

int mhp_online_type_from_str(const char *str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(online_type_to_str); i++) {
		if (sysfs_streq(str, online_type_to_str[i]))
			return i;
	}
	return -EINVAL;
}

#define to_memory_block(dev) container_of(dev, struct memory_block, dev)

static int sections_per_block;

/* memblock id计算方式：
   section_nr / sections_per_block
*/
static inline unsigned long memory_block_id(unsigned long section_nr)
{
	return section_nr / sections_per_block;
}

/* 将pfn转换为block id */
static inline unsigned long pfn_to_block_id(unsigned long pfn)
{
	return memory_block_id(pfn_to_section_nr(pfn));
}

/* 将物理地址转换为block id */
static inline unsigned long phys_to_block_id(unsigned long phys)
{
	return pfn_to_block_id(PFN_DOWN(phys));
}

static int memory_subsys_online(struct device *dev);
static int memory_subsys_offline(struct device *dev);

static struct bus_type memory_subsys = {
	.name = MEMORY_CLASS_NAME,
	.dev_name = MEMORY_CLASS_NAME,
	.online = memory_subsys_online,
	.offline = memory_subsys_offline,
};

/*
 * Memory blocks are cached in a local radix tree to avoid
 * a costly linear search for the corresponding device on
 * the subsystem bus.
 */
static DEFINE_XARRAY(memory_blocks);

static BLOCKING_NOTIFIER_HEAD(memory_chain);

/* 注册memory通知 */
int register_memory_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&memory_chain, nb);
}
EXPORT_SYMBOL(register_memory_notifier);

/* 注销memory通知 */
void unregister_memory_notifier(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&memory_chain, nb);
}
EXPORT_SYMBOL(unregister_memory_notifier);

/* memory block的释放函数 */
static void memory_block_release(struct device *dev)
{
	struct memory_block *mem = to_memory_block(dev);

	/* 释放结构体内存 */
	kfree(mem);
}

/* 默认最小的memblock size为section size，即128M或512M */
unsigned long __weak memory_block_size_bytes(void)
{
	return MIN_MEMORY_BLOCK_SIZE;
}
EXPORT_SYMBOL_GPL(memory_block_size_bytes);

/*
 * Show the first physical section index (number) of this memory block.
 */
/* 显示memory的物理index，即其block id */
static ssize_t phys_index_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct memory_block *mem = to_memory_block(dev);
	unsigned long phys_index;

	phys_index = mem->start_section_nr / sections_per_block;

	return sysfs_emit(buf, "%08lx\n", phys_index);
}

/*
 * Legacy interface that we cannot remove. Always indicate "removable"
 * with CONFIG_MEMORY_HOTREMOVE - bad heuristic.
 */
/* 这个接口不准确 */
static ssize_t removable_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	return sysfs_emit(buf, "%d\n", (int)IS_ENABLED(CONFIG_MEMORY_HOTREMOVE));
}

/*
 * online, offline, going offline, etc.
 */
/* 显示该内存节点的状态 */
static ssize_t state_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct memory_block *mem = to_memory_block(dev);
	const char *output;

	/*
	 * We can probably put these states in a nice little array
	 * so that they're not open-coded
	 */
	switch (mem->state) {
	case MEM_ONLINE:
		output = "online";
		break;
	case MEM_OFFLINE:
		output = "offline";
		break;
	case MEM_GOING_OFFLINE:
		output = "going-offline";
		break;
	default:
		WARN_ON(1);
		return sysfs_emit(buf, "ERROR-UNKNOWN-%ld\n", mem->state);
	}

	return sysfs_emit(buf, "%s\n", output);
}

/* 调用注册到memory通知链的通知 */
int memory_notify(unsigned long val, void *v)
{
	return blocking_notifier_call_chain(&memory_chain, val, v);
}

static int memory_block_online(struct memory_block *mem)
{
	unsigned long start_pfn = section_nr_to_pfn(mem->start_section_nr);
	unsigned long nr_pages = PAGES_PER_SECTION * sections_per_block;
	unsigned long nr_vmemmap_pages = mem->nr_vmemmap_pages;
	struct zone *zone;
	int ret;

	zone = zone_for_pfn_range(mem->online_type, mem->nid, start_pfn, nr_pages);

	/*
	 * Although vmemmap pages have a different lifecycle than the pages
	 * they describe (they remain until the memory is unplugged), doing
	 * their initialization and accounting at memory onlining/offlining
	 * stage helps to keep accounting easier to follow - e.g vmemmaps
	 * belong to the same zone as the memory they backed.
	 */
	if (nr_vmemmap_pages) {
		ret = mhp_init_memmap_on_memory(start_pfn, nr_vmemmap_pages, zone);
		if (ret)
			return ret;
	}

	ret = online_pages(start_pfn + nr_vmemmap_pages,
			   nr_pages - nr_vmemmap_pages, zone);
	if (ret) {
		if (nr_vmemmap_pages)
			mhp_deinit_memmap_on_memory(start_pfn, nr_vmemmap_pages);
		return ret;
	}

	/*
	 * Account once onlining succeeded. If the zone was unpopulated, it is
	 * now already properly populated.
	 */
	if (nr_vmemmap_pages)
		adjust_present_page_count(zone, nr_vmemmap_pages);

	return ret;
}

static int memory_block_offline(struct memory_block *mem)
{
	unsigned long start_pfn = section_nr_to_pfn(mem->start_section_nr);
	unsigned long nr_pages = PAGES_PER_SECTION * sections_per_block;
	unsigned long nr_vmemmap_pages = mem->nr_vmemmap_pages;
	struct zone *zone;
	int ret;

	/*
	 * Unaccount before offlining, such that unpopulated zone and kthreads
	 * can properly be torn down in offline_pages().
	 */
	if (nr_vmemmap_pages) {
		zone = page_zone(pfn_to_page(start_pfn));
		adjust_present_page_count(zone, -nr_vmemmap_pages);
	}

	ret = offline_pages(start_pfn + nr_vmemmap_pages,
			    nr_pages - nr_vmemmap_pages);
	if (ret) {
		/* offline_pages() failed. Account back. */
		if (nr_vmemmap_pages)
			adjust_present_page_count(zone, nr_vmemmap_pages);
		return ret;
	}

	if (nr_vmemmap_pages)
		mhp_deinit_memmap_on_memory(start_pfn, nr_vmemmap_pages);

	return ret;
}

/*
 * MEMORY_HOTPLUG depends on SPARSEMEM in mm/Kconfig, so it is
 * OK to have direct references to sparsemem variables in here.
 */
/* memory hotplug依赖于SPARSEMEM。本接口用于触发内存的online和offline操作
*/
static int
memory_block_action(struct memory_block *mem, unsigned long action)
{
	int ret;

	switch (action) {
	case MEM_ONLINE:
		ret = memory_block_online(mem);
		break;
	case MEM_OFFLINE:
		ret = memory_block_offline(mem);
		break;
	default:
		WARN(1, KERN_WARNING "%s(%ld, %ld) unknown action: "
		     "%ld\n", __func__, mem->start_section_nr, action, action);
		ret = -EINVAL;
	}

	return ret;
}

/* 改变该内存block的状态，online/offline */
static int memory_block_change_state(struct memory_block *mem,
		unsigned long to_state, unsigned long from_state_req)
{
	int ret = 0;

	/* 改变前的状态检查 */
	if (mem->state != from_state_req)
		return -EINVAL;

	/* 若需要将内存下线，则先将当前状态修改为MEM_GOING_OFFLINE */
	if (to_state == MEM_OFFLINE)
		mem->state = MEM_GOING_OFFLINE;

	/* 调用内存上下线执行接口 */
	ret = memory_block_action(mem, to_state);
	/* 执行成功，状态修改为目的状态。否则，状态回滚为原先状态 */
	mem->state = ret ? from_state_req : to_state;

	return ret;
}

/* The device lock serializes operations on memory_subsys_[online|offline] */
static int memory_subsys_online(struct device *dev)
{
	struct memory_block *mem = to_memory_block(dev);
	int ret;

	if (mem->state == MEM_ONLINE)
		return 0;

	/*
	 * When called via device_online() without configuring the online_type,
	 * we want to default to MMOP_ONLINE.
	 */
	if (mem->online_type == MMOP_OFFLINE)
		mem->online_type = MMOP_ONLINE;

	ret = memory_block_change_state(mem, MEM_ONLINE, MEM_OFFLINE);
	mem->online_type = MMOP_OFFLINE;

	return ret;
}

static int memory_subsys_offline(struct device *dev)
{
	struct memory_block *mem = to_memory_block(dev);

	if (mem->state == MEM_OFFLINE)
		return 0;

	return memory_block_change_state(mem, MEM_OFFLINE, MEM_ONLINE);
}

static ssize_t state_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	const int online_type = mhp_online_type_from_str(buf);
	struct memory_block *mem = to_memory_block(dev);
	int ret;

	if (online_type < 0)
		return -EINVAL;

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	switch (online_type) {
	case MMOP_ONLINE_KERNEL:
	case MMOP_ONLINE_MOVABLE:
	case MMOP_ONLINE:
		/* mem->online_type is protected by device_hotplug_lock */
		mem->online_type = online_type;
		ret = device_online(&mem->dev);
		break;
	case MMOP_OFFLINE:
		ret = device_offline(&mem->dev);
		break;
	default:
		ret = -EINVAL; /* should never happen */
	}

	unlock_device_hotplug();

	if (ret < 0)
		return ret;
	if (ret)
		return -EINVAL;

	return count;
}

/*
 * Legacy interface that we cannot remove: s390x exposes the storage increment
 * covered by a memory block, allowing for identifying which memory blocks
 * comprise a storage increment. Since a memory block spans complete
 * storage increments nowadays, this interface is basically unused. Other
 * archs never exposed != 0.
 */
static ssize_t phys_device_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct memory_block *mem = to_memory_block(dev);
	unsigned long start_pfn = section_nr_to_pfn(mem->start_section_nr);

	return sysfs_emit(buf, "%d\n",
			  arch_get_memory_phys_device(start_pfn));
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static int print_allowed_zone(char *buf, int len, int nid,
			      unsigned long start_pfn, unsigned long nr_pages,
			      int online_type, struct zone *default_zone)
{
	struct zone *zone;

	zone = zone_for_pfn_range(online_type, nid, start_pfn, nr_pages);
	if (zone == default_zone)
		return 0;

	return sysfs_emit_at(buf, len, " %s", zone->name);
}

static ssize_t valid_zones_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct memory_block *mem = to_memory_block(dev);
	unsigned long start_pfn = section_nr_to_pfn(mem->start_section_nr);
	unsigned long nr_pages = PAGES_PER_SECTION * sections_per_block;
	struct zone *default_zone;
	int len = 0;
	int nid;

	/*
	 * Check the existing zone. Make sure that we do that only on the
	 * online nodes otherwise the page_zone is not reliable
	 */
	if (mem->state == MEM_ONLINE) {
		/*
		 * The block contains more than one zone can not be offlined.
		 * This can happen e.g. for ZONE_DMA and ZONE_DMA32
		 */
		default_zone = test_pages_in_a_zone(start_pfn,
						    start_pfn + nr_pages);
		if (!default_zone)
			return sysfs_emit(buf, "%s\n", "none");
		len += sysfs_emit_at(buf, len, "%s", default_zone->name);
		goto out;
	}

	nid = mem->nid;
	default_zone = zone_for_pfn_range(MMOP_ONLINE, nid, start_pfn,
					  nr_pages);

	len += sysfs_emit_at(buf, len, "%s", default_zone->name);
	len += print_allowed_zone(buf, len, nid, start_pfn, nr_pages,
				  MMOP_ONLINE_KERNEL, default_zone);
	len += print_allowed_zone(buf, len, nid, start_pfn, nr_pages,
				  MMOP_ONLINE_MOVABLE, default_zone);
out:
	len += sysfs_emit_at(buf, len, "\n");
	return len;
}
static DEVICE_ATTR_RO(valid_zones);
#endif

static DEVICE_ATTR_RO(phys_index);
static DEVICE_ATTR_RW(state);
static DEVICE_ATTR_RO(phys_device);
static DEVICE_ATTR_RO(removable);

/*
 * Show the memory block size (shared by all memory blocks).
 */
static ssize_t block_size_bytes_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lx\n", memory_block_size_bytes());
}

static DEVICE_ATTR_RO(block_size_bytes);

/*
 * Memory auto online policy.
 */

static ssize_t auto_online_blocks_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  online_type_to_str[mhp_default_online_type]);
}

static ssize_t auto_online_blocks_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	const int online_type = mhp_online_type_from_str(buf);

	if (online_type < 0)
		return -EINVAL;

	mhp_default_online_type = online_type;
	return count;
}

static DEVICE_ATTR_RW(auto_online_blocks);

/*
 * Some architectures will have custom drivers to do this, and
 * will not need to do it from userspace.  The fake hot-add code
 * as well as ppc64 will do all of their discovery in userspace
 * and will require this interface.
 */
#ifdef CONFIG_ARCH_MEMORY_PROBE
static ssize_t probe_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	u64 phys_addr;
	int nid, ret;
	unsigned long pages_per_block = PAGES_PER_SECTION * sections_per_block;

	ret = kstrtoull(buf, 0, &phys_addr);
	if (ret)
		return ret;

	if (phys_addr & ((pages_per_block << PAGE_SHIFT) - 1))
		return -EINVAL;

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	nid = memory_add_physaddr_to_nid(phys_addr);
	ret = __add_memory(nid, phys_addr,
			   MIN_MEMORY_BLOCK_SIZE * sections_per_block,
			   MHP_NONE);

	if (ret)
		goto out;

	ret = count;
out:
	unlock_device_hotplug();
	return ret;
}

static DEVICE_ATTR_WO(probe);
#endif

#ifdef CONFIG_MEMORY_FAILURE
/*
 * Support for offlining pages of memory
 */

/* Soft offline a page */
static ssize_t soft_offline_page_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	int ret;
	u64 pfn;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (kstrtoull(buf, 0, &pfn) < 0)
		return -EINVAL;
	pfn >>= PAGE_SHIFT;
	ret = soft_offline_page(pfn, 0);
	return ret == 0 ? count : ret;
}

/* Forcibly offline a page, including killing processes. */
/* 强制offline一个page，包含杀死进程 */
static ssize_t hard_offline_page_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	int ret;
	u64 pfn;
	/* 只有具有admin权限的用户才可以执行本操作 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (kstrtoull(buf, 0, &pfn) < 0)
		return -EINVAL;
	pfn >>= PAGE_SHIFT;
	ret = memory_failure(pfn, 0);
	return ret ? ret : count;
}

static DEVICE_ATTR_WO(soft_offline_page);
static DEVICE_ATTR_WO(hard_offline_page);
#endif

/* See phys_device_show(). */
int __weak arch_get_memory_phys_device(unsigned long start_pfn)
{
	return 0;
}

/*
 * A reference for the returned memory block device is acquired.
 *
 * Called under device_hotplug_lock.
 */
/* 根据block id查找内存block结构体 */
static struct memory_block *find_memory_block_by_id(unsigned long block_id)
{
	struct memory_block *mem;

	/* 获取给定block id的memory block结构体 */
	mem = xa_load(&memory_blocks, block_id);
	if (mem)
		get_device(&mem->dev);
	return mem;
}

/*
 * Called under device_hotplug_lock.
 */
/* 通过memory section获取其对应的memory block id */
struct memory_block *find_memory_block(struct mem_section *section)
{
	unsigned long block_id = memory_block_id(__section_nr(section));

	/* 根据block id查找内存block结构体 */
	return find_memory_block_by_id(block_id);
}

static struct attribute *memory_memblk_attrs[] = {
	&dev_attr_phys_index.attr,
	&dev_attr_state.attr,
	&dev_attr_phys_device.attr,
	&dev_attr_removable.attr,
#ifdef CONFIG_MEMORY_HOTREMOVE
	&dev_attr_valid_zones.attr,
#endif
	NULL
};

static const struct attribute_group memory_memblk_attr_group = {
	.attrs = memory_memblk_attrs,
};

/* 内存block的sysfs属性 */
static const struct attribute_group *memory_memblk_attr_groups[] = {
	&memory_memblk_attr_group,
	NULL,
};

/*
 * register_memory - Setup a sysfs device for a memory block
 */
/* 注册一个memory block设备，并保存其memory_block指针 */
static
int register_memory(struct memory_block *memory)
{
	int ret;

	/* 初始化状态为offline */
	memory->dev.bus = &memory_subsys;
	memory->dev.id = memory->start_section_nr / sections_per_block;
	memory->dev.release = memory_block_release;
	memory->dev.groups = memory_memblk_attr_groups;
	memory->dev.offline = memory->state == MEM_OFFLINE;

	/* 注册该设备 */
	ret = device_register(&memory->dev);
	if (ret) {
		put_device(&memory->dev);
		return ret;
	}
	/* 将memory结构体指针保存到memory_blocks的xarray中 */
	ret = xa_err(xa_store(&memory_blocks, memory->dev.id, memory,
			      GFP_KERNEL));
	if (ret) {
		put_device(&memory->dev);
		device_unregister(&memory->dev);
	}
	return ret;
}

/* 初始化内存block */
static int init_memory_block(unsigned long block_id, unsigned long state,
			     unsigned long nr_vmemmap_pages)
{
	struct memory_block *mem;
	int ret = 0;

	/* 获取该block id对应的memory_block结构体指针 */
	mem = find_memory_block_by_id(block_id);
	if (mem) {
		put_device(&mem->dev);
		return -EEXIST;
	}
	/* 分配memblock结构体内存 */
	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	/* 设置memblock的参数 */
	mem->start_section_nr = block_id * sections_per_block;
	mem->state = state;
	mem->nid = NUMA_NO_NODE;
	mem->nr_vmemmap_pages = nr_vmemmap_pages;

	/* 注册该memory block */
	ret = register_memory(mem);

	return ret;
}

/* 添加内存block */
static int add_memory_block(unsigned long base_section_nr)
{
	int section_count = 0;
	unsigned long nr;

	/* 计算该block下present的内存section数量 */
	for (nr = base_section_nr; nr < base_section_nr + sections_per_block;
	     nr++)
		if (present_section_nr(nr))
			section_count++;

	if (section_count == 0)
		return 0;
	/* 初始化内存block */
	return init_memory_block(memory_block_id(base_section_nr),
				 MEM_ONLINE, 0);
}

/* 注销内存 */
static void unregister_memory(struct memory_block *memory)
{
	if (WARN_ON_ONCE(memory->dev.bus != &memory_subsys))
		return;

	/* 从memory_blocks中删除该memory对应的值 */
	WARN_ON(xa_erase(&memory_blocks, memory->dev.id) == NULL);

	/* drop the ref. we got via find_memory_block() */
	/* 注销该memory block对应的设备 */
	put_device(&memory->dev);
	device_unregister(&memory->dev);
}

/*
 * Create memory block devices for the given memory area. Start and size
 * have to be aligned to memory block granularity. Memory block devices
 * will be initialized as offline.
 *
 * Called under device_hotplug_lock.
 */
/* 为给定内存区域注册memory block设备，其start和size需要以memory block为
   粒度对齐。memory block设备将会被初始化为offline
*/
int create_memory_block_devices(unsigned long start, unsigned long size,
				unsigned long vmemmap_pages)
{
	/* 计算其起始和结束的block id */
	const unsigned long start_block_id = pfn_to_block_id(PFN_DOWN(start));
	unsigned long end_block_id = pfn_to_block_id(PFN_DOWN(start + size));
	struct memory_block *mem;
	unsigned long block_id;
	int ret = 0;

	/* 对齐检查 */
	if (WARN_ON_ONCE(!IS_ALIGNED(start, memory_block_size_bytes()) ||
			 !IS_ALIGNED(size, memory_block_size_bytes())))
		return -EINVAL;

	/* 遍历block id，并分别初始化它们 */
	for (block_id = start_block_id; block_id != end_block_id; block_id++) {
		ret = init_memory_block(block_id, MEM_OFFLINE, vmemmap_pages);
		if (ret)
			break;
	}
	/* 失败处理 */
	if (ret) {
		end_block_id = block_id;
		for (block_id = start_block_id; block_id != end_block_id;
		     block_id++) {
			mem = find_memory_block_by_id(block_id);
			if (WARN_ON_ONCE(!mem))
				continue;
			unregister_memory(mem);
		}
	}
	return ret;
}

/*
 * Remove memory block devices for the given memory area. Start and size
 * have to be aligned to memory block granularity. Memory block devices
 * have to be offline.
 *
 * Called under device_hotplug_lock.
 */
/* 移除给定地址返回内的memory block设备 */
void remove_memory_block_devices(unsigned long start, unsigned long size)
{
	/* 计算其起始和结束的block id */
	const unsigned long start_block_id = pfn_to_block_id(PFN_DOWN(start));
	const unsigned long end_block_id = pfn_to_block_id(PFN_DOWN(start + size));
	struct memory_block *mem;
	unsigned long block_id;

	/* 对齐检查 */
	if (WARN_ON_ONCE(!IS_ALIGNED(start, memory_block_size_bytes()) ||
			 !IS_ALIGNED(size, memory_block_size_bytes())))
		return;

	/* 遍历block id，并分别初始化它们 */
	for (block_id = start_block_id; block_id != end_block_id; block_id++) {
		mem = find_memory_block_by_id(block_id);
		if (WARN_ON_ONCE(!mem))
			continue;
		unregister_memory_block_under_nodes(mem);
		unregister_memory(mem);
	}
}

/* return true if the memory block is offlined, otherwise, return false */
/* 判断一个内存模块是否为offlined */
bool is_memblock_offlined(struct memory_block *mem)
{
	return mem->state == MEM_OFFLINE;
}

static struct attribute *memory_root_attrs[] = {
#ifdef CONFIG_ARCH_MEMORY_PROBE
	&dev_attr_probe.attr,
#endif

#ifdef CONFIG_MEMORY_FAILURE
	&dev_attr_soft_offline_page.attr,
	&dev_attr_hard_offline_page.attr,
#endif

	&dev_attr_block_size_bytes.attr,
	&dev_attr_auto_online_blocks.attr,
	NULL
};

static const struct attribute_group memory_root_attr_group = {
	.attrs = memory_root_attrs,
};

static const struct attribute_group *memory_root_attr_groups[] = {
	&memory_root_attr_group,
	NULL,
};

/*
 * Initialize the sysfs support for memory devices. At the time this function
 * is called, we cannot have concurrent creation/deletion of memory block
 * devices, the device_hotplug_lock is not needed.
 */
void __init memory_dev_init(void)
{
	int ret;
	unsigned long block_sz, nr;

	/* Validate the configured memory block size */
	/* 获取memblock size，它最小为section size */
	block_sz = memory_block_size_bytes();
	if (!is_power_of_2(block_sz) || block_sz < MIN_MEMORY_BLOCK_SIZE)
		panic("Memory block size not suitable: 0x%lx\n", block_sz);
	/* 每个block含有多少个section，默认为1个 */
	sections_per_block = block_sz / MIN_MEMORY_BLOCK_SIZE;

	/* memory节点的sysfs注册 */
	ret = subsys_system_register(&memory_subsys, memory_root_attr_groups);
	if (ret)
		panic("%s() failed to register subsystem: %d\n", __func__, ret);

	/*
	 * Create entries for memory sections that were found
	 * during boot and have been initialized
	 */
	/* 遍历整个地址范围，并分别注册其memory block设备 */
	for (nr = 0; nr <= __highest_present_section_nr;
	     nr += sections_per_block) {
		ret = add_memory_block(nr);
		if (ret)
			panic("%s() failed to add memory block: %d\n", __func__,
			      ret);
	}
}

/**
 * walk_memory_blocks - walk through all present memory blocks overlapped
 *			by the range [start, start + size)
 *
 * @start: start address of the memory range
 * @size: size of the memory range
 * @arg: argument passed to func
 * @func: callback for each memory section walked
 *
 * This function walks through all present memory blocks overlapped by the
 * range [start, start + size), calling func on each memory block.
 *
 * In case func() returns an error, walking is aborted and the error is
 * returned.
 *
 * Called under device_hotplug_lock.
 */
/* 遍历内存范围中所有存在的内存blocks，并对每个block调用给定的回调函数 */
int walk_memory_blocks(unsigned long start, unsigned long size,
		       void *arg, walk_memory_blocks_func_t func)
{
	const unsigned long start_block_id = phys_to_block_id(start);
	const unsigned long end_block_id = phys_to_block_id(start + size - 1);
	struct memory_block *mem;
	unsigned long block_id;
	int ret = 0;

	if (!size)
		return 0;

	/* 遍历给定内存范围内的block，并分别对其执行给定函数 */
	for (block_id = start_block_id; block_id <= end_block_id; block_id++) {
		mem = find_memory_block_by_id(block_id);
		if (!mem)
			continue;

		ret = func(mem, arg);
		put_device(&mem->dev);
		if (ret)
			break;
	}
	return ret;
}

struct for_each_memory_block_cb_data {
	walk_memory_blocks_func_t func;
	void *arg;
};

static int for_each_memory_block_cb(struct device *dev, void *data)
{
	struct memory_block *mem = to_memory_block(dev);
	struct for_each_memory_block_cb_data *cb_data = data;

	return cb_data->func(mem, cb_data->arg);
}

/**
 * for_each_memory_block - walk through all present memory blocks
 *
 * @arg: argument passed to func
 * @func: callback for each memory block walked
 *
 * This function walks through all present memory blocks, calling func on
 * each memory block.
 *
 * In case func() returns an error, walking is aborted and the error is
 * returned.
 */
int for_each_memory_block(void *arg, walk_memory_blocks_func_t func)
{
	struct for_each_memory_block_cb_data cb_data = {
		.func = func,
		.arg = arg,
	};

	return bus_for_each_dev(&memory_subsys, NULL, &cb_data,
				for_each_memory_block_cb);
}
