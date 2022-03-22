/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMREMAP_H_
#define _LINUX_MEMREMAP_H_
#include <linux/range.h>
#include <linux/ioport.h>
#include <linux/percpu-refcount.h>

struct resource;
struct device;

/**
 * struct vmem_altmap - pre-allocated storage for vmemmap_populate
 * @base_pfn: base of the entire dev_pagemap mapping
 * @reserve: pages mapped, but reserved for driver use (relative to @base)
 * @free: free pages set aside in the mapping for memmap storage
 * @align: pages reserved to meet allocation alignments
 * @alloc: track pages consumed, private to vmemmap_populate()
 */
/* 为vmemmap_populate预分配的存储
   base_pfn：整个dev_pagemap映射的base pfn
   reserve：page已经被映射，但被保留给驱动使用
   free：映射中留出用于memmap存储的free pages
   align：预留用于分配时对齐的page
   alloc：跟踪已经被消费的页面，是vmemmap_populate私有的
*/
struct vmem_altmap {
	unsigned long base_pfn;
	const unsigned long end_pfn;
	const unsigned long reserve;
	unsigned long free;
	unsigned long align;
	unsigned long alloc;
};

/*
 * Specialize ZONE_DEVICE memory into multiple types each has a different
 * usage.
 *
 * MEMORY_DEVICE_PRIVATE:
 * Device memory that is not directly addressable by the CPU: CPU can neither
 * read nor write private memory. In this case, we do still have struct pages
 * backing the device memory. Doing so simplifies the implementation, but it is
 * important to remember that there are certain points at which the struct page
 * must be treated as an opaque object, rather than a "normal" struct page.
 *
 * A more complete discussion of unaddressable memory may be found in
 * include/linux/hmm.h and Documentation/vm/hmm.rst.
 *
 * MEMORY_DEVICE_FS_DAX:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. In support of coordinating page
 * pinning vs other operations MEMORY_DEVICE_FS_DAX arranges for a
 * wakeup event whenever a page is unpinned and becomes idle. This
 * wakeup is used to coordinate physical address space management (ex:
 * fs truncate/hole punch) vs pinned pages (ex: device dma).
 *
 * MEMORY_DEVICE_GENERIC:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. This is for example used by DAX devices
 * that expose memory using a character device.
 *
 * MEMORY_DEVICE_PCI_P2PDMA:
 * Device memory residing in a PCI BAR intended for use with Peer-to-Peer
 * transactions.
 */
/* 指定ZONE_DEVICE内存的类型，每种类型含有不同的使用场景
   （1）MEMORY_DEVICE_PRIVATE：不是由cpu直接寻址的设备内存，CPU不能读也不能写private
   内存。这种情形下，我们依然含有设备内存的backing page结构体，它可以简化我们的
   设计，但需要注意这种page结构体需要被视为opaque队形，而不是normal的page结构体
   （2）MEMORY_DEVICE_FS_DAX：host内存含有与系统内存相似的访问方法。DMA coherent且支持
   page pinning。为了支持page pinning和其它操作的协调，MEMORY_DEVICE_FS_DAX在page处于
   unpinned且是idle时唤醒一个事件。这种唤醒用于协调物理地址空间管理（如fs截断/空洞punch）
   与pinned pages（如设备dma）
   （3）MEMORY_DEVICE_GENERIC：host内存含有与系统内存相似的访问方法。DMA coherent且支持
   page pinning。使用示例如DAX设备，它使用一个字符设备保留内存
   （4）MEMORY_DEVICE_PCI_P2PDMA：内存位于PCI的BAR中，以用于peer-to-peer传输
*/
enum memory_type {
	/* 0 is reserved to catch uninitialized type fields */
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_FS_DAX,
	MEMORY_DEVICE_GENERIC,
	MEMORY_DEVICE_PCI_P2PDMA,
};

/* 设备页映射的操作函数 */
struct dev_pagemap_ops {
	/*
	 * Called once the page refcount reaches 1.  (ZONE_DEVICE pages never
	 * reach 0 refcount unless there is a refcount bug. This allows the
	 * device driver to implement its own memory management.)
	 */
	void (*page_free)(struct page *page);

	/*
	 * Transition the refcount in struct dev_pagemap to the dead state.
	 */
	void (*kill)(struct dev_pagemap *pgmap);

	/*
	 * Wait for refcount in struct dev_pagemap to be idle and reap it.
	 */
	void (*cleanup)(struct dev_pagemap *pgmap);

	/*
	 * Used for private (un-addressable) device memory only.  Must migrate
	 * the page back to a CPU accessible page.
	 */
	/* 只用于private设备内存，需要将page迁移到cpu可访问的page */
	vm_fault_t (*migrate_to_ram)(struct vm_fault *vmf);
};

#define PGMAP_ALTMAP_VALID	(1 << 0)

/**
 * struct dev_pagemap - metadata for ZONE_DEVICE mappings
 * @altmap: pre-allocated/reserved memory for vmemmap allocations
 * @ref: reference count that pins the devm_memremap_pages() mapping
 * @internal_ref: internal reference if @ref is not provided by the caller
 * @done: completion for @internal_ref
 * @type: memory type: see MEMORY_* in memory_hotplug.h
 * @flags: PGMAP_* flags to specify defailed behavior
 * @ops: method table
 * @owner: an opaque pointer identifying the entity that manages this
 *	instance.  Used by various helpers to make sure that no
 *	foreign ZONE_DEVICE memory is accessed.
 * @nr_range: number of ranges to be mapped
 * @range: range to be mapped when nr_range == 1
 * @ranges: array of ranges to be mapped when nr_range > 1
 */
/* ZONE_DEVICE映射的metadata
*/
struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref *ref;
	struct percpu_ref internal_ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

static inline struct vmem_altmap *pgmap_altmap(struct dev_pagemap *pgmap)
{
	if (pgmap->flags & PGMAP_ALTMAP_VALID)
		return &pgmap->altmap;
	return NULL;
}

#ifdef CONFIG_ZONE_DEVICE
void *memremap_pages(struct dev_pagemap *pgmap, int nid);
void memunmap_pages(struct dev_pagemap *pgmap);
void *devm_memremap_pages(struct device *dev, struct dev_pagemap *pgmap);
void devm_memunmap_pages(struct device *dev, struct dev_pagemap *pgmap);
struct dev_pagemap *get_dev_pagemap(unsigned long pfn,
		struct dev_pagemap *pgmap);
bool pgmap_pfn_valid(struct dev_pagemap *pgmap, unsigned long pfn);

unsigned long vmem_altmap_offset(struct vmem_altmap *altmap);
void vmem_altmap_free(struct vmem_altmap *altmap, unsigned long nr_pfns);
unsigned long memremap_compat_align(void);
#else
static inline void *devm_memremap_pages(struct device *dev,
		struct dev_pagemap *pgmap)
{
	/*
	 * Fail attempts to call devm_memremap_pages() without
	 * ZONE_DEVICE support enabled, this requires callers to fall
	 * back to plain devm_memremap() based on config
	 */
	WARN_ON_ONCE(1);
	return ERR_PTR(-ENXIO);
}

static inline void devm_memunmap_pages(struct device *dev,
		struct dev_pagemap *pgmap)
{
}

static inline struct dev_pagemap *get_dev_pagemap(unsigned long pfn,
		struct dev_pagemap *pgmap)
{
	return NULL;
}

static inline bool pgmap_pfn_valid(struct dev_pagemap *pgmap, unsigned long pfn)
{
	return false;
}

static inline unsigned long vmem_altmap_offset(struct vmem_altmap *altmap)
{
	return 0;
}

static inline void vmem_altmap_free(struct vmem_altmap *altmap,
		unsigned long nr_pfns)
{
}

/* when memremap_pages() is disabled all archs can remap a single page */
static inline unsigned long memremap_compat_align(void)
{
	return PAGE_SIZE;
}
#endif /* CONFIG_ZONE_DEVICE */

static inline void put_dev_pagemap(struct dev_pagemap *pgmap)
{
	if (pgmap)
		percpu_ref_put(pgmap->ref);
}

#endif /* _LINUX_MEMREMAP_H_ */
