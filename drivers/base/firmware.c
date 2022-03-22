// SPDX-License-Identifier: GPL-2.0
/*
 * firmware.c - firmware subsystem hoohaw.
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2007 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2007 Novell Inc.
 */
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>

#include "base.h"

struct kobject *firmware_kobj;
EXPORT_SYMBOL_GPL(firmware_kobj);

/* sysfs的firmware目录初始化 */
int __init firmware_init(void)
{
	/* 在sysfs的顶级目录下，创建一个firmware目录 */
	firmware_kobj = kobject_create_and_add("firmware", NULL);
	if (!firmware_kobj)
		return -ENOMEM;
	return 0;
}
