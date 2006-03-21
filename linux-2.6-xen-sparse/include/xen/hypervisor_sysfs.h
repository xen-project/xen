/*
 *  copyright (c) 2006 IBM Corporation
 *  Authored by: Mike D. Day <ncmike@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _HYP_SYSFS_H_
#define _HYP_SYSFS_H_

#include <linux/kobject.h>
#include <linux/sysfs.h>

#define HYPERVISOR_ATTR_RO(_name) \
static struct hyp_sysfs_attr  _name##_attr = __ATTR_RO(_name)

#define HYPERVISOR_ATTR_RW(_name) \
static struct hyp_sysfs_attr _name##_attr = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

extern struct subsystem hypervisor_subsys;

struct hyp_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct hyp_sysfs_attr *, char *);
	ssize_t (*store)(struct hyp_sysfs_attr *, const char *, size_t);
	void *hyp_attr_data;
};

#endif /* _HYP_SYSFS_H_ */
