/*
 *  copyright (c) 2006 IBM Corporation
 *  Authored by: Mike D. Day <ncmike@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <xen/hypervisor_sysfs.h>

decl_subsys(hypervisor, NULL, NULL);

static ssize_t hyp_sysfs_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buffer)
{
	struct hyp_sysfs_attr *hyp_attr;
	hyp_attr = container_of(attr, struct hyp_sysfs_attr, attr);
	if (hyp_attr->show)
		return hyp_attr->show(hyp_attr, buffer);
	return 0;
}

static ssize_t hyp_sysfs_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer,
			       size_t len)
{
	struct hyp_sysfs_attr *hyp_attr;
	hyp_attr = container_of(attr, struct hyp_sysfs_attr, attr);
	if (hyp_attr->store)
		return hyp_attr->store(hyp_attr, buffer, len);
	return 0;
}

struct sysfs_ops hyp_sysfs_ops = {
	.show = hyp_sysfs_show,
	.store = hyp_sysfs_store,
};

static struct kobj_type hyp_sysfs_kobj_type = {
	.sysfs_ops = &hyp_sysfs_ops,
};

static int __init hypervisor_subsys_init(void)
{
	hypervisor_subsys.kset.kobj.ktype = &hyp_sysfs_kobj_type;
	return subsystem_register(&hypervisor_subsys);
}

device_initcall(hypervisor_subsys_init);
EXPORT_SYMBOL_GPL(hypervisor_subsys);
