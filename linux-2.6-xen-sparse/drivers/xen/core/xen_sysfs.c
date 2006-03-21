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
#include <linux/init.h>
#include <asm/hypervisor.h>
#include <xen/features.h>
#include <xen/hypervisor_sysfs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mike D. Day <ncmike@us.ibm.com>");

static ssize_t type_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	return sprintf(buffer, "xen\n");
}

HYPERVISOR_ATTR_RO(type);

static int __init xen_sysfs_type_init(void)
{
	return sysfs_create_file(&hypervisor_subsys.kset.kobj, &type_attr.attr);
}

static void xen_sysfs_type_destroy(void)
{
	sysfs_remove_file(&hypervisor_subsys.kset.kobj, &type_attr.attr);
}

/* xen version attributes */
static ssize_t major_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int version = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (version)
		return sprintf(buffer, "%d\n", version >> 16);
	return -ENODEV;
}

HYPERVISOR_ATTR_RO(major);

static ssize_t minor_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int version = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (version)
		return sprintf(buffer, "%d\n", version & 0xff);
	return -ENODEV;
}

HYPERVISOR_ATTR_RO(minor);

static ssize_t extra_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	char *extra = kmalloc(XEN_EXTRAVERSION_LEN, GFP_KERNEL);
	if (extra) {
		ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
		if (!ret)
			return sprintf(buffer, "%s\n", extra);
		kfree(extra);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(extra);

static struct attribute *version_attrs[] = {
	&major_attr.attr,
	&minor_attr.attr,
	&extra_attr.attr,
	NULL
};

static struct attribute_group version_group = {
	.name = "version",
	.attrs = version_attrs,
};

static int __init xen_sysfs_version_init(void)
{
	return sysfs_create_group(&hypervisor_subsys.kset.kobj, &version_group);
}

static void xen_sysfs_version_destroy(void)
{
	sysfs_remove_group(&hypervisor_subsys.kset.kobj, &version_group);
}

/* xen compilation attributes */

static ssize_t compiler_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	struct xen_compile_info *info =
	    kmalloc(sizeof(struct xen_compile_info), GFP_KERNEL);
	if (info) {
		ret = HYPERVISOR_xen_version(XENVER_compile_info, info);
		if (!ret)
			ret = sprintf(buffer, "%s\n", info->compiler);
		kfree(info);
	} else
		ret = -ENOMEM;

	return ret;
}

HYPERVISOR_ATTR_RO(compiler);

static ssize_t compiled_by_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	struct xen_compile_info *info;

	info = kmalloc(sizeof(struct xen_compile_info), GFP_KERNEL);
	if (info) {
		ret = HYPERVISOR_xen_version(XENVER_compile_info, info);
		if (!ret)
			ret = sprintf(buffer, "%s\n", info->compile_by);
		kfree(info);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(compiled_by);

static ssize_t compile_date_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	struct xen_compile_info *info;

	info = kmalloc(sizeof(struct xen_compile_info), GFP_KERNEL);
	if (info) {
		ret = HYPERVISOR_xen_version(XENVER_compile_info, info);
		if (!ret)
			ret = sprintf(buffer, "%s\n", info->compile_date);
		kfree(info);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(compile_date);

static struct attribute *xen_compile_attrs[] = {
	&compiler_attr.attr,
	&compiled_by_attr.attr,
	&compile_date_attr.attr,
	NULL
};

static struct attribute_group xen_compilation_group = {
	.name = "compilation",
	.attrs = xen_compile_attrs,
};

int __init static xen_compilation_init(void)
{
	return sysfs_create_group(&hypervisor_subsys.kset.kobj,
				  &xen_compilation_group);
}

static void xen_compilation_destroy(void)
{
	sysfs_remove_group(&hypervisor_subsys.kset.kobj,
			   &xen_compilation_group);
}

/* xen properties info */

static ssize_t capabilities_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	char *caps = kmalloc(XEN_CAPABILITIES_INFO_LEN, GFP_KERNEL);
	if (caps) {
		ret = HYPERVISOR_xen_version(XENVER_capabilities, caps);
		if (!ret)
			ret = sprintf(buffer, "%s\n", caps);
		kfree(caps);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(capabilities);

static ssize_t changeset_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	char *cset = kmalloc(XEN_CHANGESET_INFO_LEN, GFP_KERNEL);
	if (cset) {
		ret = HYPERVISOR_xen_version(XENVER_changeset, cset);
		if (!ret)
			ret = sprintf(buffer, "%s\n", cset);
		kfree(cset);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(changeset);

static ssize_t virtual_start_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	int ret;
	struct xen_platform_parameters *parms =
	    kmalloc(sizeof(struct xen_platform_parameters), GFP_KERNEL);
	if (parms) {
		ret = HYPERVISOR_xen_version(XENVER_platform_parameters, parms);
		if (!ret)
			ret = sprintf(buffer, "%lx\n", parms->virt_start);
		kfree(parms);
	} else
		ret = -ENOMEM;
	return ret;
}

HYPERVISOR_ATTR_RO(virtual_start);

/* eventually there will be several more features to export */
static ssize_t xen_feature_show(int index, char *buffer)
{
	int ret;

	struct xen_feature_info *info =
	    kmalloc(sizeof(struct xen_feature_info), GFP_KERNEL);
	if (info) {
		info->submap_idx = index;
		ret = HYPERVISOR_xen_version(XENVER_get_features, info);
		if (!ret)
			ret = sprintf(buffer, "%d\n", info->submap);
		kfree(info);
	} else
		ret = -ENOMEM;
	return ret;
}

static ssize_t writable_pt_show(struct hyp_sysfs_attr *attr, char *buffer)
{
	return xen_feature_show(XENFEAT_writable_page_tables, buffer);
}

HYPERVISOR_ATTR_RO(writable_pt);

static struct attribute *xen_properties_attrs[] = {
	&capabilities_attr.attr,
	&changeset_attr.attr,
	&virtual_start_attr.attr,
	&writable_pt_attr.attr,
	NULL
};

static struct attribute_group xen_properties_group = {
	.name = "properties",
	.attrs = xen_properties_attrs,
};

static int __init xen_properties_init(void)
{
	return sysfs_create_group(&hypervisor_subsys.kset.kobj,
				  &xen_properties_group);
}

static void xen_properties_destroy(void)
{
	sysfs_remove_group(&hypervisor_subsys.kset.kobj, &xen_properties_group);
}

static int __init hyper_sysfs_init(void)
{
	int ret = xen_sysfs_type_init();
	if (ret)
		goto out;
	ret = xen_sysfs_version_init();
	if (ret)
		goto version_out;
	ret = xen_compilation_init();
	if (ret)
		goto comp_out;
	ret = xen_properties_init();
	if (!ret)
		goto out;

	xen_compilation_destroy();
comp_out:
	xen_sysfs_version_destroy();
version_out:
	xen_sysfs_type_destroy();
out:
	return ret;
}

static void hyper_sysfs_exit(void)
{
	xen_properties_destroy();
	xen_compilation_destroy();
	xen_sysfs_version_destroy();
	xen_sysfs_type_destroy();

}

module_init(hyper_sysfs_init);
module_exit(hyper_sysfs_exit);
