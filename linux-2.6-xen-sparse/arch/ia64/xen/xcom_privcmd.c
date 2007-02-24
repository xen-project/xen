/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Tristan Gingold <tristan.gingold@bull.net>
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <xen/interface/xen.h>
#include <xen/interface/dom0_ops.h>
#define __XEN__
#include <xen/interface/domctl.h>
#include <xen/interface/sysctl.h>
#include <xen/interface/memory.h>
#include <xen/interface/version.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/acm_ops.h>
#include <xen/interface/hvm/params.h>
#include <xen/public/privcmd.h>
#include <asm/hypercall.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <asm/xen/xencomm.h>

#define ROUND_DIV(v,s) (((v) + (s) - 1) / (s))

static int
xencomm_privcmd_dom0_op(privcmd_hypercall_t *hypercall)
{
	dom0_op_t kern_op;
	dom0_op_t __user *user_op = (dom0_op_t __user *)hypercall->arg[0];
	struct xencomm_handle *op_desc;
	struct xencomm_handle *desc = NULL;
	int ret = 0;

	if (copy_from_user(&kern_op, user_op, sizeof(dom0_op_t)))
		return -EFAULT;

	if (kern_op.interface_version != DOM0_INTERFACE_VERSION)
		return -EACCES;

	op_desc = xencomm_create_inline(&kern_op);

	switch (kern_op.cmd) {
	default:
		printk("%s: unknown dom0 cmd %d\n", __func__, kern_op.cmd);
		return -ENOSYS;
	}

	if (ret) {
		/* error mapping the nested pointer */
		return ret;
	}

	ret = xencomm_arch_hypercall_dom0_op(op_desc);

	/* FIXME: should we restore the handle?  */
	if (copy_to_user(user_op, &kern_op, sizeof(dom0_op_t)))
		ret = -EFAULT;

	if (desc)
		xencomm_free(desc);
	return ret;
}

/*
 * Temporarily disable the NUMA PHYSINFO code until the rest of the
 * changes are upstream.
 */
#undef IA64_NUMA_PHYSINFO

static int
xencomm_privcmd_sysctl(privcmd_hypercall_t *hypercall)
{
	xen_sysctl_t kern_op;
	xen_sysctl_t __user *user_op;
	struct xencomm_handle *op_desc;
	struct xencomm_handle *desc = NULL;
	struct xencomm_handle *desc1 = NULL;
	int ret = 0;

	user_op = (xen_sysctl_t __user *)hypercall->arg[0];

	if (copy_from_user(&kern_op, user_op, sizeof(xen_sysctl_t)))
		return -EFAULT;

	if (kern_op.interface_version != XEN_SYSCTL_INTERFACE_VERSION)
		return -EACCES;

	op_desc = xencomm_create_inline(&kern_op);

	switch (kern_op.cmd) {
	case XEN_SYSCTL_readconsole:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.readconsole.buffer),
			kern_op.u.readconsole.count,
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.readconsole.buffer,
		                     (void *)desc);
		break;
	case XEN_SYSCTL_tbuf_op:
#ifndef IA64_NUMA_PHYSINFO
	case XEN_SYSCTL_physinfo:
#endif
	case XEN_SYSCTL_sched_id:
		break;
	case XEN_SYSCTL_perfc_op:
	{
		struct xencomm_handle *tmp_desc;
		xen_sysctl_t tmp_op = {
			.cmd = XEN_SYSCTL_perfc_op,
			.interface_version = XEN_SYSCTL_INTERFACE_VERSION,
			.u.perfc_op = {
				.cmd = XEN_SYSCTL_PERFCOP_query,
				// .desc.p = NULL,
				// .val.p = NULL,
			},
		};

		if (xen_guest_handle(kern_op.u.perfc_op.desc) == NULL) {
			if (xen_guest_handle(kern_op.u.perfc_op.val) != NULL)
				return -EINVAL;
			break;
		}

		/* query the buffer size for xencomm */
		tmp_desc = xencomm_create_inline(&tmp_op);
		ret = xencomm_arch_hypercall_sysctl(tmp_desc);
		if (ret)
			return ret;

		ret = xencomm_create(xen_guest_handle(kern_op.u.perfc_op.desc),
		                     tmp_op.u.perfc_op.nr_counters *
		                     sizeof(xen_sysctl_perfc_desc_t),
		                     &desc, GFP_KERNEL);
		if (ret)
			return ret;

		set_xen_guest_handle(kern_op.u.perfc_op.desc, (void *)desc);

		ret = xencomm_create(xen_guest_handle(kern_op.u.perfc_op.val),
		                     tmp_op.u.perfc_op.nr_vals *
		                     sizeof(xen_sysctl_perfc_val_t),
		                     &desc1, GFP_KERNEL);
		if (ret)
			xencomm_free(desc);

		set_xen_guest_handle(kern_op.u.perfc_op.val, (void *)desc1);
		break;
	}
	case XEN_SYSCTL_getdomaininfolist:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.getdomaininfolist.buffer),
			kern_op.u.getdomaininfolist.max_domains *
			sizeof(xen_domctl_getdomaininfo_t),
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.getdomaininfolist.buffer,
				     (void *)desc);
		break;
#ifdef IA64_NUMA_PHYSINFO
	case XEN_SYSCTL_physinfo:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.physinfo.memory_chunks),
			PUBLIC_MAXCHUNKS * sizeof(node_data_t),
			&desc, GFP_KERNEL);
		if (ret)
			return ret;
		set_xen_guest_handle(kern_op.u.physinfo.memory_chunks,
		                     (void *)desc);

		ret = xencomm_create(
			xen_guest_handle(kern_op.u.physinfo.cpu_to_node),
			PUBLIC_MAX_NUMNODES * sizeof(u64),
			&desc1, GFP_KERNEL);
		if (ret)
			xencomm_free(desc);
		set_xen_guest_handle(kern_op.u.physinfo.cpu_to_node,
		                     (void *)desc1);
		break;
#endif
	default:
		printk("%s: unknown sysctl cmd %d\n", __func__, kern_op.cmd);
		return -ENOSYS;
	}

	if (ret) {
		/* error mapping the nested pointer */
		return ret;
	}

	ret = xencomm_arch_hypercall_sysctl(op_desc);

	/* FIXME: should we restore the handles?  */
	if (copy_to_user(user_op, &kern_op, sizeof(xen_sysctl_t)))
		ret = -EFAULT;

	if (desc)
		xencomm_free(desc);
	if (desc1)
		xencomm_free(desc1);
	return ret;
}

static int
xencomm_privcmd_domctl(privcmd_hypercall_t *hypercall)
{
	xen_domctl_t kern_op;
	xen_domctl_t __user *user_op;
	struct xencomm_handle *op_desc;
	struct xencomm_handle *desc = NULL;
	int ret = 0;

	user_op = (xen_domctl_t __user *)hypercall->arg[0];

	if (copy_from_user(&kern_op, user_op, sizeof(xen_domctl_t)))
		return -EFAULT;

	if (kern_op.interface_version != XEN_DOMCTL_INTERFACE_VERSION)
		return -EACCES;

	op_desc = xencomm_create_inline(&kern_op);

	switch (kern_op.cmd) {
	case XEN_DOMCTL_createdomain:
	case XEN_DOMCTL_destroydomain:
	case XEN_DOMCTL_pausedomain:
	case XEN_DOMCTL_unpausedomain:
	case XEN_DOMCTL_getdomaininfo:
		break;
	case XEN_DOMCTL_getmemlist:
	{
		unsigned long nr_pages = kern_op.u.getmemlist.max_pfns;

		ret = xencomm_create(
			xen_guest_handle(kern_op.u.getmemlist.buffer),
			nr_pages * sizeof(unsigned long),
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.getmemlist.buffer,
		                     (void *)desc);
		break;
	}
	case XEN_DOMCTL_getpageframeinfo:
		break;
	case XEN_DOMCTL_getpageframeinfo2:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.getpageframeinfo2.array),
			kern_op.u.getpageframeinfo2.num,
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.getpageframeinfo2.array,
		                     (void *)desc);
		break;
	case XEN_DOMCTL_shadow_op:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.shadow_op.dirty_bitmap),
			ROUND_DIV(kern_op.u.shadow_op.pages, 8),
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.shadow_op.dirty_bitmap,
		                     (void *)desc);
		break;
	case XEN_DOMCTL_max_mem:
		break;
	case XEN_DOMCTL_setvcpucontext:
	case XEN_DOMCTL_getvcpucontext:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.vcpucontext.ctxt),
			sizeof(vcpu_guest_context_t),
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.vcpucontext.ctxt, (void *)desc);
		break;
	case XEN_DOMCTL_getvcpuinfo:
		break;
	case XEN_DOMCTL_setvcpuaffinity:
	case XEN_DOMCTL_getvcpuaffinity:
		ret = xencomm_create(
			xen_guest_handle(kern_op.u.vcpuaffinity.cpumap.bitmap),
			ROUND_DIV(kern_op.u.vcpuaffinity.cpumap.nr_cpus, 8),
			&desc, GFP_KERNEL);
		set_xen_guest_handle(kern_op.u.vcpuaffinity.cpumap.bitmap,
		                     (void *)desc);
		break;
	case XEN_DOMCTL_max_vcpus:
	case XEN_DOMCTL_scheduler_op:
	case XEN_DOMCTL_setdomainhandle:
	case XEN_DOMCTL_setdebugging:
	case XEN_DOMCTL_irq_permission:
	case XEN_DOMCTL_iomem_permission:
	case XEN_DOMCTL_ioport_permission:
	case XEN_DOMCTL_hypercall_init:
	case XEN_DOMCTL_arch_setup:
	case XEN_DOMCTL_settimeoffset:
	case XEN_DOMCTL_sendtrigger:
		break;
	default:
		printk("%s: unknown domctl cmd %d\n", __func__, kern_op.cmd);
		return -ENOSYS;
	}

	if (ret) {
		/* error mapping the nested pointer */
		return ret;
	}

	ret = xencomm_arch_hypercall_domctl (op_desc);

	/* FIXME: should we restore the handle?  */
	if (copy_to_user(user_op, &kern_op, sizeof(xen_domctl_t)))
		ret = -EFAULT;

	if (desc)
		xencomm_free(desc);
	return ret;
}

static int
xencomm_privcmd_acm_op(privcmd_hypercall_t *hypercall)
{
	int cmd = hypercall->arg[0];
	void __user *arg = (void __user *)hypercall->arg[1];
	struct xencomm_handle *op_desc;
	struct xencomm_handle *desc = NULL;
	int ret;

	switch (cmd) {
	case ACMOP_getssid:
	{
		struct acm_getssid kern_arg;

		if (copy_from_user(&kern_arg, arg, sizeof (kern_arg)))
			return -EFAULT;

		op_desc = xencomm_create_inline(&kern_arg);

		ret = xencomm_create(xen_guest_handle(kern_arg.ssidbuf),
		                     kern_arg.ssidbuf_size, &desc, GFP_KERNEL);
		if (ret)
			return ret;

		set_xen_guest_handle(kern_arg.ssidbuf, (void *)desc);

		ret = xencomm_arch_hypercall_acm_op(cmd, op_desc);

		xencomm_free(desc);

		if (copy_to_user(arg, &kern_arg, sizeof (kern_arg)))
			return -EFAULT;

		return ret;
	}
	default:
		printk("%s: unknown acm_op cmd %d\n", __func__, cmd);
		return -ENOSYS;
	}

	return ret;
}

static int
xencomm_privcmd_memory_op(privcmd_hypercall_t *hypercall)
{
	const unsigned long cmd = hypercall->arg[0];
	int ret = 0;

	switch (cmd) {
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_populate_physmap:
	{
		xen_memory_reservation_t kern_op;
		xen_memory_reservation_t __user *user_op;
		struct xencomm_handle *desc = NULL;
		struct xencomm_handle *desc_op;

		user_op = (xen_memory_reservation_t __user *)hypercall->arg[1];
		if (copy_from_user(&kern_op, user_op,
		                   sizeof(xen_memory_reservation_t)))
			return -EFAULT;
		desc_op = xencomm_create_inline(&kern_op);

		if (xen_guest_handle(kern_op.extent_start)) {
			void * addr;

			addr = xen_guest_handle(kern_op.extent_start);
			ret = xencomm_create
				(addr,
				 kern_op.nr_extents *
				 sizeof(*xen_guest_handle
					(kern_op.extent_start)),
				 &desc, GFP_KERNEL);
			if (ret)
				return ret;
			set_xen_guest_handle(kern_op.extent_start,
			                     (void *)desc);
		}

		ret = xencomm_arch_hypercall_memory_op(cmd, desc_op);

		if (desc)
			xencomm_free(desc);

		if (ret != 0)
			return ret;

		if (copy_to_user(user_op, &kern_op,
		                 sizeof(xen_memory_reservation_t)))
			return -EFAULT;

		return ret;
	}
	case XENMEM_translate_gpfn_list:
	{
		xen_translate_gpfn_list_t kern_op;
		xen_translate_gpfn_list_t __user *user_op;
		struct xencomm_handle *desc_gpfn = NULL;
		struct xencomm_handle *desc_mfn = NULL;
		struct xencomm_handle *desc_op;
		void *addr;

		user_op = (xen_translate_gpfn_list_t __user *)
			hypercall->arg[1];
		if (copy_from_user(&kern_op, user_op,
		                   sizeof(xen_translate_gpfn_list_t)))
			return -EFAULT;
		desc_op = xencomm_create_inline(&kern_op);

		if (kern_op.nr_gpfns) {
			/* gpfn_list.  */
			addr = xen_guest_handle(kern_op.gpfn_list);

			ret = xencomm_create(addr, kern_op.nr_gpfns *
			                     sizeof(*xen_guest_handle
			                            (kern_op.gpfn_list)),
			                     &desc_gpfn, GFP_KERNEL);
			if (ret)
				return ret;
			set_xen_guest_handle(kern_op.gpfn_list,
			                     (void *)desc_gpfn);

			/* mfn_list.  */
			addr = xen_guest_handle(kern_op.mfn_list);

			ret = xencomm_create(addr, kern_op.nr_gpfns *
			                     sizeof(*xen_guest_handle
			                            (kern_op.mfn_list)),
			                     &desc_mfn, GFP_KERNEL);
			if (ret)
				return ret;
			set_xen_guest_handle(kern_op.mfn_list,
			                     (void *)desc_mfn);
		}

		ret = xencomm_arch_hypercall_memory_op(cmd, desc_op);

		if (desc_gpfn)
			xencomm_free(desc_gpfn);

		if (desc_mfn)
			xencomm_free(desc_mfn);

		if (ret != 0)
			return ret;

		return ret;
	}
	default:
		printk("%s: unknown memory op %lu\n", __func__, cmd);
		ret = -ENOSYS;
	}
	return ret;
}

static int
xencomm_privcmd_xen_version(privcmd_hypercall_t *hypercall)
{
	int cmd = hypercall->arg[0];
	void __user *arg = (void __user *)hypercall->arg[1];
	struct xencomm_handle *desc;
	size_t argsize;
	int rc;

	switch (cmd) {
	case XENVER_version:
		/* do not actually pass an argument */
		return xencomm_arch_hypercall_xen_version(cmd, 0);
	case XENVER_extraversion:
		argsize = sizeof(xen_extraversion_t);
		break;
	case XENVER_compile_info:
		argsize = sizeof(xen_compile_info_t);
		break;
	case XENVER_capabilities:
		argsize = sizeof(xen_capabilities_info_t);
		break;
	case XENVER_changeset:
		argsize = sizeof(xen_changeset_info_t);
		break;
	case XENVER_platform_parameters:
		argsize = sizeof(xen_platform_parameters_t);
		break;
	case XENVER_pagesize:
		argsize = (arg == NULL) ? 0 : sizeof(void *);
		break;
	case XENVER_get_features:
		argsize = (arg == NULL) ? 0 : sizeof(xen_feature_info_t);
		break;

	default:
		printk("%s: unknown version op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	rc = xencomm_create(arg, argsize, &desc, GFP_KERNEL);
	if (rc)
		return rc;

	rc = xencomm_arch_hypercall_xen_version(cmd, desc);

	xencomm_free(desc);

	return rc;
}

static int
xencomm_privcmd_event_channel_op(privcmd_hypercall_t *hypercall)
{
	int cmd = hypercall->arg[0];
	struct xencomm_handle *desc;
	unsigned int argsize;
	int ret;

	switch (cmd) {
	case EVTCHNOP_alloc_unbound:
		argsize = sizeof(evtchn_alloc_unbound_t);
		break;

	case EVTCHNOP_status:
		argsize = sizeof(evtchn_status_t);
		break;

	default:
		printk("%s: unknown EVTCHNOP %d\n", __func__, cmd);
		return -EINVAL;
	}

	ret = xencomm_create((void *)hypercall->arg[1], argsize,
	                     &desc, GFP_KERNEL);
	if (ret)
		return ret;

	ret = xencomm_arch_hypercall_event_channel_op(cmd, desc);

	xencomm_free(desc);
	return ret;
}

static int
xencomm_privcmd_hvm_op(privcmd_hypercall_t *hypercall)
{
	int cmd = hypercall->arg[0];
	struct xencomm_handle *desc;
	unsigned int argsize;
	int ret;

	switch (cmd) {
	case HVMOP_get_param:
	case HVMOP_set_param:
		argsize = sizeof(xen_hvm_param_t);
		break;
	case HVMOP_set_pci_intx_level:
		argsize = sizeof(xen_hvm_set_pci_intx_level_t);
		break;
	case HVMOP_set_isa_irq_level:
		argsize = sizeof(xen_hvm_set_isa_irq_level_t);
		break;
	case HVMOP_set_pci_link_route:
		argsize = sizeof(xen_hvm_set_pci_link_route_t);
		break;

	default:
		printk("%s: unknown HVMOP %d\n", __func__, cmd);
		return -EINVAL;
	}

	ret = xencomm_create((void *)hypercall->arg[1], argsize,
	                     &desc, GFP_KERNEL);
	if (ret)
		return ret;

	ret = xencomm_arch_hypercall_hvm_op(cmd, desc);

	xencomm_free(desc);
	return ret;
}

static int
xencomm_privcmd_sched_op(privcmd_hypercall_t *hypercall)
{
	int cmd = hypercall->arg[0];
	struct xencomm_handle *desc;
	unsigned int argsize;
	int ret;

	switch (cmd) {
	case SCHEDOP_remote_shutdown:
		argsize = sizeof(sched_remote_shutdown_t);
		break;
	default:
		printk("%s: unknown SCHEDOP %d\n", __func__, cmd);
		return -EINVAL;
	}

	ret = xencomm_create((void *)hypercall->arg[1], argsize,
	                     &desc, GFP_KERNEL);
	if (ret)
		return ret;

	ret = xencomm_arch_hypercall_sched_op(cmd, desc);

	xencomm_free(desc);
	return ret;
}

int
privcmd_hypercall(privcmd_hypercall_t *hypercall)
{
	switch (hypercall->op) {
	case __HYPERVISOR_dom0_op:
		return xencomm_privcmd_dom0_op(hypercall);
	case __HYPERVISOR_domctl:
		return xencomm_privcmd_domctl(hypercall);
	case __HYPERVISOR_sysctl:
		return xencomm_privcmd_sysctl(hypercall);
        case __HYPERVISOR_acm_op:
		return xencomm_privcmd_acm_op(hypercall);
	case __HYPERVISOR_xen_version:
		return xencomm_privcmd_xen_version(hypercall);
	case __HYPERVISOR_memory_op:
		return xencomm_privcmd_memory_op(hypercall);
	case __HYPERVISOR_event_channel_op:
		return xencomm_privcmd_event_channel_op(hypercall);
	case __HYPERVISOR_hvm_op:
		return xencomm_privcmd_hvm_op(hypercall);
	case __HYPERVISOR_sched_op:
		return xencomm_privcmd_sched_op(hypercall);
	default:
		printk("%s: unknown hcall (%ld)\n", __func__, hypercall->op);
		return -ENOSYS;
	}
}

