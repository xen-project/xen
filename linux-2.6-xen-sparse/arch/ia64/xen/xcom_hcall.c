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
 *          Tristan Gingold <tristan.gingold@bull.net>
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <xen/interface/xen.h>
#include <xen/interface/dom0_ops.h>
#include <xen/interface/memory.h>
#include <xen/interface/xencomm.h>
#include <xen/interface/version.h>
#include <xen/interface/sched.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/callback.h>
#include <xen/interface/acm_ops.h>
#include <xen/interface/hvm/params.h>
#include <xen/interface/xenoprof.h>
#include <xen/interface/vcpu.h>
#include <asm/hypercall.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <asm/xen/xencomm.h>
#include <asm/perfmon.h>

/* Xencomm notes:
 * This file defines hypercalls to be used by xencomm.  The hypercalls simply
 * create inlines descriptors for pointers and then call the raw arch hypercall
 * xencomm_arch_hypercall_XXX
 *
 * If the arch wants to directly use these hypercalls, simply define macros
 * in asm/hypercall.h, eg:
 *  #define HYPERVISOR_sched_op xencomm_hypercall_sched_op
 * 
 * The arch may also define HYPERVISOR_xxx as a function and do more operations
 * before/after doing the hypercall.
 *
 * Note: because only inline descriptors are created these functions must only
 * be called with in kernel memory parameters.
 */

int
xencomm_hypercall_console_io(int cmd, int count, char *str)
{
	return xencomm_arch_hypercall_console_io
		(cmd, count, xencomm_create_inline(str));
}

int
xencomm_hypercall_event_channel_op(int cmd, void *op)
{
	return xencomm_arch_hypercall_event_channel_op
		(cmd, xencomm_create_inline(op));
}

int
xencomm_hypercall_xen_version(int cmd, void *arg)
{
	switch (cmd) {
	case XENVER_version:
	case XENVER_extraversion:
	case XENVER_compile_info:
	case XENVER_capabilities:
	case XENVER_changeset:
	case XENVER_platform_parameters:
	case XENVER_pagesize:
	case XENVER_get_features:
		break;
	default:
		printk("%s: unknown version cmd %d\n", __func__, cmd);
		return -ENOSYS;
	}

	return xencomm_arch_hypercall_xen_version
		(cmd, xencomm_create_inline(arg));
}

int
xencomm_hypercall_physdev_op(int cmd, void *op)
{
	return xencomm_arch_hypercall_physdev_op
		(cmd, xencomm_create_inline(op));
}

static void *
xencommize_grant_table_op(unsigned int cmd, void *op, unsigned int count)
{
	switch (cmd) {
	case GNTTABOP_map_grant_ref:
	case GNTTABOP_unmap_grant_ref:
		break;
	case GNTTABOP_setup_table:
	{
		struct gnttab_setup_table *setup = op;
		struct xencomm_handle *frame_list;

		frame_list = xencomm_create_inline
			(xen_guest_handle(setup->frame_list));

		set_xen_guest_handle(setup->frame_list, (void *)frame_list);
		break;
	}
	case GNTTABOP_dump_table:
	case GNTTABOP_transfer:
	case GNTTABOP_copy:
		break;
	default:
		printk("%s: unknown grant table op %d\n", __func__, cmd);
		BUG();
	}

	return  xencomm_create_inline(op);
}

int
xencomm_hypercall_grant_table_op(unsigned int cmd, void *op, unsigned int count)
{
	void *desc = xencommize_grant_table_op (cmd, op, count);

	return xencomm_arch_hypercall_grant_table_op(cmd, desc, count);
}

int
xencomm_hypercall_sched_op(int cmd, void *arg)
{
	switch (cmd) {
	case SCHEDOP_yield:
	case SCHEDOP_block:
	case SCHEDOP_shutdown:
	case SCHEDOP_remote_shutdown:
		break;
	case SCHEDOP_poll:
	{
		sched_poll_t *poll = arg;
		struct xencomm_handle *ports;

		ports = xencomm_create_inline(xen_guest_handle(poll->ports));

		set_xen_guest_handle(poll->ports, (void *)ports);
		break;
	}
	default:
		printk("%s: unknown sched op %d\n", __func__, cmd);
		return -ENOSYS;
	}
	
	return xencomm_arch_hypercall_sched_op(cmd, xencomm_create_inline(arg));
}

int
xencomm_hypercall_multicall(void *call_list, int nr_calls)
{
	int i;
	multicall_entry_t *mce;

	for (i = 0; i < nr_calls; i++) {
		mce = (multicall_entry_t *)call_list + i;

		switch (mce->op) {
		case __HYPERVISOR_update_va_mapping:
		case __HYPERVISOR_mmu_update:
			/* No-op on ia64.  */
			break;
		case __HYPERVISOR_grant_table_op:
			mce->args[1] = (unsigned long)xencommize_grant_table_op
				(mce->args[0], (void *)mce->args[1],
				 mce->args[2]);
			break;
		case __HYPERVISOR_memory_op:
		default:
			printk("%s: unhandled multicall op entry op %lu\n",
			       __func__, mce->op);
			return -ENOSYS;
		}
	}

	return xencomm_arch_hypercall_multicall
		(xencomm_create_inline(call_list), nr_calls);
}

int
xencomm_hypercall_callback_op(int cmd, void *arg)
{
	switch (cmd)
	{
	case CALLBACKOP_register:
	case CALLBACKOP_unregister:
		break;
	default:
		printk("%s: unknown callback op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	return xencomm_arch_hypercall_callback_op
		(cmd, xencomm_create_inline(arg));
}

static void
xencommize_memory_reservation (xen_memory_reservation_t *mop)
{
	struct xencomm_handle *desc;

	desc = xencomm_create_inline(xen_guest_handle(mop->extent_start));
	set_xen_guest_handle(mop->extent_start, (void *)desc);
}

int
xencomm_hypercall_memory_op(unsigned int cmd, void *arg)
{
	XEN_GUEST_HANDLE(xen_pfn_t) extent_start_va[2];
	xen_memory_reservation_t *xmr = NULL, *xme_in = NULL, *xme_out = NULL;
	int rc;

	switch (cmd) {
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_populate_physmap:
		xmr = (xen_memory_reservation_t *)arg;
		xen_guest_handle(extent_start_va[0]) =
			xen_guest_handle(xmr->extent_start);
		xencommize_memory_reservation((xen_memory_reservation_t *)arg);
		break;
		
	case XENMEM_maximum_ram_page:
		break;

	case XENMEM_exchange:
		xme_in  = &((xen_memory_exchange_t *)arg)->in;
		xme_out = &((xen_memory_exchange_t *)arg)->out;
		xen_guest_handle(extent_start_va[0]) =
			xen_guest_handle(xme_in->extent_start);
		xen_guest_handle(extent_start_va[1]) =
			xen_guest_handle(xme_out->extent_start);
		xencommize_memory_reservation
			(&((xen_memory_exchange_t *)arg)->in);
		xencommize_memory_reservation
			(&((xen_memory_exchange_t *)arg)->out);
		break;

	default:
		printk("%s: unknown memory op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	rc =  xencomm_arch_hypercall_memory_op(cmd, xencomm_create_inline(arg));

	switch (cmd) {
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_populate_physmap:
		xen_guest_handle(xmr->extent_start) =
			xen_guest_handle(extent_start_va[0]);
		break;

	case XENMEM_exchange:
		xen_guest_handle(xme_in->extent_start) =
			xen_guest_handle(extent_start_va[0]);
		xen_guest_handle(xme_out->extent_start) =
			xen_guest_handle(extent_start_va[1]);
		break;
	}

	return rc;
}

unsigned long
xencomm_hypercall_hvm_op(int cmd, void *arg)
{
	switch (cmd) {
	case HVMOP_set_param:
	case HVMOP_get_param:
		break;
	default:
		printk("%s: unknown hvm op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	return xencomm_arch_hypercall_hvm_op(cmd, xencomm_create_inline(arg));
}

int
xencomm_hypercall_suspend(unsigned long srec)
{
	struct sched_shutdown arg;

	arg.reason = SHUTDOWN_suspend;

	return xencomm_arch_hypercall_suspend(xencomm_create_inline(&arg));
}

int
xencomm_hypercall_xenoprof_op(int op, void *arg)
{
	switch (op) {
	case XENOPROF_init:
	case XENOPROF_set_active:
	case XENOPROF_set_passive:
	case XENOPROF_counter:
	case XENOPROF_get_buffer:
		break;

	case XENOPROF_reset_active_list:
	case XENOPROF_reset_passive_list:
	case XENOPROF_reserve_counters:
	case XENOPROF_setup_events:
	case XENOPROF_enable_virq:
	case XENOPROF_start:
	case XENOPROF_stop:
	case XENOPROF_disable_virq:
	case XENOPROF_release_counters:
	case XENOPROF_shutdown:
		return xencomm_arch_hypercall_xenoprof_op(op, arg);
		break;

	default:
		printk("%s: op %d isn't supported\n", __func__, op);
		return -ENOSYS;
	}
	return xencomm_arch_hypercall_xenoprof_op(op,
						  xencomm_create_inline(arg));
}

int
xencomm_hypercall_perfmon_op(unsigned long cmd, void* arg, unsigned long count)
{
	switch (cmd) {
	case PFM_GET_FEATURES:
	case PFM_CREATE_CONTEXT:
	case PFM_WRITE_PMCS:
	case PFM_WRITE_PMDS:
	case PFM_LOAD_CONTEXT:
		break;

	case PFM_DESTROY_CONTEXT:
	case PFM_UNLOAD_CONTEXT:
	case PFM_START:
	case PFM_STOP:
		return xencomm_arch_hypercall_perfmon_op(cmd, arg, count);

	default:
		printk("%s:%d cmd %ld isn't supported\n",
		       __func__,__LINE__, cmd);
		BUG();
	}

	return xencomm_arch_hypercall_perfmon_op(cmd,
	                                         xencomm_create_inline(arg),
	                                         count);
}

long
xencomm_hypercall_vcpu_op(int cmd, int cpu, void *arg)
{
	switch (cmd) {
	case VCPUOP_register_runstate_memory_area:
		xencommize_memory_reservation((xen_memory_reservation_t *)arg);
		break;

	default:
		printk("%s: unknown vcpu op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	return xencomm_arch_hypercall_vcpu_op(cmd, cpu,
					      xencomm_create_inline(arg));
}
