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
#include <linux/module.h>
#include <xen/interface/xen.h>
#include <xen/interface/platform.h>
#include <xen/interface/memory.h>
#include <xen/interface/xencomm.h>
#include <xen/interface/version.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/hvm/params.h>
#include <xen/interface/xenoprof.h>
#ifdef CONFIG_VMX_GUEST
#include <asm/hypervisor.h>
#else
#include <asm/hypercall.h>
#endif
#include <asm/xen/xencomm.h>
#include <asm/perfmon.h>

int
xencomm_mini_hypercall_event_channel_op(int cmd, void *op)
{
	struct xencomm_mini xc_area[2];
	int nbr_area = 2;
	struct xencomm_handle *desc;
	int rc;

	rc = xencomm_create_mini(xc_area, &nbr_area,
	                         op, sizeof(evtchn_op_t), &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_event_channel_op(cmd, desc);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_event_channel_op);

static int
xencommize_mini_grant_table_op(struct xencomm_mini *xc_area, int *nbr_area,
                               unsigned int cmd, void *op, unsigned int count,
                               struct xencomm_handle **desc)
{
	struct xencomm_handle *desc1;
	unsigned int argsize;
	int rc;

	switch (cmd) {
	case GNTTABOP_map_grant_ref:
		argsize = sizeof(struct gnttab_map_grant_ref);
		break;
	case GNTTABOP_unmap_grant_ref:
		argsize = sizeof(struct gnttab_unmap_grant_ref);
		break;
	case GNTTABOP_setup_table:
	{
		struct gnttab_setup_table *setup = op;

		argsize = sizeof(*setup);

		if (count != 1)
			return -EINVAL;
		rc = xencomm_create_mini
			(xc_area, nbr_area,
			 xen_guest_handle(setup->frame_list),
			 setup->nr_frames 
			 * sizeof(*xen_guest_handle(setup->frame_list)),
			 &desc1);
		if (rc)
			return rc;
		set_xen_guest_handle(setup->frame_list, (void *)desc1);
		break;
	}
	case GNTTABOP_dump_table:
		argsize = sizeof(struct gnttab_dump_table);
		break;
	case GNTTABOP_transfer:
		argsize = sizeof(struct gnttab_transfer);
		break;
	case GNTTABOP_copy:
		argsize = sizeof(struct gnttab_copy);
		break;
	case GNTTABOP_query_size:
		argsize = sizeof(struct gnttab_query_size);
		break;
	default:
		printk("%s: unknown mini grant table op %d\n", __func__, cmd);
		BUG();
	}

	rc = xencomm_create_mini(xc_area, nbr_area, op, count * argsize, desc);
	if (rc)
		return rc;

	return 0;
}

int
xencomm_mini_hypercall_grant_table_op(unsigned int cmd, void *op,
                                      unsigned int count)
{
	int rc;
	struct xencomm_handle *desc;
	int nbr_area = 2;
	struct xencomm_mini xc_area[2];

	rc = xencommize_mini_grant_table_op(xc_area, &nbr_area,
	                                    cmd, op, count, &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_grant_table_op(cmd, desc, count);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_grant_table_op);

int
xencomm_mini_hypercall_multicall(void *call_list, int nr_calls)
{
	int i;
	multicall_entry_t *mce;
	int nbr_area = 2 + nr_calls * 3;
	struct xencomm_mini xc_area[nbr_area];
	struct xencomm_handle *desc;
	int rc;

	for (i = 0; i < nr_calls; i++) {
		mce = (multicall_entry_t *)call_list + i;

		switch (mce->op) {
		case __HYPERVISOR_update_va_mapping:
		case __HYPERVISOR_mmu_update:
			/* No-op on ia64.  */
			break;
		case __HYPERVISOR_grant_table_op:
			rc = xencommize_mini_grant_table_op
				(xc_area, &nbr_area,
				 mce->args[0], (void *)mce->args[1],
				 mce->args[2], &desc);
			if (rc)
				return rc;
			mce->args[1] = (unsigned long)desc;
			break;
		case __HYPERVISOR_memory_op:
		default:
			printk("%s: unhandled multicall op entry op %lu\n",
			       __func__, mce->op);
			return -ENOSYS;
		}
	}

	rc = xencomm_create_mini(xc_area, &nbr_area, call_list,
	                         nr_calls * sizeof(multicall_entry_t), &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_multicall(desc, nr_calls);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_multicall);

static int
xencommize_mini_memory_reservation(struct xencomm_mini *area, int *nbr_area,
                                   xen_memory_reservation_t *mop)
{
	struct xencomm_handle *desc;
	int rc;

	rc = xencomm_create_mini
		(area, nbr_area,
		 xen_guest_handle(mop->extent_start),
		 mop->nr_extents 
		 * sizeof(*xen_guest_handle(mop->extent_start)),
		 &desc);
	if (rc)
		return rc;

	set_xen_guest_handle(mop->extent_start, (void *)desc);

	return 0;
}

int
xencomm_mini_hypercall_memory_op(unsigned int cmd, void *arg)
{
	int nbr_area = 4;
	struct xencomm_mini xc_area[4];
	struct xencomm_handle *desc;
	int rc;
	unsigned int argsize;

	switch (cmd) {
	case XENMEM_increase_reservation:
	case XENMEM_decrease_reservation:
	case XENMEM_populate_physmap:
		argsize = sizeof(xen_memory_reservation_t);
		rc = xencommize_mini_memory_reservation
			(xc_area, &nbr_area, (xen_memory_reservation_t *)arg);
		if (rc)
			return rc;
		break;
		
	case XENMEM_maximum_ram_page:
		argsize = 0;
		break;

	case XENMEM_exchange:
		argsize = sizeof(xen_memory_exchange_t);
		rc = xencommize_mini_memory_reservation
			(xc_area, &nbr_area,
			 &((xen_memory_exchange_t *)arg)->in);
		if (rc)
			return rc;
		rc = xencommize_mini_memory_reservation
			(xc_area, &nbr_area,
			 &((xen_memory_exchange_t *)arg)->out);
		if (rc)
			return rc;
		break;

	case XENMEM_add_to_physmap:
		argsize = sizeof (xen_add_to_physmap_t);
		break;

	default:
		printk("%s: unknown mini memory op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_memory_op(cmd, desc);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_memory_op);

unsigned long
xencomm_mini_hypercall_hvm_op(int cmd, void *arg)
{
	struct xencomm_handle *desc;
	int nbr_area = 2;
	struct xencomm_mini xc_area[2];
	unsigned int argsize;
	int rc;

	switch (cmd) {
	case HVMOP_get_param:
	case HVMOP_set_param:
		argsize = sizeof(xen_hvm_param_t);
		break;
	default:
		printk("%s: unknown HVMOP %d\n", __func__, cmd);
		return -EINVAL;
	}

	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_hvm_op(cmd, desc);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_hvm_op);

int
xencomm_mini_hypercall_xen_version(int cmd, void *arg)
{
	struct xencomm_handle *desc;
	int nbr_area = 2;
	struct xencomm_mini xc_area[2];
	unsigned int argsize;
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

	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_xen_version(cmd, desc);
}
EXPORT_SYMBOL(xencomm_mini_hypercall_xen_version);

int
xencomm_mini_hypercall_xenoprof_op(int op, void *arg)
{
	unsigned int argsize;
	struct xencomm_mini xc_area[2];
	int nbr_area = 2;
	struct xencomm_handle *desc;
	int rc;

	switch (op) {
	case XENOPROF_init:
		argsize = sizeof(xenoprof_init_t);
		break;
	case XENOPROF_set_active:
		argsize = sizeof(domid_t);
		break;
	case XENOPROF_set_passive:
		argsize = sizeof(xenoprof_passive_t);
		break;
	case XENOPROF_counter:
		argsize = sizeof(xenoprof_counter_t);
		break;
	case XENOPROF_get_buffer:
		argsize = sizeof(xenoprof_get_buffer_t);
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

	default:
		printk("%s: op %d isn't supported\n", __func__, op);
		return -ENOSYS;
	}
	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;
	return xencomm_arch_hypercall_xenoprof_op(op, desc);
}
EXPORT_SYMBOL_GPL(xencomm_mini_hypercall_xenoprof_op);

int
xencomm_mini_hypercall_perfmon_op(unsigned long cmd, void* arg,
                                  unsigned long count)
{
	unsigned int argsize;
	struct xencomm_mini xc_area[2];
	int nbr_area = 2;
	struct xencomm_handle *desc;
	int rc;

	switch (cmd) {
	case PFM_GET_FEATURES:
		argsize = sizeof(pfarg_features_t);
		break;
	case PFM_CREATE_CONTEXT:
		argsize = sizeof(pfarg_context_t);
		break;
	case PFM_LOAD_CONTEXT:
		argsize = sizeof(pfarg_load_t);
		break;
	case PFM_WRITE_PMCS:
	case PFM_WRITE_PMDS:
		argsize = sizeof(pfarg_reg_t) * count;
		break;

	case PFM_DESTROY_CONTEXT:
	case PFM_UNLOAD_CONTEXT:
	case PFM_START:
	case PFM_STOP:
		return xencomm_arch_hypercall_perfmon_op(cmd, arg, count);

	default:
		printk("%s:%d cmd %ld isn't supported\n",
		       __func__, __LINE__, cmd);
		BUG();
	}

	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;
	return xencomm_arch_hypercall_perfmon_op(cmd, desc, count);
}
EXPORT_SYMBOL_GPL(xencomm_mini_hypercall_perfmon_op);

int
xencomm_mini_hypercall_sched_op(int cmd, void *arg)
{
	int rc, nbr_area = 2;
	struct xencomm_mini xc_area[2];
	struct xencomm_handle *desc;
	unsigned int argsize;

	switch (cmd) {
	case SCHEDOP_yield:
	case SCHEDOP_block:
		argsize = 0;
		break;
	case SCHEDOP_shutdown:
		argsize = sizeof(sched_shutdown_t);
		break;
	case SCHEDOP_poll:
		argsize = sizeof(sched_poll_t);
		break;
	case SCHEDOP_remote_shutdown:
		argsize = sizeof(sched_remote_shutdown_t);
		break;

	default:
		printk("%s: unknown sched op %d\n", __func__, cmd);
		return -ENOSYS;
	}

	rc = xencomm_create_mini(xc_area, &nbr_area, arg, argsize, &desc);
	if (rc)
		return rc;

	return xencomm_arch_hypercall_sched_op(cmd, desc);
}
EXPORT_SYMBOL_GPL(xencomm_mini_hypercall_sched_op);
