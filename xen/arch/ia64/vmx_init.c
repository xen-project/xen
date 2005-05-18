/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_init.c: initialization work for vt specific domain
 * Copyright (c) 2005, Intel Corporation.
 *	Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *	Xuefei Xu (Anthony Xu) <anthony.xu@intel.com>
 *	Fred Yang <fred.yang@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

/*
 * 05/03/23 Kun Tian (Kevin Tian) <kevin.tian@intel.com>:
 * Simplied design in first step:
 *	- One virtual environment
 *	- Domain is bound to one LP
 * Later to support guest SMP:
 *	- Need interface to handle VP scheduled to different LP
 */
#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/pal.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/vmx_vcpu.h>
#include <xen/lib.h>
#include <asm/vmmu.h>
#include <public/arch-ia64.h>
#include <asm/vmx_phy_mode.h>

/* Global flag to identify whether Intel vmx feature is on */
u32 vmx_enabled = 0;
static u32 vm_order;
static u64 buffer_size;
static u64 vp_env_info;
static u64 vm_buffer = 0;	/* Buffer required to bring up VMX feature */
u64 __vsa_base = 0;	/* Run-time service base of VMX */

/* Check whether vt feature is enabled or not. */
void
identify_vmx_feature(void)
{
	pal_status_t ret;
	u64 avail = 1, status = 1, control = 1;

	vmx_enabled = 0;
	/* Check VT-i feature */
	ret = ia64_pal_proc_get_features(&avail, &status, &control);
	if (ret != PAL_STATUS_SUCCESS) {
		printk("Get proc features failed.\n");
		goto no_vti;
	}

	/* FIXME: do we need to check status field, to see whether
	 * PSR.vm is actually enabled? If yes, aonther call to
	 * ia64_pal_proc_set_features may be reuqired then.
	 */
	printk("avail:0x%lx, status:0x%lx,control:0x%lx, vm?0x%lx\n",
		avail, status, control, avail & PAL_PROC_VM_BIT);
	if (!(avail & PAL_PROC_VM_BIT)) {
		printk("No VT feature supported.\n");
		goto no_vti;
	}

	ret = ia64_pal_vp_env_info(&buffer_size, &vp_env_info);
	if (ret != PAL_STATUS_SUCCESS) {
		printk("Get vp environment info failed.\n");
		goto no_vti;
	}

	/* Does xen has ability to decode itself? */
	if (!(vp_env_info & VP_OPCODE))
		printk("WARNING: no opcode provided from hardware(%lx)!!!\n", vp_env_info);
	vm_order = get_order(buffer_size);
	printk("vm buffer size: %d, order: %d\n", buffer_size, vm_order);

	vmx_enabled = 1;
no_vti:
	return;
}

/*
 * Init virtual environment on current LP
 * vsa_base is the indicator whether it's first LP to be initialized
 * for current domain.
 */ 
void
vmx_init_env(void)
{
	u64 status, tmp_base;

	if (!vm_buffer) {
		vm_buffer = alloc_xenheap_pages(vm_order);
		ASSERT(vm_buffer);
		printk("vm_buffer: 0x%lx\n", vm_buffer);
	}

	status=ia64_pal_vp_init_env(__vsa_base ? VP_INIT_ENV : VP_INIT_ENV_INITALIZE,
				    __pa(vm_buffer),
				    vm_buffer,
				    &tmp_base);

	if (status != PAL_STATUS_SUCCESS) {
		printk("ia64_pal_vp_init_env failed.\n");
		return -1;
	}

	if (!__vsa_base)
		__vsa_base = tmp_base;
	else
		ASSERT(tmp_base != __vsa_base);
}

typedef union {
	u64 value;
	struct {
		u64 number : 8;
		u64 revision : 8;
		u64 model : 8;
		u64 family : 8;
		u64 archrev : 8;
		u64 rv : 24;
	};
} cpuid3_t;

/* Allocate vpd from xenheap */
static vpd_t *alloc_vpd(void)
{
	int i;
	cpuid3_t cpuid3;
	vpd_t *vpd;

	vpd = alloc_xenheap_pages(get_order(VPD_SIZE));
	if (!vpd) {
		printk("VPD allocation failed.\n");
		return NULL;
	}

	printk("vpd base: 0x%lx, vpd size:%d\n", vpd, sizeof(vpd_t));
	memset(vpd, 0, VPD_SIZE);
	/* CPUID init */
	for (i = 0; i < 5; i++)
		vpd->vcpuid[i] = ia64_get_cpuid(i);

	/* Limit the CPUID number to 5 */
	cpuid3.value = vpd->vcpuid[3];
	cpuid3.number = 4;	/* 5 - 1 */
	vpd->vcpuid[3] = cpuid3.value;

	vpd->vdc.d_vmsw = 1;
	return vpd;
}



/*
 * Create a VP on intialized VMX environment.
 */
static void
vmx_create_vp(struct exec_domain *ed)
{
	u64 ret;
	vpd_t *vpd = ed->arch.arch_vmx.vpd;
	u64 ivt_base;
    extern char vmx_ia64_ivt;
	/* ia64_ivt is function pointer, so need this tranlation */
	ivt_base = (u64) &vmx_ia64_ivt;
	printk("ivt_base: 0x%lx\n", ivt_base);
	ret = ia64_pal_vp_create(vpd, ivt_base, 0);
	if (ret != PAL_STATUS_SUCCESS)
		panic("ia64_pal_vp_create failed. \n");
}

/* Other non-context related tasks can be done in context switch */
void
vmx_save_state(struct exec_domain *ed)
{
	u64 status, psr;
	u64 old_rr0, dom_rr7, rr0_xen_start, rr0_vhpt;

	/* FIXME: about setting of pal_proc_vector... time consuming */
	status = ia64_pal_vp_save(ed->arch.arch_vmx.vpd, 0);
	if (status != PAL_STATUS_SUCCESS)
		panic("Save vp status failed\n");

	/* FIXME: Do we really need purge double mapping for old ed?
	 * Since rid is completely different between prev and next,
	 * it's not overlap and thus no MCA possible... */
	dom_rr7 = vmx_vrrtomrr(ed, VMX(ed, vrr[7]));
        vmx_purge_double_mapping(dom_rr7, KERNEL_START,
				 (u64)ed->arch.vtlb->ts->vhpt->hash);

}

/* Even guest is in physical mode, we still need such double mapping */
void
vmx_load_state(struct exec_domain *ed)
{
	u64 status, psr;
	u64 old_rr0, dom_rr7, rr0_xen_start, rr0_vhpt;
	u64 pte_xen, pte_vhpt;

	status = ia64_pal_vp_restore(ed->arch.arch_vmx.vpd, 0);
	if (status != PAL_STATUS_SUCCESS)
		panic("Restore vp status failed\n");

	dom_rr7 = vmx_vrrtomrr(ed, VMX(ed, vrr[7]));
	pte_xen = pte_val(pfn_pte((xen_pstart >> PAGE_SHIFT), PAGE_KERNEL));
	pte_vhpt = pte_val(pfn_pte((__pa(ed->arch.vtlb->ts->vhpt->hash) >> PAGE_SHIFT), PAGE_KERNEL));
	vmx_insert_double_mapping(dom_rr7, KERNEL_START,
				  (u64)ed->arch.vtlb->ts->vhpt->hash,
				  pte_xen, pte_vhpt);

	/* Guest vTLB is not required to be switched explicitly, since
	 * anchored in exec_domain */
}

/* Purge old double mapping and insert new one, due to rr7 change */
void
vmx_change_double_mapping(struct exec_domain *ed, u64 oldrr7, u64 newrr7)
{
	u64 pte_xen, pte_vhpt, vhpt_base;

    vhpt_base = (u64)ed->arch.vtlb->ts->vhpt->hash;
    vmx_purge_double_mapping(oldrr7, KERNEL_START,
				 vhpt_base);

	pte_xen = pte_val(pfn_pte((xen_pstart >> PAGE_SHIFT), PAGE_KERNEL));
	pte_vhpt = pte_val(pfn_pte((__pa(vhpt_base) >> PAGE_SHIFT), PAGE_KERNEL));
	vmx_insert_double_mapping(newrr7, KERNEL_START,
				  vhpt_base,
				  pte_xen, pte_vhpt);
}

/*
 * Initialize VMX envirenment for guest. Only the 1st vp/exec_domain
 * is registered here.
 */
void
vmx_final_setup_domain(struct domain *d)
{
	struct exec_domain *ed = d->exec_domain[0];
	vpd_t *vpd;

	/* Allocate resources for exec_domain 0 */
	//memset(&ed->arch.arch_vmx, 0, sizeof(struct arch_vmx_struct));

	vpd = alloc_vpd();
	ASSERT(vpd);

	ed->arch.arch_vmx.vpd = vpd;
	vpd->virt_env_vaddr = vm_buffer;

	/* ed->arch.schedule_tail = arch_vmx_do_launch; */
	vmx_create_vp(ed);

	/* Set this ed to be vmx */
	ed->arch.arch_vmx.flags = 1;

	/* Other vmx specific initialization work */
}

