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
 * 05/08/16 Kun tian (Kevin Tian) <kevin.tian@intel.com>:
 * Disable doubling mapping
 *
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
#include <public/xen.h>
#include <public/hvm/ioreq.h>
#include <public/event_channel.h>
#include <asm/vmx_phy_mode.h>
#include <asm/processor.h>
#include <asm/vmx.h>
#include <xen/mm.h>
#include <asm/viosapic.h>
#include <xen/event.h>
#include <asm/vlsapic.h>

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
	printk("vm buffer size: %ld, order: %d\n", buffer_size, vm_order);

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
		vm_buffer = (unsigned long)alloc_xenheap_pages(vm_order);
		ASSERT(vm_buffer);
		printk("vm_buffer: 0x%lx\n", vm_buffer);
	}

	status=ia64_pal_vp_init_env(__vsa_base ? VP_INIT_ENV : VP_INIT_ENV_INITALIZE,
				    __pa(vm_buffer),
				    vm_buffer,
				    &tmp_base);

	if (status != PAL_STATUS_SUCCESS) {
		printk("ia64_pal_vp_init_env failed.\n");
		return ;
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
	mapped_regs_t *mregs;

	vpd = alloc_xenheap_pages(get_order(VPD_SIZE));
	if (!vpd) {
		printk("VPD allocation failed.\n");
		return NULL;
	}

	printk(XENLOG_DEBUG "vpd base: 0x%p, vpd size:%ld\n",
	       vpd, sizeof(vpd_t));
	memset(vpd, 0, VPD_SIZE);
	mregs = &vpd->vpd_low;

	/* CPUID init */
	for (i = 0; i < 5; i++)
		mregs->vcpuid[i] = ia64_get_cpuid(i);

	/* Limit the CPUID number to 5 */
	cpuid3.value = mregs->vcpuid[3];
	cpuid3.number = 4;	/* 5 - 1 */
	mregs->vcpuid[3] = cpuid3.value;

	mregs->vac.a_from_int_cr = 1;
	mregs->vac.a_to_int_cr = 1;
	mregs->vac.a_from_psr = 1;
	mregs->vac.a_from_cpuid = 1;
	mregs->vac.a_cover = 1;
	mregs->vac.a_bsw = 1;
	mregs->vac.a_int = 1;
	mregs->vdc.d_vmsw = 1;

	return vpd;
}

/* Free vpd to xenheap */
static void
free_vpd(struct vcpu *v)
{
	if ( v->arch.privregs )
		free_xenheap_pages(v->arch.privregs, get_order(VPD_SIZE));
}

/*
 * Create a VP on intialized VMX environment.
 */
static void
vmx_create_vp(struct vcpu *v)
{
	u64 ret;
	vpd_t *vpd = (vpd_t *)v->arch.privregs;
	u64 ivt_base;
	extern char vmx_ia64_ivt;
	/* ia64_ivt is function pointer, so need this tranlation */
	ivt_base = (u64) &vmx_ia64_ivt;
	printk(XENLOG_DEBUG "ivt_base: 0x%lx\n", ivt_base);
	ret = ia64_pal_vp_create((u64 *)vpd, (u64 *)ivt_base, 0);
	if (ret != PAL_STATUS_SUCCESS){
		panic_domain(vcpu_regs(v),"ia64_pal_vp_create failed. \n");
	}
}

/* Other non-context related tasks can be done in context switch */
void
vmx_save_state(struct vcpu *v)
{
	u64 status;

	/* FIXME: about setting of pal_proc_vector... time consuming */
	status = ia64_pal_vp_save((u64 *)v->arch.privregs, 0);
	if (status != PAL_STATUS_SUCCESS){
		panic_domain(vcpu_regs(v),"Save vp status failed\n");
	}


	/* Need to save KR when domain switch, though HV itself doesn;t
	 * use them.
	 */
	v->arch.arch_vmx.vkr[0] = ia64_get_kr(0);
	v->arch.arch_vmx.vkr[1] = ia64_get_kr(1);
	v->arch.arch_vmx.vkr[2] = ia64_get_kr(2);
	v->arch.arch_vmx.vkr[3] = ia64_get_kr(3);
	v->arch.arch_vmx.vkr[4] = ia64_get_kr(4);
	v->arch.arch_vmx.vkr[5] = ia64_get_kr(5);
	v->arch.arch_vmx.vkr[6] = ia64_get_kr(6);
	v->arch.arch_vmx.vkr[7] = ia64_get_kr(7);
}

/* Even guest is in physical mode, we still need such double mapping */
void
vmx_load_state(struct vcpu *v)
{
	u64 status;

	status = ia64_pal_vp_restore((u64 *)v->arch.privregs, 0);
	if (status != PAL_STATUS_SUCCESS){
		panic_domain(vcpu_regs(v),"Restore vp status failed\n");
	}

	ia64_set_kr(0, v->arch.arch_vmx.vkr[0]);
	ia64_set_kr(1, v->arch.arch_vmx.vkr[1]);
	ia64_set_kr(2, v->arch.arch_vmx.vkr[2]);
	ia64_set_kr(3, v->arch.arch_vmx.vkr[3]);
	ia64_set_kr(4, v->arch.arch_vmx.vkr[4]);
	ia64_set_kr(5, v->arch.arch_vmx.vkr[5]);
	ia64_set_kr(6, v->arch.arch_vmx.vkr[6]);
	ia64_set_kr(7, v->arch.arch_vmx.vkr[7]);
	/* Guest vTLB is not required to be switched explicitly, since
	 * anchored in vcpu */
}

static void vmx_create_event_channels(struct vcpu *v)
{
	vcpu_iodata_t *p;
	struct vcpu *o;

	if (v->vcpu_id == 0) {
		/* Ugly: create event channels for every vcpu when vcpu 0
		   starts, so that they're available for ioemu to bind to. */
		for_each_vcpu(v->domain, o) {
			p = get_vio(v->domain, o->vcpu_id);
			o->arch.arch_vmx.xen_port = p->vp_eport =
					alloc_unbound_xen_event_channel(o, 0);
			gdprintk(XENLOG_INFO, "Allocated port %ld for hvm.\n",
			         o->arch.arch_vmx.xen_port);
		}
	}
}

static void vmx_release_assist_channel(struct vcpu *v)
{
	free_xen_event_channel(v, v->arch.arch_vmx.xen_port);
}

/*
 * Initialize VMX envirenment for guest. Only the 1st vp/vcpu
 * is registered here.
 */
int
vmx_final_setup_guest(struct vcpu *v)
{
	vpd_t *vpd;
	int rc;

	vpd = alloc_vpd();
	ASSERT(vpd);

	v->arch.privregs = (mapped_regs_t *)vpd;
	vpd->vpd_low.virt_env_vaddr = vm_buffer;

	/* Per-domain vTLB and vhpt implementation. Now vmx domain will stick
	 * to this solution. Maybe it can be deferred until we know created
	 * one as vmx domain */
#ifndef HASH_VHPT
	rc = init_domain_tlb(v);
	if (rc)
		return rc;
#endif
	vmx_create_event_channels(v);

	/* v->arch.schedule_tail = arch_vmx_do_launch; */
	vmx_create_vp(v);

	/* Physical mode emulation initialization, including
	* emulation ID allcation and related memory request
	*/
	physical_mode_init(v);

	vlsapic_reset(v);
	vtm_init(v);

	/* Set up guest 's indicator for VTi domain*/
	set_bit(ARCH_VMX_DOMAIN, &v->arch.arch_vmx.flags);

	return 0;
}

void
vmx_relinquish_guest_resources(struct domain *d)
{
	struct vcpu *v;

	for_each_vcpu(d, v)
		vmx_release_assist_channel(v);
}

void
vmx_relinquish_vcpu_resources(struct vcpu *v)
{
	vtime_t *vtm = &(v->arch.arch_vmx.vtm);

	kill_timer(&vtm->vtm_timer);

	free_domain_tlb(v);
	free_vpd(v);
}

typedef struct io_range {
	unsigned long start;
	unsigned long size;
	unsigned long type;
} io_range_t;

static const io_range_t io_ranges[] = {
	{VGA_IO_START, VGA_IO_SIZE, GPFN_FRAME_BUFFER},
	{MMIO_START, MMIO_SIZE, GPFN_LOW_MMIO},
	{LEGACY_IO_START, LEGACY_IO_SIZE, GPFN_LEGACY_IO},
	{IO_SAPIC_START, IO_SAPIC_SIZE, GPFN_IOSAPIC},
	{PIB_START, PIB_SIZE, GPFN_PIB},
};

// The P2M table is built in libxc/ia64/xc_ia64_hvm_build.c @ setup_guest()
// so only mark IO memory space here
static void vmx_build_io_physmap_table(struct domain *d)
{
	unsigned long i, j;

	/* Mark I/O ranges */
	for (i = 0; i < (sizeof(io_ranges) / sizeof(io_range_t)); i++) {
		for (j = io_ranges[i].start;
		     j < io_ranges[i].start + io_ranges[i].size; j += PAGE_SIZE)
			(void)__assign_domain_page(d, j, io_ranges[i].type,
			                           ASSIGN_writable);
	}

}

void vmx_setup_platform(struct domain *d)
{
	ASSERT(d != dom0); /* only for non-privileged vti domain */

	vmx_build_io_physmap_table(d);

	d->arch.vmx_platform.shared_page_va =
		(unsigned long)__va(__gpa_to_mpa(d, IO_PAGE_START));
	/* For buffered IO requests. */
	spin_lock_init(&d->arch.hvm_domain.buffered_io_lock);
	d->arch.hvm_domain.buffered_io_va =
		(unsigned long)__va(__gpa_to_mpa(d, BUFFER_IO_PAGE_START));
	d->arch.hvm_domain.buffered_pio_va =
		(unsigned long)__va(__gpa_to_mpa(d, BUFFER_PIO_PAGE_START));
	/* TEMP */
	d->arch.vmx_platform.pib_base = 0xfee00000UL;

	d->arch.sal_data = xmalloc(struct xen_sal_data);

	/* Only open one port for I/O and interrupt emulation */
	memset(&d->shared_info->evtchn_mask[0], 0xff,
	       sizeof(d->shared_info->evtchn_mask));

	/* Initialize iosapic model within hypervisor */
	viosapic_init(d);
}

void vmx_do_launch(struct vcpu *v)
{
	vmx_load_all_rr(v);
}
