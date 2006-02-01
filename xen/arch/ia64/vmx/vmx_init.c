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
#include <public/arch-ia64.h>
#include <public/hvm/ioreq.h>
#include <asm/vmx_phy_mode.h>
#include <asm/processor.h>
#include <asm/vmx.h>
#include <xen/mm.h>
#include <public/arch-ia64.h>
#include <asm/hvm/vioapic.h>

/* Global flag to identify whether Intel vmx feature is on */
u32 vmx_enabled = 0;
unsigned int opt_vmx_debug_level = 0;
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
vmx_create_vp(struct vcpu *v)
{
	u64 ret;
	vpd_t *vpd = v->arch.privregs;
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
vmx_save_state(struct vcpu *v)
{
	u64 status, psr;
	u64 old_rr0, dom_rr7, rr0_xen_start, rr0_vhpt;

	/* FIXME: about setting of pal_proc_vector... time consuming */
	status = ia64_pal_vp_save(v->arch.privregs, 0);
	if (status != PAL_STATUS_SUCCESS)
		panic("Save vp status failed\n");


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
	u64 status, psr;
	u64 old_rr0, dom_rr7, rr0_xen_start, rr0_vhpt;
	u64 pte_xen, pte_vhpt;
	int i;

	status = ia64_pal_vp_restore(v->arch.privregs, 0);
	if (status != PAL_STATUS_SUCCESS)
		panic("Restore vp status failed\n");

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

/*
 * Initialize VMX envirenment for guest. Only the 1st vp/vcpu
 * is registered here.
 */
void
vmx_final_setup_guest(struct vcpu *v)
{
	vpd_t *vpd;

	/* Allocate resources for vcpu 0 */
	//memset(&v->arch.arch_vmx, 0, sizeof(struct arch_vmx_struct));

	vpd = alloc_vpd();
	ASSERT(vpd);

	v->arch.privregs = vpd;
	vpd->virt_env_vaddr = vm_buffer;

	/* Per-domain vTLB and vhpt implementation. Now vmx domain will stick
	 * to this solution. Maybe it can be deferred until we know created
	 * one as vmx domain */
	v->arch.vtlb = init_domain_tlb(v);

	/* v->arch.schedule_tail = arch_vmx_do_launch; */
	vmx_create_vp(v);

	/* Set this ed to be vmx */
	set_bit(ARCH_VMX_VMCS_LOADED, &v->arch.arch_vmx.flags);

	/* Physical mode emulation initialization, including
	* emulation ID allcation and related memory request
	*/
	physical_mode_init(v);

	vlsapic_reset(v);
	vtm_init(v);

	/* One more step to enable interrupt assist */
	set_bit(ARCH_VMX_INTR_ASSIST, &v->arch.arch_vmx.flags);
}

typedef struct io_range {
	unsigned long start;
	unsigned long size;
	unsigned long type;
} io_range_t;

io_range_t io_ranges[] = {
	{VGA_IO_START, VGA_IO_SIZE, GPFN_FRAME_BUFFER},
	{MMIO_START, MMIO_SIZE, GPFN_LOW_MMIO},
	{LEGACY_IO_START, LEGACY_IO_SIZE, GPFN_LEGACY_IO},
	{IO_SAPIC_START, IO_SAPIC_SIZE, GPFN_IOSAPIC},
	{PIB_START, PIB_SIZE, GPFN_PIB},
};

#define VMX_SYS_PAGES	(2 + (GFW_SIZE >> PAGE_SHIFT))
#define VMX_CONFIG_PAGES(d) ((d)->max_pages - VMX_SYS_PAGES)

int vmx_alloc_contig_pages(struct domain *d)
{
	unsigned int order;
	unsigned long i, j, start, end, pgnr, conf_nr;
	struct page_info *page;
	struct vcpu *v = d->vcpu[0];

	ASSERT(!test_bit(ARCH_VMX_CONTIG_MEM, &v->arch.arch_vmx.flags));

	/* Mark I/O ranges */
	for (i = 0; i < (sizeof(io_ranges) / sizeof(io_range_t)); i++) {
	    for (j = io_ranges[i].start;
		 j < io_ranges[i].start + io_ranges[i].size;
		 j += PAGE_SIZE)
		map_domain_page(d, j, io_ranges[i].type);
	}

	conf_nr = VMX_CONFIG_PAGES(d);
	order = get_order_from_pages(conf_nr);
	if (unlikely((page = alloc_domheap_pages(d, order, 0)) == NULL)) {
	    printk("Could not allocate order=%d pages for vmx contig alloc\n",
			order);
	    return -1;
	}

	/* Map normal memory below 3G */
	pgnr = page_to_mfn(page);
	end = conf_nr << PAGE_SHIFT;
	for (i = 0;
	     i < (end < MMIO_START ? end : MMIO_START);
	     i += PAGE_SIZE, pgnr++)
	    map_domain_page(d, i, pgnr << PAGE_SHIFT);

	/* Map normal memory beyond 4G */
	if (unlikely(end > MMIO_START)) {
	    start = 4 * MEM_G;
	    end = start + (end - 3 * MEM_G);
	    for (i = start; i < end; i += PAGE_SIZE, pgnr++)
		map_domain_page(d, i, pgnr << PAGE_SHIFT);
	}

	d->arch.max_pfn = end >> PAGE_SHIFT;

	order = get_order_from_pages(GFW_SIZE >> PAGE_SHIFT);
	if (unlikely((page = alloc_domheap_pages(d, order, 0)) == NULL)) {
	    printk("Could not allocate order=%d pages for vmx contig alloc\n",
			order);
	    return -1;
	}

	/* Map guest firmware */
	pgnr = page_to_mfn(page);
	for (i = GFW_START; i < GFW_START + GFW_SIZE; i += PAGE_SIZE, pgnr++)
	    map_domain_page(d, i, pgnr << PAGE_SHIFT);

	if (unlikely((page = alloc_domheap_pages(d, 1, 0)) == NULL)) {
	    printk("Could not allocate order=1 pages for vmx contig alloc\n");
	    return -1;
	}

	/* Map for shared I/O page and xenstore */
	pgnr = page_to_mfn(page);
	map_domain_page(d, IO_PAGE_START, pgnr << PAGE_SHIFT);
	pgnr++;
	map_domain_page(d, STORE_PAGE_START, pgnr << PAGE_SHIFT);

	set_bit(ARCH_VMX_CONTIG_MEM, &v->arch.arch_vmx.flags);
	return 0;
}

void vmx_setup_platform(struct domain *d, struct vcpu_guest_context *c)
{
	shared_iopage_t *sp;

	ASSERT(d != dom0); /* only for non-privileged vti domain */
	d->arch.vmx_platform.shared_page_va =
		__va(__gpa_to_mpa(d, IO_PAGE_START));
	sp = get_sp(d);
	//memset((char *)sp,0,PAGE_SIZE);
	/* TEMP */
	d->arch.vmx_platform.pib_base = 0xfee00000UL;

	/* Only open one port for I/O and interrupt emulation */
	memset(&d->shared_info->evtchn_mask[0], 0xff,
	    sizeof(d->shared_info->evtchn_mask));
	clear_bit(iopacket_port(d), &d->shared_info->evtchn_mask[0]);

	/* Initialize the virtual interrupt lines */
	vmx_virq_line_init(d);

	/* Initialize iosapic model within hypervisor */
	hvm_vioapic_init(d);
}


