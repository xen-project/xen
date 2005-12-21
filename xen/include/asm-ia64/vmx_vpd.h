/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx.h: prototype for generial vmx related interface
 * Copyright (c) 2004, Intel Corporation.
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
 *      Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 */

#ifndef _ASM_IA64_VMX_VPD_H_
#define _ASM_IA64_VMX_VPD_H_

#ifndef __ASSEMBLY__

#include <asm/vtm.h>
#include <asm/vmx_platform.h>
#include <public/arch-ia64.h>

#define VPD_SHIFT	17	/* 128K requirement */
#define VPD_SIZE	(1 << VPD_SHIFT)

typedef struct {
	unsigned long	dcr;		// CR0
	unsigned long	itm;
	unsigned long	iva;
	unsigned long	rsv1[5];
	unsigned long	pta;		// CR8
	unsigned long	rsv2[7];
	unsigned long	ipsr;		// CR16
	unsigned long	isr;
	unsigned long	rsv3;
	unsigned long	iip;
	unsigned long	ifa;
	unsigned long	itir;
	unsigned long	iipa;
	unsigned long	ifs;
	unsigned long	iim;		// CR24
	unsigned long	iha;
	unsigned long	rsv4[38];
	unsigned long	lid;		// CR64
	unsigned long	ivr;
	unsigned long	tpr;
	unsigned long	eoi;
	unsigned long	irr[4];
	unsigned long	itv;		// CR72
	unsigned long	pmv;
	unsigned long	cmcv;
	unsigned long	rsv5[5];
	unsigned long	lrr0;		// CR80
	unsigned long	lrr1;
	unsigned long	rsv6[46];
} cr_t;

#ifdef VTI_DEBUG
struct ivt_debug{
    unsigned long iip;
    unsigned long ipsr;
    unsigned long ifa;
    unsigned long vector;
};
#define IVT_DEBUG_MAX 128
#endif
struct arch_vmx_struct {
//	vpd_t       *vpd;
    vtime_t	    vtm;
    struct vlapic   vlapic;
    unsigned long   vrr[8];
    unsigned long   vkr[8];
    unsigned long   cr_iipa;   /* for emulation */
    unsigned long   cr_isr;    /* for emulation */
    unsigned long   cause;
    unsigned long   opcode;

//    unsigned long   mrr5;
//    unsigned long   mrr6;
//    unsigned long   mrr7;
    unsigned long   mpta;
//    unsigned long   rfi_pfs;
//    unsigned long   rfi_iip;
//    unsigned long   rfi_ipsr;
//    unsigned long   rfi_ifs;
//	unsigned long	in_service[4];	// vLsapic inservice IRQ bits
	unsigned long   flags;
#ifdef VTI_DEBUG
    unsigned long  ivt_current;
    struct ivt_debug ivt_debug[IVT_DEBUG_MAX];
#endif
};

#define vmx_schedule_tail(next)         \
    (next)->thread.arch_vmx.arch_vmx_schedule_tail((next))

#define VMX_DOMAIN(d)   d->arch.arch_vmx.flags

#define ARCH_VMX_VMCS_LOADED    0       /* VMCS has been loaded and active */
#define ARCH_VMX_VMCS_LAUNCH    1       /* Needs VMCS launch */
#define ARCH_VMX_VMCS_RESUME    2       /* Needs VMCS resume */
#define ARCH_VMX_IO_WAIT        3       /* Waiting for I/O completion */
#define ARCH_VMX_INTR_ASSIST    4       /* Need DM's assist to issue intr */
#define ARCH_VMX_CONTIG_MEM 	5	/* Need contiguous machine pages */


#define VMX_DEBUG 1
#if VMX_DEBUG
#define DBG_LEVEL_0     (1 << 0)
#define DBG_LEVEL_1     (1 << 1)
#define DBG_LEVEL_2     (1 << 2)
#define DBG_LEVEL_3     (1 << 3)
#define DBG_LEVEL_IO    (1 << 4)
#define DBG_LEVEL_VMMU  (1 << 5)
#define DBG_LEVEL_IOAPIC 	(1 << 6)

extern unsigned int opt_vmx_debug_level;
#define VMX_DBG_LOG(level, _f, _a...)           \
    if ((level) & opt_vmx_debug_level)          \
        printk("[VMX]" _f "\n", ## _a )
#else
#define VMX_DBG_LOG(level, _f, _a...)
#endif

#define  __vmx_bug(regs)                                        \
    do {                                                        \
        printk("__vmx_bug at %s:%d\n", __FILE__, __LINE__);     \
        show_registers(regs);                                   \
        domain_crash(current->domain);                          \
    } while (0)

#endif //__ASSEMBLY__

// VPD field offset
#define VPD_VAC_START_OFFSET		0
#define VPD_VDC_START_OFFSET		8
#define VPD_VHPI_START_OFFSET		256
#define VPD_VGR_START_OFFSET		1024
#define VPD_VBGR_START_OFFSET		1152
#define VPD_VNAT_START_OFFSET		1280
#define VPD_VBNAT_START_OFFSET		1288
#define VPD_VCPUID_START_OFFSET		1296
#define VPD_VPSR_START_OFFSET		1424
#define VPD_VPR_START_OFFSET		1432
#define VPD_VRSE_CFLE_START_OFFSET	1440
#define VPD_VCR_START_OFFSET		2048
#define VPD_VRR_START_OFFSET		3072
#define VPD_VMM_VAIL_START_OFFSET	31744


#endif /* _ASM_IA64_VMX_VPD_H_ */
