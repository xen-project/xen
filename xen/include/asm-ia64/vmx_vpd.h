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

#ifndef _VPD_H_
#define _VPD_H_

#ifndef __ASSEMBLY__

#include <asm/vtm.h>
#include <asm/vmx_platform.h>

#define VPD_SHIFT	17	/* 128K requirement */
#define VPD_SIZE	(1 << VPD_SHIFT)
typedef union {
	unsigned long value;
	struct {
		int 	a_int:1;
		int 	a_from_int_cr:1;
		int	a_to_int_cr:1;
		int	a_from_psr:1;
		int	a_from_cpuid:1;
		int	a_cover:1;
		int	a_bsw:1;
		long	reserved:57;
	};
} vac_t;

typedef union {
	unsigned long value;
	struct {
		int 	d_vmsw:1;
		int 	d_extint:1;
		int	d_ibr_dbr:1;
		int	d_pmc:1;
		int	d_to_pmd:1;
		int	d_itm:1;
		long	reserved:58;
	};
} vdc_t;

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

typedef struct vpd {
	vac_t			vac;
	vdc_t			vdc;
	unsigned long		virt_env_vaddr;
	unsigned long		reserved1[29];
	unsigned long		vhpi;
	unsigned long		reserved2[95];
	unsigned long		vgr[16];
	unsigned long		vbgr[16];
	unsigned long		vnat;
	unsigned long		vbnat;
	unsigned long		vcpuid[5];
	unsigned long		reserved3[11];
	unsigned long		vpsr;
	unsigned long		vpr;
	unsigned long		reserved4[76];
	unsigned long		vcr[128];
	unsigned long		reserved5[128];
	unsigned long		reserved6[3456];
	unsigned long		vmm_avail[128];
	unsigned long		reserved7[4096];
} vpd_t;

void vmx_enter_scheduler(void);

//FIXME: Map for LID to exec_domain, Eddie
#define	MAX_NUM_LPS		(1UL<<16)
extern struct exec_domain	*lid_edt[MAX_NUM_LPS];

struct arch_vmx_struct {
//    struct virutal_platform_def     vmx_platform;
	vpd_t       *vpd;
	vtime_t	    vtm;
    unsigned long   vrr[8];
    unsigned long   mrr5;
    unsigned long   mrr6;
    unsigned long   mrr7;
    unsigned long   mpta;
    unsigned long   rfi_pfs;
    unsigned long   rfi_iip;
    unsigned long   rfi_ipsr;
    unsigned long   rfi_ifs;
	unsigned long	in_service[4];	// vLsapic inservice IRQ bits
	struct virutal_platform_def     vmx_platform;
	unsigned long   flags;
};

#define vmx_schedule_tail(next)         \
    (next)->thread.arch_vmx.arch_vmx_schedule_tail((next))

#define VMX_DOMAIN(d)   d->arch.arch_vmx.flags

#define ARCH_VMX_VMCS_LOADED    0       /* VMCS has been loaded and active */
#define ARCH_VMX_VMCS_LAUNCH    1       /* Needs VMCS launch */
#define ARCH_VMX_VMCS_RESUME    2       /* Needs VMCS resume */
#define ARCH_VMX_IO_WAIT        3       /* Waiting for I/O completion */


#define VMX_DEBUG 1
#if VMX_DEBUG
#define DBG_LEVEL_0     (1 << 0)
#define DBG_LEVEL_1     (1 << 1)
#define DBG_LEVEL_2     (1 << 2)
#define DBG_LEVEL_3     (1 << 3)
#define DBG_LEVEL_IO    (1 << 4)
#define DBG_LEVEL_VMMU  (1 << 5)

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
        domain_crash();                                         \
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


#endif /* _VPD_H_ */
