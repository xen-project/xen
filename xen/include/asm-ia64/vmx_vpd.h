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
#include <public/xen.h>
#include <xen/spinlock.h>

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
    unsigned long   vrr[8];
    /* if the corresponding bit is 1, then this page size is
       used in this region */
    unsigned long   psbits[8];
    unsigned long   vkr[8];
    unsigned long   cr_iipa;   /* for emulation */
    unsigned long   cr_isr;    /* for emulation */
    unsigned long   cause;
    unsigned long   opcode;
    unsigned long   mpta;
    unsigned long   flags;
    unsigned long   xen_port;
    unsigned char   xtp;
    unsigned char   pal_init_pending;
#ifdef VTI_DEBUG
    unsigned long  ivt_current;
    struct ivt_debug ivt_debug[IVT_DEBUG_MAX];
#endif
};

#define VMX_DOMAIN(v)   v->arch.arch_vmx.flags

#define ARCH_VMX_IO_WAIT        3       /* Waiting for I/O completion */
#define ARCH_VMX_DOMAIN         5       /* Need it to indicate VTi domain */

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
#define VPD_VTPR_START_OFFSET		2576
#define VPD_VRR_START_OFFSET		3072
#define VPD_VMM_VAIL_START_OFFSET	31744


#endif /* _ASM_IA64_VMX_VPD_H_ */
