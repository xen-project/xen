/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * asm-xsi-offsets.c_
 * Copyright (c) 2005, Intel Corporation.
 *      Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *      Eddie Dong  <eddie.dong@intel.com>
 *      Fred Yang <fred.yang@intel.com>
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
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <public/xen.h>
#include <asm/tlb.h>
#include <asm/regs.h>

#define task_struct vcpu

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " (%0) " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )

#define DEFINE_MAPPED_REG_OFS(sym, field) \
	DEFINE(sym, (XMAPPEDREGS_OFS + offsetof(mapped_regs_t, field)))

void foo(void)
{
	DEFINE_MAPPED_REG_OFS(XSI_PSR_I_ADDR_OFS, interrupt_mask_addr);
	DEFINE_MAPPED_REG_OFS(XSI_IPSR_OFS, ipsr);
	DEFINE_MAPPED_REG_OFS(XSI_IIP_OFS, iip);
	DEFINE_MAPPED_REG_OFS(XSI_IFS_OFS, ifs);
	DEFINE_MAPPED_REG_OFS(XSI_PRECOVER_IFS_OFS, precover_ifs);
	DEFINE_MAPPED_REG_OFS(XSI_ISR_OFS, isr);
	DEFINE_MAPPED_REG_OFS(XSI_IFA_OFS, ifa);
	DEFINE_MAPPED_REG_OFS(XSI_IIPA_OFS, iipa);
	DEFINE_MAPPED_REG_OFS(XSI_IIM_OFS, iim);
	DEFINE_MAPPED_REG_OFS(XSI_TPR_OFS, tpr);
	DEFINE_MAPPED_REG_OFS(XSI_IHA_OFS, iha);
	DEFINE_MAPPED_REG_OFS(XSI_ITIR_OFS, itir);
	DEFINE_MAPPED_REG_OFS(XSI_ITV_OFS, itv);
	DEFINE_MAPPED_REG_OFS(XSI_PTA_OFS, pta);
	DEFINE_MAPPED_REG_OFS(XSI_VPSR_DFH_OFS, vpsr_dfh);
	DEFINE_MAPPED_REG_OFS(XSI_HPSR_DFH_OFS, hpsr_dfh);
	DEFINE_MAPPED_REG_OFS(XSI_PSR_IC_OFS, interrupt_collection_enabled);
	DEFINE_MAPPED_REG_OFS(XSI_VPSR_PP_OFS, vpsr_pp);
	DEFINE_MAPPED_REG_OFS(XSI_METAPHYS_OFS, metaphysical_mode);
	DEFINE_MAPPED_REG_OFS(XSI_BANKNUM_OFS, banknum);
	DEFINE_MAPPED_REG_OFS(XSI_BANK0_R16_OFS, bank0_regs[0]);
	DEFINE_MAPPED_REG_OFS(XSI_BANK1_R16_OFS, bank1_regs[0]);
	DEFINE_MAPPED_REG_OFS(XSI_B0NATS_OFS, vbnat);
	DEFINE_MAPPED_REG_OFS(XSI_B1NATS_OFS, vnat);
	DEFINE_MAPPED_REG_OFS(XSI_RR0_OFS, rrs[0]);
	DEFINE_MAPPED_REG_OFS(XSI_KR0_OFS, krs[0]);
}
