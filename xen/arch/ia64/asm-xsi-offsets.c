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

#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

void foo(void)
{

	DEFINE(XSI_BASE, SHARED_ARCHINFO_ADDR);

	DEFINE(XSI_PSR_I_OFS, offsetof(mapped_regs_t, interrupt_delivery_enabled));
	DEFINE(XSI_PSR_I, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, interrupt_delivery_enabled)));
	DEFINE(XSI_IPSR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ipsr)));
	DEFINE(XSI_IPSR_OFS, offsetof(mapped_regs_t, ipsr));
	DEFINE(XSI_IIP_OFS, offsetof(mapped_regs_t, iip));
	DEFINE(XSI_IIP, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, iip)));
	DEFINE(XSI_IFS_OFS, offsetof(mapped_regs_t, ifs));
	DEFINE(XSI_IFS, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ifs)));
	DEFINE(XSI_PRECOVER_IFS_OFS, offsetof(mapped_regs_t, precover_ifs));
	DEFINE(XSI_PRECOVER_IFS, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, precover_ifs)));
	DEFINE(XSI_ISR_OFS, offsetof(mapped_regs_t, isr));
	DEFINE(XSI_ISR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, isr)));
	DEFINE(XSI_IFA_OFS, offsetof(mapped_regs_t, ifa));
	DEFINE(XSI_IFA, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ifa)));
	DEFINE(XSI_IIPA_OFS, offsetof(mapped_regs_t, iipa));
	DEFINE(XSI_IIPA, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, iipa)));
	DEFINE(XSI_IIM_OFS, offsetof(mapped_regs_t, iim));
	DEFINE(XSI_IIM, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, iim)));
	DEFINE(XSI_TPR_OFS, offsetof(mapped_regs_t, tpr));
	DEFINE(XSI_TPR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, tpr)));
	DEFINE(XSI_IHA_OFS, offsetof(mapped_regs_t, iha));
	DEFINE(XSI_IHA, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, iha)));
	DEFINE(XSI_ITIR_OFS, offsetof(mapped_regs_t, itir));
	DEFINE(XSI_ITIR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, itir)));
	DEFINE(XSI_ITV_OFS, offsetof(mapped_regs_t, itv));
	DEFINE(XSI_ITV, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, itv)));
	DEFINE(XSI_PTA_OFS, offsetof(mapped_regs_t, pta));
	DEFINE(XSI_PTA, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, pta)));
	DEFINE(XSI_PSR_IC_OFS, offsetof(mapped_regs_t, interrupt_collection_enabled));
	DEFINE(XSI_PSR_IC, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, interrupt_collection_enabled)));
	DEFINE(XSI_PEND_OFS, offsetof(mapped_regs_t, pending_interruption));
	DEFINE(XSI_PEND, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, pending_interruption)));
	DEFINE(XSI_INCOMPL_REGFR_OFS, offsetof(mapped_regs_t, incomplete_regframe));
	DEFINE(XSI_INCOMPL_REGFR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, incomplete_regframe)));
	DEFINE(XSI_METAPHYS_OFS, offsetof(mapped_regs_t, metaphysical_mode));
	DEFINE(XSI_METAPHYS, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, metaphysical_mode)));

	DEFINE(XSI_BANKNUM_OFS, offsetof(mapped_regs_t, banknum));
	DEFINE(XSI_BANKNUM, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, banknum)));

	DEFINE(XSI_BANK0_R16_OFS, offsetof(mapped_regs_t, bank0_regs[0]));
	DEFINE(XSI_BANK0_R16, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, bank0_regs[0])));
	DEFINE(XSI_BANK1_R16_OFS, offsetof(mapped_regs_t, bank1_regs[0]));
	DEFINE(XSI_BANK1_R16, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, bank1_regs[0])));
	DEFINE(XSI_RR0_OFS, offsetof(mapped_regs_t, rrs[0]));
	DEFINE(XSI_RR0, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, rrs[0])));
	DEFINE(XSI_KR0_OFS, offsetof(mapped_regs_t, krs[0]));
	DEFINE(XSI_KR0, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, krs[0])));
	DEFINE(XSI_PKR0_OFS, offsetof(mapped_regs_t, pkrs[0]));
	DEFINE(XSI_PKR0, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, pkrs[0])));
	DEFINE(XSI_TMP0_OFS, offsetof(mapped_regs_t, tmp[0]));
	DEFINE(XSI_TMP0, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, tmp[0])));
	
}
