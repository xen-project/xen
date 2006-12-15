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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <public/xen.h>
#include <asm/processor.h>
#include <asm/percpu.h>
#include <asm/debugger.h>
#include "scom.h"

#define MCK_SRR1_INSN_FETCH_UNIT    0x0000000000200000 /* 42 */
#define MCK_SRR1_LOAD_STORE         0x0000000000100000 /* 43 */
#define MCK_SRR1_CAUSE_MASK         0x00000000000c0000 /* 44:45 */
#define MCK_SRR1_CAUSE_NONE         0x0000000000000000 /* 0b00 */
#define MCK_SRR1_CAUSE_SLB_PAR      0x0000000000040000 /* 0b01 */
#define MCK_SRR1_CAUSE_TLB_PAR      0x0000000000080000 /* 0b10 */
#define MCK_SRR1_CAUSE_UE           0x00000000000c0000 /* 0b11 */
#define MCK_SRR1_RI                 MSR_RI

#define MCK_DSISR_UE                0x00008000 /* 16 */
#define MCK_DSISR_UE_TABLE_WALK     0x00004000 /* 17 */
#define MCK_DSISR_L1_DCACHE_PAR     0x00002000 /* 18 */
#define MCK_DSISR_L1_DCACHE_TAG_PAR 0x00001000 /* 19 */
#define MCK_DSISR_D_ERAT_PAR        0x00000800 /* 20 */
#define MCK_DSISR_TLB_PAR           0x00000400 /* 21 */
#define MCK_DSISR_SLB_PAR           0x00000100 /* 23 */

int cpu_machinecheck(struct cpu_user_regs *regs)
{
    int recover = 0;
    u32 dsisr = mfdsisr();

    if (regs->msr & MCK_SRR1_RI)
        recover = 1;

    printk("MACHINE CHECK: %s Recoverable\n", recover ? "IS": "NOT");
    if (mck_cpu_stats[mfpir()] != 0)
        printk("While in CI IO\n");

    show_backtrace_regs(regs);

    printk("SRR1: 0x%016lx\n", regs->msr);
    if (regs->msr & MCK_SRR1_INSN_FETCH_UNIT)
        printk("42: Exception caused by Instruction Fetch Unit (IFU)\n"
               "    detection of a hardware uncorrectable error (UE).\n");

    if (regs->msr & MCK_SRR1_LOAD_STORE)
        printk("43: Exception caused by load/store detection of error\n"
               "    (see DSISR)\n");

    switch (regs->msr & MCK_SRR1_CAUSE_MASK) {
    case 0:
        printk("0b00: Likely caused by an asynchronous machine check,\n"
               "      see SCOM Asynchronous Machine Check Register\n");
        cpu_scom_AMCR();
        break;
    case MCK_SRR1_CAUSE_SLB_PAR:
        printk("0b01: Exception caused by an SLB parity error detected\n"
               "      while translating an instruction fetch address.\n");
        break;
    case MCK_SRR1_CAUSE_TLB_PAR:
        printk("0b10: Exception caused by a TLB parity error detected\n"
               "      while translating an instruction fetch address.\n");
        break;
    case MCK_SRR1_CAUSE_UE:
        printk("0b11: Exception caused by a hardware uncorrectable\n"
               "      error (UE) detected while doing a reload of an\n"
               "      instruction-fetch TLB tablewalk.\n");
        break;
    }

    printk("\nDSISR: 0x%08x\n", dsisr);
    if (dsisr & MCK_DSISR_UE)
        printk("16: Exception caused by a UE deferred error\n"
               "    (DAR is undefined).\n");
    
    if (dsisr & MCK_DSISR_UE_TABLE_WALK)
        printk("17: Exception caused by a UE deferred error\n"
               "    during a tablewalk (D-side).\n"); 

    if (dsisr & MCK_DSISR_L1_DCACHE_PAR)
        printk("18: Exception was caused by a software recoverable\n"
               "    parity error in the L1 D-cache.\n");

    if (dsisr & MCK_DSISR_L1_DCACHE_TAG_PAR)
        printk("19: Exception was caused by a software recoverable\n"
               "    parity error in the L1 D-cache tag.\n");

    if (dsisr & MCK_DSISR_D_ERAT_PAR)
        printk("20: Exception was caused by a software recoverable parity\n"
               "    error in the D-ERAT.\n");
        
    if (dsisr & MCK_DSISR_TLB_PAR)
        printk("21: Exception was caused by a software recoverable parity\n"
               "    error in the TLB.\n");

    if (dsisr & MCK_DSISR_SLB_PAR) {
        printk("23: Exception was caused by an SLB parity error (may not be\n"
               "    recoverable). This condition could occur if the\n"
               "    effective segment ID (ESID) fields of two or more SLB\n"
               "    entries contain the same value.\n");
        dump_segments(0);
    }

    return 0; /* for now lets not recover */
}
