/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright IBM Corp. 2005, 2006, 2007
 * Copyright Raptor Engineering, LLC
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *          Timothy Pearson <tpearson@raptorengineering.com>
 *          Shawn Anastasio <sanastasio@raptorengineering.com>
 */

#ifndef _ASM_PPC_PROCESSOR_H
#define _ASM_PPC_PROCESSOR_H

#define IOBMP_BYTES          8192
#define IOBMP_INVALID_OFFSET 0x8000

/* Processor Version Register (PVR) field extraction */

#define PVR_VER(pvr) (((pvr) >> 16) & 0xFFFF) /* Version field */
#define PVR_REV(pvr) (((pvr) >> 0) & 0xFFFF)  /* Revison field */

#define __is_processor(pv) (PVR_VER(mfspr(SPRN_PVR)) == (pv))

/*
 * IBM has further subdivided the standard PowerPC 16-bit version and
 * revision subfields of the PVR for the PowerPC 403s into the following:
 */

#define PVR_FAM(pvr)  (((pvr) >> 20) & 0xFFF) /* Family field */
#define PVR_MEM(pvr)  (((pvr) >> 16) & 0xF)   /* Member field */
#define PVR_CORE(pvr) (((pvr) >> 12) & 0xF)   /* Core field */
#define PVR_CFG(pvr)  (((pvr) >> 8) & 0xF)    /* Configuration field */
#define PVR_MAJ(pvr)  (((pvr) >> 4) & 0xF)    /* Major revision field */
#define PVR_MIN(pvr)  (((pvr) >> 0) & 0xF)    /* Minor revision field */

/* Processor Version Numbers */

#define PVR_403GA    0x00200000
#define PVR_403GB    0x00200100
#define PVR_403GC    0x00200200
#define PVR_403GCX   0x00201400
#define PVR_405GP    0x40110000
#define PVR_STB03XXX 0x40310000
#define PVR_NP405H   0x41410000
#define PVR_NP405L   0x41610000
#define PVR_601      0x00010000
#define PVR_602      0x00050000
#define PVR_603      0x00030000
#define PVR_603e     0x00060000
#define PVR_603ev    0x00070000
#define PVR_603r     0x00071000
#define PVR_604      0x00040000
#define PVR_604e     0x00090000
#define PVR_604r     0x000A0000
#define PVR_620      0x00140000
#define PVR_740      0x00080000
#define PVR_750      PVR_740
#define PVR_740P     0x10080000
#define PVR_750P     PVR_740P
#define PVR_7400     0x000C0000
#define PVR_7410     0x800C0000
#define PVR_7450     0x80000000
#define PVR_8540     0x80200000
#define PVR_8560     0x80200000
/*
 * For the 8xx processors, all of them report the same PVR family for
 * the PowerPC core. The various versions of these processors must be
 * differentiated by the version number in the Communication Processor
 * Module (CPM).
 */
#define PVR_821  0x00500000
#define PVR_823  PVR_821
#define PVR_850  PVR_821
#define PVR_860  PVR_821
#define PVR_8240 0x00810100
#define PVR_8245 0x80811014
#define PVR_8260 PVR_8240

/* 64-bit processors */
#define PVR_NORTHSTAR 0x0033
#define PVR_PULSAR    0x0034
#define PVR_POWER4    0x0035
#define PVR_ICESTAR   0x0036
#define PVR_SSTAR     0x0037
#define PVR_POWER4p   0x0038
#define PVR_970       0x0039
#define PVR_POWER5    0x003A
#define PVR_POWER5p   0x003B
#define PVR_970FX     0x003C
#define PVR_POWER6    0x003E
#define PVR_POWER7    0x003F
#define PVR_630       0x0040
#define PVR_630p      0x0041
#define PVR_970MP     0x0044
#define PVR_970GX     0x0045
#define PVR_POWER7p   0x004A
#define PVR_POWER8E   0x004B
#define PVR_POWER8NVL 0x004C
#define PVR_POWER8    0x004D
#define PVR_POWER9    0x004E
#define PVR_POWER10   0x0080
#define PVR_BE        0x0070
#define PVR_PA6T      0x0090

/* Exception Definitions */
#define EXC_SYSTEM_RESET    0x0100 /* System Reset Interrupt */
#define EXC_MACHINE_CHECK   0x0200 /* Machine Check Interrupt */
#define EXC_DATA_STORAGE    0x0300 /* Data Storage Interrupt */
#define EXC_DATA_SEGMENT    0x0380 /* Data Segment Interrupt */
#define EXC_INSN_STORAGE    0x0400 /* Instruction Storage Interrupt */
#define EXC_INSN_SEGMENT    0x0480 /* Instruction Segment Interrupt */
#define EXC_EXTERNAL        0x0500 /* External Interrupt */
#define EXC_ALIGNMENT       0x0600 /* Alignment Interrupt */
#define EXC_PROGRAM         0x0700 /* Program Interrupt */
#define EXC_FPU_UNAVAIL     0x0800 /* Floating-Point Unavailable Interrupt */
#define EXC_DECREMENTER     0x0900 /* Decrementer Interrupt */
#define EXC_H_DECREMENTER   0x0980 /* Hypervisor Decrementer Interrupt */
#define EXC_PRIV_DOORBELL   0x0A00 /* Directed Privileged Doorbell Interrupt */
#define EXC_SYSTEM_CALL     0x0C00 /* System Call Interrupt */
#define EXC_TRACE           0x0D00 /* Trace Interrupt */
#define EXC_H_DATA_STORAGE  0x0E00 /* Hypervisor Data Storage Interrupt */
#define EXC_H_INSN_STORAGE  0x0E20 /* Hypervisor Instruction Storage Interrupt */
#define EXC_H_EMUL_ASST     0x0E40 /* Hypervisor Emulation Assistance Interrupt */
#define EXC_H_MAINTENANCE   0x0E60 /* Hypervisor Maintenance Interrupt */
#define EXC_H_DOORBELL      0x0E80 /* Directed Hypervisor Doorbell Interrupt */
#define EXC_H_VIRT          0x0EA0 /* Hypervisor Virtualization Interrupt */
#define EXC_PERF_MON        0x0F00 /* Performance Monitor Interrupt */
#define EXC_VECTOR_UNAVAIL  0x0F20 /* Vector Unavailable Interrupt */
#define EXC_VSX_UNAVAIL     0x0F40 /* VSX Unavailable Interrupt */
#define EXC_FACIL_UNAVAIL   0x0F60 /* Facility Unavailable Interrupt */
#define EXC_H_FACIL_UNAVAIL 0x0F80 /* Hypervisor Facility Unavailable Interrupt */

/* Base address of interrupt vector table when LPCR[AIL]=3 */
#define AIL_VECTOR_BASE _AC(0xc000000000004000, UL)

#ifndef __ASSEMBLY__

#include <xen/types.h>

/* Macro to adjust thread priority for hardware multithreading */
#define HMT_very_low()  asm volatile ( "or %r31, %r31, %r31" )

/* TODO: This isn't correct */
#define cpu_to_core(cpu)   (0)
#define cpu_to_socket(cpu) (0)

/*
 * User-accessible registers: most of these need to be saved/restored
 * for every nested Xen invocation.
 */
struct cpu_user_regs
{
    uint64_t gprs[32];
    uint64_t lr;
    uint64_t ctr;
    uint64_t srr0;
    uint64_t srr1;
    uint64_t pc;
    uint64_t msr;
    uint64_t fpscr;
    uint64_t xer;
    uint64_t hid4;  /* debug only */
    uint64_t dar;   /* debug only */
    uint32_t dsisr; /* debug only */
    uint32_t cr;
    uint32_t __pad; /* good spot for another 32bit reg */
    uint32_t entry_vector;
};

static inline void sync(void)
{
    asm volatile ( "sync" );
}

static inline void isync(void)
{
    asm volatile ( "isync" );
}

static inline unsigned long mfmsr(void)
{
    unsigned long msr;
    asm volatile ( "mfmsr %0" : "=r" (msr) );
    return msr;
}

static inline void mtmsrd(unsigned long msr)
{
    asm volatile ( "mtmsrd %0" : : "r" (msr) );
}

static inline void mtspr(uint16_t spr, unsigned long val)
{
    asm volatile ( "mtspr %0, %1" : : "K" (spr), "r" (val) );
}

static inline unsigned long mfspr(uint16_t spr)
{
    unsigned long val;
    asm volatile ( "mfspr %0, %1" : "=r" (val) : "K" (spr) );
    return val;
}

/*
 * panic() isn't available at the moment so an infinite loop will be
 * used temporarily.
 * TODO: change it to panic()
 */
static inline void noreturn die(void)
{
    for ( ; ; )
        HMT_very_low();
}

/*
 * Implemented on pre-POWER10 by setting HMT to low then to medium using
 * the special OR forms. See HMT_very_low above.
 */
#define cpu_relax() asm volatile ( "or %r1, %r1, %r1; or %r2, %r2, %r2" )

#define dump_execution_state() run_in_exception_handler(show_execution_state)

#endif /* __ASSEMBLY__ */

#endif /* _ASM_PPC_PROCESSOR_H */
