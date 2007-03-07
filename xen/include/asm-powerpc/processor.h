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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_PROCESSOR_H_
#define _ASM_PROCESSOR_H_

#include <xen/config.h>
#include <asm/reg_defs.h>
#include <asm/msr.h>

#define IOBMP_BYTES             8192
#define IOBMP_INVALID_OFFSET    0x8000

/* most assembler do not know this instruction */
#define HRFID .long 0x4c000224

/* Processor Version Register (PVR) field extraction */

#define PVR_VER(pvr)	(((pvr) >>  16) & 0xFFFF)	/* Version field */
#define PVR_REV(pvr)	(((pvr) >>   0) & 0xFFFF)	/* Revison field */

#define __is_processor(pv)	(PVR_VER(mfspr(SPRN_PVR)) == (pv))

/*
 * IBM has further subdivided the standard PowerPC 16-bit version and
 * revision subfields of the PVR for the PowerPC 403s into the following:
 */

#define PVR_FAM(pvr)	(((pvr) >> 20) & 0xFFF)	/* Family field */
#define PVR_MEM(pvr)	(((pvr) >> 16) & 0xF)	/* Member field */
#define PVR_CORE(pvr)	(((pvr) >> 12) & 0xF)	/* Core field */
#define PVR_CFG(pvr)	(((pvr) >>  8) & 0xF)	/* Configuration field */
#define PVR_MAJ(pvr)	(((pvr) >>  4) & 0xF)	/* Major revision field */
#define PVR_MIN(pvr)	(((pvr) >>  0) & 0xF)	/* Minor revision field */

/* Processor Version Numbers */

#define PVR_403GA	0x00200000
#define PVR_403GB	0x00200100
#define PVR_403GC	0x00200200
#define PVR_403GCX	0x00201400
#define PVR_405GP	0x40110000
#define PVR_STB03XXX	0x40310000
#define PVR_NP405H	0x41410000
#define PVR_NP405L	0x41610000
#define PVR_601		0x00010000
#define PVR_602		0x00050000
#define PVR_603		0x00030000
#define PVR_603e	0x00060000
#define PVR_603ev	0x00070000
#define PVR_603r	0x00071000
#define PVR_604		0x00040000
#define PVR_604e	0x00090000
#define PVR_604r	0x000A0000
#define PVR_620		0x00140000
#define PVR_740		0x00080000
#define PVR_750		PVR_740
#define PVR_740P	0x10080000
#define PVR_750P	PVR_740P
#define PVR_7400	0x000C0000
#define PVR_7410	0x800C0000
#define PVR_7450	0x80000000
#define PVR_8540	0x80200000
#define PVR_8560	0x80200000
/*
 * For the 8xx processors, all of them report the same PVR family for
 * the PowerPC core. The various versions of these processors must be
 * differentiated by the version number in the Communication Processor
 * Module (CPM).
 */
#define PVR_821		0x00500000
#define PVR_823		PVR_821
#define PVR_850		PVR_821
#define PVR_860		PVR_821
#define PVR_8240	0x00810100
#define PVR_8245	0x80811014
#define PVR_8260	PVR_8240

/* 64-bit processors */
/* XXX the prefix should be PVR_, we'll do a global sweep to fix it one day */
#define PV_NORTHSTAR	0x0033
#define PV_PULSAR	0x0034
#define PV_POWER4	0x0035
#define PV_ICESTAR	0x0036
#define PV_SSTAR	0x0037
#define PV_POWER4p	0x0038
#define PV_970		0x0039
#define PV_POWER5	0x003A
#define PV_POWER5p	0x003B
#define PV_970FX	0x003C
#define PV_630		0x0040
#define PV_630p	0x0041
#define PV_970MP	0x0044
#define PV_BE		0x0070

#ifndef __ASSEMBLY__ 
#include <xen/types.h>

struct domain;
struct vcpu;
struct cpu_user_regs;
extern int cpu_machinecheck(struct cpu_user_regs *);
extern void show_registers(struct cpu_user_regs *);
extern unsigned int cpu_extent_order(void);
extern unsigned int cpu_default_rma_order_pages(void);
extern int cpu_rma_valid(unsigned int order);
extern uint cpu_large_page_orders(uint *sizes, uint max);
extern void cpu_initialize(int cpuid);
extern void cpu_init_vcpu(struct vcpu *);
extern int cpu_threads(int cpuid);
extern void save_cpu_sprs(struct vcpu *);
extern void load_cpu_sprs(struct vcpu *);
extern void flush_segments(void);
extern void dump_segments(int valid);

#define ARCH_HAS_PREFETCH
static inline void prefetch(const void *x) {;}

static __inline__ void sync(void)
{
    __asm__ __volatile__ ("sync");
}

static __inline__ void isync(void)
{
    __asm__ __volatile__ ("isync");
}

static inline ulong mfmsr(void) {
    ulong msr;
    __asm__ __volatile__ ("mfmsr %0" : "=&r"(msr));
    return msr;
}

static inline void nop(void) {
    __asm__ __volatile__ ("nop");
}
/* will need to address thread priorities when we go SMT */
#define cpu_relax() barrier()

static inline unsigned int mfpir(void)
{
    unsigned int pir;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r" (pir): "i"(SPRN_PIR));
    return pir;
}

static inline unsigned int mftbu(void)
{
    unsigned int tbu;
    __asm__ __volatile__ ("mftbu %0" : "=r" (tbu));
    return tbu;
}

static inline unsigned int mftbl(void)
{
    unsigned int tbl;
    __asm__ __volatile__ ("mftbl %0" : "=r" (tbl));
    return tbl;
}

static inline unsigned int mfdec(void)
{
    unsigned int tmp;
    __asm__ __volatile__ ("mfdec %0" : "=r"(tmp));
    return tmp;
}
static inline void mtdec(unsigned int ticks)
{
    __asm__ __volatile__ ("mtdec %0" : : "r" (ticks));
}

static inline u32 mfpvr(void) {
    u32 pvr;
    asm volatile("mfpvr %0" : "=&r" (pvr));
    return pvr;
}

static inline ulong mfr1(void)
{
    ulong r1;
    asm volatile("mr %0, 1" : "=&r" (r1));
    return r1;
}

static inline void mtsprg0(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_SPRG0), "r"(val));
}
static inline ulong mfsprg0(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_SPRG0));
    return val;
}

static inline void mtsprg1(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_SPRG1), "r"(val));
}
static inline ulong mfsprg1(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_SPRG1));
    return val;
}

static inline void mtsprg2(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_SPRG2), "r"(val));
}
static inline ulong mfsprg2(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_SPRG2));
    return val;
}

static inline void mtsprg3(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_SPRG3), "r"(val));
}
static inline ulong mfsprg3(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_SPRG3));
    return val;
}

static inline void mtsdr1(ulong val)
{
    __asm__ __volatile__ ("mtsdr1 %0" : : "r"(val));
}
static inline ulong mfsdr1(void)
{
    ulong val;
    __asm__ __volatile__ ("mfsdr1 %0" : "=r"(val));
    return val;
}

static inline void mtdar(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_DAR), "r"(val));
}
static inline ulong mfdar(void)
{
    ulong val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_DAR));
    return val;
}

static inline void mtdsisr(ulong val)
{
    __asm__ __volatile__ ("mtspr %0, %1" : : "i"(SPRN_DSISR), "r"(val));
}
static inline unsigned mfdsisr(void)
{
    unsigned val;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r"(val) : "i"(SPRN_DSISR));
    return val;
}

#ifdef CONFIG_SYSTEMSIM
static inline int on_systemsim(void)
{
    return !!(mfmsr() & MSR_SYSTEMSIM);
}
#else /* CONFIG_SYSTEMSIM */
static inline int on_systemsim(void) { return 0; }
#endif

#endif /* __ASSEMBLY__ */

#include <asm/powerpc64/processor.h>

#endif
