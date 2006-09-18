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

#ifndef __ASSEMBLY__ 
#include <xen/types.h>

struct domain;
struct vcpu;
struct cpu_user_regs;
extern void show_registers(struct cpu_user_regs *);
extern void show_execution_state(struct cpu_user_regs *);
extern void show_backtrace(ulong sp, ulong lr, ulong pc);
extern unsigned int cpu_extent_order(void);
extern unsigned int cpu_default_rma_order_pages(void);
extern int cpu_rma_valid(unsigned int log);
extern uint cpu_large_page_orders(uint *sizes, uint max);
extern void cpu_initialize(int cpuid);
extern void cpu_init_vcpu(struct vcpu *);
extern void save_cpu_sprs(struct vcpu *);
extern void load_cpu_sprs(struct vcpu *);

/* XXX this could also land us in GDB */
#define dump_execution_state() BUG()

extern void __warn(char *file, int line);
#define WARN() __warn(__FILE__, __LINE__)
#define WARN_ON(_p) do { if (_p) WARN(); } while ( 0 )

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
#define cpu_relax() nop()

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

#ifdef CONFIG_MAMBO
static inline int on_mambo(void)
{
    return !!(mfmsr() & MSR_MAMBO);
}
#else /* CONFIG_MAMBO */
static inline int on_mambo(void) { return 0; }
#endif

#endif /* __ASSEMBLY__ */

#include <asm/powerpc64/processor.h>

#endif
