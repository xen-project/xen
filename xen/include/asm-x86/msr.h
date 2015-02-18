#ifndef __ASM_MSR_H
#define __ASM_MSR_H

#include "msr-index.h"

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/percpu.h>
#include <xen/errno.h>
#include <asm/asm_defns.h>
#include <asm/cpufeature.h>

#define rdmsr(msr,val1,val2) \
     __asm__ __volatile__("rdmsr" \
			  : "=a" (val1), "=d" (val2) \
			  : "c" (msr))

#define rdmsrl(msr,val) do { unsigned long a__,b__; \
       __asm__ __volatile__("rdmsr" \
			    : "=a" (a__), "=d" (b__) \
			    : "c" (msr)); \
       val = a__ | ((u64)b__<<32); \
} while(0)

#define wrmsr(msr,val1,val2) \
     __asm__ __volatile__("wrmsr" \
			  : /* no outputs */ \
			  : "c" (msr), "a" (val1), "d" (val2))

static inline void wrmsrl(unsigned int msr, __u64 val)
{
        __u32 lo, hi;
        lo = (__u32)val;
        hi = (__u32)(val >> 32);
        wrmsr(msr, lo, hi);
}

/* rdmsr with exception handling */
#define rdmsr_safe(msr,val) ({\
    int _rc; \
    uint32_t lo, hi; \
    __asm__ __volatile__( \
        "1: rdmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: xorl %0,%0\n; xorl %1,%1\n" \
        "   movl %5,%2\n; jmp 2b\n" \
        ".previous\n" \
        _ASM_EXTABLE(1b, 3b) \
        : "=a" (lo), "=d" (hi), "=&r" (_rc) \
        : "c" (msr), "2" (0), "i" (-EFAULT)); \
    val = lo | ((uint64_t)hi << 32); \
    _rc; })

/* wrmsr with exception handling */
static inline int wrmsr_safe(unsigned int msr, uint64_t val)
{
    int _rc;
    uint32_t lo, hi;
    lo = (uint32_t)val;
    hi = (uint32_t)(val >> 32);

    __asm__ __volatile__(
        "1: wrmsr\n2:\n"
        ".section .fixup,\"ax\"\n"
        "3: movl %5,%0\n; jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(1b, 3b)
        : "=&r" (_rc)
        : "c" (msr), "a" (lo), "d" (hi), "0" (0), "i" (-EFAULT));
    return _rc;
}

static inline uint64_t rdtsc(void)
{
    uint32_t low, high;

    __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));

    return ((uint64_t)high << 32) | low;
}

#define __write_tsc(val) wrmsrl(MSR_IA32_TSC, val)
#define write_tsc(val) ({                                       \
    /* Reliable TSCs are in lockstep across all CPUs. We should \
     * never write to them. */                                  \
    ASSERT(!boot_cpu_has(X86_FEATURE_TSC_RELIABLE));            \
    __write_tsc(val);                                           \
})

#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)

#define rdpmc(counter,low,high) \
     __asm__ __volatile__("rdpmc" \
			  : "=a" (low), "=d" (high) \
			  : "c" (counter))

static inline unsigned long __rdfsbase(void)
{
    unsigned long base;

#ifdef HAVE_GAS_FSGSBASE
    asm volatile ( "rdfsbase %0" : "=r" (base) );
#else
    asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0" : "=a" (base) );
#endif

    return base;
}

static inline unsigned long __rdgsbase(void)
{
    unsigned long base;

#ifdef HAVE_GAS_FSGSBASE
    asm volatile ( "rdgsbase %0" : "=r" (base) );
#else
    asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc8" : "=a" (base) );
#endif

    return base;
}

static inline unsigned long rdfsbase(void)
{
    unsigned long base;

    if ( cpu_has_fsgsbase )
        return __rdfsbase();

    rdmsrl(MSR_FS_BASE, base);

    return base;
}

static inline unsigned long rdgsbase(void)
{
    unsigned long base;

    if ( cpu_has_fsgsbase )
        return __rdgsbase();

    rdmsrl(MSR_GS_BASE, base);

    return base;
}

static inline void wrfsbase(unsigned long base)
{
    if ( cpu_has_fsgsbase )
#ifdef HAVE_GAS_FSGSBASE
        asm volatile ( "wrfsbase %0" :: "r" (base) );
#else
        asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0" :: "a" (base) );
#endif
    else
        wrmsrl(MSR_FS_BASE, base);
}

static inline void wrgsbase(unsigned long base)
{
    if ( cpu_has_fsgsbase )
#ifdef HAVE_GAS_FSGSBASE
        asm volatile ( "wrgsbase %0" :: "r" (base) );
#else
        asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd8" :: "a" (base) );
#endif
    else
        wrmsrl(MSR_GS_BASE, base);
}

DECLARE_PER_CPU(u64, efer);
u64 read_efer(void);
void write_efer(u64 val);

DECLARE_PER_CPU(u32, ler_msr);

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_MSR_H */
