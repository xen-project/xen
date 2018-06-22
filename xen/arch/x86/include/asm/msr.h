/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_MSR_H
#define X86_MSR_H

#include <xen/errno.h>
#include <xen/percpu.h>

#include <asm/alternative.h>
#include <asm/asm_defns.h>
#include <asm/msr-index.h>

/*
 * MSR APIs.  Most logic is expected to use:
 *
 *   uint64_t foo = rdmsr(MSR_BAR);
 *   wrmsrns(MSR_BAR, foo);
 *
 * and, if architectural serialisaition is necessary, or there are other
 * reasons that WRMSRNS is inapplicable, then:
 *
 *   wrmsr(MSR_BAR, foo);
 *
 * In addition, *_safe() wrappers exist to cope gracefully with a #GP.
 *
 *
 * All legacy forms are to be phased out:
 *
 *  rdmsrl(MSR_FOO, val);
 *  wrmsrl(MSR_FOO, val);
 */

static always_inline uint64_t rdmsr(unsigned int msr)
{
    unsigned long lo, hi;

    asm volatile ( "rdmsr"
                   : "=a" (lo), "=d" (hi)
                   : "c" (msr) );

    return (hi << 32) | lo;
}

#define rdmsrl(msr,val) do { unsigned long a__,b__; \
       __asm__ __volatile__("rdmsr" \
			    : "=a" (a__), "=d" (b__) \
			    : "c" (msr)); \
       val = a__ | ((u64)b__<<32); \
} while(0)

static inline void wrmsr(unsigned int msr, uint64_t val)
{
    uint32_t lo = val, hi = val >> 32;

    asm volatile ( "wrmsr" :: "a" (lo), "d" (hi), "c" (msr) );
}
#define wrmsrl(msr, val) wrmsr(msr, val)

/* Non-serialising WRMSR, when available.  Falls back to a serialising WRMSR. */
static inline void wrmsrns(uint32_t msr, uint64_t val)
{
    uint32_t lo = val, hi = val >> 32;

    /*
     * WRMSR is 2 bytes.  WRMSRNS is 3 bytes.  Pad WRMSR with a redundant CS
     * prefix to avoid a trailing NOP.
     */
    alternative_input(".byte 0x2e; wrmsr",
                      ".byte 0x0f,0x01,0xc6", X86_FEATURE_WRMSRNS,
                      "c" (msr), "a" (lo), "d" (hi));
}

/* rdmsr with exception handling */
static inline int rdmsr_safe(unsigned int msr, uint64_t *val)
{
    uint64_t lo, hi;

#ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
    asm_inline goto (
        "1: rdmsr\n\t"
        _ASM_EXTABLE(1b, %l[fault])
        : "=a" (lo), "=d" (hi)
        : "c" (msr)
        :
        : fault );

    *val = lo | (hi << 32);

    return 0;

 fault:
    return -EFAULT;
#else
    int rc;

    asm_inline volatile (
        "1: rdmsr\n2:\n"
        ".section .fixup,\"ax\"\n"
        "3: xorl %k0,%k0\n\t"
        "   xorl %k1,%k1\n\t"
        "   movl %5,%2\n\t"
        "   jmp 2b\n\t"
        ".previous"
        _ASM_EXTABLE(1b, 3b)
        : "=a" (lo), "=d" (hi), "=&r" (rc)
        : "c" (msr), "2" (0), "i" (-EFAULT) );

    *val = lo | (hi << 32);

    return rc;
#endif
}

/* wrmsr with exception handling */
static inline int wrmsr_safe(unsigned int msr, uint64_t val)
{
    uint32_t lo = val, hi = val >> 32;

    asm_inline goto (
        "1: wrmsr\n\t"
        _ASM_EXTABLE(1b, %l[fault])
        :
        : "a" (lo), "c" (msr), "d" (hi)
        :
        : fault );

    return 0;

 fault:
    return -EFAULT;
}

DECLARE_PER_CPU(uint64_t, efer);
static inline uint64_t read_efer(void)
{
    return this_cpu(efer);
}

static inline void write_efer(uint64_t val)
{
    this_cpu(efer) = val;
    wrmsrl(MSR_EFER, val);
}

DECLARE_PER_CPU(uint32_t, tsc_aux);

/* Lazy update of MSR_TSC_AUX */
static inline void wrmsr_tsc_aux(uint32_t val)
{
    uint32_t *this_tsc_aux = &this_cpu(tsc_aux);

    if ( *this_tsc_aux != val )
    {
        wrmsrns(MSR_TSC_AUX, val);
        *this_tsc_aux = val;
    }
}

#endif /* X86_MSR_H */
