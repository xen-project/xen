#ifndef __ASM_MSR_H
#define __ASM_MSR_H

#include "msr-index.h"

#include <xen/types.h>
#include <xen/percpu.h>
#include <xen/errno.h>
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/asm_defns.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>

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

static inline void wrmsrl(unsigned int msr, uint64_t val)
{
        uint32_t lo = val, hi = val >> 32;

        wrmsr(msr, lo, hi);
}

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
#define rdmsr_safe(msr,val) ({\
    int rc_; \
    uint64_t lo_, hi_; \
    __asm__ __volatile__( \
        "1: rdmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: xorl %k0,%k0\n; xorl %k1,%k1\n" \
        "   movl %5,%2\n; jmp 2b\n" \
        ".previous\n" \
        _ASM_EXTABLE(1b, 3b) \
        : "=a" (lo_), "=d" (hi_), "=&r" (rc_) \
        : "c" (msr), "2" (0), "i" (-EFAULT)); \
    val = lo_ | (hi_ << 32); \
    rc_; })

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

static inline uint64_t msr_fold(const struct cpu_user_regs *regs)
{
    return (regs->rdx << 32) | regs->eax;
}

static inline void msr_split(struct cpu_user_regs *regs, uint64_t val)
{
    regs->rdx = val >> 32;
    regs->rax = (uint32_t)val;
}

#define rdpmc(counter,low,high) \
     __asm__ __volatile__("rdpmc" \
			  : "=a" (low), "=d" (high) \
			  : "c" (counter))

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
        wrmsr(MSR_TSC_AUX, val, 0);
        *this_tsc_aux = val;
    }
}

#endif /* __ASM_MSR_H */
