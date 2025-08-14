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

static inline uint64_t rdtsc(void)
{
    uint64_t low, high;

    __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));

    return (high << 32) | low;
}

static inline uint64_t rdtsc_ordered(void)
{
    uint64_t low, high, aux;

    /*
     * The RDTSC instruction is not serializing.  Make it dispatch serializing
     * for the purposes here by issuing LFENCE (or MFENCE if necessary) ahead
     * of it.
     *
     * RDTSCP, otoh, "does wait until all previous instructions have executed
     * and all previous loads are globally visible" (SDM) / "forces all older
     * instructions to retire before reading the timestamp counter" (APM).
     */
    alternative_io_2("lfence; rdtsc",
                     "mfence; rdtsc", X86_FEATURE_MFENCE_RDTSC,
                     "rdtscp",        X86_FEATURE_RDTSCP,
                     ASM_OUTPUT2("=a" (low), "=d" (high), "=c" (aux)),
                     /* no inputs */);

    return (high << 32) | low;
}

#define __write_tsc(val) wrmsrl(MSR_IA32_TSC, val)
#define write_tsc(val) ({                                       \
    /* Reliable TSCs are in lockstep across all CPUs. We should \
     * never write to them. */                                  \
    ASSERT(!boot_cpu_has(X86_FEATURE_TSC_RELIABLE));            \
    __write_tsc(val);                                           \
})

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
