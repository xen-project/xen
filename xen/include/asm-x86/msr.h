#ifndef __ASM_MSR_H
#define __ASM_MSR_H

#include "msr-index.h"

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/percpu.h>
#include <xen/errno.h>

#define rdmsr(msr,val1,val2) \
     __asm__ __volatile__("rdmsr" \
			  : "=a" (val1), "=d" (val2) \
			  : "c" (msr))

#define rdmsrl(msr,val) do { unsigned long a__,b__; \
       __asm__ __volatile__("rdmsr" \
			    : "=a" (a__), "=d" (b__) \
			    : "c" (msr)); \
       val = a__ | ((u64)b__<<32); \
} while(0);

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
        ".section __ex_table,\"a\"\n" \
        "   "__FIXUP_ALIGN"\n" \
        "   "__FIXUP_WORD" 1b,3b\n" \
        ".previous\n" \
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
        ".section __ex_table,\"a\"\n"
        "   "__FIXUP_ALIGN"\n"
        "   "__FIXUP_WORD" 1b,3b\n"
        ".previous\n"
        : "=&r" (_rc)
        : "c" (msr), "a" (lo), "d" (hi), "0" (0), "i" (-EFAULT));
    return _rc;
}

#define rdtsc(low,high) \
     __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))

#define rdtscl(low) \
     __asm__ __volatile__("rdtsc" : "=a" (low) : : "edx")

#if defined(__i386__)
#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))
#elif defined(__x86_64__)
#define rdtscll(val) do { \
     unsigned int a,d; \
     asm volatile("rdtsc" : "=a" (a), "=d" (d)); \
     (val) = ((unsigned long)a) | (((unsigned long)d)<<32); \
} while(0)
#endif

#define write_tsc(val) wrmsrl(MSR_IA32_TSC, val)

#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)

#define rdpmc(counter,low,high) \
     __asm__ __volatile__("rdpmc" \
			  : "=a" (low), "=d" (high) \
			  : "c" (counter))


DECLARE_PER_CPU(u64, efer);
u64 read_efer(void);
void write_efer(u64 val);

DECLARE_PER_CPU(u32, ler_msr);

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_MSR_H */
