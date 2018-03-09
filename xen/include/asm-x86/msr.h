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
    uint32_t low, high;

    __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));

    return ((uint64_t)high << 32) | low;
}

static inline uint64_t rdtsc_ordered(void)
{
	/*
	 * The RDTSC instruction is not ordered relative to memory access.
	 * The Intel SDM and the AMD APM are both vague on this point, but
	 * empirically an RDTSC instruction can be speculatively executed
	 * before prior loads.  An RDTSC immediately after an appropriate
	 * barrier appears to be ordered as a normal load, that is, it
	 * provides the same ordering guarantees as reading from a global
	 * memory location that some other imaginary CPU is updating
	 * continuously with a time stamp.
	 */
	alternative("lfence", "mfence", X86_FEATURE_MFENCE_RDTSC);
	return rdtsc();
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

static inline unsigned long __rdfsbase(void)
{
    unsigned long base;

#ifdef HAVE_AS_FSGSBASE
    asm volatile ( "rdfsbase %0" : "=r" (base) );
#else
    asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0" : "=a" (base) );
#endif

    return base;
}

static inline unsigned long __rdgsbase(void)
{
    unsigned long base;

#ifdef HAVE_AS_FSGSBASE
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

static inline unsigned long rdgsshadow(void)
{
    unsigned long base;

    if ( cpu_has_fsgsbase )
    {
        asm volatile ( "swapgs" );
        base = __rdgsbase();
        asm volatile ( "swapgs" );
    }
    else
        rdmsrl(MSR_SHADOW_GS_BASE, base);

    return base;
}

static inline void wrfsbase(unsigned long base)
{
    if ( cpu_has_fsgsbase )
#ifdef HAVE_AS_FSGSBASE
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
#ifdef HAVE_AS_FSGSBASE
        asm volatile ( "wrgsbase %0" :: "r" (base) );
#else
        asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd8" :: "a" (base) );
#endif
    else
        wrmsrl(MSR_GS_BASE, base);
}

static inline void wrgsshadow(unsigned long base)
{
    if ( cpu_has_fsgsbase )
    {
        asm volatile ( "swapgs\n\t"
#ifdef HAVE_AS_FSGSBASE
                       "wrgsbase %0\n\t"
                       "swapgs"
                       :: "r" (base) );
#else
                       ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd8\n\t"
                       "swapgs"
                       :: "a" (base) );
#endif
    }
    else
        wrmsrl(MSR_SHADOW_GS_BASE, base);
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

DECLARE_PER_CPU(u32, ler_msr);

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

/* MSR policy object for shared per-domain MSRs */
struct msr_domain_policy
{
    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    struct {
        bool available; /* This MSR is non-architectural */
        bool cpuid_faulting;
    } plaform_info;
};

/* RAW msr domain policy: contains the actual values from H/W MSRs */
extern struct msr_domain_policy raw_msr_domain_policy;
/*
 * HOST msr domain policy: features that Xen actually decided to use,
 * a subset of RAW policy.
 */
extern struct msr_domain_policy host_msr_domain_policy;

/* MSR policy object for per-vCPU MSRs */
struct msr_vcpu_policy
{
    /* 0x00000048 - MSR_SPEC_CTRL */
    struct {
        /*
         * Only the bottom two bits are defined, so no need to waste space
         * with uint64_t at the moment, but use uint32_t for the convenience
         * of the assembly code.
         */
        uint32_t raw;
    } spec_ctrl;

    /* 0x00000140  MSR_INTEL_MISC_FEATURES_ENABLES */
    struct {
        bool available; /* This MSR is non-architectural */
        bool cpuid_faulting;
    } misc_features_enables;
};

void init_guest_msr_policy(void);
int init_domain_msr_policy(struct domain *d);
int init_vcpu_msr_policy(struct vcpu *v);

/*
 * Below functions can return X86EMUL_UNHANDLEABLE which means that MSR is
 * not (yet) handled by it and must be processed by legacy handlers. Such
 * behaviour is needed for transition period until all rd/wrmsr are handled
 * by the new MSR infrastructure.
 *
 * These functions are also used by the migration logic, so need to cope with
 * being used outside of v's context.
 */
int guest_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val);
int guest_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val);

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_MSR_H */
