#ifndef __ASM_MSR_H
#define __ASM_MSR_H

#include "msr-index.h"

#include <xen/types.h>
#include <xen/percpu.h>
#include <xen/errno.h>

#include <xen/lib/x86/msr.h>

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

static inline void wrmsrl(unsigned int msr, __u64 val)
{
        __u32 lo, hi;
        lo = (__u32)val;
        hi = (__u32)(val >> 32);
        wrmsr(msr, lo, hi);
}

/* rdmsr with exception handling */
#define rdmsr_safe(msr,val) ({\
    int rc_; \
    uint32_t lo_, hi_; \
    __asm__ __volatile__( \
        "1: rdmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: xorl %0,%0\n; xorl %1,%1\n" \
        "   movl %5,%2\n; jmp 2b\n" \
        ".previous\n" \
        _ASM_EXTABLE(1b, 3b) \
        : "=a" (lo_), "=d" (hi_), "=&r" (rc_) \
        : "c" (msr), "2" (0), "i" (-EFAULT)); \
    val = lo_ | ((uint64_t)hi_ << 32); \
    rc_; })

/* wrmsr with exception handling */
static inline int wrmsr_safe(unsigned int msr, uint64_t val)
{
    int rc;
    uint32_t lo, hi;
    lo = (uint32_t)val;
    hi = (uint32_t)(val >> 32);

    __asm__ __volatile__(
        "1: wrmsr\n2:\n"
        ".section .fixup,\"ax\"\n"
        "3: movl %5,%0\n; jmp 2b\n"
        ".previous\n"
        _ASM_EXTABLE(1b, 3b)
        : "=&r" (rc)
        : "c" (msr), "a" (lo), "d" (hi), "0" (0), "i" (-EFAULT));
    return rc;
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

/*
 * On hardware supporting FSGSBASE, the value loaded into hardware is the
 * guest kernel's choice for 64bit PV guests (Xen's choice for Idle, HVM and
 * 32bit PV).
 *
 * Therefore, the {RD,WR}{FS,GS}BASE instructions are only safe to use if
 * %cr4.fsgsbase is set.
 */
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

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdfsbase();

    rdmsrl(MSR_FS_BASE, base);

    return base;
}

static inline unsigned long rdgsbase(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdgsbase();

    rdmsrl(MSR_GS_BASE, base);

    return base;
}

static inline unsigned long rdgsshadow(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
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
    if ( read_cr4() & X86_CR4_FSGSBASE )
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
    if ( read_cr4() & X86_CR4_FSGSBASE )
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
    if ( read_cr4() & X86_CR4_FSGSBASE )
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

extern unsigned int ler_msr;

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

extern struct msr_policy     raw_msr_policy,
                            host_msr_policy,
                          pv_max_msr_policy,
                          pv_def_msr_policy,
                         hvm_max_msr_policy,
                         hvm_def_msr_policy;

/* Container object for per-vCPU MSRs */
struct vcpu_msrs
{
    /* 0x00000048 - MSR_SPEC_CTRL */
    struct {
        uint32_t raw;
    } spec_ctrl;

    /*
     * 0x00000140 - MSR_INTEL_MISC_FEATURES_ENABLES
     *
     * This MSR is non-architectural, but for simplicy we allow it to be read
     * unconditionally.  The CPUID Faulting bit is the only writeable bit, and
     * only if enumerated by MSR_PLATFORM_INFO.
     */
    union {
        uint32_t raw;
        struct {
            bool cpuid_faulting:1;
        };
    } misc_features_enables;

    /* 0x00000da0 - MSR_IA32_XSS */
    struct {
        uint64_t raw;
    } xss;

    /*
     * 0xc0000103 - MSR_TSC_AUX
     *
     * Value is guest chosen, and always loaded in vcpu context.  Guests have
     * no direct MSR access, and the value is accessible to userspace with the
     * RDTSCP and RDPID instructions.
     */
    uint32_t tsc_aux;

    /*
     * 0xc00110{27,19-1b} MSR_AMD64_DR{0-3}_ADDRESS_MASK
     *
     * Loaded into hardware for guests which have active %dr7 settings.
     * Furthermore, HVM guests are offered direct access, meaning that the
     * values here may be stale in current context.
     */
    uint32_t dr_mask[4];
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
int guest_rdmsr(struct vcpu *v, uint32_t msr, uint64_t *val);
int guest_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val);

#endif /* __ASM_MSR_H */
