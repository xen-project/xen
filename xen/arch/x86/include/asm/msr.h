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

static inline void wrmsrl(unsigned int msr, __u64 val)
{
        __u32 lo, hi;
        lo = (__u32)val;
        hi = (__u32)(val >> 32);
        wrmsr(msr, lo, hi);
}

/* Non-serialising WRMSR, when available.  Falls back to a serialising WRMSR. */
static inline void wrmsr_ns(uint32_t msr, uint32_t lo, uint32_t hi)
{
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

static inline void __wrfsbase(unsigned long base)
{
#ifdef HAVE_AS_FSGSBASE
    asm volatile ( "wrfsbase %0" :: "r" (base) );
#else
    asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd0" :: "a" (base) );
#endif
}

static inline void __wrgsbase(unsigned long base)
{
#ifdef HAVE_AS_FSGSBASE
    asm volatile ( "wrgsbase %0" :: "r" (base) );
#else
    asm volatile ( ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd8" :: "a" (base) );
#endif
}

static inline unsigned long read_fs_base(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdfsbase();

    rdmsrl(MSR_FS_BASE, base);

    return base;
}

static inline unsigned long read_gs_base(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdgsbase();

    rdmsrl(MSR_GS_BASE, base);

    return base;
}

static inline unsigned long read_gs_shadow(void)
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

static inline void write_fs_base(unsigned long base)
{
    if ( read_cr4() & X86_CR4_FSGSBASE )
        __wrfsbase(base);
    else
        wrmsrl(MSR_FS_BASE, base);
}

static inline void write_gs_base(unsigned long base)
{
    if ( read_cr4() & X86_CR4_FSGSBASE )
        __wrgsbase(base);
    else
        wrmsrl(MSR_GS_BASE, base);
}

static inline void write_gs_shadow(unsigned long base)
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

uint64_t msr_spec_ctrl_valid_bits(const struct cpu_policy *cp);

/* Container object for per-vCPU MSRs */
struct vcpu_msrs
{
    /*
     * 0x00000048 - MSR_SPEC_CTRL
     * 0xc001011f - MSR_VIRT_SPEC_CTRL (if X86_FEATURE_AMD_SSBD)
     *
     * For PV guests, this holds the guest kernel value.  It is accessed on
     * every entry/exit path.
     *
     * For VT-x guests, one of two situations exist:
     *
     * - If hardware supports virtualized MSR_SPEC_CTRL, it is active by
     *   default and the guest value lives in the VMCS.
     * - Otherwise, the guest value is held in the MSR load/save list.
     *
     * For SVM, the guest value lives in the VMCB, and hardware saves/restores
     * the host value automatically.  However, guests run with the OR of the
     * host and guest value, which allows Xen to set protections behind the
     * guest's back.
     *
     * We must clear/restore Xen's value before/after VMRUN to avoid unduly
     * influencing the guest.  In order to support "behind the guest's back"
     * protections, we load this value (commonly 0) before VMRUN.
     *
     * Once of such "behind the guest's back" usages is setting SPEC_CTRL.SSBD
     * if the guest sets VIRT_SPEC_CTRL.SSBD.
     */
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

    /*
     * 0x00000560 ... 57x - MSR_RTIT_*
     *
     * "Real Time Instruction Trace", now called Processor Trace.
     *
     * These MSRs are not exposed to guests.  They are controlled by Xen
     * behind the scenes, when vmtrace is enabled for the domain.
     *
     * MSR_RTIT_OUTPUT_BASE not stored here.  It is fixed per vcpu, and
     * derived from v->vmtrace.buf.
     */
    struct {
        /*
         * Placed in the MSR load/save lists.  Only modified by hypercall in
         * the common case.
         */
        uint64_t ctl;

        /*
         * Updated by hardware in non-root mode.  Synchronised here on vcpu
         * context switch.
         */
        uint64_t status;
        union {
            uint64_t output_mask;
            struct {
                uint32_t output_limit;
                uint32_t output_offset;
            };
        };
    } rtit;

    /*
     * 0x000006e1 - MSR_PKRS - Protection Key Supervisor.
     *
     * Exposed R/W to guests.  Xen doesn't use PKS yet, so only context
     * switched per vcpu.  When in current context, live value is in hardware,
     * and this value is stale.
     */
    uint32_t pkrs;

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
     * 0xc001011f - MSR_VIRT_SPEC_CTRL (if !X86_FEATURE_AMD_SSBD)
     *
     * AMD only, used on Zen1 and older hardware (pre-AMD_SSBD).  Holds the
     * the guests value.
     *
     * In the default case, Xen doesn't protect itself from SSB, and guests
     * are expected to use VIRT_SPEC_CTRL.SSBD=1 sparingly.  Xen therefore
     * runs in the guest kernel's choice of SSBD.
     *
     * However, if the global enable `spec-ctrl=ssbd` is selected, hardware is
     * always configured with SSBD=1 and the guest's setting is never loaded
     * into hardware.
     */
    struct {
        uint32_t raw;
    } virt_spec_ctrl;

    /*
     * 0xc00110{27,19-1b} MSR_AMD64_DR{0-3}_ADDRESS_MASK
     *
     * Loaded into hardware for guests which have active %dr7 settings.
     * Furthermore, HVM guests are offered direct access, meaning that the
     * values here may be stale in current context.
     */
    uint32_t dr_mask[4];
};

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
