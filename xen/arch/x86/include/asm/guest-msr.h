/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_GUEST_MSR_H
#define X86_GUEST_MSR_H

#include <xen/types.h>

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

struct vcpu;
struct cpu_policy;

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

uint64_t msr_spec_ctrl_valid_bits(const struct cpu_policy *cp);

#endif /* X86_GUEST_MSR_H */
