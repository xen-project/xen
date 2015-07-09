#ifndef __XEN_PUBLIC_ARCH_X86_PMU_H__
#define __XEN_PUBLIC_ARCH_X86_PMU_H__

/* x86-specific PMU definitions */

/* AMD PMU registers and structures */
struct xen_pmu_amd_ctxt {
    /* Offsets to counter and control MSRs (relative to xen_pmu_arch.c.amd) */
    uint32_t counters;
    uint32_t ctrls;

    /* Counter MSRs */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint64_t regs[];
#elif defined(__GNUC__)
    uint64_t regs[0];
#endif
};
typedef struct xen_pmu_amd_ctxt xen_pmu_amd_ctxt_t;
DEFINE_XEN_GUEST_HANDLE(xen_pmu_amd_ctxt_t);

/* Intel PMU registers and structures */
struct xen_pmu_cntr_pair {
    uint64_t counter;
    uint64_t control;
};
typedef struct xen_pmu_cntr_pair xen_pmu_cntr_pair_t;
DEFINE_XEN_GUEST_HANDLE(xen_pmu_cntr_pair_t);

struct xen_pmu_intel_ctxt {
   /*
    * Offsets to fixed and architectural counter MSRs (relative to
    * xen_pmu_arch.c.intel)
    */
    uint32_t fixed_counters;
    uint32_t arch_counters;

    /* PMU registers */
    uint64_t global_ctrl;
    uint64_t global_ovf_ctrl;
    uint64_t global_status;
    uint64_t fixed_ctrl;
    uint64_t ds_area;
    uint64_t pebs_enable;
    uint64_t debugctl;

    /* Fixed and architectural counter MSRs */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint64_t regs[];
#elif defined(__GNUC__)
    uint64_t regs[0];
#endif
};
typedef struct xen_pmu_intel_ctxt xen_pmu_intel_ctxt_t;
DEFINE_XEN_GUEST_HANDLE(xen_pmu_intel_ctxt_t);

/* Sampled domain's registers */
struct xen_pmu_regs {
    uint64_t ip;
    uint64_t sp;
    uint64_t flags;
    uint16_t cs;
    uint16_t ss;
    uint8_t cpl;
    uint8_t pad[3];
};
typedef struct xen_pmu_regs xen_pmu_regs_t;
DEFINE_XEN_GUEST_HANDLE(xen_pmu_regs_t);

/* PMU flags */
#define PMU_CACHED         (1<<0) /* PMU MSRs are cached in the context */

/*
 * Architecture-specific information describing state of the processor at
 * the time of PMU interrupt.
 * Fields of this structure marked as RW for guest should only be written by
 * the guest when PMU_CACHED bit in pmu_flags is set (which is done by the
 * hypervisor during PMU interrupt). Hypervisor will read updated data in
 * XENPMU_flush hypercall and clear PMU_CACHED bit.
 */
struct xen_pmu_arch {
    union {
        /*
         * Processor's registers at the time of interrupt.
         * WO for hypervisor, RO for guests.
         */
        struct xen_pmu_regs regs;
        /* Padding for adding new registers to xen_pmu_regs in the future */
#define XENPMU_REGS_PAD_SZ  64
        uint8_t pad[XENPMU_REGS_PAD_SZ];
    } r;

    /* WO for hypervisor, RO for guest */
    uint64_t pmu_flags;

    /* Placeholder for APIC LVTPC register */
    uint64_t lvtpc_pad;

    /* Placeholder for vendor-specific PMU registers */
#define XENPMU_CTXT_PAD_SZ  128
    uint64_t pmu_regs_pad[XENPMU_CTXT_PAD_SZ / 8];
};
typedef struct xen_pmu_arch xen_pmu_arch_t;
DEFINE_XEN_GUEST_HANDLE(xen_pmu_arch_t);

#endif /* __XEN_PUBLIC_ARCH_X86_PMU_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

