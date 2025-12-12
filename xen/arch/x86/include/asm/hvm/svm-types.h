/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SVM types needed to form struct domain/vcpu.
 */
#ifndef X86_SVM_TYPES_H
#define X86_SVM_TYPES_H

#include <xen/types.h>

struct svm_domain {
    union {
        uint64_t raw[2];
        struct {
            uint64_t length;
            uint64_t status;
        };
    } osvw;
};

struct svm_vcpu {
    struct vmcb_struct *vmcb;
    unsigned long *msrpm;
    uint64_t vmcb_pa;
    int     launch_core;

    uint8_t vmcb_sync_state; /* enum vmcb_sync_state */

    /* VMCB has a cached instruction from #PF/#NPF Decode Assist? */
    uint8_t cached_insn_len; /* Zero if no cached instruction. */

    /*
     * Upper four bytes are undefined in the VMCB, therefore we can't use the
     * fields in the VMCB. Write a 64bit value and then read a 64bit value is
     * fine unless there's a VMRUN/VMEXIT in between which clears the upper
     * four bytes.
     */
    uint64_t guest_sysenter_cs;
    uint64_t guest_sysenter_esp;
    uint64_t guest_sysenter_eip;
};

struct nestedsvm {
    uint64_t ns_msr_hsavepa; /* MSR HSAVE_PA value */

    /*
     * l1 guest physical address of virtual vmcb used by prior VMRUN.  Needed
     * for VMCB Cleanbit emulation.
     */
    uint64_t ns_ovvmcb_pa;

    /* Cached real intercepts of the l2 guest */
    uint32_t ns_cr_intercepts;
    uint32_t ns_dr_intercepts;
    uint32_t ns_exception_intercepts;
    uint32_t ns_general1_intercepts;
    uint32_t ns_general2_intercepts;

    /* Cached real MSR permission bitmaps of the l2 guest */
    unsigned long *ns_cached_msrpm;
    /* Merged MSR permission bitmap */
    unsigned long *ns_merged_msrpm;

    /* guest physical address of virtual io permission map */
    paddr_t ns_iomap_pa, ns_oiomap_pa;
    /* Shadow io permission map */
    unsigned long *ns_iomap;

     /*
      * Cached guest_cr[0] of l1 guest while l2 guest runs.  Needed to handle
      * FPU context switching.
      */
    uint64_t ns_cr0;

    /*
     * Cache guest cr3/host cr3 the guest sets up for the l2 guest.
     * Used by Shadow-on-Shadow and Nested-on-Nested.
     * ns_vmcb_guestcr3: in l2 guest physical address space and points to
     *     the l2 guest page table
     * ns_vmcb_hostcr3: in l1 guest physical address space and points to
     *     the l1 guest nested page table
     */
    uint64_t ns_vmcb_guestcr3, ns_vmcb_hostcr3;
    uint32_t ns_asid;

    bool ns_gif;
    bool ns_hap_enabled;

    /* Only meaningful when vmexit_pending flag is set */
    struct {
        uint64_t exitcode;  /* native exitcode to inject into l1 guest */
        uint64_t exitinfo1; /* additional information to the exitcode */
        uint64_t exitinfo2; /* additional information to the exitcode */
    } ns_vmexit;

    union {
        uint32_t bytes;
        struct {
            uint32_t rflagsif:1;
            uint32_t vintrmask:1;
            uint32_t reserved:30;
        } fields;
    } ns_hostflags;
};

#endif /* X86_SVM_TYPES_H */
