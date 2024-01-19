/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * nestedsvm.h: Nested Virtualization
 * Copyright (c) 2011, Advanced Micro Devices, Inc
 *
 */
#ifndef __ASM_X86_HVM_SVM_NESTEDSVM_H__
#define __ASM_X86_HVM_SVM_NESTEDSVM_H__

#include <xen/types.h>

struct nestedsvm {
    bool ns_gif;
    uint64_t ns_msr_hsavepa; /* MSR HSAVE_PA value */

    /* l1 guest physical address of virtual vmcb used by prior VMRUN.
     * Needed for VMCB Cleanbit emulation.
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

    uint64_t ns_cr0; /* Cached guest_cr[0] of l1 guest while l2 guest runs.
                      * Needed to handle FPU context switching */

    /* Cache guest cr3/host cr3 the guest sets up for the l2 guest.
     * Used by Shadow-on-Shadow and Nested-on-Nested.
     * ns_vmcb_guestcr3: in l2 guest physical address space and points to
     *     the l2 guest page table
     * ns_vmcb_hostcr3: in l1 guest physical address space and points to
     *     the l1 guest nested page table
     */
    uint64_t ns_vmcb_guestcr3, ns_vmcb_hostcr3;
    uint32_t ns_asid;

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
            uint32_t rflagsif: 1;
            uint32_t vintrmask: 1;
            uint32_t reserved: 30;
        } fields;
    } ns_hostflags;
};

#endif /* ASM_X86_HVM_SVM_NESTEDSVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
