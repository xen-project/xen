/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmcb.h: VMCB related definitions
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc
 * Copyright (c) 2004, Intel Corporation.
 *
 */
#ifndef __ASM_X86_HVM_SVM_VMCB_H__
#define __ASM_X86_HVM_SVM_VMCB_H__

#include <xen/types.h>

struct svm_domain {
    /* OSVW MSRs */
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
    u64    vmcb_pa;
    unsigned long *msrpm;
    int    launch_core;

    uint8_t vmcb_sync_state; /* enum vmcb_sync_state */

    /* VMCB has a cached instruction from #PF/#NPF Decode Assist? */
    uint8_t cached_insn_len; /* Zero if no cached instruction. */

    /* Upper four bytes are undefined in the VMCB, therefore we can't
     * use the fields in the VMCB. Write a 64bit value and then read a 64bit
     * value is fine unless there's a VMRUN/VMEXIT in between which clears
     * the upper four bytes.
     */
    uint64_t guest_sysenter_cs;
    uint64_t guest_sysenter_esp;
    uint64_t guest_sysenter_eip;
};

#endif /* ASM_X86_HVM_SVM_VMCS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
