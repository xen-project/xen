/* SPDX-License-Identifier: GPL-2.0 */
/*
 * svm.h: SVM Architecture related definitions
 *
 * Copyright (c) 2005, AMD Corporation.
 * Copyright (c) 2004, Intel Corporation.
 */

#ifndef __X86_HVM_SVM_SVM_PRIV_H__
#define __X86_HVM_SVM_SVM_PRIV_H__

#include <xen/types.h>

struct cpu_user_regs;

unsigned long *svm_msrbit(unsigned long *msr_bitmap, uint32_t msr);
void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len);

static inline void svm_vmload_pa(paddr_t vmcb)
{
    asm volatile (
        ".byte 0x0f,0x01,0xda" /* vmload */
        : : "a" (vmcb) : "memory" );
}

static inline void svm_vmsave_pa(paddr_t vmcb)
{
    asm volatile (
        ".byte 0x0f,0x01,0xdb" /* vmsave */
        : : "a" (vmcb) : "memory" );
}

static inline void svm_invlpga(unsigned long linear, uint32_t asid)
{
    asm volatile (
        ".byte 0x0f,0x01,0xdf"
        : /* output */
        : /* input */
        "a" (linear), "c" (asid) );
}

/* TSC rate */
#define DEFAULT_TSC_RATIO       0x0000000100000000ULL
#define TSC_RATIO_RSVD_BITS     0xffffff0000000000ULL

/* EXITINFO1 fields on NPT faults */
#define _NPT_PFEC_with_gla     32
#define NPT_PFEC_with_gla      (1UL<<_NPT_PFEC_with_gla)
#define _NPT_PFEC_in_gpt       33
#define NPT_PFEC_in_gpt        (1UL<<_NPT_PFEC_in_gpt)

#endif /* __X86_HVM_SVM_SVM_PRIV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
