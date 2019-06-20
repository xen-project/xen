/*
 * svm.h: SVM Architecture related definitions
 * Copyright (c) 2005, AMD Corporation.
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __ASM_X86_HVM_SVM_H__
#define __ASM_X86_HVM_SVM_H__

#include <xen/types.h>

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
        "a" (linear), "c" (asid));
}

unsigned long *svm_msrbit(unsigned long *msr_bitmap, uint32_t msr);
void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len);
void svm_update_guest_cr(struct vcpu *, unsigned int cr, unsigned int flags);

/*
 * PV context switch helper. Calls with zero ldt_base request a prefetch of
 * the VMCB area to be loaded from, instead of an actual load of state.
 */
bool svm_load_segs(unsigned int ldt_ents, unsigned long ldt_base,
                   unsigned int fs_sel, unsigned long fs_base,
                   unsigned int gs_sel, unsigned long gs_base,
                   unsigned long gs_shadow);

extern u32 svm_feature_flags;

#define SVM_FEATURE_NPT            0 /* Nested page table support */
#define SVM_FEATURE_LBRV           1 /* LBR virtualization support */
#define SVM_FEATURE_SVML           2 /* SVM locking MSR support */
#define SVM_FEATURE_NRIPS          3 /* Next RIP save on VMEXIT support */
#define SVM_FEATURE_TSCRATEMSR     4 /* TSC ratio MSR support */
#define SVM_FEATURE_VMCBCLEAN      5 /* VMCB clean bits support */
#define SVM_FEATURE_FLUSHBYASID    6 /* TLB flush by ASID support */
#define SVM_FEATURE_DECODEASSISTS  7 /* Decode assists support */
#define SVM_FEATURE_PAUSEFILTER   10 /* Pause intercept filter support */
#define SVM_FEATURE_PAUSETHRESH   12 /* Pause intercept filter support */
#define SVM_FEATURE_VLOADSAVE     15 /* virtual vmload/vmsave */
#define SVM_FEATURE_VGIF          16 /* Virtual GIF */

#define cpu_has_svm_feature(f) (svm_feature_flags & (1u << (f)))
#define cpu_has_svm_npt       cpu_has_svm_feature(SVM_FEATURE_NPT)
#define cpu_has_svm_lbrv      cpu_has_svm_feature(SVM_FEATURE_LBRV)
#define cpu_has_svm_svml      cpu_has_svm_feature(SVM_FEATURE_SVML)
#define cpu_has_svm_nrips     cpu_has_svm_feature(SVM_FEATURE_NRIPS)
#define cpu_has_svm_cleanbits cpu_has_svm_feature(SVM_FEATURE_VMCBCLEAN)
#define cpu_has_svm_decode    cpu_has_svm_feature(SVM_FEATURE_DECODEASSISTS)
#define cpu_has_svm_vgif      cpu_has_svm_feature(SVM_FEATURE_VGIF)
#define cpu_has_pause_filter  cpu_has_svm_feature(SVM_FEATURE_PAUSEFILTER)
#define cpu_has_pause_thresh  cpu_has_svm_feature(SVM_FEATURE_PAUSETHRESH)
#define cpu_has_tsc_ratio     cpu_has_svm_feature(SVM_FEATURE_TSCRATEMSR)
#define cpu_has_svm_vloadsave cpu_has_svm_feature(SVM_FEATURE_VLOADSAVE)

#define SVM_PAUSEFILTER_INIT    4000
#define SVM_PAUSETHRESH_INIT    1000

/* TSC rate */
#define DEFAULT_TSC_RATIO       0x0000000100000000ULL
#define TSC_RATIO_RSVD_BITS     0xffffff0000000000ULL

extern void svm_host_osvw_reset(void);
extern void svm_host_osvw_init(void);

/* EXITINFO1 fields on NPT faults */
#define _NPT_PFEC_with_gla     32
#define NPT_PFEC_with_gla      (1UL<<_NPT_PFEC_with_gla)
#define _NPT_PFEC_in_gpt       33
#define NPT_PFEC_in_gpt        (1UL<<_NPT_PFEC_in_gpt)

#endif /* __ASM_X86_HVM_SVM_H__ */
