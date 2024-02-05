/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svm.h: SVM Architecture related definitions
 * Copyright (c) 2005, AMD Corporation.
 * Copyright (c) 2004, Intel Corporation.
 *
 */

#ifndef __ASM_X86_HVM_SVM_H__
#define __ASM_X86_HVM_SVM_H__

/*
 * PV context switch helpers.  Prefetching the VMCB area itself has been shown
 * to be useful for performance.
 *
 * Must only be used for NUL FS/GS, as the segment attributes/limits are not
 * read from the GDT/LDT.
 */
void svm_load_segs_prefetch(void);
bool svm_load_segs(unsigned int ldt_ents, unsigned long ldt_base,
                   unsigned long fs_base, unsigned long gs_base,
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
#define SVM_FEATURE_SSS           19 /* NPT Supervisor Shadow Stacks */
#define SVM_FEATURE_SPEC_CTRL     20 /* MSR_SPEC_CTRL virtualisation */

static inline bool cpu_has_svm_feature(unsigned int feat)
{
    return svm_feature_flags & (1u << feat);
}
#define cpu_has_svm_npt       cpu_has_svm_feature(SVM_FEATURE_NPT)
#define cpu_has_svm_lbrv      cpu_has_svm_feature(SVM_FEATURE_LBRV)
#define cpu_has_svm_svml      cpu_has_svm_feature(SVM_FEATURE_SVML)
#define cpu_has_svm_nrips     cpu_has_svm_feature(SVM_FEATURE_NRIPS)
#define cpu_has_svm_cleanbits cpu_has_svm_feature(SVM_FEATURE_VMCBCLEAN)
#define cpu_has_svm_flushbyasid cpu_has_svm_feature(SVM_FEATURE_FLUSHBYASID)
#define cpu_has_svm_decode    cpu_has_svm_feature(SVM_FEATURE_DECODEASSISTS)
#define cpu_has_svm_vgif      cpu_has_svm_feature(SVM_FEATURE_VGIF)
#define cpu_has_pause_filter  cpu_has_svm_feature(SVM_FEATURE_PAUSEFILTER)
#define cpu_has_pause_thresh  cpu_has_svm_feature(SVM_FEATURE_PAUSETHRESH)
#define cpu_has_tsc_ratio     cpu_has_svm_feature(SVM_FEATURE_TSCRATEMSR)
#define cpu_has_svm_vloadsave cpu_has_svm_feature(SVM_FEATURE_VLOADSAVE)
#define cpu_has_svm_sss       cpu_has_svm_feature(SVM_FEATURE_SSS)
#define cpu_has_svm_spec_ctrl cpu_has_svm_feature(SVM_FEATURE_SPEC_CTRL)

#endif /* __ASM_X86_HVM_SVM_H__ */
