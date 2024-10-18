/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * nestedsvm.h: Nested Virtualization
 *
 * Copyright (c) 2011, Advanced Micro Devices, Inc
 */

#ifndef __X86_HVM_SVM_NESTEDHVM_PRIV_H__
#define __X86_HVM_SVM_NESTEDHVM_PRIV_H__

#include <xen/mm.h>
#include <xen/types.h>

#include <asm/hvm/vcpu.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/msr-index.h>

/* SVM specific intblk types, cannot be an enum because gcc 4.5 complains */
/* GIF cleared */
#define hvm_intblk_svm_gif      hvm_intblk_arch

#define vcpu_nestedsvm(v) (vcpu_nestedhvm(v).u.nsvm)

/* True when l1 guest enabled SVM in EFER */
#define nsvm_efer_svm_enabled(v) \
    (!!((v)->arch.hvm.guest_efer & EFER_SVME))

int nestedsvm_vmcb_map(struct vcpu *v, uint64_t vmcbaddr);
void nestedsvm_vmexit_defer(struct vcpu *v,
    uint64_t exitcode, uint64_t exitinfo1, uint64_t exitinfo2);
enum nestedhvm_vmexits
nestedsvm_vmexit_n2n1(struct vcpu *v, struct cpu_user_regs *regs);
enum nestedhvm_vmexits
nestedsvm_check_intercepts(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode);
void svm_nested_features_on_efer_update(struct vcpu *v);

/* Interface methods */
void cf_check nsvm_vcpu_destroy(struct vcpu *v);
int cf_check nsvm_vcpu_initialise(struct vcpu *v);
int cf_check nsvm_vcpu_reset(struct vcpu *v);
int nsvm_vcpu_vmrun(struct vcpu *v, struct cpu_user_regs *regs);
int cf_check nsvm_vcpu_vmexit_event(struct vcpu *v,
                                    const struct x86_event *event);
uint64_t cf_check nsvm_vcpu_hostcr3(struct vcpu *v);
bool cf_check nsvm_vmcb_guest_intercepts_event(
    struct vcpu *v, unsigned int vector, int errcode);
bool cf_check nsvm_vmcb_hap_enabled(struct vcpu *v);
enum hvm_intblk cf_check nsvm_intr_blocked(struct vcpu *v);

/* Interrupts, vGIF */
void svm_vmexit_do_clgi(struct cpu_user_regs *regs, struct vcpu *v);
void svm_vmexit_do_stgi(struct cpu_user_regs *regs, struct vcpu *v);
bool nestedsvm_gif_isset(struct vcpu *v);
int cf_check nsvm_hap_walk_L1_p2m(
    struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa, unsigned int *page_order,
    uint8_t *p2m_acc, struct npfec npfec);

#define NSVM_INTR_NOTHANDLED     3
#define NSVM_INTR_NOTINTERCEPTED 2
#define NSVM_INTR_FORCEVMEXIT    1
#define NSVM_INTR_MASKED         0

int nestedsvm_vcpu_interrupt(struct vcpu *v, const struct hvm_intack intack);

#endif /* __X86_HVM_SVM_NESTEDHVM_PRIV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
