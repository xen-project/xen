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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#ifndef __ASM_X86_HVM_SVM_H__
#define __ASM_X86_HVM_SVM_H__

#include <xen/sched.h>
#include <asm/types.h>
#include <asm/regs.h>
#include <asm/processor.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/i387.h>

extern void svm_dump_vmcb(const char *from, struct vmcb_struct *vmcb);
extern void svm_do_launch(struct vcpu *v);
extern void arch_svm_do_resume(struct vcpu *v);

extern u64 root_vmcb_pa[NR_CPUS];

static inline int svm_long_mode_enabled(struct vcpu *v)
{
    u64 guest_efer = v->arch.hvm_svm.cpu_shadow_efer;
    return guest_efer & EFER_LMA;
}

static inline int svm_lme_is_set(struct vcpu *v)
{
    u64 guest_efer = v->arch.hvm_svm.cpu_shadow_efer;
    return guest_efer & EFER_LME;
}

static inline int svm_cr4_pae_is_set(struct vcpu *v)
{
    unsigned long guest_cr4 = v->arch.hvm_svm.cpu_shadow_cr4;
    return guest_cr4 & X86_CR4_PAE;
}

static inline int svm_paging_enabled(struct vcpu *v)
{
    unsigned long guest_cr0 = v->arch.hvm_svm.cpu_shadow_cr0;
    return (guest_cr0 & X86_CR0_PE) && (guest_cr0 & X86_CR0_PG);
}

static inline int svm_pae_enabled(struct vcpu *v)
{
    unsigned long guest_cr4 = v->arch.hvm_svm.cpu_shadow_cr4;
    return svm_paging_enabled(v) && (guest_cr4 & X86_CR4_PAE);
}

static inline int svm_pgbit_test(struct vcpu *v)
{
    return v->arch.hvm_svm.cpu_shadow_cr0 & X86_CR0_PG;
}

#define SVM_REG_EAX (0) 
#define SVM_REG_ECX (1) 
#define SVM_REG_EDX (2) 
#define SVM_REG_EBX (3) 
#define SVM_REG_ESP (4) 
#define SVM_REG_EBP (5) 
#define SVM_REG_ESI (6) 
#define SVM_REG_EDI (7) 
#define SVM_REG_R8  (8)
#define SVM_REG_R9  (9)
#define SVM_REG_R10 (10)
#define SVM_REG_R11 (11)
#define SVM_REG_R12 (12)
#define SVM_REG_R13 (13)
#define SVM_REG_R14 (14)
#define SVM_REG_R15 (15)

#endif /* __ASM_X86_HVM_SVM_H__ */
