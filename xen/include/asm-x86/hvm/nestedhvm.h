/*
 * Nested HVM
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
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
 */

#ifndef _HVM_NESTEDHVM_H
#define _HVM_NESTEDHVM_H

#include <xen/types.h>         /* for uintNN_t */
#include <xen/sched.h>         /* for struct vcpu, struct domain */
#include <asm/hvm/vcpu.h>      /* for vcpu_nestedhvm */

enum nestedhvm_vmexits {
    NESTEDHVM_VMEXIT_ERROR = 0, /* inject VMEXIT w/ invalid VMCB */
    NESTEDHVM_VMEXIT_FATALERROR = 1, /* crash first level guest */
    NESTEDHVM_VMEXIT_HOST = 2,  /* exit handled on host level */
    NESTEDHVM_VMEXIT_CONTINUE = 3, /* further handling */
    NESTEDHVM_VMEXIT_INJECT = 4, /* inject VMEXIT */
    NESTEDHVM_VMEXIT_DONE = 5, /* VMEXIT handled */
};

/* Nested HVM on/off per domain */
bool_t nestedhvm_enabled(struct domain *d);

/* Nested VCPU */
int nestedhvm_vcpu_initialise(struct vcpu *v);
void nestedhvm_vcpu_destroy(struct vcpu *v);
void nestedhvm_vcpu_reset(struct vcpu *v);
bool_t nestedhvm_vcpu_in_guestmode(struct vcpu *v);
#define nestedhvm_vcpu_enter_guestmode(v) \
    vcpu_nestedhvm(v).nv_guestmode = 1
#define nestedhvm_vcpu_exit_guestmode(v)  \
    vcpu_nestedhvm(v).nv_guestmode = 0

/* Nested paging */
#define NESTEDHVM_PAGEFAULT_DONE       0
#define NESTEDHVM_PAGEFAULT_INJECT     1
#define NESTEDHVM_PAGEFAULT_L1_ERROR   2
#define NESTEDHVM_PAGEFAULT_L0_ERROR   3
#define NESTEDHVM_PAGEFAULT_MMIO       4
#define NESTEDHVM_PAGEFAULT_RETRY      5
#define NESTEDHVM_PAGEFAULT_DIRECT_MMIO 6
int nestedhvm_hap_nested_page_fault(struct vcpu *v, paddr_t *L2_gpa,
    bool_t access_r, bool_t access_w, bool_t access_x);

/* IO permission map */
unsigned long *nestedhvm_vcpu_iomap_get(bool_t ioport_80, bool_t ioport_ed);

/* Misc */
#define nestedhvm_paging_mode_hap(v) (!!nhvm_vmcx_hap_enabled(v))
#define nestedhvm_vmswitch_in_progress(v)   \
    (!!vcpu_nestedhvm((v)).nv_vmswitch_in_progress)

void nestedhvm_vmcx_flushtlb(struct p2m_domain *p2m);

bool_t nestedhvm_is_n2(struct vcpu *v);

static inline void nestedhvm_set_cr(struct vcpu *v, unsigned int cr,
                                    unsigned long value)
{
    if ( !nestedhvm_vmswitch_in_progress(v) &&
         nestedhvm_vcpu_in_guestmode(v) )
        v->arch.hvm_vcpu.nvcpu.guest_cr[cr] = value;
}

#endif /* _HVM_NESTEDHVM_H */
