/*
 * vmx_platform.h: VMX platform support
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
#ifndef __ASM_IA64_VMX_PLATFORM_H__
#define __ASM_IA64_VMX_PLATFORM_H__

#include <public/xen.h>
#include <public/arch-ia64.h>
#include <asm/hvm/vioapic.h>

struct mmio_list;
typedef struct virtual_platform_def {
    unsigned long       shared_page_va;
    unsigned long       pib_base;
    unsigned char       xtp;
    struct mmio_list    *mmio;
    /* One IOSAPIC now... */
    struct hvm_vioapic  vioapic;
} vir_plat_t;

static inline int __fls(uint32_t word)
{
    long double d = word;
    long exp;

    __asm__ __volatile__ ("getf.exp %0=%1" : "=r"(exp) : "f"(d));
    return word ? (exp - 0xffff) : -1;
}

/* This is a connect structure between vIOSAPIC model and vLSAPIC model.
 * vlapic is required by vIOSAPIC model to manipulate pending bits, and
 * we just map them into vpd here
 */
typedef struct vlapic {
    struct vcpu	*vcpu;	/* Link to current vcpu */
} vlapic_t;

extern uint64_t dummy_tmr[];
#define VCPU(_v,_x)	_v->arch.privregs->_x
#define VLAPIC_ID(l) (uint16_t)(VCPU((l)->vcpu, lid) >> 16)
#define VLAPIC_IRR(l) VCPU((l)->vcpu, irr[0])

extern int vmx_vcpu_pend_interrupt(struct vcpu *vcpu, uint8_t vector);
static inline int vlapic_set_irq(struct vlapic *t, uint8_t vec, uint8_t trig)
{
    return vmx_vcpu_pend_interrupt(t->vcpu, vec);
}

/* As long as we register vlsapic to ioapic controller, it's said enabled */
#define vlapic_enabled(l) 1
#define hvm_apic_support(d) 1

#define VLAPIC_DELIV_MODE_FIXED		0x0
#define VLAPIC_DELIV_MODE_REDIR		0x1
#define VLAPIC_DELIV_MODE_LPRI		VLAPIC_DELIV_MODE_REDIR
#define VLAPIC_DELIV_MODE_PMI		0x2
#define VLAPIC_DELIV_MODE_SMI		0x2 /* For IA32 */
#define VLAPIC_DELIV_MODE_RESERVED	0x3
#define VLAPIC_DELIV_MODE_NMI		0x4
#define VLAPIC_DELIV_MODE_INIT		0x5
#define VLAPIC_DELIV_MODE_STARTUP	0x6 /* For IA32 */
#define VLAPIC_DELIV_MODE_EXT		0x7

#endif
