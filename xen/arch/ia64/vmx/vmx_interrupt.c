/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_interrupt.c: handle inject interruption.
 * Copyright (c) 2005, Intel Corporation.
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
 *  Shaofan Li (Susue Li) <susie.li@intel.com>
 *  Xiaoyan Feng (Fleming Feng)  <fleming.feng@intel.com>
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */
#include <xen/types.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/debugger.h>

/* SDM vol2 5.5 - IVA based interruption handling */
#define INITIAL_PSR_VALUE_AT_INTERRUPTION 0x0000001808028034

static void
collect_interruption(VCPU *vcpu)
{
    u64 ipsr;
    u64 vdcr;
    u64 vifs;
    IA64_PSR vpsr;
    REGS * regs = vcpu_regs(vcpu);
    vpsr.val = vmx_vcpu_get_psr(vcpu);
    vcpu_bsw0(vcpu);
    if(vpsr.ic){

        /* Sync mpsr id/da/dd/ss/ed bits to vipsr
         * since after guest do rfi, we still want these bits on in
         * mpsr
         */

        ipsr = regs->cr_ipsr;
        vpsr.val = vpsr.val | (ipsr & (IA64_PSR_ID | IA64_PSR_DA
             | IA64_PSR_DD |IA64_PSR_SS |IA64_PSR_ED));
        vcpu_set_ipsr(vcpu, vpsr.val);

        /* Currently, for trap, we do not advance IIP to next
         * instruction. That's because we assume caller already
         * set up IIP correctly
         */

        vcpu_set_iip(vcpu , regs->cr_iip);

        /* set vifs.v to zero */
        vifs = VCPU(vcpu,ifs);
        vifs &= ~IA64_IFS_V;
        vcpu_set_ifs(vcpu, vifs);

        vcpu_set_iipa(vcpu, VMX(vcpu,cr_iipa));
    }

    vdcr = VCPU(vcpu,dcr);

    /* Set guest psr
     * up/mfl/mfh/pk/dt/rt/mc/it keeps unchanged
     * be: set to the value of dcr.be
     * pp: set to the value of dcr.pp
     */
    vpsr.val &= INITIAL_PSR_VALUE_AT_INTERRUPTION;
    vpsr.val |= ( vdcr & IA64_DCR_BE);

    /* VDCR pp bit position is different from VPSR pp bit */
    if ( vdcr & IA64_DCR_PP ) {
        vpsr.val |= IA64_PSR_PP;
    } else {
        vpsr.val &= ~IA64_PSR_PP;
    }

    vmx_vcpu_set_psr(vcpu, vpsr.val);

}

void
inject_guest_interruption(VCPU *vcpu, u64 vec)
{
    u64 viva;
    REGS *regs;
    ISR pt_isr;

    perfc_incra(vmx_inject_guest_interruption, vec >> 8);

    regs = vcpu_regs(vcpu);

    // clear cr.isr.ir (incomplete register frame)
    pt_isr.val = VMX(vcpu,cr_isr);
    pt_isr.ir = 0;
    VMX(vcpu,cr_isr) = pt_isr.val;

    collect_interruption(vcpu);
    vmx_ia64_set_dcr(vcpu);

    viva = vmx_vcpu_get_iva(vcpu);
    regs->cr_iip = viva + vec;

    debugger_event(vec == IA64_EXTINT_VECTOR ?
                   XEN_IA64_DEBUG_ON_EXTINT : XEN_IA64_DEBUG_ON_EXCEPT);
}

void hvm_pci_intx_assert(
        struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi;

    ASSERT((device <= 31) && (intx <= 3));

    if ( __test_and_set_bit(device * 4 + intx, &hvm_irq->pci_intx.i) )
        return;
    gsi = hvm_pci_intx_gsi(device, intx);
    if ( ++hvm_irq->gsi_assert_count[gsi] == 1 )
        viosapic_set_irq(d, gsi, 1);
}

void hvm_pci_intx_deassert(
        struct domain *d, unsigned int device, unsigned int intx)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int gsi;

    ASSERT((device <= 31) && (intx <= 3));

    if ( !__test_and_clear_bit(device * 4 + intx, &hvm_irq->pci_intx.i) )
        return;

    gsi = hvm_pci_intx_gsi(device, intx);

    if (--hvm_irq->gsi_assert_count[gsi] == 0)
        viosapic_set_irq(d, gsi, 0);
}

void hvm_isa_irq_assert(struct domain *d, unsigned int isa_irq)
{
    /* dummy */
}

void hvm_isa_irq_deassert(struct domain *d, unsigned int isa_irq)
{
    /* dummy */
}

int msixtbl_pt_register(struct domain *d, int pirq, uint64_t gtable)
{
    /* dummy */
    return -ENOSYS;
}

void msixtbl_pt_unregister(struct domain *d, int pirq)
{
    /* dummy */
}
