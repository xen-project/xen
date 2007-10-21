/******************************************************************************
 * vmx_vcpu_save.c
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <asm/vmx_vcpu.h>
#include <asm/vmx_vcpu_save.h>

void
vmx_arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    vpd_t *vpd = (void *)v->arch.privregs;
    struct mapped_regs *vpd_low = &vpd->vpd_low;
    unsigned long nats;
    unsigned long bnats;

    union vcpu_ar_regs *ar = &c.nat->regs.ar;
    union vcpu_cr_regs *cr = &c.nat->regs.cr;
    int i;

    // banked registers
    if (vpd_low->vpsr & IA64_PSR_BN) {
        for (i = 0; i < 16; i++) {
            //c.nat->regs.r[i + 16] = vpd_low->vgr[i];
            c.nat->regs.bank[i] = vpd_low->vbgr[i];
        }
        nats = vpd_low->vnat;
        bnats = vpd_low->vbnat;
    } else {
        for (i = 0; i < 16; i++) {
            c.nat->regs.bank[i] = vpd_low->vgr[i];
            //c.nat->regs.r[i + 16] = vpd_low->vbgr[i];
        }
        bnats = vpd_low->vnat;
        nats = vpd_low->vbnat;
    }
    // c.nat->regs.nats[0:15] is already set. we shouldn't overwrite.
    c.nat->regs.nats =
        (c.nat->regs.nats & MASK(0, 16)) | (nats & MASK(16, 16));
    c.nat->regs.bnats = bnats & MASK(16, 16);

    //c.nat->regs.psr = vpd_low->vpsr;
    //c.nat->regs.pr = vpd_low->vpr;

    // ar
    ar->kr[0] = v->arch.arch_vmx.vkr[0];
    ar->kr[1] = v->arch.arch_vmx.vkr[1];
    ar->kr[2] = v->arch.arch_vmx.vkr[2];
    ar->kr[3] = v->arch.arch_vmx.vkr[3];
    ar->kr[4] = v->arch.arch_vmx.vkr[4];
    ar->kr[5] = v->arch.arch_vmx.vkr[5];
    ar->kr[6] = v->arch.arch_vmx.vkr[6];
    ar->kr[7] = v->arch.arch_vmx.vkr[7];
#ifdef CONFIG_IA32_SUPPORT
    // csd and ssd are done by arch_get_info_guest()
    ar->fcr = v->arch._thread.fcr;
    ar->eflag = v->arch._thread.eflag;
    ar->cflg = v->arch._thread.cflg;
    ar->fsr = v->arch._thread.fsr;
    ar->fir = v->arch._thread.fir;
    ar->fdr = v->arch._thread.fdr;
#endif
    //ar->itc = vpd_low->itc;//see vtime

    // cr
    //cr->dcr = vpd_low->dcr;
    //cr->itm = vpd_low->itm;
    //cr->iva = vpd_low->iva;
    //cr->pta = vpd_low->pta;
    //cr->ipsr = vpd_low->ipsr;
    //cr->isr = vpd_low->isr;
    //cr->iip = vpd_low->iip;
    //cr->ifa = vpd_low->ifa;
    //cr->itir = vpd_low->itir;
    cr->iipa = vpd_low->iipa;
    cr->ifs = vpd_low->ifs;
    //cr->iim = vpd_low->iim;
    //cr->iha = vpd_low->iha;
    cr->lid = vpd_low->lid;
    cr->ivr = vpd_low->ivr;
    //cr->tpr = vpd_low->tpr;
    cr->eoi = vpd_low->eoi;
    //cr->irr[0] = vpd_low->irr[0];
    //cr->irr[1] = vpd_low->irr[1];
    //cr->irr[2] = vpd_low->irr[2];
    //cr->irr[3] = vpd_low->irr[3];
    //cr->itv = vpd_low->itv;
    //cr->pmv = vpd_low->pmv;
    //cr->cmcv = vpd_low->cmcv;
    cr->lrr0 = vpd_low->lrr0;
    cr->lrr1 = vpd_low->lrr1;
}

int
vmx_arch_set_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    vpd_t *vpd = (void *)v->arch.privregs;
    struct mapped_regs *vpd_low = &vpd->vpd_low;
    unsigned long vnat;
    unsigned long vbnat;

     union vcpu_ar_regs *ar = &c.nat->regs.ar;
     union vcpu_cr_regs *cr = &c.nat->regs.cr;
    int i;

    // banked registers
    if (c.nat->regs.psr & IA64_PSR_BN) {
        for (i = 0; i < 16; i++) {
            //vpd_low->vgr[i] = c.nat->regs.r[i + 16];
            vpd_low->vbgr[i] = c.nat->regs.bank[i];
        }
        vnat = c.nat->regs.nats;
        vbnat = c.nat->regs.bnats;
    } else {
        for (i = 0; i < 16; i++) {
            vpd_low->vgr[i] = c.nat->regs.bank[i];
            //vpd_low->vbgr[i] = c.nat->regs.r[i + 16];
        }
        vbnat = c.nat->regs.nats;
        vnat = c.nat->regs.bnats;
    }
    vpd_low->vnat = vnat & MASK(16, 16);
    vpd_low->vbnat = vbnat & MASK(16, 16);
    //vpd_low->vpsr = c.nat->regs.psr;
    //vpd_low->vpr = c.nat->regs.pr;

    // ar
    v->arch.arch_vmx.vkr[0] = ar->kr[0];
    v->arch.arch_vmx.vkr[1] = ar->kr[1];
    v->arch.arch_vmx.vkr[2] = ar->kr[2];
    v->arch.arch_vmx.vkr[3] = ar->kr[3];
    v->arch.arch_vmx.vkr[4] = ar->kr[4];
    v->arch.arch_vmx.vkr[5] = ar->kr[5];
    v->arch.arch_vmx.vkr[6] = ar->kr[6];
    v->arch.arch_vmx.vkr[7] = ar->kr[7];
#ifdef CONFIG_IA32_SUPPORT
    v->arch._thread.fcr = ar->fcr;
    v->arch._thread.eflag = ar->eflag;
    v->arch._thread.cflg = ar->cflg;
    v->arch._thread.fsr = ar->fsr;
    v->arch._thread.fir = ar->fir;
    v->arch._thread.fdr = ar->fdr;
#endif
    //vpd_low->itc = ar->itc;// see vtime.

    // cr
    vpd_low->dcr = cr->dcr;
    vpd_low->itm = cr->itm;
    //vpd_low->iva = cr->iva;
    vpd_low->pta = cr->pta;
    vpd_low->ipsr = cr->ipsr;
    vpd_low->isr = cr->isr;
    vpd_low->iip = cr->iip;
    vpd_low->ifa = cr->ifa;
    vpd_low->itir = cr->itir;
    vpd_low->iipa = cr->iipa;
    vpd_low->ifs = cr->ifs;
    vpd_low->iim = cr->iim;
    vpd_low->iha = cr->iha;
    vpd_low->lid = cr->lid;
    vpd_low->ivr = cr->ivr; //XXX vlsapic
    vpd_low->tpr = cr->tpr;
    vpd_low->eoi = cr->eoi;
    vpd_low->irr[0] = cr->irr[0];
    vpd_low->irr[1] = cr->irr[1];
    vpd_low->irr[2] = cr->irr[2];
    vpd_low->irr[3] = cr->irr[3];
    vpd_low->itv = cr->itv;
    vpd_low->pmv = cr->pmv;
    vpd_low->cmcv = cr->cmcv;
    vpd_low->lrr0 = cr->lrr0;
    vpd_low->lrr1 = cr->lrr1;

    v->arch.irq_new_condition = 1;
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
