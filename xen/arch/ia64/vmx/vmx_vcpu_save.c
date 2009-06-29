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
#include <asm/hvm/support.h>
#include <public/hvm/save.h>

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
    vpd_low->tpr = cr->tpr;
    vpd_low->ivr = cr->ivr; //XXX vlsapic
    vpd_low->eoi = cr->eoi;
    if (c.nat->flags & VGCF_SET_CR_IRR) {
        vpd_low->irr[0] = cr->irr[0];
        vpd_low->irr[1] = cr->irr[1];
        vpd_low->irr[2] = cr->irr[2];
        vpd_low->irr[3] = cr->irr[3];
    }
    vpd_low->itv = cr->itv;
    vpd_low->pmv = cr->pmv;
    vpd_low->cmcv = cr->cmcv;
    vpd_low->lrr0 = cr->lrr0;
    vpd_low->lrr1 = cr->lrr1;

    v->arch.irq_new_condition = 1;
    return 0;
}


static int vmx_cpu_save(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    for_each_vcpu(d, v) {
        struct pt_regs *regs = vcpu_regs(v);
        struct hvm_hw_ia64_cpu ia64_cpu;

        if (test_bit(_VPF_down, &v->pause_flags))
            continue;

        memset(&ia64_cpu, 0, sizeof(ia64_cpu));

        ia64_cpu.ipsr = regs->cr_ipsr;

        if (hvm_save_entry(CPU, v->vcpu_id, h, &ia64_cpu))
            return -EINVAL;
    }

    return 0;
}

static int vmx_cpu_load(struct domain *d, hvm_domain_context_t *h)
{
    int rc = 0;
    uint16_t vcpuid;
    struct vcpu *v;
    struct hvm_hw_ia64_cpu ia64_cpu;
    struct pt_regs *regs;

    vcpuid = hvm_load_instance(h);
    if (vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL) {
        gdprintk(XENLOG_ERR,
                 "%s: domain has no vcpu %u\n", __func__, vcpuid);
        rc = -EINVAL;
        goto out;
    }

    if (hvm_load_entry(CPU, h, &ia64_cpu) != 0) {
        rc = -EINVAL;
        goto out;
    }

    regs = vcpu_regs(v);
    regs->cr_ipsr = ia64_cpu.ipsr | IA64_PSR_VM;

 out:
    return rc;
}

HVM_REGISTER_SAVE_RESTORE(CPU, vmx_cpu_save, vmx_cpu_load, 1, HVMSR_PER_VCPU);

static int vmx_vpd_save(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    for_each_vcpu(d, v) {
        vpd_t *vpd = (void *)v->arch.privregs;

        if (test_bit(_VPF_down, &v->pause_flags))
            continue;
        
        // currently struct hvm_hw_ia64_vpd = struct vpd
        // if it is changed, this must be revised.
        if (hvm_save_entry(VPD, v->vcpu_id, h, (struct hvm_hw_ia64_vpd*)vpd))
            return -EINVAL;
    }

    return 0;
}

static int vmx_vpd_load(struct domain *d, hvm_domain_context_t *h)
{
    int rc = 0;
    uint16_t vcpuid;
    struct vcpu *v;
    vpd_t *vpd;
    struct hvm_hw_ia64_vpd *ia64_vpd = NULL;
    int i;

    vcpuid = hvm_load_instance(h);
    if (vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL) {
        gdprintk(XENLOG_ERR,
                 "%s: domain has no vcpu %u\n", __func__, vcpuid);
        rc = -EINVAL;
        goto out;
    }

    ia64_vpd = xmalloc(struct hvm_hw_ia64_vpd);
    if (ia64_vpd == NULL) {
        gdprintk(XENLOG_ERR,
                 "%s: can't allocate memory %d\n", __func__, vcpuid);
        rc = -ENOMEM;
        goto out;
    }

    if (hvm_load_entry(VPD, h, ia64_vpd) != 0) {
        rc = -EINVAL;
        goto out;
    }

    vpd = (void *)v->arch.privregs;
#define VPD_COPY(x)    vpd->vpd_low.x = ia64_vpd->vpd.vpd_low.x

    for (i = 0; i < 16; i++)
        VPD_COPY(vgr[i]);
    for (i = 0; i < 16; i++)
        VPD_COPY(vbgr[i]);
    VPD_COPY(vnat);
    VPD_COPY(vbnat);
    for (i = 0; i < 5; i++)
        VPD_COPY(vcpuid[i]);
    VPD_COPY(vpsr);
    VPD_COPY(vpr);

    // cr
#if 0
    VPD_COPY(dcr);
    VPD_COPY(itm);
    VPD_COPY(iva);
    VPD_COPY(pta);
    VPD_COPY(ipsr);
    VPD_COPY(isr);
    VPD_COPY(iip);
    VPD_COPY(ifa);
    VPD_COPY(itir);
    VPD_COPY(iipa);
    VPD_COPY(ifs);
    VPD_COPY(iim);
    VPD_COPY(iha);
    VPD_COPY(lid);
    VPD_COPY(ivr);
    VPD_COPY(tpr);
    VPD_COPY(eoi);
    VPD_COPY(irr[0]);
    VPD_COPY(irr[1]);
    VPD_COPY(irr[2]);
    VPD_COPY(irr[3]);
    VPD_COPY(itv);
    VPD_COPY(pmv);
    VPD_COPY(cmcv);
    VPD_COPY(lrr0);
    VPD_COPY(lrr1);
#else
    memcpy(&vpd->vpd_low.vcr[0], &ia64_vpd->vpd.vpd_low.vcr[0],
           sizeof(vpd->vpd_low.vcr));
#endif
#undef VPD_COPY

    v->arch.irq_new_condition = 1;

 out:
    if (ia64_vpd != NULL)
        xfree(ia64_vpd);
    return rc;
}

HVM_REGISTER_SAVE_RESTORE(VPD, vmx_vpd_save, vmx_vpd_load, 1, HVMSR_PER_VCPU);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
