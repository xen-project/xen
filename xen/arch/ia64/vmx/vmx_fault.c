/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_fault.c: handling VMX architecture-related VM exits
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
 *  Xiaoyan Feng (Fleming Feng)  <fleming.feng@intel.com>
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <asm/ptrace.h>
#include <xen/delay.h>

#include <linux/efi.h>  /* FOR EFI_UNIMPLEMENTED */
#include <asm/sal.h>    /* FOR struct ia64_sal_retval */

#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/vlsapic.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/regionreg.h>
#include <asm/privop.h>
#include <asm/ia64_int.h>
#include <asm/debugger.h>
#include <asm/dom_fw.h>
#include <asm/vmx_vcpu.h>
#include <asm/kregs.h>
#include <asm/vmx.h>
#include <asm/vmmu.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx_phy_mode.h>
#include <xen/mm.h>
#include <asm/vmx_pal.h>
#include <asm/shadow.h>
#include <asm/sioemu.h>
#include <public/arch-ia64/sioemu.h>
#include <xen/hvm/irq.h>

/* reset all PSR field to 0, except up,mfl,mfh,pk,dt,rt,mc,it */
#define INITIAL_PSR_VALUE_AT_INTERRUPTION 0x0000001808028034

extern unsigned long handle_fpu_swa (int fp_fault, struct pt_regs *regs, unsigned long isr);

#define DOMN_PAL_REQUEST    0x110000
#define DOMN_SAL_REQUEST    0x110001

static const u16 vec2off[68] = {0x0,0x400,0x800,0xc00,0x1000,0x1400,0x1800,
    0x1c00,0x2000,0x2400,0x2800,0x2c00,0x3000,0x3400,0x3800,0x3c00,0x4000,
    0x4400,0x4800,0x4c00,0x5000,0x5100,0x5200,0x5300,0x5400,0x5500,0x5600,
    0x5700,0x5800,0x5900,0x5a00,0x5b00,0x5c00,0x5d00,0x5e00,0x5f00,0x6000,
    0x6100,0x6200,0x6300,0x6400,0x6500,0x6600,0x6700,0x6800,0x6900,0x6a00,
    0x6b00,0x6c00,0x6d00,0x6e00,0x6f00,0x7000,0x7100,0x7200,0x7300,0x7400,
    0x7500,0x7600,0x7700,0x7800,0x7900,0x7a00,0x7b00,0x7c00,0x7d00,0x7e00,
    0x7f00
};

void vmx_lazy_load_fpu(struct vcpu *vcpu)
{
    if (FP_PSR(vcpu) & IA64_PSR_DFH) {
        FP_PSR(vcpu) = IA64_PSR_MFH;
        if (__ia64_per_cpu_var(fp_owner) != vcpu)
            __ia64_load_fpu(vcpu->arch._thread.fph);
    }
}

void vmx_reflect_interruption(u64 ifa, u64 isr, u64 iim,
                              u64 vec, REGS *regs)
{
    u64 status, vector;
    VCPU *vcpu = current;
    u64 vpsr = VCPU(vcpu, vpsr);
    
    vector = vec2off[vec];

    switch (vec) {
    case 5:  // IA64_DATA_NESTED_TLB_VECTOR
        break;
    case 22:	// IA64_INST_ACCESS_RIGHTS_VECTOR
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        if (vhpt_access_rights_fixup(vcpu, ifa, 0))
            return;
        break;

    case 25:	// IA64_DISABLED_FPREG_VECTOR
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        vmx_lazy_load_fpu(vcpu);
        if (!(VCPU(vcpu, vpsr) & IA64_PSR_DFH)) {
            regs->cr_ipsr &= ~IA64_PSR_DFH;
            return;
        }

        break;       

    case 32:	// IA64_FP_FAULT_VECTOR
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        // handle fpswa emulation
        // fp fault
        status = handle_fpu_swa(1, regs, isr);
        if (!status) {
            vcpu_increment_iip(vcpu);
            return;
        }
        break;

    case 33:	// IA64_FP_TRAP_VECTOR
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        //fp trap
        status = handle_fpu_swa(0, regs, isr);
        if (!status)
            return;
        break;

    case 29: // IA64_DEBUG_VECTOR
    case 35: // IA64_TAKEN_BRANCH_TRAP_VECTOR
    case 36: // IA64_SINGLE_STEP_TRAP_VECTOR
        if (vmx_guest_kernel_mode(regs)
            && current->domain->debugger_attached) {
            domain_pause_for_debugger();
            return;
        }
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        break;

    default:
        if (!(vpsr & IA64_PSR_IC))
            goto nested_fault;
        break;
    } 
    VCPU(vcpu,isr) = isr;
    VCPU(vcpu,iipa) = regs->cr_iip;
    if (vector == IA64_BREAK_VECTOR || vector == IA64_SPECULATION_VECTOR)
        VCPU(vcpu,iim) = iim;
    else
        set_ifa_itir_iha(vcpu, ifa, 1, 1, 1);
    inject_guest_interruption(vcpu, vector);
    return;

 nested_fault:
    panic_domain(regs, "Guest nested fault vector=%lx!\n", vector);
}


IA64FAULT
vmx_ia64_handle_break (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long iim)
{
    struct domain *d = current->domain;
    struct vcpu *v = current;

    perfc_incr(vmx_ia64_handle_break);
#ifdef CRASH_DEBUG
    if ((iim == 0 || iim == CDB_BREAK_NUM) && !vmx_user_mode(regs) &&
        IS_VMM_ADDRESS(regs->cr_iip)) {
        if (iim == 0)
            show_registers(regs);
        debugger_trap_fatal(0 /* don't care */, regs);
        regs_increment_iip(regs);
        return IA64_NO_FAULT;
    }
#endif
    if (!vmx_user_mode(regs)) {
        show_registers(regs);
        gdprintk(XENLOG_DEBUG, "%s:%d imm %lx\n", __func__, __LINE__, iim);
        ia64_fault(11 /* break fault */, isr, ifa, iim,
                   0 /* cr.itir */, 0, 0, 0, (unsigned long)regs);
    }

    if (ia64_psr(regs)->cpl == 0) {
        /* Allow hypercalls only when cpl = 0.  */

        /* Only common hypercalls are handled by vmx_break_fault. */
        if (iim == d->arch.breakimm) {
            ia64_hypercall(regs);
            vcpu_increment_iip(v);
            return IA64_NO_FAULT;
        }

        /* normal hypercalls are handled by vmx_break_fault */
        BUG_ON(iim == d->arch.breakimm);
        
        if (iim == DOMN_PAL_REQUEST) {
            pal_emul(v);
            vcpu_increment_iip(v);
            return IA64_NO_FAULT;
        } else if (iim == DOMN_SAL_REQUEST) {
            if (d->arch.is_sioemu)
                sioemu_sal_assist(v);
            else {
                sal_emul(v);
                vcpu_increment_iip(v);
            }
            return IA64_NO_FAULT;
        }
    }
    vmx_reflect_interruption(ifa, isr, iim, 11, regs);
    return IA64_NO_FAULT;
}


void save_banked_regs_to_vpd(VCPU *v, REGS *regs)
{
    unsigned long i=0UL, * src,* dst, *sunat, *dunat;
    IA64_PSR vpsr;

    src = &regs->r16;
    sunat = &regs->eml_unat;
    vpsr.val = VCPU(v, vpsr);
    if (vpsr.bn) {
        dst = &VCPU(v, vgr[0]);
        dunat =&VCPU(v, vnat);
        __asm__ __volatile__ (";;extr.u %0 = %1,%4,16;; \
                            dep %2 = %0, %2, 0, 16;; \
                            st8 [%3] = %2;;"
       ::"r"(i),"r"(*sunat),"r"(*dunat),"r"(dunat),"i"(IA64_PT_REGS_R16_SLOT):"memory");

    } else {
        dst = &VCPU(v, vbgr[0]);
//        dunat =&VCPU(v, vbnat);
//        __asm__ __volatile__ (";;extr.u %0 = %1,%4,16;;
//                            dep %2 = %0, %2, 16, 16;;
//                            st8 [%3] = %2;;"
//       ::"r"(i),"r"(*sunat),"r"(*dunat),"r"(dunat),"i"(IA64_PT_REGS_R16_SLOT):"memory");

    }
    for (i = 0; i < 16; i++)
        *dst++ = *src++;
}


// ONLY gets called from ia64_leave_kernel
// ONLY call with interrupts disabled?? (else might miss one?)
// NEVER successful if already reflecting a trap/fault because psr.i==0
void leave_hypervisor_tail(void)
{
    struct domain *d = current->domain;
    struct vcpu *v = current;

    /* FIXME: can this happen ?  */
    if (is_idle_domain(current->domain))
        return;

    // A softirq may generate an interrupt.  So call softirq early.
    local_irq_enable();
    do_softirq();
    local_irq_disable();

    // FIXME: Will this work properly if doing an RFI???
    if (d->arch.is_sioemu) {
        if (local_events_need_delivery()) {
            sioemu_deliver_event();
        }
    } else if (v->vcpu_id == 0) {
        unsigned long callback_irq =
            d->arch.hvm_domain.params[HVM_PARAM_CALLBACK_IRQ];
        
        if (v->arch.arch_vmx.pal_init_pending) {
            /* inject INIT interruption to guest pal */
            v->arch.arch_vmx.pal_init_pending = 0;
            deliver_pal_init(v);
            return;
        }

        /*
         * val[63:56] == 1: val[55:0] is a delivery PCI INTx line:
         *                  Domain = val[47:32], Bus  = val[31:16],
         *                  DevFn  = val[15: 8], IntX = val[ 1: 0]
         * val[63:56] == 0: val[55:0] is a delivery as GSI
         */
        if (callback_irq != 0 && local_events_need_delivery()) {
            /* change level for para-device callback irq */
            /* use level irq to send discrete event */
            if ((uint8_t)(callback_irq >> 56) == 1) {
                /* case of using PCI INTx line as callback irq */
                int pdev = (callback_irq >> 11) & 0x1f;
                int pintx = callback_irq & 3;
                viosapic_set_pci_irq(d, pdev, pintx, 1);
                viosapic_set_pci_irq(d, pdev, pintx, 0);
            } else {
                /* case of using GSI as callback irq */
                viosapic_set_irq(d, callback_irq, 1);
                viosapic_set_irq(d, callback_irq, 0);
            }
        }
    }

    rmb();
    if (xchg(&v->arch.irq_new_pending, 0)) {
        v->arch.irq_new_condition = 0;
        vmx_check_pending_irq(v);
    } else if (v->arch.irq_new_condition) {
        v->arch.irq_new_condition = 0;
        vhpi_detection(v);
    }
}

static int vmx_handle_lds(REGS* regs)
{
    regs->cr_ipsr |= IA64_PSR_ED;
    return IA64_FAULT;
}

static inline int unimpl_phys_addr (u64 paddr)
{
    return (pa_clear_uc(paddr) >> MAX_PHYS_ADDR_BITS) != 0;
}

/* We came here because the H/W VHPT walker failed to find an entry */
IA64FAULT
vmx_hpw_miss(u64 vadr, u64 vec, REGS* regs)
{
    IA64_PSR vpsr;
    int type;
    u64 vhpt_adr, gppa, pteval, rr, itir;
    ISR misr;
    PTA vpta;
    thash_data_t *data;
    VCPU *v = current;

    vpsr.val = VCPU(v, vpsr);
    misr.val = VMX(v,cr_isr);
    
    if (vec == 1 || vec == 3)
        type = ISIDE_TLB;
    else if (vec == 2 || vec == 4)
        type = DSIDE_TLB;
    else
        panic_domain(regs, "wrong vec:%lx\n", vec);

    /* Physical mode. */
    if (type == ISIDE_TLB) {
        if (!vpsr.it) {
            if (unlikely(unimpl_phys_addr(vadr))) {
                unimpl_iaddr_trap(v, vadr);
                return IA64_FAULT;
            }
            physical_tlb_miss(v, vadr, type);
            return IA64_FAULT;
        }
    } else { /* DTLB miss. */
        if (!misr.rs) {
            if (!vpsr.dt) {
                u64 pte;
                if (misr.sp) /* Refer to SDM Vol2 Table 4-11,4-12 */
                    return vmx_handle_lds(regs);
                if (unlikely(unimpl_phys_addr(vadr))) {
                    unimpl_daddr(v);
                    return IA64_FAULT;
                }
                pte = lookup_domain_mpa(v->domain, pa_clear_uc(vadr), NULL);
                if (v->domain != dom0 && (pte & _PAGE_IO)) {
                    emulate_io_inst(v, pa_clear_uc(vadr), 4,
                                    pte_pfn(__pte(pte)));
                    return IA64_FAULT;
                }
                physical_tlb_miss(v, vadr, type);
                return IA64_FAULT;
            }
        } else { /* RSE fault. */
            if (!vpsr.rt) {
                if (unlikely(unimpl_phys_addr(vadr))) {
                    unimpl_daddr(v);
                    return IA64_FAULT;
                }
                physical_tlb_miss(v, vadr, type);
                return IA64_FAULT;
            }
        }
    }
    
try_again:
    /* Search in VTLB.  */
    data = vtlb_lookup(v, vadr, type);
    if (data != 0) {
        /* Found.  */
        if (v->domain != dom0 && type == DSIDE_TLB) {
            u64 pte;
            if (misr.sp) { /* Refer to SDM Vol2 Table 4-10,4-12 */
                if ((data->ma == VA_MATTR_UC) || (data->ma == VA_MATTR_UCE))
                    return vmx_handle_lds(regs);
            }
            gppa = thash_translate(data, vadr);
            pte = lookup_domain_mpa(v->domain, gppa, NULL);
            if (pte & _PAGE_IO) {
                if (misr.sp)
                    panic_domain(NULL, "ld.s on I/O page not with UC attr."
                                 " pte=0x%lx\n", data->page_flags);
                if (data->pl >= ((regs->cr_ipsr >> IA64_PSR_CPL0_BIT) & 3))
                    emulate_io_inst(v, gppa, data->ma, 
                                    pte_pfn(__pte(pte)));
                else {
                    vcpu_set_isr(v, misr.val);
                    data_access_rights(v, vadr);
                }
                return IA64_FAULT;
            }
        }
        thash_vhpt_insert(v, data->page_flags, data->itir, vadr, type);
        return IA64_NO_FAULT;
    }

    if (type == DSIDE_TLB) {
        struct opt_feature* optf = &(v->domain->arch.opt_feature);

        if (misr.sp)
            return vmx_handle_lds(regs);

        vcpu_get_rr(v, vadr, &rr);
        itir = rr & (RR_RID_MASK | RR_PS_MASK);

        if (!vhpt_enabled(v, vadr, misr.rs ? RSE_REF : DATA_REF)) {
            /* windows use region 4 and 5 for identity mapping */
            if ((optf->mask & XEN_IA64_OPTF_IDENT_MAP_REG4_FLG) &&
                REGION_NUMBER(vadr) == 4 && !(regs->cr_ipsr & IA64_PSR_CPL) &&
                REGION_OFFSET(vadr) <= _PAGE_PPN_MASK) {

                pteval = PAGEALIGN(REGION_OFFSET(vadr), itir_ps(itir)) |
                         optf->im_reg4.pgprot;
                if (thash_purge_and_insert(v, pteval, itir, vadr, type))
                    goto try_again;
                return IA64_NO_FAULT;
            }
            if ((optf->mask & XEN_IA64_OPTF_IDENT_MAP_REG5_FLG) &&
                REGION_NUMBER(vadr) == 5 && !(regs->cr_ipsr & IA64_PSR_CPL) &&
                REGION_OFFSET(vadr) <= _PAGE_PPN_MASK) {

                pteval = PAGEALIGN(REGION_OFFSET(vadr), itir_ps(itir)) |
                         optf->im_reg5.pgprot;
                if (thash_purge_and_insert(v, pteval, itir, vadr, type))
                    goto try_again;
                return IA64_NO_FAULT;
            }
            if (vpsr.ic) {
                vcpu_set_isr(v, misr.val);
                alt_dtlb(v, vadr);
            } else {
                nested_dtlb(v);
            }
            return IA64_FAULT;
        }

        vpta.val = vmx_vcpu_get_pta(v);
        if (vpta.vf) {
            /* Long format is not yet supported.  */
            goto inject_dtlb_fault;
        }

        /* avoid recursively walking (short format) VHPT */
        if (!(optf->mask & XEN_IA64_OPTF_IDENT_MAP_REG4_FLG) &&
            !(optf->mask & XEN_IA64_OPTF_IDENT_MAP_REG5_FLG) &&
            (((vadr ^ vpta.val) << 3) >> (vpta.size + 3)) == 0) {
            goto inject_dtlb_fault;
        }
            
        vhpt_adr = vmx_vcpu_thash(v, vadr);
        if (!guest_vhpt_lookup(vhpt_adr, &pteval)) {
            /* VHPT successfully read.  */
            if (!(pteval & _PAGE_P)) {
                goto inject_dtlb_fault;
            } else if ((pteval & _PAGE_MA_MASK) != _PAGE_MA_ST) {
                thash_purge_and_insert(v, pteval, itir, vadr, DSIDE_TLB);
               return IA64_NO_FAULT;
            }
            goto inject_dtlb_fault;
        } else {
            /* Can't read VHPT.  */
            if (vpsr.ic) {
                vcpu_set_isr(v, misr.val);
                dvhpt_fault(v, vadr);
                return IA64_FAULT;
            } else {
                nested_dtlb(v);
                return IA64_FAULT;
            }
        }
    } else if (type == ISIDE_TLB) {
    
        if (!vpsr.ic)
            misr.ni = 1;

        /* Don't bother with PHY_D mode (will require rr0+rr4 switches,
           and certainly used only within nested TLB handler (hence TR mapped
           and ic=0).  */
        if (!vpsr.dt)
            goto inject_itlb_fault;

        if (!vhpt_enabled(v, vadr, INST_REF)) {
            vcpu_set_isr(v, misr.val);
            alt_itlb(v, vadr);
            return IA64_FAULT;
        }

        vpta.val = vmx_vcpu_get_pta(v);
        if (vpta.vf) {
            /* Long format is not yet supported.  */
            goto inject_itlb_fault;
        }


        vhpt_adr = vmx_vcpu_thash(v, vadr);
        if (!guest_vhpt_lookup(vhpt_adr, &pteval)) {
            /* VHPT successfully read.  */
            if (pteval & _PAGE_P) {
                if ((pteval & _PAGE_MA_MASK) == _PAGE_MA_ST) {
                    goto inject_itlb_fault;
                }
                vcpu_get_rr(v, vadr, &rr);
                itir = rr & (RR_RID_MASK | RR_PS_MASK);
                thash_purge_and_insert(v, pteval, itir, vadr, ISIDE_TLB);
                return IA64_NO_FAULT;
            } else {
                vcpu_set_isr(v, misr.val);
                inst_page_not_present(v, vadr);
                return IA64_FAULT;
            }
        } else {
            vcpu_set_isr(v, misr.val);
            ivhpt_fault(v, vadr);
            return IA64_FAULT;
        }
    }
    return IA64_NO_FAULT;

 inject_dtlb_fault:
    if (vpsr.ic) {
        vcpu_set_isr(v, misr.val);
        dtlb_fault(v, vadr);
    } else
        nested_dtlb(v);

    return IA64_FAULT;

 inject_itlb_fault:
    vcpu_set_isr(v, misr.val);
    itlb_fault(v, vadr);
    return IA64_FAULT;
}

void
vmx_ia64_shadow_fault(u64 ifa, u64 isr, u64 mpa, REGS *regs)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    u64 gpfn, pte;
    thash_data_t *data;

    if (!shadow_mode_enabled(d))
        goto inject_dirty_bit;

    gpfn = get_gpfn_from_mfn(mpa >> PAGE_SHIFT);
    data = vhpt_lookup(ifa);
    if (data) {
        pte = data->page_flags;
        // BUG_ON((pte ^ mpa) & (_PAGE_PPN_MASK & PAGE_MASK));
        if (!(pte & _PAGE_VIRT_D))
            goto inject_dirty_bit;
        data->page_flags = pte | _PAGE_D;
    } else {
        data = vtlb_lookup(v, ifa, DSIDE_TLB);
        if (data) {
            if (!(data->page_flags & _PAGE_VIRT_D))
                goto inject_dirty_bit;
        }
        pte = 0;
    }

    /* Set the dirty bit in the bitmap.  */
    shadow_mark_page_dirty(d, gpfn);

    /* Retry */
    atomic64_inc(&d->arch.shadow_fault_count);
    ia64_ptcl(ifa, PAGE_SHIFT << 2);
    return;

inject_dirty_bit:
    /* Reflect. no need to purge.  */
    VCPU(v, isr) = isr;
    set_ifa_itir_iha (v, ifa, 1, 1, 1);
    inject_guest_interruption(v, IA64_DIRTY_BIT_VECTOR);
    return;
}
