/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_process.c: handling VMX architecture-related VM exits
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
//#include <asm/hpsim_ssc.h>
#include <asm/dom_fw.h>
#include <asm/vmx_vcpu.h>
#include <asm/kregs.h>
#include <asm/vmx.h>
#include <asm/vmmu.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx_phy_mode.h>
#include <xen/mm.h>
#include <asm/vmx_pal.h>
/* reset all PSR field to 0, except up,mfl,mfh,pk,dt,rt,mc,it */
#define INITIAL_PSR_VALUE_AT_INTERRUPTION 0x0000001808028034


extern void die_if_kernel(char *str, struct pt_regs *regs, long err);
extern void rnat_consumption (VCPU *vcpu);
extern void alt_itlb (VCPU *vcpu, u64 vadr);
extern void itlb_fault (VCPU *vcpu, u64 vadr);
extern void ivhpt_fault (VCPU *vcpu, u64 vadr);
extern unsigned long handle_fpu_swa (int fp_fault, struct pt_regs *regs, unsigned long isr);

#define DOMN_PAL_REQUEST    0x110000
#define DOMN_SAL_REQUEST    0x110001

static u64 vec2off[68] = {0x0,0x400,0x800,0xc00,0x1000,0x1400,0x1800,
    0x1c00,0x2000,0x2400,0x2800,0x2c00,0x3000,0x3400,0x3800,0x3c00,0x4000,
    0x4400,0x4800,0x4c00,0x5000,0x5100,0x5200,0x5300,0x5400,0x5500,0x5600,
    0x5700,0x5800,0x5900,0x5a00,0x5b00,0x5c00,0x5d00,0x5e00,0x5f00,0x6000,
    0x6100,0x6200,0x6300,0x6400,0x6500,0x6600,0x6700,0x6800,0x6900,0x6a00,
    0x6b00,0x6c00,0x6d00,0x6e00,0x6f00,0x7000,0x7100,0x7200,0x7300,0x7400,
    0x7500,0x7600,0x7700,0x7800,0x7900,0x7a00,0x7b00,0x7c00,0x7d00,0x7e00,
    0x7f00
};



void vmx_reflect_interruption(u64 ifa, u64 isr, u64 iim,
                              u64 vec, REGS *regs)
{
    u64 status, vector;
    VCPU *vcpu = current;
    u64 vpsr = VCPU(vcpu, vpsr);
    
    vector = vec2off[vec];
    if(!(vpsr&IA64_PSR_IC)&&(vector!=IA64_DATA_NESTED_TLB_VECTOR)){
        panic_domain(regs, "Guest nested fault vector=%lx!\n", vector);
    }

    switch (vec) {

    case 25:	// IA64_DISABLED_FPREG_VECTOR

        if (FP_PSR(vcpu) & IA64_PSR_DFH) {
            FP_PSR(vcpu) = IA64_PSR_MFH;
            if (__ia64_per_cpu_var(fp_owner) != vcpu)
                __ia64_load_fpu(vcpu->arch._thread.fph);
        }
        if (!(VCPU(vcpu, vpsr) & IA64_PSR_DFH)) {
            regs->cr_ipsr &= ~IA64_PSR_DFH;
            return;
        }

        break;       
        
    case 32:	// IA64_FP_FAULT_VECTOR
        // handle fpswa emulation
        // fp fault
        status = handle_fpu_swa(1, regs, isr);
        if (!status) {
            vcpu_increment_iip(vcpu);
            return;
        } else if (IA64_RETRY == status)
            return;
        break;

    case 33:	// IA64_FP_TRAP_VECTOR
        //fp trap
        status = handle_fpu_swa(0, regs, isr);
        if (!status)
            return;
        else if (IA64_RETRY == status) {
            vcpu_decrement_iip(vcpu);
            return;
        }
        break;
    
    } 
    VCPU(vcpu,isr)=isr;
    VCPU(vcpu,iipa) = regs->cr_iip;
    if (vector == IA64_BREAK_VECTOR || vector == IA64_SPECULATION_VECTOR)
        VCPU(vcpu,iim) = iim;
    else {
        set_ifa_itir_iha(vcpu,ifa,1,1,1);
    }
    inject_guest_interruption(vcpu, vector);
}


IA64FAULT
vmx_ia64_handle_break (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long iim)
{
    struct domain *d = current->domain;
    struct vcpu *v = current;

    perfc_incrc(vmx_ia64_handle_break);
#ifdef CRASH_DEBUG
    if ((iim == 0 || iim == CDB_BREAK_NUM) && !user_mode(regs) &&
        IS_VMM_ADDRESS(regs->cr_iip)) {
        if (iim == 0)
            show_registers(regs);
        debugger_trap_fatal(0 /* don't care */, regs);
    } else
#endif
    {
        if (iim == 0) 
            vmx_die_if_kernel("Break 0 in Hypervisor.", regs, iim);

        if (!user_mode(regs)) {
            /* Allow hypercalls only when cpl = 0.  */
            if (iim == d->arch.breakimm) {
                ia64_hypercall(regs);
                vcpu_increment_iip(v);
                return IA64_NO_FAULT;
            }
            else if(iim == DOMN_PAL_REQUEST){
                pal_emul(v);
                vcpu_increment_iip(v);
                return IA64_NO_FAULT;
            }else if(iim == DOMN_SAL_REQUEST){
                sal_emul(v);
                vcpu_increment_iip(v);
                return IA64_NO_FAULT;
            }
        }
        vmx_reflect_interruption(ifa,isr,iim,11,regs);
    }
    return IA64_NO_FAULT;
}


void save_banked_regs_to_vpd(VCPU *v, REGS *regs)
{
    unsigned long i=0UL, * src,* dst, *sunat, *dunat;
    IA64_PSR vpsr;
    src=&regs->r16;
    sunat=&regs->eml_unat;
    vpsr.val = VCPU(v, vpsr);
    if(vpsr.bn){
        dst = &VCPU(v, vgr[0]);
        dunat =&VCPU(v, vnat);
        __asm__ __volatile__ (";;extr.u %0 = %1,%4,16;; \
                            dep %2 = %0, %2, 0, 16;; \
                            st8 [%3] = %2;;"
       ::"r"(i),"r"(*sunat),"r"(*dunat),"r"(dunat),"i"(IA64_PT_REGS_R16_SLOT):"memory");

    }else{
        dst = &VCPU(v, vbgr[0]);
//        dunat =&VCPU(v, vbnat);
//        __asm__ __volatile__ (";;extr.u %0 = %1,%4,16;;
//                            dep %2 = %0, %2, 16, 16;;
//                            st8 [%3] = %2;;"
//       ::"r"(i),"r"(*sunat),"r"(*dunat),"r"(dunat),"i"(IA64_PT_REGS_R16_SLOT):"memory");

    }
    for(i=0; i<16; i++)
        *dst++ = *src++;
}


// ONLY gets called from ia64_leave_kernel
// ONLY call with interrupts disabled?? (else might miss one?)
// NEVER successful if already reflecting a trap/fault because psr.i==0
void leave_hypervisor_tail(void)
{
    struct domain *d = current->domain;
    struct vcpu *v = current;

    // FIXME: Will this work properly if doing an RFI???
    if (!is_idle_domain(d) ) {	// always comes from guest
//        struct pt_regs *user_regs = vcpu_regs(current);
        local_irq_enable();
        do_softirq();
        local_irq_disable();

        if (v->vcpu_id == 0) {
            unsigned long callback_irq =
                d->arch.hvm_domain.params[HVM_PARAM_CALLBACK_IRQ];

            if ( v->arch.arch_vmx.pal_init_pending ) {
                /*inject INIT interruption to guest pal*/
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
            return;
        }

        if (v->arch.irq_new_condition) {
            v->arch.irq_new_condition = 0;
            vhpi_detection(v);
        }
    }
}

extern ia64_rr vmx_vcpu_rr(VCPU *vcpu, u64 vadr);

static int vmx_handle_lds(REGS* regs)
{
    regs->cr_ipsr |=IA64_PSR_ED;
    return IA64_FAULT;
}

/* We came here because the H/W VHPT walker failed to find an entry */
IA64FAULT
vmx_hpw_miss(u64 vadr , u64 vec, REGS* regs)
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
    
    if (vec == 1)
        type = ISIDE_TLB;
    else if (vec == 2)
        type = DSIDE_TLB;
    else
        panic_domain(regs, "wrong vec:%lx\n", vec);

    if(is_physical_mode(v)&&(!(vadr<<1>>62))){
        if(vec==2){
            if (v->domain != dom0
                && __gpfn_is_io(v->domain, (vadr << 1) >> (PAGE_SHIFT + 1))) {
                emulate_io_inst(v,((vadr<<1)>>1),4);   //  UC
                return IA64_FAULT;
            }
        }
        physical_tlb_miss(v, vadr, type);
        return IA64_FAULT;
    }

    if((data=vtlb_lookup(v, vadr,type))!=0){
        if (v->domain != dom0 && type == DSIDE_TLB) {
            gppa = (vadr & ((1UL << data->ps) - 1)) +
                   (data->ppn >> (data->ps - 12) << data->ps);
            if (__gpfn_is_io(v->domain, gppa >> PAGE_SHIFT)) {
                if (data->pl >= ((regs->cr_ipsr >> IA64_PSR_CPL0_BIT) & 3))
                    emulate_io_inst(v, gppa, data->ma);
                else {
                    vcpu_set_isr(v, misr.val);
                    data_access_rights(v, vadr);
                }
                return IA64_FAULT;
            }
        }
        thash_vhpt_insert(v, data->page_flags, data->itir, vadr, type);

    }else if(type == DSIDE_TLB){
    
        if (misr.sp)
            return vmx_handle_lds(regs);

        if(!vhpt_enabled(v, vadr, misr.rs?RSE_REF:DATA_REF)){
            if(vpsr.ic){
                vcpu_set_isr(v, misr.val);
                alt_dtlb(v, vadr);
                return IA64_FAULT;
            } else{
                nested_dtlb(v);
                return IA64_FAULT;
            }
        }

        vmx_vcpu_get_pta(v, &vpta.val);
        if (vpta.vf) {
            /* Long format is not yet supported.  */
            if (vpsr.ic) {
                vcpu_set_isr(v, misr.val);
                dtlb_fault(v, vadr);
                return IA64_FAULT;
            } else {
                nested_dtlb(v);
                return IA64_FAULT;
            }
        }

        /* avoid recursively walking (short format) VHPT */
        if ((((vadr ^ vpta.val) << 3) >> (vpta.size + 3)) == 0) {
            if (vpsr.ic) {
                vcpu_set_isr(v, misr.val);
                dtlb_fault(v, vadr);
                return IA64_FAULT;
            } else {
                nested_dtlb(v);
                return IA64_FAULT;
            }
        }
            
        vmx_vcpu_thash(v, vadr, &vhpt_adr);
        if (!guest_vhpt_lookup(vhpt_adr, &pteval)) {
            /* VHPT successfully read.  */
            if (!(pteval & _PAGE_P)) {
                if (vpsr.ic) {
                    vcpu_set_isr(v, misr.val);
                    dtlb_fault(v, vadr);
                    return IA64_FAULT;
                } else {
                    nested_dtlb(v);
                    return IA64_FAULT;
                }
            } else if ((pteval & _PAGE_MA_MASK) != _PAGE_MA_ST) {
                vcpu_get_rr(v, vadr, &rr);
                itir = rr & (RR_RID_MASK | RR_PS_MASK);
                thash_purge_and_insert(v, pteval, itir, vadr, DSIDE_TLB);
                return IA64_NO_FAULT;
            } else if (vpsr.ic) {
                vcpu_set_isr(v, misr.val);
                dtlb_fault(v, vadr);
                return IA64_FAULT;
            }else{
                nested_dtlb(v);
                return IA64_FAULT;
            }
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
    }else if(type == ISIDE_TLB){
    
        if (!vpsr.ic)
            misr.ni = 1;
        if (!vhpt_enabled(v, vadr, INST_REF)) {
            vcpu_set_isr(v, misr.val);
            alt_itlb(v, vadr);
            return IA64_FAULT;
        }

        vmx_vcpu_get_pta(v, &vpta.val);
        if (vpta.vf) {
            /* Long format is not yet supported.  */
            vcpu_set_isr(v, misr.val);
            itlb_fault(v, vadr);
            return IA64_FAULT;
        }


        vmx_vcpu_thash(v, vadr, &vhpt_adr);
        if (!guest_vhpt_lookup(vhpt_adr, &pteval)) {
            /* VHPT successfully read.  */
            if (pteval & _PAGE_P) {
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
}
