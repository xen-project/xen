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
//#include <asm/ldt.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <asm/regionreg.h>
#include <asm/privop.h>
#include <asm/ia64_int.h>
#include <asm/hpsim_ssc.h>
#include <asm/dom_fw.h>
#include <asm/vmx_vcpu.h>
#include <asm/kregs.h>
#include <asm/vmx_mm_def.h>
/* reset all PSR field to 0, except up,mfl,mfh,pk,dt,rt,mc,it */
#define INITIAL_PSR_VALUE_AT_INTERRUPTION 0x0000001808028034


extern struct ia64_sal_retval pal_emulator_static(UINT64);
extern struct ia64_sal_retval sal_emulator(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
extern void rnat_consumption (VCPU *vcpu);

IA64FAULT
vmx_ia64_handle_break (unsigned long ifa, struct pt_regs *regs, unsigned long isr, unsigned long iim)
{
	static int first_time = 1;
	struct domain *d = (struct domain *) current->domain;
	struct exec_domain *ed = (struct domain *) current;
	extern unsigned long running_on_sim;
	unsigned long i, sal_param[8];

#if 0
	if (first_time) {
		if (platform_is_hp_ski()) running_on_sim = 1;
		else running_on_sim = 0;
		first_time = 0;
	}
	if (iim == 0x80001 || iim == 0x80002) {	//FIXME: don't hardcode constant
		if (running_on_sim) do_ssc(vcpu_get_gr(current,36), regs);
		else do_ssc(vcpu_get_gr(current,36), regs);
	}
#endif
	if (iim == d->breakimm) {
		struct ia64_sal_retval x;
		switch (regs->r2) {
		    case FW_HYPERCALL_PAL_CALL:
			//printf("*** PAL hypercall: index=%d\n",regs->r28);
			//FIXME: This should call a C routine
			x = pal_emulator_static(VMX_VPD(ed, vgr[12]));
			regs->r8 = x.status; regs->r9 = x.v0;
			regs->r10 = x.v1; regs->r11 = x.v2;
#if 0
			if (regs->r8)
				printk("Failed vpal emulation, with index:0x%lx\n",
					VMX_VPD(ed, vgr[12]));
#endif
			break;
		    case FW_HYPERCALL_SAL_CALL:
			for (i = 0; i < 8; i++)
				vmx_vcpu_get_gr(ed, 32+i, &sal_param[i]);
			x = sal_emulator(sal_param[0], sal_param[1],
					 sal_param[2], sal_param[3],
					 sal_param[4], sal_param[5],
					 sal_param[6], sal_param[7]);
			regs->r8 = x.status; regs->r9 = x.v0;
			regs->r10 = x.v1; regs->r11 = x.v2;
#if 0
			if (regs->r8)
				printk("Failed vsal emulation, with index:0x%lx\n",
					sal_param[0]);
#endif
			break;
		    case FW_HYPERCALL_EFI_RESET_SYSTEM:
			printf("efi.reset_system called ");
			if (current->domain == dom0) {
				printf("(by dom0)\n ");
				(*efi.reset_system)(EFI_RESET_WARM,0,0,NULL);
			}
			printf("(not supported for non-0 domain)\n");
			regs->r8 = EFI_UNSUPPORTED;
			break;
		    case FW_HYPERCALL_EFI_GET_TIME:
			{
			unsigned long *tv, *tc;
			fooefi();
			vmx_vcpu_get_gr(ed, 32, &tv);
			vmx_vcpu_get_gr(ed, 33, &tc);
			printf("efi_get_time(%p,%p) called...",tv,tc);
			tv = __va(translate_domain_mpaddr(tv));
			if (tc) tc = __va(translate_domain_mpaddr(tc));
			regs->r8 = (*efi.get_time)(tv,tc);
			printf("and returns %lx\n",regs->r8);
			}
			break;
		    case FW_HYPERCALL_EFI_SET_TIME:
		    case FW_HYPERCALL_EFI_GET_WAKEUP_TIME:
		    case FW_HYPERCALL_EFI_SET_WAKEUP_TIME:
			// FIXME: need fixes in efi.h from 2.6.9
		    case FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP:
			// FIXME: WARNING!! IF THIS EVER GETS IMPLEMENTED
			// SOME OF THE OTHER EFI EMULATIONS WILL CHANGE AS
			// POINTER ARGUMENTS WILL BE VIRTUAL!!
		    case FW_HYPERCALL_EFI_GET_VARIABLE:
			// FIXME: need fixes in efi.h from 2.6.9
		    case FW_HYPERCALL_EFI_GET_NEXT_VARIABLE:
		    case FW_HYPERCALL_EFI_SET_VARIABLE:
		    case FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT:
			// FIXME: need fixes in efi.h from 2.6.9
			regs->r8 = EFI_UNSUPPORTED;
			break;
		}
#if 0
		if (regs->r8)
			printk("Failed vgfw emulation, with index:0x%lx\n",
				regs->r2);
#endif
		vmx_vcpu_increment_iip(current);
	} else
		vmx_reflect_interruption(ifa,isr,iim,11);
}

static UINT64 vec2off[68] = {0x0,0x400,0x800,0xc00,0x1000, 0x1400,0x1800,
    0x1c00,0x2000,0x2400,0x2800,0x2c00,0x3000,0x3400,0x3800,0x3c00,0x4000,
    0x4400,0x4800,0x4c00,0x5000,0x5100,0x5200,0x5300,0x5400,0x5500,0x5600,
    0x5700,0x5800,0x5900,0x5a00,0x5b00,0x5c00,0x5d00,0x5e00,0x5f00,0x6000,
    0x6100,0x6200,0x6300,0x6400,0x6500,0x6600,0x6700,0x6800,0x6900,0x6a00,
    0x6b00,0x6c00,0x6d00,0x6e00,0x6f00,0x7000,0x7100,0x7200,0x7300,0x7400,
    0x7500,0x7600,0x7700,0x7800,0x7900,0x7a00,0x7b00,0x7c00,0x7d00,0x7e00,
    0x7f00,
};



void vmx_reflect_interruption(UINT64 ifa,UINT64 isr,UINT64 iim,
     UINT64 vector)
{
    VCPU *vcpu = current;
    REGS *regs=vcpu_regs(vcpu);
    UINT64 viha,vpsr = vmx_vcpu_get_psr(vcpu);
    if(!(vpsr&IA64_PSR_IC)&&(vector!=5)){
        panic("Guest nested fault!");
    }
    VPD_CR(vcpu,isr)=isr;
    VPD_CR(vcpu,iipa) = regs->cr_iip;
    vector=vec2off[vector];
    if (vector == IA64_BREAK_VECTOR || vector == IA64_SPECULATION_VECTOR)
        VPD_CR(vcpu,iim) = iim;
    else {
        set_ifa_itir_iha(vcpu,ifa,1,1,1);
    }
    inject_guest_interruption(vcpu, vector);
}

// ONLY gets called from ia64_leave_kernel
// ONLY call with interrupts disabled?? (else might miss one?)
// NEVER successful if already reflecting a trap/fault because psr.i==0
void vmx_deliver_pending_interrupt(struct pt_regs *regs)
{
	struct domain *d = current->domain;
	struct exec_domain *ed = current;
	// FIXME: Will this work properly if doing an RFI???
	if (!is_idle_task(d) ) {	// always comes from guest
		//vcpu_poke_timer(ed);
		//if (vcpu_deliverable_interrupts(ed)) {
		//	unsigned long isr = regs->cr_ipsr & IA64_PSR_RI;
		//	foodpi();
		//	reflect_interruption(0,isr,0,regs,IA64_EXTINT_VECTOR);
		//}
	        extern void vmx_dorfirfi(void);
		struct pt_regs *user_regs = vcpu_regs(current);

		if (user_regs != regs)
			printk("WARNING: checking pending interrupt in nested interrupt!!!\n");
		if (regs->cr_iip == *(unsigned long *)vmx_dorfirfi)
			return;
		vmx_check_pending_irq(ed);
	}
}

extern ia64_rr vmx_vcpu_rr(VCPU *vcpu,UINT64 vadr);

/* We came here because the H/W VHPT walker failed to find an entry */
void vmx_hpw_miss(VCPU *vcpu, u64 vec, u64 vadr)
{
    IA64_PSR vpsr;
    CACHE_LINE_TYPE type;
    u64 vhpt_adr;
    ISR misr;
    ia64_rr vrr;
    REGS *regs;
    thash_cb_t *vtlb, *vhpt;
    thash_data_t *data, me;
    vtlb=vmx_vcpu_get_vtlb(vcpu);
#ifdef  VTLB_DEBUG
    check_vtlb_sanity(vtlb);
    dump_vtlb(vtlb);
#endif
    vpsr.val = vmx_vcpu_get_psr(vcpu);
    regs = vcpu_regs(vcpu);
    misr.val=regs->cr_isr;
/*  TODO
    if(vcpu->domain->id && vec == 2 &&
       vpsr.dt == 0 && is_gpa_io(MASK_PMA(vaddr))){
        emulate_ins(&v);
        return;
    }
*/

    if((vec==1)&&(!vpsr.it)){
        physical_itlb_miss(vcpu, vadr);
        return;
    }
    if((vec==2)&&(!vpsr.dt)){
        physical_dtlb_miss(vcpu, vadr);
        return;
    }
    vrr = vmx_vcpu_rr(vcpu,vadr);
    if(vec == 1) type = ISIDE_TLB;
    else if(vec == 2) type = DSIDE_TLB;
    else panic("wrong vec\n");

//    prepare_if_physical_mode(vcpu);

    if(data=vtlb_lookup_ex(vtlb, vrr.rid, vadr,type)){
    	if ( data->ps != vrr.ps ) {
    		machine_tlb_insert(vcpu, data);
    	}
    	else {
	        thash_insert(vtlb->ts->vhpt,data,vadr);
	    }
    }else if(type == DSIDE_TLB){
        if(!vhpt_enabled(vcpu, vadr, misr.rs?RSE_REF:DATA_REF)){
            if(vpsr.ic){
                vmx_vcpu_set_isr(vcpu, misr.val);
                alt_dtlb(vcpu, vadr);
                return IA64_FAULT;
            } else{
                if(misr.sp){
                    //TODO  lds emulation
                    panic("Don't support speculation load");
                }else{
                    nested_dtlb(vcpu);
                    return IA64_FAULT;
                }
            }
        } else{
            vmx_vcpu_thash(vcpu, vadr, &vhpt_adr);
            vrr=vmx_vcpu_rr(vcpu,vhpt_adr);
            data = vtlb_lookup_ex(vtlb, vrr.rid, vhpt_adr, DSIDE_TLB);
            if(data){
                if(vpsr.ic){
                    vmx_vcpu_set_isr(vcpu, misr.val);
                    dtlb_fault(vcpu, vadr);
                    return IA64_FAULT;
                }else{
                    if(misr.sp){
                        //TODO  lds emulation
                        panic("Don't support speculation load");
                    }else{
                        nested_dtlb(vcpu);
                        return IA64_FAULT;
                    }
                }
            }else{
                if(vpsr.ic){
                    vmx_vcpu_set_isr(vcpu, misr.val);
                    dvhpt_fault(vcpu, vadr);
                    return IA64_FAULT;
                }else{
                    if(misr.sp){
                        //TODO  lds emulation
                        panic("Don't support speculation load");
                    }else{
                        nested_dtlb(vcpu);
                        return IA64_FAULT;
                    }
                }
            }
        }
    }else if(type == ISIDE_TLB){
        if(!vhpt_enabled(vcpu, vadr, misr.rs?RSE_REF:DATA_REF)){
            if(!vpsr.ic){
                misr.ni=1;
            }
            vmx_vcpu_set_isr(vcpu, misr.val);
            alt_itlb(vcpu, vadr);
            return IA64_FAULT;
        } else{
            vmx_vcpu_thash(vcpu, vadr, &vhpt_adr);
            vrr=vmx_vcpu_rr(vcpu,vhpt_adr);
            data = vtlb_lookup_ex(vtlb, vrr.rid, vhpt_adr, DSIDE_TLB);
            if(data){
                if(!vpsr.ic){
                    misr.ni=1;
                }
                vmx_vcpu_set_isr(vcpu, misr.val);
                itlb_fault(vcpu, vadr);
                return IA64_FAULT;
            }else{
                if(!vpsr.ic){
                    misr.ni=1;
                }
                vmx_vcpu_set_isr(vcpu, misr.val);
                ivhpt_fault(vcpu, vadr);
                return IA64_FAULT;
            }
        }
    }
}


