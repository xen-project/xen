/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_vcpu.c: handling all virtual cpu related thing.
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
 *  Fred yang (fred.yang@intel.com)
 *  Arun Sharma (arun.sharma@intel.com)
 *  Shaofan Li (Susue Li) <susie.li@intel.com>
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */
#include <xen/sched.h>
#include <public/xen.h>
#include <asm/ia64_int.h>
#include <asm/vmx_vcpu.h>
#include <asm/regionreg.h>
#include <asm/tlb.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/regs.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx.h>
#include <asm/vmx_phy_mode.h>

/**************************************************************************
 VCPU general register access routines
**************************************************************************/
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>
//unsigned long last_guest_rsm = 0x0;

#ifdef	VTI_DEBUG
struct guest_psr_bundle{
    unsigned long ip;
    unsigned long psr;
};

struct guest_psr_bundle guest_psr_buf[100];
unsigned long guest_psr_index = 0;
#endif


void
vmx_ia64_set_dcr(VCPU *v)   
{
    unsigned long dcr_bits = IA64_DEFAULT_DCR_BITS;

    // if guest is runing on cpl > 0, set dcr.dm=1
    // if geust is runing on cpl = 0, set dcr.dm=0
    // because Guest OS may ld.s on tr mapped page.
    if (!(VCPU(v, vpsr) & IA64_PSR_CPL))
        dcr_bits &= ~IA64_DCR_DM;

    ia64_set_dcr(dcr_bits);
}


void
vmx_vcpu_set_psr(VCPU *vcpu, unsigned long value)
{

    u64 mask;
    REGS *regs;
    IA64_PSR old_psr, new_psr;
    old_psr.val=VCPU(vcpu, vpsr);

    regs=vcpu_regs(vcpu);
    /* We only support guest as:
     *  vpsr.pk = 0
     *  vpsr.is = 0
     * Otherwise panic
     */
    if ( value & (IA64_PSR_PK | IA64_PSR_IS | IA64_PSR_VM )) {
        panic_domain (regs,"Setting unsupport guest psr!");
    }

    /*
     * For those IA64_PSR bits: id/da/dd/ss/ed/ia
     * Since these bits will become 0, after success execution of each
     * instruction, we will change set them to mIA64_PSR
     */
    VCPU(vcpu,vpsr) = value &
            (~ (IA64_PSR_ID |IA64_PSR_DA | IA64_PSR_DD |
                IA64_PSR_SS | IA64_PSR_ED | IA64_PSR_IA
            ));

    if ( !old_psr.i && (value & IA64_PSR_I) ) {
        // vpsr.i 0->1
        vcpu->arch.irq_new_condition = 1;
    }
    new_psr.val=VCPU(vcpu, vpsr);
#ifdef	VTI_DEBUG    
    {
    struct pt_regs *regs = vcpu_regs(vcpu);
    guest_psr_buf[guest_psr_index].ip = regs->cr_iip;
    guest_psr_buf[guest_psr_index].psr = new_psr.val;
    if (++guest_psr_index >= 100)
        guest_psr_index = 0;
    }
#endif    
#if 0
    if (old_psr.i != new_psr.i) {
    if (old_psr.i)
        last_guest_rsm = vcpu_regs(vcpu)->cr_iip;
    else
        last_guest_rsm = 0;
    }
#endif

    /*
     * All vIA64_PSR bits shall go to mPSR (v->tf->tf_special.psr)
     * , except for the following bits:
     *  ic/i/dt/si/rt/mc/it/bn/vm
     */
    mask =  IA64_PSR_IC + IA64_PSR_I + IA64_PSR_DT + IA64_PSR_SI +
        IA64_PSR_RT + IA64_PSR_MC + IA64_PSR_IT + IA64_PSR_BN +
        IA64_PSR_VM;

    regs->cr_ipsr = (regs->cr_ipsr & mask ) | ( value & (~mask) );

    if (FP_PSR(vcpu) & IA64_PSR_DFH)
        regs->cr_ipsr |= IA64_PSR_DFH;

    check_mm_mode_switch(vcpu, old_psr, new_psr);
    return ;
}

IA64FAULT vmx_vcpu_cover(VCPU *vcpu)
{
    REGS *regs = vcpu_regs(vcpu);
    IA64_PSR vpsr;
    vpsr.val = VCPU(vcpu, vpsr);

    if(!vpsr.ic)
        VCPU(vcpu,ifs) = regs->cr_ifs;
    regs->cr_ifs = IA64_IFS_V;
    return (IA64_NO_FAULT);
}

struct virtual_platform_def *
vmx_vcpu_get_plat(VCPU *vcpu)
{
    return &(vcpu->domain->arch.vmx_platform);
}

IA64FAULT vmx_vcpu_set_rr(VCPU *vcpu, u64 reg, u64 val)
{
    ia64_rr oldrr,newrr;
    extern void * pal_vaddr;
    u64 rrval;

    vcpu_get_rr(vcpu, reg, &oldrr.rrval);
    newrr.rrval=val;
    if (newrr.rid >= (1 << vcpu->domain->arch.rid_bits))
        panic_domain (NULL, "use of invalid rid %x\n", newrr.rid);

    VMX(vcpu,vrr[reg>>VRN_SHIFT]) = val;
    switch((u64)(reg>>VRN_SHIFT)) {
    case VRN7:
        vmx_switch_rr7(vrrtomrr(vcpu,val),vcpu->domain->shared_info,
        (void *)vcpu->arch.privregs,
        (void *)vcpu->arch.vhpt.hash, pal_vaddr );
       break;
    case VRN4:
        rrval = vrrtomrr(vcpu,val);
        vcpu->arch.metaphysical_saved_rr4 = rrval;
        if (!is_physical_mode(vcpu))
            ia64_set_rr(reg,rrval);
        break;
    case VRN0:
        rrval = vrrtomrr(vcpu,val);
        vcpu->arch.metaphysical_saved_rr0 = rrval;
        if (!is_physical_mode(vcpu))
            ia64_set_rr(reg,rrval);
        break;
    default:
        ia64_set_rr(reg,vrrtomrr(vcpu,val));
        break;
    }

    return (IA64_NO_FAULT);
}



/**************************************************************************
 VCPU protection key register access routines
**************************************************************************/

IA64FAULT vmx_vcpu_get_pkr(VCPU *vcpu, u64 reg, u64 *pval)
{
    u64 val = (u64)ia64_get_pkr(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}

IA64FAULT vmx_vcpu_set_pkr(VCPU *vcpu, u64 reg, u64 val)
{
    ia64_set_pkr(reg,val);
    return (IA64_NO_FAULT);
}

#if 0
int tlb_debug=0;
check_entry(u64 va, u64 ps, char *str)
{
     va &= ~ (PSIZE(ps)-1);
     if ( va == 0x2000000002908000UL ||
      va == 0x600000000000C000UL ) {
    stop();
     }
     if (tlb_debug) printk("%s at %lx %lx\n", str, va, 1UL<<ps);
}
#endif


u64 vmx_vcpu_get_itir_on_fault(VCPU *vcpu, u64 ifa)
{
    ia64_rr rr,rr1;
    vcpu_get_rr(vcpu,ifa,&rr.rrval);
    rr1.rrval=0;
    rr1.ps=rr.ps;
    rr1.rid=rr.rid;
    return (rr1.rrval);
}




IA64FAULT vmx_vcpu_rfi(VCPU *vcpu)
{
    // TODO: Only allowed for current vcpu
    u64 ifs, psr;
    REGS *regs = vcpu_regs(vcpu);
    psr = VCPU(vcpu,ipsr);
    if (psr & IA64_PSR_BN)
        vcpu_bsw1(vcpu);
    else
        vcpu_bsw0(vcpu);
    vmx_vcpu_set_psr(vcpu,psr);
    vmx_ia64_set_dcr(vcpu);
    ifs=VCPU(vcpu,ifs);
    if(ifs>>63)
        regs->cr_ifs = ifs;
    regs->cr_iip = VCPU(vcpu,iip);
    return (IA64_NO_FAULT);
}


#if 0
IA64FAULT
vmx_vcpu_get_bgr(VCPU *vcpu, unsigned int reg, u64 *val)
{
    IA64_PSR vpsr;

    vpsr.val = vmx_vcpu_get_psr(vcpu);
    if ( vpsr.bn ) {
        *val=VCPU(vcpu,vgr[reg-16]);
        // Check NAT bit
        if ( VCPU(vcpu,vnat) & (1UL<<(reg-16)) ) {
            // TODO
            //panic ("NAT consumption fault\n");
            return IA64_FAULT;
        }

    }
    else {
        *val=VCPU(vcpu,vbgr[reg-16]);
        if ( VCPU(vcpu,vbnat) & (1UL<<reg) ) {
            //panic ("NAT consumption fault\n");
            return IA64_FAULT;
        }

    }
    return IA64_NO_FAULT;
}

IA64FAULT
vmx_vcpu_set_bgr(VCPU *vcpu, unsigned int reg, u64 val,int nat)
{
    IA64_PSR vpsr;
    vpsr.val = vmx_vcpu_get_psr(vcpu);
    if ( vpsr.bn ) {
        VCPU(vcpu,vgr[reg-16]) = val;
        if(nat){
            VCPU(vcpu,vnat) |= ( 1UL<<(reg-16) );
        }else{
            VCPU(vcpu,vbnat) &= ~( 1UL<<(reg-16) );
        }
    }
    else {
        VCPU(vcpu,vbgr[reg-16]) = val;
        if(nat){
            VCPU(vcpu,vnat) |= ( 1UL<<(reg) );
        }else{
            VCPU(vcpu,vbnat) &= ~( 1UL<<(reg) );
        }
    }
    return IA64_NO_FAULT;
}

#endif
#if 0
IA64FAULT
vmx_vcpu_get_gr(VCPU *vcpu, unsigned reg, u64 * val)
{
    REGS *regs=vcpu_regs(vcpu);
    int nat;
    //TODO, Eddie
    if (!regs) return 0;
#if 0
    if (reg >= 16 && reg < 32) {
        return vmx_vcpu_get_bgr(vcpu,reg,val);
    }
#endif
    getreg(reg,val,&nat,regs);    // FIXME: handle NATs later
    if(nat){
        return IA64_FAULT;
    }
    return IA64_NO_FAULT;
}

// returns:
//   IA64_ILLOP_FAULT if the register would cause an Illegal Operation fault
//   IA64_NO_FAULT otherwise

IA64FAULT
vmx_vcpu_set_gr(VCPU *vcpu, unsigned reg, u64 value, int nat)
{
    REGS *regs = vcpu_regs(vcpu);
    long sof = (regs->cr_ifs) & 0x7f;
    //TODO Eddie

    if (!regs) return IA64_ILLOP_FAULT;
    if (reg >= sof + 32) return IA64_ILLOP_FAULT;
#if 0
    if ( reg >= 16 && reg < 32 ) {
        return vmx_vcpu_set_bgr(vcpu,reg, value, nat);
    }
#endif
    setreg(reg,value,nat,regs);
    return IA64_NO_FAULT;
}

#endif

/*
    VPSR can't keep track of below bits of guest PSR
    This function gets guest PSR
 */

u64 vmx_vcpu_get_psr(VCPU *vcpu)
{
    u64 mask;
    REGS *regs = vcpu_regs(vcpu);
    mask = IA64_PSR_BE | IA64_PSR_UP | IA64_PSR_AC | IA64_PSR_MFL |
           IA64_PSR_MFH | IA64_PSR_CPL | IA64_PSR_RI;
    return (VCPU(vcpu, vpsr) & ~mask) | (regs->cr_ipsr & mask);
}

IA64FAULT vmx_vcpu_reset_psr_sm(VCPU *vcpu, u64 imm24)
{
    u64 vpsr;
    vpsr = vmx_vcpu_get_psr(vcpu);
    vpsr &= (~imm24);
    vmx_vcpu_set_psr(vcpu, vpsr);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_set_psr_sm(VCPU *vcpu, u64 imm24)
{
    u64 vpsr;
    vpsr = vmx_vcpu_get_psr(vcpu);
    vpsr |= imm24;
    vmx_vcpu_set_psr(vcpu, vpsr);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_set_psr_l(VCPU *vcpu, u64 val)
{
    val = (val & MASK(0, 32)) | (vmx_vcpu_get_psr(vcpu) & MASK(32, 32));
    vmx_vcpu_set_psr(vcpu, val);
    return IA64_NO_FAULT;
}

IA64FAULT
vmx_vcpu_set_tpr(VCPU *vcpu, u64 val)
{
    VCPU(vcpu,tpr)=val;
    vcpu->arch.irq_new_condition = 1;
    return IA64_NO_FAULT;
}

