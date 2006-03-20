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
#include <public/arch-ia64.h>
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
//u64  fire_itc;
//u64  fire_itc2;
//u64  fire_itm;
//u64  fire_itm2;
/*
 * Copyright (c) 2005 Intel Corporation.
 *    Anthony Xu (anthony.xu@intel.com)
 *    Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
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

/**************************************************************************
 VCPU general register access routines
**************************************************************************/
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>
//unsigned long last_guest_rsm = 0x0;
struct guest_psr_bundle{
    unsigned long ip;
    unsigned long psr;
};

struct guest_psr_bundle guest_psr_buf[100];
unsigned long guest_psr_index = 0;

void
vmx_vcpu_set_psr(VCPU *vcpu, unsigned long value)
{

    UINT64 mask;
    REGS *regs;
    IA64_PSR old_psr, new_psr;
    old_psr.val=vmx_vcpu_get_psr(vcpu);

    regs=vcpu_regs(vcpu);
    /* We only support guest as:
     *  vpsr.pk = 0
     *  vpsr.is = 0
     * Otherwise panic
     */
    if ( value & (IA64_PSR_PK | IA64_PSR_IS | IA64_PSR_VM )) {
        panic ("Setting unsupport guest psr!");
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
    new_psr.val=vmx_vcpu_get_psr(vcpu);
    {
    struct pt_regs *regs = vcpu_regs(vcpu);
    guest_psr_buf[guest_psr_index].ip = regs->cr_iip;
    guest_psr_buf[guest_psr_index].psr = new_psr.val;
    if (++guest_psr_index >= 100)
        guest_psr_index = 0;
    }
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

    check_mm_mode_switch(vcpu, old_psr, new_psr);
    return ;
}

/* Adjust slot both in pt_regs and vpd, upon vpsr.ri which
 * should have sync with ipsr in entry.
 *
 * Clear some bits due to successfully emulation.
 */
IA64FAULT vmx_vcpu_increment_iip(VCPU *vcpu)
{
    // TODO: trap_bounce?? Eddie
    REGS *regs = vcpu_regs(vcpu);
    IA64_PSR vpsr;
    IA64_PSR *ipsr = (IA64_PSR *)&regs->cr_ipsr;

    vpsr.val = vmx_vcpu_get_psr(vcpu);
    if (vpsr.ri == 2) {
    vpsr.ri = 0;
    regs->cr_iip += 16;
    } else {
    vpsr.ri++;
    }

    ipsr->ri = vpsr.ri;
    vpsr.val &=
            (~ (IA64_PSR_ID |IA64_PSR_DA | IA64_PSR_DD |
                IA64_PSR_SS | IA64_PSR_ED | IA64_PSR_IA
            ));

    VCPU(vcpu, vpsr) = vpsr.val;

    ipsr->val &=
            (~ (IA64_PSR_ID |IA64_PSR_DA | IA64_PSR_DD |
                IA64_PSR_SS | IA64_PSR_ED | IA64_PSR_IA
            ));

    return (IA64_NO_FAULT);
}


IA64FAULT vmx_vcpu_cover(VCPU *vcpu)
{
    REGS *regs = vcpu_regs(vcpu);
    IA64_PSR vpsr;
    vpsr.val = vmx_vcpu_get_psr(vcpu);

    if(!vpsr.ic)
        VCPU(vcpu,ifs) = regs->cr_ifs;
    regs->cr_ifs = IA64_IFS_V;
    return (IA64_NO_FAULT);
}


thash_cb_t *
vmx_vcpu_get_vtlb(VCPU *vcpu)
{
    return vcpu->arch.vtlb;
}


struct virtual_platform_def *
vmx_vcpu_get_plat(VCPU *vcpu)
{
    return &(vcpu->domain->arch.vmx_platform);
}



IA64FAULT vmx_vcpu_set_rr(VCPU *vcpu, UINT64 reg, UINT64 val)
{
    ia64_rr oldrr,newrr;
    thash_cb_t *hcb;
    extern void * pal_vaddr;
    vcpu_get_rr(vcpu, reg, &oldrr.rrval);
    newrr.rrval=val;
    if(oldrr.ps!=newrr.ps){
        hcb = vmx_vcpu_get_vtlb(vcpu);
        thash_purge_all(hcb);
    }
    VMX(vcpu,vrr[reg>>61]) = val;
    switch((u64)(reg>>61)) {
    case VRN7:
        vmx_switch_rr7(vmx_vrrtomrr(vcpu,val),vcpu->domain->shared_info,
        (void *)vcpu->arch.privregs,
        (void *)vcpu->arch.vtlb->vhpt->hash, pal_vaddr );
       break;
    default:
        ia64_set_rr(reg,vmx_vrrtomrr(vcpu,val));
        break;
    }

    return (IA64_NO_FAULT);
}



/**************************************************************************
 VCPU protection key register access routines
**************************************************************************/

IA64FAULT vmx_vcpu_get_pkr(VCPU *vcpu, UINT64 reg, UINT64 *pval)
{
    UINT64 val = (UINT64)ia64_get_pkr(reg);
    *pval = val;
    return (IA64_NO_FAULT);
}

IA64FAULT vmx_vcpu_set_pkr(VCPU *vcpu, UINT64 reg, UINT64 val)
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
     if (tlb_debug) printf("%s at %lx %lx\n", str, va, 1UL<<ps);
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
    UINT64 ifs, psr;
    REGS *regs = vcpu_regs(vcpu);
    psr = VCPU(vcpu,ipsr);
    vcpu_bsw1(vcpu);
    vmx_vcpu_set_psr(vcpu,psr);
    ifs=VCPU(vcpu,ifs);
    if((ifs>>63)&&(ifs<<1)){
        ifs=(regs->cr_ifs)&0x7f;
        regs->rfi_pfs = (ifs<<7)|ifs;
        regs->cr_ifs = VCPU(vcpu,ifs);
    }
    regs->cr_iip = VCPU(vcpu,iip);
    return (IA64_NO_FAULT);
}


UINT64
vmx_vcpu_get_psr(VCPU *vcpu)
{
    return VCPU(vcpu,vpsr);
}

#if 0
IA64FAULT
vmx_vcpu_get_bgr(VCPU *vcpu, unsigned int reg, UINT64 *val)
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
vmx_vcpu_get_gr(VCPU *vcpu, unsigned reg, UINT64 * val)
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

IA64FAULT vmx_vcpu_reset_psr_sm(VCPU *vcpu, UINT64 imm24)
{
    UINT64 vpsr;
    vpsr = vmx_vcpu_get_psr(vcpu);
    vpsr &= (~imm24);
    vmx_vcpu_set_psr(vcpu, vpsr);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_set_psr_sm(VCPU *vcpu, UINT64 imm24)
{
    UINT64 vpsr;
    vpsr = vmx_vcpu_get_psr(vcpu);
    vpsr |= imm24;
    vmx_vcpu_set_psr(vcpu, vpsr);
    return IA64_NO_FAULT;
}


IA64FAULT vmx_vcpu_set_psr_l(VCPU *vcpu, UINT64 val)
{
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

