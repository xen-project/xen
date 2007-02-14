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
/* SDM vol2 5.5 - IVA based interruption handling */
#define INITIAL_PSR_VALUE_AT_INTERRUPTION 0x0000001808028034
void
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
        vpsr.val &= ~IA64_PSR_PP;;
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
    regs=vcpu_regs(vcpu);
    // clear cr.isr.ri 
    pt_isr.val = VMX(vcpu,cr_isr);
    pt_isr.ir = 0;
    VMX(vcpu,cr_isr) = pt_isr.val;
    collect_interruption(vcpu);
    vmx_ia64_set_dcr(vcpu);
    vmx_vcpu_get_iva(vcpu,&viva);
    regs->cr_iip = viva + vec;
}


/*
 * Set vIFA & vITIR & vIHA, when vPSR.ic =1
 * Parameter:
 *  set_ifa: if true, set vIFA
 *  set_itir: if true, set vITIR
 *  set_iha: if true, set vIHA
 */
void
set_ifa_itir_iha (VCPU *vcpu, u64 vadr,
          int set_ifa, int set_itir, int set_iha)
{
    IA64_PSR vpsr;
    u64 value;
    vpsr.val = VCPU(vcpu, vpsr);
    /* Vol2, Table 8-1 */
    if ( vpsr.ic ) {
        if ( set_ifa){
            vcpu_set_ifa(vcpu, vadr);
        }
        if ( set_itir) {
            value = vmx_vcpu_get_itir_on_fault(vcpu, vadr);
            vcpu_set_itir(vcpu, value);
        }

        if ( set_iha) {
            vmx_vcpu_thash(vcpu, vadr, &value);
            vcpu_set_iha(vcpu, value);
        }
    }


}

/*
 * Data TLB Fault
 *  @ Data TLB vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
dtlb_fault (VCPU *vcpu, u64 vadr)
{
    /* If vPSR.ic, IFA, ITIR, IHA */
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 1);
    inject_guest_interruption(vcpu,IA64_DATA_TLB_VECTOR);
}

/*
 * Instruction TLB Fault
 *  @ Instruction TLB vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
itlb_fault (VCPU *vcpu, u64 vadr)
{
     /* If vPSR.ic, IFA, ITIR, IHA */
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 1);
    inject_guest_interruption(vcpu,IA64_INST_TLB_VECTOR);
}



/*
 * Data Nested TLB Fault
 *  @ Data Nested TLB Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
nested_dtlb (VCPU *vcpu)
{
    inject_guest_interruption(vcpu,IA64_DATA_NESTED_TLB_VECTOR);
}

/*
 * Alternate Data TLB Fault
 *  @ Alternate Data TLB vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
alt_dtlb (VCPU *vcpu, u64 vadr)
{
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 0);
    inject_guest_interruption(vcpu,IA64_ALT_DATA_TLB_VECTOR);
}


/*
 * Data TLB Fault
 *  @ Data TLB vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
alt_itlb (VCPU *vcpu, u64 vadr)
{
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 0);
    inject_guest_interruption(vcpu,IA64_ALT_INST_TLB_VECTOR);
}

/* Deal with:
 *  VHPT Translation Vector
 */
static void
_vhpt_fault(VCPU *vcpu, u64 vadr)
{
    /* If vPSR.ic, IFA, ITIR, IHA*/
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 1);
    inject_guest_interruption(vcpu,IA64_VHPT_TRANS_VECTOR);


}

/*
 * VHPT Instruction Fault
 *  @ VHPT Translation vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
ivhpt_fault (VCPU *vcpu, u64 vadr)
{
    _vhpt_fault(vcpu, vadr);
}


/*
 * VHPT Data Fault
 *  @ VHPT Translation vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
dvhpt_fault (VCPU *vcpu, u64 vadr)
{
    _vhpt_fault(vcpu, vadr);
}



/*
 * Deal with:
 *  General Exception vector
 */
void
_general_exception (VCPU *vcpu)
{
    inject_guest_interruption(vcpu,IA64_GENEX_VECTOR);
}


/*
 * Illegal Operation Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
illegal_op (VCPU *vcpu)
{
    _general_exception(vcpu);
}

/*
 * Illegal Dependency Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
illegal_dep (VCPU *vcpu)
{
    _general_exception(vcpu);
}

/*
 * Reserved Register/Field Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
rsv_reg_field (VCPU *vcpu)
{
    _general_exception(vcpu);
}
/*
 * Privileged Operation Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */

void
privilege_op (VCPU *vcpu)
{
    _general_exception(vcpu);
}

/*
 * Unimplement Data Address Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
unimpl_daddr (VCPU *vcpu)
{
    _general_exception(vcpu);
}

/*
 * Privileged Register Fault
 *  @ General Exception Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
privilege_reg (VCPU *vcpu)
{
    _general_exception(vcpu);
}

/* Deal with
 *  Nat consumption vector
 * Parameter:
 *  vaddr: Optional, if t == REGISTER
 */
static void
_nat_consumption_fault(VCPU *vcpu, u64 vadr, miss_type t)
{
    /* If vPSR.ic && t == DATA/INST, IFA */
    if ( t == DATA || t == INSTRUCTION ) {
        /* IFA */
        set_ifa_itir_iha (vcpu, vadr, 1, 0, 0);
    }

    inject_guest_interruption(vcpu,IA64_NAT_CONSUMPTION_VECTOR);
}

/*
 * IR Data Nat Page Consumption Fault
 *  @ Nat Consumption Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
#if 0
static void
ir_nat_page_consumption (VCPU *vcpu, u64 vadr)
{
    _nat_consumption_fault(vcpu, vadr, DATA);
}
#endif //shadow it due to no use currently 

/*
 * Instruction Nat Page Consumption Fault
 *  @ Nat Consumption Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
inat_page_consumption (VCPU *vcpu, u64 vadr)
{
    _nat_consumption_fault(vcpu, vadr, INSTRUCTION);
}

/*
 * Register Nat Consumption Fault
 *  @ Nat Consumption Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
rnat_consumption (VCPU *vcpu)
{
    _nat_consumption_fault(vcpu, 0, REGISTER);
}

/*
 * Data Nat Page Consumption Fault
 *  @ Nat Consumption Vector
 * Refer to SDM Vol2 Table 5-6 & 8-1
 */
void
dnat_page_consumption (VCPU *vcpu, uint64_t vadr)
{
    _nat_consumption_fault(vcpu, vadr, DATA);
}

/* Deal with
 *  Page not present vector
 */
static void
__page_not_present(VCPU *vcpu, u64 vadr)
{
    /* If vPSR.ic, IFA, ITIR */
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 0);
    inject_guest_interruption(vcpu, IA64_PAGE_NOT_PRESENT_VECTOR);
}


void
data_page_not_present(VCPU *vcpu, u64 vadr)
{
    __page_not_present(vcpu, vadr);
}


void
inst_page_not_present(VCPU *vcpu, u64 vadr)
{
    __page_not_present(vcpu, vadr);
}


/* Deal with
 *  Data access rights vector
 */
void
data_access_rights(VCPU *vcpu, u64 vadr)
{
    /* If vPSR.ic, IFA, ITIR */
    set_ifa_itir_iha (vcpu, vadr, 1, 1, 0);
    inject_guest_interruption(vcpu, IA64_DATA_ACCESS_RIGHTS_VECTOR);
}

