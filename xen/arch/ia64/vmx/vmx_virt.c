/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_virt.c:
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
 *  Shaofan Li (Susue Li) <susie.li@intel.com>
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */
#include <asm/bundle.h>
#include <asm/vmx_vcpu.h>
#include <asm/processor.h>
#include <asm/delay.h>	// Debug only
#include <asm/vmmu.h>
#include <asm/vmx_mm_def.h>
#include <asm/smp.h>
#include <asm/vmx.h>
#include <asm/virt_event.h>
#include <asm/vmx_phy_mode.h>

#ifdef BYPASS_VMAL_OPCODE
static void
ia64_priv_decoder(IA64_SLOT_TYPE slot_type, INST64 inst, u64 * cause)
{
    *cause=0;
    switch (slot_type) {
        case M:
        if (inst.generic.major==0){
            if(inst.M28.x3==0){
                if(inst.M44.x4==6){
                    *cause=EVENT_SSM;
                }else if(inst.M44.x4==7){
                    *cause=EVENT_RSM;
                }else if(inst.M30.x4==8&&inst.M30.x2==2){
                    *cause=EVENT_MOV_TO_AR_IMM;
                }
            }
        }
        else if(inst.generic.major==1){
            if(inst.M28.x3==0){
                if(inst.M32.x6==0x2c){
                    *cause=EVENT_MOV_TO_CR;
                }else if(inst.M33.x6==0x24){
                    *cause=EVENT_MOV_FROM_CR;
                }else if(inst.M35.x6==0x2d){
                    *cause=EVENT_MOV_TO_PSR;
                }else if(inst.M36.x6==0x25){
                    *cause=EVENT_MOV_FROM_PSR;
                }else if(inst.M29.x6==0x2A){
                    *cause=EVENT_MOV_TO_AR;
                }else if(inst.M31.x6==0x22){
                    *cause=EVENT_MOV_FROM_AR;
                }else if(inst.M45.x6==0x09){
                    *cause=EVENT_PTC_L;
                }else if(inst.M45.x6==0x0A){
                    *cause=EVENT_PTC_G;
                }else if(inst.M45.x6==0x0B){
                    *cause=EVENT_PTC_GA;
                }else if(inst.M45.x6==0x0C){
                    *cause=EVENT_PTR_D;
                }else if(inst.M45.x6==0x0D){
                    *cause=EVENT_PTR_I;
                }else if(inst.M46.x6==0x1A){
                    *cause=EVENT_THASH;
                }else if(inst.M46.x6==0x1B){
                    *cause=EVENT_TTAG;
                }else if(inst.M46.x6==0x1E){
                    *cause=EVENT_TPA;
                }else if(inst.M46.x6==0x1F){
                    *cause=EVENT_TAK;
                }else if(inst.M47.x6==0x34){
                    *cause=EVENT_PTC_E;
                }else if(inst.M41.x6==0x2E){
                    *cause=EVENT_ITC_D;
                }else if(inst.M41.x6==0x2F){
                    *cause=EVENT_ITC_I;
                }else if(inst.M42.x6==0x00){
                    *cause=EVENT_MOV_TO_RR;
                }else if(inst.M42.x6==0x01){
                    *cause=EVENT_MOV_TO_DBR;
                }else if(inst.M42.x6==0x02){
                    *cause=EVENT_MOV_TO_IBR;
                }else if(inst.M42.x6==0x03){
                    *cause=EVENT_MOV_TO_PKR;
                }else if(inst.M42.x6==0x04){
                    *cause=EVENT_MOV_TO_PMC;
                }else if(inst.M42.x6==0x05){
                    *cause=EVENT_MOV_TO_PMD;
                }else if(inst.M42.x6==0x0E){
                    *cause=EVENT_ITR_D;
                }else if(inst.M42.x6==0x0F){
                    *cause=EVENT_ITR_I;
                }else if(inst.M43.x6==0x10){
                    *cause=EVENT_MOV_FROM_RR;
                }else if(inst.M43.x6==0x11){
                    *cause=EVENT_MOV_FROM_DBR;
                }else if(inst.M43.x6==0x12){
                    *cause=EVENT_MOV_FROM_IBR;
                }else if(inst.M43.x6==0x13){
                    *cause=EVENT_MOV_FROM_PKR;
                }else if(inst.M43.x6==0x14){
                    *cause=EVENT_MOV_FROM_PMC;
/*
                }else if(inst.M43.x6==0x15){
                    *cause=EVENT_MOV_FROM_PMD;
*/
                }else if(inst.M43.x6==0x17){
                    *cause=EVENT_MOV_FROM_CPUID;
                }
            }
        }
        break;
        case B:
        if(inst.generic.major==0){
            if(inst.B8.x6==0x02){
                *cause=EVENT_COVER;
            }else if(inst.B8.x6==0x08){
                *cause=EVENT_RFI;
            }else if(inst.B8.x6==0x0c){
                *cause=EVENT_BSW_0;
            }else if(inst.B8.x6==0x0d){
                *cause=EVENT_BSW_1;
            }
        }
        case I:
        case F:
        case L:
        case ILLEGAL:
        break;
    }
}
#endif

static IA64FAULT vmx_emul_rsm(VCPU *vcpu, INST64 inst)
{
    u64 imm24 = (inst.M44.i << 23) | (inst.M44.i2 << 21) | inst.M44.imm;
    return vmx_vcpu_reset_psr_sm(vcpu,imm24);
}

static IA64FAULT vmx_emul_ssm(VCPU *vcpu, INST64 inst)
{
    u64 imm24 = (inst.M44.i << 23) | (inst.M44.i2 << 21) | inst.M44.imm;
    return vmx_vcpu_set_psr_sm(vcpu,imm24);
}

static IA64FAULT vmx_emul_mov_from_psr(VCPU *vcpu, INST64 inst)
{
    u64 tgt = inst.M33.r1;
    u64 val;

/*
    if ((fault = vmx_vcpu_get_psr(vcpu,&val)) == IA64_NO_FAULT)
        return vcpu_set_gr(vcpu, tgt, val);
    else return fault;
    */
    val = vmx_vcpu_get_psr(vcpu);
    val = (val & MASK(0, 32)) | (val & MASK(35, 2));
    return vcpu_set_gr(vcpu, tgt, val, 0);
}

/**
 * @todo Check for reserved bits and return IA64_RSVDREG_FAULT.
 */
static IA64FAULT vmx_emul_mov_to_psr(VCPU *vcpu, INST64 inst)
{
    u64 val;

    if(vcpu_get_gr_nat(vcpu, inst.M35.r2, &val) != IA64_NO_FAULT)
	panic_domain(vcpu_regs(vcpu),"get_psr nat bit fault\n");

    return vmx_vcpu_set_psr_l(vcpu, val);
}


/**************************************************************************
Privileged operation emulation routines
**************************************************************************/

static IA64FAULT vmx_emul_rfi(VCPU *vcpu, INST64 inst)
{
    IA64_PSR  vpsr;
    REGS *regs;
#ifdef  CHECK_FAULT
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    regs=vcpu_regs(vcpu);
    vpsr.val=regs->cr_ipsr;
    if ( vpsr.is == 1 ) {
        panic_domain(regs,"We do not support IA32 instruction yet");
    }

    return vmx_vcpu_rfi(vcpu);
}

static IA64FAULT vmx_emul_bsw0(VCPU *vcpu, INST64 inst)
{
#ifdef  CHECK_FAULT
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
   return vcpu_bsw0(vcpu);
}

static IA64FAULT vmx_emul_bsw1(VCPU *vcpu, INST64 inst)
{
#ifdef  CHECK_FAULT
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    return vcpu_bsw1(vcpu);
}

static IA64FAULT vmx_emul_cover(VCPU *vcpu, INST64 inst)
{
    return vmx_vcpu_cover(vcpu);
}

static IA64FAULT vmx_emul_ptc_l(VCPU *vcpu, INST64 inst)
{
    u64 r2,r3;
#ifdef  VMAL_NO_FAULT_CHECK
    IA64_PSR  vpsr;

    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    if(vcpu_get_gr_nat(vcpu,inst.M45.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M45.r2,&r2)){
#ifdef  VMAL_NO_FAULT_CHECK
        ISR isr;
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (unimplemented_gva(vcpu,r3) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK
    return vmx_vcpu_ptc_l(vcpu,r3,bits(r2,2,7));
}

static IA64FAULT vmx_emul_ptc_e(VCPU *vcpu, INST64 inst)
{
    u64 r3;
#ifdef  VMAL_NO_FAULT_CHECK
    IA64_PSR  vpsr;

    vpsr.val=vmx_vcpu_get_psr(vcpu);
    ISR isr;
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    if(vcpu_get_gr_nat(vcpu,inst.M47.r3,&r3)){
#ifdef  VMAL_NO_FAULT_CHECK
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
    return vmx_vcpu_ptc_e(vcpu,r3);
}

static IA64FAULT vmx_emul_ptc_g(VCPU *vcpu, INST64 inst)
{
    u64 r2,r3;
#ifdef  VMAL_NO_FAULT_CHECK    
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK    
    if(vcpu_get_gr_nat(vcpu,inst.M45.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M45.r2,&r2)){
#ifdef  VMAL_NO_FAULT_CHECK
        ISR isr;
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (unimplemented_gva(vcpu,r3) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK
    return vmx_vcpu_ptc_g(vcpu,r3,bits(r2,2,7));
}

static IA64FAULT vmx_emul_ptc_ga(VCPU *vcpu, INST64 inst)
{
    u64 r2,r3;
#ifdef  VMAL_NO_FAULT_CHECK    
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK    
    if(vcpu_get_gr_nat(vcpu,inst.M45.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M45.r2,&r2)){
#ifdef  VMAL_NO_FAULT_CHECK
        ISR isr;
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (unimplemented_gva(vcpu,r3) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK
    return vmx_vcpu_ptc_ga(vcpu,r3,bits(r2,2,7));
}

static IA64FAULT ptr_fault_check(VCPU *vcpu, INST64 inst, u64 *pr2, u64 *pr3)
{
    IA64FAULT	ret1, ret2;

#ifdef  VMAL_NO_FAULT_CHECK
    ISR isr;
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    ret1 = vcpu_get_gr_nat(vcpu,inst.M45.r3,pr3);
    ret2 = vcpu_get_gr_nat(vcpu,inst.M45.r2,pr2);
#ifdef  VMAL_NO_FAULT_CHECK
    if ( ret1 != IA64_NO_FAULT || ret2 != IA64_NO_FAULT ) {
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
    }
    if (unimplemented_gva(vcpu,r3) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK
   return IA64_NO_FAULT;
}

static IA64FAULT vmx_emul_ptr_d(VCPU *vcpu, INST64 inst)
{
    u64 r2,r3;
    if ( ptr_fault_check(vcpu, inst, &r2, &r3 ) == IA64_FAULT )
    	return IA64_FAULT;
    return vmx_vcpu_ptr_d(vcpu,r3,bits(r2,2,7));
}

static IA64FAULT vmx_emul_ptr_i(VCPU *vcpu, INST64 inst)
{
    u64 r2,r3;
    if ( ptr_fault_check(vcpu, inst, &r2, &r3 ) == IA64_FAULT )
    	return IA64_FAULT;
    return vmx_vcpu_ptr_i(vcpu,r3,bits(r2,2,7));
}


static IA64FAULT vmx_emul_thash(VCPU *vcpu, INST64 inst)
{
    u64 r1,r3;
#ifdef  CHECK_FAULT
    ISR visr;
    IA64_PSR vpsr;
    if(check_target_register(vcpu, inst.M46.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
#endif //CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu, inst.M46.r3, &r3)){
#ifdef  CHECK_FAULT
        vcpu_set_gr(vcpu, inst.M46.r1, 0, 1);
        return IA64_NO_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(unimplemented_gva(vcpu, r3)){
        vcpu_set_gr(vcpu, inst.M46.r1, 0, 1);
        return IA64_NO_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_thash(vcpu, r3, &r1);
    vcpu_set_gr(vcpu, inst.M46.r1, r1, 0);
    return(IA64_NO_FAULT);
}


static IA64FAULT vmx_emul_ttag(VCPU *vcpu, INST64 inst)
{
    u64 r1,r3;
#ifdef  CHECK_FAULT
    ISR visr;
    IA64_PSR vpsr;
#endif
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M46.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
#endif //CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu, inst.M46.r3, &r3)){
#ifdef  CHECK_FAULT
        vcpu_set_gr(vcpu, inst.M46.r1, 0, 1);
        return IA64_NO_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(unimplemented_gva(vcpu, r3)){
        vcpu_set_gr(vcpu, inst.M46.r1, 0, 1);
        return IA64_NO_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_ttag(vcpu, r3, &r1);
    vcpu_set_gr(vcpu, inst.M46.r1, r1, 0);
    return(IA64_NO_FAULT);
}


static IA64FAULT vmx_emul_tpa(VCPU *vcpu, INST64 inst)
{
    u64 r1,r3;
#ifdef  CHECK_FAULT
    ISR visr;
    if(check_target_register(vcpu, inst.M46.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if(vpsr.cpl!=0){
        visr.val=0;
        vcpu_set_isr(vcpu, visr.val);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu, inst.M46.r3, &r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,1);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if (unimplemented_gva(vcpu,r3) ) {
        // inject unimplemented_data_address_fault
        visr.val = set_isr_ei_ni(vcpu);
        visr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        // FAULT_UNIMPLEMENTED_DATA_ADDRESS.
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif  //CHECK_FAULT

    if(vmx_vcpu_tpa(vcpu, r3, &r1)){
        return IA64_FAULT;
    }
    vcpu_set_gr(vcpu, inst.M46.r1, r1, 0);
    return(IA64_NO_FAULT);
}

static IA64FAULT vmx_emul_tak(VCPU *vcpu, INST64 inst)
{
    u64 r1,r3;
#ifdef  CHECK_FAULT
    ISR visr;
    IA64_PSR vpsr;
    int fault=IA64_NO_FAULT;
    visr.val=0;
    if(check_target_register(vcpu, inst.M46.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if(vpsr.cpl!=0){
        vcpu_set_isr(vcpu, visr.val);
        return IA64_FAULT;
    }
#endif
    if(vcpu_get_gr_nat(vcpu, inst.M46.r3, &r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,1);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif
    }
    if(vmx_vcpu_tak(vcpu, r3, &r1)){
        return IA64_FAULT;
    }
    vcpu_set_gr(vcpu, inst.M46.r1, r1, 0);
    return(IA64_NO_FAULT);
}


/************************************
 * Insert translation register/cache
************************************/

static IA64FAULT vmx_emul_itr_d(VCPU *vcpu, INST64 inst)
{
    u64 itir, ifa, pte, slot;
#ifdef  VMAL_NO_FAULT_CHECK
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.ic ) {
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    ISR isr;
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    if(vcpu_get_gr_nat(vcpu,inst.M45.r3,&slot)||vcpu_get_gr_nat(vcpu,inst.M45.r2,&pte)){
#ifdef  VMAL_NO_FAULT_CHECK
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if(is_reserved_rr_register(vcpu, slot)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK

    if (vcpu_get_itir(vcpu,&itir)){
        return(IA64_FAULT);
    }
    if (vcpu_get_ifa(vcpu,&ifa)){
        return(IA64_FAULT);
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (is_reserved_itir_field(vcpu, itir)) {
    	// TODO
    	return IA64_FAULT;
    }
    if (unimplemented_gva(vcpu,ifa) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK

    return (vmx_vcpu_itr_d(vcpu,slot,pte,itir,ifa));
}

static IA64FAULT vmx_emul_itr_i(VCPU *vcpu, INST64 inst)
{
    u64 itir, ifa, pte, slot;
#ifdef  VMAL_NO_FAULT_CHECK
    ISR isr;
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.ic ) {
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    if(vcpu_get_gr_nat(vcpu,inst.M45.r3,&slot)||vcpu_get_gr_nat(vcpu,inst.M45.r2,&pte)){
#ifdef  VMAL_NO_FAULT_CHECK
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif // VMAL_NO_FAULT_CHECK
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if(is_reserved_rr_register(vcpu, slot)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK

    if (vcpu_get_itir(vcpu,&itir)){
        return(IA64_FAULT);
    }
    if (vcpu_get_ifa(vcpu,&ifa)){
        return(IA64_FAULT);
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (is_reserved_itir_field(vcpu, itir)) {
    	// TODO
    	return IA64_FAULT;
    }
    if (unimplemented_gva(vcpu,ifa) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK

   return (vmx_vcpu_itr_i(vcpu,slot,pte,itir,ifa));
}

static IA64FAULT itc_fault_check(VCPU *vcpu, INST64 inst,
                                 u64 *itir, u64 *ifa, u64 *pte)
{
    IA64FAULT	ret1;

#ifdef  VMAL_NO_FAULT_CHECK
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.ic ) {
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }

    u64 fault;
    ISR isr;
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK
    ret1 = vcpu_get_gr_nat(vcpu,inst.M45.r2,pte);
#ifdef  VMAL_NO_FAULT_CHECK
    if( ret1 != IA64_NO_FAULT ){
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
    }
#endif // VMAL_NO_FAULT_CHECK

    if (vcpu_get_itir(vcpu,itir)){
        return(IA64_FAULT);
    }
    if (vcpu_get_ifa(vcpu,ifa)){
        return(IA64_FAULT);
    }
#ifdef  VMAL_NO_FAULT_CHECK
    if (unimplemented_gva(vcpu,ifa) ) {
        isr.val = set_isr_ei_ni(vcpu);
        isr.code = IA64_RESERVED_REG_FAULT;
        vcpu_set_isr(vcpu, isr.val);
        unimpl_daddr(vcpu);
        return IA64_FAULT;
   }
#endif // VMAL_NO_FAULT_CHECK
   return IA64_NO_FAULT;
}

static IA64FAULT vmx_emul_itc_d(VCPU *vcpu, INST64 inst)
{
    u64 itir, ifa, pte;

    if ( itc_fault_check(vcpu, inst, &itir, &ifa, &pte) == IA64_FAULT ) {
    	return IA64_FAULT;
    }

   return (vmx_vcpu_itc_d(vcpu,pte,itir,ifa));
}

static IA64FAULT vmx_emul_itc_i(VCPU *vcpu, INST64 inst)
{
    u64 itir, ifa, pte;

    if ( itc_fault_check(vcpu, inst, &itir, &ifa, &pte) == IA64_FAULT ) {
    	return IA64_FAULT;
    }

   return (vmx_vcpu_itc_i(vcpu,pte,itir,ifa));

}

/*************************************
 * Moves to semi-privileged registers
*************************************/

static IA64FAULT vmx_emul_mov_to_ar_imm(VCPU *vcpu, INST64 inst)
{
    // I27 and M30 are identical for these fields
    u64 imm;

    if(inst.M30.ar3!=44){
        panic_domain(vcpu_regs(vcpu),"Can't support ar register other than itc");
    }
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(inst.M30.s){
        imm = -inst.M30.imm;
    }else{
        imm = inst.M30.imm;
    }
    return (vmx_vcpu_set_itc(vcpu, imm));
}

static IA64FAULT vmx_emul_mov_to_ar_reg(VCPU *vcpu, INST64 inst)
{
    // I26 and M29 are identical for these fields
    u64 r2;
    if(inst.M29.ar3!=44){
        panic_domain(vcpu_regs(vcpu),"Can't support ar register other than itc");
    }
    if(vcpu_get_gr_nat(vcpu,inst.M29.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    return (vmx_vcpu_set_itc(vcpu, r2));
}


static IA64FAULT vmx_emul_mov_from_ar_reg(VCPU *vcpu, INST64 inst)
{
    // I27 and M30 are identical for these fields
    u64 r1;
    if(inst.M31.ar3!=44){
        panic_domain(vcpu_regs(vcpu),"Can't support ar register other than itc");
    }
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu,inst.M31.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.si&& vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    vmx_vcpu_get_itc(vcpu,&r1);
    vcpu_set_gr(vcpu,inst.M31.r1,r1,0);
    return IA64_NO_FAULT;
}


/********************************
 * Moves to privileged registers
********************************/

static IA64FAULT vmx_emul_mov_to_pkr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_pkr(vcpu,r3,r2));
}

static IA64FAULT vmx_emul_mov_to_rr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_rr(vcpu,r3,r2));
}

static IA64FAULT vmx_emul_mov_to_dbr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
    return IA64_NO_FAULT;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_dbr(vcpu,r3,r2));
}

static IA64FAULT vmx_emul_mov_to_ibr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
    return IA64_NO_FAULT;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_ibr(vcpu,r3,r2));
}

static IA64FAULT vmx_emul_mov_to_pmc(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_pmc(vcpu,r3,r2));
}

static IA64FAULT vmx_emul_mov_to_pmd(VCPU *vcpu, INST64 inst)
{
    u64 r3,r2;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu,inst.M42.r3,&r3)||vcpu_get_gr_nat(vcpu,inst.M42.r2,&r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
    return (vmx_vcpu_set_pmd(vcpu,r3,r2));
}


/**********************************
 * Moves from privileged registers
 **********************************/

static IA64FAULT vmx_emul_mov_from_rr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }

#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_rr_register(vcpu,r3>>VRN_SHIFT)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
    }
#endif  //CHECK_FAULT
    vcpu_get_rr(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_from_pkr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }

#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_indirect_register(vcpu,r3)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_get_pkr(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_from_dbr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }

#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_indirect_register(vcpu,r3)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_get_dbr(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_from_ibr(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }

#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_indirect_register(vcpu,r3)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_get_ibr(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_from_pmc(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if (vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }

#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_indirect_register(vcpu,r3)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_get_pmc(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_from_cpuid(VCPU *vcpu, INST64 inst)
{
    u64 r3,r1;
#ifdef  CHECK_FAULT
    if(check_target_register(vcpu, inst.M43.r1)){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
#endif //CHECK_FAULT
     if(vcpu_get_gr_nat(vcpu,inst.M43.r3,&r3)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef  CHECK_FAULT
    if(is_reserved_indirect_register(vcpu,r3)){
        set_rsv_reg_field_isr(vcpu);
        rsv_reg_field(vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    vmx_vcpu_get_cpuid(vcpu,r3,&r1);
    return vcpu_set_gr(vcpu, inst.M43.r1, r1,0);
}

static IA64FAULT vmx_emul_mov_to_cr(VCPU *vcpu, INST64 inst)
{
    u64 r2;
    extern u64 cr_igfld_mask(int index, u64 value);
#ifdef  CHECK_FAULT
    IA64_PSR  vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if(is_reserved_cr(inst.M32.cr3)||(vpsr.ic&&is_interruption_control_cr(inst.M32.cr3))){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT
    if(vcpu_get_gr_nat(vcpu, inst.M32.r2, &r2)){
#ifdef  CHECK_FAULT
        set_isr_reg_nat_consumption(vcpu,0,0);
        rnat_comsumption(vcpu);
        return IA64_FAULT;
#endif  //CHECK_FAULT
    }
#ifdef   CHECK_FAULT
    if ( check_cr_rsv_fields (inst.M32.cr3, r2)) {
        /* Inject Reserved Register/Field fault
         * into guest */
        set_rsv_reg_field_isr (vcpu,0);
        rsv_reg_field (vcpu);
        return IA64_FAULT;
    }
#endif  //CHECK_FAULT
    r2 = cr_igfld_mask(inst.M32.cr3,r2);
    switch (inst.M32.cr3) {
        case 0: return vcpu_set_dcr(vcpu,r2);
        case 1: return vmx_vcpu_set_itm(vcpu,r2);
        case 2: return vmx_vcpu_set_iva(vcpu,r2);
        case 8: return vmx_vcpu_set_pta(vcpu,r2);
        case 16:return vcpu_set_ipsr(vcpu,r2);
        case 17:return vcpu_set_isr(vcpu,r2);
        case 19:return vcpu_set_iip(vcpu,r2);
        case 20:return vcpu_set_ifa(vcpu,r2);
        case 21:return vcpu_set_itir(vcpu,r2);
        case 22:return vcpu_set_iipa(vcpu,r2);
        case 23:return vcpu_set_ifs(vcpu,r2);
        case 24:return vcpu_set_iim(vcpu,r2);
        case 25:return vcpu_set_iha(vcpu,r2);
        case 64:printk("SET LID to 0x%lx\n", r2);
                return IA64_NO_FAULT;
        case 65:return IA64_NO_FAULT;
        case 66:return vmx_vcpu_set_tpr(vcpu,r2);
        case 67:return vmx_vcpu_set_eoi(vcpu,r2);
        case 68:return IA64_NO_FAULT;
        case 69:return IA64_NO_FAULT;
        case 70:return IA64_NO_FAULT;
        case 71:return IA64_NO_FAULT;
        case 72:return vmx_vcpu_set_itv(vcpu,r2);
        case 73:return vmx_vcpu_set_pmv(vcpu,r2);
        case 74:return vmx_vcpu_set_cmcv(vcpu,r2);
        case 80:return vmx_vcpu_set_lrr0(vcpu,r2);
        case 81:return vmx_vcpu_set_lrr1(vcpu,r2);
        default:VCPU(vcpu, vcr[inst.M32.cr3]) = r2;
                return IA64_NO_FAULT;
    }
}


#define cr_get(cr) \
    ((fault=vcpu_get_##cr(vcpu,&val))==IA64_NO_FAULT)?\
        vcpu_set_gr(vcpu, tgt, val,0):fault;

#define vmx_cr_get(cr) \
    ((fault=vmx_vcpu_get_##cr(vcpu,&val))==IA64_NO_FAULT)?\
        vcpu_set_gr(vcpu, tgt, val,0):fault;

static IA64FAULT vmx_emul_mov_from_cr(VCPU *vcpu, INST64 inst)
{
    u64 tgt = inst.M33.r1;
    u64 val;
    IA64FAULT fault;
#ifdef  CHECK_FAULT
    IA64_PSR vpsr;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    if(is_reserved_cr(inst.M33.cr3)||is_read_only_cr(inst.M33.cr3||
        (vpsr.ic&&is_interruption_control_cr(inst.M33.cr3)))){
        set_illegal_op_isr(vcpu);
        illegal_op(vcpu);
        return IA64_FAULT;
    }
    if ( vpsr.cpl != 0) {
        /* Inject Privileged Operation fault into guest */
        set_privileged_operation_isr (vcpu, 0);
        privilege_op (vcpu);
        return IA64_FAULT;
    }
#endif // CHECK_FAULT

//    from_cr_cnt[inst.M33.cr3]++;
    switch (inst.M33.cr3) {
        case 0: return cr_get(dcr);
        case 1: return vmx_cr_get(itm);
        case 2: return vmx_cr_get(iva);
        case 8: return vmx_cr_get(pta);
        case 16:return cr_get(ipsr);
        case 17:return cr_get(isr);
        case 19:return cr_get(iip);
        case 20:return cr_get(ifa);
        case 21:return cr_get(itir);
        case 22:return cr_get(iipa);
        case 23:return cr_get(ifs);
        case 24:return cr_get(iim);
        case 25:return cr_get(iha);
        case 64:return vmx_cr_get(lid);
        case 65:
                vmx_vcpu_get_ivr(vcpu,&val);
                return vcpu_set_gr(vcpu,tgt,val,0);
        case 66:return vmx_cr_get(tpr);
        case 67:return vcpu_set_gr(vcpu,tgt,0L,0);
        case 68:return vmx_cr_get(irr0);
        case 69:return vmx_cr_get(irr1);
        case 70:return vmx_cr_get(irr2);
        case 71:return vmx_cr_get(irr3);
        case 72:return vmx_cr_get(itv);
        case 73:return vmx_cr_get(pmv);
        case 74:return vmx_cr_get(cmcv);
        case 80:return vmx_cr_get(lrr0);
        case 81:return vmx_cr_get(lrr1);
        default: return IA64_NO_FAULT;
    }
}


//#define  BYPASS_VMAL_OPCODE
extern IA64_SLOT_TYPE  slot_types[0x20][3];
unsigned long
__vmx_get_domain_bundle(u64 iip, IA64_BUNDLE *pbundle)
{
	return fetch_code(current, iip, pbundle);
}

/** Emulate a privileged operation.
 *
 *
 * @param vcpu virtual cpu
 * @cause the reason cause virtualization fault
 * @opcode the instruction code which cause virtualization fault
 */

void
vmx_emulate(VCPU *vcpu, REGS *regs)
{
    IA64FAULT status;
    INST64 inst;
    u64 iip, cause, opcode;
    iip = regs->cr_iip;
    cause = VMX(vcpu,cause);
    opcode = VMX(vcpu,opcode);

#ifdef  VTLB_DEBUG
    check_vtlb_sanity(vmx_vcpu_get_vtlb(vcpu));
    dump_vtlb(vmx_vcpu_get_vtlb(vcpu));
#endif
#if 0
if ( (cause == 0xff && opcode == 0x1e000000000) || cause == 0 ) {
		printk ("VMAL decode error: cause - %lx; op - %lx\n", 
			cause, opcode );
		return;
}
#endif
#ifdef BYPASS_VMAL_OPCODE
    // make a local copy of the bundle containing the privop
    IA64_BUNDLE bundle;
    int slot;
    IA64_SLOT_TYPE slot_type;
    IA64_PSR vpsr;
    bundle = __vmx_get_domain_bundle(iip);
    slot = ((struct ia64_psr *)&(regs->cr_ipsr))->ri;
    if (!slot) inst.inst = bundle.slot0;
    else if (slot == 1)
        inst.inst = bundle.slot1a + (bundle.slot1b<<18);
    else if (slot == 2) inst.inst = bundle.slot2;
    else printk("priv_handle_op: illegal slot: %d\n", slot);
    slot_type = slot_types[bundle.template][slot];
    ia64_priv_decoder(slot_type, inst, &cause);
    if(cause==0){
        panic_domain(regs,"This instruction at 0x%lx slot %d can't be  virtualized", iip, slot);
    }
#else
    inst.inst=opcode;
#endif /* BYPASS_VMAL_OPCODE */
    /*
     * Switch to actual virtual rid in rr0 and rr4,
     * which is required by some tlb related instructions.
     */
    prepare_if_physical_mode(vcpu);

    switch(cause) {
    case EVENT_RSM:
        perfc_incrc(vmx_rsm);
        status=vmx_emul_rsm(vcpu, inst);
        break;
    case EVENT_SSM:
        perfc_incrc(vmx_ssm);
        status=vmx_emul_ssm(vcpu, inst);
        break;
    case EVENT_MOV_TO_PSR:
        perfc_incrc(vmx_mov_to_psr);
        status=vmx_emul_mov_to_psr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_PSR:
        perfc_incrc(vmx_mov_from_psr);
        status=vmx_emul_mov_from_psr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_CR:
        perfc_incrc(vmx_mov_from_cr);
        status=vmx_emul_mov_from_cr(vcpu, inst);
        break;
    case EVENT_MOV_TO_CR:
        perfc_incrc(vmx_mov_to_cr);
        status=vmx_emul_mov_to_cr(vcpu, inst);
        break;
    case EVENT_BSW_0:
        perfc_incrc(vmx_bsw0);
        status=vmx_emul_bsw0(vcpu, inst);
        break;
    case EVENT_BSW_1:
        perfc_incrc(vmx_bsw1);
        status=vmx_emul_bsw1(vcpu, inst);
        break;
    case EVENT_COVER:
        perfc_incrc(vmx_cover);
        status=vmx_emul_cover(vcpu, inst);
        break;
    case EVENT_RFI:
        perfc_incrc(vmx_rfi);
        status=vmx_emul_rfi(vcpu, inst);
        break;
    case EVENT_ITR_D:
        perfc_incrc(vmx_itr_d);
        status=vmx_emul_itr_d(vcpu, inst);
        break;
    case EVENT_ITR_I:
        perfc_incrc(vmx_itr_i);
        status=vmx_emul_itr_i(vcpu, inst);
        break;
    case EVENT_PTR_D:
        perfc_incrc(vmx_ptr_d);
        status=vmx_emul_ptr_d(vcpu, inst);
        break;
    case EVENT_PTR_I:
        perfc_incrc(vmx_ptr_i);
        status=vmx_emul_ptr_i(vcpu, inst);
        break;
    case EVENT_ITC_D:
        perfc_incrc(vmx_itc_d);
        status=vmx_emul_itc_d(vcpu, inst);
        break;
    case EVENT_ITC_I:
        perfc_incrc(vmx_itc_i);
        status=vmx_emul_itc_i(vcpu, inst);
        break;
    case EVENT_PTC_L:
        perfc_incrc(vmx_ptc_l);
        status=vmx_emul_ptc_l(vcpu, inst);
        break;
    case EVENT_PTC_G:
        perfc_incrc(vmx_ptc_g);
        status=vmx_emul_ptc_g(vcpu, inst);
        break;
    case EVENT_PTC_GA:
        perfc_incrc(vmx_ptc_ga);
        status=vmx_emul_ptc_ga(vcpu, inst);
        break;
    case EVENT_PTC_E:
        perfc_incrc(vmx_ptc_e);
        status=vmx_emul_ptc_e(vcpu, inst);
        break;
    case EVENT_MOV_TO_RR:
        perfc_incrc(vmx_mov_to_rr);
        status=vmx_emul_mov_to_rr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_RR:
        perfc_incrc(vmx_mov_from_rr);
        status=vmx_emul_mov_from_rr(vcpu, inst);
        break;
    case EVENT_THASH:
        perfc_incrc(vmx_thash);
        status=vmx_emul_thash(vcpu, inst);
        break;
    case EVENT_TTAG:
        perfc_incrc(vmx_ttag);
        status=vmx_emul_ttag(vcpu, inst);
        break;
    case EVENT_TPA:
        perfc_incrc(vmx_tpa);
        status=vmx_emul_tpa(vcpu, inst);
        break;
    case EVENT_TAK:
        perfc_incrc(vmx_tak);
        status=vmx_emul_tak(vcpu, inst);
        break;
    case EVENT_MOV_TO_AR_IMM:
        perfc_incrc(vmx_mov_to_ar_imm);
        status=vmx_emul_mov_to_ar_imm(vcpu, inst);
        break;
    case EVENT_MOV_TO_AR:
        perfc_incrc(vmx_mov_to_ar_reg);
        status=vmx_emul_mov_to_ar_reg(vcpu, inst);
        break;
    case EVENT_MOV_FROM_AR:
        perfc_incrc(vmx_mov_from_ar_reg);
        status=vmx_emul_mov_from_ar_reg(vcpu, inst);
        break;
    case EVENT_MOV_TO_DBR:
        perfc_incrc(vmx_mov_to_dbr);
        status=vmx_emul_mov_to_dbr(vcpu, inst);
        break;
    case EVENT_MOV_TO_IBR:
        perfc_incrc(vmx_mov_to_ibr);
        status=vmx_emul_mov_to_ibr(vcpu, inst);
        break;
    case EVENT_MOV_TO_PMC:
        perfc_incrc(vmx_mov_to_pmc);
        status=vmx_emul_mov_to_pmc(vcpu, inst);
        break;
    case EVENT_MOV_TO_PMD:
        perfc_incrc(vmx_mov_to_pmd);
        status=vmx_emul_mov_to_pmd(vcpu, inst);
        break;
    case EVENT_MOV_TO_PKR:
        perfc_incrc(vmx_mov_to_pkr);
        status=vmx_emul_mov_to_pkr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_DBR:
        perfc_incrc(vmx_mov_from_dbr);
        status=vmx_emul_mov_from_dbr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_IBR:
        perfc_incrc(vmx_mov_from_ibr);
        status=vmx_emul_mov_from_ibr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_PMC:
        perfc_incrc(vmx_mov_from_pmc);
        status=vmx_emul_mov_from_pmc(vcpu, inst);
        break;
    case EVENT_MOV_FROM_PKR:
        perfc_incrc(vmx_mov_from_pkr);
        status=vmx_emul_mov_from_pkr(vcpu, inst);
        break;
    case EVENT_MOV_FROM_CPUID:
        perfc_incrc(vmx_mov_from_cpuid);
        status=vmx_emul_mov_from_cpuid(vcpu, inst);
        break;
    case EVENT_VMSW:
        printk ("Unimplemented instruction %ld\n", cause);
	status=IA64_FAULT;
        break;
    default:
        panic_domain(regs,"unknown cause %ld, iip: %lx, ipsr: %lx\n", cause,regs->cr_iip,regs->cr_ipsr);
        break;
    };

#if 0
    if (status == IA64_FAULT)
	panic("Emulation failed with cause %d:\n", cause);
#endif

    if ( status == IA64_NO_FAULT && cause !=EVENT_RFI ) {
        vcpu_increment_iip(vcpu);
    }

    recover_if_physical_mode(vcpu);
    return;

}

