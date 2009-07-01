/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_utility.c:
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
#include <asm/processor.h>
#include <asm/vmx_mm_def.h>

#ifdef CHECK_FAULT
/*
 * Return:
 *  0:  Not reserved indirect registers
 *  1:  Is reserved indirect registers
 */
int
is_reserved_indirect_register (
    int type,
    int index )
{
    switch (type) {
        case IA64_CPUID:
            if ( index >= 5 ) {
                return 1;
            }

        case IA64_DBR:
        case IA64_IBR:
            //bugbugbug:check with pal about the max ibr/dbr!!!!
            break;

        case IA64_PMC:
            //bugbugbug:check with pal about the max ibr/dbr!!!!
            break;

        case IA64_PMD:
            //bugbugbug:check with pal about the max ibr/dbr!!!!
            break;

        case IA64_PKR:
            //bugbugbug:check with pal about the max pkr!!!!
            break;

        case IA64_RR:
            //bugbugbug:check with pal about the max rr!!!!
            break;

        default:
            panic ("Unsupported instruction!");
    }

    return 0;

}
#endif

/*
 * Return:
 *  Set all ignored fields in value to 0 and return
 */
u64
indirect_reg_igfld_MASK (
    int type,
    int index,
    u64 value
    )
{
    u64 nvalue;

    nvalue = value;
    switch ( type ) {
        case IA64_CPUID:
            if ( index == 2 ) {
                nvalue = 0;
            }
            break;

        case IA64_DBR:
        case IA64_IBR:
            /* Refer to SDM Vol2 Table 7-1,7-2 */
            if ( index % 2 != 0) {
                /* Ignore field: {61:60} */
                nvalue = value & (~MASK (60, 2));
            }
            break;
        case IA64_PMC:
            if ( index == 0 ) {
                /* Ignore field: 3:1 */
                nvalue = value & (~MASK (1, 3));
            }
            break;
        case IA64_PMD:
            if ( index >= 4 ) {
                /* Ignore field: 7:7 */
                /* bugbug: this code is correct for generic
                 * PMD. However, for implementation specific
                 * PMD, it's WRONG. need more info to judge
                 * what's implementation specific PMD.
                 */
                nvalue = value & (~MASK (7, 1));
            }
            break;
        case IA64_PKR:
        case IA64_RR:
            break;
        default:
            panic ("Unsupported instruction!");
    }

    return nvalue;
}

/*
 * Return:
 *  Set all ignored fields in value to 0 and return
 */
u64
cr_igfld_mask (int index, u64 value)
{
    u64 nvalue;

    nvalue = value;

    switch ( index ) {
    case IA64_REG_CR_IVA:
        /* Ignore filed: 14:0 */
        nvalue = value & (~MASK (0, 15));
        break;

    case IA64_REG_CR_IHA:
        /* Ignore filed: 1:0 */
        nvalue = value & (~MASK (0, 2));
        break;

    case IA64_REG_CR_LID:
        /* Ignore filed: 63:32 */
        nvalue = value & (~MASK (32, 32));
        break;

    case IA64_REG_CR_TPR:
        /* Ignore filed: 63:17,3:0 */
        nvalue = value & (~MASK (17, 47));
        nvalue = nvalue & (~MASK (0, 4));
        break;

    case IA64_REG_CR_EOI:
        /* Ignore filed: 63:0 */
        nvalue = 0;
        break;

    case IA64_REG_CR_ITV:
    case IA64_REG_CR_PMV:
    case IA64_REG_CR_CMCV:
    case IA64_REG_CR_LRR0:
    case IA64_REG_CR_LRR1:
        /* Ignore filed: 63:17,12:12 */
        nvalue = value & (~MASK (17, 47));
        nvalue = nvalue & (~MASK (12, 1));
        break;
    }

    return nvalue;
}


/*
 * Return:
 *  1: PSR reserved fields are not zero
 *  0:  PSR reserved fields are all zero
 */
int
check_psr_rsv_fields (u64 value)
{
    /* PSR reserved fields: 0, 12~6, 16, 31~28, 63~46
     * These reserved fields shall all be zero
     * Otherwise we will panic
     */

    if ( value & MASK (0, 1) ||
         value & MASK (6, 7) ||
         value & MASK (16, 1) ||
         value & MASK (28, 4) ||
         value & MASK (46, 18)
         ) {
             return 1;
         }

    return 0;
}


#ifdef CHECK_FAULT
/*
 * Return:
 *  1: CR reserved fields are not zero
 *  0:  CR reserved fields are all zero
 */
int
check_cr_rsv_fields (int index, u64 value)
{
    switch (index) {
        case IA64_REG_CR_DCR:
            if ( (value & MASK ( 3, 5 )) ||
                (value & MASK (15, 49))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_ITM:
        case IA64_REG_CR_IVA:
        case IA64_REG_CR_IIP:
        case IA64_REG_CR_IFA:
        case IA64_REG_CR_IIPA:
        case IA64_REG_CR_IIM:
        case IA64_REG_CR_IHA:
        case IA64_REG_CR_EOI:
            return 0;

        case IA64_REG_CR_PTA:
            if ( (value & MASK ( 1, 1 )) ||
                (value & MASK (9, 6))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_IPSR:
            return check_psr_rsv_fields (value);


        case IA64_REG_CR_ISR:
            if ( (value & MASK ( 24, 8 )) ||
                (value & MASK (44, 20))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_ITIR:
            if ( (value & MASK ( 0, 2 )) ||
                (value & MASK (32, 32))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_IFS:
            if ( (value & MASK ( 38, 25 ))) {
                return 1;
            }
            return 0;

        case IA64_REG_CR_LID:
            if ( (value & MASK ( 0, 16 ))) {
                return 1;
            }
            return 0;

        case IA64_REG_CR_IVR:
            if ( (value & MASK ( 8, 56 ))) {
                return 1;
            }
            return 0;

        case IA64_REG_CR_TPR:
            if ( (value & MASK ( 8, 8 ))) {
                return 1;
            }
            return 0;

        case IA64_REG_CR_IRR0:
            if ( (value & MASK ( 1, 1 )) ||
                (value & MASK (3, 13))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_ITV:
        case IA64_REG_CR_PMV:
        case IA64_REG_CR_CMCV:
            if ( (value & MASK ( 8, 4 )) ||
                (value & MASK (13, 3))) {
                    return 1;
            }
            return 0;

        case IA64_REG_CR_LRR0:
        case IA64_REG_CR_LRR1:
            if ( (value & MASK ( 11, 1 )) ||
                (value & MASK (14, 1))) {
                    return 1;
            }
            return 0;
    }
    panic ("Unsupported CR");
    return 0;
}
#endif

#if 0
/*
 * Return:
 *  0:  Indirect Reg reserved fields are not zero
 *  1:  Indirect Reg reserved fields are all zero
 */
int
check_indirect_reg_rsv_fields ( int type, int index, u64 value )
{

    switch ( type ) {
        case IA64_CPUID:
            if ( index == 3 ) {
                if ( value & MASK (40, 24 )) {
                    return 0;
                }
            } else if ( index == 4 ) {
                if ( value & MASK (2, 62 )) {
                    return 0;
                }
            }
            break;

        case IA64_DBR:
        case IA64_IBR:
        case IA64_PMC:
        case IA64_PMD:
            break;

        case IA64_PKR:
            if ( value & MASK (4, 4) ||
                value & MASK (32, 32 )) {
                return 0;
                }
            break;

        case IA64_RR:
            if ( value & MASK (1, 1) ||
                value & MASK (32, 32 )) {
                return 0;
                }
            break;

        default:
            panic ("Unsupported instruction!");
    }

    return 1;
}
#endif



/* Return
 * Same format as isr_t
 * Only ei/ni bits are valid, all other bits are zero
 */
u64
set_isr_ei_ni (VCPU *vcpu)
{

    IA64_PSR vpsr,ipsr;
    ISR visr;
    REGS *regs;

    regs=vcpu_regs(vcpu);

    visr.val = 0;

    vpsr.val = VCPU(vcpu, vpsr);

    if (!vpsr.ic == 1 ) {
        /* Set ISR.ni */
        visr.ni = 1;
    }
    ipsr.val = regs->cr_ipsr;

    visr.ei = ipsr.ri;
    return visr.val;
}


/* Set up ISR.na/code{3:0}/r/w for no-access instructions
 * Refer to SDM Vol Table 5-1
 * Parameter:
 *  setr: if 1, indicates this function will set up ISR.r
 *  setw: if 1, indicates this function will set up ISR.w
 * Return:
 *  Same format as ISR. All fields are zero, except na/code{3:0}/r/w
 */
u64
set_isr_for_na_inst(VCPU *vcpu, int op)
{
    ISR visr;
    visr.val = 0;
    switch (op) {
        case IA64_INST_TPA:
            visr.na = 1;
            visr.code = 0;
            break;
        case IA64_INST_TAK:
            visr.na = 1;
            visr.code = 3;
            break;
    }
    return visr.val;
}



/*
 * Set up ISR for registe Nat consumption fault
 * Parameters:
 *  read: if 1, indicates this is a read access;
 *  write: if 1, indicates this is a write access;
 */
void
set_rnat_consumption_isr (VCPU *vcpu,int inst,int read,int write)
{
    ISR visr;
    u64 value;
    /* Need set up ISR: code, ei, ni, na, r/w */
    visr.val = 0;

    /* ISR.code{7:4} =1,
     * Set up ISR.code{3:0}, ISR.na
     */
    visr.code = (1 << 4);
    if (inst) {

        value = set_isr_for_na_inst (vcpu,inst);
        visr.val = visr.val | value;
    }

    /* Set up ISR.r/w */
    visr.r = read;
    visr.w = write;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr (vcpu,visr.val);
}



/*
 * Set up ISR for break fault
 */
void set_break_isr (VCPU *vcpu)
{
    ISR visr;
    u64 value;

    /* Need set up ISR: ei, ni */

    visr.val = 0;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr(vcpu, visr.val);
}






/*
 * Set up ISR for Priviledged Operation fault
 */
void set_privileged_operation_isr (VCPU *vcpu,int inst)
{
    ISR visr;
    u64 value;

    /* Need set up ISR: code, ei, ni, na */

    visr.val = 0;

    /* Set up na, code{3:0} for no-access instruction */
    value = set_isr_for_na_inst (vcpu, inst);
    visr.val = visr.val | value;


    /* ISR.code{7:4} =1 */
    visr.code = (1 << 4) | visr.code;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr (vcpu, visr.val);
}




/*
 * Set up ISR for Priviledged Register fault
 */
void set_privileged_reg_isr (VCPU *vcpu, int inst)
{
    ISR visr;
    u64 value;

    /* Need set up ISR: code, ei, ni */

    visr.val = 0;

    /* ISR.code{7:4} =2 */
    visr.code = 2 << 4;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr (vcpu, visr.val);
}





/*
 * Set up ISR for Reserved Register/Field fault
 */
void set_rsv_reg_field_isr (VCPU *vcpu)
{
    ISR visr;
    u64 value;

    /* Need set up ISR: code, ei, ni */

    visr.val = 0;

    /* ISR.code{7:4} =4 */
    visr.code = (3 << 4) | visr.code;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr (vcpu, visr.val);
}



/*
 * Set up ISR for Illegal Operation fault
 */
void set_illegal_op_isr (VCPU *vcpu)
{
    ISR visr;
    u64 value;

    /* Need set up ISR: ei, ni */

    visr.val = 0;

    /* Set up ei/ni */
    value = set_isr_ei_ni (vcpu);
    visr.val = visr.val | value;

    vcpu_set_isr (vcpu, visr.val);
}


void set_isr_reg_nat_consumption(VCPU *vcpu, u64 flag, u64 non_access)
{
    ISR isr;

    isr.val = 0;
    isr.val = set_isr_ei_ni(vcpu);
    isr.code = IA64_REG_NAT_CONSUMPTION_FAULT | flag;
    isr.na = non_access;
    isr.r = 1;
    isr.w = 0;
    vcpu_set_isr(vcpu, isr.val);
    return;
}

void set_isr_for_priv_fault(VCPU *vcpu, u64 non_access)
{
    ISR isr;

    isr.val = set_isr_ei_ni(vcpu);
    isr.code = IA64_PRIV_OP_FAULT;
    isr.na = non_access;
    vcpu_set_isr(vcpu, isr.val);

    return;
}


IA64FAULT check_target_register(VCPU *vcpu, u64 reg_index)
{
    u64 sof;
    REGS *regs;
    regs=vcpu_regs(vcpu);
    sof = regs->cr_ifs & 0x7f;
    if(reg_index >= sof + 32)
        return IA64_FAULT;
    return IA64_NO_FAULT;
}


int is_reserved_rr_register(VCPU* vcpu, int reg_index)
{
    return (reg_index >= 8);
}

#define  ITIR_RSV_MASK		(0x3UL | (((1UL<<32)-1) << 32))
int is_reserved_itir_field(VCPU* vcpu, u64 itir)
{
	if ( itir & ITIR_RSV_MASK ) {
		return 1;
	}
	return 0;
}

static int __is_reserved_rr_field(u64 reg_value)
{
    ia64_rr rr = { .rrval = reg_value };

    if(rr.reserved0 != 0 || rr.reserved1 != 0){
        return 1;
    }
    if(rr.ps < 12 || rr.ps > 28){
        // page too big or small.
        return 1;
    }
    if(rr.ps > 15 && rr.ps % 2 != 0){
        // unsupported page size.
        return 1;
    }
    return 0;
}

int is_reserved_rr_rid(VCPU* vcpu, u64 reg_value)
{
    ia64_rr rr = { .rrval = reg_value };

    if (rr.rid >= (1UL << vcpu->domain->arch.rid_bits))
        return 1;

    return 0;
}

int is_reserved_rr_field(VCPU* vcpu, u64 reg_value)
{
    if (__is_reserved_rr_field(reg_value))
        return 1;

    return is_reserved_rr_rid(vcpu, reg_value);
}
