/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_phy_mode.c: emulating domain physical mode.
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
 * Arun Sharma (arun.sharma@intel.com)
 * Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 * Xuefei Xu (Anthony Xu) (anthony.xu@intel.com)
 */


#include <asm/processor.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_phy_mode.h>
#include <xen/sched.h>
#include <asm/pgtable.h>
#include <asm/vmmu.h>
int valid_mm_mode[8] = {
    GUEST_PHYS, /* (it, dt, rt) -> (0, 0, 0) */
    INV_MODE,
    INV_MODE,
    GUEST_PHYS, /* (it, dt, rt) -> (0, 1, 1) */
    INV_MODE,
    GUEST_PHYS, /* (it, dt, rt) -> (1, 0, 1) */
    INV_MODE,
    GUEST_VIRT, /* (it, dt, rt) -> (1, 1, 1).*/
};

/*
 * Special notes:
 * - Index by it/dt/rt sequence
 * - Only existing mode transitions are allowed in this table
 * - RSE is placed at lazy mode when emulating guest partial mode
 * - If gva happens to be rr0 and rr4, only allowed case is identity
 *   mapping (gva=gpa), or panic! (How?)
 */
int mm_switch_table[8][8] = {
    /*  2004/09/12(Kevin): Allow switch to self */
        /*
         *  (it,dt,rt): (0,0,0) -> (1,1,1)
         *  This kind of transition usually occurs in the very early
     *  stage of Linux boot up procedure. Another case is in efi
     *  and pal calls. (see "arch/ia64/kernel/head.S")
     *
     *  (it,dt,rt): (0,0,0) -> (0,1,1)
     *  This kind of transition is found when OSYa exits efi boot
     *  service. Due to gva = gpa in this case (Same region),
     *  data access can be satisfied though itlb entry for physical
     *  emulation is hit.
         */
    {SW_SELF,0,  0,  SW_NOP, 0,  0,  0,  SW_P2V},
    {0,  0,  0,  0,  0,  0,  0,  0},
    {0,  0,  0,  0,  0,  0,  0,  0},
    /*
     *  (it,dt,rt): (0,1,1) -> (1,1,1)
     *  This kind of transition is found in OSYa.
     *
     *  (it,dt,rt): (0,1,1) -> (0,0,0)
     *  This kind of transition is found in OSYa
     */
    {SW_NOP, 0,  0,  SW_SELF,0,  0,  0,  SW_P2V},
    /* (1,0,0)->(1,1,1) */
    {0,  0,  0,  0,  0,  0,  0,  SW_P2V},
    /*
         *  (it,dt,rt): (1,0,1) -> (1,1,1)
         *  This kind of transition usually occurs when Linux returns
     *  from the low level TLB miss handlers.
         *  (see "arch/ia64/kernel/ivt.S")
         */
    {0,  0,  0,  0,  0,  SW_SELF,0,  SW_P2V},
    {0,  0,  0,  0,  0,  0,  0,  0},
    /*
         *  (it,dt,rt): (1,1,1) -> (1,0,1)
         *  This kind of transition usually occurs in Linux low level
     *  TLB miss handler. (see "arch/ia64/kernel/ivt.S")
     *
     *  (it,dt,rt): (1,1,1) -> (0,0,0)
     *  This kind of transition usually occurs in pal and efi calls,
     *  which requires running in physical mode.
     *  (see "arch/ia64/kernel/head.S")
     *  (1,1,1)->(1,0,0)
     */

    {SW_V2P, 0,  0,  0,  SW_V2P, SW_V2P, 0,  SW_SELF},
};

void
physical_mode_init(VCPU *vcpu)
{
    vcpu->arch.mode_flags = GUEST_IN_PHY;
}

extern void vmx_switch_rr7(unsigned long ,shared_info_t*,void *,void *,void *);

void
physical_tlb_miss(VCPU *vcpu, u64 vadr, int type)
{
    u64 pte;
    ia64_rr rr;
    rr.rrval = ia64_get_rr(vadr);
    pte =  vadr& _PAGE_PPN_MASK;
    pte = pte | PHY_PAGE_WB;
    thash_vhpt_insert(vcpu, pte, (rr.ps << 2), vadr, type);
    return;
}


void
vmx_init_all_rr(VCPU *vcpu)
{
	VMX(vcpu, vrr[VRN0]) = 0x38;
	// enable vhpt in guest physical mode
	vcpu->arch.metaphysical_rr0 |= 1;
	vcpu->arch.metaphysical_saved_rr0 = vrrtomrr(vcpu, 0x38);
	VMX(vcpu, vrr[VRN1]) = 0x38;
	VMX(vcpu, vrr[VRN2]) = 0x38;
	VMX(vcpu, vrr[VRN3]) = 0x38;
	VMX(vcpu, vrr[VRN4]) = 0x38;
	// enable vhpt in guest physical mode
	vcpu->arch.metaphysical_rr4 |= 1;
	vcpu->arch.metaphysical_saved_rr4 = vrrtomrr(vcpu, 0x38);
	VMX(vcpu, vrr[VRN5]) = 0x38;
	VMX(vcpu, vrr[VRN6]) = 0x38;
	VMX(vcpu, vrr[VRN7]) = 0x738;
}

extern void * pal_vaddr;

void
vmx_load_all_rr(VCPU *vcpu)
{
	unsigned long psr;

	local_irq_save(psr);

	/* WARNING: not allow co-exist of both virtual mode and physical
	 * mode in same region
	 */
	if (is_physical_mode(vcpu)) {
		if (vcpu->arch.mode_flags & GUEST_PHY_EMUL){
			panic_domain(vcpu_regs(vcpu),
			             "Unexpected domain switch in phy emul\n");
		}
		ia64_set_rr((VRN0 << VRN_SHIFT), vcpu->arch.metaphysical_rr0);
		ia64_dv_serialize_data();
		ia64_set_rr((VRN4 << VRN_SHIFT), vcpu->arch.metaphysical_rr4);
		ia64_dv_serialize_data();
	} else {
		ia64_set_rr((VRN0 << VRN_SHIFT),
                            vcpu->arch.metaphysical_saved_rr0);
		ia64_dv_serialize_data();
		ia64_set_rr((VRN4 << VRN_SHIFT),
                            vcpu->arch.metaphysical_saved_rr4);
		ia64_dv_serialize_data();
	}

	/* rr567 will be postponed to last point when resuming back to guest */
	ia64_set_rr((VRN1 << VRN_SHIFT),
		     vrrtomrr(vcpu, VMX(vcpu, vrr[VRN1])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN2 << VRN_SHIFT),
		     vrrtomrr(vcpu, VMX(vcpu, vrr[VRN2])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN3 << VRN_SHIFT),
		     vrrtomrr(vcpu, VMX(vcpu, vrr[VRN3])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN5 << VRN_SHIFT),
		     vrrtomrr(vcpu, VMX(vcpu, vrr[VRN5])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN6 << VRN_SHIFT),
		     vrrtomrr(vcpu, VMX(vcpu, vrr[VRN6])));
	ia64_dv_serialize_data();
	vmx_switch_rr7(vrrtomrr(vcpu,VMX(vcpu, vrr[VRN7])),
			(void *)vcpu->domain->shared_info,
			(void *)vcpu->arch.privregs,
			(void *)vcpu->arch.vhpt.hash, pal_vaddr );
	ia64_set_pta(VMX(vcpu, mpta));
	vmx_ia64_set_dcr(vcpu);

	ia64_srlz_d();
	ia64_set_psr(psr);
	ia64_srlz_i();
}



void
switch_to_physical_rid(VCPU *vcpu)
{
    u64 psr;
    /* Save original virtual mode rr[0] and rr[4] */
    psr=ia64_clear_ic();
    ia64_set_rr(VRN0<<VRN_SHIFT, vcpu->arch.metaphysical_rr0);
    ia64_srlz_d();
    ia64_set_rr(VRN4<<VRN_SHIFT, vcpu->arch.metaphysical_rr4);
    ia64_srlz_d();

    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}


void
switch_to_virtual_rid(VCPU *vcpu)
{
    u64 psr;
    psr=ia64_clear_ic();
    ia64_set_rr(VRN0<<VRN_SHIFT, vcpu->arch.metaphysical_saved_rr0);
    ia64_srlz_d();
    ia64_set_rr(VRN4<<VRN_SHIFT, vcpu->arch.metaphysical_saved_rr4);
    ia64_srlz_d();
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

static int mm_switch_action(IA64_PSR opsr, IA64_PSR npsr)
{
    return mm_switch_table[MODE_IND(opsr)][MODE_IND(npsr)];
}

void
switch_mm_mode(VCPU *vcpu, IA64_PSR old_psr, IA64_PSR new_psr)
{
    int act;
    act = mm_switch_action(old_psr, new_psr);
    perfc_incra(vmx_switch_mm_mode, act);
    switch (act) {
    case SW_V2P:
//        printk("V -> P mode transition: (0x%lx -> 0x%lx)\n",
//               old_psr.val, new_psr.val);
        switch_to_physical_rid(vcpu);
        /*
         * Set rse to enforced lazy, to prevent active rse save/restor when
         * guest physical mode.
         */
        vcpu->arch.mode_flags |= GUEST_IN_PHY;
        break;
    case SW_P2V:
//        printk("P -> V mode transition: (0x%lx -> 0x%lx)\n",
//               old_psr.val, new_psr.val);
        switch_to_virtual_rid(vcpu);
        /*
         * recover old mode which is saved when entering
         * guest physical mode
         */
        vcpu->arch.mode_flags &= ~GUEST_IN_PHY;
        break;
    case SW_SELF:
        printk("Switch to self-0x%lx!!! MM mode doesn't change...\n",
            old_psr.val);
        break;
    case SW_NOP:
//        printk("No action required for mode transition: (0x%lx -> 0x%lx)\n",
//               old_psr.val, new_psr.val);
        break;
    default:
        /* Sanity check */
        panic_domain(vcpu_regs(vcpu),"Unexpected virtual <--> physical mode transition,old:%lx,new:%lx\n",old_psr.val,new_psr.val);
        break;
    }
    return;
}



/*
 * In physical mode, insert tc/tr for region 0 and 4 uses
 * RID[0] and RID[4] which is for physical mode emulation.
 * However what those inserted tc/tr wants is rid for
 * virtual mode. So original virtual rid needs to be restored
 * before insert.
 *
 * Operations which required such switch include:
 *  - insertions (itc.*, itr.*)
 *  - purges (ptc.* and ptr.*)
 *  - tpa
 *  - tak
 *  - thash?, ttag?
 * All above needs actual virtual rid for destination entry.
 */

void
check_mm_mode_switch (VCPU *vcpu,  IA64_PSR old_psr, IA64_PSR new_psr)
{

    if ( (old_psr.dt != new_psr.dt ) ||
         (old_psr.it != new_psr.it ) ||
         (old_psr.rt != new_psr.rt )
         ) {
        switch_mm_mode (vcpu, old_psr, new_psr);
    }

    return;
}


/*
 * In physical mode, insert tc/tr for region 0 and 4 uses
 * RID[0] and RID[4] which is for physical mode emulation.
 * However what those inserted tc/tr wants is rid for
 * virtual mode. So original virtual rid needs to be restored
 * before insert.
 *
 * Operations which required such switch include:
 *  - insertions (itc.*, itr.*)
 *  - purges (ptc.* and ptr.*)
 *  - tpa
 *  - tak
 *  - thash?, ttag?
 * All above needs actual virtual rid for destination entry.
 */

void
prepare_if_physical_mode(VCPU *vcpu)
{
    if (is_physical_mode(vcpu)) {
	vcpu->arch.mode_flags |= GUEST_PHY_EMUL;
        switch_to_virtual_rid(vcpu);
    }
    return;
}

/* Recover always follows prepare */
void
recover_if_physical_mode(VCPU *vcpu)
{
    if (is_physical_mode(vcpu))
        switch_to_physical_rid(vcpu);
    vcpu->arch.mode_flags &= ~GUEST_PHY_EMUL;
    return;
}

