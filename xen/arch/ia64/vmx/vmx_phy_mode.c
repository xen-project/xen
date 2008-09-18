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
#include <asm/pgtable.h>
#include <asm/vmmu.h>
#include <asm/debugger.h>

#define MODE_IND(psr)   \
    (((psr).it << 2) + ((psr).dt << 1) + (psr).rt)

#define SW_BAD    0   /* Bad mode transitition */
#define SW_2P_DT  1   /* Physical emulation is activated */
#define SW_2P_D   2   /* Physical emulation is activated (only for data) */
#define SW_2V     3   /* Exit physical mode emulation */
#define SW_SELF   4   /* No mode transition */
#define SW_NOP    5   /* Mode transition, but without action required */

/*
 * Special notes:
 * - Index by it/dt/rt sequence
 * - Only existing mode transitions are allowed in this table
 * - If gva happens to be rr0 and rr4, only allowed case is identity
 *   mapping (gva=gpa), or panic! (How?)
 */
static const unsigned char mm_switch_table[8][8] = {
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
     *
     *  (it,dt,rt): (0,0,0) -> (1,0,1)
     */
    {SW_SELF,0,  0,  SW_NOP, 0,  SW_2P_D,  0,  SW_2V},
    {0,  0,  0,  0,  0,  0,  0,  0},
    {0,  0,  0,  0,  0,  0,  0,  0},
    /*
     *  (it,dt,rt): (0,1,1) -> (1,1,1)
     *  This kind of transition is found in OSYa.
     *
     *  (it,dt,rt): (0,1,1) -> (0,0,0)
     *  This kind of transition is found in OSYa
     */
    {SW_NOP, 0,  0,  SW_SELF,0,  0,  0,  SW_2V},
    /* (1,0,0)->(1,1,1) */
    {0,  0,  0,  0,  0,  0,  0,  SW_2V},
    /*
     *  (it,dt,rt): (1,0,1) -> (1,1,1)
     *  This kind of transition usually occurs when Linux returns
     *  from the low level TLB miss handlers.
     *  (see "arch/ia64/kernel/ivt.S")
     *
     *  (it,dt,rt): (1,0,1) -> (0,0,0)
     */
    {SW_2P_DT,  0,  0,  0,  0,  SW_SELF,0,  SW_2V},
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
     *
     *  (it,dt,rt): (1,1,1)->(1,0,0)
     */
    {SW_2P_DT, 0,  0,  0,  SW_2P_D, SW_2P_D, 0,  SW_SELF},
};

void
physical_mode_init(VCPU *vcpu)
{
    vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_PHY_DT;
}

void
physical_tlb_miss(VCPU *vcpu, u64 vadr, int type)
{
    u64 pte;

    pte = (vadr & _PAGE_PPN_MASK) | PHY_PAGE_WB;
    thash_vhpt_insert(vcpu, pte, (PAGE_SHIFT << 2), vadr, type);
}

void
vmx_init_all_rr(VCPU *vcpu)
{
	// enable vhpt in guest physical mode
	vcpu->arch.metaphysical_rid_dt |= 1;

	VMX(vcpu, vrr[VRN0]) = 0x38;
	vcpu->arch.metaphysical_saved_rr0 = vrrtomrr(vcpu, 0x38);
	VMX(vcpu, vrr[VRN1]) = 0x38;
	VMX(vcpu, vrr[VRN2]) = 0x38;
	VMX(vcpu, vrr[VRN3]) = 0x38;
	VMX(vcpu, vrr[VRN4]) = 0x38;
	vcpu->arch.metaphysical_saved_rr4 = vrrtomrr(vcpu, 0x38);
	VMX(vcpu, vrr[VRN5]) = 0x38;
	VMX(vcpu, vrr[VRN6]) = 0x38;
	VMX(vcpu, vrr[VRN7]) = 0x738;
}

void
vmx_load_all_rr(VCPU *vcpu)
{
	unsigned long rr0, rr4;

	switch (vcpu->arch.arch_vmx.mmu_mode) {
	case VMX_MMU_VIRTUAL:
		rr0 = vcpu->arch.metaphysical_saved_rr0;
		rr4 = vcpu->arch.metaphysical_saved_rr4;
		break;
	case VMX_MMU_PHY_DT:
		rr0 = vcpu->arch.metaphysical_rid_dt;
		rr4 = vcpu->arch.metaphysical_rid_dt;
		break;
	case VMX_MMU_PHY_D:
		rr0 = vcpu->arch.metaphysical_rid_d;
		rr4 = vcpu->arch.metaphysical_rid_d;
		break;
	default:
		panic_domain(NULL, "bad mmu mode value");
	}

	ia64_set_rr((VRN0 << VRN_SHIFT), rr0);
	ia64_dv_serialize_data();
	ia64_set_rr((VRN4 << VRN_SHIFT), rr4);
	ia64_dv_serialize_data();
	ia64_set_rr((VRN1 << VRN_SHIFT), vrrtomrr(vcpu, VMX(vcpu, vrr[VRN1])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN2 << VRN_SHIFT), vrrtomrr(vcpu, VMX(vcpu, vrr[VRN2])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN3 << VRN_SHIFT), vrrtomrr(vcpu, VMX(vcpu, vrr[VRN3])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN5 << VRN_SHIFT), vrrtomrr(vcpu, VMX(vcpu, vrr[VRN5])));
	ia64_dv_serialize_data();
	ia64_set_rr((VRN6 << VRN_SHIFT), vrrtomrr(vcpu, VMX(vcpu, vrr[VRN6])));
	ia64_dv_serialize_data();
	vmx_switch_rr7_vcpu(vcpu, vrrtomrr(vcpu, VMX(vcpu, vrr[VRN7])));
	ia64_set_pta(VMX(vcpu, mpta));
	vmx_ia64_set_dcr(vcpu);

	ia64_srlz_d();
}

void
switch_to_physical_rid(VCPU *vcpu)
{
    u64 psr;
    u64 rr;

    switch (vcpu->arch.arch_vmx.mmu_mode) {
    case VMX_MMU_PHY_DT:
        rr = vcpu->arch.metaphysical_rid_dt;
        break;
    case VMX_MMU_PHY_D:
        rr = vcpu->arch.metaphysical_rid_d;
        break;
    default:
        panic_domain(NULL, "bad mmu mode value");
    }
    
    psr = ia64_clear_ic();
    ia64_set_rr(VRN0<<VRN_SHIFT, rr);
    ia64_dv_serialize_data();
    ia64_set_rr(VRN4<<VRN_SHIFT, rr);
    ia64_srlz_d();
    
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

void
switch_to_virtual_rid(VCPU *vcpu)
{
    u64 psr;

    psr = ia64_clear_ic();
    ia64_set_rr(VRN0<<VRN_SHIFT, vcpu->arch.metaphysical_saved_rr0);
    ia64_dv_serialize_data();
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

/* In fast path, psr.ic = 0, psr.i = 0, psr.bn = 0
 * so that no tlb miss is allowed.
 */
void
switch_mm_mode_fast(VCPU *vcpu, IA64_PSR old_psr, IA64_PSR new_psr)
{
    int act;
    act = mm_switch_action(old_psr, new_psr);
    switch (act) {
    case SW_2P_DT:
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_PHY_DT;
        switch_to_physical_rid(vcpu);
        break;
    case SW_2P_D:
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_PHY_D;
        switch_to_physical_rid(vcpu);
        break;
    case SW_2V:
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_VIRTUAL;
        switch_to_virtual_rid(vcpu);
        break;
    default:
        break;
    }
    return;
}

void
switch_mm_mode(VCPU *vcpu, IA64_PSR old_psr, IA64_PSR new_psr)
{
    int act;
    /* Switch to physical mode when injecting PAL_INIT */
    if (unlikely(MODE_IND(new_psr) == 0 &&
                 vcpu_regs(vcpu)->cr_iip == PAL_INIT_ENTRY))
        act = SW_2P_DT;
    else
        act = mm_switch_action(old_psr, new_psr);
    perfc_incra(vmx_switch_mm_mode, act);
    switch (act) {
    case SW_2P_DT:
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_PHY_DT;
        switch_to_physical_rid(vcpu);
        break;
    case SW_2P_D:
//        printk("V -> P_D mode transition: (0x%lx -> 0x%lx)\n",
//               old_psr.val, new_psr.val);
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_PHY_D;
        switch_to_physical_rid(vcpu);
        break;
    case SW_2V:
//        printk("P -> V mode transition: (0x%lx -> 0x%lx)\n",
//               old_psr.val, new_psr.val);
        vcpu->arch.arch_vmx.mmu_mode = VMX_MMU_VIRTUAL;
        switch_to_virtual_rid(vcpu);
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
        panic_domain(vcpu_regs(vcpu),
                     "Unexpected virtual <--> physical mode transition, "
                     "old:%lx, new:%lx\n", old_psr.val, new_psr.val);
        break;
    }
    return;
}

void
check_mm_mode_switch (VCPU *vcpu,  IA64_PSR old_psr, IA64_PSR new_psr)
{
    if (old_psr.dt != new_psr.dt ||
        old_psr.it != new_psr.it ||
        old_psr.rt != new_psr.rt) {
        switch_mm_mode(vcpu, old_psr, new_psr);
        debugger_event(XEN_IA64_DEBUG_ON_MMU);
    }
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
    if (!is_virtual_mode(vcpu))
        switch_to_virtual_rid(vcpu);
    return;
}

/* Recover always follows prepare */
void
recover_if_physical_mode(VCPU *vcpu)
{
    if (!is_virtual_mode(vcpu))
        switch_to_physical_rid(vcpu);
    return;
}

