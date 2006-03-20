/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_phy_mode.h: 
 * Copyright (c) 2004, Intel Corporation.
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

#ifndef _PHY_MODE_H_
#define _PHY_MODE_H_

/*
 *  Guest Physical Mode is emulated by GVMM, which is actually running
 *  in virtual mode.
 *
 *  For all combinations of (it,dt,rt), only three were taken into
 *  account:
 *  (0,0,0): some firmware and kernel start code execute in this mode;
 *  (1,1,1): most kernel C code execute in this mode;
 *  (1,0,1): some low level TLB miss handler code execute in this mode;
 *  Till now, no other kind of combinations were found.
 *
 *  Because all physical addresses fall into two categories:
 *  0x0xxxxxxxxxxxxxxx, which is cacheable, and 0x8xxxxxxxxxxxxxxx, which
 *  is uncacheable. These two kinds of addresses reside in region 0 and 4
 *  of the virtual mode. Therefore, we load two different Region IDs
 *  (A, B) into RR0 and RR4, respectively, when guest is entering phsical
 *  mode. These two RIDs are totally different from the RIDs used in
 *  virtual mode. So, the aliasness between physical addresses and virtual
 *  addresses can be disambiguated by different RIDs.
 *
 *  RID A and B are stolen from the cpu ulm region id. In linux, each
 *  process is allocated 8 RIDs:
 *          mmu_context << 3 + 0
 *          mmu_context << 3 + 1
 *          mmu_context << 3 + 2
 *          mmu_context << 3 + 3
 *          mmu_context << 3 + 4
 *          mmu_context << 3 + 5
 *          mmu_context << 3 + 6
 *          mmu_context << 3 + 7
 *  Because all processes share region 5~7, the last 3 are left untouched.
 *  So, we stolen "mmu_context << 3 + 5" and "mmu_context << 3 + 6" from
 *  ulm and use them as RID A and RID B.
 *
 *  When guest is running in (1,0,1) mode, the instructions been accessed
 *  reside in region 5~7, not in region 0 or 4. So, instruction can be
 *  accessed in virtual mode without interferring physical data access.
 *
 *  When dt!=rt, it is rarely to perform "load/store" and "RSE" operation
 *  at the same time. No need to consider such a case. We consider (0,1)
 *  as (0,0).
 *
 */


#include <asm/vmx_vcpu.h>
#include <asm/regionreg.h>
#include <asm/gcc_intrin.h>
#include <asm/pgtable.h>
/* Due to change of ia64_set_rr interface */

#define PHY_PAGE_UC (_PAGE_A|_PAGE_D|_PAGE_P|_PAGE_MA_UC|_PAGE_AR_RWX)
#define PHY_PAGE_WB (_PAGE_A|_PAGE_D|_PAGE_P|_PAGE_MA_WB|_PAGE_AR_RWX)

//#ifdef PHY_16M  /* 16M: large granule for test*/
//#define EMUL_PHY_PAGE_SHIFT 24
//#else   /* 4K: emulated physical page granule */
//#define EMUL_PHY_PAGE_SHIFT 12
//#endif
#define IA64_RSC_MODE       0x0000000000000003
#define XEN_RR7_RID    (0xf00010)
#define GUEST_IN_PHY    0x1
#define GUEST_PHY_EMUL	0x2
extern int valid_mm_mode[];
extern int mm_switch_table[][8];
extern void physical_mode_init(VCPU *);
extern void switch_to_physical_rid(VCPU *);
extern void switch_to_virtual_rid(VCPU *vcpu);
extern void switch_mm_mode(VCPU *vcpu, IA64_PSR old_psr, IA64_PSR new_psr);
extern void stlb_phys_lookup(VCPU *vcpu, UINT64 paddr, UINT64 type);
extern void check_mm_mode_switch (VCPU *vcpu,  IA64_PSR old_psr, IA64_PSR new_psr);
extern void prepare_if_physical_mode(VCPU *vcpu);
extern void recover_if_physical_mode(VCPU *vcpu);
extern void vmx_init_all_rr(VCPU *vcpu);
extern void vmx_load_all_rr(VCPU *vcpu);
extern void physical_tlb_miss(VCPU *vcpu, u64 vadr, u64 vec);
/*
 * No sanity check here, since all psr changes have been
 * checked in switch_mm_mode().
 */
#define is_physical_mode(v) \
    ((v->arch.mode_flags) & GUEST_IN_PHY)

#define is_virtual_mode(v) \
    (!is_physical_mode(v))

#define MODE_IND(psr)   \
    (((psr).it << 2) + ((psr).dt << 1) + (psr).rt)

#define SW_BAD  0   /* Bad mode transitition */
#define SW_V2P  1   /* Physical emulatino is activated */
#define SW_P2V  2   /* Exit physical mode emulation */
#define SW_SELF 3   /* No mode transition */
#define SW_NOP  4   /* Mode transition, but without action required */

#define INV_MODE    0   /* Invalid mode */
#define GUEST_VIRT  1   /* Guest in virtual mode */
#define GUEST_PHYS  2   /* Guest in physical mode, requiring emulation */



#endif /* _PHY_MODE_H_ */



