/*
 * arch/ia64/kernel/vmx_ivt.S
 *
 * Copyright (C) 1998-2001, 2003 Hewlett-Packard Co
 *	Stephane Eranian <eranian@hpl.hp.com>
 *	David Mosberger <davidm@hpl.hp.com>
 * Copyright (C) 2000, 2002-2003 Intel Co
 *	Asit Mallick <asit.k.mallick@intel.com>
 *      Suresh Siddha <suresh.b.siddha@intel.com>
 *      Kenneth Chen <kenneth.w.chen@intel.com>
 *      Fenghua Yu <fenghua.yu@intel.com>
 *
 *
 * 00/08/23 Asit Mallick <asit.k.mallick@intel.com> TLB handling for SMP
 * 00/12/20 David Mosberger-Tang <davidm@hpl.hp.com> DTLB/ITLB handler now uses virtual PT.
 *
 * 05/3/20 Xuefei Xu  (Anthony Xu) (anthony.xu@intel.com)
 *              Supporting Intel virtualization architecture
 *
 */

/*
 * This file defines the interruption vector table used by the CPU.
 * It does not include one entry per possible cause of interruption.
 *
 * The first 20 entries of the table contain 64 bundles each while the
 * remaining 48 entries contain only 16 bundles each.
 *
 * The 64 bundles are used to allow inlining the whole handler for critical
 * interruptions like TLB misses.
 *
 *  For each entry, the comment is as follows:
 *
 *		// 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
 *  entry offset ----/     /         /                  /          /
 *  entry number ---------/         /                  /          /
 *  size of the entry -------------/                  /          /
 *  vector name -------------------------------------/          /
 *  interruptions triggering this vector ----------------------/
 *
 * The table is 32KB in size and must be aligned on 32KB boundary.
 * (The CPU ignores the 15 lower bits of the address)
 *
 * Table is based upon EAS2.6 (Oct 1999)
 */

#include <linux/config.h>

#include <asm/asmmacro.h>
#include <asm/break.h>
#include <asm/ia32.h>
#include <asm/kregs.h>
#include <asm/offsets.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#include <asm/vhpt.h>


#if 0
  /*
   * This lets you track the last eight faults that occurred on the CPU.  Make sure ar.k2 isn't
   * needed for something else before enabling this...
   */
# define VMX_DBG_FAULT(i)	mov r16=ar.k2;;	shl r16=r16,8;;	add r16=(i),r16;;mov ar.k2=r16
#else
# define VMX_DBG_FAULT(i)
#endif

#include "vmx_minstate.h"



#define VMX_FAULT(n)    \
vmx_fault_##n:;          \
    br.sptk vmx_fault_##n;         \
    ;;                  \


#define VMX_REFLECT(n)				\
	mov r31=pr;									\
	mov r19=n;			/* prepare to save predicates */		\
    mov r29=cr.ipsr;        \
    ;;      \
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;       \
(p7) br.sptk.many vmx_dispatch_reflection;        \
    VMX_FAULT(n);            \


GLOBAL_ENTRY(vmx_panic)
    br.sptk.many vmx_panic
    ;;
END(vmx_panic)





	.section .text.ivt,"ax"

	.align 32768	// align on 32KB boundary
	.global vmx_ia64_ivt
vmx_ia64_ivt:
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0000 Entry 0 (size 64 bundles) VHPT Translation (8,20,47)
ENTRY(vmx_vhpt_miss)
    VMX_FAULT(0)
END(vmx_vhpt_miss)

	.org vmx_ia64_ivt+0x400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0400 Entry 1 (size 64 bundles) ITLB (21)
ENTRY(vmx_itlb_miss)
    mov r31 = pr
    mov r29=cr.ipsr;
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;
(p6) br.sptk vmx_fault_1
    mov r16 = cr.ifa
    ;;
    thash r17 = r16
    ttag r20 = r16
    ;;
vmx_itlb_loop:
    cmp.eq p6,p0 = r0, r17
(p6) br vmx_itlb_out
    ;;
    adds r22 = VLE_TITAG_OFFSET, r17
    adds r23 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r24 = [r22]
    ld8 r25 = [r23]
    ;;
    lfetch [r25]
    cmp.eq  p6,p7 = r20, r24
    ;;
(p7)    mov r17 = r25;
(p7)    br.sptk vmx_itlb_loop
    ;;
    adds r23 = VLE_PGFLAGS_OFFSET, r17
    adds r24 = VLE_ITIR_OFFSET, r17
    ;;
    ld8 r26 = [r23]
    ld8 r25 = [r24]
    ;;
    mov cr.itir = r25
    ;;
    itc.i r26
    ;;
    srlz.i
    ;;
    mov r23=r31
    mov r22=b0
    adds r16=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r16]
    ;;
    adds r19=VPD(VPSR),r18
    movl r20=__vsa_base
    ;;
    ld8 r19=[r19]
    ld8 r20=[r20]
    ;;
    br.sptk ia64_vmm_entry
    ;;
vmx_itlb_out:
    mov r19 = 1
    br.sptk vmx_dispatch_tlb_miss
    VMX_FAULT(1);
END(vmx_itlb_miss)

	.org vmx_ia64_ivt+0x0800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0800 Entry 2 (size 64 bundles) DTLB (9,48)
ENTRY(vmx_dtlb_miss)
    mov r31 = pr
    mov r29=cr.ipsr;
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;
(p6)br.sptk vmx_fault_1
    mov r16 = cr.ifa
    ;;
    thash r17 = r16
    ttag r20 = r16
    ;;
vmx_dtlb_loop:
    cmp.eq p6,p0 = r0, r17
(p6)br vmx_dtlb_out
    ;;
    adds r22 = VLE_TITAG_OFFSET, r17
    adds r23 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r24 = [r22]
    ld8 r25 = [r23]
    ;;
    lfetch [r25]
    cmp.eq  p6,p7 = r20, r24
    ;;
(p7)mov r17 = r25;
(p7)br.sptk vmx_dtlb_loop
    ;;
    adds r23 = VLE_PGFLAGS_OFFSET, r17
    adds r24 = VLE_ITIR_OFFSET, r17
    ;;
    ld8 r26 = [r23]
    ld8 r25 = [r24]
    ;;
    mov cr.itir = r25
    ;;
    itc.d r26
    ;;
    srlz.d;
    ;;
    mov r23=r31
    mov r22=b0
    adds r16=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r16]
    ;;
    adds r19=VPD(VPSR),r18
    movl r20=__vsa_base
    ;;
    ld8 r19=[r19]
    ld8 r20=[r20]
    ;;
    br.sptk ia64_vmm_entry
    ;;
vmx_dtlb_out:
    mov r19 = 2
    br.sptk vmx_dispatch_tlb_miss
    VMX_FAULT(2);
END(vmx_dtlb_miss)

	.org vmx_ia64_ivt+0x0c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0c00 Entry 3 (size 64 bundles) Alt ITLB (19)
ENTRY(vmx_alt_itlb_miss)
    mov r31 = pr
    mov r29=cr.ipsr;
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;
(p7)br.sptk vmx_fault_3
	mov r16=cr.ifa		// get address that caused the TLB miss
	movl r17=PAGE_KERNEL
	mov r24=cr.ipsr
	movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
	;;
	and r19=r19,r16		// clear ed, reserved bits, and PTE control bits
	shr.u r18=r16,57	// move address bit 61 to bit 4
	;;
	andcm r18=0x10,r18	// bit 4=~address-bit(61)
	or r19=r17,r19		// insert PTE control bits into r19
	;;
	or r19=r19,r18		// set bit 4 (uncached) if the access was to region 6
	;;
	itc.i r19		// insert the TLB entry
	mov pr=r31,-1
	rfi
    VMX_FAULT(3);
END(vmx_alt_itlb_miss)


	.org vmx_ia64_ivt+0x1000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1000 Entry 4 (size 64 bundles) Alt DTLB (7,46)
ENTRY(vmx_alt_dtlb_miss)
	mov r31=pr
    mov r29=cr.ipsr;
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;
(p7)br.sptk vmx_fault_4
	mov r16=cr.ifa		// get address that caused the TLB miss
	movl r17=PAGE_KERNEL
	mov r20=cr.isr
	movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
	mov r24=cr.ipsr
	;;
	and r22=IA64_ISR_CODE_MASK,r20		// get the isr.code field
	tbit.nz p6,p7=r20,IA64_ISR_SP_BIT	// is speculation bit on?
	shr.u r18=r16,57			// move address bit 61 to bit 4
	and r19=r19,r16				// clear ed, reserved bits, and PTE control bits
	tbit.nz p9,p0=r20,IA64_ISR_NA_BIT	// is non-access bit on?
	;;
	andcm r18=0x10,r18	// bit 4=~address-bit(61)
(p9) cmp.eq.or.andcm p6,p7=IA64_ISR_CODE_LFETCH,r22	// check isr.code field
	dep r24=-1,r24,IA64_PSR_ED_BIT,1
	or r19=r19,r17		// insert PTE control bits into r19
	;;
	or r19=r19,r18		// set bit 4 (uncached) if the access was to region 6
(p6) mov cr.ipsr=r24
	;;
(p7) itc.d r19		// insert the TLB entry
	mov pr=r31,-1
	rfi
    VMX_FAULT(4);
END(vmx_alt_dtlb_miss)

	.org vmx_ia64_ivt+0x1400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1400 Entry 5 (size 64 bundles) Data nested TLB (6,45)
ENTRY(vmx_nested_dtlb_miss)
    VMX_FAULT(5)
END(vmx_nested_dtlb_miss)

	.org vmx_ia64_ivt+0x1800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1800 Entry 6 (size 64 bundles) Instruction Key Miss (24)
ENTRY(vmx_ikey_miss)
	VMX_REFLECT(6)
END(vmx_ikey_miss)

	.org vmx_ia64_ivt+0x1c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
ENTRY(vmx_dkey_miss)
	VMX_REFLECT(7)
END(vmx_dkey_miss)

	.org vmx_ia64_ivt+0x2000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2000 Entry 8 (size 64 bundles) Dirty-bit (54)
ENTRY(vmx_dirty_bit)
	VMX_REFLECT(8)
END(vmx_idirty_bit)

	.org vmx_ia64_ivt+0x2400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2400 Entry 9 (size 64 bundles) Instruction Access-bit (27)
ENTRY(vmx_iaccess_bit)
	VMX_REFLECT(9)
END(vmx_iaccess_bit)

	.org vmx_ia64_ivt+0x2800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2800 Entry 10 (size 64 bundles) Data Access-bit (15,55)
ENTRY(vmx_daccess_bit)
	VMX_REFLECT(10)
END(vmx_daccess_bit)

	.org vmx_ia64_ivt+0x2c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2c00 Entry 11 (size 64 bundles) Break instruction (33)
ENTRY(vmx_break_fault)
	mov r31=pr
    mov r19=11
    br.sptk.many vmx_dispatch_break_fault
END(vmx_break_fault)

	.org vmx_ia64_ivt+0x3000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3000 Entry 12 (size 64 bundles) External Interrupt (4)
ENTRY(vmx_interrupt)
	mov r31=pr		// prepare to save predicates
    mov r19=12
    mov r29=cr.ipsr
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT
(p7) br.sptk vmx_dispatch_interrupt
    ;;
	mov r27=ar.rsc			/* M */
	mov r20=r1			/* A */
	mov r25=ar.unat		/* M */
	mov r26=ar.pfs			/* I */
	mov r28=cr.iip			/* M */
	cover               /* B (or nothing) */
	;;
	mov r1=sp
	;;
	invala				/* M */
	mov r30=cr.ifs
	;;
    addl r1=-IA64_PT_REGS_SIZE,r1
    ;;
	adds r17=2*L1_CACHE_BYTES,r1		/* really: biggest cache-line size */
	adds r16=PT(CR_IPSR),r1
	;;
	lfetch.fault.excl.nt1 [r17],L1_CACHE_BYTES
	st8 [r16]=r29		/* save cr.ipsr */
	;;
	lfetch.fault.excl.nt1 [r17]
	mov r29=b0
	;;
	adds r16=PT(R8),r1  	/* initialize first base pointer */
	adds r17=PT(R9),r1  	/* initialize second base pointer */
	mov r18=r0      		/* make sure r18 isn't NaT */
	;;
.mem.offset 0,0; st8.spill [r16]=r8,16
.mem.offset 8,0; st8.spill [r17]=r9,16
        ;;
.mem.offset 0,0; st8.spill [r16]=r10,24
.mem.offset 8,0; st8.spill [r17]=r11,24
        ;;
	st8 [r16]=r28,16	/* save cr.iip */
	st8 [r17]=r30,16	/* save cr.ifs */
	mov r8=ar.fpsr		/* M */
	mov r9=ar.csd
	mov r10=ar.ssd
	movl r11=FPSR_DEFAULT   /* L-unit */
	;;
	st8 [r16]=r25,16	/* save ar.unat */
	st8 [r17]=r26,16	/* save ar.pfs */
	shl r18=r18,16		/* compute ar.rsc to be used for "loadrs" */
	;;
    st8 [r16]=r27,16   /* save ar.rsc */
    adds r17=16,r17    /* skip over ar_rnat field */
    ;;          /* avoid RAW on r16 & r17 */
    st8 [r17]=r31,16   /* save predicates */
    adds r16=16,r16    /* skip over ar_bspstore field */
    ;;
    st8 [r16]=r29,16   /* save b0 */
    st8 [r17]=r18,16   /* save ar.rsc value for "loadrs" */
    ;;
.mem.offset 0,0; st8.spill [r16]=r20,16    /* save original r1 */
.mem.offset 8,0; st8.spill [r17]=r12,16
    adds r12=-16,r1    /* switch to kernel memory stack (with 16 bytes of scratch) */
    ;;
.mem.offset 0,0; st8.spill [r16]=r13,16
.mem.offset 8,0; st8.spill [r17]=r8,16 /* save ar.fpsr */
    mov r13=r21    /* establish `current' */
    ;;
.mem.offset 0,0; st8.spill [r16]=r15,16
.mem.offset 8,0; st8.spill [r17]=r14,16
    dep r14=-1,r0,60,4
    ;;
.mem.offset 0,0; st8.spill [r16]=r2,16
.mem.offset 8,0; st8.spill [r17]=r3,16
    adds r2=IA64_PT_REGS_R16_OFFSET,r1
    ;;
    mov r8=ar.ccv
    movl r1=__gp       /* establish kernel global pointer */
    ;;                                          \
    bsw.1
    ;;
	alloc r14=ar.pfs,0,0,2,0 // must be first in an insn group
	mov out0=cr.ivr		// pass cr.ivr as first arg
	add out1=16,sp		// pass pointer to pt_regs as second arg

	ssm psr.ic
    ;;
    srlz.i
	;;
    ssm psr.i
	adds r3=8,r2		// set up second base pointer for SAVE_REST
	srlz.i			// ensure everybody knows psr.ic is back on
	;;
.mem.offset 0,0; st8.spill [r2]=r16,16
.mem.offset 8,0; st8.spill [r3]=r17,16
    ;;
.mem.offset 0,0; st8.spill [r2]=r18,16
.mem.offset 8,0; st8.spill [r3]=r19,16
    ;;
.mem.offset 0,0; st8.spill [r2]=r20,16
.mem.offset 8,0; st8.spill [r3]=r21,16
    mov r18=b6
    ;;
.mem.offset 0,0; st8.spill [r2]=r22,16
.mem.offset 8,0; st8.spill [r3]=r23,16
    mov r19=b7
    ;;
.mem.offset 0,0; st8.spill [r2]=r24,16
.mem.offset 8,0; st8.spill [r3]=r25,16
    ;;
.mem.offset 0,0; st8.spill [r2]=r26,16
.mem.offset 8,0; st8.spill [r3]=r27,16
    ;;
.mem.offset 0,0; st8.spill [r2]=r28,16
.mem.offset 8,0; st8.spill [r3]=r29,16
    ;;
.mem.offset 0,0; st8.spill [r2]=r30,16
.mem.offset 8,0; st8.spill [r3]=r31,32
    ;;
    mov ar.fpsr=r11     /* M-unit */
    st8 [r2]=r8,8      /* ar.ccv */
    adds r24=PT(B6)-PT(F7),r3
    ;;
    stf.spill [r2]=f6,32
    stf.spill [r3]=f7,32
    ;;
    stf.spill [r2]=f8,32
    stf.spill [r3]=f9,32
    ;;
    stf.spill [r2]=f10
    stf.spill [r3]=f11
    adds r25=PT(B7)-PT(F11),r3
    ;;
    st8 [r24]=r18,16       /* b6 */
    st8 [r25]=r19,16       /* b7 */
    ;;
    st8 [r24]=r9           /* ar.csd */
    st8 [r25]=r10          /* ar.ssd */
    ;;
	srlz.d			// make sure we see the effect of cr.ivr
	movl r14=ia64_leave_nested
	;;
	mov rp=r14
	br.call.sptk.many b6=vmx_ia64_handle_irq
	;;
END(vmx_interrupt)

	.org vmx_ia64_ivt+0x3400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3400 Entry 13 (size 64 bundles) Reserved
	VMX_DBG_FAULT(13)
	VMX_FAULT(13)


	.org vmx_ia64_ivt+0x3800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3800 Entry 14 (size 64 bundles) Reserved
	VMX_DBG_FAULT(14)
	VMX_FAULT(14)


	.org vmx_ia64_ivt+0x3c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3c00 Entry 15 (size 64 bundles) Reserved
	VMX_DBG_FAULT(15)
	VMX_FAULT(15)


	.org vmx_ia64_ivt+0x4000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x4000 Entry 16 (size 64 bundles) Reserved
	VMX_DBG_FAULT(16)
	VMX_FAULT(16)

	.org vmx_ia64_ivt+0x4400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x4400 Entry 17 (size 64 bundles) Reserved
	VMX_DBG_FAULT(17)
	VMX_FAULT(17)

	.org vmx_ia64_ivt+0x4800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x4800 Entry 18 (size 64 bundles) Reserved
	VMX_DBG_FAULT(18)
	VMX_FAULT(18)

	.org vmx_ia64_ivt+0x4c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x4c00 Entry 19 (size 64 bundles) Reserved
	VMX_DBG_FAULT(19)
	VMX_FAULT(19)

/////////////////////////////////////////////////////////////////////////////////////////
// 0x5200 Entry 22 (size 16 bundles) Instruction Access Rights (26)
ENTRY(vmx_iaccess_rights)
	VMX_REFLECT(22)
END(vmx_iaccess_rights)

	.org vmx_ia64_ivt+0x5300
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5300 Entry 23 (size 16 bundles) Data Access Rights (14,53)
ENTRY(vmx_daccess_rights)
	VMX_REFLECT(23)
END(vmx_daccess_rights)

	.org vmx_ia64_ivt+0x5400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5400 Entry 24 (size 16 bundles) General Exception (5,32,34,36,38,39)
ENTRY(vmx_general_exception)
    VMX_FAULT(24)
//    VMX_REFLECT(24)
END(vmx_general_exception)

	.org vmx_ia64_ivt+0x5500
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5500 Entry 25 (size 16 bundles) Disabled FP-Register (35)
ENTRY(vmx_disabled_fp_reg)
	VMX_REFLECT(25)
END(vmx_disabled_fp_reg)

	.org vmx_ia64_ivt+0x5600
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5600 Entry 26 (size 16 bundles) Nat Consumption (11,23,37,50)
ENTRY(vmx_nat_consumption)
	VMX_REFLECT(26)
END(vmx_nat_consumption)

	.org vmx_ia64_ivt+0x5700
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5700 Entry 27 (size 16 bundles) Speculation (40)
ENTRY(vmx_speculation_vector)
	VMX_REFLECT(27)
END(vmx_speculation_vector)

	.org vmx_ia64_ivt+0x5800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5800 Entry 28 (size 16 bundles) Reserved
	VMX_DBG_FAULT(28)
	VMX_FAULT(28)

	.org vmx_ia64_ivt+0x5900
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5900 Entry 29 (size 16 bundles) Debug (16,28,56)
ENTRY(vmx_debug_vector)
	VMX_DBG_FAULT(29)
	VMX_FAULT(29)
END(vmx_debug_vector)

	.org vmx_ia64_ivt+0x5a00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5a00 Entry 30 (size 16 bundles) Unaligned Reference (57)
ENTRY(vmx_unaligned_access)
	VMX_REFLECT(30)
END(vmx_unaligned_access)

	.org vmx_ia64_ivt+0x5b00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5b00 Entry 31 (size 16 bundles) Unsupported Data Reference (57)
ENTRY(vmx_unsupported_data_reference)
	VMX_REFLECT(31)
END(vmx_unsupported_data_reference)

	.org vmx_ia64_ivt+0x5c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5c00 Entry 32 (size 16 bundles) Floating-Point Fault (64)
ENTRY(vmx_floating_point_fault)
	VMX_REFLECT(32)
END(vmx_floating_point_fault)

	.org vmx_ia64_ivt+0x5d00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5d00 Entry 33 (size 16 bundles) Floating Point Trap (66)
ENTRY(vmx_floating_point_trap)
	VMX_REFLECT(33)
END(vmx_floating_point_trap)

	.org vmx_ia64_ivt+0x5e00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5e00 Entry 34 (size 16 bundles) Lower Privilege Transfer Trap (66)
ENTRY(vmx_lower_privilege_trap)
	VMX_REFLECT(34)
END(vmx_lower_privilege_trap)

	.org vmx_ia64_ivt+0x5f00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5f00 Entry 35 (size 16 bundles) Taken Branch Trap (68)
ENTRY(vmx_taken_branch_trap)
	VMX_REFLECT(35)
END(vmx_taken_branch_trap)

	.org vmx_ia64_ivt+0x6000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6000 Entry 36 (size 16 bundles) Single Step Trap (69)
ENTRY(vmx_single_step_trap)
	VMX_REFLECT(36)
END(vmx_single_step_trap)

	.org vmx_ia64_ivt+0x6100
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6100 Entry 37 (size 16 bundles) Virtualization Fault
ENTRY(vmx_virtualization_fault)
	VMX_DBG_FAULT(37)
	mov r31=pr
    mov r19=37
    br.sptk vmx_dispatch_virtualization_fault
END(vmx_virtualization_fault)

	.org vmx_ia64_ivt+0x6200
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6200 Entry 38 (size 16 bundles) Reserved
	VMX_DBG_FAULT(38)
	VMX_FAULT(38)

	.org vmx_ia64_ivt+0x6300
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6300 Entry 39 (size 16 bundles) Reserved
	VMX_DBG_FAULT(39)
	VMX_FAULT(39)

	.org vmx_ia64_ivt+0x6400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6400 Entry 40 (size 16 bundles) Reserved
	VMX_DBG_FAULT(40)
	VMX_FAULT(40)

	.org vmx_ia64_ivt+0x6500
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6500 Entry 41 (size 16 bundles) Reserved
	VMX_DBG_FAULT(41)
	VMX_FAULT(41)

	.org vmx_ia64_ivt+0x6600
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6600 Entry 42 (size 16 bundles) Reserved
	VMX_DBG_FAULT(42)
	VMX_FAULT(42)

	.org vmx_ia64_ivt+0x6700
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6700 Entry 43 (size 16 bundles) Reserved
	VMX_DBG_FAULT(43)
	VMX_FAULT(43)

	.org vmx_ia64_ivt+0x6800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6800 Entry 44 (size 16 bundles) Reserved
	VMX_DBG_FAULT(44)
	VMX_FAULT(44)

	.org vmx_ia64_ivt+0x6900
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6900 Entry 45 (size 16 bundles) IA-32 Exeception (17,18,29,41,42,43,44,58,60,61,62,72,73,75,76,77)
ENTRY(vmx_ia32_exception)
	VMX_DBG_FAULT(45)
	VMX_FAULT(45)
END(vmx_ia32_exception)

	.org vmx_ia64_ivt+0x6a00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6a00 Entry 46 (size 16 bundles) IA-32 Intercept  (30,31,59,70,71)
ENTRY(vmx_ia32_intercept)
	VMX_DBG_FAULT(46)
	VMX_FAULT(46)
END(vmx_ia32_intercept)

	.org vmx_ia64_ivt+0x6b00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6b00 Entry 47 (size 16 bundles) IA-32 Interrupt  (74)
ENTRY(vmx_ia32_interrupt)
	VMX_DBG_FAULT(47)
	VMX_FAULT(47)
END(vmx_ia32_interrupt)

	.org vmx_ia64_ivt+0x6c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6c00 Entry 48 (size 16 bundles) Reserved
	VMX_DBG_FAULT(48)
	VMX_FAULT(48)

	.org vmx_ia64_ivt+0x6d00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6d00 Entry 49 (size 16 bundles) Reserved
	VMX_DBG_FAULT(49)
	VMX_FAULT(49)

	.org vmx_ia64_ivt+0x6e00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6e00 Entry 50 (size 16 bundles) Reserved
	VMX_DBG_FAULT(50)
	VMX_FAULT(50)

	.org vmx_ia64_ivt+0x6f00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6f00 Entry 51 (size 16 bundles) Reserved
	VMX_DBG_FAULT(51)
	VMX_FAULT(51)

	.org vmx_ia64_ivt+0x7000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7000 Entry 52 (size 16 bundles) Reserved
	VMX_DBG_FAULT(52)
	VMX_FAULT(52)

	.org vmx_ia64_ivt+0x7100
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7100 Entry 53 (size 16 bundles) Reserved
	VMX_DBG_FAULT(53)
	VMX_FAULT(53)

	.org vmx_ia64_ivt+0x7200
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7200 Entry 54 (size 16 bundles) Reserved
	VMX_DBG_FAULT(54)
	VMX_FAULT(54)

	.org vmx_ia64_ivt+0x7300
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7300 Entry 55 (size 16 bundles) Reserved
	VMX_DBG_FAULT(55)
	VMX_FAULT(55)

	.org vmx_ia64_ivt+0x7400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7400 Entry 56 (size 16 bundles) Reserved
	VMX_DBG_FAULT(56)
	VMX_FAULT(56)

	.org vmx_ia64_ivt+0x7500
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7500 Entry 57 (size 16 bundles) Reserved
	VMX_DBG_FAULT(57)
	VMX_FAULT(57)

	.org vmx_ia64_ivt+0x7600
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7600 Entry 58 (size 16 bundles) Reserved
	VMX_DBG_FAULT(58)
	VMX_FAULT(58)

	.org vmx_ia64_ivt+0x7700
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7700 Entry 59 (size 16 bundles) Reserved
	VMX_DBG_FAULT(59)
	VMX_FAULT(59)

	.org vmx_ia64_ivt+0x7800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7800 Entry 60 (size 16 bundles) Reserved
	VMX_DBG_FAULT(60)
	VMX_FAULT(60)

	.org vmx_ia64_ivt+0x7900
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7900 Entry 61 (size 16 bundles) Reserved
	VMX_DBG_FAULT(61)
	VMX_FAULT(61)

	.org vmx_ia64_ivt+0x7a00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7a00 Entry 62 (size 16 bundles) Reserved
	VMX_DBG_FAULT(62)
	VMX_FAULT(62)

	.org vmx_ia64_ivt+0x7b00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7b00 Entry 63 (size 16 bundles) Reserved
	VMX_DBG_FAULT(63)
	VMX_FAULT(63)

	.org vmx_ia64_ivt+0x7c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7c00 Entry 64 (size 16 bundles) Reserved
    VMX_DBG_FAULT(64)
	VMX_FAULT(64)

	.org vmx_ia64_ivt+0x7d00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7d00 Entry 65 (size 16 bundles) Reserved
	VMX_DBG_FAULT(65)
	VMX_FAULT(65)

	.org vmx_ia64_ivt+0x7e00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7e00 Entry 66 (size 16 bundles) Reserved
	VMX_DBG_FAULT(66)
	VMX_FAULT(66)

	.org vmx_ia64_ivt+0x7f00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x7f00 Entry 67 (size 16 bundles) Reserved
	VMX_DBG_FAULT(67)
	VMX_FAULT(67)

	.org vmx_ia64_ivt+0x8000
    // There is no particular reason for this code to be here, other than that
    // there happens to be space here that would go unused otherwise.  If this
    // fault ever gets "unreserved", simply moved the following code to a more
    // suitable spot...


ENTRY(vmx_dispatch_reflection)
    /*
     * Input:
     *  psr.ic: off
     *  r19:    intr type (offset into ivt, see ia64_int.h)
     *  r31:    contains saved predicates (pr)
     */
    VMX_SAVE_MIN_WITH_COVER_R19
    alloc r14=ar.pfs,0,0,4,0
    mov out0=cr.ifa
    mov out1=cr.isr
    mov out2=cr.iim
    mov out3=r15

    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    ssm psr.i               // restore psr.i
    adds r3=16,r2                // set up second base pointer
    ;;
    VMX_SAVE_REST
    movl r14=ia64_leave_hypervisor
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_reflect_interruption
END(vmx_dispatch_reflection)

ENTRY(vmx_dispatch_virtualization_fault)
    cmp.eq pEml,pNonEml=r0,r0       /* force pEml =1, save r4 ~ r7 */
    ;;
    VMX_SAVE_MIN_WITH_COVER_R19
    ;;
    alloc r14=ar.pfs,0,0,3,0        // now it's safe (must be first in insn group!)
    mov out0=r13        //vcpu
    mov out1=r4         //cause
    mov out2=r5         //opcode
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    ssm psr.i               // restore psr.i
    adds r3=16,r2                // set up second base pointer
    ;;
    VMX_SAVE_REST
    movl r14=ia64_leave_hypervisor
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_emulate
END(vmx_dispatch_virtualization_fault)



ENTRY(vmx_dispatch_tlb_miss)
    VMX_SAVE_MIN_WITH_COVER_R19
    alloc r14=ar.pfs,0,0,3,0
    mov out0=r13
    mov out1=r15
    mov out2=cr.ifa

    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    ssm psr.i               // restore psr.i
    adds r3=16,r2                // set up second base pointer
    ;;
    VMX_SAVE_REST
    movl r14=ia64_leave_hypervisor
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_hpw_miss
END(vmx_dispatch_tlb_miss)


ENTRY(vmx_dispatch_break_fault)
    cmp.ne pEml,pNonEml=r0,r0       /* force pNonEml =1, don't save r4 ~ r7 */
    ;;
    VMX_SAVE_MIN_WITH_COVER_R19
    ;;
    alloc r14=ar.pfs,0,0,4,0 // now it's safe (must be first in insn group!)
    mov out0=cr.ifa
    adds out1=16,sp
    mov out2=cr.isr     // FIXME: pity to make this slow access twice
    mov out3=cr.iim     // FIXME: pity to make this slow access twice

    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    ssm psr.i               // restore psr.i
    adds r3=16,r2                // set up second base pointer
    ;;
    VMX_SAVE_REST
    movl r14=ia64_leave_hypervisor
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_ia64_handle_break
END(vmx_dispatch_break_fault)


ENTRY(vmx_dispatch_interrupt)
    cmp.ne pEml,pNonEml=r0,r0       /* force pNonEml =1, don't save r4 ~ r7 */
    ;;
	VMX_SAVE_MIN_WITH_COVER_R19	// uses r31; defines r2 and r3
	;;
	alloc r14=ar.pfs,0,0,2,0 // must be first in an insn group
	mov out0=cr.ivr		// pass cr.ivr as first arg
	add out1=16,sp		// pass pointer to pt_regs as second arg

	ssm psr.ic
	;;
    srlz.i
    ;;
    ssm psr.i
	adds r3=16,r2		// set up second base pointer for SAVE_REST
	;;
	VMX_SAVE_REST
	movl r14=ia64_leave_hypervisor
	;;
	mov rp=r14
	br.call.sptk.many b6=vmx_ia64_handle_irq
END(vmx_dispatch_interrupt)
