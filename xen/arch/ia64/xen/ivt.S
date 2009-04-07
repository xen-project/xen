#include <asm/debugger.h>
#include <asm/vhpt.h>
#include <public/arch-ia64.h>
#include <asm/config.h>
/*
 * arch/ia64/kernel/ivt.S
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
 * 00/08/23 Asit Mallick <asit.k.mallick@intel.com> TLB handling for SMP
 * 00/12/20 David Mosberger-Tang <davidm@hpl.hp.com> DTLB/ITLB handler now
 * uses virtual PT.
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
#include <xen/errno.h>
#include <linux/efi.h>

#if 1
# define PSR_DEFAULT_BITS	psr.ac
#else
# define PSR_DEFAULT_BITS	0
#endif

#if 0
  /*
   * This lets you track the last eight faults that occurred on the CPU.
   * Make sure ar.k2 isn't needed for something else before enabling this...
   */
# define DBG_FAULT(i)		\
	mov r16=ar.k2;;		\
	shl r16=r16,8;;		\
	add r16=(i),r16;;	\
	mov ar.k2=r16
#else
# define DBG_FAULT(i)
#endif

#define MINSTATE_VIRT	/* needed by minstate.h */
#include "minstate.h"

#define FAULT(n)							\
	mov r19=n;		/* prepare to save predicates */	\
	mov r31=pr;							\
	br.sptk.many dispatch_to_fault_handler

#define FAULT_OR_REFLECT(n)						\
	mov r20=cr.ipsr;						\
	mov r19=n;		/* prepare to save predicates */	\
	mov r31=pr;;	 	 					\
	extr.u r20=r20,IA64_PSR_CPL0_BIT,2;;   				\
	cmp.ne p6,p0=r0,r20; 	/* cpl != 0?*/				\
(p6)	br.dptk.many dispatch_reflection;				\
	br.sptk.few dispatch_to_fault_handler

	.section .text.ivt,"ax"

	.align 32768	// align on 32KB boundary
	.global ia64_ivt
ia64_ivt:
//////////////////////////////////////////////////////////////////////////
// 0x0000 Entry 0 (size 64 bundles) VHPT Translation (8,20,47)
ENTRY(vhpt_miss)
	DBG_FAULT(0)
	FAULT(0)
END(vhpt_miss)

	.org ia64_ivt+0x400
//////////////////////////////////////////////////////////////////////////
// 0x0400 Entry 1 (size 64 bundles) ITLB (21)
ENTRY(itlb_miss)
	DBG_FAULT(1)
	mov r16 = cr.ifa
	mov r31 = pr
	;;
	extr.u r17=r16,59,5
	;;
	/* If address belongs to VMM, go to alt tlb handler */
	cmp.eq p6,p0=0x1e,r17
(p6)	br.cond.spnt	late_alt_itlb_miss
	br.cond.sptk fast_tlb_miss_reflect
	;;
END(itlb_miss)

	.org ia64_ivt+0x0800
//////////////////////////////////////////////////////////////////////////
// 0x0800 Entry 2 (size 64 bundles) DTLB (9,48)
ENTRY(dtlb_miss)
	DBG_FAULT(2)
	mov r16=cr.ifa			// get virtual address
	mov r31=pr
	;;
	extr.u r17=r16,59,5
	;;
	/* If address belongs to VMM, go to alt tlb handler */
	cmp.eq p6,p0=0x1e,r17
(p6)	br.cond.spnt	late_alt_dtlb_miss
	br.cond.sptk fast_tlb_miss_reflect
	;;
END(dtlb_miss)

	.org ia64_ivt+0x0c00
//////////////////////////////////////////////////////////////////////////
// 0x0c00 Entry 3 (size 64 bundles) Alt ITLB (19)
ENTRY(alt_itlb_miss)
	DBG_FAULT(3)
	mov r16=cr.ifa		// get address that caused the TLB miss
	mov r31=pr
	;;
late_alt_itlb_miss:
	mov r21=cr.ipsr
	movl r17=PAGE_KERNEL
	movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
	;;
	mov r20=cr.itir
	extr.u r23=r21,IA64_PSR_CPL0_BIT,2	// extract psr.cpl
	and r19=r19,r16		// clear ed, reserved bits, and PTE ctrl bits
	extr.u r18=r16,XEN_VIRT_UC_BIT,1	// extract UC bit
	;;
	cmp.ne p8,p0=r0,r23	// psr.cpl != 0?
	or r19=r17,r19		// insert PTE control bits into r19
	dep r20=0,r20,IA64_ITIR_KEY,IA64_ITIR_KEY_LEN	// clear the key 
	;;
	dep r19=r18,r19,4,1	// set bit 4 (uncached) if access to UC area.
	mov cr.itir=r20		// set itir with cleared key
(p8)	br.cond.spnt page_fault
	;;
	itc.i r19		// insert the TLB entry
	mov pr=r31,-1
	rfi
END(alt_itlb_miss)

	.org ia64_ivt+0x1000
//////////////////////////////////////////////////////////////////////////
// 0x1000 Entry 4 (size 64 bundles) Alt DTLB (7,46)
ENTRY(alt_dtlb_miss)
	DBG_FAULT(4)
	mov r16=cr.ifa		// get address that caused the TLB miss
	mov r31=pr
	;;
late_alt_dtlb_miss:
	mov r20=cr.isr
	movl r17=PAGE_KERNEL
	mov r29=cr.ipsr // frametable_miss is shared by paravirtual and HVM sides
			// and it assumes ipsr is saved in r29. If change the
			// registers usage here, please check both sides!   
	movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
	;;
	extr.u r23=r29,IA64_PSR_CPL0_BIT,2	// extract psr.cpl
	and r22=IA64_ISR_CODE_MASK,r20		// get the isr.code field
	tbit.nz p6,p7=r20,IA64_ISR_SP_BIT	// is speculation bit on?
	extr.u r18=r16,XEN_VIRT_UC_BIT,1	// extract UC bit
	and r19=r19,r16				// clear ed, reserved bits, and
						//   PTE control bits
	tbit.nz p9,p0=r20,IA64_ISR_NA_BIT	// is non-access bit on?
	;;
	cmp.ne p8,p0=r0,r23
(p9)	cmp.eq.or.andcm p6,p7=IA64_ISR_CODE_LFETCH,r22	// check isr.code field
(p8)	br.cond.spnt page_fault
	;;
	mov r20=cr.itir
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
	shr r22=r16,56	 	// Test for the address of virtual frame_table
	;;
	cmp.eq p8,p0=((VIRT_FRAME_TABLE_ADDR>>56)&0xff)-0x100,r22
(p8)	br.cond.sptk frametable_miss ;;
#endif
	//    !( (r22 == 0x18 && rr6 == XEN_EFI_RR6) ||
	//	 (r22 == 0x1c && rr7 == XEN_EFI_RR7) ||
	//	 r22 == 0x1e)

	extr.u r22=r16,59,5
	;;
	dep r20=0,r20,IA64_ITIR_KEY,IA64_ITIR_KEY_LEN	// clear the key
	movl r24=6 << 61
	movl r23=7 << 61
	;;
	mov r24=rr[r24]
	mov r23=rr[r23]
	;;
	movl r26=XEN_EFI_RR6
	movl r25=XEN_EFI_RR7

	cmp.eq p8,p0=0x18,r22		// 0xc...
	cmp.eq p9,p0=0x1c,r22		// 0xe...
	;;
	cmp.eq.and p8,p0=r26,r24	// rr6 == XEN_EFI_RR6
	cmp.eq.and p9,p0=r25,r23	// rr7 == XEN_EFI_RR7
	;;
	cmp.eq.or p9,p0=0x1e,r22	// 0xf...
(p8)	br.cond.spnt alt_dtlb_miss_identity_map
(p9)	br.cond.spnt alt_dtlb_miss_identity_map
	br.cond.spnt page_fault
	;;
alt_dtlb_miss_identity_map:
	dep r29=-1,r29,IA64_PSR_ED_BIT,1
	or r19=r19,r17		// insert PTE control bits into r19
	mov cr.itir=r20		// set itir with cleared key
	;;
	cmp.ne p8,p0=r0,r18		// Xen UC bit set
	;;
	cmp.eq.or p8,p0=0x18,r22	// Region 6 is UC for EFI
	;;
(p8)	dep r19=-1,r19,4,1	// set bit 4 (uncached) if access to UC area
(p6)	mov cr.ipsr=r29
	;;
(p7)	itc.d r19		// insert the TLB entry
	mov pr=r31,-1
	rfi
END(alt_dtlb_miss)

#ifdef CONFIG_VIRTUAL_FRAME_TABLE	
GLOBAL_ENTRY(frametable_miss)
	rsm psr.dt		// switch to using physical data addressing
	movl r24=(frametable_pg_dir-PAGE_OFFSET)  // r24=__pa(frametable_pg_dir)
	;;
	srlz.d
	extr.u r17=r16,PGDIR_SHIFT,(PAGE_SHIFT-3)
	;;
	shladd r24=r17,3,r24	// r24=&pgd[pgd_offset(addr)]
	;;
	ld8 r24=[r24]		// r24=pgd[pgd_offset(addr)]
	extr.u r18=r16,PMD_SHIFT,(PAGE_SHIFT-3)	// r18=pmd_offset
	;;
	cmp.eq p6,p7=0,r24	// pgd present?
	shladd r24=r18,3,r24	// r24=&pmd[pmd_offset(addr)]
	;;
(p7)	ld8 r24=[r24]		// r24=pmd[pmd_offset(addr)]
	extr.u r19=r16,PAGE_SHIFT,(PAGE_SHIFT-3)// r19=pte_offset
(p6)	br.spnt.few frametable_fault
	;;
	cmp.eq p6,p7=0,r24	// pmd present?
	shladd r24=r19,3,r24	// r24=&pte[pte_offset(addr)]
	;;
(p7)	ld8 r24=[r24]		// r24=pte[pte_offset(addr)]
	mov r25=(PAGE_SHIFT<<IA64_ITIR_PS)
(p6)	br.spnt.few frametable_fault
	;;
	mov cr.itir=r25
	ssm psr.dt		// switch to using virtual data addressing
	tbit.z p6,p7=r24,_PAGE_P_BIT	// pte present? 
	;;
(p7)	itc.d r24		// install updated PTE
(p6)	br.spnt.few frametable_fault	// page present bit cleared?
	;;
	mov pr=r31,-1		// restore predicate registers
	rfi
END(frametable_miss)

ENTRY(frametable_fault)		//ipsr saved in r29 before coming here!
	ssm psr.dt		// switch to using virtual data addressing
	mov r18=cr.iip
	movl r19=ia64_frametable_probe
	;;
	cmp.eq p6,p7=r18,r19	// is faulting addrress ia64_frametable_probe?
	mov r8=0		// assumes that 'probe.r' uses r8
	dep r29=-1,r29,IA64_PSR_RI_BIT+1,1 // return to next instruction in
					   //   bundle 2
	;;
(p6)	mov cr.ipsr=r29
	mov r19=4		// FAULT(4)
(p7)	br.spnt.few dispatch_to_fault_handler
	;;
	mov pr=r31,-1
	rfi
END(frametable_fault)

GLOBAL_ENTRY(ia64_frametable_probe)
	{
	probe.r	r8=r32,0	// destination register must be r8
	nop.f 0x0
	br.ret.sptk.many b0	// this instruction must be in bundle 2
	}
END(ia64_frametable_probe)
#endif /* CONFIG_VIRTUAL_FRAME_TABLE */

	.org ia64_ivt+0x1400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1400 Entry 5 (size 64 bundles) Data nested TLB (6,45)
ENTRY(nested_dtlb_miss)
	DBG_FAULT(5)
	mov b0=r30
	br.sptk.many b0			// return to the continuation point
	;;
END(nested_dtlb_miss)

GLOBAL_ENTRY(dispatch_reflection)
	/*
	 * Input:
	 *	psr.ic:	off
	 *	r19:	intr type (offset into ivt, see ia64_int.h)
	 *	r31:	contains saved predicates (pr)
	 */
	SAVE_MIN_WITH_COVER_R19
	alloc r14=ar.pfs,0,0,5,0
	mov out4=r15
	mov out0=cr.ifa
	adds out1=16,sp
	mov out2=cr.isr
	mov out3=cr.iim

	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i				// guarantee that interruption 
					//   collection is on
	;;
(p15)	ssm psr.i			// restore psr.i
	adds r3=8,r2			// set up second base pointer
	;;
	SAVE_REST
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
//	br.sptk.many ia64_prepare_handle_reflection // TODO: why commented out?
    	br.call.sptk.many b6=ia64_handle_reflection
END(dispatch_reflection)

	.org ia64_ivt+0x1800
//////////////////////////////////////////////////////////////////////////
// 0x1800 Entry 6 (size 64 bundles) Instruction Key Miss (24)
ENTRY(ikey_miss)
	DBG_FAULT(6)
	FAULT_OR_REFLECT(6)
END(ikey_miss)

	//----------------------------------------------------------------
	// call do_page_fault (predicates are in r31, psr.dt may be off, 
	// r16 is faulting address)
GLOBAL_ENTRY(page_fault)
	ssm psr.dt
	;;
	srlz.i
	;;
	SAVE_MIN_WITH_COVER
	alloc r15=ar.pfs,0,0,4,0
	mov out0=cr.ifa
	mov out1=cr.isr
	mov out3=cr.itir
	adds r3=8,r2			// set up second base pointer
	;;
	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i				// guarantee that interruption 
					//   collection is on
	;;
(p15)	ssm psr.i			// restore psr.i
	movl r14=ia64_leave_kernel
	;;
	SAVE_REST
	mov rp=r14
	;;
	adds out2=16,r12		// out2 = pointer to pt_regs
	br.call.sptk.many b6=ia64_do_page_fault	// ignore return address
END(page_fault)

	.org ia64_ivt+0x1c00
//////////////////////////////////////////////////////////////////////////
// 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
ENTRY(dkey_miss)
	DBG_FAULT(7)
	FAULT_OR_REFLECT(7)
END(dkey_miss)

	.org ia64_ivt+0x2000
//////////////////////////////////////////////////////////////////////////
// 0x2000 Entry 8 (size 64 bundles) Dirty-bit (54)
ENTRY(dirty_bit)
	DBG_FAULT(8)
	mov r20=cr.ipsr
	mov r31=pr
	;;
	extr.u r20=r20,IA64_PSR_CPL0_BIT,2
	;;
	mov r19=8			// prepare to save predicates
	cmp.eq p6,p0=r0,r20 		// cpl == 0?
(p6)	br.sptk.few dispatch_to_fault_handler
	// If shadow mode is not enabled, reflect the fault.
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET
	;;
	ld8 r22=[r22]
	;;
	add r22=IA64_VCPU_SHADOW_BITMAP_OFFSET,r22
	;;
	ld8 r22=[r22]
	;;
	cmp.eq p6,p0=r0,r22 		// !shadow_bitmap ?
(p6)	br.dptk.many dispatch_reflection

	SAVE_MIN_WITH_COVER
	alloc r14=ar.pfs,0,0,4,0
	mov out0=cr.ifa
	mov out1=cr.itir
	mov out2=cr.isr
	adds out3=16,sp

	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i				// guarantee that interruption 
					//   collection is on
	;;
(p15)	ssm psr.i			// restore psr.i
	adds r3=8,r2			// set up second base pointer
	;;
	SAVE_REST
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
	br.call.sptk.many b6=ia64_shadow_fault
END(dirty_bit)

	.org ia64_ivt+0x2400
//////////////////////////////////////////////////////////////////////////
// 0x2400 Entry 9 (size 64 bundles) Instruction Access-bit (27)
ENTRY(iaccess_bit)
	DBG_FAULT(9)
	mov r16=cr.isr
	mov r17=cr.ifa
	mov r31=pr
	mov r19=9
	mov r20=0x2400
	br.sptk.many fast_access_reflect;;
END(iaccess_bit)

	.org ia64_ivt+0x2800
//////////////////////////////////////////////////////////////////////////
// 0x2800 Entry 10 (size 64 bundles) Data Access-bit (15,55)
ENTRY(daccess_bit)
	DBG_FAULT(10)
	mov r16=cr.isr
	mov r17=cr.ifa
	mov r18=cr.ipsr
	mov r31=pr
	mov r19=10
	;;
	mov r20=0x2800
	extr.u r18=r18,IA64_PSR_CPL0_BIT,2
	;;
	cmp.ne p6,p0=r0,r18 	/* cpl != 0? */
(p6)	br.sptk.many fast_access_reflect
	/* __domain_get_bundle() may cause this fault. */
	br.sptk.few dispatch_to_fault_handler
	;;
END(daccess_bit)

	.org ia64_ivt+0x2c00
//////////////////////////////////////////////////////////////////////////
// 0x2c00 Entry 11 (size 64 bundles) Break instruction (33)
ENTRY(break_fault)
	.body
	/*
	 * The streamlined system call entry/exit paths only save/restore 
	 * the initial part of pt_regs.  This implies that the callers of
	 * system-calls must adhere to the normal procedure calling 
	 * conventions.
	 *
	 *   Registers to be saved & restored:
	 *	CR registers: cr.ipsr, cr.iip, cr.ifs
	 *	AR registers: ar.unat, ar.pfs, ar.rsc, ar.rnat, ar.bspstore,
	 *		      ar.fpsr
	 * 	others: pr, b0, b6, loadrs, r1, r11, r12, r13, r15
	 *   Registers to be restored only:
	 * 	r8-r11: output value from the system call.
	 *
	 * During system call exit, scratch registers (including r15) are
	 * modified/cleared to prevent leaking bits from kernel to user 
	 * level.
	 */
	DBG_FAULT(11)
	mov r16=cr.isr
	mov r17=cr.iim
	mov r31=pr
	;;
	cmp.eq p7,p0=r17,r0
(p7)	br.spnt.few dispatch_break_fault
	;;
#ifdef CRASH_DEBUG
        // A panic can occur before domain0 is created.  In such cases, 
	// referencing XSI_PSR_IC causes nested_dtlb_miss.
        movl r18=CDB_BREAK_NUM
	;;
        cmp.eq p7,p0=r17,r18
	;; 
(p7)    br.spnt.few dispatch_break_fault
	;;
#endif
	movl r18=THIS_CPU(current_psr_ic_addr)
	;;
	ld8 r18=[r18]    
	;;
#ifdef CONFIG_PRIVIFY
	// pseudo-cover are replaced by break.b which (unfortunatly) always
	// clear iim.
	cmp.eq p7,p0=r0,r17
(p7)	br.spnt.many dispatch_privop_fault
	;;
#endif
	// if (ipsr.cpl == CONFIG_CPL0_EMUL &&
	//    (iim - HYPERPRIVOP_START) < HYPERPRIVOP_MAX)
	// this is a hyperprivop. A hyperprivop is hand-coded assembly with
	// psr.ic off which means it can make no calls, cannot use r1-r15,
	// and it can have no memory accesses unless they are to pinned
	// addresses!
	mov r19= cr.ipsr
	mov r20=HYPERPRIVOP_START
	mov r21=HYPERPRIVOP_MAX
	;;
	sub r20=r17,r20
	extr.u r19=r19,IA64_PSR_CPL0_BIT,2  // extract cpl field from cr.ipsr
	;;
	cmp.gtu p7,p0=r21,r20
	;;
	cmp.eq.and p7,p0=CONFIG_CPL0_EMUL,r19	// ipsr.cpl==CONFIG_CPL0_EMUL
(p7)	br.sptk.many fast_hyperprivop
	;;
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET
	;;
	ld8 r22 = [r22]
	;;
	adds r23=IA64_VCPU_BREAKIMM_OFFSET,r22
	;;
	ld4 r23=[r23];;
	cmp4.eq p6,p0=r23,r17;;			// Xen-reserved breakimm?
	cmp.eq.and p6,p0=CONFIG_CPL0_EMUL,r19        
(p6)	br.spnt.many fast_hypercall
	;;
	br.sptk.many fast_break_reflect
	;;


fast_hypercall:
	shr r25=r2,8;;
	cmp.ne p7,p0=r0,r25
(p7)	br.spnt.few dispatch_break_fault
	;;
	// fall through
   

	/*
	 * The streamlined system call entry/exit paths only save/restore the initial part
	 * of pt_regs.  This implies that the callers of system-calls must adhere to the
	 * normal procedure calling conventions.
	 *
	 *   Registers to be saved & restored:
	 *	CR registers: cr.ipsr, cr.iip, cr.ifs
	 *	AR registers: ar.unat, ar.pfs, ar.rsc, ar.rnat, ar.bspstore, ar.fpsr
	 * 	others: pr, b0, b6, loadrs, r1, r11, r12, r13, r15
	 *   Registers to be restored only:
	 * 	r8-r11: output value from the system call.
	 *
	 * During system call exit, scratch registers (including r15) are modified/cleared
	 * to prevent leaking bits from kernel to user level.
	 */
    
//	DBG_FAULT(11)
//	mov.m r16=IA64_KR(CURRENT)		// M2 r16 <- current task (12 cyc)
	mov r16=r22
	mov r29=cr.ipsr				// M2 (12 cyc)
//	mov r31=pr				// I0 (2 cyc)
	mov r15=r2

//	mov r17=cr.iim				// M2 (2 cyc)
	mov.m r27=ar.rsc			// M2 (12 cyc)
//	mov r18=__IA64_BREAK_SYSCALL		// A

	mov.m ar.rsc=0				// M2
	mov.m r21=ar.fpsr			// M2 (12 cyc)
	mov r19=b6				// I0 (2 cyc)
	;;
	mov.m r23=ar.bspstore			// M2 (12 cyc)
	mov.m r24=ar.rnat			// M2 (5 cyc)
	mov.i r26=ar.pfs			// I0 (2 cyc)

	invala					// M0|1
	nop.m 0					// M
	mov r20=r1				// A			save r1

	nop.m 0
//	movl r30=sys_call_table			// X
	movl r30=ia64_hypercall_table			// X

	mov r28=cr.iip				// M2 (2 cyc)
//	cmp.eq p0,p7=r18,r17			// I0 is this a system call?
//(p7)	br.cond.spnt non_syscall		// B  no ->
	//
	// From this point on, we are definitely on the syscall-path
	// and we can use (non-banked) scratch registers.
	//
///////////////////////////////////////////////////////////////////////
	mov r1=r16				// A    move task-pointer to "addl"-addressable reg
	mov r2=r16				// A    setup r2 for ia64_syscall_setup
//	add r9=TI_FLAGS+IA64_TASK_SIZE,r16	// A	r9 = &current_thread_info()->flags

	adds r16=IA64_TASK_THREAD_ON_USTACK_OFFSET,r16
//	adds r15=-1024,r15			// A    subtract 1024 from syscall number
//	mov r3=NR_syscalls - 1
	mov r3=NR_hypercalls - 1
	;;
	ld1.bias r17=[r16]			// M0|1 r17 = current->thread.on_ustack flag
//	ld4 r9=[r9]				// M0|1 r9 = current_thread_info()->flags
	mov r9=r0               // force flags = 0
	extr.u r8=r29,41,2			// I0   extract ei field from cr.ipsr

	shladd r30=r15,3,r30			// A    r30 = sys_call_table + 8*(syscall-1024)
	addl r22=IA64_RBS_OFFSET,r1		// A    compute base of RBS
	cmp.leu p6,p7=r15,r3			// A    syscall number in range?
	;;

	lfetch.fault.excl.nt1 [r22]		// M0|1 prefetch RBS
(p6)	ld8 r30=[r30]				// M0|1 load address of syscall entry point
	tnat.nz.or p7,p0=r15			// I0	is syscall nr a NaT?

	mov.m ar.bspstore=r22			// M2   switch to kernel RBS
	cmp.eq p8,p9=2,r8			// A    isr.ei==2?
	;;

(p8)	mov r8=0				// A    clear ei to 0
//(p7)	movl r30=sys_ni_syscall			// X
(p7)	movl r30=do_ni_hypercall			// X

(p8)	adds r28=16,r28				// A    switch cr.iip to next bundle
(p9)	adds r8=1,r8				// A    increment ei to next slot
	nop.i 0
	;;

	mov.m r25=ar.unat			// M2 (5 cyc)
	dep r29=r8,r29,41,2			// I0   insert new ei into cr.ipsr
//	adds r15=1024,r15			// A    restore original syscall number
	//
	// If any of the above loads miss in L1D, we'll stall here until
	// the data arrives.
	//
///////////////////////////////////////////////////////////////////////
	st1 [r16]=r0				// M2|3 clear current->thread.on_ustack flag
	mov b6=r30				// I0   setup syscall handler branch reg early
	cmp.eq pKStk,pUStk=r0,r17		// A    were we on kernel stacks already?

//	and r9=_TIF_SYSCALL_TRACEAUDIT,r9	// A    mask trace or audit
	mov r18=ar.bsp				// M2 (12 cyc)
	;;
(pUStk)	addl r1=IA64_STK_OFFSET-IA64_PT_REGS_SIZE,r1 // A    compute base of memory stack
//	cmp.eq p14,p0=r9,r0			// A    are syscalls being traced/audited?
	br.call.sptk.many b7=ia64_syscall_setup	// B
1:
	mov ar.rsc=0x3				// M2   set eager mode, pl 0, LE, loadrs=0
	nop 0
	bsw.1					// B (6 cyc) regs are saved, switch to bank 1
	;;

	PT_REGS_UNWIND_INFO(-48)
	ssm psr.ic | PSR_DEFAULT_BITS		// M2	now it's safe to re-enable intr.-collection
//	movl r3=ia64_ret_from_syscall		// X
	;;

	srlz.i					// M0   ensure interruption collection is on
//	mov rp=r3				// I0   set the real return addr
//(p10)	br.cond.spnt.many ia64_ret_from_syscall	// B    return if bad call-frame or r15 is a NaT
(p15)	ssm psr.i				// M2   restore psr.i
//(p14)	br.call.sptk.many b6=b6			// B    invoke syscall-handker (ignore return addr)
//	br.call.sptk.many b6=b6			// B    invoke syscall-handker (ignore return addr)
	br.call.sptk.many b0=b6			// B    invoke syscall-handker (ignore return addr)
//	br.cond.spnt.many ia64_trace_syscall	// B	do syscall-tracing thingamagic
	;;
	adds r2=PT(R8)+16,r12
	;;
	st8 [r2]=r8
	;;
	br.call.sptk.many b0=do_softirq
	;;
	//restore hypercall argument if continuation
	adds r2=IA64_VCPU_HYPERCALL_CONTINUATION_OFS,r13
	;;
	ld1 r20=[r2]
	;;
	st1 [r2]=r0
	;;
	cmp.ne p6,p0=r20,r0
	;;
(p6)	adds r2=PT(R16)+16,r12
(p6)	adds r3=PT(R17)+16,r12
	;;
(p6)	ld8 r32=[r2],16
(p6)	ld8 r33=[r3],16
	;;
(p6)	ld8 r34=[r2],16
(p6)	ld8 r35=[r3],16
	;;
(p6)	ld8 r36=[r2],16
	;;
//save ar.bsp before cover
	mov r16=ar.bsp
	add r2=PT(R14)+16,r12
	;;
	st8 [r2]=r16
	;;
	rsm psr.i|psr.ic
	;;
	srlz.i
	;;
	cover
	;;
	mov r20=cr.ifs    
	adds r2=PT(CR_IFS)+16,r12
	;;
	st8 [r2]=r20
	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i
	;;
	br.call.sptk.many b0=reflect_event
	;;
	rsm psr.i|psr.ic
	adds r2=PT(R14)+16,r12
	adds r3=PT(R8)+16,r12
	;;
	//r16 contains ar.bsp before cover
	ld8 r16=[r2]
	ld8 r8=[r3]
	srlz.i
	;;
	br.sptk.many ia64_ret_from_syscall
	;;
END(break_fault)

	.org ia64_ivt+0x3000
//////////////////////////////////////////////////////////////////////////
// 0x3000 Entry 12 (size 64 bundles) External Interrupt (4)
ENTRY(interrupt)
	DBG_FAULT(12)
	mov r31=pr		// prepare to save predicates
	mov r30=cr.ivr		// pass cr.ivr as first arg
	// FIXME: this is a hack... use cpuinfo.ksoftirqd because its
	// not used anywhere else and we need a place to stash ivr and
	// there's no registers available unused by SAVE_MIN/REST
	movl r29=THIS_CPU(cpu_info)+IA64_CPUINFO_KSOFTIRQD_OFFSET
	;;
	st8 [r29]=r30
	movl r28=slow_interrupt
	;;
	mov r29=rp
	;;
	mov rp=r28
	;;
	br.cond.sptk.many fast_tick_reflect
	;;
slow_interrupt:
	mov rp=r29;;
	SAVE_MIN_WITH_COVER	// uses r31; defines r2 and r3
	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	adds r3=8,r2		// set up second base pointer for SAVE_REST
	srlz.i			// ensure everybody knows psr.ic is back on
	;;
	SAVE_REST
	;;
	alloc r14=ar.pfs,0,0,2,0 // must be first in an insn group
	movl out0=THIS_CPU(cpu_info)+IA64_CPUINFO_KSOFTIRQD_OFFSET;;
	ld8 out0=[out0];;
	add out1=16,sp		// pass pointer to pt_regs as second arg
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
	br.call.sptk.many b6=ia64_handle_irq
END(interrupt)

	.org ia64_ivt+0x3400
//////////////////////////////////////////////////////////////////////////
// 0x3400 Entry 13 (size 64 bundles) Reserved
	DBG_FAULT(13)
	FAULT(13)

	// There is no particular reason for this code to be here, other
	// than that there happens to be space here that would go unused 
	// otherwise.  If this fault ever gets "unreserved", simply move
	// the following code to a more suitable spot...

GLOBAL_ENTRY(dispatch_break_fault)
	SAVE_MIN_WITH_COVER
	;;
dispatch_break_fault_post_save:
	alloc r14=ar.pfs,0,0,4,0 // now it's safe (must be first in insn group!)
	mov out0=cr.ifa
	adds out1=16,sp
	mov out2=cr.isr		// FIXME: pity to make this slow access twice
	mov out3=cr.iim		// FIXME: pity to make this slow access twice

	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i			// guarantee that interruption collection is on
	;;
(p15)	ssm psr.i		// restore psr.i
	adds r3=8,r2		// set up second base pointer
	;;
	SAVE_REST
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
    	br.call.sptk.many b6=ia64_handle_break
END(dispatch_break_fault)

	.org ia64_ivt+0x3800
//////////////////////////////////////////////////////////////////////////
// 0x3800 Entry 14 (size 64 bundles) Reserved
	DBG_FAULT(14)
	FAULT(14)

    // this code segment is from 2.6.16.13
    
	/*
	 * There is no particular reason for this code to be here, other than that
	 * there happens to be space here that would go unused otherwise.  If this
	 * fault ever gets "unreserved", simply moved the following code to a more
	 * suitable spot...
	 *
	 * ia64_syscall_setup() is a separate subroutine so that it can
	 *	allocate stacked registers so it can safely demine any
	 *	potential NaT values from the input registers.
	 *
	 * On entry:
	 *	- executing on bank 0 or bank 1 register set (doesn't matter)
	 *	-  r1: stack pointer
	 *	-  r2: current task pointer
	 *	-  r3: preserved
	 *	- r11: original contents (saved ar.pfs to be saved)
	 *	- r12: original contents (sp to be saved)
	 *	- r13: original contents (tp to be saved)
	 *	- r15: original contents (syscall # to be saved)
	 *	- r18: saved bsp (after switching to kernel stack)
	 *	- r19: saved b6
	 *	- r20: saved r1 (gp)
	 *	- r21: saved ar.fpsr
	 *	- r22: kernel's register backing store base (krbs_base)
	 *	- r23: saved ar.bspstore
	 *	- r24: saved ar.rnat
	 *	- r25: saved ar.unat
	 *	- r26: saved ar.pfs
	 *	- r27: saved ar.rsc
	 *	- r28: saved cr.iip
	 *	- r29: saved cr.ipsr
	 *	- r31: saved pr
	 *	-  b0: original contents (to be saved)
	 * On exit:
	 *	-  p10: TRUE if syscall is invoked with more than 8 out
	 *		registers or r15's Nat is true
	 *	-  r1: kernel's gp
	 *	-  r3: preserved (same as on entry)
	 *	-  r8: -EINVAL if p10 is true
	 *	- r12: points to kernel stack
	 *	- r13: points to current task
	 *	- r14: preserved (same as on entry)
	 *	- p13: preserved
	 *	- p15: TRUE if interrupts need to be re-enabled
	 *	- ar.fpsr: set to kernel settings
	 *	-  b6: preserved (same as on entry)
	 */
GLOBAL_ENTRY(ia64_syscall_setup)
#if PT(B6) != 0
# error This code assumes that b6 is the first field in pt_regs.
#endif
	st8 [r1]=r19				// save b6
	add r16=PT(CR_IPSR),r1			// initialize first base pointer
	add r17=PT(R11),r1			// initialize second base pointer
	;;
	alloc r19=ar.pfs,8,0,0,0		// ensure in0-in7 are writable
	st8 [r16]=r29,PT(AR_PFS)-PT(CR_IPSR)	// save cr.ipsr
	tnat.nz p8,p0=in0

	st8.spill [r17]=r11,PT(CR_IIP)-PT(R11)	// save r11
	tnat.nz p9,p0=in1
(pKStk)	mov r18=r0				// make sure r18 isn't NaT
	;;

	st8 [r16]=r26,PT(CR_IFS)-PT(AR_PFS)	// save ar.pfs
	st8 [r17]=r28,PT(AR_UNAT)-PT(CR_IIP)	// save cr.iip
	mov r28=b0				// save b0 (2 cyc)
	;;

	st8 [r17]=r25,PT(AR_RSC)-PT(AR_UNAT)	// save ar.unat
	dep r19=0,r19,38,26			// clear all bits but 0..37 [I0]
(p8)	mov in0=-1
	;;

	st8 [r16]=r19,PT(AR_RNAT)-PT(CR_IFS)	// store ar.pfs.pfm in cr.ifs
	extr.u r11=r19,7,7	// I0		// get sol of ar.pfs
	and r8=0x7f,r19		// A		// get sof of ar.pfs

	st8 [r17]=r27,PT(AR_BSPSTORE)-PT(AR_RSC)// save ar.rsc
	tbit.nz p15,p0=r29,IA64_PSR_I_BIT // I0
(p9)	mov in1=-1
	;;

(pUStk) sub r18=r18,r22				// r18=RSE.ndirty*8
	tnat.nz p10,p0=in2
	add r11=8,r11
	;;
(pKStk) adds r16=PT(PR)-PT(AR_RNAT),r16		// skip over ar_rnat field
(pKStk) adds r17=PT(B0)-PT(AR_BSPSTORE),r17	// skip over ar_bspstore field
	tnat.nz p11,p0=in3
	;;
(p10)	mov in2=-1
	tnat.nz p12,p0=in4				// [I0]
(p11)	mov in3=-1
	;;
(pUStk) st8 [r16]=r24,PT(PR)-PT(AR_RNAT)	// save ar.rnat
(pUStk) st8 [r17]=r23,PT(B0)-PT(AR_BSPSTORE)	// save ar.bspstore
	shl r18=r18,16				// compute ar.rsc to be used for "loadrs"
	;;
	st8 [r16]=r31,PT(LOADRS)-PT(PR)		// save predicates
	st8 [r17]=r28,PT(R1)-PT(B0)		// save b0
	tnat.nz p13,p0=in5				// [I0]
	;;
	st8 [r16]=r18,PT(R12)-PT(LOADRS)	// save ar.rsc value for "loadrs"
	st8.spill [r17]=r20,PT(R13)-PT(R1)	// save original r1
(p12)	mov in4=-1
	;;

.mem.offset 0,0; st8.spill [r16]=r12,PT(AR_FPSR)-PT(R12)	// save r12
.mem.offset 8,0; st8.spill [r17]=r13,PT(R15)-PT(R13)		// save r13
(p13)	mov in5=-1
	;;
	st8 [r16]=r21,PT(R8)-PT(AR_FPSR)	// save ar.fpsr
	tnat.nz p13,p0=in6
	cmp.lt p10,p9=r11,r8	// frame size can't be more than local+8
	;;
	mov r8=1
(p9)	tnat.nz p10,p0=r15
	adds r12=-16,r1		// switch to kernel memory stack (with 16 bytes of scratch)

	st8.spill [r17]=r15			// save r15
	tnat.nz p8,p0=in7
	nop.i 0

	mov r13=r2				// establish `current'
	movl r1=__gp				// establish kernel global pointer
	;;
	st8 [r16]=r8		// ensure pt_regs.r8 != 0 (see handle_syscall_error)
(p13)	mov in6=-1
(p8)	mov in7=-1

	cmp.eq pSys,pNonSys=r0,r0		// set pSys=1, pNonSys=0
	movl r17=FPSR_DEFAULT
	;;
	mov.m ar.fpsr=r17			// set ar.fpsr to kernel default value
(p10)	mov r8=-EINVAL
	br.ret.sptk.many b7
END(ia64_syscall_setup)

	
	.org ia64_ivt+0x3c00
//////////////////////////////////////////////////////////////////////////
// 0x3c00 Entry 15 (size 64 bundles) Reserved
	DBG_FAULT(15)
	FAULT(15)


	.org ia64_ivt+0x4000
//////////////////////////////////////////////////////////////////////////
// 0x4000 Entry 16 (size 64 bundles) Reserved
	DBG_FAULT(16)
	FAULT(16)

	// There is no particular reason for this code to be here, other
	// than that there happens to be space here that would go unused 
	// otherwise.  If this fault ever gets "unreserved", simply move
	// the following code to a more suitable spot...

ENTRY(dispatch_privop_fault)
	SAVE_MIN_WITH_COVER
	;;
	alloc r14=ar.pfs,0,0,4,0	// now it's safe (must be first in
					//   insn group!)
	mov out0=cr.ifa
	adds out1=16,sp
	mov out2=cr.isr		// FIXME: pity to make this slow access twice
	mov out3=cr.itir

	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i				// guarantee that interruption 
					//   collection is on
	;;
(p15)	ssm psr.i			// restore psr.i
	adds r3=8,r2			// set up second base pointer
	;;
	SAVE_REST
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
     	br.call.sptk.many b6=ia64_handle_privop
END(dispatch_privop_fault)


	.org ia64_ivt+0x4400
//////////////////////////////////////////////////////////////////////////
// 0x4400 Entry 17 (size 64 bundles) Reserved
	DBG_FAULT(17)
	FAULT(17)


	.org ia64_ivt+0x4800
//////////////////////////////////////////////////////////////////////////
// 0x4800 Entry 18 (size 64 bundles) Reserved
	DBG_FAULT(18)
	FAULT(18)


	.org ia64_ivt+0x4c00
//////////////////////////////////////////////////////////////////////////
// 0x4c00 Entry 19 (size 64 bundles) Reserved
	DBG_FAULT(19)
	FAULT(19)

	/*
	 * There is no particular reason for this code to be here, other 
	 * than that there happens to be space here that would go unused 
	 * otherwise.  If this fault ever gets "unreserved", simply move
	 * the following code to a more suitable spot...
	 */

GLOBAL_ENTRY(dispatch_to_fault_handler)
	/*
	 * Input:
	 *	psr.ic:	off
	 *	r19:	fault vector number (e.g., 24 for General Exception)
	 *	r31:	contains saved predicates (pr)
	 */
	SAVE_MIN_WITH_COVER_R19
	alloc r14=ar.pfs,0,0,5,0
	mov out0=r15
	mov out1=cr.isr
	mov out2=cr.ifa
	mov out3=cr.iim
	mov out4=cr.itir
	;;
	ssm psr.ic | PSR_DEFAULT_BITS
	;;
	srlz.i				// guarantee that interruption 
					//   collection is on
	;;
(p15)	ssm psr.i			// restore psr.i
	adds r3=8,r2			// set up second base pointer for
					//   SAVE_REST
	;;
	SAVE_REST
	movl r14=ia64_leave_kernel
	;;
	mov rp=r14
	br.call.sptk.many b6=ia64_fault
END(dispatch_to_fault_handler)

//
// --- End of long entries, Beginning of short entries
//

	.org ia64_ivt+0x5000
//////////////////////////////////////////////////////////////////////////
// 0x5000 Entry 20 (size 16 bundles) Page Not Present (10,22,49)
ENTRY(page_not_present)
	DBG_FAULT(20)
	FAULT_OR_REFLECT(20)
END(page_not_present)

	.org ia64_ivt+0x5100
//////////////////////////////////////////////////////////////////////////
// 0x5100 Entry 21 (size 16 bundles) Key Permission (13,25,52)
ENTRY(key_permission)
	DBG_FAULT(21)
	FAULT_OR_REFLECT(21)
END(key_permission)

	.org ia64_ivt+0x5200
//////////////////////////////////////////////////////////////////////////
// 0x5200 Entry 22 (size 16 bundles) Instruction Access Rights (26)
ENTRY(iaccess_rights)
	DBG_FAULT(22)
	FAULT_OR_REFLECT(22)
END(iaccess_rights)

	.org ia64_ivt+0x5300
//////////////////////////////////////////////////////////////////////////
// 0x5300 Entry 23 (size 16 bundles) Data Access Rights (14,53)
ENTRY(daccess_rights)
	DBG_FAULT(23)
	mov r31=pr
	mov r16=cr.isr
	mov r17=cr.ifa
	mov r19=23
	mov r20=0x5300
	br.sptk.many fast_access_reflect
	;;
END(daccess_rights)

	.org ia64_ivt+0x5400
//////////////////////////////////////////////////////////////////////////
// 0x5400 Entry 24 (size 16 bundles) General Exception (5,32,34,36,38,39)
ENTRY(general_exception)
	DBG_FAULT(24)
	mov r16=cr.isr
	mov r31=pr
	;;
	cmp4.ge p6,p0=0x20,r16
(p6)	br.sptk.many dispatch_privop_fault
	;;
	FAULT_OR_REFLECT(24)
END(general_exception)

	.org ia64_ivt+0x5500
//////////////////////////////////////////////////////////////////////////
// 0x5500 Entry 25 (size 16 bundles) Disabled FP-Register (35)
ENTRY(disabled_fp_reg)
	DBG_FAULT(25)
	FAULT_OR_REFLECT(25)
END(disabled_fp_reg)

	.org ia64_ivt+0x5600
//////////////////////////////////////////////////////////////////////////
// 0x5600 Entry 26 (size 16 bundles) Nat Consumption (11,23,37,50)
ENTRY(nat_consumption)
	DBG_FAULT(26)
	FAULT_OR_REFLECT(26)
END(nat_consumption)

	.org ia64_ivt+0x5700
//////////////////////////////////////////////////////////////////////////
// 0x5700 Entry 27 (size 16 bundles) Speculation (40)
ENTRY(speculation_vector)
	DBG_FAULT(27)
	// this probably need not reflect...
	FAULT_OR_REFLECT(27)
END(speculation_vector)

	.org ia64_ivt+0x5800
//////////////////////////////////////////////////////////////////////////
// 0x5800 Entry 28 (size 16 bundles) Reserved
	DBG_FAULT(28)
	FAULT(28)

	.org ia64_ivt+0x5900
//////////////////////////////////////////////////////////////////////////
// 0x5900 Entry 29 (size 16 bundles) Debug (16,28,56)
ENTRY(debug_vector)
	DBG_FAULT(29)
	FAULT_OR_REFLECT(29)
END(debug_vector)

	.org ia64_ivt+0x5a00
//////////////////////////////////////////////////////////////////////////
// 0x5a00 Entry 30 (size 16 bundles) Unaligned Reference (57)
ENTRY(unaligned_access)
	DBG_FAULT(30)
	FAULT_OR_REFLECT(30)
END(unaligned_access)

	.org ia64_ivt+0x5b00
//////////////////////////////////////////////////////////////////////////
// 0x5b00 Entry 31 (size 16 bundles) Unsupported Data Reference (57)
ENTRY(unsupported_data_reference)
	DBG_FAULT(31)
	FAULT_OR_REFLECT(31)
END(unsupported_data_reference)

	.org ia64_ivt+0x5c00
//////////////////////////////////////////////////////////////////////////
// 0x5c00 Entry 32 (size 16 bundles) Floating-Point Fault (64)
ENTRY(floating_point_fault)
	DBG_FAULT(32)
	FAULT_OR_REFLECT(32)
END(floating_point_fault)

	.org ia64_ivt+0x5d00
//////////////////////////////////////////////////////////////////////////
// 0x5d00 Entry 33 (size 16 bundles) Floating Point Trap (66)
ENTRY(floating_point_trap)
	DBG_FAULT(33)
	FAULT_OR_REFLECT(33)
END(floating_point_trap)

	.org ia64_ivt+0x5e00
//////////////////////////////////////////////////////////////////////////
// 0x5e00 Entry 34 (size 16 bundles) Lower Privilege Transfer Trap (66)
ENTRY(lower_privilege_trap)
	DBG_FAULT(34)
	FAULT_OR_REFLECT(34)
END(lower_privilege_trap)

	.org ia64_ivt+0x5f00
//////////////////////////////////////////////////////////////////////////
// 0x5f00 Entry 35 (size 16 bundles) Taken Branch Trap (68)
ENTRY(taken_branch_trap)
	DBG_FAULT(35)
	FAULT_OR_REFLECT(35)
END(taken_branch_trap)

	.org ia64_ivt+0x6000
//////////////////////////////////////////////////////////////////////////
// 0x6000 Entry 36 (size 16 bundles) Single Step Trap (69)
ENTRY(single_step_trap)
	DBG_FAULT(36)
	FAULT_OR_REFLECT(36)
END(single_step_trap)

	.org ia64_ivt+0x6100
//////////////////////////////////////////////////////////////////////////
// 0x6100 Entry 37 (size 16 bundles) Reserved
	DBG_FAULT(37)
	FAULT(37)

	.org ia64_ivt+0x6200
//////////////////////////////////////////////////////////////////////////
// 0x6200 Entry 38 (size 16 bundles) Reserved
	DBG_FAULT(38)
	FAULT(38)

	.org ia64_ivt+0x6300
//////////////////////////////////////////////////////////////////////////
// 0x6300 Entry 39 (size 16 bundles) Reserved
	DBG_FAULT(39)
	FAULT(39)

	.org ia64_ivt+0x6400
//////////////////////////////////////////////////////////////////////////
// 0x6400 Entry 40 (size 16 bundles) Reserved
	DBG_FAULT(40)
	FAULT(40)

	.org ia64_ivt+0x6500
//////////////////////////////////////////////////////////////////////////
// 0x6500 Entry 41 (size 16 bundles) Reserved
	DBG_FAULT(41)
	FAULT(41)

	.org ia64_ivt+0x6600
//////////////////////////////////////////////////////////////////////////
// 0x6600 Entry 42 (size 16 bundles) Reserved
	DBG_FAULT(42)
	FAULT(42)

	.org ia64_ivt+0x6700
//////////////////////////////////////////////////////////////////////////
// 0x6700 Entry 43 (size 16 bundles) Reserved
	DBG_FAULT(43)
	FAULT(43)

	.org ia64_ivt+0x6800
//////////////////////////////////////////////////////////////////////////
// 0x6800 Entry 44 (size 16 bundles) Reserved
	DBG_FAULT(44)
	FAULT(44)

	.org ia64_ivt+0x6900
//////////////////////////////////////////////////////////////////////////
// 0x6900 Entry 45 (size 16 bundles) IA-32 Exeception (17,18,29,41,42,43,
//						       44,58,60,61,62,72,
//						       73,75,76,77)
ENTRY(ia32_exception)
	DBG_FAULT(45)
	FAULT_OR_REFLECT(45)
END(ia32_exception)

	.org ia64_ivt+0x6a00
//////////////////////////////////////////////////////////////////////////
// 0x6a00 Entry 46 (size 16 bundles) IA-32 Intercept  (30,31,59,70,71)
ENTRY(ia32_intercept)
	DBG_FAULT(46)
	FAULT_OR_REFLECT(46)
END(ia32_intercept)

	.org ia64_ivt+0x6b00
//////////////////////////////////////////////////////////////////////////
// 0x6b00 Entry 47 (size 16 bundles) IA-32 Interrupt  (74)
ENTRY(ia32_interrupt)
	DBG_FAULT(47)
	FAULT_OR_REFLECT(47)
END(ia32_interrupt)

	.org ia64_ivt+0x6c00
//////////////////////////////////////////////////////////////////////////
// 0x6c00 Entry 48 (size 16 bundles) Reserved
	DBG_FAULT(48)
	FAULT(48)

	.org ia64_ivt+0x6d00
//////////////////////////////////////////////////////////////////////////
// 0x6d00 Entry 49 (size 16 bundles) Reserved
	DBG_FAULT(49)
	FAULT(49)

	.org ia64_ivt+0x6e00
//////////////////////////////////////////////////////////////////////////
// 0x6e00 Entry 50 (size 16 bundles) Reserved
	DBG_FAULT(50)
	FAULT(50)

	.org ia64_ivt+0x6f00
//////////////////////////////////////////////////////////////////////////
// 0x6f00 Entry 51 (size 16 bundles) Reserved
	DBG_FAULT(51)
	FAULT(51)

	.org ia64_ivt+0x7000
//////////////////////////////////////////////////////////////////////////
// 0x7000 Entry 52 (size 16 bundles) Reserved
	DBG_FAULT(52)
	FAULT(52)

	.org ia64_ivt+0x7100
//////////////////////////////////////////////////////////////////////////
// 0x7100 Entry 53 (size 16 bundles) Reserved
	DBG_FAULT(53)
	FAULT(53)

	.org ia64_ivt+0x7200
//////////////////////////////////////////////////////////////////////////
// 0x7200 Entry 54 (size 16 bundles) Reserved
	DBG_FAULT(54)
	FAULT(54)

	.org ia64_ivt+0x7300
//////////////////////////////////////////////////////////////////////////
// 0x7300 Entry 55 (size 16 bundles) Reserved
	DBG_FAULT(55)
	FAULT(55)

	.org ia64_ivt+0x7400
//////////////////////////////////////////////////////////////////////////
// 0x7400 Entry 56 (size 16 bundles) Reserved
	DBG_FAULT(56)
	FAULT(56)

	.org ia64_ivt+0x7500
//////////////////////////////////////////////////////////////////////////
// 0x7500 Entry 57 (size 16 bundles) Reserved
	DBG_FAULT(57)
	FAULT(57)

	.org ia64_ivt+0x7600
//////////////////////////////////////////////////////////////////////////
// 0x7600 Entry 58 (size 16 bundles) Reserved
	DBG_FAULT(58)
	FAULT(58)

	.org ia64_ivt+0x7700
//////////////////////////////////////////////////////////////////////////
// 0x7700 Entry 59 (size 16 bundles) Reserved
	DBG_FAULT(59)
	FAULT(59)

	.org ia64_ivt+0x7800
//////////////////////////////////////////////////////////////////////////
// 0x7800 Entry 60 (size 16 bundles) Reserved
	DBG_FAULT(60)
	FAULT(60)

	.org ia64_ivt+0x7900
//////////////////////////////////////////////////////////////////////////
// 0x7900 Entry 61 (size 16 bundles) Reserved
	DBG_FAULT(61)
	FAULT(61)

	.org ia64_ivt+0x7a00
//////////////////////////////////////////////////////////////////////////
// 0x7a00 Entry 62 (size 16 bundles) Reserved
	DBG_FAULT(62)
	FAULT(62)

	.org ia64_ivt+0x7b00
//////////////////////////////////////////////////////////////////////////
// 0x7b00 Entry 63 (size 16 bundles) Reserved
	DBG_FAULT(63)
	FAULT(63)

	.org ia64_ivt+0x7c00
//////////////////////////////////////////////////////////////////////////
// 0x7c00 Entry 64 (size 16 bundles) Reserved
	DBG_FAULT(64)
	FAULT(64)

	.org ia64_ivt+0x7d00
//////////////////////////////////////////////////////////////////////////
// 0x7d00 Entry 65 (size 16 bundles) Reserved
	DBG_FAULT(65)
	FAULT(65)

	.org ia64_ivt+0x7e00
//////////////////////////////////////////////////////////////////////////
// 0x7e00 Entry 66 (size 16 bundles) Reserved
	DBG_FAULT(66)
	FAULT(66)

	.org ia64_ivt+0x7f00
//////////////////////////////////////////////////////////////////////////
// 0x7f00 Entry 67 (size 16 bundles) Reserved
	DBG_FAULT(67)
	FAULT(67)

	.org ia64_ivt+0x8000
