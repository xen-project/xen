/*
 * arch/ia64/kernel/vmx_ivt.S
 *
 * Copyright (C) 1998-2001, 2003 Hewlett-Packard Co
 *      Stephane Eranian <eranian@hpl.hp.com>
 *      David Mosberger <davidm@hpl.hp.com>
 * Copyright (C) 2000, 2002-2003 Intel Co
 *      Asit Mallick <asit.k.mallick@intel.com>
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
 *              // 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
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
#include <asm/virt_event.h>
#include <asm/vmx_phy_mode.h>
#include <xen/errno.h>

#if 1
# define PSR_DEFAULT_BITS   psr.ac
#else
# define PSR_DEFAULT_BITS   0
#endif


#ifdef VTI_DEBUG
#define IVT_DEBUG_MASK  (IVT_DEBUG_SIZE * (IVT_DEBUG_MAX - 1))
#define VMX_DBG_FAULT(i)                \
    mov r31=pr;                         \
    mov r20=cr.ipsr;;                   \
    tbit.z p6,p0=r20,IA64_PSR_VM_BIT;;  \
(p6)movl r21=THIS_CPU(cpu_kr)+          \
        IA64_KR_CURRENT_OFFSET;;        \
(p6)ld8 r21=[r21];                      \
    mov pr=r31;;                        \
    add r16=IVT_CUR_OFS,r21;            \
    add r17=IVT_DBG_OFS,r21;;           \
    ld8  r18=[r16];;                    \
    add r17=r18,r17;                    \
    mov r19=cr.iip;                     \
    mov r22=cr.ifa;                     \
    mov r23=i;;                         \
    st8 [r17]=r19,8;                    \
    add r18=IVT_DEBUG_SIZE,r18;;        \
    st8 [r17]=r20,8;                    \
    mov r19=IVT_DEBUG_MASK;;            \
    st8 [r17]=r22,8;                    \
    and r18=r19,r18;;                   \
    st8 [r17]=r23;                      \
    st8 [r16]=r18;;
#else
# define VMX_DBG_FAULT(i)
#endif

#include "vmx_minstate.h"

#define MINSTATE_VIRT	/* needed by minstate.h */
#include "minstate.h"


#define VMX_FAULT(n)                            \
vmx_fault_##n:;                                 \
    mov r19=n;                                  \
    br.sptk.many dispatch_to_fault_handler;     \
    ;;

#define VMX_REFLECT(n)                              \
    mov r31=pr;                                     \
    mov r19=n;  /* prepare to save predicates */    \
    mov r29=cr.ipsr;                                \
    ;;                                              \
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT;               \
(p7)br.sptk.many vmx_dispatch_reflection;           \
    br.sptk.many dispatch_to_fault_handler

#ifdef CONFIG_VMX_PANIC
GLOBAL_ENTRY(vmx_panic)
    br.sptk.many vmx_panic
    ;;
END(vmx_panic)
#endif




    .section .text.ivt,"ax"

    .align 32768    // align on 32KB boundary
    .global vmx_ia64_ivt
vmx_ia64_ivt:
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0000 Entry 0 (size 64 bundles) VHPT Translation (8,20,47)
ENTRY(vmx_vhpt_miss)
    VMX_DBG_FAULT(0)
    VMX_FAULT(0)
END(vmx_vhpt_miss)

    .org vmx_ia64_ivt+0x400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x0400 Entry 1 (size 64 bundles) ITLB (21)
ENTRY(vmx_itlb_miss)
    VMX_DBG_FAULT(1)
    mov r29=cr.ipsr
    mov r31 = pr
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT
(p6) br.sptk vmx_alt_itlb_miss_vmm
    mov r16 = cr.ifa
    ;;
    thash r17 = r16
    ttag r20 = r16
    ;;
    mov r18 = r17
    adds r28 = VLE_TITAG_OFFSET,r17
    adds r19 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r17 = [r19]	// Read chain
    ;;
vmx_itlb_loop:
    cmp.eq p6,p0 = r0, r17 // End of chain ?
(p6)br vmx_itlb_out
    ;;
    adds r16 = VLE_TITAG_OFFSET, r17
    adds r19 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r24 = [r16] // Read tag
    ld8 r23 = [r19] // Read chain
    ;;
    lfetch [r23]
    cmp.eq  p6,p7 = r20, r24 // does tag match ?
    ;;
(p7)mov r17 = r23; // No: entry = chain
(p7)br.sptk vmx_itlb_loop // again
    ;;
    // Swap the first entry with the entry found in the collision chain
    // to speed up next hardware search (and keep LRU).
    // In comments 1 stands for the first entry and 2 for the found entry.
    ld8 r29 = [r28] // Read tag of 1
    dep r22 = -1,r24,63,1    // set ti=1 of 2 (to disable it during the swap)
    ;;
    ld8 r25 = [r17] // Read value of 2
    ld8 r27 = [r18] // Read value of 1
    st8 [r16] = r29, VLE_ITIR_OFFSET - VLE_TITAG_OFFSET // Write tag of 2
    st8 [r28] = r22, VLE_ITIR_OFFSET - VLE_TITAG_OFFSET // Write tag of 1
    mf
    ;;
    ld8 r29 = [r16] // read itir of 2
    ld8 r22 = [r28] // read itir of 1
    st8 [r18] = r25 // Write value of 1
    st8 [r17] = r27 // Write value of 2
    ;;
    st8 [r16] = r22 // Write itir of 2
    st8 [r28] = r29, VLE_TITAG_OFFSET - VLE_ITIR_OFFSET // write itir of 1
    ;;
    st8.rel [r28] = r24 // Write tag of 1 (with ti=0)
    // Insert the translation entry
    itc.i r25
    dv_serialize_data
    // Resume
    mov r17=cr.isr
    mov r23=r31
    mov r22=b0
    adds r16=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r16]
    ;;
    adds r19=VPD(VPSR),r18
    ;;
    ld8 r19=[r19]
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
    VMX_DBG_FAULT(2)
    mov r29=cr.ipsr	
    mov r31 = pr
    ;;
    tbit.z p6,p7=r29,IA64_PSR_VM_BIT
(p6)br.sptk vmx_alt_dtlb_miss_vmm
    mov r16 = cr.ifa
    ;;
    thash r17 = r16
    ttag r20 = r16
    ;;
    mov r18 = r17
    adds r28 = VLE_TITAG_OFFSET,r17
    adds r19 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r17 = [r19]
    ;;
vmx_dtlb_loop:
    cmp.eq p6,p0 = r0, r17
(p6)br vmx_dtlb_out
    ;;
    adds r16 = VLE_TITAG_OFFSET, r17
    adds r19 = VLE_CCHAIN_OFFSET, r17
    ;;
    ld8 r24 = [r16]
    ld8 r23 = [r19]
    ;;
    lfetch [r23]
    cmp.eq  p6,p7 = r20, r24
    ;;
(p7)mov r17 = r23;
(p7)br.sptk vmx_dtlb_loop
    ;;
    ld8 r29 = [r28]
    dep r22 = -1,r24,63,1    //set ti=1
    ;;
    ld8 r25 = [r17]
    ld8 r27 = [r18]
    st8 [r16] = r29, VLE_ITIR_OFFSET - VLE_TITAG_OFFSET
    st8 [r28] = r22, VLE_ITIR_OFFSET - VLE_TITAG_OFFSET
    mf
    ;;
    ld8 r29 = [r16]
    ld8 r22 = [r28]
    st8 [r18] = r25
    st8 [r17] = r27
    ;;
    st8 [r16] = r22
    st8 [r28] = r29, VLE_TITAG_OFFSET - VLE_ITIR_OFFSET
    ;;
    st8.rel [r28] = r24 
    itc.d r25
    dv_serialize_data
    mov r17=cr.isr
    mov r23=r31
    mov r22=b0
    adds r16=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r16]
    ;;
    adds r19=VPD(VPSR),r18
    ;;
    ld8 r19=[r19]
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
    VMX_DBG_FAULT(3)
    mov r29=cr.ipsr
    mov r31 = pr
    adds r22=IA64_VCPU_MMU_MODE_OFFSET, r21
    ;;
    tbit.nz p7,p0=r29,IA64_PSR_VM_BIT
(p7)br.spnt vmx_alt_itlb_miss_dom
vmx_alt_itlb_miss_vmm:
    mov r16=cr.ifa    // get address that caused the TLB miss
    movl r17=PAGE_KERNEL
    mov r24=cr.ipsr
    movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
    ;;
    and r19=r19,r16     // clear ed, reserved bits, and PTE control bits
    extr.u r18=r16,XEN_VIRT_UC_BIT, 1     // extract UC bit
    ;;
    or r19=r17,r19      // insert PTE control bits into r19
    mov r20=IA64_GRANULE_SHIFT<<2
    ;;
    dep r19=r18,r19,4,1	// set bit 4 (uncached) if the access was to UC region
    mov cr.itir=r20
    ;;
    itc.i r19		// insert the TLB entry
    mov pr=r31,-1
    rfi
    ;;
vmx_alt_itlb_miss_dom:
    ld1 r23=[r22]  // Load mmu_mode
    ;;
    cmp.eq p6,p7=VMX_MMU_PHY_D,r23
(p7)br.sptk vmx_fault_3
    ;;
    mov r19=3
    br.sptk vmx_dispatch_tlb_miss
    VMX_FAULT(3);
END(vmx_alt_itlb_miss)


    .org vmx_ia64_ivt+0x1000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1000 Entry 4 (size 64 bundles) Alt DTLB (7,46)
ENTRY(vmx_alt_dtlb_miss)
    VMX_DBG_FAULT(4)
    mov r29=cr.ipsr	//frametable_miss needs ipsr is saved in r29.
    mov r31=pr
    adds r22=IA64_VCPU_MMU_MODE_OFFSET, r21
    ;;
    tbit.nz p7,p0=r29,IA64_PSR_VM_BIT
(p7)br.spnt vmx_alt_dtlb_miss_dom
vmx_alt_dtlb_miss_vmm:
    mov r16=cr.ifa		// get address that caused the TLB miss
    ;;
#ifdef CONFIG_VIRTUAL_FRAME_TABLE
    // Test for the address of virtual frame_table
    shr r22=r16,56;;
    cmp.eq p8,p0=((VIRT_FRAME_TABLE_ADDR>>56)&0xff)-0x100,r22
(p8)br.cond.sptk frametable_miss ;; //Make sure ipsr is saved in r29
#endif
    movl r17=PAGE_KERNEL
    mov r20=cr.isr
    movl r19=(((1 << IA64_MAX_PHYS_BITS) - 1) & ~0xfff)
    mov r24=cr.ipsr
    ;;
    and r22=IA64_ISR_CODE_MASK,r20		// get the isr.code field
    tbit.nz p6,p7=r20,IA64_ISR_SP_BIT		// is speculation bit on?
    tbit.nz p8,p0=r16,XEN_VIRT_UC_BIT		// is Xen UC region?
    extr.u r23=r16,59,5				// iva fault address
						// 0xc0000000_00000000 >> 59 = 0x18 EFI UC address
						// 0xe0000000_00000000 >> 59 = 0x1c EFI address

    and r19=r19,r16				// clear ed, reserved bits, and PTE control bits
    tbit.nz p9,p0=r20,IA64_ISR_NA_BIT		// is non-access bit on?
    ;;
    cmp.eq.or p8,p0=0x18,r23			// Region 6 is UC for EFI
(p9)cmp.eq.or.andcm p6,p7=IA64_ISR_CODE_LFETCH,r22	// check isr.code field
    dep r24=-1,r24,IA64_PSR_ED_BIT,1
    or r19=r19,r17				// insert PTE control bits into r19
    mov r20=IA64_GRANULE_SHIFT<<2
    ;;
(p8)dep r19=-1,r19,4,1				// set bit 4 (uncached) if access to UC area

(p6)mov cr.ipsr=r24
    mov cr.itir=r20
    ;;
(p7)itc.d r19		// insert the TLB entry
    mov pr=r31,-1
    rfi
    ;;
vmx_alt_dtlb_miss_dom:
    ld1 r23=[r22]  // Load mmu_mode
    ;;
    cmp.eq p6,p7=VMX_MMU_PHY_D,r23
(p7)br.sptk vmx_fault_4
    ;;
    mov r19=4
    br.sptk vmx_dispatch_tlb_miss
    VMX_FAULT(4);
END(vmx_alt_dtlb_miss)

    .org vmx_ia64_ivt+0x1400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1400 Entry 5 (size 64 bundles) Data nested TLB (6,45)
ENTRY(vmx_nested_dtlb_miss)
    VMX_DBG_FAULT(5)
    mov r29=cr.ipsr
    mov b0=r30
    ;;
    tbit.z p6,p0=r29,IA64_PSR_VM_BIT
(p6)br.sptk b0		// return to the continuation point
    VMX_FAULT(5)
END(vmx_nested_dtlb_miss)

    .org vmx_ia64_ivt+0x1800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1800 Entry 6 (size 64 bundles) Instruction Key Miss (24)
ENTRY(vmx_ikey_miss)
    VMX_DBG_FAULT(6)
    VMX_REFLECT(6)
END(vmx_ikey_miss)

    .org vmx_ia64_ivt+0x1c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
ENTRY(vmx_dkey_miss)
    VMX_DBG_FAULT(7)
    VMX_REFLECT(7)
END(vmx_dkey_miss)

    .org vmx_ia64_ivt+0x2000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2000 Entry 8 (size 64 bundles) Dirty-bit (54)
ENTRY(vmx_dirty_bit)
    VMX_DBG_FAULT(8)
    mov r28=cr.ipsr
    mov r31=pr
    ;;
    mov r19=cr.ifa
    tbit.z p6,p0=r28,IA64_PSR_VM_BIT
(p6)br.spnt.few vmx_fault_8
    // Prepare for nested dtlb miss
    mov r22=b0
    dep.z r29=r28,IA64_PSR_VM_BIT,1
    ;;
    mov cr.ipsr=r29	// ipsr.vm=0
    movl r30=dirty_bit_tpa_fail
    ;;
    tpa r19=r19		// possibly nested dtlb miss?
    mov cr.ipsr=r28	// ipsr.vm=1
    br.sptk vmx_dispatch_shadow_fault
    VMX_FAULT(8)
dirty_bit_tpa_fail:
    // Resume & Retry
    mov cr.ipsr=r28	// ipsr.vm=1
    mov r17=cr.isr
    mov r23=r31
//  mov r22=b0		// b0 is clobbered in vmx_nested_dtlb_miss
    adds r16=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r16]
    ;;
    adds r19=VPD(VPSR),r18
    ;;
    ld8 r19=[r19]
    br.sptk ia64_vmm_entry
    ;;
END(vmx_dirty_bit)

    .org vmx_ia64_ivt+0x2400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2400 Entry 9 (size 64 bundles) Instruction Access-bit (27)
ENTRY(vmx_iaccess_bit)
    VMX_DBG_FAULT(9)
    VMX_REFLECT(9)
END(vmx_iaccess_bit)

    .org vmx_ia64_ivt+0x2800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2800 Entry 10 (size 64 bundles) Data Access-bit (15,55)
ENTRY(vmx_daccess_bit)
    VMX_DBG_FAULT(10)
    VMX_REFLECT(10)
END(vmx_daccess_bit)

    .org vmx_ia64_ivt+0x2c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x2c00 Entry 11 (size 64 bundles) Break instruction (33)
ENTRY(vmx_break_fault)
    VMX_DBG_FAULT(11)
    mov r31=pr
    mov r19=11
    mov r17=cr.iim
    mov r29=cr.ipsr
    ;;
    tbit.z p6,p0=r29,IA64_PSR_VM_BIT
(p6)br.sptk.many vmx_dispatch_break_fault /* make sure before access [r21] */
    adds r22=IA64_VCPU_BREAKIMM_OFFSET, r21
    ;;
    ld4 r22=[r22]
    extr.u r24=r29,IA64_PSR_CPL0_BIT,2
    cmp.ltu p6,p0=NR_hypercalls,r2
    ;;
    cmp.ne.or p6,p0=r22,r17
    cmp.ne.or p6,p0=r0,r24
(p6) br.sptk.many vmx_dispatch_break_fault
    ;;
   /*
    * The streamlined system call entry/exit paths only save/restore the initial part
    * of pt_regs.  This implies that the callers of system-calls must adhere to the
    * normal procedure calling conventions.
    *
    *   Registers to be saved & restored:
    *   CR registers: cr.ipsr, cr.iip, cr.ifs
    *   AR registers: ar.unat, ar.pfs, ar.rsc, ar.rnat, ar.bspstore, ar.fpsr
    *   others: pr, b0, b6, loadrs, r1, r11, r12, r13, r15
    *   Registers to be restored only:
    *   r8-r11: output value from the system call.
    *
    * During system call exit, scratch registers (including r15) are modified/cleared
    * to prevent leaking bits from kernel to user level.
    */
   
    mov r14=r21				// save r21 before bsw.1
    bsw.1				// B (6 cyc) switch to bank 1
    ;;   
    mov r29=cr.ipsr			// M2 (12 cyc)
    mov r31=pr				// I0 (2 cyc)
    mov r16=r14
    mov r15=r2

    mov r17=cr.iim			// M2 (2 cyc)
    mov.m r27=ar.rsc			// M2 (12 cyc)

    mov.m ar.rsc=0			// M2
    mov.m r21=ar.fpsr			// M2 (12 cyc)
    mov r19=b6				// I0 (2 cyc)
    ;;
    mov.m r23=ar.bspstore		// M2 (12 cyc)
    mov.m r24=ar.rnat			// M2 (5 cyc)
    mov.i r26=ar.pfs			// I0 (2 cyc)

    invala				// M0|1
    nop.m 0				// M
    mov r20=r1				// A			save r1

    nop.m 0
    movl r30=ia64_hypercall_table	// X

    mov r28=cr.iip			// M2 (2 cyc)
   //
   // From this point on, we are definitely on the syscall-path
   // and we can use (non-banked) scratch registers.
   //
///////////////////////////////////////////////////////////////////////
    mov r1=r16				// A    move task-pointer to "addl"-addressable reg
    mov r2=r16				// A    setup r2 for ia64_syscall_setup

    mov r3=NR_hypercalls - 1
    ;;
    mov r9=r0               		// force flags = 0
    extr.u r8=r29,41,2			// I0   extract ei field from cr.ipsr

    shladd r30=r15,3,r30		// A    r30 = hcall_table + 8*syscall
    addl r22=IA64_RBS_OFFSET,r1		// A    compute base of RBS
    cmp.leu p6,p7=r15,r3		// A    syscall number in range?
    ;;

    lfetch.fault.excl.nt1 [r22]		// M0|1 prefetch RBS
(p6) ld8 r30=[r30]			// M0|1 load address of syscall entry point
    tnat.nz.or p7,p0=r15		// I0	is syscall nr a NaT?

    mov.m ar.bspstore=r22		// M2   switch to kernel RBS
    cmp.eq p8,p9=2,r8			// A    isr.ei==2?
    ;;

(p8) mov r8=0				// A    clear ei to 0
(p7) movl r30=do_ni_hypercall		// X

(p8) adds r28=16,r28			// A    switch cr.iip to next bundle
(p9) adds r8=1,r8			// A    increment ei to next slot
    nop.i 0
    ;;

    mov.m r25=ar.unat			// M2 (5 cyc)
    dep r29=r8,r29,41,2			// I0   insert new ei into cr.ipsr
   //
   // If any of the above loads miss in L1D, we'll stall here until
   // the data arrives.
   //
///////////////////////////////////////////////////////////////////////
    mov b6=r30				// I0   setup syscall handler branch reg early

    mov r18=ar.bsp				// M2 (12 cyc)
   ;;
    addl r1=IA64_STK_OFFSET-IA64_PT_REGS_SIZE,r1 // A    compute base of memory stack
    br.call.sptk.many b7=ia64_hypercall_setup	// B
1:
    mov ar.rsc=0x3				// M2   set eager mode, pl 0, LE, loadrs=0
    ;;
    ssm psr.ic | PSR_DEFAULT_BITS		// M2	now it's safe to re-enable intr.-collection
    ;;

    srlz.i					// M0   ensure interruption collection is on
(p15)   ssm psr.i				// M2   restore psr.i
    br.call.sptk.many b0=b6			// B    invoke syscall-handker (ignore return addr)
	;; 
	//restore hypercall argument if continuation
	adds r2=IA64_VCPU_HYPERCALL_CONTINUATION_OFS,r13
	;;
	ld1 r20=[r2]
	;;
	st1 [r2]=r0
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
	br.sptk.many ia64_leave_hypercall
	;;

   VMX_FAULT(11)
END(vmx_break_fault)

    .org vmx_ia64_ivt+0x3000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3000 Entry 12 (size 64 bundles) External Interrupt (4)
ENTRY(vmx_interrupt)
    VMX_DBG_FAULT(12)
    mov r31=pr		// prepare to save predicates
    mov r19=12
    br.sptk vmx_dispatch_interrupt
END(vmx_interrupt)

    .org vmx_ia64_ivt+0x3400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3400 Entry 13 (size 64 bundles) Reserved
ENTRY(vmx_virtual_exirq)
    VMX_DBG_FAULT(13)
    mov r31=pr
    mov r19=13
    br.sptk vmx_dispatch_vexirq
END(vmx_virtual_exirq)

    .org vmx_ia64_ivt+0x3800
/////////////////////////////////////////////////////////////////////////////////////////
// 0x3800 Entry 14 (size 64 bundles) Reserved
    VMX_DBG_FAULT(14)
    VMX_FAULT(14)
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
ENTRY(ia64_hypercall_setup)
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
//(pKStk) mov r18=r0				// make sure r18 isn't NaT
    ;;

    st8 [r16]=r26,PT(CR_IFS)-PT(AR_PFS)	// save ar.pfs
    st8 [r17]=r28,PT(AR_UNAT)-PT(CR_IIP)	// save cr.iip
    mov r28=b0				// save b0 (2 cyc)
    ;;

    st8 [r17]=r25,PT(AR_RSC)-PT(AR_UNAT)	// save ar.unat
    dep r19=0,r19,38,26			// clear all bits but 0..37 [I0]
(p8)    mov in0=-1
    ;;

    st8 [r16]=r19,PT(AR_RNAT)-PT(CR_IFS)	// store ar.pfs.pfm in cr.ifs
    extr.u r11=r19,7,7	// I0		// get sol of ar.pfs
    and r8=0x7f,r19		// A		// get sof of ar.pfs

    st8 [r17]=r27,PT(AR_BSPSTORE)-PT(AR_RSC)// save ar.rsc
    tbit.nz p15,p0=r29,IA64_PSR_I_BIT // I0
(p9)    mov in1=-1
    ;;

//(pUStk) sub r18=r18,r22				// r18=RSE.ndirty*8
    sub r18=r18,r22				// r18=RSE.ndirty*8
    tnat.nz p10,p0=in2
    add r11=8,r11
    ;;
//(pKStk) adds r16=PT(PR)-PT(AR_RNAT),r16		// skip over ar_rnat field
//(pKStk) adds r17=PT(B0)-PT(AR_BSPSTORE),r17	// skip over ar_bspstore field
    tnat.nz p11,p0=in3
    ;;
(p10)   mov in2=-1
    tnat.nz p12,p0=in4				// [I0]
(p11)   mov in3=-1
    ;;
//(pUStk) st8 [r16]=r24,PT(PR)-PT(AR_RNAT)	// save ar.rnat
    st8 [r16]=r24,PT(PR)-PT(AR_RNAT)	// save ar.rnat
//(pUStk) st8 [r17]=r23,PT(B0)-PT(AR_BSPSTORE)	// save ar.bspstore
    st8 [r17]=r23,PT(B0)-PT(AR_BSPSTORE)	// save ar.bspstore	
    shl r18=r18,16				// compute ar.rsc to be used for "loadrs"
    ;;
    st8 [r16]=r31,PT(LOADRS)-PT(PR)		// save predicates
    st8 [r17]=r28,PT(R1)-PT(B0)		// save b0
    tnat.nz p13,p0=in5				// [I0]
    ;;
    st8 [r16]=r18,PT(R12)-PT(LOADRS)	// save ar.rsc value for "loadrs"
    st8.spill [r17]=r20,PT(R13)-PT(R1)	// save original r1
(p12)   mov in4=-1
    ;;

.mem.offset 0,0; st8.spill [r16]=r12,PT(AR_FPSR)-PT(R12)	// save r12
.mem.offset 8,0; st8.spill [r17]=r13,PT(R15)-PT(R13)		// save r13
(p13)   mov in5=-1
    ;;
    st8 [r16]=r21,PT(R8)-PT(AR_FPSR)	// save ar.fpsr
    tnat.nz p13,p0=in6
    cmp.lt p10,p9=r11,r8	// frame size can't be more than local+8
    ;;
    mov r8=1
(p9)    tnat.nz p10,p0=r15
    adds r12=-16,r1		// switch to kernel memory stack (with 16 bytes of scratch)

    st8.spill [r17]=r15			// save r15
    tnat.nz p8,p0=in7
    nop.i 0

    mov r13=r2				// establish `current'
    movl r1=__gp				// establish kernel global pointer
    ;;
    st8 [r16]=r8		// ensure pt_regs.r8 != 0 (see handle_syscall_error)
(p13)   mov in6=-1
(p8)    mov in7=-1

    cmp.eq pSys,pNonSys=r0,r0		// set pSys=1, pNonSys=0
    movl r17=FPSR_DEFAULT
    ;;
    mov.m ar.fpsr=r17			// set ar.fpsr to kernel default value
(p10)   mov r8=-EINVAL
    br.ret.sptk.many b7
END(ia64_hypercall_setup)


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

    .org vmx_ia64_ivt+0x5000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5000 Entry 20 (size 16 bundles) Page Not Present
ENTRY(vmx_page_not_present)
    VMX_DBG_FAULT(20)
    VMX_REFLECT(20)
END(vmx_page_not_present)

    .org vmx_ia64_ivt+0x5100
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5100 Entry 21 (size 16 bundles) Key Permission vector
ENTRY(vmx_key_permission)
    VMX_DBG_FAULT(21)
    VMX_REFLECT(21)
END(vmx_key_permission)

    .org vmx_ia64_ivt+0x5200
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5200 Entry 22 (size 16 bundles) Instruction Access Rights (26)
ENTRY(vmx_iaccess_rights)
    VMX_DBG_FAULT(22)
    VMX_REFLECT(22)
END(vmx_iaccess_rights)

    .org vmx_ia64_ivt+0x5300
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5300 Entry 23 (size 16 bundles) Data Access Rights (14,53)
ENTRY(vmx_daccess_rights)
    VMX_DBG_FAULT(23)
    VMX_REFLECT(23)
END(vmx_daccess_rights)

    .org vmx_ia64_ivt+0x5400
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5400 Entry 24 (size 16 bundles) General Exception (5,32,34,36,38,39)
ENTRY(vmx_general_exception)
    VMX_DBG_FAULT(24)
    VMX_REFLECT(24)
//    VMX_FAULT(24)
END(vmx_general_exception)

    .org vmx_ia64_ivt+0x5500
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5500 Entry 25 (size 16 bundles) Disabled FP-Register (35)
ENTRY(vmx_disabled_fp_reg)
    VMX_DBG_FAULT(25)
    VMX_REFLECT(25)
END(vmx_disabled_fp_reg)

    .org vmx_ia64_ivt+0x5600
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5600 Entry 26 (size 16 bundles) Nat Consumption (11,23,37,50)
ENTRY(vmx_nat_consumption)
    VMX_DBG_FAULT(26)
    VMX_REFLECT(26)
END(vmx_nat_consumption)

    .org vmx_ia64_ivt+0x5700
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5700 Entry 27 (size 16 bundles) Speculation (40)
ENTRY(vmx_speculation_vector)
    VMX_DBG_FAULT(27)
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
    VMX_REFLECT(29)
END(vmx_debug_vector)

    .org vmx_ia64_ivt+0x5a00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5a00 Entry 30 (size 16 bundles) Unaligned Reference (57)
ENTRY(vmx_unaligned_access)
    VMX_DBG_FAULT(30)
    VMX_REFLECT(30)
END(vmx_unaligned_access)

    .org vmx_ia64_ivt+0x5b00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5b00 Entry 31 (size 16 bundles) Unsupported Data Reference (57)
ENTRY(vmx_unsupported_data_reference)
    VMX_DBG_FAULT(31)
    VMX_REFLECT(31)
END(vmx_unsupported_data_reference)

    .org vmx_ia64_ivt+0x5c00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5c00 Entry 32 (size 16 bundles) Floating-Point Fault (64)
ENTRY(vmx_floating_point_fault)
    VMX_DBG_FAULT(32)
    VMX_REFLECT(32)
END(vmx_floating_point_fault)

    .org vmx_ia64_ivt+0x5d00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5d00 Entry 33 (size 16 bundles) Floating Point Trap (66)
ENTRY(vmx_floating_point_trap)
    VMX_DBG_FAULT(33)
    VMX_REFLECT(33)
END(vmx_floating_point_trap)

    .org vmx_ia64_ivt+0x5e00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5e00 Entry 34 (size 16 bundles) Lower Privilege Transfer Trap (66)
ENTRY(vmx_lower_privilege_trap)
    VMX_DBG_FAULT(34)
    VMX_REFLECT(34)
END(vmx_lower_privilege_trap)

    .org vmx_ia64_ivt+0x5f00
/////////////////////////////////////////////////////////////////////////////////////////
// 0x5f00 Entry 35 (size 16 bundles) Taken Branch Trap (68)
ENTRY(vmx_taken_branch_trap)
    VMX_DBG_FAULT(35)
    VMX_REFLECT(35)
END(vmx_taken_branch_trap)

    .org vmx_ia64_ivt+0x6000
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6000 Entry 36 (size 16 bundles) Single Step Trap (69)
ENTRY(vmx_single_step_trap)
    VMX_DBG_FAULT(36)
    VMX_REFLECT(36)
END(vmx_single_step_trap)

    .global vmx_virtualization_fault_back
    .org vmx_ia64_ivt+0x6100
/////////////////////////////////////////////////////////////////////////////////////////
// 0x6100 Entry 37 (size 16 bundles) Virtualization Fault
ENTRY(vmx_virtualization_fault)
//    VMX_DBG_FAULT(37)
    mov r31=pr
#ifndef CONFIG_XEN_IA64_DISABLE_OPTVFAULT
    movl r30 = virtualization_fault_table
    mov r23=b0
    ;;
    shladd r30=r24,4,r30
    ;;
    mov b0=r30
    br.sptk.many b0
    ;;
#endif
vmx_virtualization_fault_back:
    mov r19=37
    adds r16 = IA64_VCPU_CAUSE_OFFSET,r21
    adds r17 = IA64_VCPU_OPCODE_OFFSET,r21
    ;;
    st8 [r16] = r24
    st8 [r17] = r25
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
    alloc r14=ar.pfs,0,0,5,0
    mov out0=cr.ifa
    mov out1=cr.isr
    mov out2=cr.iim
    mov out3=r15
    adds r3=8,r2                // set up second base pointer
    ;;
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15) ssm psr.i               // restore psr.i
    movl r14=ia64_leave_hypervisor
    ;;
    VMX_SAVE_REST
    mov rp=r14
    ;;
    P6_BR_CALL_PANIC(.Lvmx_dispatch_reflection_string)
    adds out4=16,r12
    br.call.sptk.many b6=vmx_reflect_interruption
END(vmx_dispatch_reflection)

ENTRY(vmx_dispatch_virtualization_fault)
    VMX_SAVE_MIN_WITH_COVER
    ;;
    alloc r14=ar.pfs,0,0,2,0        // now it's safe (must be first in insn group!)
    mov out0=r13        //vcpu
    adds r3=8,r2                // set up second base pointer
    ;;
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15) ssm psr.i               // restore psr.i
    movl r14=ia64_leave_hypervisor_prepare
    ;;
    VMX_SAVE_REST
    VMX_SAVE_EXTRA
    mov rp=r14
    ;;
    P6_BR_CALL_PANIC(.Lvmx_dispatch_virtualization_fault_string)
    adds out1=16,sp         //regs
    br.call.sptk.many b6=vmx_emulate
END(vmx_dispatch_virtualization_fault)


GLOBAL_ENTRY(vmx_dispatch_vexirq)
    VMX_SAVE_MIN_WITH_COVER
    alloc r14=ar.pfs,0,0,1,0
    mov out0=r13

    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15) ssm psr.i               // restore psr.i
    adds r3=8,r2                // set up second base pointer
    ;;
    VMX_SAVE_REST
    movl r14=ia64_leave_hypervisor
    ;;
    mov rp=r14
    P6_BR_CALL_PANIC(.Lvmx_dispatch_vexirq_string)
    br.call.sptk.many b6=vmx_vexirq
END(vmx_dispatch_vexirq)

ENTRY(vmx_dispatch_tlb_miss)
    VMX_SAVE_MIN_WITH_COVER_R19
    alloc r14=ar.pfs,0,0,3,0
    mov out0=cr.ifa
    mov out1=r15
    adds r3=8,r2                // set up second base pointer
    ;;
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15) ssm psr.i               // restore psr.i
    movl r14=ia64_leave_hypervisor
    ;;
    VMX_SAVE_REST
    mov rp=r14
    ;;
    P6_BR_CALL_PANIC(.Lvmx_dispatch_tlb_miss_string)
    adds out2=16,r12
    br.call.sptk.many b6=vmx_hpw_miss
END(vmx_dispatch_tlb_miss)

ENTRY(vmx_dispatch_break_fault)
    VMX_SAVE_MIN_WITH_COVER_NO_PANIC
    ;;
    alloc r14=ar.pfs,0,0,4,0 // now it's safe (must be first in insn group!)
    mov out0=cr.ifa
    mov out2=cr.isr     // FIXME: pity to make this slow access twice
    mov out3=cr.iim     // FIXME: pity to make this slow access twice
    adds r3=8,r2                // set up second base pointer
    ;;
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15)ssm psr.i               // restore psr.i
(pUStk)movl r14=ia64_leave_hypervisor
    ;;
(pKStk)movl r14=ia64_leave_nested
    VMX_SAVE_REST
    mov rp=r14
    ;;
    adds out1=16,sp
    br.call.sptk.many b6=vmx_ia64_handle_break
    ;;
END(vmx_dispatch_break_fault)


ENTRY(vmx_dispatch_interrupt)
    VMX_SAVE_MIN_WITH_COVER_NO_PANIC	// uses r31; defines r2 and r3
    ;;
    alloc r14=ar.pfs,0,0,2,0	// must be first in an insn group
    ssm psr.ic
    mov out0=cr.ivr		// pass cr.ivr as first arg
    adds r3=8,r2		// set up second base pointer for SAVE_REST
    ;;
(pUStk) movl r14=ia64_leave_hypervisor
    srlz.i
    ;;
(pKStk) movl r14=ia64_leave_nested
    VMX_SAVE_REST
    add out1=16,sp		// pass pointer to pt_regs as second arg
    mov rp=r14
    br.call.sptk.many b6=ia64_handle_irq
END(vmx_dispatch_interrupt)


ENTRY(vmx_dispatch_shadow_fault)
    VMX_SAVE_MIN_WITH_COVER_R19
    alloc r14=ar.pfs,0,0,4,0
    mov out0=cr.ifa
    mov out1=cr.isr
    mov out2=r15
    adds r3=8,r2                // set up second base pointer
    ;;
    ssm psr.ic
    ;;
    srlz.i                  // guarantee that interruption collection is on
    ;;
    (p15) ssm psr.i               // restore psr.i
    movl r14=ia64_leave_hypervisor
    ;;
    VMX_SAVE_REST
    mov rp=r14
    ;;
    P6_BR_CALL_PANIC(.Lvmx_dispatch_shadow_fault_string)
    adds out3=16,r12
    br.call.sptk.many b6=vmx_ia64_shadow_fault
END(vmx_dispatch_shadow_fault)

    .section .rodata, "a"
.Lvmx_dispatch_reflection_string:
    .asciz "vmx_dispatch_reflection\n"
.Lvmx_dispatch_virtualization_fault_string:
    .asciz "vmx_dispatch_virtualization_fault\n"
.Lvmx_dispatch_vexirq_string:
    .asciz "vmx_dispatch_vexirq\n"
.Lvmx_dispatch_tlb_miss_string:
    .asciz "vmx_dispatch_tlb_miss\n"
.Lvmx_dispatch_shadow_fault_string:
    .asciz "vmx_dispatch_shadow_fault\n"
    .previous
