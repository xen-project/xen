/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_entry.S:
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
 *  Xuefei Xu (Anthony Xu) (anthony.xu@intel.com)
 *  Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 */

#ifndef VCPU_TLB_SHIFT
#define VCPU_TLB_SHIFT	22
#endif
#include <linux/config.h>
#include <asm/asmmacro.h>
#include <asm/cache.h>
#include <asm/kregs.h>
#include <asm/offsets.h>
#include <asm/pgtable.h>
#include <asm/percpu.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#include <asm/vhpt.h>
#include <asm/vmmu.h>
#include "vmx_minstate.h"

GLOBAL_ENTRY(ia64_leave_nested)
	rsm psr.i
	;;
	adds r21=PT(PR)+16,r12
	;;
	lfetch [r21],PT(CR_IPSR)-PT(PR)
	adds r2=PT(B6)+16,r12
	adds r3=PT(R16)+16,r12
	;;
	lfetch [r21]
	ld8 r28=[r2],8		// load b6
	adds r29=PT(R24)+16,r12

	ld8.fill r16=[r3]
	adds r3=PT(AR_CSD)-PT(R16),r3
	adds r30=PT(AR_CCV)+16,r12
	;;
	ld8.fill r24=[r29]
	ld8 r15=[r30]		// load ar.ccv
	;;
	ld8 r29=[r2],16		// load b7
	ld8 r30=[r3],16		// load ar.csd
	;;
	ld8 r31=[r2],16		// load ar.ssd
	ld8.fill r8=[r3],16
	;;
	ld8.fill r9=[r2],16
	ld8.fill r10=[r3],PT(R17)-PT(R10)
	;;
	ld8.fill r11=[r2],PT(R18)-PT(R11)
	ld8.fill r17=[r3],16
	;;
	ld8.fill r18=[r2],16
	ld8.fill r19=[r3],16
	;;
	ld8.fill r20=[r2],16
	ld8.fill r21=[r3],16
	mov ar.csd=r30
	mov ar.ssd=r31
	;;
	rsm psr.i | psr.ic	// initiate turning off of interrupt and interruption collection
	invala			// invalidate ALAT
	;;
	ld8.fill r22=[r2],24
	ld8.fill r23=[r3],24
	mov b6=r28
	;;
	ld8.fill r25=[r2],16
	ld8.fill r26=[r3],16
	mov b7=r29
	;;
	ld8.fill r27=[r2],16
	ld8.fill r28=[r3],16
	;;
	ld8.fill r29=[r2],16
	ld8.fill r30=[r3],24
	;;
	ld8.fill r31=[r2],PT(F9)-PT(R31)
	adds r3=PT(F10)-PT(F6),r3
	;;
	ldf.fill f9=[r2],PT(F6)-PT(F9)
	ldf.fill f10=[r3],PT(F8)-PT(F10)
	;;
	ldf.fill f6=[r2],PT(F7)-PT(F6)
	;;
	ldf.fill f7=[r2],PT(F11)-PT(F7)
	ldf.fill f8=[r3],32
	;;
	srlz.i			// ensure interruption collection is off
	mov ar.ccv=r15
	;;
	bsw.0			// switch back to bank 0 (no stop bit required beforehand...)
	;;
	ldf.fill f11=[r2]
//	mov r18=r13
//    mov r21=r13
	adds r16=PT(CR_IPSR)+16,r12
	adds r17=PT(CR_IIP)+16,r12
	;;
	ld8 r29=[r16],16	// load cr.ipsr
	ld8 r28=[r17],16	// load cr.iip
	;;
	ld8 r30=[r16],16	// load cr.ifs
	ld8 r25=[r17],16	// load ar.unat
	;;
	ld8 r26=[r16],16	// load ar.pfs
	ld8 r27=[r17],16	// load ar.rsc
	cmp.eq p9,p0=r0,r0	// set p9 to indicate that we should restore cr.ifs
	;;
	ld8 r24=[r16],16	// load ar.rnat (may be garbage)
	ld8 r23=[r17],16// load ar.bspstore (may be garbage)
	;;
	ld8 r31=[r16],16	// load predicates
	ld8 r22=[r17],16	// load b0
	;;
	ld8 r19=[r16],16	// load ar.rsc value for "loadrs"
	ld8.fill r1=[r17],16	// load r1
	;;
	ld8.fill r12=[r16],16
	ld8.fill r13=[r17],16
	;;
	ld8 r20=[r16],16	// ar.fpsr
	ld8.fill r15=[r17],16
	;;
	ld8.fill r14=[r16],16
	ld8.fill r2=[r17]
	;;
	ld8.fill r3=[r16]
	;;
	mov r16=ar.bsp		// get existing backing store pointer
	;;
	mov b0=r22
	mov ar.pfs=r26
	mov cr.ifs=r30
	mov cr.ipsr=r29
	mov ar.fpsr=r20
	mov cr.iip=r28
	;;
	mov ar.rsc=r27
	mov ar.unat=r25
	mov pr=r31,-1
	rfi
END(ia64_leave_nested)



GLOBAL_ENTRY(ia64_leave_hypervisor_prepare)
    PT_REGS_UNWIND_INFO(0)
    /*
     * work.need_resched etc. mustn't get changed by this CPU before it returns to
    ;;
     * user- or fsys-mode, hence we disable interrupts early on:
     */
    adds r2 = PT(R4)+16,r12
    adds r3 = PT(R5)+16,r12
    adds r8 = PT(EML_UNAT)+16,r12
    ;;
    ld8 r8 = [r8]
    ;;
    mov ar.unat=r8
    ;;
    ld8.fill r4=[r2],16    //load r4
    ld8.fill r5=[r3],16    //load r5
    ;;
    ld8.fill r6=[r2]    //load r6
    ld8.fill r7=[r3]    //load r7
    ;;
END(ia64_leave_hypervisor_prepare)
//fall through
GLOBAL_ENTRY(ia64_leave_hypervisor)
    PT_REGS_UNWIND_INFO(0)
    rsm psr.i
    ;;
    br.call.sptk.many b0=leave_hypervisor_tail
    ;;
    adds r20=PT(PR)+16,r12
    adds r8=PT(EML_UNAT)+16,r12
    ;;
    ld8 r8=[r8]
    ;;
    mov ar.unat=r8
    ;;
    lfetch [r20],PT(CR_IPSR)-PT(PR)
    adds r2 = PT(B6)+16,r12
    adds r3 = PT(B7)+16,r12
    ;;
    lfetch [r20]
    ;;
    ld8 r24=[r2],16        /* B6 */
    ld8 r25=[r3],16        /* B7 */
    ;;
    ld8 r26=[r2],16        /* ar_csd */
    ld8 r27=[r3],16        /* ar_ssd */
    mov b6 = r24
    ;;
    ld8.fill r8=[r2],16
    ld8.fill r9=[r3],16
    mov b7 = r25
    ;;
    mov ar.csd = r26
    mov ar.ssd = r27
    ;;
    ld8.fill r10=[r2],PT(R15)-PT(R10)
    ld8.fill r11=[r3],PT(R14)-PT(R11)
    ;;
    ld8.fill r15=[r2],PT(R16)-PT(R15)
    ld8.fill r14=[r3],PT(R17)-PT(R14)
    ;;
    ld8.fill r16=[r2],16
    ld8.fill r17=[r3],16
    ;;
    ld8.fill r18=[r2],16
    ld8.fill r19=[r3],16
    ;;
    ld8.fill r20=[r2],16
    ld8.fill r21=[r3],16
    ;;
    ld8.fill r22=[r2],16
    ld8.fill r23=[r3],16
    ;;
    ld8.fill r24=[r2],16
    ld8.fill r25=[r3],16
    ;;
    ld8.fill r26=[r2],16
    ld8.fill r27=[r3],16
    ;;
    ld8.fill r28=[r2],16
    ld8.fill r29=[r3],16
    ;;
    ld8.fill r30=[r2],PT(F6)-PT(R30)
    ld8.fill r31=[r3],PT(F7)-PT(R31)
    ;;
    rsm psr.i | psr.ic  // initiate turning off of interrupt and interruption collection
    invala          // invalidate ALAT
    ;;
    ldf.fill f6=[r2],32
    ldf.fill f7=[r3],32
    ;;
    ldf.fill f8=[r2],32
    ldf.fill f9=[r3],32
    ;;
    ldf.fill f10=[r2],32
    ldf.fill f11=[r3],24
    ;;
    srlz.i          // ensure interruption collection is off
    ;;
    bsw.0
    ;;
    adds r16 = PT(CR_IPSR)+16,r12
    adds r17 = PT(CR_IIP)+16,r12
    mov r21=r13		// get current
    ;;
    ld8 r31=[r16],16    // load cr.ipsr
    ld8 r30=[r17],16    // load cr.iip
    ;;
    ld8 r29=[r16],16    // load cr.ifs
    ld8 r28=[r17],16    // load ar.unat
    ;;
    ld8 r27=[r16],16    // load ar.pfs
    ld8 r26=[r17],16    // load ar.rsc
    ;;
    ld8 r25=[r16],16    // load ar.rnat
    ld8 r24=[r17],16    // load ar.bspstore
    ;;
    ld8 r23=[r16],16    // load predicates
    ld8 r22=[r17],16    // load b0
    ;;
    ld8 r20=[r16],16    // load ar.rsc value for "loadrs"
    ld8.fill r1=[r17],16    //load r1
    ;;
    ld8.fill r12=[r16],16    //load r12
    ld8.fill r13=[r17],PT(R2)-PT(R13)    //load r13
    ;;
    ld8 r19=[r16],PT(R3)-PT(AR_FPSR)    //load ar_fpsr
    ld8.fill r2=[r17],PT(AR_CCV)-PT(R2)    //load r2
    ;;
    ld8.fill r3=[r16]	//load r3
    ld8 r18=[r17]	//load ar_ccv
    ;;
    mov ar.fpsr=r19
    mov ar.ccv=r18
    shr.u r18=r20,16
    ;;
vmx_rbs_switch:    
    movl r19= THIS_CPU(ia64_phys_stacked_size_p8)
    ;;
    ld4 r19=[r19]
     
vmx_dont_preserve_current_frame:
/*
    * To prevent leaking bits between the hypervisor and guest domain,
    * we must clear the stacked registers in the "invalid" partition here.
    * 5 registers/cycle on McKinley).
    */
#   define pRecurse	p6
#   define pReturn	p7
#   define Nregs	14
    
    alloc loc0=ar.pfs,2,Nregs-2,2,0
    shr.u loc1=r18,9		// RNaTslots <= floor(dirtySize / (64*8))
    sub r19=r19,r18			// r19 = (physStackedSize + 8) - dirtySize
    ;;
    mov ar.rsc=r20			// load ar.rsc to be used for "loadrs"
    shladd in0=loc1,3,r19
    mov in1=0
    ;;
    TEXT_ALIGN(32)
vmx_rse_clear_invalid:
    alloc loc0=ar.pfs,2,Nregs-2,2,0
    cmp.lt pRecurse,p0=Nregs*8,in0	// if more than Nregs regs left to clear, (re)curse
    add out0=-Nregs*8,in0
    add out1=1,in1			// increment recursion count
    mov loc1=0
    mov loc2=0
    ;;
    mov loc3=0
    mov loc4=0
    mov loc5=0
    mov loc6=0
    mov loc7=0
(pRecurse) br.call.dptk.few b0=vmx_rse_clear_invalid
    ;;
    mov loc8=0
    mov loc9=0
    cmp.ne pReturn,p0=r0,in1	// if recursion count != 0, we need to do a br.ret
    mov loc10=0
    mov loc11=0
(pReturn) br.ret.dptk.many b0

#	undef pRecurse
#	undef pReturn

// loadrs has already been shifted
    alloc r16=ar.pfs,0,0,0,0    // drop current register frame
    ;;
    loadrs
    ;;
    mov ar.bspstore=r24
    ;;
    mov ar.unat=r28
    mov ar.rnat=r25
    mov ar.rsc=r26
    ;;
    mov cr.ipsr=r31
    mov cr.iip=r30
(pNonSys) mov cr.ifs=r29
    mov ar.pfs=r27
    adds r18=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r18]   //vpd
    adds r17=IA64_VCPU_ISR_OFFSET,r21
    ;;
    ld8 r17=[r17]
    adds r19=VPD(VPSR),r18
    ;;
    ld8 r19=[r19]        //vpsr
    movl r20=__vsa_base
    ;;
//vsa_sync_write_start
    ld8 r20=[r20]       // read entry point
    mov r25=r18
    ;;
    movl r24=ia64_vmm_entry  // calculate return address
    add r16=PAL_VPS_SYNC_WRITE,r20
    ;;
    mov b0=r16
    br.cond.sptk b0         // call the service
    ;;
END(ia64_leave_hypervisor)
// fall through
GLOBAL_ENTRY(ia64_vmm_entry)
/*
 *  must be at bank 0
 *  parameter:
 *  r17:cr.isr
 *  r18:vpd
 *  r19:vpsr
 *  r20:__vsa_base
 *  r22:b0
 *  r23:predicate
 */
    mov r24=r22
    mov r25=r18
    tbit.nz p1,p2 = r19,IA64_PSR_IC_BIT        // p1=vpsr.ic
    ;;
    (p1) add r29=PAL_VPS_RESUME_NORMAL,r20
    (p1) br.sptk.many ia64_vmm_entry_out
    ;;
    tbit.nz p1,p2 = r17,IA64_ISR_IR_BIT		//p1=cr.isr.ir
    ;;
    (p1) add r29=PAL_VPS_RESUME_NORMAL,r20
    (p2) add r29=PAL_VPS_RESUME_HANDLER,r20
    (p2) ld8 r26=[r25]
    ;;
ia64_vmm_entry_out:    
    mov pr=r23,-2
    mov b0=r29
    ;;
    br.cond.sptk b0             // call pal service
END(ia64_vmm_entry)



/*
 * ia64_leave_syscall(): Same as ia64_leave_kernel, except that it doesn't
 *  need to switch to bank 0 and doesn't restore the scratch registers.
 *  To avoid leaking kernel bits, the scratch registers are set to
 *  the following known-to-be-safe values:
 *
 *        r1: restored (global pointer)
 *        r2: cleared
 *        r3: 1 (when returning to user-level)
 *        r8-r11: restored (syscall return value(s))
 *       r12: restored (user-level stack pointer)
 *       r13: restored (user-level thread pointer)
 *       r14: set to __kernel_syscall_via_epc
 *       r15: restored (syscall #)
 *       r16-r17: cleared
 *       r18: user-level b6
 *       r19: cleared
 *       r20: user-level ar.fpsr
 *       r21: user-level b0
 *       r22: cleared
 *       r23: user-level ar.bspstore
 *       r24: user-level ar.rnat
 *       r25: user-level ar.unat
 *       r26: user-level ar.pfs
 *       r27: user-level ar.rsc
 *       r28: user-level ip
 *       r29: user-level psr
 *       r30: user-level cfm
 *       r31: user-level pr
 *        f6-f11: cleared
 *        pr: restored (user-level pr)
 *        b0: restored (user-level rp)
 *        b6: restored
 *        b7: set to __kernel_syscall_via_epc
 *        ar.unat: restored (user-level ar.unat)
 *        ar.pfs: restored (user-level ar.pfs)
 *        ar.rsc: restored (user-level ar.rsc)
 *        ar.rnat: restored (user-level ar.rnat)
 *        ar.bspstore: restored (user-level ar.bspstore)
 *        ar.fpsr: restored (user-level ar.fpsr)
 *        ar.ccv: cleared
 *        ar.csd: cleared
 *        ar.ssd: cleared
 */
GLOBAL_ENTRY(ia64_leave_hypercall)
    PT_REGS_UNWIND_INFO(0)
    /*
     * work.need_resched etc. mustn't get changed by this CPU before it returns to
     * user- or fsys-mode, hence we disable interrupts early on.
     *
     * p6 controls whether current_thread_info()->flags needs to be check for
     * extra work.  We always check for extra work when returning to user-level.
     * With CONFIG_PREEMPT, we also check for extra work when the preempt_count
     * is 0.  After extra work processing has been completed, execution
     * resumes at .work_processed_syscall with p6 set to 1 if the extra-work-check
     * needs to be redone.
     */
    ;;
    adds r16=PT(R8)+16,r12
    ;;
    st8 [r16]=r8
    ;;
(pUStk) rsm psr.i
    cmp.eq pLvSys,p0=r0,r0		// pLvSys=1: leave from syscall
(pUStk) cmp.eq.unc p6,p0=r0,r0		// p6 <- pUStk
    ;;
    br.call.sptk.many b0=leave_hypervisor_tail
.work_processed_syscall:
    //clean up bank 1 registers
    ;;
    adds r16=PT(R8)+16,r12
    ;;
    ld8 r8=[r16]
    ;;
    mov r16=r0
    mov r17=r0
    mov r18=r0
    mov r19=r0
    mov r20=r0
    mov r21=r0
    mov r22=r0
    mov r23=r0
    mov r24=r0
    mov r25=r0
    mov r26=r0
    mov r27=r0
    mov r28=r0
    mov r29=r0
    mov r30=r0
    mov r31=r0
    bsw.0
    ;;
    adds r2=PT(LOADRS)+16,r12
    adds r3=PT(AR_BSPSTORE)+16,r12
#ifndef XEN
    adds r18=TI_FLAGS+IA64_TASK_SIZE,r13
    ;;
(p6) ld4 r31=[r18]				// load current_thread_info()->flags
#endif
    ;;
    ld8 r20=[r2],PT(B6)-PT(LOADRS)		// load ar.rsc value for "loadrs"
    nop.i 0
    ;;
//  mov r16=ar.bsp				// M2  get existing backing store pointer
    ld8 r18=[r2],PT(R9)-PT(B6)		// load b6
#ifndef XEN
(p6)    and r15=TIF_WORK_MASK,r31		// any work other than TIF_SYSCALL_TRACE?
#endif
    ;;
    ld8 r24=[r3],PT(R11)-PT(AR_BSPSTORE)	// load ar.bspstore (may be garbage)
#ifndef XEN
(p6)    cmp4.ne.unc p6,p0=r15, r0		// any special work pending?
(p6)    br.cond.spnt .work_pending_syscall
#endif
    ;;
    // start restoring the state saved on the kernel stack (struct pt_regs):
    ld8 r9=[r2],PT(CR_IPSR)-PT(R9)
    ld8 r11=[r3],PT(CR_IIP)-PT(R11)
//(pNonSys) break 0		//      bug check: we shouldn't be here if pNonSys is TRUE!
    ;;
    invala			// M0|1 invalidate ALAT
    rsm psr.i | psr.ic	// M2   turn off interrupts and interruption collection
    cmp.eq p9,p0=r0,r0	// A    set p9 to indicate that we should restore cr.ifs

    ld8 r31=[r2],32		// M0|1 load cr.ipsr
    ld8 r30=[r3],16		// M0|1 load cr.iip
    ;;
//  ld8 r29=[r2],16		// M0|1 load cr.ifs
    ld8 r28=[r3],16		// M0|1 load ar.unat
//(pUStk) add r14=IA64_TASK_THREAD_ON_USTACK_OFFSET,r13
    ;;
    ld8 r27=[r2],PT(B0)-PT(AR_PFS)	// M0|1 load ar.pfs
(pKStk) mov r22=psr			// M2   read PSR now that interrupts are disabled
    nop 0
    ;;
    ld8 r22=[r2],PT(AR_RNAT)-PT(B0) // M0|1 load b0
    ld8 r26=[r3],PT(PR)-PT(AR_RSC)	// M0|1 load ar.rsc
    mov f6=f0			// F    clear f6
    ;;
    ld8 r25=[r2],PT(AR_FPSR)-PT(AR_RNAT)	// M0|1 load ar.rnat (may be garbage)
    ld8 r23=[r3],PT(R1)-PT(PR)		// M0|1 load predicates
    mov f7=f0				// F    clear f7
    ;;
    ld8 r20=[r2],PT(R12)-PT(AR_FPSR)	// M0|1 load ar.fpsr
    ld8.fill r1=[r3],16			// M0|1 load r1
//(pUStk) mov r17=1				// A
    ;;
//(pUStk) st1 [r14]=r17				// M2|3
    ld8.fill r13=[r3],16			// M0|1
    mov f8=f0				// F    clear f8
    ;;
    ld8.fill r12=[r2]			// M0|1 restore r12 (sp)
#ifdef XEN    
    ld8.fill r2=[r3]			// M0|1
#else    
    ld8.fill r15=[r3]			// M0|1 restore r15
#endif    
    mov b6=r18				// I0   restore b6
    mov ar.fpsr=r20
//  addl r17=THIS_CPU(ia64_phys_stacked_size_p8),r0 // A
    mov f9=f0					// F    clear f9
//(pKStk) br.cond.dpnt.many skip_rbs_switch		// B

//  srlz.d				// M0   ensure interruption collection is off (for cover)
//  shr.u r18=r19,16		// I0|1 get byte size of existing "dirty" partition
    mov r3=r21
    cover				// B    add current frame into dirty partition & set cr.ifs
    ;;
//(pUStk) ld4 r17=[r17]			// M0|1 r17 = cpu_data->phys_stacked_size_p8
    mov r19=ar.bsp			// M2   get new backing store pointer
    addl r18=IA64_RBS_OFFSET, r3
    ;;
    mov r3=r0
    sub r18=r19,r18     // get byte size of existing "dirty" partition
    ;;
    shl r20=r18,16     // set rsc.load 
    mov f10=f0			// F    clear f10
#ifdef XEN
    mov r14=r0
#else
    movl r14=__kernel_syscall_via_epc // X
#endif
    ;;
    mov.m ar.csd=r0			// M2   clear ar.csd
    mov.m ar.ccv=r0			// M2   clear ar.ccv
    mov b7=r14			// I0   clear b7 (hint with __kernel_syscall_via_epc)

    mov.m ar.ssd=r0			// M2   clear ar.ssd
    mov f11=f0			// F    clear f11
    br.cond.sptk.many vmx_rbs_switch	// B
END(ia64_leave_hypercall)


/*
 * in0: new rr7
 * in1: virtual address of shared_info
 * in2: virtual address of shared_arch_info (VPD)
 * in3: virtual address of guest_vhpt
 * in4: virtual address of pal code segment
 * r8: will contain old rid value
 */


#define PSR_BITS_TO_CLEAR                      \
   (IA64_PSR_I | IA64_PSR_IT | IA64_PSR_DT | IA64_PSR_DB |IA64_PSR_RT |     \
    IA64_PSR_DD | IA64_PSR_SS | IA64_PSR_RI | IA64_PSR_ED |    \
    IA64_PSR_DFL | IA64_PSR_DFH)
#define PSR_BITS_TO_SET    IA64_PSR_BN

//extern void vmx_switch_rr7(unsigned long rid,void *shared_info, void *shared_arch_info, void *guest_vhpt, void * pal_vaddr );

GLOBAL_ENTRY(vmx_switch_rr7)
   // not sure this unwind statement is correct...
   .prologue ASM_UNW_PRLG_RP|ASM_UNW_PRLG_PFS, ASM_UNW_PRLG_GRSAVE(1)
   alloc loc1 = ar.pfs, 5, 9, 0, 0
1: {
     mov r28  = in0        // copy procedure index
     mov r8   = ip         // save ip to compute branch
     mov loc0 = rp         // save rp
    };;
    .body
    movl loc2=PERCPU_ADDR
    ;;
    tpa loc2 = loc2         // get physical address of per cpu date
    ;;
    dep loc3 = 0,in1,60,4          // get physical address of shared_info
    dep loc4 = 0,in2,60,4          // get physical address of shared_arch_info
    dep loc5 = 0,in3,60,4          // get physical address of guest_vhpt
    dep loc6 = 0,in4,60,4          // get physical address of pal code
    ;;
    mov loc7 = psr          // save psr
    ;;
    mov loc8 = ar.rsc           // save RSE configuration
    ;;
    mov ar.rsc = 0          // put RSE in enforced lazy, LE mode
    movl r16=PSR_BITS_TO_CLEAR
    movl r17=PSR_BITS_TO_SET
    ;;
    or loc7 = loc7,r17      // add in psr the bits to set
    ;;
    andcm r16=loc7,r16      // removes bits to clear from psr
    br.call.sptk.many rp=ia64_switch_mode_phys
1:
   // now in physical mode with psr.i/ic off so do rr7 switch
    dep r16=-1,r0,61,3
    ;;
    mov rr[r16]=in0
    srlz.d
    ;;
    rsm 0x6000
    ;;
    srlz.d

    // re-pin mappings for kernel text and data
    mov r18=KERNEL_TR_PAGE_SHIFT<<2
    movl r17=KERNEL_START
    ;;
    ptr.i   r17,r18
    ptr.d   r17,r18
    ;;
    mov cr.itir=r18
    mov cr.ifa=r17
    mov r16=IA64_TR_KERNEL
    //mov r3=ip
    movl r25 = PAGE_KERNEL
    ;;
    dep r2=0,r3,0,KERNEL_TR_PAGE_SHIFT
    ;;
    or r18=r2,r25
    ;;
   srlz.i
   ;;
   itr.i itr[r16]=r18
   ;;
   itr.d dtr[r16]=r18
   ;;

   // re-pin mappings for per-cpu data

   movl r22 = PERCPU_ADDR
   ;;
   mov r24=IA64_TR_PERCPU_DATA
   or loc2 = r25,loc2          // construct PA | page properties
   mov r23=PERCPU_PAGE_SHIFT<<2
   ;;
   ptr.d   r22,r23
   ;;
   mov cr.itir=r23
   mov cr.ifa=r22
   ;;
   itr.d dtr[r24]=loc2     // wire in new mapping...
   ;;

   // re-pin mappings for guest_vhpt

   mov r24=IA64_TR_VHPT
   movl r25=PAGE_KERNEL
   ;;
   or loc5 = r25,loc5          // construct PA | page properties
   mov r23 = VCPU_VHPT_SHIFT <<2
   ;;
   ptr.d   in3,r23
   ;;
   mov cr.itir=r23
   mov cr.ifa=in3
   ;;
   itr.d dtr[r24]=loc5     // wire in new mapping...
   ;;

   // re-pin mappings for PAL code section

   mov r24=IA64_TR_PALCODE
   or loc6 = r25,loc6          // construct PA | page properties
   mov r23 = IA64_GRANULE_SHIFT<<2
   ;;
   ptr.i   in4,r23
   ;;
   mov cr.itir=r23
   mov cr.ifa=in4
   ;;
   itr.i itr[r24]=loc6     // wire in new mapping...
   ;;

   // done, switch back to virtual and return
   mov r16=loc7            // r16= original psr
   br.call.sptk.many rp=ia64_switch_mode_virt // return to virtual mode
   mov ar.pfs = loc1
   mov rp = loc0
   ;;
   mov ar.rsc=loc8         // restore RSE configuration
   srlz.d              // seralize restoration of psr.l
   br.ret.sptk.many rp
END(vmx_switch_rr7)
