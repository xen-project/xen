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

#include "vmx_minstate.h"

/*
 * prev_task <- vmx_ia64_switch_to(struct task_struct *next)
 *	With Ingo's new scheduler, interrupts are disabled when this routine gets
 *	called.  The code starting at .map relies on this.  The rest of the code
 *	doesn't care about the interrupt masking status.
 *
 * Since we allocate domain stack in xenheap, there's no need to map new
 * domain's stack since all xenheap is mapped by TR. Another different task
 * for vmx_ia64_switch_to is to switch to bank0 and change current pointer.
 */
GLOBAL_ENTRY(vmx_ia64_switch_to)
	.prologue
	alloc r16=ar.pfs,1,0,0,0
	DO_SAVE_SWITCH_STACK
	.body

	bsw.0	// Switch to bank0, because bank0 r21 is current pointer
	;;
	adds r22=IA64_TASK_THREAD_KSP_OFFSET,r13
	movl r25=init_task
	adds r26=IA64_TASK_THREAD_KSP_OFFSET,in0
	;;
	st8 [r22]=sp			// save kernel stack pointer of old task
	;;
	/*
	 * TR always mapped this task's page, we can skip doing it again.
	 */
	ld8 sp=[r26]			// load kernel stack pointer of new task
	mov r21=in0			// update "current" application register
	mov r8=r13			// return pointer to previously running task
	mov r13=in0			// set "current" pointer
	;;
	bsw.1
	;;
	DO_LOAD_SWITCH_STACK

#ifdef CONFIG_SMP
	sync.i				// ensure "fc"s done by this CPU are visible on other CPUs
#endif
	br.ret.sptk.many rp		// boogie on out in new context
END(vmx_ia64_switch_to)

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



GLOBAL_ENTRY(ia64_leave_hypervisor)
    PT_REGS_UNWIND_INFO(0)
    /*
     * work.need_resched etc. mustn't get changed by this CPU before it returns to
    ;;
     * user- or fsys-mode, hence we disable interrupts early on:
     */
    rsm psr.i
    ;;
    alloc loc0=ar.pfs,0,1,1,0
    adds out0=16,r12
    ;;
    br.call.sptk.many b0=vmx_deliver_pending_interrupt
    mov ar.pfs=loc0
    adds r8=IA64_VPD_BASE_OFFSET,r13
    ;;
    ld8 r8=[r8]
    ;;
    adds r9=VPD(VPSR),r8
    ;;
    ld8 r9=[r9]
    ;;
    tbit.z pBN0,pBN1=r9,IA64_PSR_BN_BIT
    ;;
(pBN0) add r7=VPD(VBNAT),r8;
(pBN1) add r7=VPD(VNAT),r8;
    ;;
    ld8 r7=[r7]
    ;;
    mov ar.unat=r7
(pBN0) add r4=VPD(VBGR),r8;
(pBN1) add r4=VPD(VGR),r8;
(pBN0) add r5=VPD(VBGR)+0x8,r8;
(pBN1) add r5=VPD(VGR)+0x8,r8;
    ;;
    ld8.fill r16=[r4],16
    ld8.fill r17=[r5],16
    ;;
    ld8.fill r18=[r4],16
    ld8.fill r19=[r5],16
    ;;
    ld8.fill r20=[r4],16
    ld8.fill r21=[r5],16
    ;;
    ld8.fill r22=[r4],16
    ld8.fill r23=[r5],16
    ;;
    ld8.fill r24=[r4],16
    ld8.fill r25=[r5],16
    ;;
    ld8.fill r26=[r4],16
    ld8.fill r27=[r5],16
    ;;
    ld8.fill r28=[r4],16
    ld8.fill r29=[r5],16
    ;;
    ld8.fill r30=[r4],16
    ld8.fill r31=[r5],16
    ;;
    bsw.0
    ;;
    mov r18=r8      //vpd
    mov r19=r9      //vpsr
    adds r20=PT(PR)+16,r12
    ;;
    lfetch [r20],PT(CR_IPSR)-PT(PR)
    adds r16=PT(B6)+16,r12
    adds r17=PT(B7)+16,r12
    ;;
    lfetch [r20]
    mov r21=r13		// get current
    ;;
    ld8 r30=[r16],16      // load b6
    ld8 r31=[r17],16      // load b7
    add r20=PT(EML_UNAT)+16,r12
    ;;
    ld8 r29=[r20]       //load ar_unat
    mov b6=r30
    mov b7=r31
    ld8 r30=[r16],16    //load ar_csd
    ld8 r31=[r17],16    //load ar_ssd
    ;;
    mov ar.unat=r29
    mov ar.csd=r30
    mov ar.ssd=r31
    ;;
    ld8.fill r8=[r16],16    //load r8
    ld8.fill r9=[r17],16    //load r9
    ;;
    ld8.fill r10=[r16],PT(R1)-PT(R10)    //load r10
    ld8.fill r11=[r17],PT(R12)-PT(R11)    //load r11
    ;;
    ld8.fill r1=[r16],16    //load r1
    ld8.fill r12=[r17],16    //load r12
    ;;
    ld8.fill r13=[r16],16    //load r13
    ld8 r30=[r17],16    //load ar_fpsr
    ;;
    ld8.fill r15=[r16],16    //load r15
    ld8.fill r14=[r17],16    //load r14
    mov ar.fpsr=r30
    ;;
    ld8.fill r2=[r16],16    //load r2
    ld8.fill r3=[r17],16    //load r3
    ;;
/*
(pEml) ld8.fill r4=[r16],16    //load r4
(pEml) ld8.fill r5=[r17],16    //load r5
    ;;
(pEml) ld8.fill r6=[r16],PT(AR_CCV)-PT(R6)   //load r6
(pEml) ld8.fill r7=[r17],PT(F7)-PT(R7)   //load r7
    ;;
(pNonEml) adds r16=PT(AR_CCV)-PT(R4),r16
(pNonEml) adds r17=PT(F7)-PT(R5),r17
    ;;
*/
    ld8.fill r4=[r16],16    //load r4
    ld8.fill r5=[r17],16    //load r5
     ;;
    ld8.fill r6=[r16],PT(AR_CCV)-PT(R6)   //load r6
    ld8.fill r7=[r17],PT(F7)-PT(R7)   //load r7
    ;;

    ld8 r30=[r16],PT(F6)-PT(AR_CCV)
    rsm psr.i | psr.ic  // initiate turning off of interrupt and interruption collection
    ;;
    srlz.i          // ensure interruption collection is off
    ;;
    invala          // invalidate ALAT
    ;;
    ldf.fill f6=[r16],32
    ldf.fill f7=[r17],32
    ;;
    ldf.fill f8=[r16],32
    ldf.fill f9=[r17],32
    ;;
    ldf.fill f10=[r16]
    ldf.fill f11=[r17]
    ;;
    mov ar.ccv=r30
    adds r16=PT(CR_IPSR)-PT(F10),r16
    adds r17=PT(CR_IIP)-PT(F11),r17
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
    ld8 r25=[r16],16    // load ar.rnat (may be garbage)
    ld8 r24=[r17],16// load ar.bspstore (may be garbage)
    ;;
    ld8 r23=[r16],16    // load predicates
    ld8 r22=[r17],PT(RFI_PFS)-PT(B0)    // load b0
    ;;
    ld8 r20=[r16],16    // load ar.rsc value for "loadrs"
    ;;
//rbs_switch
    // loadrs has already been shifted
    alloc r16=ar.pfs,0,0,0,0    // drop current register frame
    ;;
    mov ar.rsc=r20
    ;;
    loadrs
    ;;
    mov ar.bspstore=r24
    ;;
    ld8 r24=[r17]       //load rfi_pfs
    mov ar.unat=r28
    mov ar.rnat=r25
    mov ar.rsc=r26
    ;;
    mov cr.ipsr=r31
    mov cr.iip=r30
    mov cr.ifs=r29
    cmp.ne p6,p0=r24,r0
(p6)br.sptk vmx_dorfirfi
    ;;
vmx_dorfirfi_back:
    mov ar.pfs=r27

//vsa_sync_write_start
    movl r20=__vsa_base
    ;;
    ld8 r20=[r20]       // read entry point
    mov r25=r18
    ;;
    add r16=PAL_VPS_SYNC_WRITE,r20
    movl r24=switch_rr7  // calculate return address
    ;;
    mov b0=r16
    br.cond.sptk b0         // call the service
    ;;
// switch rr7 and rr5
switch_rr7:
    adds r24=SWITCH_MRR5_OFFSET, r21
    adds r26=SWITCH_MRR6_OFFSET, r21
    adds r16=SWITCH_MRR7_OFFSET ,r21
    movl r25=(5<<61)
    movl r27=(6<<61)
    movl r17=(7<<61)
    ;;
    ld8 r24=[r24]
    ld8 r26=[r26]
    ld8 r16=[r16]
    ;;
    mov rr[r25]=r24
    mov rr[r27]=r26
    mov rr[r17]=r16
    ;;
    srlz.i
    ;;
    add r24=SWITCH_MPTA_OFFSET, r21
    ;;
    ld8 r24=[r24]
    ;;
    mov cr.pta=r24
    ;;
    srlz.i
    ;;
// fall through
GLOBAL_ENTRY(ia64_vmm_entry)
/*
 *  must be at bank 0
 *  parameter:
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
    (p2) add r29=PAL_VPS_RESUME_HANDLER,r20
    ;;
    mov pr=r23,-2
    mov b0=r29
    ;;
    br.cond.sptk b0             // call pal service
END(ia64_leave_hypervisor)

//r24 rfi_pfs
//r17 address of rfi_pfs
GLOBAL_ENTRY(vmx_dorfirfi)
    mov r16=ar.ec
    movl r20 = vmx_dorfirfi_back
	;;
// clean rfi_pfs
    st8 [r17]=r0
    mov b0=r20
// pfs.pec=ar.ec
    dep r24 = r16, r24, 52, 6
    ;;
    mov ar.pfs=r24
	;;
    br.ret.sptk b0
	;;
END(vmx_dorfirfi)


#define VMX_PURGE_RR7	0
#define VMX_INSERT_RR7	1
/*
 * in0: old rr7
 * in1: virtual address of xen image
 * in2: virtual address of vhpt table
 */
GLOBAL_ENTRY(vmx_purge_double_mapping)
    alloc loc1 = ar.pfs,5,9,0,0
    mov loc0 = rp
    movl r8 = 1f
    ;;
    movl loc4 = KERNEL_TR_PAGE_SHIFT
    movl loc5 = VCPU_TLB_SHIFT
    mov loc6 = psr
    movl loc7 = XEN_RR7_SWITCH_STUB
    mov loc8 = (1<<VMX_PURGE_RR7)
    ;;
    srlz.i
    ;;
    rsm psr.i | psr.ic
    ;;
    srlz.i
    ;;
    mov ar.rsc = 0
    mov b6 = loc7
    mov rp = r8
    ;;
    br.sptk b6
1:
    mov ar.rsc = 3
    mov rp = loc0
    ;;
    mov psr.l = loc6
    ;;
    srlz.i
    ;;
    br.ret.sptk rp
END(vmx_purge_double_mapping)

/*
 * in0: new rr7
 * in1: virtual address of xen image
 * in2: virtual address of vhpt table
 * in3: pte entry of xen image
 * in4: pte entry of vhpt table
 */
GLOBAL_ENTRY(vmx_insert_double_mapping)
    alloc loc1 = ar.pfs,5,9,0,0
    mov loc0 = rp
    movl loc2 = IA64_TR_XEN_IN_DOM // TR number for xen image
    ;;
    movl loc3 = IA64_TR_VHPT_IN_DOM	// TR number for vhpt table
    movl r8 = 1f
    movl loc4 = KERNEL_TR_PAGE_SHIFT
    ;;
    movl loc5 = VCPU_TLB_SHIFT
    mov loc6 = psr
    movl loc7 = XEN_RR7_SWITCH_STUB
    ;;
    srlz.i
    ;;
    rsm psr.i | psr.ic
    mov loc8 = (1<<VMX_INSERT_RR7)
    ;;
    srlz.i
    ;;
    mov ar.rsc = 0
    mov b6 = loc7
    mov rp = r8
    ;;
    br.sptk b6
1:
    mov ar.rsc = 3
    mov rp = loc0
    ;;
    mov psr.l = loc6
    ;;
    srlz.i
    ;;
    br.ret.sptk rp
END(vmx_insert_double_mapping)

    .align PAGE_SIZE
/*
 * Stub to add double mapping for new domain, which shouldn't
 * access any memory when active. Before reaching this point,
 * both psr.i/ic is cleared and rse is set in lazy mode.
 *
 * in0: new rr7
 * in1: virtual address of xen image
 * in2: virtual address of vhpt table
 * in3: pte entry of xen image
 * in4: pte entry of vhpt table
 * loc2: TR number for xen image
 * loc3: TR number for vhpt table
 * loc4: page size for xen image
 * loc5: page size of vhpt table
 * loc7: free to use
 * loc8: purge or insert
 * r8: will contain old rid value
 */
GLOBAL_ENTRY(vmx_switch_rr7)
    movl loc7 = (7<<61)
    dep.z loc4 = loc4, 2, 6
    dep.z loc5 = loc5, 2, 6
    ;;
    tbit.nz p6,p7=loc8, VMX_INSERT_RR7
    mov r8 = rr[loc7]
    ;;
    mov rr[loc7] = in0
(p6)mov cr.ifa = in1
(p6)mov cr.itir = loc4
    ;;
    srlz.i
    ;;
(p6)itr.i itr[loc2] = in3
(p7)ptr.i in1, loc4
    ;;
(p6)itr.d dtr[loc2] = in3
(p7)ptr.d in1, loc4
    ;;
    srlz.i
    ;;
(p6)mov cr.ifa = in2
(p6)mov cr.itir = loc5
    ;;
(p6)itr.d dtr[loc3] = in4
(p7)ptr.d in2, loc5
    ;;
    srlz.i
    ;;
    mov rr[loc7] = r8
    ;;
    srlz.i
    br.sptk rp
END(vmx_switch_rr7)
    .align PAGE_SIZE
