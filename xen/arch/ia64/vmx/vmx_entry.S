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
    adds r7 = PT(EML_UNAT)+16,r12
    ;;
    ld8 r7 = [r7]
    br.call.sptk.many b0=leave_hypervisor_tail
    ;;
    mov ar.pfs=loc0
    mov ar.unat=r7
    adds r20=PT(PR)+16,r12
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
    ld8.fill r4=[r2],16    //load r4
    ld8.fill r5=[r3],16    //load r5
    ;;
    ld8.fill r6=[r2]    //load r6
    ld8.fill r7=[r3]    //load r7
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
    ld8.fill r3=[r16]    //load r3
    ld8 r18=[r17],PT(RFI_PFS)-PT(AR_CCV)           //load ar_ccv
    ;;
    mov ar.fpsr=r19
    mov ar.ccv=r18
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
    adds r18=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r18]   //vpd
    ;;
    adds r19=VPD(VPSR),r18
    ;;
    ld8 r19=[r19]        //vpsr
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
switch_rr7:
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

#ifdef XEN_DBL_MAPPING  /* will be removed */

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

#else
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


#if    0
   // re-pin mappings for shared_info

   mov r24=IA64_TR_SHARED_INFO
   movl r25=__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RW)
   ;;
   or loc3 = r25,loc3          // construct PA | page properties
   mov r23 = PAGE_SHIFT<<2
   ;;
   ptr.d   in1,r23
   ;;
   mov cr.itir=r23
   mov cr.ifa=in1
   ;;
   itr.d dtr[r24]=loc3     // wire in new mapping...
   ;;
   // re-pin mappings for shared_arch_info

   mov r24=IA64_TR_ARCH_INFO
   or loc4 = r25,loc4          // construct PA | page properties
   mov r23 = PAGE_SHIFT<<2
   ;;
   ptr.d   in2,r23
   ;;
   mov cr.itir=r23
   mov cr.ifa=in2
   ;;
   itr.d dtr[r24]=loc4     // wire in new mapping...
   ;;
#endif


   // re-pin mappings for guest_vhpt

   mov r24=IA64_TR_PERVP_VHPT
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
#endif

