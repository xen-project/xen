/*
 * Assembly support routines for Xen/ia64
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <asm/asmmacro.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/vhpt.h>
#include <asm/asm-xsi-offsets.h>
#include <public/xen.h>
	
// Change rr7 to the passed value while ensuring
// Xen is mapped into the new region.
#define PSR_BITS_TO_CLEAR						\
	(IA64_PSR_I | IA64_PSR_IT | IA64_PSR_DT | IA64_PSR_RT |		\
	 IA64_PSR_DD | IA64_PSR_SS | IA64_PSR_RI | IA64_PSR_ED |	\
	 IA64_PSR_DFL | IA64_PSR_DFH | IA64_PSR_IC)
// FIXME? Note that this turns off the DB bit (debug)
#define PSR_BITS_TO_SET	IA64_PSR_BN

//extern void ia64_new_rr7(unsigned long rid,      	 /* in0 */
//                         void *shared_info,      	 /* in1 */
//                         void *shared_arch_info, 	 /* in2 */
//                         unsigned long shared_info_va, /* in3 */
//                         unsigned long va_vhpt)   	 /* in4 */
//Local usage:
//  loc0=rp, loc1=ar.pfs, loc2=percpu_paddr, loc3=psr, loc4=ar.rse
//  loc5=pal_vaddr, loc6=xen_paddr, loc7=shared_archinfo_paddr,
//  r16, r19, r20 are used by ia64_switch_mode_{phys, virt}()
GLOBAL_ENTRY(ia64_new_rr7)
	// FIXME? not sure this unwind statement is correct...
	.prologue ASM_UNW_PRLG_RP|ASM_UNW_PRLG_PFS, ASM_UNW_PRLG_GRSAVE(1)
	alloc loc1 = ar.pfs, 5, 8, 0, 0
	movl loc2=PERCPU_ADDR
1:	{
	  mov loc3 = psr		// save psr	
	  mov loc0 = rp			// save rp
	  mov r8   = ip			// save ip to compute branch
	};;
	.body
	tpa loc2=loc2			// grab this BEFORE changing rr7
	tpa in1=in1			// grab shared_info BEFORE changing rr7
	adds r8 = 1f-1b,r8		// calculate return address for call
	;;
	tpa loc7=in2			// grab arch_vcpu_info BEFORE chg rr7
	movl r17=PSR_BITS_TO_SET
	mov loc4=ar.rsc			// save RSE configuration
	movl r16=PSR_BITS_TO_CLEAR
	;; 
	tpa r8=r8			// convert rp to physical
	mov ar.rsc=0			// put RSE in enforced lazy, LE mode
	or loc3=loc3,r17		// add in psr the bits to set
	;;
	andcm r16=loc3,r16		// removes bits to clear from psr
	dep loc6=0,r8,0,KERNEL_TR_PAGE_SHIFT // Xen code paddr
	br.call.sptk.many rp=ia64_switch_mode_phys
1:
	// now in physical mode with psr.i/ic off so do rr7 switch
	movl r16=pal_vaddr		// Note: belong to region 7!
	;; 
	mov	rr[r16]=in0
	;; 
	srlz.d
	dep	r16=0,r16,60,4		// Get physical address.
	;;
	ld8 loc5=[r16]			// read pal_vaddr
	movl	r26=PAGE_KERNEL
	;; 

	// re-pin mappings for kernel text and data
	mov r24=KERNEL_TR_PAGE_SHIFT<<2
	movl r17=KERNEL_START
	;;
	ptr.i	r17,r24
	ptr.d	r17,r24
	mov r16=IA64_TR_KERNEL
	mov cr.itir=r24
	mov cr.ifa=r17
	or r18=loc6,r26
	;;
	itr.i itr[r16]=r18
	;; 
	itr.d dtr[r16]=r18

	// re-pin mappings for stack (current)

	// unless overlaps with KERNEL_TR
	dep r18=0,r13,0,KERNEL_TR_PAGE_SHIFT
	;;
	cmp.eq p7,p0=r17,r18
(p7)	br.cond.sptk	.stack_overlaps
	mov r25=IA64_GRANULE_SHIFT<<2
	dep r21=0,r13,60,4		// physical address of "current"
	;;
	ptr.d	r13,r25
	or r23=r21,r26			// construct PA | page properties
	mov cr.itir=r25
	mov cr.ifa=r13			// VA of next task...
	mov r21=IA64_TR_CURRENT_STACK
	;;
	itr.d dtr[r21]=r23		// wire in new mapping...

	//  Per-cpu	
.stack_overlaps:
	mov r24=PERCPU_PAGE_SHIFT<<2
	movl r22=PERCPU_ADDR
	;;
	ptr.d	r22,r24
	or r23=loc2,r26			// construct PA | page properties
	mov cr.itir=r24
	mov cr.ifa=r22
	mov r25=IA64_TR_PERCPU_DATA
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...

	// VHPT
#if VHPT_ENABLED
#if IA64_GRANULE_SHIFT < VHPT_SIZE_LOG2
#error "it must be that VHPT_SIZE_LOG2 <= IA64_GRANULE_SHIFT"
#endif	
	// unless overlaps with KERNEL_TR and IA64_TR_CURRENT_STACK
	dep r14=0,in4,0,KERNEL_TR_PAGE_SHIFT
	dep r15=0,in4,0,IA64_GRANULE_SHIFT
	dep r21=0,r13,0,IA64_GRANULE_SHIFT
	;;
	cmp.eq p7,p0=r17,r14
	cmp.eq p8,p0=r15,r21
(p7)	br.cond.sptk	.vhpt_overlaps
(p8)	br.cond.sptk	.vhpt_overlaps
	mov r21=IA64_TR_VHPT
	dep r22=0,r15,60,4		// physical address of
	                                // va_vhpt & ~(IA64_GRANULE_SIZE - 1)
	mov r24=IA64_GRANULE_SHIFT<<2
	;;
	ptr.d	r15,r24
	or r23=r22,r26			// construct PA | page properties
	mov cr.itir=r24
	mov cr.ifa=r15
	srlz.d
	;;
	itr.d dtr[r21]=r23		// wire in new mapping...
.vhpt_overlaps:	
#endif

	//  Shared info
	mov r24=XSI_SHIFT<<2
	movl r25=__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RW)
	;;
	ptr.d	in3,r24
	or r23=in1,r25			// construct PA | page properties
	mov cr.itir=r24
	mov cr.ifa=in3
	mov r21=IA64_TR_SHARED_INFO
	;;
	itr.d dtr[r21]=r23		// wire in new mapping...
	
	// Map mapped_regs
	mov r22=XMAPPEDREGS_OFS
	mov r24=XMAPPEDREGS_SHIFT<<2
	;; 
	add r22=r22,in3
	;;
	ptr.d	r22,r24
	or r23=loc7,r25			// construct PA | page properties
	mov cr.itir=r24
	mov cr.ifa=r22
	mov r21=IA64_TR_MAPPED_REGS
	;;
	itr.d dtr[r21]=r23		// wire in new mapping...

	// Purge/insert PAL TR
	mov r24=IA64_TR_PALCODE
	mov r23=IA64_GRANULE_SHIFT<<2
	dep r25=0,loc5,60,4		// convert pal vaddr to paddr
	;;
	ptr.i	loc5,r23
	or r25=r25,r26			// construct PA | page properties
	mov cr.itir=r23
	mov cr.ifa=loc5
	;;
	itr.i itr[r24]=r25

	// done, switch back to virtual and return
	mov r16=loc3			// r16= original psr
	br.call.sptk.many rp=ia64_switch_mode_virt // return to virtual mode
	mov psr.l = loc3		// restore init PSR

	mov ar.pfs = loc1
	mov rp = loc0
	;;
	mov ar.rsc=loc4			// restore RSE configuration
	srlz.d				// seralize restoration of psr.l
	br.ret.sptk.many rp
END(ia64_new_rr7)

#if 0 /* Not used */
#include "minstate.h"

GLOBAL_ENTRY(ia64_prepare_handle_privop)
	.prologue
	/*
	 * r16 = fake ar.pfs, we simply need to make sure privilege is still 0
	 */
	mov r16=r0
	DO_SAVE_SWITCH_STACK
	br.call.sptk.many rp=ia64_handle_privop	// stack frame setup in ivt
.ret22:	.body
	DO_LOAD_SWITCH_STACK
	br.cond.sptk.many rp			// goes to ia64_leave_kernel
END(ia64_prepare_handle_privop)

GLOBAL_ENTRY(ia64_prepare_handle_break)
	.prologue
	/*
	 * r16 = fake ar.pfs, we simply need to make sure privilege is still 0
	 */
	mov r16=r0
	DO_SAVE_SWITCH_STACK
	br.call.sptk.many rp=ia64_handle_break	// stack frame setup in ivt
.ret23:	.body
	DO_LOAD_SWITCH_STACK
	br.cond.sptk.many rp			// goes to ia64_leave_kernel
END(ia64_prepare_handle_break)

GLOBAL_ENTRY(ia64_prepare_handle_reflection)
	.prologue
	/*
	 * r16 = fake ar.pfs, we simply need to make sure privilege is still 0
	 */
	mov r16=r0
	DO_SAVE_SWITCH_STACK
	br.call.sptk.many rp=ia64_handle_reflection // stack frame setup in ivt
.ret24:	.body
	DO_LOAD_SWITCH_STACK
	br.cond.sptk.many rp			// goes to ia64_leave_kernel
END(ia64_prepare_handle_reflection)
#endif

GLOBAL_ENTRY(__get_domain_bundle)
	EX(.failure_in_get_bundle,ld8 r8=[r32],8)
	;;
	EX(.failure_in_get_bundle,ld8 r9=[r32])
	;;
	br.ret.sptk.many rp
	;;
.failure_in_get_bundle:
	mov r8=0
	;;
	mov r9=0
	;;
	br.ret.sptk.many rp
	;;
END(__get_domain_bundle)

/* derived from linux/arch/ia64/hp/sim/boot/boot_head.S */
GLOBAL_ENTRY(pal_emulator_static)
	mov r8=-1
	mov r9=256
	;;
	cmp.gtu p7,p8=r9,r32		/* r32 <= 255? */
(p7)	br.cond.sptk.few static
	;;
	mov r9=512
	;;
	cmp.gtu p7,p8=r9,r32
(p7)	br.cond.sptk.few stacked
	;;
static:	cmp.eq p7,p8=6,r32		/* PAL_PTCE_INFO */
(p8)	br.cond.sptk.few 1f
	;;
	mov r8=0			/* status = 0 */
	movl r9=0x100000000		/* tc.base */
	movl r10=0x0000000200000003	/* count[0], count[1] */
	movl r11=0x1000000000002000	/* stride[0], stride[1] */
	br.ret.sptk.few rp
1:	cmp.eq p7,p8=14,r32		/* PAL_FREQ_RATIOS */
(p8)	br.cond.sptk.few 1f
	mov r8=0			/* status = 0 */
	movl r9 =0x900000002		/* proc_ratio (1/100) */
	movl r10=0x100000100		/* bus_ratio<<32 (1/256) */
	movl r11=0x900000002		/* itc_ratio<<32 (1/100) */
	;;
1:	cmp.eq p7,p8=19,r32		/* PAL_RSE_INFO */
(p8)	br.cond.sptk.few 1f
	mov r8=0			/* status = 0 */
	mov r9=96			/* num phys stacked */
	mov r10=0			/* hints */
	mov r11=0
	br.ret.sptk.few rp
1:	cmp.eq p7,p8=1,r32		/* PAL_CACHE_FLUSH */
(p8)	br.cond.sptk.few 1f
#if 0
	mov r9=ar.lc
	movl r8=524288		/* flush 512k million cache lines (16MB) */
	;;
	mov ar.lc=r8
	movl r8=0xe000000000000000
	;;
.loop:	fc r8
	add r8=32,r8
	br.cloop.sptk.few .loop
	sync.i
	;;
	srlz.i
	;;
	mov ar.lc=r9
	mov r8=r0
	;;
1:	cmp.eq p7,p8=15,r32		/* PAL_PERF_MON_INFO */
(p8)	br.cond.sptk.few 1f
	mov r8=0			/* status = 0 */
	movl r9 =0x08122f04		/* generic=4 width=47 retired=8 
					 * cycles=18
					 */
	mov r10=0			/* reserved */
	mov r11=0			/* reserved */
	mov r16=0xffff			/* implemented PMC */
	mov r17=0x3ffff			/* implemented PMD */
	add r18=8,r29			/* second index */
	;;
	st8 [r29]=r16,16		/* store implemented PMC */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
	st8 [r29]=r0,16			/* clear remaining bits  */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
	st8 [r29]=r17,16		/* store implemented PMD */
	st8 [r18]=r0,16			/* clear remaining bits  */
	mov r16=0xf0			/* cycles count capable PMC */
	;;
	st8 [r29]=r0,16			/* clear remaining bits  */
	st8 [r18]=r0,16			/* clear remaining bits  */
	mov r17=0xf0			/* retired bundles capable PMC */
	;;
	st8 [r29]=r16,16		/* store cycles capable */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
	st8 [r29]=r0,16			/* clear remaining bits  */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
	st8 [r29]=r17,16		/* store retired bundle capable */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
	st8 [r29]=r0,16			/* clear remaining bits  */
	st8 [r18]=r0,16			/* clear remaining bits  */
	;;
1:	br.cond.sptk.few rp
#else
1:
#endif
stacked:
	br.ret.sptk.few rp
END(pal_emulator_static)

//  These instructions are copied in the domains.
//  This is the virtual PAL, which simply does a hypercall.
//  The size is 2 bundles (32 Bytes).  It handles both static and stacked
//    convention.
//  If you modify this code, you have to modify dom_fw.h (for the size) and
//   dom_fw_pal_hypercall_patch.
GLOBAL_ENTRY(pal_call_stub)
	{
	 .mii
	addl r2=0x1000,r0	//  Hypercall number (Value is patched).
	mov r9=256
	;; 
	cmp.gtu p7,p8=r9,r28		/* r32 <= 255? */
	}
	{
	 .mbb
	break 0x1000		//  Hypercall vector (Value is patched).
(p7)	br.cond.sptk.few rp
(p8)	br.ret.sptk.few rp
	}
END(pal_call_stub)


