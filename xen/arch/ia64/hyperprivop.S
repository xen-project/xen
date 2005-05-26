/*
 * arch/ia64/kernel/hyperprivop.S
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>

#include <asm/asmmacro.h>
#include <asm/kregs.h>
#include <asm/offsets.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <public/arch-ia64.h>

// Note: not hand-scheduled for now
//  Registers at entry
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC_OFS
//	r19 == vpsr.ic (low 32 bits) | vpsr.i (high 32 bits)
//	r31 == pr
GLOBAL_ENTRY(fast_hyperprivop)
	//cover;;
	// if domain interrupts pending, give up for now and do it the slow way
	adds r20=XSI_PEND_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20] ;;
	cmp.ne p7,p0=r0,r20
(p7)	br.sptk.many dispatch_break_fault ;;

	// HYPERPRIVOP_RFI?
	cmp.eq p7,p6=XEN_HYPER_RFI,r17
(p7)	br.sptk.many hyper_rfi;;
	// if not rfi, give up for now and do it the slow way
	br.sptk.many dispatch_break_fault ;;

// ensure that, if giving up, registers at entry to fast_hyperprivop unchanged
ENTRY(hyper_rfi)
	adds r20=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r20];;		// r21 = vcr.ipsr
	extr.u r22=r21,IA64_PSR_BE_BIT,1 ;;
	// if turning on psr.be, give up for now and do it the slow way
	cmp.ne p7,p0=r22,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	// if (!(vpsr.dt && vpsr.rt && vpsr.it)), do it the slow way
	movl r20=(IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_IT);;
	and r22=r20,r21
	;;
	cmp.ne p7,p0=r22,r20
(p7)	br.sptk.many dispatch_break_fault ;;
	// if was in metaphys mode, do it the slow way (FIXME later?)
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r20=[r20];;
	cmp.ne p7,p0=r20,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	// if domain hasn't already done virtual bank switch
	//  do it the slow way (FIXME later?)
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r20=[r20];;
	cmp.eq p7,p0=r20,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	// validate vcr.iip, if in Xen range, do it the slow way
	adds r20=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r22=[r20];;
	movl r23=XEN_VIRT_SPACE_LOW
	movl r24=XEN_VIRT_SPACE_HIGH ;;
	cmp.ltu p0,p7=r22,r23 ;;	// if !(iip<low) &&
(p7)	cmp.geu p0,p7=r22,r24 ;;	//    !(iip>=high)
(p7)	br.sptk.many dispatch_break_fault ;;

	// OK now, let's do an rfi.
	// r18=&vpsr.i|vpsr.ic, r21==vpsr, r20==&vcr.iip, r22=vcr.iip
	mov cr.iip=r22;;
	adds r20=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
	adds r20=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	dep r20=0,r20,38,25;; // ensure ifs has no reserved bits set
	mov cr.ifs=r20 ;;
// TODO: increment a counter so we can count how many rfi's go the fast way
//    but where?  counter must be pinned
	// ipsr.cpl == (vcr.ipsr.cpl == 0) 2 : 3;
	dep r21=-1,r21,IA64_PSR_CPL1_BIT,1 ;;
	// vpsr.i = vcr.ipsr.i; vpsr.ic = vcr.ipsr.ic
	mov r19=r0 ;;
	extr.u r22=r21,IA64_PSR_I_BIT,1 ;;
	cmp.ne p7,p6=r22,r0 ;;
(p7)	dep r19=-1,r19,32,1
	extr.u r22=r21,IA64_PSR_IC_BIT,1 ;;
	cmp.ne p7,p6=r22,r0 ;;
(p7)	dep r19=-1,r19,0,1 ;;
	st8 [r18]=r19 ;;
	// force on psr.ic, i, dt, rt, it, bn
	movl r20=(IA64_PSR_I|IA64_PSR_IC|IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_IT|IA64_PSR_BN)
	;;
	or r21=r21,r20
	;;
	mov cr.ipsr=r21
	mov pr=r31,-1
	;;
	rfi
	;;
