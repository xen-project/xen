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

#if 0
	// HYPERPRIVOP_SSM_I?
	cmp.eq p7,p6=XEN_HYPER_SSM_I,r17
(p7)	br.sptk.many hyper_ssm_i;;
#endif

#if 1
// hard to test, because only called from rbs_switch
	// HYPERPRIVOP_COVER?
	cmp.eq p7,p6=XEN_HYPER_COVER,r17
(p7)	br.sptk.many hyper_cover;;
#endif

#if 0 // FIXME: This inexplicably causes the number of ssm_dt's to
      // skyrocket, thus slowing down everything
	// HYPERPRIVOP_SSM_DT?
	cmp.eq p7,p6=XEN_HYPER_SSM_DT,r17
(p7)	br.sptk.many hyper_ssm_dt;;
#endif

#if 1
	// HYPERPRIVOP_RSM_DT?
	cmp.eq p7,p6=XEN_HYPER_RSM_DT,r17
(p7)	br.sptk.many hyper_rsm_dt;;
#endif

	// if not one of the above, give up for now and do it the slow way
	br.sptk.many dispatch_break_fault ;;

// reflect domain breaks directly to domain
// FIXME: DOES NOT WORK YET
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC
//	r19 == vpsr.ic (low 32 bits) | vpsr.i (high 32 bits)
//	r22 == IA64_KR(CURRENT)+IA64_VCPU_BREAKIMM_OFFSET
//	r31 == pr
GLOBAL_ENTRY(fast_break_reflect)
	mov r20=cr.ipsr;;
	// if big-endian domain or privileged-perfmon bits set, do slow way
	extr.u r21=r20,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	extr.u r21=r20,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	// ensure ipsr.cpl==2, ipsr.ri==0
	// FIXME: any other psr bits need to be properly set/validated?
	//   ...see process.c: DELIVER_PSR_CLR/SET
	extr.u r21=r20,IA64_PSR_CPL0_BIT,2;;
	extr.u r23=r20,IA64_PSR_RI_BIT,2;;
	dep r20=-1,r20,IA64_PSR_CPL1_BIT,1 ;;
	dep r20=0,r20,IA64_PSR_CPL0_BIT,1 ;;
	dep r20=0,r20,IA64_PSR_RI_BIT,2 ;;
	mov cr.ipsr=r20;;
	// save ipsr in shared_info, vipsr.cpl==(ipsr.cpl==3)?3:0
	cmp.ne p7,p0=3,r21;;
(p7)	mov r21=r0
	dep r20=r21,r20,IA64_PSR_CPL0_BIT,2 ;;
	dep r20=r23,r20,IA64_PSR_RI_BIT,2 ;;
	// vipsr.i=vpsr.i
	adds r21=XSI_PSR_I_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r21];;
	dep r20=r21,r20,IA64_PSR_I_BIT,1 ;;
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	// FIXME: any other vpsr bits need to be properly set/validated?
	st8 [r21]=r20;;
	// save iim in shared_info
	adds r21=XSI_IIM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17;;
	// save iip in shared_info
	mov r20=cr.iip;;
	adds r21=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20;;
	// save ifs in shared_info
	adds r21=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r21]=r0 ;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18
	st8 [r21]=r0 ;;
	cover ;;
	mov r20=cr.ifs;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20;;
	// vpsr.i = vpsr.ic = 0 on delivery of interruption
	st8 [r18]=r0;;
	// FIXME: need to save iipa and isr to be arch-compliant
	// set iip to go to domain IVA break instruction vector
	adds r22=IA64_VCPU_IVA_OFFSET-IA64_VCPU_BREAKIMM_OFFSET,r22;;
	ld8 r23=[r22];;
	movl r24=0x2c00;;
	add r24=r24,r23;;
	mov cr.iip=r24;;
	// OK, now all set to go except for switch to virtual bank0
	mov r30=r2; mov r29=r3;;
	adds r2=XSI_BANK1_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_OFS+8)-XSI_PSR_IC_OFS,r18;;
	bsw.1;;
	st8 [r2]=r16,16; st8 [r3]=r17,16 ;;
	st8 [r2]=r18,16; st8 [r3]=r19,16 ;;
	st8 [r2]=r20,16; st8 [r3]=r21,16 ;;
	st8 [r2]=r22,16; st8 [r3]=r23,16 ;;
	st8 [r2]=r24,16; st8 [r3]=r25,16 ;;
	st8 [r2]=r26,16; st8 [r3]=r27,16 ;;
	st8 [r2]=r28,16; st8 [r3]=r29,16 ;;
	st8 [r2]=r30,16; st8 [r3]=r31,16 ;;
	movl r31=XSI_IPSR;;
	bsw.0 ;;
	mov r2=r30; mov r3=r29;;
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
	mov pr=r31,-1 ;;
	rfi
	;;


// ensure that, if giving up, registers at entry to fast_hyperprivop unchanged
ENTRY(hyper_rfi)
#define FAST_HYPERPRIVOP_CNT
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_RFI);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
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

ENTRY(hyper_cover)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_COVER);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	// skip test for vpsr.ic.. it's a prerequisite for hyperprivops
	cover ;;
	adds r20=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	mov r30=cr.ifs;;
	adds r22=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18
	ld4 r21=[r20] ;;
	cmp.eq p6,p7=r21,r0 ;;
(p6)	st8 [r22]=r30;;
(p7)	st4 [r20]=r0;;
	mov cr.ifs=r0;;
	// adjust return address to skip over break instruction
	extr.u r26=r24,41,2 ;;
	cmp.eq p6,p7=2,r26 ;;
(p6)	mov r26=0
(p6)	adds r25=16,r25
(p7)	adds r26=1,r26
	;;
	dep r24=r26,r24,41,2
	;;
	mov cr.ipsr=r24
	mov cr.iip=r25
	mov pr=r31,-1 ;;
	rfi
	;;

#if 1
// return from metaphysical mode (meta=1) to virtual mode (meta=0)
ENTRY(hyper_ssm_dt)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SSM_DT);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.eq p7,p0=r21,r0	// meta==0?
(p7)	br.spnt.many	1f ;;	// already in virtual mode
	mov r22=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_META_SAVED_RR0_OFFSET,r22;;
	ld4 r23=[r22];;
	mov rr[r0]=r23;;
	srlz.i;;
	st4 [r20]=r0 ;;
	// adjust return address to skip over break instruction
	extr.u r26=r24,41,2 ;;
	cmp.eq p6,p7=2,r26 ;;
(p6)	mov r26=0
(p6)	adds r25=16,r25
(p7)	adds r26=1,r26
	;;
	dep r24=r26,r24,41,2
	;;
	mov cr.ipsr=r24
	mov cr.iip=r25
1:	mov pr=r31,-1 ;;
	rfi
	;;

// go to metaphysical mode (meta=1) from virtual mode (meta=0)
ENTRY(hyper_rsm_dt)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_RSM_DT);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.ne p7,p0=r21,r0	// meta==0?
(p7)	br.spnt.many	1f ;;	// already in metaphysical mode
	mov r22=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_META_RR0_OFFSET,r22;;
	ld4 r23=[r22];;
	mov rr[r0]=r23;;
	srlz.i;;
	adds r21=1,r0 ;;
	st4 [r20]=r21 ;;
	// adjust return address to skip over break instruction
	extr.u r26=r24,41,2 ;;
	cmp.eq p6,p7=2,r26 ;;
(p6)	mov r26=0
(p6)	adds r25=16,r25
(p7)	adds r26=1,r26
	;;
	dep r24=r26,r24,41,2
	;;
	mov cr.ipsr=r24
	mov cr.iip=r25
1:	mov pr=r31,-1 ;;
	rfi
	;;

// enable interrupts (and also interrupt collection)
ENTRY(hyper_ssm_i)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SSM_I);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	movl r20=0x100000001;;
	st8 [r18]=r20;;	// turn on both vpsr.i and vpsr.ic
// FIXME: NEED TO UPDATE IPSR/IIP TO SKIP BREAK INST
// FIXME: NEED TO CHECK FOR PENDING INTERRUPTS AND DELIVER THEM!
1:	mov pr=r31,-1 ;;
	rfi
	;;
#endif

