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

#define FAST_HYPERPRIVOP_CNT
#define FAST_REFLECT_CNT

// FIXME: This is defined in include/asm-ia64/hw_irq.h but this
// doesn't appear to be include'able from assembly?
#define IA64_TIMER_VECTOR 0xef

// Should be included from common header file (also in process.c)
//  NO PSR_CLR IS DIFFERENT! (CPL)
#define IA64_PSR_CPL1	(__IA64_UL(1) << IA64_PSR_CPL1_BIT)
#define IA64_PSR_CPL0	(__IA64_UL(1) << IA64_PSR_CPL0_BIT)
// note IA64_PSR_PK removed from following, why is this necessary?
#define	DELIVER_PSR_SET	(IA64_PSR_IC | IA64_PSR_I | \
			IA64_PSR_DT | IA64_PSR_RT | IA64_PSR_CPL1 | \
			IA64_PSR_IT | IA64_PSR_BN)

#define	DELIVER_PSR_CLR	(IA64_PSR_AC | IA64_PSR_DFL | IA64_PSR_DFH | \
			IA64_PSR_SP | IA64_PSR_DI | IA64_PSR_SI |	\
			IA64_PSR_DB | IA64_PSR_LP | IA64_PSR_TB | \
			IA64_PSR_MC | IA64_PSR_IS | \
			IA64_PSR_ID | IA64_PSR_DA | IA64_PSR_DD | \
			IA64_PSR_SS | IA64_PSR_RI | IA64_PSR_ED | IA64_PSR_IA)

// Note: not hand-scheduled for now
//  Registers at entry
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC_OFS
//	r19 == vpsr.ic (low 32 bits) | vpsr.i (high 32 bits)
//	r31 == pr
GLOBAL_ENTRY(fast_hyperprivop)
	// HYPERPRIVOP_SSM_I?
	// assumes domain interrupts pending, so just do it
	cmp.eq p7,p6=XEN_HYPER_SSM_I,r17
(p7)	br.sptk.many hyper_ssm_i;;

	// FIXME. This algorithm gives up (goes to the slow path) if there
	// are ANY interrupts pending, even if they are currently
	// undeliverable.  This should be improved later...
	adds r20=XSI_PEND_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r20=[r20] ;;
	cmp.eq p7,p0=r0,r20
(p7)	br.cond.sptk.many 1f
	mov r20=IA64_KR(CURRENT);;
	adds r21=IA64_VCPU_IRR0_OFFSET,r20;
	adds r22=IA64_VCPU_IRR0_OFFSET+8,r20;;
	ld8 r23=[r21],16; ld8 r24=[r22],16;;
	ld8 r21=[r21]; ld8 r22=[r22];;
	or r23=r23,r24; or r21=r21,r22;;
	or r20=r23,r21;;
1:	// when we get to here r20=~=interrupts pending

	// HYPERPRIVOP_RFI?
	cmp.eq p7,p6=XEN_HYPER_RFI,r17
(p7)	br.sptk.many hyper_rfi;;

	// HYPERPRIVOP_GET_IVR?
	cmp.eq p7,p6=XEN_HYPER_GET_IVR,r17
(p7)	br.sptk.many hyper_get_ivr;;

	cmp.ne p7,p0=r20,r0
(p7)	br.spnt.many dispatch_break_fault ;;

	// HYPERPRIVOP_COVER?
	cmp.eq p7,p6=XEN_HYPER_COVER,r17
(p7)	br.sptk.many hyper_cover;;

	// HYPERPRIVOP_SSM_DT?
	cmp.eq p7,p6=XEN_HYPER_SSM_DT,r17
(p7)	br.sptk.many hyper_ssm_dt;;

	// HYPERPRIVOP_RSM_DT?
	cmp.eq p7,p6=XEN_HYPER_RSM_DT,r17
(p7)	br.sptk.many hyper_rsm_dt;;

	// HYPERPRIVOP_GET_TPR?
	cmp.eq p7,p6=XEN_HYPER_GET_TPR,r17
(p7)	br.sptk.many hyper_get_tpr;;

	// HYPERPRIVOP_SET_TPR?
	cmp.eq p7,p6=XEN_HYPER_SET_TPR,r17
(p7)	br.sptk.many hyper_set_tpr;;

	// HYPERPRIVOP_EOI?
	cmp.eq p7,p6=XEN_HYPER_EOI,r17
(p7)	br.sptk.many hyper_eoi;;

	// HYPERPRIVOP_SET_ITM?
	cmp.eq p7,p6=XEN_HYPER_SET_ITM,r17
(p7)	br.sptk.many hyper_set_itm;;

	// HYPERPRIVOP_SET_RR?
	cmp.eq p7,p6=XEN_HYPER_SET_RR,r17
(p7)	br.sptk.many hyper_set_rr;;

	// HYPERPRIVOP_GET_RR?
	cmp.eq p7,p6=XEN_HYPER_GET_RR,r17
(p7)	br.sptk.many hyper_get_rr;;

	// HYPERPRIVOP_PTC_GA?
	cmp.eq p7,p6=XEN_HYPER_PTC_GA,r17
(p7)	br.sptk.many hyper_ptc_ga;;

	// HYPERPRIVOP_ITC_D?
	cmp.eq p7,p6=XEN_HYPER_ITC_D,r17
(p7)	br.sptk.many hyper_itc_d;;

	// HYPERPRIVOP_ITC_I?
	cmp.eq p7,p6=XEN_HYPER_ITC_I,r17
(p7)	br.sptk.many hyper_itc_i;;

	// if not one of the above, give up for now and do it the slow way
	br.sptk.many dispatch_break_fault ;;


// give up for now if: ipsr.be==1, ipsr.pp==1
// from reflect_interruption, don't need to:
//  - printf first extint (debug only)
//  - check for interrupt collection enabled (routine will force on)
//  - set ifa (not valid for extint)
//  - set iha (not valid for extint)
//  - set itir (not valid for extint)
// DO need to
//  - increment the HYPER_SSM_I fast_hyperprivop counter
//  - set shared_mem iip to instruction after HYPER_SSM_I
//  - set cr.iip to guest iva+0x3000
//  - set shared_mem ipsr to [vcpu_get_ipsr_int_state]
//     be = pp = bn = 0; dt = it = rt = 1; cpl = 3 or 0;
//     i = shared_mem interrupt_delivery_enabled
//     ic = shared_mem interrupt_collection_enabled
//     ri = instruction after HYPER_SSM_I
//     all other bits unchanged from real cr.ipsr
//  - set cr.ipsr (DELIVER_PSR_SET/CLEAR, don't forget cpl!)
//  - set shared_mem isr: isr.ei to instr following HYPER_SSM_I
//	and isr.ri to cr.isr.ri (all other bits zero)
//  - cover and set shared_mem precover_ifs to cr.ifs
//		^^^ MISSED THIS FOR fast_break??
//  - set shared_mem ifs and incomplete_regframe to 0
//  - set shared_mem interrupt_delivery_enabled to 0
//  - set shared_mem interrupt_collection_enabled to 0
//  - set r31 to SHAREDINFO_ADDR
//  - virtual bank switch 0
// maybe implement later
//  - verify that there really IS a deliverable interrupt pending
//  - set shared_mem iva
// needs to be done but not implemented (in reflect_interruption)
//  - set shared_mem iipa
// don't know for sure
//  - set shared_mem unat
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC
//	r19 == vpsr.ic (low 32 bits) | vpsr.i (high 32 bits)
//	r31 == pr
ENTRY(hyper_ssm_i)
	// give up for now if: ipsr.be==1, ipsr.pp==1
	mov r30=cr.ipsr;;
	mov r29=cr.iip;;
	extr.u r21=r30,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.sptk.many dispatch_break_fault ;;
	extr.u r21=r30,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.sptk.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SSM_I);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	// set shared_mem iip to instruction after HYPER_SSM_I
	extr.u r20=r30,41,2 ;;
	cmp.eq p6,p7=2,r20 ;;
(p6)	mov r20=0
(p6)	adds r29=16,r29
(p7)	adds r20=1,r20 ;;
	dep r30=r20,r30,41,2;;	// adjust cr.ipsr.ri but don't save yet
	adds r21=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r29 ;;
	// set shared_mem isr
	extr.u r16=r16,38,1;;	// grab cr.isr.ir bit
	dep r16=r16,r0,38,1 ;;	// insert into cr.isr (rest of bits zero)
	dep r16=r20,r16,41,2 ;; // deposit cr.isr.ri
	adds r21=XSI_ISR_OFS-XSI_PSR_IC_OFS,r18 ;; 
	st8 [r21]=r16 ;;
	// set cr.ipsr
	mov r29=r30 ;;
	movl r28=DELIVER_PSR_SET;;
	movl r27=~DELIVER_PSR_CLR;;
	or r29=r29,r28;;
	and r29=r29,r27;;
	mov cr.ipsr=r29;;
	// set shared_mem ipsr (from ipsr in r30 with ipsr.ri already set)
	extr.u r29=r30,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p7=3,r29;;
(p6)	dep r30=-1,r30,IA64_PSR_CPL0_BIT,2
(p7)	dep r30=0,r30,IA64_PSR_CPL0_BIT,2
	;;
	// FOR SSM_I ONLY, also turn on psr.i and psr.ic
	movl r28=(IA64_PSR_DT|IA64_PSR_IT|IA64_PSR_RT|IA64_PSR_I|IA64_PSR_IC);;
	movl r27=~(IA64_PSR_BE|IA64_PSR_PP|IA64_PSR_BN);;
	or r30=r30,r28;;
	and r30=r30,r27;;
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r30 ;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st8 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs and incomplete_regframe to 0
	cover ;;
	mov r20=cr.ifs;;
	adds r21=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r21]=r0 ;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r0 ;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20 ;;
	// leave cr.ifs alone for later rfi
	// set iip to go to domain IVA break instruction vector
	mov r22=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_IVA_OFFSET,r22;;
	ld8 r23=[r22];;
	movl r24=0x3000;;
	add r24=r24,r23;;
	mov cr.iip=r24;;
	// OK, now all set to go except for switch to virtual bank0
	mov r30=r2; mov r29=r3;;
	adds r2=XSI_BANK1_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_OFS+8)-XSI_PSR_IC_OFS,r18;;
	bsw.1;;
	// FIXME: need to handle ar.unat!
	.mem.offset 0,0; st8.spill [r2]=r16,16;
	.mem.offset 8,0; st8.spill [r3]=r17,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r18,16;
	.mem.offset 8,0; st8.spill [r3]=r19,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r20,16;
	.mem.offset 8,0; st8.spill [r3]=r21,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r22,16;
	.mem.offset 8,0; st8.spill [r3]=r23,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r24,16;
	.mem.offset 8,0; st8.spill [r3]=r25,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r26,16;
	.mem.offset 8,0; st8.spill [r3]=r27,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r28,16;
	.mem.offset 8,0; st8.spill [r3]=r29,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r30,16;
	.mem.offset 8,0; st8.spill [r3]=r31,16 ;;
	movl r31=XSI_IPSR;;
	bsw.0 ;;
	mov r2=r30; mov r3=r29;;
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
	mov pr=r31,-1 ;;
	rfi
	;;

// reflect domain clock interrupt
//	r31 == pr
//	r30 == cr.ivr
//	r29 == rp
GLOBAL_ENTRY(fast_tick_reflect)
#define FAST_TICK
#ifndef FAST_TICK
	br.cond.sptk.many rp;;
#endif
	mov r28=IA64_TIMER_VECTOR;;
	cmp.ne p6,p0=r28,r30
(p6)	br.cond.sptk.many rp;;
	movl r20=(PERCPU_ADDR)+IA64_CPUINFO_ITM_NEXT_OFFSET;;
	ld8 r21=[r20];;
	mov r27=ar.itc;;
	cmp.ltu p6,p0=r21,r27
(p6)	br.cond.sptk.many rp;;
	mov r17=cr.ipsr;;
	// slow path if: ipsr.be==1, ipsr.pp==1
	extr.u r21=r17,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p6,p0=r21,r0
(p6)	br.cond.sptk.many rp;;
	extr.u r21=r17,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p6,p0=r21,r0
(p6)	br.cond.sptk.many rp;;
#ifdef FAST_REFLECT_CNT
	movl r20=fast_reflect_count+((0x3000>>8)*8);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov cr.eoi=r0;;
	mov rp=r29;;
	// vcpu_pend_timer(current)
	movl r18=XSI_PSR_IC;;
	adds r20=XSI_ITV_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	cmp.eq p6,p0=r20,r0	// if cr.itv==0 done
(p6)	br.cond.sptk.many fast_tick_reflect_done;;
	tbit.nz p6,p0=r20,16;;	// check itv.m (discard) bit
(p6)	br.cond.sptk.many fast_tick_reflect_done;;
	extr.u r27=r20,0,6	// r27 has low 6 bits of itv.vector
	extr.u r26=r20,6,2;;	// r26 has irr index of itv.vector
	mov r19=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_DOMAIN_ITM_LAST_OFFSET,r19
	adds r23=IA64_VCPU_DOMAIN_ITM_OFFSET,r19;;
	ld8 r24=[r22];;
	ld8 r23=[r23];;
	cmp.eq p6,p0=r23,r24	// skip if this tick already delivered
(p6)	br.cond.sptk.many fast_tick_reflect_done;;
	// set irr bit
	adds r21=IA64_VCPU_IRR0_OFFSET,r19;
	shl r26=r26,3;;
	add r21=r21,r26;;
	mov r25=1;;
	shl r22=r25,r27;;
	ld8 r23=[r21];;
	or r22=r22,r23;;
	st8 [r21]=r22;;
	// set PSCB(pending_interruption)!
	adds r20=XSI_PEND_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r25;;
	
	// if interrupted at pl0, we're done
	extr.u r16=r17,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p0=r16,r0;;
(p6)	br.cond.sptk.many fast_tick_reflect_done;;
	// now deliver to iva+0x3000
	//	r17 == cr.ipsr
	//	r18 == XSI_PSR_IC
	//	r19 == IA64_KR(CURRENT)
	//	r31 == pr

	// if guest vpsr.i is off, we're done
	adds r21=XSI_PSR_I_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r21];;
	cmp.eq p6,p0=r21,r0
(p6)	br.cond.sptk.many fast_tick_reflect_done;;

	// OK, we have a clock tick to deliver to the active domain!
	mov r16=cr.isr;;
	mov r29=cr.iip;;
	adds r21=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r29 ;;
	// set shared_mem isr
	extr.u r16=r16,38,1;;	// grab cr.isr.ir bit
	dep r16=r16,r0,38,1 ;;	// insert into cr.isr (rest of bits zero)
	extr.u r20=r17,41,2 ;;	// get ipsr.ri
	dep r16=r20,r16,41,2 ;; // deposit cr.isr.ei
	adds r21=XSI_ISR_OFS-XSI_PSR_IC_OFS,r18 ;; 
	st8 [r21]=r16 ;;
	// set cr.ipsr (make sure cpl==2!)
	mov r29=r17 ;;
	movl r28=DELIVER_PSR_SET;;
	movl r27=~(DELIVER_PSR_CLR|IA64_PSR_CPL0);;
	or r29=r29,r28;;
	and r29=r29,r27;;
	mov cr.ipsr=r29;;
	// set shared_mem ipsr (from ipsr in r17 with ipsr.ri already set)
	extr.u r29=r17,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p7=3,r29;;
(p6)	dep r17=-1,r17,IA64_PSR_CPL0_BIT,2
(p7)	dep r17=0,r17,IA64_PSR_CPL0_BIT,2
	;;
	movl r28=(IA64_PSR_DT|IA64_PSR_IT|IA64_PSR_RT);;
	movl r27=~(IA64_PSR_BE|IA64_PSR_PP|IA64_PSR_BN|IA64_PSR_I|IA64_PSR_IC);;
	dep r21=-1,r21,IA64_PSR_CPL1_BIT,1 ;;
	or r17=r17,r28;;
	and r17=r17,r27;;
	ld4 r16=[r18],4;;
	cmp.ne p6,p0=r16,r0;;
(p6)	dep r17=-1,r17,IA64_PSR_IC_BIT,1 ;;
	ld4 r16=[r18],-4;;
	cmp.ne p6,p0=r16,r0;;
(p6)	dep r17=-1,r17,IA64_PSR_I_BIT,1 ;;
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17 ;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st8 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs and incomplete_regframe to 0
	cover ;;
	mov r20=cr.ifs;;
	adds r21=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r21]=r0 ;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r0 ;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20 ;;
	// leave cr.ifs alone for later rfi
	// set iip to go to domain IVA break instruction vector
	adds r22=IA64_VCPU_IVA_OFFSET,r19;;
	ld8 r23=[r22];;
	movl r24=0x3000;;
	add r24=r24,r23;;
	mov cr.iip=r24;;
	// OK, now all set to go except for switch to virtual bank0
	mov r30=r2; mov r29=r3;;
	adds r2=XSI_BANK1_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_OFS+8)-XSI_PSR_IC_OFS,r18;;
	bsw.1;;
	// FIXME: need to handle ar.unat!
	.mem.offset 0,0; st8.spill [r2]=r16,16;
	.mem.offset 8,0; st8.spill [r3]=r17,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r18,16;
	.mem.offset 8,0; st8.spill [r3]=r19,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r20,16;
	.mem.offset 8,0; st8.spill [r3]=r21,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r22,16;
	.mem.offset 8,0; st8.spill [r3]=r23,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r24,16;
	.mem.offset 8,0; st8.spill [r3]=r25,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r26,16;
	.mem.offset 8,0; st8.spill [r3]=r27,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r28,16;
	.mem.offset 8,0; st8.spill [r3]=r29,16 ;;
	.mem.offset 0,0; st8.spill [r2]=r30,16;
	.mem.offset 8,0; st8.spill [r3]=r31,16 ;;
	movl r31=XSI_IPSR;;
	bsw.0 ;;
	mov r2=r30; mov r3=r29;;
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
fast_tick_reflect_done:
	mov pr=r31,-1 ;;
	rfi
END(fast_tick_reflect)

// reflect domain breaks directly to domain
// FIXME: DOES NOT WORK YET
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC
//	r19 == vpsr.ic (low 32 bits) | vpsr.i (high 32 bits)
//	r31 == pr
GLOBAL_ENTRY(fast_break_reflect)
#define FAST_BREAK
#ifndef FAST_BREAK
	br.sptk.many dispatch_break_fault ;;
#endif
	mov r30=cr.ipsr;;
	mov r29=cr.iip;;
	extr.u r21=r30,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0 ;;
(p7)	br.sptk.many dispatch_break_fault ;;
	extr.u r21=r30,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0 ;;
(p7)	br.sptk.many dispatch_break_fault ;;
#if 1 /* special handling in case running on simulator */
	movl r20=first_break;;
	ld4 r23=[r20];;
	movl r21=0x80001;
	movl r22=0x80002;;
	cmp.ne p7,p0=r23,r0;;
(p7)	br.sptk.many dispatch_break_fault ;;
	cmp.eq p7,p0=r21,r17;
(p7)	br.sptk.many dispatch_break_fault ;;
	cmp.eq p7,p0=r22,r17;
(p7)	br.sptk.many dispatch_break_fault ;;
#endif
#ifdef FAST_REFLECT_CNT
	movl r20=fast_reflect_count+((0x2c00>>8)*8);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	// save iim in shared_info
	adds r21=XSI_IIM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17;;
	// save iip in shared_info (DON'T POINT TO NEXT INSTRUCTION!)
	adds r21=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r29;;
	// set shared_mem isr
	adds r21=XSI_ISR_OFS-XSI_PSR_IC_OFS,r18 ;; 
	st8 [r21]=r16 ;;
	// set cr.ipsr
	mov r29=r30 ;;
	movl r28=DELIVER_PSR_SET;;
	movl r27=~(DELIVER_PSR_CLR|IA64_PSR_CPL0);;
	or r29=r29,r28;;
	and r29=r29,r27;;
	mov cr.ipsr=r29;;
	// set shared_mem ipsr (from ipsr in r30 with ipsr.ri already set)
	extr.u r29=r30,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p7=3,r29;;
(p6)	dep r30=-1,r30,IA64_PSR_CPL0_BIT,2
(p7)	dep r30=0,r30,IA64_PSR_CPL0_BIT,2
	;;
	movl r28=(IA64_PSR_DT|IA64_PSR_IT|IA64_PSR_RT);;
	movl r27=~(IA64_PSR_BE|IA64_PSR_PP|IA64_PSR_BN);;
	or r30=r30,r28;;
	and r30=r30,r27;;
	// also set shared_mem ipsr.i and ipsr.ic appropriately
	ld8 r20=[r18];;
	extr.u r22=r20,32,32
	cmp4.eq p6,p7=r20,r0;;
(p6)	dep r30=0,r30,IA64_PSR_IC_BIT,1
(p7)	dep r30=-1,r30,IA64_PSR_IC_BIT,1 ;;
	cmp4.eq p6,p7=r22,r0;;
(p6)	dep r30=0,r30,IA64_PSR_I_BIT,1
(p7)	dep r30=-1,r30,IA64_PSR_I_BIT,1 ;;
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r30 ;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st8 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs and incomplete_regframe to 0
	cover ;;
	mov r20=cr.ifs;;
	adds r21=XSI_INCOMPL_REG_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r21]=r0 ;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r0 ;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20 ;;
	// vpsr.i = vpsr.ic = 0 on delivery of interruption
	st8 [r18]=r0;;
	// FIXME: need to save iipa and isr to be arch-compliant
	// set iip to go to domain IVA break instruction vector
	mov r22=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_IVA_OFFSET,r22;;
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
	// if no interrupts pending, proceed
	mov r30=r0
	cmp.eq p7,p0=r20,r0
(p7)	br.sptk.many 1f
	;;
	adds r20=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r20];;		// r21 = vcr.ipsr
	extr.u r22=r21,IA64_PSR_I_BIT,1 ;;
	mov r30=r22	
	// r30 determines whether we might deliver an immediate extint
1:
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

1:	// OK now, let's do an rfi.
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_RFI);;
	ld8 r23=[r20];;
	adds r23=1,r23;;
	st8 [r20]=r23;;
#endif
	cmp.ne p6,p0=r30,r0
(p6)	br.cond.sptk.many check_extint;
	;;
just_do_rfi:
	// r18=&vpsr.i|vpsr.ic, r21==vpsr, r22=vcr.iip
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
	extr.u r23=r21,IA64_PSR_I_BIT,1 ;;
	cmp.ne p7,p6=r23,r0 ;;
	// not done yet
(p7)	dep r19=-1,r19,32,1
	extr.u r23=r21,IA64_PSR_IC_BIT,1 ;;
	cmp.ne p7,p6=r23,r0 ;;
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

check_extint:
	br.sptk.many dispatch_break_fault ;;

	// r18=&vpsr.i|vpsr.ic, r21==vpsr, r22=vcr.iip
	mov r30=IA64_KR(CURRENT);;
	adds r24=IA64_VCPU_INSVC3_OFFSET,r30;;
	mov r25=192
	adds r22=IA64_VCPU_IRR3_OFFSET,r30;;
	ld8 r23=[r22];;
	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
	cmp.eq p6,p0=r23,r0
(p6)	br.cond.sptk.many 1f;	// this is actually an error
	// r22 points to non-zero element of irr, r23 has value
	// r24 points to corr element of insvc, r25 has elt*64
	ld8 r26=[r24];;
	cmp.geu p6,p0=r26,r23
(p6)	br.cond.spnt.many 1f;
	// not masked by insvc, get vector number
	shr.u r26=r23,1;;
	or r26=r23,r26;;
	shr.u r27=r26,2;;
	or r26=r26,r27;;
	shr.u r27=r26,4;;
	or r26=r26,r27;;
	shr.u r27=r26,8;;
	or r26=r26,r27;;
	shr.u r27=r26,16;;
	or r26=r26,r27;;
	shr.u r27=r26,32;;
	or r26=r26,r27;;
	andcm r26=0xffffffffffffffff,r26;;
	popcnt r26=r26;;
	sub r26=63,r26;;
	// r26 now contains the bit index (mod 64)
	mov r27=1;;
	shl r27=r27,r26;;
	// r27 now contains the (within the proper word) bit mask 
	add r26=r25,r26
	// r26 now contains the vector [0..255]
	adds r20=XSI_TPR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20] ;;
	extr.u r28=r20,16,1
	extr.u r29=r20,4,4 ;;
	cmp.ne p6,p0=r28,r0	// if tpr.mmi is set, return SPURIOUS
(p6)	br.cond.sptk.many 1f;
	shl r29=r29,4;;
	adds r29=15,r29;;
	cmp.ge p6,p0=r29,r26
(p6)	br.cond.sptk.many 1f;
	// OK, have an unmasked vector to process/return
	ld8 r25=[r24];;
	or r25=r25,r27;;
	st8 [r24]=r25;;
	ld8 r25=[r22];;
	andcm r25=r25,r27;;
	st8 [r22]=r25;;
	mov r8=r26;;
	// not done yet

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
1:	extr.u r26=r24,41,2 ;;
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
1:	extr.u r26=r24,41,2 ;;
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

ENTRY(hyper_get_tpr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_GET_TPR);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	adds r20=XSI_TPR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r8=[r20];;
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
END(hyper_get_tpr)

// if we get to here, there are no interrupts pending so we
// can change virtual tpr to any value without fear of provoking
// (or accidentally missing) delivering an interrupt
ENTRY(hyper_set_tpr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SET_TPR);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	movl r27=0xff00;;
	adds r20=XSI_TPR_OFS-XSI_PSR_IC_OFS,r18 ;;
	andcm r8=r8,r27;;
	st8 [r20]=r8;;
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
END(hyper_set_tpr)

ENTRY(hyper_get_ivr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r22=fast_hyperpriv_cnt+(8*XEN_HYPER_GET_IVR);;
	ld8 r21=[r22];;
	adds r21=1,r21;;
	st8 [r22]=r21;;
#endif
	mov r8=15;;
	// when we get to here r20=~=interrupts pending
	cmp.eq p7,p0=r20,r0;;
(p7)	adds r20=XSI_PEND_OFS-XSI_PSR_IC_OFS,r18 ;;
(p7)	st4 [r20]=r0;;
(p7)	br.spnt.many 1f ;;
	mov r30=IA64_KR(CURRENT);;
	adds r24=IA64_VCPU_INSVC3_OFFSET,r30;;
	mov r25=192
	adds r22=IA64_VCPU_IRR3_OFFSET,r30;;
	ld8 r23=[r22];;
	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
	cmp.eq p6,p0=r23,r0
(p6)	br.cond.sptk.many 1f;	// this is actually an error
	// r22 points to non-zero element of irr, r23 has value
	// r24 points to corr element of insvc, r25 has elt*64
	ld8 r26=[r24];;
	cmp.geu p6,p0=r26,r23
(p6)	br.cond.spnt.many 1f;
	// not masked by insvc, get vector number
	shr.u r26=r23,1;;
	or r26=r23,r26;;
	shr.u r27=r26,2;;
	or r26=r26,r27;;
	shr.u r27=r26,4;;
	or r26=r26,r27;;
	shr.u r27=r26,8;;
	or r26=r26,r27;;
	shr.u r27=r26,16;;
	or r26=r26,r27;;
	shr.u r27=r26,32;;
	or r26=r26,r27;;
	andcm r26=0xffffffffffffffff,r26;;
	popcnt r26=r26;;
	sub r26=63,r26;;
	// r26 now contains the bit index (mod 64)
	mov r27=1;;
	shl r27=r27,r26;;
	// r27 now contains the (within the proper word) bit mask 
	add r26=r25,r26
	// r26 now contains the vector [0..255]
	adds r20=XSI_TPR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20] ;;
	extr.u r28=r20,16,1
	extr.u r29=r20,4,4 ;;
	cmp.ne p6,p0=r28,r0	// if tpr.mmi is set, return SPURIOUS
(p6)	br.cond.sptk.many 1f;
	shl r29=r29,4;;
	adds r29=15,r29;;
	cmp.ge p6,p0=r29,r26
(p6)	br.cond.sptk.many 1f;
	// OK, have an unmasked vector to process/return
	ld8 r25=[r24];;
	or r25=r25,r27;;
	st8 [r24]=r25;;
	ld8 r25=[r22];;
	andcm r25=r25,r27;;
	st8 [r22]=r25;;
	mov r8=r26;;
	// if its a clock tick, remember itm to avoid delivering it twice
	adds r20=XSI_ITV_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	extr.u r20=r20,0,8;;
	cmp.eq p6,p0=r20,r8
	adds r22=IA64_VCPU_DOMAIN_ITM_LAST_OFFSET,r30
	adds r23=IA64_VCPU_DOMAIN_ITM_OFFSET,r30;;
	ld8 r23=[r23];;
(p6)	st8 [r22]=r23;;
	// all done
1:	mov r24=cr.ipsr
	mov r25=cr.iip;;
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
END(hyper_get_ivr)

ENTRY(hyper_eoi)
	// when we get to here r20=~=interrupts pending
	cmp.ne p7,p0=r20,r0
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_EOI);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	mov r22=IA64_KR(CURRENT);;
	adds r22=IA64_VCPU_INSVC3_OFFSET,r22;;
	ld8 r23=[r22];;
	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r22=-8,r22;;
(p6)	ld8 r23=[r22];;
(p6)	cmp.eq p6,p0=r23,r0;;
	cmp.eq p6,p0=r23,r0
(p6)	br.cond.sptk.many 1f;	// this is actually an error
	// r22 points to non-zero element of insvc, r23 has value
	shr.u r24=r23,1;;
	or r24=r23,r24;;
	shr.u r25=r24,2;;
	or r24=r24,r25;;
	shr.u r25=r24,4;;
	or r24=r24,r25;;
	shr.u r25=r24,8;;
	or r24=r24,r25;;
	shr.u r25=r24,16;;
	or r24=r24,r25;;
	shr.u r25=r24,32;;
	or r24=r24,r25;;
	andcm r24=0xffffffffffffffff,r24;;
	popcnt r24=r24;;
	sub r24=63,r24;;
	// r24 now contains the bit index
	mov r25=1;;
	shl r25=r25,r24;;
	andcm r23=r23,r25;;
	st8 [r22]=r23;;
1:	mov r24=cr.ipsr
	mov r25=cr.iip;;
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
END(hyper_eoi)

ENTRY(hyper_set_itm)
	// when we get to here r20=~=interrupts pending
	cmp.ne p7,p0=r20,r0
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SET_ITM);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	movl r20=(PERCPU_ADDR)+IA64_CPUINFO_ITM_NEXT_OFFSET;;
	ld8 r21=[r20];;
	mov r20=IA64_KR(CURRENT);;
	adds r20=IA64_VCPU_DOMAIN_ITM_OFFSET,r20;;
	st8 [r20]=r8;;
	cmp.geu p6,p0=r21,r8;;
(p6)	mov r21=r8;;
	// now "safe set" cr.itm=r21
	mov r23=100;;
2:	mov cr.itm=r21;;
	srlz.d;;
	mov r22=ar.itc ;;
	cmp.leu p6,p0=r21,r22;;
	add r21=r21,r23;;
	shl r23=r23,1;;
(p6)	br.cond.spnt.few 2b;;
1:	mov r24=cr.ipsr
	mov r25=cr.iip;;
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
END(hyper_set_itm)

ENTRY(hyper_get_rr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_GET_RR);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	extr.u r25=r8,61,3;;
	adds r20=XSI_RR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shl r25=r25,3;;
	add r20=r20,r25;;
	ld8 r8=[r20];;
1:	mov r24=cr.ipsr
	mov r25=cr.iip;;
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
END(hyper_get_rr)

ENTRY(hyper_set_rr)
	extr.u r25=r8,61,3;;
	cmp.leu p7,p0=7,r25	// punt on setting rr7
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=fast_hyperpriv_cnt+(8*XEN_HYPER_SET_RR);;
	ld8 r21=[r20];;
	adds r21=1,r21;;
	st8 [r20]=r21;;
#endif
	extr.u r26=r9,8,24	// r26 = r9.rid
	mov r20=IA64_KR(CURRENT);;
	adds r21=IA64_VCPU_STARTING_RID_OFFSET,r20;;
	ld4 r22=[r21];;
	adds r21=IA64_VCPU_ENDING_RID_OFFSET,r20;;
	ld4 r23=[r21];;
	adds r24=IA64_VCPU_META_SAVED_RR0_OFFSET,r20;;
	add r22=r26,r22;;
	cmp.geu p6,p0=r22,r23	// if r9.rid + starting_rid >= ending_rid
(p6)	br.cond.sptk.many 1f;	// this is an error, but just ignore/return
	// r21=starting_rid
	adds r20=XSI_RR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shl r25=r25,3;;
	add r20=r20,r25;;
	st8 [r20]=r9;;		// store away exactly what was passed
	// but adjust value actually placed in rr[r8]
	// r22 contains adjusted rid, "mangle" it (see regionreg.c)
	// and set ps to PAGE_SHIFT and ve to 1
	extr.u r27=r22,0,8
	extr.u r28=r22,8,8
	extr.u r29=r22,16,8;;
	dep.z r23=PAGE_SHIFT,2,6;;
	dep r23=-1,r23,0,1;;	// mangling is swapping bytes 1 & 3
	dep r23=r27,r23,24,8;;
	dep r23=r28,r23,16,8;;
	dep r23=r29,r23,8,8
	cmp.eq p6,p0=r25,r0;;	// if rr0, save for metaphysical
(p6)	st4 [r24]=r23
	mov rr[r8]=r23;;
	// done, mosey on back
1:	mov r24=cr.ipsr
	mov r25=cr.iip;;
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
END(hyper_set_rr)

ENTRY(hyper_ptc_ga)
	br.spnt.many dispatch_break_fault ;;
END(hyper_ptc_ga)

ENTRY(hyper_itc_d)
	br.spnt.many dispatch_break_fault ;;
END(hyper_itc_d)

ENTRY(hyper_itc_i)
	br.spnt.many dispatch_break_fault ;;
END(hyper_itc_i)

