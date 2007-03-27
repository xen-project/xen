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
#include <asm/debugger.h>
#include <asm/asm-xsi-offsets.h>
#include <public/xen.h>


#define	_PAGE_PPN_MASK	0x0003fffffffff000 //asm/pgtable.h doesn't do assembly
#define PAGE_PHYS	0x0010000000000761 //__pgprot(__DIRTY_BITS|
					   //         _PAGE_PL_2|_PAGE_AR_RWX)
#define _PAGE_PL_2	(2<<7)

#if 1	 // change to 0 to turn off all fast paths
# define FAST_HYPERPRIVOPS
# ifdef PERF_COUNTERS
#  define FAST_HYPERPRIVOP_CNT
#  define FAST_HYPERPRIVOP_PERFC(N) PERFC(fast_hyperprivop + N)
#  define FAST_REFLECT_CNT
# endif
	
//#define FAST_TICK // mostly working (unat problems) but default off for now
//#define FAST_TLB_MISS_REFLECT	// mostly working but default off for now
# undef FAST_ITC		//XXX TODO fast_itc doesn't support dom0 vp yet
# define FAST_BREAK
# undef FAST_ACCESS_REFLECT 	//XXX TODO fast_access_reflect
                            	//    doesn't support dom0 vp yet.
# define FAST_RFI
// TODO: Since we use callback to deliver interrupt, 
//       FAST_SSM_I needs to be rewritten.
# define FAST_SSM_I
# define FAST_PTC_GA
# undef RFI_TO_INTERRUPT // not working yet
#endif

#ifdef CONFIG_SMP
 //#warning "FIXME: ptc.ga instruction requires spinlock for SMP"
 #undef FAST_PTC_GA
#endif

// FIXME: turn off for now... but NaTs may crash Xen so re-enable soon!
#define HANDLE_AR_UNAT

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
//	r19 == vpsr.ic
//	r31 == pr
GLOBAL_ENTRY(fast_hyperprivop)
	// HYPERPRIVOP_SSM_I?
	// assumes domain interrupts pending, so just do it
	cmp.eq p7,p6=HYPERPRIVOP_SSM_I,r17
(p7)	br.sptk.many hyper_ssm_i;;

	// Check pending event indication
	adds r20=XSI_PSR_I_ADDR_OFS-XSI_PSR_IC_OFS, r18;;
	ld8 r20=[r20]
	;;
	ld1 r22=[r20],-1	// evtchn_upcall_mask
	;;
	ld1 r20=[r20]		// evtchn_upcall_pending
	;;

	// HYPERPRIVOP_RFI?
	cmp.eq p7,p6=HYPERPRIVOP_RFI,r17
(p7)	br.sptk.many hyper_rfi
	;;
#ifndef FAST_HYPERPRIVOPS // see beginning of file
	br.sptk.many dispatch_break_fault ;;
#endif
	// if event enabled and there are pending events
	cmp.ne p7,p0=r20,r0
	;;
	cmp.eq.and p7,p0=r22,r0
(p7)	br.spnt.many dispatch_break_fault
	;;

	// HYPERPRIVOP_COVER?
	cmp.eq p7,p6=HYPERPRIVOP_COVER,r17
(p7)	br.sptk.many hyper_cover
	;;

	// HYPERPRIVOP_SSM_DT?
	cmp.eq p7,p6=HYPERPRIVOP_SSM_DT,r17
(p7)	br.sptk.many hyper_ssm_dt
	;;

	// HYPERPRIVOP_RSM_DT?
	cmp.eq p7,p6=HYPERPRIVOP_RSM_DT,r17
(p7)	br.sptk.many hyper_rsm_dt
	;;

	// HYPERPRIVOP_SET_ITM?
	cmp.eq p7,p6=HYPERPRIVOP_SET_ITM,r17
(p7)	br.sptk.many hyper_set_itm
	;;

	// HYPERPRIVOP_SET_RR?
	cmp.eq p7,p6=HYPERPRIVOP_SET_RR,r17
(p7)	br.sptk.many hyper_set_rr
	;;

	// HYPERPRIVOP_GET_RR?
	cmp.eq p7,p6=HYPERPRIVOP_GET_RR,r17
(p7)	br.sptk.many hyper_get_rr
	;;

	// HYPERPRIVOP_GET_PSR?
	cmp.eq p7,p6=HYPERPRIVOP_GET_PSR,r17
(p7)	br.sptk.many hyper_get_psr
	;;

	// HYPERPRIVOP_PTC_GA?
	cmp.eq p7,p6=HYPERPRIVOP_PTC_GA,r17
(p7)	br.sptk.many hyper_ptc_ga
	;;

	// HYPERPRIVOP_ITC_D?
	cmp.eq p7,p6=HYPERPRIVOP_ITC_D,r17
(p7)	br.sptk.many hyper_itc_d
	;;

	// HYPERPRIVOP_ITC_I?
	cmp.eq p7,p6=HYPERPRIVOP_ITC_I,r17
(p7)	br.sptk.many hyper_itc_i
	;;

	// HYPERPRIVOP_THASH?
	cmp.eq p7,p6=HYPERPRIVOP_THASH,r17
(p7)	br.sptk.many hyper_thash
	;;

	// HYPERPRIVOP_SET_KR?
	cmp.eq p7,p6=HYPERPRIVOP_SET_KR,r17
(p7)	br.sptk.many hyper_set_kr
	;;

	// if not one of the above, give up for now and do it the slow way
	br.sptk.many dispatch_break_fault
	;;
END(fast_hyperprivop)

// give up for now if: ipsr.be==1, ipsr.pp==1
// from reflect_interruption, don't need to:
//  - printk first extint (debug only)
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
//	r19 == vpsr.ic 
//	r31 == pr
ENTRY(hyper_ssm_i)
#ifndef FAST_SSM_I
	br.spnt.few dispatch_break_fault ;;
#endif
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
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_SSM_I);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
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
	// set hpsr_dfh to ipsr
	adds r28=XSI_HPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	ld1 r28=[r28];;
	dep r29=r28,r29,IA64_PSR_DFH_BIT,1;;
	mov cr.ipsr=r29;;
	// set shared_mem ipsr (from ipsr in r30 with ipsr.ri already set)
	extr.u r29=r30,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p7=3,r29;;
(p6)	dep r30=-1,r30,IA64_PSR_CPL0_BIT,2
(p7)	dep r30=0,r30,IA64_PSR_CPL0_BIT,2
	;;
	// FOR SSM_I ONLY, also turn on psr.i and psr.ic
	movl r28=(IA64_PSR_DT|IA64_PSR_IT|IA64_PSR_RT|IA64_PSR_I|IA64_PSR_IC);;
//	movl r27=~(IA64_PSR_BE|IA64_PSR_PP|IA64_PSR_BN);;
	movl r27=~(IA64_PSR_BE|IA64_PSR_BN);;
	or r30=r30,r28;;
	and r30=r30,r27;;
	mov r20=1
	movl r22=THIS_CPU(current_psr_i_addr)
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r22=[r22]
	;;
	adds r27=XSI_VPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	ld1 r28=[r27];;
	st1 [r27]=r0
	dep r30=r28,r30,IA64_PSR_DFH_BIT,1
	;;
	st8 [r21]=r30;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st1 [r22]=r20
	st4 [r18]=r0
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs to 0
	cover ;;
	mov r20=cr.ifs;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r0 ;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r20 ;;
	// leave cr.ifs alone for later rfi
	// set iip to go to event callback handler
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r22=[r22];;
	adds r22=IA64_VCPU_EVENT_CALLBACK_IP_OFFSET,r22;;
	ld8 r24=[r22];;
	mov cr.iip=r24;;
	// OK, now all set to go except for switch to virtual bank0
	mov r30=r2
	mov r29=r3
	;;
	adds r2=XSI_BANK1_R16_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_R16_OFS+8)-XSI_PSR_IC_OFS,r18;;
	bsw.1;;
	// FIXME?: ar.unat is not really handled correctly,
	// but may not matter if the OS is NaT-clean
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
	bsw.0 ;;
	mov r2=r30
	mov r3=r29
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
	mov pr=r31,-1 ;;
	rfi
	;;
END(hyper_ssm_i)

// reflect domain clock interrupt
//	r31 == pr
//	r30 == cr.ivr
//	r29 == rp
GLOBAL_ENTRY(fast_tick_reflect)
#ifndef FAST_TICK // see beginning of file
	br.cond.sptk.many rp;;
#endif
	mov r28=IA64_TIMER_VECTOR;;
	cmp.ne p6,p0=r28,r30
(p6)	br.cond.spnt.few rp;;
	movl r20=THIS_CPU(cpu_info)+IA64_CPUINFO_ITM_NEXT_OFFSET;;
	ld8 r26=[r20];;
	mov r27=ar.itc;;
	adds r27=200,r27;;	// safety margin
	cmp.ltu p6,p0=r26,r27
(p6)	br.cond.spnt.few rp;;
	mov r17=cr.ipsr;;
	// slow path if: ipsr.be==1, ipsr.pp==1
	extr.u r21=r17,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p6,p0=r21,r0
(p6)	br.cond.spnt.few rp;;
	extr.u r21=r17,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p6,p0=r21,r0
(p6)	br.cond.spnt.few rp;;
	// definitely have a domain tick
	mov cr.eoi=r0;;
	mov rp=r29;;
	mov cr.itm=r26;;	// ensure next tick
#ifdef FAST_REFLECT_CNT
	movl r20=PERFC(fast_reflect + (0x3000>>8));;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	// vcpu_pend_timer(current)
	movl r18=THIS_CPU(current_psr_ic_addr)
	;;
	ld8 r18=[r18]
	;;
	adds r20=XSI_ITV_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	cmp.eq p6,p0=r20,r0	// if cr.itv==0 done
(p6)	br.cond.spnt.few fast_tick_reflect_done;;
	tbit.nz p6,p0=r20,16;;	// check itv.m (discard) bit
(p6)	br.cond.spnt.few fast_tick_reflect_done;;
	extr.u r27=r20,0,6	// r27 has low 6 bits of itv.vector
	extr.u r26=r20,6,2;;	// r26 has irr index of itv.vector
	movl r19=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r19=[r19];;
	adds r22=IA64_VCPU_DOMAIN_ITM_LAST_OFFSET,r19
	adds r23=IA64_VCPU_DOMAIN_ITM_OFFSET,r19;;
	ld8 r24=[r22];;
	ld8 r23=[r23];;
	cmp.eq p6,p0=r23,r24	// skip if this tick already delivered
(p6)	br.cond.spnt.few fast_tick_reflect_done;;
	// set irr bit
	adds r21=IA64_VCPU_IRR0_OFFSET,r19;
	shl r26=r26,3;;
	add r21=r21,r26;;
	mov r25=1;;
	shl r22=r25,r27;;
	ld8 r23=[r21];;
	or r22=r22,r23;;
	st8 [r21]=r22;;
	// set evtchn_upcall_pending!
	adds r20=XSI_PSR_I_ADDR_OFS-XSI_PSR_IC_OFS,r18;;
	ld8 r20=[r20];;
	adds r20=-1,r20;;		// evtchn_upcall_pending
	st1 [r20]=r25;;
	// if interrupted at pl0, we're done
	extr.u r16=r17,IA64_PSR_CPL0_BIT,2;;
	cmp.eq p6,p0=r16,r0;;
(p6)	br.cond.spnt.few fast_tick_reflect_done;;
	// if guest vpsr.i is off, we're done
	movl r21=THIS_CPU(current_psr_i_addr);;
	ld8 r21=[r21];;
	ld1 r21=[r21];;
	cmp.eq p0,p6=r21,r0
(p6)	br.cond.spnt.few fast_tick_reflect_done;;

	// OK, we have a clock tick to deliver to the active domain!
	// so deliver to iva+0x3000
	//	r17 == cr.ipsr
	//	r18 == XSI_PSR_IC
	//	r19 == IA64_KR(CURRENT)
	//	r31 == pr
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
	ld4 r16=[r18];;
	cmp.ne p6,p0=r16,r0;;
	movl r22=THIS_CPU(current_psr_i_addr);;
	ld8 r22=[r22]
(p6)	dep r17=-1,r17,IA64_PSR_IC_BIT,1 ;;
	ld1 r16=[r22];;
	cmp.eq p6,p0=r16,r0;;
(p6)	dep r17=-1,r17,IA64_PSR_I_BIT,1 ;;
	mov r20=1
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17 ;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st1 [r22]=r20;;
	st4 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs to 0
	cover ;;
	mov r20=cr.ifs;;
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
	mov r30=r2
	mov r29=r3
#ifdef HANDLE_AR_UNAT
	mov r28=ar.unat;
#endif
	;;
	adds r2=XSI_BANK1_R16_OFS-XSI_PSR_IC_OFS,r18
	adds r3=(XSI_BANK1_R16_OFS+8)-XSI_PSR_IC_OFS,r18
	;;
	bsw.1;;
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
#ifdef HANDLE_AR_UNAT
 	// r16~r23 are preserved regsin bank0 regs, we need to restore them,
	// r24~r31 are scratch regs, we don't need to handle NaT bit,
	// because OS handler must assign it before access it
	ld8 r16=[r2],16;
	ld8 r17=[r3],16;;
	ld8 r18=[r2],16;
	ld8 r19=[r3],16;;
	ld8 r20=[r2],16;
	ld8 r21=[r3],16;;
	ld8 r22=[r2],16;
	ld8 r23=[r3],16;;
#endif
	;;
	bsw.0 ;;
	mov r24=ar.unat;
	mov r2=r30
	mov r3=r29
#ifdef HANDLE_AR_UNAT
	mov ar.unat=r28;
#endif
	;;
	adds r25=XSI_B1NATS_OFS-XSI_PSR_IC_OFS,r18 ;
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r25]=r24;
	st4 [r20]=r0 ;;
fast_tick_reflect_done:
	mov pr=r31,-1 ;;
	rfi
END(fast_tick_reflect)

// reflect domain breaks directly to domain
//	r16 == cr.isr
//	r17 == cr.iim
//	r18 == XSI_PSR_IC
//	r19 == vpsr.ic
//	r31 == pr
GLOBAL_ENTRY(fast_break_reflect)
#ifndef FAST_BREAK // see beginning of file
	br.sptk.many dispatch_break_fault ;;
#endif
	mov r30=cr.ipsr;;
	mov r29=cr.iip;;
	extr.u r21=r30,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0 ;;
(p7)	br.spnt.few dispatch_break_fault ;;
	extr.u r21=r30,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0 ;;
(p7)	br.spnt.few dispatch_break_fault ;;
        movl r20=IA64_PSR_CPL ;; 
        and r22=r20,r30 ;;
        cmp.ne p7,p0=r22,r0
(p7)    br.spnt.many 1f ;;
        cmp.eq p7,p0=r17,r0
(p7)    br.spnt.few dispatch_break_fault ;;
#ifdef CRASH_DEBUG
	movl r21=CDB_BREAK_NUM ;;
	cmp.eq p7,p0=r17,r21
(p7)	br.spnt.few dispatch_break_fault ;;
#endif	
1:	
#if 1 /* special handling in case running on simulator */
	movl r20=first_break;;
	ld4 r23=[r20];;
	movl r21=0x80001;
	movl r22=0x80002;;
	cmp.ne p7,p0=r23,r0;;
(p7)	br.spnt.few dispatch_break_fault ;;
	cmp.eq p7,p0=r21,r17;
(p7)	br.spnt.few dispatch_break_fault ;;
	cmp.eq p7,p0=r22,r17;
(p7)	br.spnt.few dispatch_break_fault ;;
#endif
	movl r20=0x2c00;
	// save iim in shared_info
	adds r21=XSI_IIM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17;;
	// fall through
END(fast_break_reflect)

// reflect to domain ivt+r20
// sets up isr,iip,ipsr,ifs (FIXME: do iipa too)
//	r16 == cr.isr
//	r18 == XSI_PSR_IC
//	r20 == offset into ivt
//	r29 == iip
//	r30 == ipsr
//	r31 == pr
ENTRY(fast_reflect)
#ifdef FAST_REFLECT_CNT
	movl r22=PERFC(fast_reflect);
	shr r23=r20,8-2;;
	add r22=r22,r23;;
	ld4 r21=[r22];;
	adds r21=1,r21;;
	st4 [r22]=r21;;
#endif
	// save iip in shared_info (DON'T POINT TO NEXT INSTRUCTION!)
	adds r21=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r29,XSI_ISR_OFS-XSI_IIP_OFS;;
	// set shared_mem isr
	st8 [r21]=r16 ;;
	// set cr.ipsr
	movl r21=THIS_CPU(current_psr_i_addr)
	mov r29=r30 ;;
	ld8 r21=[r21]
	movl r28=DELIVER_PSR_SET;;
	movl r27=~(DELIVER_PSR_CLR|IA64_PSR_CPL0);;
	or r29=r29,r28;;
	and r29=r29,r27;;
	// set hpsr_dfh to ipsr
	adds r28=XSI_HPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	ld1 r28=[r28];;
	dep r29=r28,r29,IA64_PSR_DFH_BIT,1;;
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
	ld1 r22=[r21]
	ld4 r24=[r18];;
	cmp4.eq p6,p7=r24,r0;;
(p6)	dep r30=0,r30,IA64_PSR_IC_BIT,1
(p7)	dep r30=-1,r30,IA64_PSR_IC_BIT,1 ;;
	mov r24=r21
	cmp.ne p6,p7=r22,r0;;
(p6)	dep r30=0,r30,IA64_PSR_I_BIT,1
(p7)	dep r30=-1,r30,IA64_PSR_I_BIT,1 ;;
	mov r22=1
	adds r21=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 
	;;
	adds r27=XSI_VPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	ld1 r28=[r27];;
	st1 [r27]=r0
	dep r30=r28,r30,IA64_PSR_DFH_BIT,1
	;;
	st8 [r21]=r30 ;;
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st1 [r24]=r22
	st4 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs to 0
	cover ;;
	mov r24=cr.ifs;;
	adds r21=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r0 ;;
	adds r21=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r24 ;;
	// FIXME: need to save iipa and isr to be arch-compliant
	// set iip to go to domain IVA break instruction vector
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r22=[r22];;
	adds r22=IA64_VCPU_IVA_OFFSET,r22;;
	ld8 r23=[r22];;
	add r20=r20,r23;;
	mov cr.iip=r20;;
	// OK, now all set to go except for switch to virtual bank0
	mov r30=r2
	mov r29=r3
#ifdef HANDLE_AR_UNAT
	mov r28=ar.unat;
#endif
	adds r2=XSI_BANK1_R16_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_R16_OFS+8)-XSI_PSR_IC_OFS,r18
	;;
	bsw.1;;
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
#ifdef HANDLE_AR_UNAT
	// r16~r23 are preserved regs in bank0 regs, we need to restore them,
	// r24~r31 are scratch regs, we don't need to handle NaT bit,
	// because OS handler must assign it before access it
	ld8 r16=[r2],16;
	ld8 r17=[r3],16;;
	ld8 r18=[r2],16;
	ld8 r19=[r3],16;;
	ld8 r20=[r2],16;
	ld8 r21=[r3],16;;
	ld8 r22=[r2],16;
	ld8 r23=[r3],16;;
#endif
	;;
	bsw.0 ;;
	mov r24=ar.unat;
	mov r2=r30
	mov r3=r29
#ifdef HANDLE_AR_UNAT
	mov ar.unat=r28;
#endif
	;;
	adds r25=XSI_B1NATS_OFS-XSI_PSR_IC_OFS,r18 ;
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r25]=r24;
	st4 [r20]=r0 ;;
	mov pr=r31,-1 ;;
	rfi
	;;
END(fast_reflect)

// reflect access faults (0x2400,0x2800,0x5300) directly to domain
//	r16 == isr
//	r17 == ifa
//	r19 == reflect number (only pass-thru to dispatch_reflection)
//	r20 == offset into ivt
//	r31 == pr
GLOBAL_ENTRY(fast_access_reflect)
#ifndef FAST_ACCESS_REFLECT // see beginning of file
	br.spnt.few dispatch_reflection ;;
#endif
	mov r30=cr.ipsr;;
	mov r29=cr.iip;;
	extr.u r21=r30,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.spnt.few dispatch_reflection ;;
	extr.u r21=r30,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.spnt.few dispatch_reflection ;;
	extr.u r21=r30,IA64_PSR_CPL0_BIT,2 ;;
	cmp.eq p7,p0=r21,r0
(p7)	br.spnt.few dispatch_reflection ;;
	movl r18=THIS_CPU(current_psr_ic_addr);;
	ld8 r18=[r18];;
	ld4 r21=[r18];;
	cmp.eq p7,p0=r0,r21
(p7)	br.spnt.few dispatch_reflection ;;
	// set shared_mem ifa, FIXME: should we validate it?
	mov r17=cr.ifa;;
	adds r21=XSI_IFA_OFS-XSI_PSR_IC_OFS,r18 ;; 
	st8 [r21]=r17 ;;
	// get rr[ifa] and save to itir in shared memory (extra bits ignored)
	shr.u r22=r17,61
	adds r23=XSI_ITIR_OFS-XSI_PSR_IC_OFS,r18 
	adds r21=XSI_RR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shladd r22=r22,3,r21;;
	ld8 r22=[r22];;
	and r22=~3,r22;;
	st8 [r23]=r22;;
	br.cond.sptk.many fast_reflect;;
END(fast_access_reflect)

// when we get to here, VHPT_CCHAIN_LOOKUP has failed and everything
// is as it was at the time of original miss.  We want to preserve that
// so if we get a nested fault, we can just branch to page_fault
GLOBAL_ENTRY(fast_tlb_miss_reflect)
#ifndef FAST_TLB_MISS_REFLECT // see beginning of file
	br.spnt.few page_fault ;;
#else
	mov r31=pr
	mov r30=cr.ipsr
	mov r29=cr.iip
	mov r16=cr.isr
	mov r17=cr.ifa;;
	// for now, always take slow path for region 0 (e.g. metaphys mode)
	extr.u r21=r17,61,3;;
	cmp.eq p7,p0=r0,r21
(p7)	br.spnt.few page_fault ;;
	// always take slow path for PL0 (e.g. __copy_from_user)
	extr.u r21=r30,IA64_PSR_CPL0_BIT,2 ;;
	cmp.eq p7,p0=r21,r0
(p7)	br.spnt.few page_fault ;;
	// slow path if strange ipsr or isr bits set
	extr.u r21=r30,IA64_PSR_BE_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.spnt.few page_fault ;;
	extr.u r21=r30,IA64_PSR_PP_BIT,1 ;;
	cmp.ne p7,p0=r21,r0
(p7)	br.spnt.few page_fault ;;
	movl r21=IA64_ISR_IR|IA64_ISR_SP|IA64_ISR_NA ;;
	and r21=r16,r21;;
	cmp.ne p7,p0=r0,r21
(p7)	br.spnt.few page_fault ;;
	// also take slow path if virtual psr.ic=0
	movl r18=XSI_PSR_IC;;
	ld4 r21=[r18];;
	cmp.eq p7,p0=r0,r21
(p7)	br.spnt.few page_fault ;;
	// OK, if we get to here, we are doing a fast vcpu_translate.  Need to:
	// 1) look in the virtual TR's (pinned), if not there
	// 2) look in the 1-entry TLB (pinned), if not there
	// 3) check the domain VHPT (NOT pinned, accesses domain memory!)
	// If we find it in any of these places, we need to effectively do
	// a hyper_itc_i/d

	// short-term hack for now, if in region 5-7, take slow path
	// since all Linux TRs are in region 5 or 7, we need not check TRs
	extr.u r21=r17,61,3;;
	cmp.le p7,p0=5,r21
(p7)	br.spnt.few page_fault ;;
fast_tlb_no_tr_match:
	movl r27=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r27=[r27];;
	tbit.nz p6,p7=r16,IA64_ISR_X_BIT;;
(p6)	adds r25=IA64_VCPU_ITLB_OFFSET,r27;;
(p7)	adds r25=IA64_VCPU_DTLB_OFFSET,r27;;
	ld8 r20=[r25],8;;
	tbit.z p7,p0=r20,0;;	// present?
(p7)	br.cond.spnt.few 1f;;
	// if ifa is in range of tlb, don't bother to check rid, go slow path
	ld8 r21=[r25],8;;
	mov r23=1
	extr.u r21=r21,2,6;;
	shl r22=r23,r21
	ld8 r21=[r25],8;;
	cmp.ltu p7,p0=r17,r21
(p7)	br.cond.sptk.many 1f;
	add r21=r22,r21;;
	cmp.ltu p7,p0=r17,r21
(p7)	br.cond.spnt.few page_fault;;
	
1:	// check the guest VHPT
	adds r19 = XSI_PTA_OFS-XSI_PSR_IC_OFS, r18;;
	ld8 r19=[r19];;
	tbit.nz p7,p0=r19,IA64_PTA_VF_BIT;;	// long format VHPT
(p7)	br.cond.spnt.few page_fault;;
	// if (!rr.ve || !(pta & IA64_PTA_VE)) take slow way for now
	// FIXME: later, we deliver an alt_d/i vector after thash and itir
	tbit.z p7,p0=r19,IA64_PTA_VE_BIT;;	// 
(p7)	br.cond.spnt.few page_fault;;
	extr.u r25=r17,61,3;;
	adds r21=XSI_RR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shl r25=r25,3;;
	add r21=r21,r25;;
	ld8 r22=[r21];;
	tbit.z p7,p0=r22,0
(p7)	br.cond.spnt.few page_fault;;

	// compute and save away itir (r22 & RR_PS_MASK)
	movl r21=0xfc;;
	and r22=r22,r21;;
	adds r21=XSI_ITIR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r22;;
	
	// save away ifa
	adds r21=XSI_IFA_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r21]=r17;;
	// see vcpu_thash to save away iha
	shr.u r20 = r17, 61
	addl r25 = 1, r0
	movl r30 = 0xe000000000000000
	;;
	and r21 = r30, r17		// VHPT_Addr1
	;;
	shladd r28 = r20, 3, r18
	adds r19 = XSI_PTA_OFS-XSI_PSR_IC_OFS, r18
	;;
	adds r27 = XSI_RR0_OFS-XSI_PSR_IC_OFS, r28
	addl r28 = 32767, r0
	ld8 r24 = [r19]			// pta
	;;
	ld8 r23 = [r27]			// rrs[vadr>>61]
	extr.u r26 = r24, 2, 6
	;;
	extr.u r22 = r23, 2, 6
	shl r30 = r25, r26
	;;
	shr.u r19 = r17, r22
	shr.u r29 = r24, 15
	;;
	adds r30 = -1, r30
	;;
	shladd r27 = r19, 3, r0
	extr.u r26 = r30, 15, 46
	;;
	andcm r24 = r29, r26
	and r19 = r28, r27
	shr.u r25 = r27, 15
	;;
	and r23 = r26, r25
	;;
	or r22 = r24, r23
	;;
	dep.z r20 = r22, 15, 46
	;;
	or r30 = r20, r21
	;;
	//or r8 = r19, r30
	or r19 = r19, r30
	;;
	adds r23=XSI_IHA_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r23]=r19;;
	// done with thash, check guest VHPT

	adds r20 = XSI_PTA_OFS-XSI_PSR_IC_OFS, r18;;
	ld8 r24 = [r20];;			// pta
	// avoid recursively walking the VHPT
	// if (((r17=address ^ r24=pta) & ((itir_mask(pta) << 3) >> 3)) != 0) {
	mov r20=-8
	xor r21=r17,r24
	extr.u r24=r24,2,6;;
	shl r20=r20,r24;;
	shr.u r20=r20,3;;
	and r21=r20,r21;;
	cmp.eq p7,p0=r21,r0
(p7)	br.cond.spnt.few 1f;;
	// __copy_from_user(&pte, r19=(void *)(*iha), sizeof(pte)=8)
	// prepare for possible nested dtlb fault
	mov r29=b0
	movl r30=guest_vhpt_miss;;
	// now go fetch the entry from the guest VHPT
	ld8 r20=[r19];;
	// if we wind up here, we successfully loaded the VHPT entry

	// this VHPT walker aborts on non-present pages instead
	// of inserting a not-present translation, this allows
	// vectoring directly to the miss handler
	tbit.z p7,p0=r20,0
(p7)	br.cond.spnt.few page_not_present;;

#ifdef FAST_REFLECT_CNT
	movl r21=PERFC(fast_vhpt_translate);;
	ld4 r22=[r21];;
	adds r22=1,r22;;
	st4 [r21]=r22;;
#endif

// prepare for fast_insert(PSCB(ifa),PSCB(itir),r16=pte)
//	r16 == pte
//	r17 == bit0: 1=inst, 0=data; bit1: 1=itc, 0=vcpu_translate
//	r18 == XSI_PSR_IC_OFS
//	r24 == ps
//	r29 == saved value of b0 in case of recovery
//	r30 == recovery ip if failure occurs
//	r31 == pr
	tbit.nz p6,p7=r16,IA64_ISR_X_BIT;;
(p6)	mov r17=1;;
(p7)	mov r17=0;;
	mov r16=r20
	mov r29=b0 ;;
	movl r30=recover_and_page_fault ;;
	adds r21=XSI_ITIR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r24=[r21];;
	extr.u r24=r24,2,6;;
	// IFA already in PSCB
	br.cond.sptk.many fast_insert;;
END(fast_tlb_miss_reflect)

// we get here if fast_insert fails (e.g. due to metaphysical lookup)
ENTRY(recover_and_page_fault)
#ifdef PERF_COUNTERS
	movl r21=PERFC(recover_to_page_fault);;
	ld4 r22=[r21];;
	adds r22=1,r22;;
	st4 [r21]=r22;;
#endif
	mov b0=r29;;
	br.cond.sptk.many page_fault;;

// if we wind up here, we missed in guest VHPT so recover
// from nested dtlb fault and reflect a tlb fault to the guest
guest_vhpt_miss:
	mov b0=r29;;
	// fault = IA64_VHPT_FAULT
	mov r20=r0
	br.cond.sptk.many 1f;

	// if we get to here, we are ready to reflect
	// need to set up virtual ifa, iha, itir (fast_reflect handles
	// virtual isr, iip, ipsr, ifs
	// see vcpu_get_itir_on_fault: get ps,rid,(FIXME key) from rr[ifa]
page_not_present:
	tbit.nz p6,p7=r16,IA64_ISR_X_BIT;;
(p6)	movl r20=0x400;;
(p7)	movl r20=0x800;;

1:	extr.u r25=r17,61,3;;
	adds r21=XSI_RR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shl r25=r25,3;;
	add r21=r21,r25;;
	ld8 r22=[r21];;
	extr.u r22=r22,2,30;;
	dep.z r22=r22,2,30;;
	adds r23=XSI_ITIR_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r23]=r22;;

	// fast reflect expects
	//	r16 == cr.isr
	//	r18 == XSI_PSR_IC
	//	r20 == offset into ivt
	//	r29 == iip
	//	r30 == ipsr
	//	r31 == pr
	//mov r16=cr.isr
	mov r29=cr.iip
	mov r30=cr.ipsr
	br.sptk.many fast_reflect;;
#endif
END(fast_tlb_miss_reflect)

ENTRY(slow_vcpu_rfi)
	adds r22=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18;;
	ld8 r22=[r22];;
	tbit.z p6,p0=r22,63
(p6)	br.spnt.few dispatch_break_fault ;;
	// if vips is valid, discard current register frame
	// don't need dorfirfi any more
	alloc r22=ar.pfs,0,0,0,0
	br.spnt.few dispatch_break_fault
	;;
END(slow_vcpu_rfi)    

// ensure that, if giving up, registers at entry to fast_hyperprivop unchanged
ENTRY(hyper_rfi)
#ifndef FAST_RFI
	br.spnt.few slow_vcpu_rfi ;;
#endif
	// if no interrupts pending, proceed
	mov r30=r0
	cmp.eq p7,p0=r20,r0
(p7)	br.sptk.many 1f
	;;
	adds r20=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r20];;		// r21 = vcr.ipsr
	extr.u r22=r21,IA64_PSR_I_BIT,1 ;;
	mov r30=r22;;
	// r30 determines whether we might deliver an immediate extint
#ifndef RFI_TO_INTERRUPT // see beginning of file
	cmp.ne p6,p0=r30,r0
(p6)	br.cond.spnt.few slow_vcpu_rfi ;;
#endif
1:
	adds r20=XSI_IPSR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r20];;		// r21 = vcr.ipsr
	extr.u r22=r21,IA64_PSR_BE_BIT,1 ;;
	// if turning on psr.be, give up for now and do it the slow way
	cmp.ne p7,p0=r22,r0
(p7)	br.spnt.few slow_vcpu_rfi ;;
	// if (!(vpsr.dt && vpsr.rt && vpsr.it)), do it the slow way
	movl r20=(IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_IT);;
	and r22=r20,r21
	;;
	cmp.ne p7,p0=r22,r20
(p7)	br.spnt.few slow_vcpu_rfi ;;
	// if was in metaphys mode, do it the slow way (FIXME later?)
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r20=[r20];;
	cmp.ne p7,p0=r20,r0
(p7)	br.spnt.few slow_vcpu_rfi ;;
	// if domain hasn't already done virtual bank switch
	//  do it the slow way (FIXME later?)
#if 0
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r20=[r20];;
	cmp.eq p7,p0=r20,r0
(p7)	br.spnt.few slow_vcpu_rfi ;;
#endif
	// validate vcr.iip, if in Xen range, do it the slow way
	adds r20=XSI_IIP_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r22=[r20];;
	movl r23=HYPERVISOR_VIRT_START
	movl r24=HYPERVISOR_VIRT_END;;
	cmp.ltu p0,p7=r22,r23 ;;	// if !(iip<low) &&
(p7)	cmp.geu p0,p7=r22,r24 ;;	//    !(iip>=high)
(p7)	br.spnt.few slow_vcpu_rfi ;;

1:	// OK now, let's do an rfi.
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_RFI);;
	ld4 r23=[r20];;
	adds r23=1,r23;;
	st4 [r20]=r23;;
#endif
#ifdef RFI_TO_INTERRUPT
	// maybe do an immediate interrupt delivery?
	cmp.ne p6,p0=r30,r0
(p6)	br.cond.spnt.few rfi_check_extint;;
#endif

just_do_rfi:
	// r18=&vpsr.i|vpsr.ic, r21==vpsr, r22=vcr.iip
	mov cr.iip=r22;;
	adds r20=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	dep r20=0,r20,38,25;; // ensure ifs has no reserved bits set
	mov cr.ifs=r20 ;;
	// ipsr.cpl == (vcr.ipsr.cpl == 0) 2 : 3;
	movl r20=THIS_CPU(current_psr_i_addr)
	dep r21=-1,r21,IA64_PSR_CPL1_BIT,1 ;;
	// vpsr.i = vcr.ipsr.i; vpsr.ic = vcr.ipsr.ic
	ld8 r20=[r20]
	mov r19=1 
	extr.u r23=r21,IA64_PSR_I_BIT,1 ;;
	cmp.ne p7,p6=r23,r0 ;;
	// not done yet
(p7)	st1 [r20]=r0
(p6)	st1 [r20]=r19;;
	extr.u r23=r21,IA64_PSR_IC_BIT,1 ;;
	cmp.ne p7,p6=r23,r0 ;;
(p7)	st4 [r18]=r19;;
(p6)	st4 [r18]=r0;;
	// force on psr.ic, i, dt, rt, it, bn
	movl r20=(IA64_PSR_I|IA64_PSR_IC|IA64_PSR_DT|IA64_PSR_RT| \
	          IA64_PSR_IT|IA64_PSR_BN)
	;;
	or r21=r21,r20
	;;
	adds r20=XSI_VPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	tbit.z p8,p9 = r21, IA64_PSR_DFH_BIT
	;;
	(p9) mov r27=1;;
	(p9) st1 [r20]=r27
	;;
	(p8) st1 [r20]=r0
	(p8) adds r20=XSI_HPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	(p8) ld1 r27=[r20]
	;;
	(p8) dep r21=r27,r21, IA64_PSR_DFH_BIT, 1
	;;
	mov cr.ipsr=r21
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.ne p7,p0=r21,r0	// domain already did "bank 1 switch?"
(p7)	br.cond.spnt.few 1f;
	// OK, now all set to go except for switch to virtual bank1
	mov r22=1;; st4 [r20]=r22;
	mov r30=r2; mov r29=r3;;
    mov r17=ar.unat;;
    adds r16=XSI_B1NATS_OFS-XSI_PSR_IC_OFS,r18
	adds r2=XSI_BANK1_R16_OFS-XSI_PSR_IC_OFS,r18;
	adds r3=(XSI_BANK1_R16_OFS+8)-XSI_PSR_IC_OFS,r18;;
    ld8 r16=[r16];;
    mov ar.unat=r16;;
	bsw.1;;
	// FIXME?: ar.unat is not really handled correctly,
	// but may not matter if the OS is NaT-clean
	.mem.offset 0,0; ld8.fill r16=[r2],16 ;
	.mem.offset 8,0; ld8.fill r17=[r3],16 ;;
	.mem.offset 0,0; ld8.fill r18=[r2],16 ;
	.mem.offset 0,0; ld8.fill r19=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r20=[r2],16 ;
	.mem.offset 8,0; ld8.fill r21=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r22=[r2],16 ;
	.mem.offset 8,0; ld8.fill r23=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r24=[r2],16 ;
	.mem.offset 8,0; ld8.fill r25=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r26=[r2],16 ;
	.mem.offset 8,0; ld8.fill r27=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r28=[r2],16 ;
	.mem.offset 8,0; ld8.fill r29=[r3],16 ;;
	.mem.offset 8,0; ld8.fill r30=[r2],16 ;
	.mem.offset 8,0; ld8.fill r31=[r3],16 ;;
	bsw.0 ;;
    mov ar.unat=r17;;
	mov r2=r30; mov r3=r29;;
1:	mov pr=r31,-1
	;;
	rfi
	;;
END(hyper_rfi)
	
#ifdef RFI_TO_INTERRUPT
ENTRY(rfi_check_extint)
	//br.sptk.many dispatch_break_fault ;;

	// r18=&vpsr.i|vpsr.ic, r21==vpsr, r22=vcr.iip
	// make sure none of these get trashed in case going to just_do_rfi
	movl r30=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r30=[r30];;
	adds r24=IA64_VCPU_INSVC3_OFFSET,r30;;
	mov r25=192
	adds r16=IA64_VCPU_IRR3_OFFSET,r30;;
	ld8 r23=[r16];;
	cmp.eq p6,p0=r23,r0;;
(p6)	adds r16=-8,r16;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r16];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r16=-8,r16;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r16];;
(p6)	cmp.eq p6,p0=r23,r0;;
(p6)	adds r16=-8,r16;;
(p6)	adds r24=-8,r24;;
(p6)	adds r25=-64,r25;;
(p6)	ld8 r23=[r16];;
(p6)	cmp.eq p6,p0=r23,r0;;
	cmp.eq p6,p0=r23,r0
(p6)	br.cond.spnt.few just_do_rfi;	// this is actually an error
	// r16 points to non-zero element of irr, r23 has value
	// r24 points to corr element of insvc, r25 has elt*64
	ld8 r26=[r24];;
	cmp.geu p6,p0=r26,r23
(p6)	br.cond.spnt.many just_do_rfi;

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
	cmp.ne p6,p0=r28,r0	// if tpr.mmi is set, just rfi
(p6)	br.cond.spnt.few just_do_rfi;;
	shl r29=r29,4;;
	adds r29=15,r29;;
	cmp.ge p6,p0=r29,r26	// if tpr masks interrupt, just rfi
(p6)	br.cond.spnt.few just_do_rfi;;
END(rfi_check_extint)

// this doesn't work yet (dies early after getting to user mode)
// but happens relatively infrequently, so fix it later.
// NOTE that these will be counted incorrectly for now (for privcnt output)
ENTRY(rfi_with_interrupt)
#if 1
	br.sptk.many dispatch_break_fault ;;
#endif

	// OK, have an unmasked vector, so deliver extint to vcr.iva+0x3000
	//	r18 == XSI_PSR_IC
	//	r21 == vipsr (ipsr in shared_mem)
	//	r30 == IA64_KR(CURRENT)
	//	r31 == pr
	mov r17=cr.ipsr;;
	mov r16=cr.isr;;
	// set shared_mem isr
	extr.u r16=r16,38,1;;	// grab cr.isr.ir bit
	dep r16=r16,r0,38,1 ;;	// insert into cr.isr (rest of bits zero)
	extr.u r20=r21,41,2 ;;	// get v(!)psr.ri
	dep r16=r20,r16,41,2 ;; // deposit cr.isr.ei
	adds r22=XSI_ISR_OFS-XSI_PSR_IC_OFS,r18 ;; 
	st8 [r22]=r16;;
	movl r22=THIS_CPU(current_psr_i_addr)
	// set cr.ipsr (make sure cpl==2!)
	mov r29=r17
	movl r28=DELIVER_PSR_SET;;
	mov r20=1;;
	ld8 r22=[r22]
	movl r27=~(DELIVER_PSR_CLR|IA64_PSR_CPL0)
	or r29=r29,r28;;
	and r29=r29,r27;;
	mov cr.ipsr=r29;;
	// v.ipsr and v.iip are already set (and v.iip validated) as rfi target
	// set shared_mem interrupt_delivery_enabled to 0
	// set shared_mem interrupt_collection_enabled to 0
	st1 [r22]=r20
	st4 [r18]=r0;;
	// cover and set shared_mem precover_ifs to cr.ifs
	// set shared_mem ifs to 0
#if 0
	cover ;;
	mov r20=cr.ifs;;
	adds r22=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r22]=r0 ;;
	adds r22=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r22]=r20 ;;
	// leave cr.ifs alone for later rfi
#else
	adds r22=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r22];;
	st8 [r22]=r0 ;;
	adds r22=XSI_PRECOVER_IFS_OFS-XSI_PSR_IC_OFS,r18 ;;
	st8 [r22]=r20 ;;
#endif
	// set iip to go to domain IVA break instruction vector
	adds r22=IA64_VCPU_IVA_OFFSET,r30;;
	ld8 r23=[r22];;
	movl r24=0x3000;;
	add r24=r24,r23;;
	mov cr.iip=r24;;
#if 0
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
	bsw.0 ;;
	mov r2=r30; mov r3=r29;;
#endif
	adds r20=XSI_BANKNUM_OFS-XSI_PSR_IC_OFS,r18 ;;
	st4 [r20]=r0 ;;
	mov pr=r31,-1 ;;
	rfi
END(rfi_with_interrupt)
#endif // RFI_TO_INTERRUPT

ENTRY(hyper_cover)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_COVER);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	// skip test for vpsr.ic.. it's a prerequisite for hyperprivops
	cover ;;
	mov r30=cr.ifs
	adds r22=XSI_IFS_OFS-XSI_PSR_IC_OFS,r18;;
	st8 [r22]=r30;;
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
END(hyper_cover)

// return from metaphysical mode (meta=1) to virtual mode (meta=0)
ENTRY(hyper_ssm_dt)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_SSM_DT);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.eq p7,p0=r21,r0	// meta==0?
(p7)	br.spnt.many	1f ;;	// already in virtual mode
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r22=[r22];;
	adds r22=IA64_VCPU_META_SAVED_RR0_OFFSET,r22;;
	ld8 r23=[r22];;
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
END(hyper_ssm_dt)

// go to metaphysical mode (meta=1) from virtual mode (meta=0)
ENTRY(hyper_rsm_dt)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_RSM_DT);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	mov r25=cr.iip;;
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.ne p7,p0=r21,r0	// meta==0?
(p7)	br.spnt.many	1f ;;	// already in metaphysical mode
	movl r22=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r22=[r22];;
	adds r22=IA64_VCPU_META_RR0_OFFSET,r22;;
	ld8 r23=[r22];;
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
END(hyper_rsm_dt)

ENTRY(hyper_set_itm)
	// when we get to here r20=~=interrupts pending
	cmp.ne p7,p0=r20,r0
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_SET_ITM);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	movl r20=THIS_CPU(cpu_info)+IA64_CPUINFO_ITM_NEXT_OFFSET;;
	ld8 r21=[r20];;
	movl r20=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r20=[r20];;
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

ENTRY(hyper_get_psr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_GET_PSR);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	mov r24=cr.ipsr
	movl r8=0x18ffffffff;;
	// only return PSR{36:35,31:0}
	and r8=r8,r24
	// set vpsr.ic
	ld4 r21=[r18];;
	dep r8=r21,r8,IA64_PSR_IC_BIT,1
	// set vpsr.pp
	adds r20=XSI_VPSR_PP_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld1 r21=[r20];;
	dep r8=r21,r8,IA64_PSR_PP_BIT,1
	// set vpsr.dt
	adds r20=XSI_METAPHYS_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld4 r21=[r20];;
	cmp.ne p6,p0=r21,r0
	;;
(p6)	dep.z r8=r8,IA64_PSR_DT_BIT,1
	// set vpsr.i
	adds r20=XSI_PSR_I_ADDR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r20=[r20];;
	ld1 r21=[r20];;
	dep r8=r21,r8,IA64_PSR_I_BIT,1
	;;
	// set vpsr.dfh
	adds r20=XSI_VPSR_DFH_OFS-XSI_PSR_IC_OFS,r18;;
	ld1 r21=[r20];;
	dep r8=r21,r8,IA64_PSR_DFH_BIT,1
	;;
	mov r25=cr.iip
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
END(hyper_get_psr)

    
ENTRY(hyper_get_rr)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_GET_RR);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
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
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_SET_RR);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	extr.u r26=r9,8,24	// r26 = r9.rid
	movl r20=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r20=[r20];;
	adds r21=IA64_VCPU_STARTING_RID_OFFSET,r20;;
	ld4 r22=[r21];;
	adds r21=IA64_VCPU_ENDING_RID_OFFSET,r20;;
	ld4 r23=[r21];;
	adds r24=IA64_VCPU_META_SAVED_RR0_OFFSET,r20;;
	add r22=r26,r22;;
	cmp.geu p6,p0=r22,r23	// if r9.rid + starting_rid >= ending_rid
(p6)	br.cond.spnt.few 1f;	// this is an error, but just ignore/return
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
(p6)	st8 [r24]=r23
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

ENTRY(hyper_set_kr)
	extr.u r25=r8,3,61;;
	cmp.ne p7,p0=r0,r25	// if kr# > 7, go slow way
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_SET_KR);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	adds r21=XSI_KR0_OFS-XSI_PSR_IC_OFS,r18 ;;
	shl r20=r8,3;;
	add r22=r20,r21;;
	st8 [r22]=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar0=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar1=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar2=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar3=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar4=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar5=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar6=r9;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar7=r9;;
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
END(hyper_set_kr)

// this routine was derived from optimized assembly output from
// vcpu_thash so it is dense and difficult to read but it works
// On entry:
//	r18 == XSI_PSR_IC
//	r31 == pr
ENTRY(hyper_thash)
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_THASH);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	shr.u r20 = r8, 61
	addl r25 = 1, r0
	movl r17 = 0xe000000000000000
	;;
	and r21 = r17, r8		// VHPT_Addr1
	;;
	shladd r28 = r20, 3, r18
	adds r19 = XSI_PTA_OFS-XSI_PSR_IC_OFS, r18
	;;
	adds r27 = XSI_RR0_OFS-XSI_PSR_IC_OFS, r28
	addl r28 = 32767, r0
	ld8 r24 = [r19]			// pta
	;;
	ld8 r23 = [r27]			// rrs[vadr>>61]
	extr.u r26 = r24, 2, 6
	;;
	extr.u r22 = r23, 2, 6
	shl r30 = r25, r26
	;;
	shr.u r19 = r8, r22
	shr.u r29 = r24, 15
	;;
	adds r17 = -1, r30
	;;
	shladd r27 = r19, 3, r0
	extr.u r26 = r17, 15, 46
	;;
	andcm r24 = r29, r26
	and r19 = r28, r27
	shr.u r25 = r27, 15
	;;
	and r23 = r26, r25
	;;
	or r22 = r24, r23
	;;
	dep.z r20 = r22, 15, 46
	;;
	or r16 = r20, r21
	;;
	or r8 = r19, r16
	// done, update iip/ipsr to next instruction
	mov r24=cr.ipsr
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
END(hyper_thash)

ENTRY(hyper_ptc_ga)
#ifndef FAST_PTC_GA
	br.spnt.few dispatch_break_fault ;;
#endif
	// FIXME: validate not flushing Xen addresses
#ifdef FAST_HYPERPRIVOP_CNT
	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_PTC_GA);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
	mov r28=r8
	extr.u r19=r9,2,6		// addr_range=1<<((r9&0xfc)>>2)
	mov r20=1
	shr.u r24=r8,61
	addl r27=56,r0			// PAGE_SHIFT<<2 (for ptc.ga)
	movl r26=0x8000000000000000	// INVALID_TI_TAG
	mov r30=ar.lc
	;;
	shl r19=r20,r19
	cmp.eq p7,p0=7,r24
(p7)	br.spnt.many dispatch_break_fault ;;	// slow way for rr7
	;;
	cmp.le p7,p0=r19,r0		// skip flush if size<=0
(p7)	br.cond.dpnt 2f ;;
	extr.u r24=r19,0,PAGE_SHIFT
	shr.u r23=r19,PAGE_SHIFT ;;	// repeat loop for n pages
	cmp.ne p7,p0=r24,r0 ;;
(p7)	adds r23=1,r23 ;;		// n_pages<size<n_pages+1? extra iter
	mov ar.lc=r23
	movl r29=PAGE_SIZE;;
1:
	thash r25=r28 ;;
	adds r25=16,r25 ;;
	ld8 r24=[r25] ;;
	// FIXME: should check if tag matches, not just blow it away
	or r24=r26,r24 ;;		// vhpt_entry->ti_tag = 1
	st8 [r25]=r24
	ptc.ga r28,r27 ;;
	srlz.i ;;
	add r28=r29,r28
	br.cloop.sptk.few 1b
	;;
2:
	mov ar.lc=r30 ;;
	mov r29=cr.ipsr
	mov r30=cr.iip;;
	movl r27=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r27=[r27];;
	adds r25=IA64_VCPU_DTLB_OFFSET,r27
	adds r26=IA64_VCPU_ITLB_OFFSET,r27;;
	ld8 r24=[r25]
	ld8 r27=[r26] ;;
	and r24=-2,r24
	and r27=-2,r27 ;;
	st8 [r25]=r24			// set 1-entry i/dtlb as not present
	st8 [r26]=r27 ;;
	// increment to point to next instruction
	extr.u r26=r29,41,2 ;;
	cmp.eq p6,p7=2,r26 ;;
(p6)	mov r26=0
(p6)	adds r30=16,r30
(p7)	adds r26=1,r26
	;;
	dep r29=r26,r29,41,2
	;;
	mov cr.ipsr=r29
	mov cr.iip=r30
	mov pr=r31,-1 ;;
	rfi
	;;
END(hyper_ptc_ga)

// recovery block for hyper_itc metaphysical memory lookup
ENTRY(recover_and_dispatch_break_fault)
#ifdef PERF_COUNTERS
	movl r21=PERFC(recover_to_break_fault);;
	ld4 r22=[r21];;
	adds r22=1,r22;;
	st4 [r21]=r22;;
#endif
	mov b0=r29 ;;
	br.sptk.many dispatch_break_fault;;
END(recover_and_dispatch_break_fault)

//  Registers at entry
//	r17 = break immediate (HYPERPRIVOP_ITC_D or I)
//	r18 == XSI_PSR_IC_OFS
//	r31 == pr
ENTRY(hyper_itc)
hyper_itc_i:	
	// fall through, hyper_itc_d handles both i and d
hyper_itc_d:	
#ifndef FAST_ITC
	br.sptk.many dispatch_break_fault ;;
#else
	// ensure itir.ps >= xen's pagesize
	adds r23=XSI_ITIR_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r23=[r23];;
	extr.u r24=r23,2,6;;		// r24==logps
	cmp.gt p7,p0=PAGE_SHIFT,r24
(p7)	br.spnt.many dispatch_break_fault ;;
	adds r21=XSI_IFA_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r21];;
	// for now, punt on region0 inserts
	extr.u r21=r21,61,3;;
	cmp.eq p7,p0=r21,r0
(p7)	br.spnt.many dispatch_break_fault ;;
	movl r27=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r27=[r27];;
	adds r27=IA64_VCPU_DOMAIN_OFFSET,r27;;
	ld8 r27=[r27];;
// FIXME: is the global var dom0 always pinned? assume so for now
	movl r28=dom0;;
	ld8 r28=[r28];;
// FIXME: for now, only handle dom0 (see lookup_domain_mpa below)
	cmp.ne p7,p0=r27,r28
(p7)	br.spnt.many dispatch_break_fault ;;
#ifdef FAST_HYPERPRIVOP_CNT
	cmp.eq p6,p7=HYPERPRIVOP_ITC_D,r17;;
(p6)	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_ITC_D);;
(p7)	movl r20=FAST_HYPERPRIVOP_PERFC(HYPERPRIVOP_ITC_I);;
	ld4 r21=[r20];;
	adds r21=1,r21;;
	st4 [r20]=r21;;
#endif
(p6)	mov r17=2;;
(p7)	mov r17=3;;
	mov r29=b0 ;;
	movl r30=recover_and_dispatch_break_fault ;;
	mov r16=r8;;
	// fall through
#endif
END(hyper_itc)

#if defined(FAST_ITC) || defined (FAST_TLB_MISS_REFLECT)

// fast_insert(PSCB(ifa),r24=ps,r16=pte)
//	r16 == pte
//	r17 == bit0: 1=inst, 0=data; bit1: 1=itc, 0=vcpu_translate
//	r18 == XSI_PSR_IC_OFS
//	r24 == ps
//	r29 == saved value of b0 in case of recovery
//	r30 == recovery ip if failure occurs
//	r31 == pr
ENTRY(fast_insert)
	// translate_domain_pte(r16=pteval,PSCB(ifa)=address,r24=itir)
	mov r19=1;;
	shl r20=r19,r24;;
	adds r20=-1,r20;;	// r20 == mask
	movl r19=_PAGE_PPN_MASK;;
	and r22=r16,r19;;	// r22 == pteval & _PAGE_PPN_MASK
	andcm r19=r22,r20;;
	adds r21=XSI_IFA_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r21=[r21];;
	and r20=r21,r20;;
	or r19=r19,r20;;	// r19 == mpaddr
// FIXME: for now, just do domain0 and skip mpaddr range checks
	dep r20=r0,r19,0,PAGE_SHIFT
	movl r21=PAGE_PHYS ;;
	or r20=r20,r21 ;;	// r20==return value from lookup_domain_mpa
	// r16=pteval,r20=pteval2
	movl r19=_PAGE_PPN_MASK
	movl r21=_PAGE_PL_2;;
	andcm r25=r16,r19;;	// r25==pteval & ~_PAGE_PPN_MASK
	and r22=r20,r19;;
	or r22=r22,r21;;
	or r22=r22,r25;;	// r22==return value from translate_domain_pte
	// done with translate_domain_pte
	// now do vcpu_itc_no_srlz(vcpu,IorD,ifa,r22=pte,r16=mppte,r24=logps)
// FIXME: for now, just domain0 and skip range check
	// psr.ic already cleared
	// NOTE: r24 still contains ps (from above)
	shladd r24=r24,2,r0;;
	mov cr.itir=r24;;
	adds r23=XSI_IFA_OFS-XSI_PSR_IC_OFS,r18 ;;
	ld8 r23=[r23];;
	mov cr.ifa=r23;;
	tbit.z p6,p7=r17,0;;
(p6)	itc.d r22;;
(p7)	itc.i r22;;
	dv_serialize_data
	// vhpt_insert(r23=vaddr,r22=pte,r24=logps<<2)
	thash r28=r23
	or r26=1,r22;;
	ttag r21=r23
	adds r25=8,r28
	mov r19=r28;;
	st8 [r25]=r24
	adds r20=16,r28;;
	st8 [r19]=r26
	st8 [r20]=r21;;
	// vcpu_set_tr_entry(trp,r22=pte|1,r24=itir,r23=ifa)
	// TR_ENTRY = {page_flags,itir,addr,rid}
	tbit.z p6,p7=r17,0;;
	movl r27=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r27=[r27];;
	adds r28=IA64_VCPU_STARTING_RID_OFFSET,r27
(p6)	adds r27=IA64_VCPU_DTLB_OFFSET,r27
(p7)	adds r27=IA64_VCPU_ITLB_OFFSET,r27;;
	st8 [r27]=r22,8;;	// page_flags: already has pl >= 2 and p==1
	st8 [r27]=r24,8;;	// itir
	mov r19=-4096;;
	and r23=r23,r19;;
	st8 [r27]=r23,8;;	// ifa & ~0xfff
	adds r29 = XSI_RR0_OFS-XSI_PSR_IC_OFS,r18
	extr.u r25=r23,61,3;;
	shladd r29=r25,3,r29;;
	ld8 r29=[r29];;
	movl r20=0xffffff00;;
	and r29=r29,r20;;
	st8 [r27]=r29,-8;;		// rid
	//if ps > 12
	cmp.eq p7,p0=12<<2,r24
(p7)	br.cond.sptk.many 1f;;
	// if (ps > 12) {
	// trp->ppn &= ~((1UL<<(ps-12))-1); trp->vadr &= ~((1UL<<ps)-1); }
	extr.u r29=r24,2,6
	mov r28=1;;
	shl r26=r28,r29;;
	adds r29=-12,r29;;
	shl r25=r28,r29;;
	mov r29=-1
	adds r26=-1,r26
	adds r25=-1,r25;;
	andcm r26=r29,r26	// ~((1UL<<ps)-1)
	andcm r25=r29,r25;;	// ~((1UL<<(ps-12))-1)
	ld8 r29=[r27];;
	and r29=r29,r26;;
	st8 [r27]=r29,-16;;
	ld8 r29=[r27];;
	extr.u r28=r29,12,38;;
	movl r26=0xfffc000000000fff;;
	and r29=r29,r26
	and r28=r28,r25;;
	shl r28=r28,12;;
	or r29=r29,r28;;
	st8 [r27]=r29;;
1:	// done with vcpu_set_tr_entry
	//PSCBX(vcpu,i/dtlb_pte) = mp_pte
	movl r27=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;;
	ld8 r27=[r27];;
	tbit.z p6,p7=r17,0;;
(p6)	adds r27=IA64_VCPU_DTLB_PTE_OFFSET,r27
(p7)	adds r27=IA64_VCPU_ITLB_PTE_OFFSET,r27;;
	st8 [r27]=r16;;
	// done with vcpu_itc_no_srlz

	// if hyper_itc, increment to point to next instruction
	tbit.z p7,p0=r17,1
(p7)	br.cond.sptk.few no_inc_iip;;

	mov r29=cr.ipsr
	mov r30=cr.iip;;
	extr.u r26=r29,41,2 ;;
	cmp.eq p6,p7=2,r26 ;;
(p6)	mov r26=0
(p6)	adds r30=16,r30
(p7)	adds r26=1,r26
	;;
	dep r29=r26,r29,41,2
	;;
	mov cr.ipsr=r29
	mov cr.iip=r30;;

no_inc_iip:
	mov pr=r31,-1 ;;
	rfi
	;;
END(fast_insert)
#endif
