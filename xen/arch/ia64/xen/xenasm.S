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

#if 0
// FIXME: there's gotta be a better way...
// ski and spaski are different... moved to xenmisc.c
#define RunningOnHpSki(rx,ry,pn) 			\
	addl rx = 2, r0; 				\
	addl ry = 3, r0; 				\
	;; 						\
	mov rx = cpuid[rx]; 				\
	mov ry = cpuid[ry]; 				\
	;; 						\
	cmp.eq pn,p0 = 0, rx; 				\
	;; 						\
	(pn) movl rx = 0x7000004 ; 			\
	;; 						\
	(pn) cmp.ge pn,p0 = ry, rx; 			\
	;;

//int platform_is_hp_ski(void)
GLOBAL_ENTRY(platform_is_hp_ski)
	mov r8 = 0
	RunningOnHpSki(r3,r9,p8)
(p8)	mov r8 = 1
	br.ret.sptk.many b0
END(platform_is_hp_ski)
#endif

// Change rr7 to the passed value while ensuring
// Xen is mapped into the new region.
//   in0: new rr7 value
//   in1: Xen virtual address of shared info (to be pinned)
#define PSR_BITS_TO_CLEAR						\
	(IA64_PSR_I | IA64_PSR_IT | IA64_PSR_DT | IA64_PSR_RT |		\
	 IA64_PSR_DD | IA64_PSR_SS | IA64_PSR_RI | IA64_PSR_ED |	\
	 IA64_PSR_DFL | IA64_PSR_DFH)
// FIXME? Note that this turns off the DB bit (debug)
#define PSR_BITS_TO_SET	IA64_PSR_BN

//extern void ia64_new_rr7(unsigned long rid,void *shared_info, void *shared_arch_info, unsigned long p_vhpt, unsigned long v_pal);
GLOBAL_ENTRY(ia64_new_rr7)
	// not sure this unwind statement is correct...
	.prologue ASM_UNW_PRLG_RP|ASM_UNW_PRLG_PFS, ASM_UNW_PRLG_GRSAVE(1)
	alloc loc1 = ar.pfs, 5, 9, 0, 0
1:	{
	  mov r28  = in0		// copy procedure index
	  mov r8   = ip			// save ip to compute branch
	  mov loc0 = rp			// save rp
	};;
	.body
	movl loc2=PERCPU_ADDR
	;;
	tpa loc2=loc2			// grab this BEFORE changing rr7
	;;
	dep loc8=0,in4,60,4
	;;
#if VHPT_ENABLED
	mov loc6=in3
	;;
	//tpa loc6=loc6			// grab this BEFORE changing rr7
	;;
#endif
	mov loc5=in1
	;;
	tpa loc5=loc5			// grab this BEFORE changing rr7
	;;
	mov loc7=in2			// arch_vcpu_info_t
	;;
	tpa loc7=loc7			// grab this BEFORE changing rr7
	;;
	mov loc3 = psr			// save psr
	adds r8  = 1f-1b,r8		// calculate return address for call
	;;
	tpa r8=r8			// convert rp to physical
	;;
	mov loc4=ar.rsc			// save RSE configuration
	;;
	mov ar.rsc=0			// put RSE in enforced lazy, LE mode
	movl r16=PSR_BITS_TO_CLEAR
	movl r17=PSR_BITS_TO_SET
	;;
	or loc3=loc3,r17		// add in psr the bits to set
	;;
	andcm r16=loc3,r16		// removes bits to clear from psr
	br.call.sptk.many rp=ia64_switch_mode_phys
1:
	// now in physical mode with psr.i/ic off so do rr7 switch
	dep	r16=-1,r0,61,3
	;;
	mov	rr[r16]=in0
	srlz.d
	;;

	// re-pin mappings for kernel text and data
	mov r18=KERNEL_TR_PAGE_SHIFT<<2
	movl r17=KERNEL_START
	;;
	rsm psr.i | psr.ic
	;;
	srlz.i
	;;
	ptr.i	r17,r18
	ptr.d	r17,r18
	;;
	mov cr.itir=r18
	mov cr.ifa=r17
	mov r16=IA64_TR_KERNEL
	//mov r3=ip
	movl r18=PAGE_KERNEL
	;;
	dep r2=0,r3,0,KERNEL_TR_PAGE_SHIFT
	;;
	or r18=r2,r18
	;;
	srlz.i
	;;
	itr.i itr[r16]=r18
	;;
	itr.d dtr[r16]=r18
	;;

	// re-pin mappings for stack (current), per-cpu, vhpt, and shared info

	// unless overlaps with KERNEL_TR
	dep r18=0,r13,0,KERNEL_TR_PAGE_SHIFT
	;;
	cmp.eq p7,p0=r17,r18
(p7)	br.cond.sptk	.stack_overlaps
	;;
	movl r25=PAGE_KERNEL
	dep r21=0,r13,60,4		// physical address of "current"
	;;
	or r23=r25,r21			// construct PA | page properties
	mov r25=IA64_GRANULE_SHIFT<<2
	;;
	ptr.d	r13,r25
	;;
	mov cr.itir=r25
	mov cr.ifa=r13			// VA of next task...
	;;
	mov r25=IA64_TR_CURRENT_STACK
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	;;
.stack_overlaps:

	movl r22=PERCPU_ADDR
	;;
	movl r25=PAGE_KERNEL
	;;
	mov r21=loc2			// saved percpu physical address
	;;
	or r23=r25,r21			// construct PA | page properties
	mov r24=PERCPU_PAGE_SHIFT<<2
	;;
	ptr.d	r22,r24
	;;
	mov cr.itir=r24
	mov cr.ifa=r22
	;;
	mov r25=IA64_TR_PERCPU_DATA
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	;;

#if VHPT_ENABLED
	movl r22=VHPT_ADDR
	;;
	movl r25=PAGE_KERNEL
	;;
	mov r21=loc6			// saved vhpt physical address
	;;
	or r23=r25,r21			// construct PA | page properties
	mov r24=VHPT_SIZE_LOG2<<2
	;;
	ptr.d	r22,r24
	;;
	mov cr.itir=r24
	mov cr.ifa=r22
	;;
	mov r25=IA64_TR_VHPT
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	;;
#endif

	movl r22=SHAREDINFO_ADDR
	;;
	movl r25=__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RW)
	;;
	mov r21=loc5			// saved sharedinfo physical address
	;;
	or r23=r25,r21			// construct PA | page properties
	mov r24=PAGE_SHIFT<<2
	;;
	ptr.d	r22,r24
	;;
	mov cr.itir=r24
	mov cr.ifa=r22
	;;
	mov r25=IA64_TR_SHARED_INFO
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	;;
	// Map for arch_vcpu_info_t
	movl r22=SHARED_ARCHINFO_ADDR
	;;
	movl r25=__pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RW)
	;;
	mov r21=loc7			// saved sharedinfo physical address
	;;
	or r23=r25,r21			// construct PA | page properties
	mov r24=PAGE_SHIFT<<2
	;;
	ptr.d	r22,r24
	;;
	mov cr.itir=r24
	mov cr.ifa=r22
	;;
	mov r25=IA64_TR_ARCH_INFO
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	;;

	//Purge/insert PAL TR
	mov r24=IA64_TR_PALCODE
	movl r25=PAGE_KERNEL
	;;
	or loc8=r25,loc8
	mov r23=IA64_GRANULE_SHIFT<<2
	;;
	ptr.i	in4,r23
	;;
	mov cr.itir=r23
	mov cr.ifa=in4
	;;
	itr.i itr[r24]=loc8
	;;

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

#include "minstate.h"

GLOBAL_ENTRY(ia64_prepare_handle_privop)
	.prologue
	/*
	 * r16 = fake ar.pfs, we simply need to make sure privilege is still 0
	 */
	mov r16=r0
	DO_SAVE_SWITCH_STACK
	br.call.sptk.many rp=ia64_handle_privop		// stack frame setup in ivt
.ret22:	.body
	DO_LOAD_SWITCH_STACK
	br.cond.sptk.many rp				// goes to ia64_leave_kernel
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
	br.call.sptk.many rp=ia64_handle_reflection	// stack frame setup in ivt
.ret24:	.body
	DO_LOAD_SWITCH_STACK
	br.cond.sptk.many rp			// goes to ia64_leave_kernel
END(ia64_prepare_handle_reflection)

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

GLOBAL_ENTRY(dorfirfi)
        movl r16 = XSI_IIP
        movl r17 = XSI_IPSR
        movl r18 = XSI_IFS
	;;
	ld8 r16 = [r16]
	ld8 r17 = [r17]
	ld8 r18 = [r18]
	;;
        mov cr.iip=r16
        mov cr.ipsr=r17
        mov cr.ifs=r18
	;;
        // fall through
END(dorfirfi)

GLOBAL_ENTRY(dorfi)
        rfi
	;;
END(dorfirfi)

//
// Long's Peak UART Offsets
//
#define COM_TOP 0xff5e0000
#define COM_BOT 0xff5e2000

// UART offsets	
#define UART_TX		0	/* Out: Transmit buffer (DLAB=0) */
#define UART_INT_ENB	1	/* interrupt enable (DLAB=0) */	
#define UART_INT_ID	2	/* Interrupt ID register */
#define UART_LINE_CTL	3	/* Line control register */
#define UART_MODEM_CTL	4	/* Modem Control Register */
#define UART_LSR	5	/* In:  Line Status Register */
#define UART_MSR	6	/* Modem status register */	
#define UART_DLATCH_LOW UART_TX
#define UART_DLATCH_HIGH UART_INT_ENB
#define COM1   0x3f8
#define COM2   0x2F8
#define COM3   0x3E8

/* interrupt enable bits (offset 1) */
#define DATA_AVAIL_INT 1
#define XMIT_HOLD_EMPTY_INT 2
#define LINE_STAT_INT 4
#define MODEM_STAT_INT 8

/* line status bits (offset 5) */
#define REC_DATA_READY 1
#define OVERRUN 2
#define PARITY_ERROR 4
#define FRAMING_ERROR 8
#define BREAK_INTERRUPT 0x10
#define XMIT_HOLD_EMPTY 0x20
#define XMIT_SHIFT_EMPTY 0x40

// Write a single character
// input: r32 = character to be written
// output: none
GLOBAL_ENTRY(longs_peak_putc)	
	rsm psr.dt
        movl r16 = 0x8000000000000000 + COM_TOP + UART_LSR
	;;
	srlz.i
	;;

.Chk_THRE_p:
        ld1.acq r18=[r16]
        ;;
	
	and r18 = XMIT_HOLD_EMPTY, r18
	;;
	cmp4.eq p6,p0=0,r18
	;;
	
(p6)    br .Chk_THRE_p
	;;
        movl r16 = 0x8000000000000000 + COM_TOP + UART_TX
	;;
	st1.rel [r16]=r32
	;;
	ssm psr.dt
	;;
	srlz.i
	;;
	br.ret.sptk.many b0
END(longs_peak_putc)	

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
	movl r8=524288			/* flush 512k million cache lines (16MB) */
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
	movl r9 =0x08122f04		/* generic=4 width=47 retired=8 cycles=18 */
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
//  This is the virtual PAL, which simply does an hypercall.
//  The size is 2 bunldes (32 Bytes).  It handles both static and stacked
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
	break 0x1000	//  Hypercall vector (Value is patched).
(p7)	br.cond.sptk.few rp
(p8)	br.ret.sptk.few rp
	}
END(pal_call_stub)


