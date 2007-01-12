/*
 * ia64/xen/xenpal.S
 *
 * Alternate PAL  routines for Xen.  Heavily leveraged from
 *   ia64/kernel/pal.S
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@.hp.com>
 */

#include <asm/asmmacro.h>
#include <asm/processor.h>

GLOBAL_ENTRY(xen_pal_call_static)
	.prologue ASM_UNW_PRLG_RP|ASM_UNW_PRLG_PFS, ASM_UNW_PRLG_GRSAVE(5)
	alloc loc1 = ar.pfs,5,5,0,0
#ifdef CONFIG_XEN
	movl r22=running_on_xen;;
	ld4 r22=[r22];;
	cmp.eq p7,p0=r22,r0
(p7)	br.cond.spnt.many __ia64_pal_call_static;;
#endif
	movl loc2 = pal_entry_point
1:	{
	  mov r28 = in0
	  mov r29 = in1
	  mov r8 = ip
	}
	;;
	ld8 loc2 = [loc2]		// loc2 <- entry point
	tbit.nz p6,p7 = in4, 0
	adds r8 = 1f-1b,r8
	mov loc4=ar.rsc			// save RSE configuration
	;;
	mov ar.rsc=0			// put RSE in enforced lazy, LE mode
#ifdef CONFIG_XEN
	mov r9 = r8
	XEN_HYPER_GET_PSR
	;;
	mov loc3 = r8
	mov r8 = r9
	;;
#else    
	mov loc3 = psr
#endif    
	mov loc0 = rp
	.body
	mov r30 = in2

#ifdef CONFIG_XEN
	// this is low priority for paravirtualization, but is called
	// from the idle loop so confuses privop counting
	movl r31=XSI_PSR_I_ADDR
	;;
	ld8 r31=[r31]
	mov r22=1
	;;
	st1 [r31]=r22
	;;  
(p6)	movl r31=XSI_PSR_IC
	;;
(p6)	st4.rel [r31]=r0
	;;
	mov r31 = in3
	mov b7 = loc2
	;;
#else
(p6)	rsm psr.i | psr.ic
	mov r31 = in3
	mov b7 = loc2

(p7)	rsm psr.i
	;;
(p6)	srlz.i
#endif
	mov rp = r8
	br.cond.sptk.many b7
1:	mov psr.l = loc3
	mov ar.rsc = loc4		// restore RSE configuration
	mov ar.pfs = loc1
	mov rp = loc0
	;;
	srlz.d				// seralize restoration of psr.l
	br.ret.sptk.many b0
END(xen_pal_call_static)
