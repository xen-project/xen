/*
 * Support routines for Xen
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/asmmacro.h>

#define isBP	p3	// are we the Bootstrap Processor?

	.text
GLOBAL_ENTRY(early_xen_setup)
	mov r8=ar.rsc		// Initialized in head.S
(isBP)	movl r9=running_on_xen;;
	extr.u r8=r8,2,2;;	// Extract pl fields
	cmp.eq p7,p0=r8,r0	// p7: !running on xen
	mov r8=1		// booleanize.
(p7)	br.ret.sptk.many rp;;
(isBP)	st4 [r9]=r8
	movl r10=xen_ivt;;
	
	mov cr.iva=r10

#if XSI_BASE != 0xf100000000000000UL
	/* Backward compatibility.  */
(isBP)	mov r2=0x600
(isBP)	movl r28=XSI_BASE;;
(isBP)	break 0x1000;;
#endif

	br.ret.sptk.many rp
	;;
END(early_xen_setup)

#include <xen/interface/xen.h>

/* Stub for suspend.
   Just force the stacked registers to be written in memory.  */	
GLOBAL_ENTRY(HYPERVISOR_suspend)
	alloc r20=ar.pfs,0,0,0,0
	mov r14=2
	mov r15=r12
	;;
	/* We don't want to deal with RSE.  */
	flushrs
	mov r2=__HYPERVISOR_sched_op
	st4 [r12]=r14
	;;
	break 0x1000
	;; 
	mov ar.pfs=r20
	br.ret.sptk.many b0
END(HYPERVISOR_suspend)
