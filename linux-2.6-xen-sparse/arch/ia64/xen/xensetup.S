/*
 * Support routines for Xen
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

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

	/* Set xsi base.  */
#define FW_HYPERCALL_SET_SHARED_INFO_VA			0x600
(isBP)	mov r2=FW_HYPERCALL_SET_SHARED_INFO_VA
(isBP)	movl r28=XSI_BASE;;
(isBP)	break 0x1000;;

	br.ret.sptk.many rp
	;;
END(early_xen_setup)

#include <xen/interface/xen.h>

/* Stub for suspend.
   Just force the stacked registers to be written in memory.  */	
GLOBAL_ENTRY(xencomm_arch_hypercall_suspend)
	;; 
	alloc r20=ar.pfs,0,0,6,0
	mov r2=__HYPERVISOR_sched_op
	;; 
	/* We don't want to deal with RSE.  */
	flushrs
	mov r33=r32
	mov r32=2 // SCHEDOP_shutdown
	;;
	break 0x1000
	;; 
	br.ret.sptk.many b0
END(xencomm_arch_hypercall_suspend)
