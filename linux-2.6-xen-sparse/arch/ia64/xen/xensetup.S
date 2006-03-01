/*
 * Support routines for Xen
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/asmmacro.h>

	.data
	.align 8
	.globl running_on_xen
running_on_xen:
	data4 0

#define isBP	p3	// are we the Bootstrap Processor?

	.text
GLOBAL_ENTRY(early_xen_setup)
	mov r8=cr.dcr
(isBP)	movl r9=running_on_xen;;
	extr.u r8=r8,63,1;;
	cmp.ne p7,p0=r8,r0;;
(isBP)	st4 [r9]=r8
(p7)	movl r10=xen_ivt;;
(p7)	mov cr.iva=r10
	br.ret.sptk.many rp;;
END(early_xen_setup)

GLOBAL_ENTRY(is_running_on_xen)
	movl r9=running_on_xen;;
	ld4 r8=[r9]
	br.ret.sptk.many rp;;
END(is_running_on_xen)
