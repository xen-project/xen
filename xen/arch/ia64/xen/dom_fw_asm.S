#include <asm/dom_fw.h>

// moved from xenasm.S to be shared by xen and libxc
/*
 * Assembly support routines for Xen/ia64
 *
 * Copyright (C) 2004 Hewlett-Packard Co
 *      Dan Magenheimer <dan.magenheimer@hp.com>
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

//  These instructions are copied in the domains.
//  This is the virtual PAL, which simply does a hypercall.
//  The size is 2 bundles (32 Bytes).  It handles both static and stacked
//    convention.
//  If you modify this code, you have to modify dom_fw.h (for the size) and
//   dom_fw_pal_hypercall_patch.

// This file is shared with xen and libxc.
// GLOBAL_ENTRY() end END() macro can't be used.

//GLOBAL_ENTRY(xen_ia64_pal_call_stub)
.global xen_ia64_pal_call_stub;
.align 32;
.proc xen_ia64_pal_call_stub;
xen_ia64_pal_call_stub:
	{
	 .mii
	addl r2=FW_HYPERCALL_PAL_CALL_ASM,r0	//  Hypercall number (Value is patched).
	mov r9=256
	;; 
	cmp.gtu p7,p8=r9,r28		/* r32 <= 255? */
	}
	{
	 .mbb
	break __IA64_XEN_HYPERCALL_DEFAULT	//  Hypercall vector (Value is patched).
(p7)	br.cond.sptk.few rp
(p8)	br.ret.sptk.few rp
	}
//END(xen_ia64_pal_call_stub)
.endp xen_ia64_pal_call_stub
