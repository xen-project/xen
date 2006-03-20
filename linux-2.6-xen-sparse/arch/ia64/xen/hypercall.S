/*
 * Support routines for Xen hypercalls
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/asmmacro.h>

GLOBAL_ENTRY(xen_get_ivr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=cr.ivr;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_IVR
	;;
	st8 [r9]=r10
	br.ret.sptk.many rp
	;;
END(xen_get_ivr)

GLOBAL_ENTRY(xen_get_tpr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=cr.tpr;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_TPR
	;;
	st8 [r9]=r10
	br.ret.sptk.many rp
	;;
END(xen_get_tpr)

GLOBAL_ENTRY(xen_set_tpr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov cr.tpr=r32;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_SET_TPR
	;;
	st8 [r9]=r10
	br.ret.sptk.many rp
	;;
END(xen_set_tpr)

GLOBAL_ENTRY(xen_eoi)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov cr.eoi=r0;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_EOI
	;;
	st8 [r9]=r10
	br.ret.sptk.many rp
	;;
END(xen_eoi)

GLOBAL_ENTRY(xen_thash)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	thash r8=r32;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_THASH
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
	;;
END(xen_thash)

GLOBAL_ENTRY(xen_set_itm)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov cr.itm=r32;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_SET_ITM
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
	;;
END(xen_set_itm)

GLOBAL_ENTRY(xen_ptcga)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	ptc.ga r32,r33;;
(p7)	br.ret.sptk.many rp
	;;
	movl r11=XSI_PSR_IC
	mov r8=r32
	mov r9=r33
	;;
	ld8 r10=[r11]
	;;
	st8 [r11]=r0
	;;
	XEN_HYPER_PTC_GA
	;;
	st8 [r11]=r10
	;;
	br.ret.sptk.many rp
	;;
END(xen_ptcga)

GLOBAL_ENTRY(xen_get_rr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=rr[r32];;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_RR
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
	;;
END(xen_get_rr)

GLOBAL_ENTRY(xen_set_rr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov rr[r32]=r33;;
(p7)	br.ret.sptk.many rp
	;;
	movl r11=XSI_PSR_IC
	mov r8=r32
	mov r9=r33
	;;
	ld8 r10=[r11]
	;;
	st8 [r11]=r0
	;;
	XEN_HYPER_SET_RR
	;;
	st8 [r11]=r10
	;;
	br.ret.sptk.many rp
	;;
END(xen_set_rr)

GLOBAL_ENTRY(xen_set_kr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.ne p7,p0=r8,r0;;
(p7)	br.cond.spnt.few 1f;
	;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar0=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar1=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar2=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar3=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar4=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar5=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar6=r9
(p7)	br.ret.sptk.many rp;;
	cmp.eq p7,p0=r8,r0
	adds r8=-1,r8;;
(p7)	mov ar7=r9
(p7)	br.ret.sptk.many rp;;

1:	movl r11=XSI_PSR_IC
	mov r8=r32
	mov r9=r33
	;;
	ld8 r10=[r11]
	;;
	st8 [r11]=r0
	;;
	XEN_HYPER_SET_KR
	;;
	st8 [r11]=r10
	;;
	br.ret.sptk.many rp
END(xen_set_rr)

GLOBAL_ENTRY(xen_fc)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	fc r32;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_FC
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
END(xen_fc)

GLOBAL_ENTRY(xen_get_cpuid)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=cpuid[r32];;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_CPUID
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
END(xen_get_cpuid)

GLOBAL_ENTRY(xen_get_pmd)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=pmd[r32];;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_PMD
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
END(xen_get_pmd)

#ifdef CONFIG_IA32_SUPPORT
GLOBAL_ENTRY(xen_get_eflag)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=ar24;;
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_GET_EFLAG
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
END(xen_get_eflag)
	
// some bits aren't set if pl!=0, see SDM vol1 3.1.8
GLOBAL_ENTRY(xen_set_eflag)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov ar24=r32
(p7)	br.ret.sptk.many rp
	;;
	movl r9=XSI_PSR_IC
	mov r8=r32
	;;
	ld8 r10=[r9]
	;;
	st8 [r9]=r0
	;;
	XEN_HYPER_SET_EFLAG
	;;
	st8 [r9]=r10
	;;
	br.ret.sptk.many rp
END(xen_set_eflag)
#endif
