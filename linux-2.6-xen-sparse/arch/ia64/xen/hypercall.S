/*
 * Support routines for Xen hypercalls
 *
 * Copyright (C) 2005 Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <linux/config.h>
#include <asm/processor.h>
#include <asm/asmmacro.h>

/* To clear vpsr.ic, vpsr.i needs to be cleared first */
#define XEN_CLEAR_PSR_IC				\
	mov r14=1;					\
	movl r15=XSI_PSR_I_ADDR;			\
	movl r2=XSI_PSR_IC;				\
	;;						\
	ld8 r15=[r15];					\
	ld4 r3=[r2];					\
	;;						\
	ld1 r16=[r15];					\
	;;						\
	st1 [r15]=r14;					\
	st4 [r2]=r0;					\
	;;

/* First restore vpsr.ic, and then vpsr.i */
#define XEN_RESTORE_PSR_IC				\
	st4 [r2]=r3;					\
	st1 [r15]=r16;					\
	;;

GLOBAL_ENTRY(xen_get_ivr)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	mov r8=cr.ivr;;
(p7)	br.ret.sptk.many rp
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_IVR
	;;
	XEN_RESTORE_PSR_IC
	;;
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
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_TPR
	;;
	XEN_RESTORE_PSR_IC
	;;
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_SET_TPR
	;;
	XEN_RESTORE_PSR_IC
	;;
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_EOI
	;;
	XEN_RESTORE_PSR_IC
	;;
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_THASH
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_SET_ITM
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	mov r9=r33
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_PTC_GA
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_RR
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	mov r9=r33
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_SET_RR
	;;
	XEN_RESTORE_PSR_IC
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

1:	mov r8=r32
	mov r9=r33
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_SET_KR
	;;
	XEN_RESTORE_PSR_IC
	;;
	br.ret.sptk.many rp
END(xen_set_kr)

GLOBAL_ENTRY(xen_fc)
	movl r8=running_on_xen;;
	ld4 r8=[r8];;
	cmp.eq p7,p0=r8,r0;;
(p7)	fc r32;;
(p7)	br.ret.sptk.many rp
	;;
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_FC
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_CPUID
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_PMD
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_GET_EFLAG
	;;
	XEN_RESTORE_PSR_IC
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
	mov r8=r32
	;;
	XEN_CLEAR_PSR_IC
	;;
	XEN_HYPER_SET_EFLAG
	;;
	XEN_RESTORE_PSR_IC
	;;
	br.ret.sptk.many rp
END(xen_set_eflag)
#endif

GLOBAL_ENTRY(xen_send_ipi)
        mov r14=r32
        mov r15=r33
        mov r2=0x400
        break 0x1000
        ;;
        br.ret.sptk.many rp
        ;;
END(xen_send_ipi)

#ifdef CONFIG_XEN_IA64_VDSO_PARAVIRT
// Those are vdso specialized.
// In fsys mode, call, ret can't be used.
GLOBAL_ENTRY(xen_rsm_be_i)
	ld8 r22=[r22]
	;; 
	st1 [r22]=r20
	st4 [r23]=r0
	XEN_HYPER_RSM_BE
	st4 [r23]=r20
	brl.cond.sptk	.vdso_rsm_be_i_ret
	;; 
END(xen_rsm_be_i)

GLOBAL_ENTRY(xen_get_psr)
	mov r31=r8
	mov r25=IA64_PSR_IC
	st4 [r23]=r0
	XEN_HYPER_GET_PSR
	;; 
	st4 [r23]=r20
	or r29=r8,r25 // vpsr.ic was cleared for hyperprivop
	mov r8=r31
	brl.cond.sptk	.vdso_get_psr_ret
	;; 
END(xen_get_psr)

	// see xen_ssm_i() in privop.h
	// r22 = &vcpu->evtchn_mask
	// r23 = &vpsr.ic
	// r24 = &vcpu->pending_interruption
	// r25 = tmp
	// r31 = tmp
	// p11 = tmp
	// p14 = tmp
#define XEN_SET_PSR_I			\
	ld4 r31=[r22];			\
	ld4 r25=[r24];			\
	;;				\
	st4 [r22]=r0;			\
	cmp.ne.unc p14,p0=r0,r31;	\
	;;				\
(p14)	cmp.ne.unc p11,p0=r0,r25;	\
	;;				\
(p11)	st4 [r22]=r20;			\
(p11)	st4 [r23]=r0;			\
(p11)	XEN_HYPER_SSM_I;
		
GLOBAL_ENTRY(xen_ssm_i_0)
	XEN_SET_PSR_I
	brl.cond.sptk	.vdso_ssm_i_0_ret
	;; 
END(xen_ssm_i_0)

GLOBAL_ENTRY(xen_ssm_i_1)
	XEN_SET_PSR_I
	brl.cond.sptk	.vdso_ssm_i_1_ret
	;; 
END(xen_ssm_i_1)
#endif
