/*
 * vmx_minstate.h:
 * Copyright (c) 2005, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */

#include <linux/config.h>

#include <asm/asmmacro.h>
#include <asm/fpu.h>
#include <asm/mmu_context.h>
#include <asm/offsets.h>
#include <asm/pal.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/system.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/vmx_vpd.h>
#include <asm/cache.h>
#include "entry.h"

#define VMX_MINSTATE_START_SAVE_MIN                                                             \
(pUStk) mov ar.rsc=0;           /* set enforced lazy mode, pl 0, little-endian, loadrs=0 */     \
        ;;                                                                                      \
(pUStk) mov.m r28=ar.rnat;                                                                      \
(pUStk) addl r22=IA64_RBS_OFFSET,r1;                    /* compute base of RBS */               \
(pKStk) mov r1=sp;                                      /* get sp  */                           \
        ;;                                                                                      \
(pUStk) lfetch.fault.excl.nt1 [r22];                                                            \
(pUStk) addl r1=IA64_STK_OFFSET-IA64_PT_REGS_SIZE,r1;   /* compute base of memory stack */      \
(pUStk) mov r23=ar.bspstore;                            /* save ar.bspstore */                  \
        ;;                                                                                      \
(pUStk) mov ar.bspstore=r22;                            /* switch to kernel RBS */              \
(pKStk) addl r1=-IA64_PT_REGS_SIZE,r1;                  /* if in kernel mode, use sp (r12) */   \
        ;;                                                                                      \
(pUStk) mov r18=ar.bsp;                                                                         \
(pUStk) mov ar.rsc=0x3;         /* set eager mode, pl 0, little-endian, loadrs=0 */

#define VMX_MINSTATE_END_SAVE_MIN                                                               \
    bsw.1;              /* switch back to bank 1 (must be last in insn group) */                \
    ;;

#define PAL_VSA_SYNC_READ                               \
    /* begin to call pal vps sync_read */               \
{ .mii;                                                 \
(pUStk) add r25=IA64_VPD_BASE_OFFSET, r21;              \
(pUStk) nop 0x0;                                        \
(pUStk) mov r24=ip;                                     \
    ;;                                                  \
};                                                      \
{ .mmb;                                                 \
(pUStk) add r24 = 0x20, r24;                            \
(pUStk) ld8 r25=[r25];          /* read vpd base */     \
(pUStk) br.cond.sptk vmx_vps_sync_read;        /*  call the service */ \
    ;;                                                  \
};

#define IA64_CURRENT_REG    IA64_KR(CURRENT)  /* r21 is reserved for current pointer */
//#define VMX_MINSTATE_GET_CURRENT(reg)   mov reg=IA64_CURRENT_REG
#define VMX_MINSTATE_GET_CURRENT(reg)   mov reg=r21

/*
 * VMX_DO_SAVE_MIN switches to the kernel stacks (if necessary) and saves
 * the minimum state necessary that allows us to turn psr.ic back
 * on.
 *
 * Assumed state upon entry:
 *  psr.ic: off
 *  r31:    contains saved predicates (pr)
 *
 * Upon exit, the state is as follows:
 *  psr.ic: off
 *   r2 = points to &pt_regs.r16
 *   r8 = contents of ar.ccv
 *   r9 = contents of ar.csd
 *  r10 = contents of ar.ssd
 *  r11 = FPSR_DEFAULT
 *  r12 = kernel sp (kernel virtual address)
 *  r13 = points to current task_struct (kernel virtual address)
 *   p6 = (psr.vm || isr.ni)
 *        panic if not external interrupt (fault in xen VMM)
 *  p15 = TRUE if psr.i is set in cr.ipsr
 *  predicate registers (other than p2, p3, and p15), b6, r3, r14, r15:
 *      preserved
 *
 * Note that psr.ic is NOT turned on by this macro.  This is so that
 * we can pass interruption state as arguments to a handler.
 */

#ifdef CONFIG_VMX_PANIC
# define P6_BR_VMX_PANIC        (p6)br.spnt.few vmx_panic;
#else
# define P6_BR_VMX_PANIC        /* nothing */
#endif

#define P6_BR_CALL_PANIC(panic_string)  \
(p6) movl out0=panic_string;            \
(p6) br.call.spnt.few b6=panic;

#define VMX_DO_SAVE_MIN(COVER,SAVE_IFS,EXTRA,VMX_PANIC)                                 \
    mov r27=ar.rsc;                     /* M */                                         \
    mov r20=r1;                         /* A */                                         \
    mov r25=ar.unat;                    /* M */                                         \
    mov r29=cr.ipsr;                    /* M */                                         \
    mov r26=ar.pfs;                     /* I */                                         \
    mov r18=cr.isr;                                                                     \
    COVER;                              /* B;; (or nothing) */                          \
    ;;                                                                                  \
    cmp.eq p6,p0=r0,r0;                                                                 \
    tbit.z pKStk,pUStk=r29,IA64_PSR_VM_BIT;                                             \
    tbit.z p0,p15=r29,IA64_PSR_I_BIT;                                                   \
    ;;                                                                                  \
(pUStk) tbit.nz.and p6,p0=r18,IA64_ISR_NI_BIT;                                          \
(pUStk)VMX_MINSTATE_GET_CURRENT(r1);                                                    \
    VMX_PANIC                                                                           \
    /* switch from user to kernel RBS: */                                               \
    ;;                                                                                  \
    invala;                             /* M */                                         \
    SAVE_IFS;                                                                           \
    ;;                                                                                  \
    VMX_MINSTATE_START_SAVE_MIN                                                         \
    adds r17=2*L1_CACHE_BYTES,r1;       /* really: biggest cache-line size */           \
    adds r16=PT(CR_IPSR),r1;                                                            \
    ;;                                                                                  \
    lfetch.fault.excl.nt1 [r17],L1_CACHE_BYTES;                                         \
    st8 [r16]=r29;      /* save cr.ipsr */                                              \
    ;;                                                                                  \
    lfetch.fault.excl.nt1 [r17];                                                        \
    mov r29=b0                                                                          \
    ;;                                                                                  \
    adds r16=PT(R8),r1; /* initialize first base pointer */                             \
    adds r17=PT(R9),r1; /* initialize second base pointer */                            \
(pKStk) mov r18=r0;     /* make sure r18 isn't NaT */                                   \
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r8,16;                                                 \
.mem.offset 8,0; st8.spill [r17]=r9,16;                                                 \
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r10,24;                                                \
.mem.offset 8,0; st8.spill [r17]=r11,24;                                                \
    ;;                                                                                  \
    mov r9=cr.iip;      /* M */                                                         \
    mov r10=ar.fpsr;    /* M */                                                         \
    ;;                                                                                  \
    st8 [r16]=r9,16;    /* save cr.iip */                                               \
    st8 [r17]=r30,16;   /* save cr.ifs */                                               \
(pUStk) sub r18=r18,r22;/* r18=RSE.ndirty*8 */                                          \
    ;;                                                                                  \
    st8 [r16]=r25,16;   /* save ar.unat */                                              \
    st8 [r17]=r26,16;    /* save ar.pfs */                                              \
    shl r18=r18,16;     /* compute ar.rsc to be used for "loadrs" */                    \
    ;;                                                                                  \
    st8 [r16]=r27,16;   /* save ar.rsc */                                               \
(pUStk) st8 [r17]=r28,16;/* save ar.rnat */                                             \
(pKStk) adds r17=16,r17;/* skip over ar_rnat field */                                   \
    ;;                  /* avoid RAW on r16 & r17 */                                    \
(pUStk) st8 [r16]=r23,16;   /* save ar.bspstore */                                      \
    st8 [r17]=r31,16;   /* save predicates */                                           \
(pKStk) adds r16=16,r16;    /* skip over ar_bspstore field */                           \
    ;;                                                                                  \
    st8 [r16]=r29,16;   /* save b0 */                                                   \
    st8 [r17]=r18,16;   /* save ar.rsc value for "loadrs" */                            \
    cmp.eq pNonSys,pSys=r0,r0   /* initialize pSys=0, pNonSys=1 */                      \
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r20,16;        /* save original r1 */                  \
.mem.offset 8,0; st8.spill [r17]=r12,16;                                                \
    adds r12=-16,r1;    /* switch to kernel memory stack (with 16 bytes of scratch) */  \
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r13,16;                                                \
.mem.offset 8,0; st8.spill [r17]=r10,16;        /* save ar.fpsr */                      \
(pUStk) VMX_MINSTATE_GET_CURRENT(r13);          /* establish `current' */               \
(pKStk) movl r13=THIS_CPU(cpu_kr)+IA64_KR_CURRENT_OFFSET;/* From MINSTATE_GET_CURRENT */\
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r15,16;                                                \
.mem.offset 8,0; st8.spill [r17]=r14,16;                                                \
(pKStk) ld8 r13=[r13];                          /* establish `current' */               \
    ;;                                                                                  \
.mem.offset 0,0; st8.spill [r16]=r2,16;                                                 \
.mem.offset 8,0; st8.spill [r17]=r3,16;                                                 \
    adds r2=IA64_PT_REGS_R16_OFFSET,r1;                                                 \
    ;;                                                                                  \
(pUStk) adds r16=IA64_VCPU_IIPA_OFFSET,r13;                                             \
(pUStk) adds r17=IA64_VCPU_ISR_OFFSET,r13;                                              \
(pUStk) mov r26=cr.iipa;                                                                \
(pUStk) mov r27=cr.isr;                                                                 \
    ;;                                                                                  \
(pUStk) st8 [r16]=r26;                                                                  \
(pUStk) st8 [r17]=r27;                                                                  \
    ;;                                                                                  \
    EXTRA;                                                                              \
    mov r8=ar.ccv;                                                                      \
    mov r9=ar.csd;                                                                      \
    mov r10=ar.ssd;                                                                     \
    movl r11=FPSR_DEFAULT;      /* L-unit */                                            \
    movl r1=__gp;               /* establish kernel global pointer */                   \
    ;;                                                                                  \
    PAL_VSA_SYNC_READ                                                                   \
    VMX_MINSTATE_END_SAVE_MIN

/*
 * SAVE_REST saves the remainder of pt_regs (with psr.ic on).
 *
 * Assumed state upon entry:
 *  psr.ic: on
 *  r2: points to &pt_regs.f6
 *  r3: points to &pt_regs.f7
 *  r8: contents of ar.ccv
 *  r9: contents of ar.csd
 *  r10:    contents of ar.ssd
 *  r11:    FPSR_DEFAULT
 *
 * Registers r14 and r15 are guaranteed not to be touched by SAVE_REST.
 */
#define VMX_SAVE_REST                   \
.mem.offset 0,0; st8.spill [r2]=r16,16; \
.mem.offset 8,0; st8.spill [r3]=r17,16; \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r18,16; \
.mem.offset 8,0; st8.spill [r3]=r19,16; \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r20,16; \
.mem.offset 8,0; st8.spill [r3]=r21,16; \
    mov r18=b6;                         \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r22,16; \
.mem.offset 8,0; st8.spill [r3]=r23,16; \
    mov r19=b7;                         \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r24,16; \
.mem.offset 8,0; st8.spill [r3]=r25,16; \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r26,16; \
.mem.offset 8,0; st8.spill [r3]=r27,16; \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r28,16; \
.mem.offset 8,0; st8.spill [r3]=r29,16; \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r30,16; \
.mem.offset 8,0; st8.spill [r3]=r31,32; \
    ;;                                  \
    mov ar.fpsr=r11;                    \
    st8 [r2]=r8,8;                      \
    adds r24=PT(B6)-PT(F7),r3;          \
    ;;                                  \
    stf.spill [r2]=f6,32;               \
    stf.spill [r3]=f7,32;               \
    ;;                                  \
    stf.spill [r2]=f8,32;               \
    stf.spill [r3]=f9,32;               \
    ;;                                  \
    stf.spill [r2]=f10,32;              \
    stf.spill [r3]=f11;                 \
    adds r25=PT(B7)-PT(F11),r3;         \
    ;;                                  \
    st8 [r24]=r18,16;   /* b6 */        \
    st8 [r25]=r19,16;   /* b7 */        \
    adds r3=PT(R5)-PT(F11),r3;          \
    ;;                                  \
    st8 [r24]=r9;       /* ar.csd */    \
    st8 [r25]=r10;      /* ar.ssd */    \
    ;;                                  \
(pUStk)mov r18=ar.unat;                 \
(pUStk)adds r19=PT(EML_UNAT)-PT(R4),r2; \
    ;;                                  \
(pUStk)st8 [r19]=r18;      /* eml_unat */

#define VMX_SAVE_EXTRA                  \
.mem.offset 0,0; st8.spill [r2]=r4,16;  \
.mem.offset 8,0; st8.spill [r3]=r5,16;  \
    ;;                                  \
.mem.offset 0,0; st8.spill [r2]=r6,16;  \
.mem.offset 8,0; st8.spill [r3]=r7;     \
    ;;                                  \
    mov r26=ar.unat;                    \
    ;;                                  \
    st8 [r2]=r26;       /* eml_unat */

#define VMX_SAVE_MIN_WITH_COVER     VMX_DO_SAVE_MIN(cover, mov r30=cr.ifs,, P6_BR_VMX_PANIC)
#define VMX_SAVE_MIN_WITH_COVER_NO_PANIC    \
                                    VMX_DO_SAVE_MIN(cover, mov r30=cr.ifs,, )
#define VMX_SAVE_MIN_WITH_COVER_R19 VMX_DO_SAVE_MIN(cover, mov r30=cr.ifs, mov r15=r19, P6_BR_VMX_PANIC)
#define VMX_SAVE_MIN                VMX_DO_SAVE_MIN(     , mov r30=r0,, P6_BR_VMX_PANIC)

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
