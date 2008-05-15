/*
 * arch/ia64/vmx/optvfault.S
 * optimize virtualization fault handler
 *
 * Copyright (C) 2006 Intel Co
 * Xuefei Xu (Anthony Xu) <anthony.xu@intel.com>
 */

#include <linux/config.h>
#include <asm/config.h>
#include <asm/pgtable.h>
#include <asm/asmmacro.h>
#include <asm/kregs.h>
#include <asm/offsets.h>
#include <asm/percpu.h>
#include <asm/processor.h>
#include <asm/vmx_vpd.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/asm-offsets.h>
#include <asm/virt_event.h>
#include <asm-ia64/vmx_mm_def.h>
#include <asm-ia64/vmx_phy_mode.h>
#include "entry.h"

// r21 : current
// r23 : b0
// r31 : pr

#define VMX_VIRT_SAVE                                                       \
    mov r27=ar.rsc;     /* M */                                             \
    ;;                                                                      \
    cover;              /* B;; (or nothing) */                              \
    ;;                                                                      \
    /* switch from user to kernel RBS: */                                   \
    invala;             /* M */                                             \
    ;;                                                                      \
    mov ar.rsc=0;       /* set enforced lazy mode  */                       \
    ;;                                                                      \
    mov.m r26=ar.rnat;                                                      \
    movl r28=IA64_RBS_OFFSET;        /* compute base of RBS */              \
    ;;                                                                      \
    mov r22=ar.bspstore;             /* save ar.bspstore */                 \
    add r28=r28,r21;                                                        \
    ;;                                                                      \
    mov ar.bspstore=r28;    /* switch to kernel RBS */                      \
    ;;                                                                      \
    mov r18=ar.bsp;                                                         \
    mov ar.rsc=0x3;         /* set eager mode */                            \
    ;;                                                                      \
    alloc r32=ar.pfs,24,0,3,0    /* save pfs */                             \
    ;;                                                                      \
    sub r18=r18,r28;    /* r18=RSE.ndirty*8 */                              \
    ;;                                                                      \
    shl r33=r18,16;     /* save loadrs */                                   \
    mov r35=b6;         /* save b6 */                                       \
    mov r36=b7;         /* save b7 */                                       \
    mov r37=ar.csd;     /* save ar.csd */                                   \
    mov r38=ar.ssd;     /* save ar.ssd */                                   \
    mov r39=r8;         /* save r8 */                               \
    mov r40=r9;         /* save r9 */                               \
    mov r41=r10;        /* save r10 */                              \
    mov r42=r11;        /* save r11 */                              \
    mov r43=r27;        /* save ar.rsc */                           \
    mov r44=r26;        /* save ar.rnat */                          \
    mov r45=r22;        /* save ar.bspstore */                      \
    mov r46=r31;        /* save pr */                               \
    mov r47=r23;        /* save b0 */                               \
    mov r48=r1;         /* save r1 */                               \
    mov r49=r12;        /* save r12 */                              \
    mov r50=r13;        /* save r13 */                              \
    mov r51=r15;        /* save r15 */                              \
    mov r52=r14;        /* save r14 */                              \
    mov r53=r2;         /* save r2 */                               \
    mov r54=r3;         /* save r3 */                               \
    mov r34=ar.ccv;     /* save ar.ccv */                           \
    ;;                                                              \
    movl r1=__gp;                                                   \
    movl r29=IA64_STK_OFFSET-IA64_PT_REGS_SIZE-16;                  \
    ;;                                                              \
    add r12=r29,r21;   /* compute base of memory stack */           \
    mov r13=r21;                                                    \
    ;;                                                              \
{ .mii;       /* call vps sync read */                              \
    add r25=IA64_VPD_BASE_OFFSET, r21;                              \
    nop 0x0;                                                        \
    mov r24=ip;                                                     \
    ;;                                                              \
};                                                                  \
{ .mmb;                                                             \
    add r24 = 0x20, r24;                                            \
    ld8 r25=[r25];          /* read vpd base */                     \
    br.cond.sptk vmx_vps_sync_read;   /*  call the service */       \
    ;;                                                              \
};


ENTRY(ia64_leave_hypervisor_virt)
    invala              /* M */
    ;;
    mov r21=r13         /* get current */
    mov b6=r35          /* restore b6 */
    mov b7=r36          /* restore b7 */
    mov ar.csd=r37      /* restore ar.csd */
    mov ar.ssd=r38      /* restore ar.ssd */
    mov r8=r39          /* restore r8 */
    mov r9=r40          /* restore r9 */
    mov r10=r41         /* restore r10 */
    mov r11=r42         /* restore r11 */
    mov ar.pfs=r32      /* restore ar.pfs */
    mov r27=r43         /* restore ar.rsc */
    mov r26=r44         /* restore ar.rnat */
    mov r25=r45         /* restore ar.bspstore */
    mov r23=r46         /* restore predicates */
    mov r22=r47         /* restore b0 */
    mov r1=r48          /* restore r1 */
    mov r12=r49         /* restore r12 */
    mov r13=r50         /* restore r13 */
    mov r15=r51         /* restore r15 */
    mov r14=r52         /* restore r14 */
    mov r2=r53          /* restore r2 */
    mov r3=r54          /* restore r3 */
    mov ar.ccv=r34      /* restore ar.ccv */
    mov ar.rsc=r33      /* load ar.rsc to be used for "loadrs" */
    ;;
    alloc r16=ar.pfs,0,0,0,0    /* drop current register frame */
    ;;
    loadrs
    ;;
    mov ar.bspstore=r25
    ;;
    mov ar.rnat=r26
    ;;
    mov ar.rsc=r27
    adds r18=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r25=[r18]       // load vpd
    mov r17=r0
    ;;
//vsa_sync_write_start
    ;;
    movl r24=ia64_leave_hypervisor_virt_1   // calculate return address
    br.cond.sptk vmx_vps_sync_write         // call the service
    ;;
ia64_leave_hypervisor_virt_1:
    mov r24=r22
    mov r31=r23
    br.cond.sptk vmx_resume_to_guest
END(ia64_leave_hypervisor_virt)



// Inputs are: r21 (= current), r24 (= cause), r25 (= insn), r31 (=saved pr)

#define BACK_TO_SLOW_PATH                   \
{;                                          \
    nop.m 0x0;                              \
    mov b0=r23;                             \
    br.many vmx_virtualization_fault_back;  \
};                                          \

GLOBAL_ENTRY(virtualization_fault_table)
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 3 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_mov_from_ar
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 6 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_mov_to_psr
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 10 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_mov_to_rr
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 18 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_mov_from_rr
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 24 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_ssm
}
{   /* Entry 25 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_rsm
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 31 */
    cmp.eq p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_thash
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
{   /* Entry 37 */
    cmp.ne p2,p0=r0,r0
    mov b0=r23
    br.many vmx_asm_rfi
}
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
    BACK_TO_SLOW_PATH
END(virtualization_fault_table)


ENTRY(vmx_dummy_function)
    br.sptk.many vmx_dummy_function
END(vmx_dummy_function)

/*
 *  Inputs:
 *  r24 : return address
 *  r25 : vpd
 *  r29 : scratch
 *
 */
GLOBAL_ENTRY(vmx_vps_sync_read)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    br.sptk.many b0
END(vmx_vps_sync_read)

/*
 *  Inputs:
 *  r24 : return address
 *  r25 : vpd
 *  r29 : scratch
 */
GLOBAL_ENTRY(vmx_vps_sync_write)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    br.sptk.many b0
END(vmx_vps_sync_write)

/*
 *  Inputs:
 *  r23 : pr
 *  r24 : guest b0
 *  r25 : vpd
 */
GLOBAL_ENTRY(vmx_vps_resume_normal)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    mov pr=r23,-2
    br.sptk.many b0
END(vmx_vps_resume_normal)

/*
 *  Inputs:
 *  r23 : pr
 *  r24 : guest b0
 *  r25 : vpd
 *  r17 : isr
 */
GLOBAL_ENTRY(vmx_vps_resume_handler)
    movl r29 = vmx_dummy_function
    ;;
    ld8 r26=[r25]
    shr r17=r17,IA64_ISR_IR_BIT
    ;;
    dep r26=r17,r26,63,1   // bit 63 of r26 indicate whether enable CFLE
    mov b0=r29
    mov pr=r23,-2
    br.sptk.many b0
END(vmx_vps_resume_handler)

//r13 ->vcpu
//call with psr.bn = 0
GLOBAL_ENTRY(vmx_asm_bsw0)
    mov r15=ar.unat
    ;;
    adds r14=IA64_VPD_BASE_OFFSET,r13
    ;;
    ld8 r14=[r14]
    bsw.1
    ;;
    adds r2=IA64_VPD_VB1REG_OFFSET, r14
    adds r3=IA64_VPD_VB1REG_OFFSET+8, r14
    ;;
    .mem.offset 0,0; st8.spill [r2]=r16,16
    .mem.offset 8,0; st8.spill [r3]=r17,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r18,16
    .mem.offset 8,0; st8.spill [r3]=r19,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r20,16
    .mem.offset 8,0; st8.spill [r3]=r21,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r22,16
    .mem.offset 8,0; st8.spill [r3]=r23,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r24,16
    .mem.offset 8,0; st8.spill [r3]=r25,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r26,16
    .mem.offset 8,0; st8.spill [r3]=r27,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r28,16
    .mem.offset 8,0; st8.spill [r3]=r29,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r30,16
    .mem.offset 8,0; st8.spill [r3]=r31,16
    ;;
    mov r9=ar.unat
    adds r8=IA64_VPD_VB1NAT_OFFSET, r14
    ;;
    st8 [r8]=r9
    adds r8=IA64_VPD_VB0NAT_OFFSET, r14
    ;;
    ld8 r9=[r8]
    adds r2= IA64_VPD_VB0REG_OFFSET, r14
    adds r3= IA64_VPD_VB0REG_OFFSET+8, r14
    ;;
    mov ar.unat=r9
    ;;
    ld8.fill r16=[r2],16
    ld8.fill r17=[r3],16
    ;;
    ld8.fill r18=[r2],16
    ld8.fill r19=[r3],16
    ;;
    ld8.fill r20=[r2],16
    ld8.fill r21=[r3],16
    ;;
    ld8.fill r22=[r2],16
    ld8.fill r23=[r3],16
    ;;
    ld8.fill r24=[r2],16
    ld8.fill r25=[r3],16
    ;;
    ld8.fill r26=[r2],16
    ld8.fill r27=[r3],16
    ;;
    ld8.fill r28=[r2],16
    ld8.fill r29=[r3],16
    ;;
    ld8.fill r30=[r2],16
    ld8.fill r31=[r3],16
    ;;
    mov ar.unat=r15
    ;;
    bsw.0
    ;;
    br.ret.sptk.many b0
END(vmx_asm_bsw0)

//r13 ->vcpu
//call with psr.bn = 0
GLOBAL_ENTRY(vmx_asm_bsw1)
    mov r15=ar.unat
    ;;
    adds r14=IA64_VPD_BASE_OFFSET,r13
    ;;
    ld8 r14=[r14]
    bsw.1
    ;;
    adds r2=IA64_VPD_VB0REG_OFFSET, r14
    adds r3=IA64_VPD_VB0REG_OFFSET+8, r14
    ;;
    .mem.offset 0,0; st8.spill [r2]=r16,16
    .mem.offset 8,0; st8.spill [r3]=r17,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r18,16
    .mem.offset 8,0; st8.spill [r3]=r19,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r20,16
    .mem.offset 8,0; st8.spill [r3]=r21,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r22,16
    .mem.offset 8,0; st8.spill [r3]=r23,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r24,16
    .mem.offset 8,0; st8.spill [r3]=r25,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r26,16
    .mem.offset 8,0; st8.spill [r3]=r27,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r28,16
    .mem.offset 8,0; st8.spill [r3]=r29,16
    ;;
    .mem.offset 0,0; st8.spill [r2]=r30,16
    .mem.offset 8,0; st8.spill [r3]=r31,16
    ;;
    mov r9=ar.unat
    adds r8=IA64_VPD_VB0NAT_OFFSET, r14
    ;;
    st8 [r8]=r9
    adds r8=IA64_VPD_VB1NAT_OFFSET, r14
    ;;
    ld8 r9=[r8]
    adds r2=IA64_VPD_VB1REG_OFFSET, r14
    adds r3=IA64_VPD_VB1REG_OFFSET+8, r14
    ;;
    mov ar.unat=r9
    ;;
    ld8.fill r16=[r2],16
    ld8.fill r17=[r3],16
    ;;
    ld8.fill r18=[r2],16
    ld8.fill r19=[r3],16
    ;;
    ld8.fill r20=[r2],16
    ld8.fill r21=[r3],16
    ;;
    ld8.fill r22=[r2],16
    ld8.fill r23=[r3],16
    ;;
    ld8.fill r24=[r2],16
    ld8.fill r25=[r3],16
    ;;
    ld8.fill r26=[r2],16
    ld8.fill r27=[r3],16
    ;;
    ld8.fill r28=[r2],16
    ld8.fill r29=[r3],16
    ;;
    ld8.fill r30=[r2],16
    ld8.fill r31=[r3],16
    ;;
    mov ar.unat=r15
    ;;
    bsw.0
    ;;
    br.ret.sptk.many b0
END(vmx_asm_bsw1)


// rfi
ENTRY(vmx_asm_rfi)
    adds r18=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r18]
    ;;
    adds r26=IA64_VPD_VIFS_OFFSET,r18
    ;;
    ld8 r26=[r26]
    ;;
    tbit.z p6,p0=r26,63
    (p6) br.cond.dptk.few vmx_asm_rfi_1
    ;;
    //if vifs.v=1 desert current register frame
    alloc r27=ar.pfs,0,0,0,0
    ;;
vmx_asm_rfi_1:
    adds r26=IA64_VPD_VHPI_OFFSET,r18
    ;;
    ld8 r26=[r26]
    ;;
    cmp.ne p6,p0=r26,r0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    VMX_VIRT_SAVE
    ;;
    mov out0=r21
    movl r14=ia64_leave_hypervisor_virt
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_vcpu_rfi_fast
END(vmx_asm_rfi)


//mov r1=ar3 (only itc is virtualized)
ENTRY(vmx_asm_mov_from_ar)
    add r18=VCPU_VTM_OFFSET_OFS,r21
    add r16=VCPU_VTM_LAST_ITC_OFS,r21
    extr.u r17=r25,6,7
    ;;
    ld8 r18=[r18]
    mov r19=ar.itc
    mov r24=b0
    ;;
    ld8 r16=[r16]
    add r19=r19,r18
    movl r20=asm_mov_to_reg
    ;;
    adds r30=vmx_resume_to_guest-asm_mov_to_reg,r20
    shladd r17=r17,4,r20
    cmp.gtu p6,p0=r16,r19
    ;;
    (p6) mov r19=r16
    mov b0=r17
    br.sptk.few b0
    ;;
END(vmx_asm_mov_from_ar)


// mov r1=rr[r3]
ENTRY(vmx_asm_mov_from_rr)
    extr.u r16=r25,20,7
    extr.u r17=r25,6,7
    movl r20=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_mov_from_rr_back_1-asm_mov_from_reg,r20
    shladd r16=r16,4,r20
    mov r24=b0
    ;;
    add r27=VCPU_VRR0_OFS,r21
    mov b0=r16
    br.many b0
    ;;
vmx_asm_mov_from_rr_back_1:
    adds r30=vmx_resume_to_guest-asm_mov_from_reg,r20
    adds r22=asm_mov_to_reg-asm_mov_from_reg,r20
    shr.u r26=r19,61
    ;;
    shladd r17=r17,4,r22
    shladd r27=r26,3,r27
    ;;
    ld8 r19=[r27]
    mov b0=r17
    br.many b0
END(vmx_asm_mov_from_rr)


// mov rr[r3]=r2
ENTRY(vmx_asm_mov_to_rr)
    extr.u r16=r25,20,7         // r3
    extr.u r17=r25,13,7         // r2
    movl r20=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_mov_to_rr_back_1-asm_mov_from_reg,r20
    shladd r16=r16,4,r20        // get r3
    ;;
    mov b0=r16
    br.many b0
    ;;
vmx_asm_mov_to_rr_back_1:
    adds r30=vmx_asm_mov_to_rr_back_2-asm_mov_from_reg,r20
    shr.u r16=r19,61            // get RR #
    ;;
    //if rr7, go back
    cmp.eq p6,p0=7,r16
    mov b0=r23// restore b0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    mov r16=r19
    shladd r17=r17,4,r20        // get r2
    ;;
    mov b0=r17
    br.many b0
vmx_asm_mov_to_rr_back_2:
    mov r17=r19                 // get value
    ;;
    // if invalid value , go back
    adds r26=IA64_VCPU_RID_BITS_OFFSET,r21
    mov r27=r0
    ;;
    ld1 r27=[r26]
    ;;
    shr r19=r19,r27
    ;;
    cmp.ne p6,p0=r19,r0
    mov b0=r23// restore b0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    VMX_VIRT_SAVE
    ;;
    mov out0=r21
    mov out1=r16
    mov out2=r17
    movl r14=ia64_leave_hypervisor_virt
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_vcpu_set_rr_fast
END(vmx_asm_mov_to_rr)


//rsm 25
ENTRY(vmx_asm_rsm)
    extr.u r26=r25,6,21 // Imm21
    extr.u r27=r25,31,2 // I2d
    ;;
    extr.u r28=r25,36,1 // I
    dep r26=r27,r26,21,2
    ;;
    //r18 is imm24
    dep r16=r28,r26,23,1
    ;;
    VMX_VIRT_SAVE
    ;;
    mov out0=r21
    mov out1=r16
    movl r14=ia64_leave_hypervisor_virt
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_vcpu_rsm_fast
END(vmx_asm_rsm)


//ssm 24
ENTRY(vmx_asm_ssm)
    adds r18=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r18=[r18]
    ;;
    adds r26=IA64_VPD_VHPI_OFFSET,r18
    ;;
    ld8 r26=[r26]
    ;;
    cmp.ne p6,p0=r26,r0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    extr.u r26=r25,6,21
    extr.u r27=r25,31,2
    ;;
    extr.u r28=r25,36,1
    dep r26=r27,r26,21,2
    ;;  //r18 is imm24
    dep r16=r28,r26,23,1
    ;;
    VMX_VIRT_SAVE
    ;;
    mov out0=r21
    mov out1=r16
    movl r14=ia64_leave_hypervisor_virt
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_vcpu_ssm_fast
END(vmx_asm_ssm)


//mov psr.l=r2
ENTRY(vmx_asm_mov_to_psr)
    extr.u r26=r25,13,7 //r2
    movl r27=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_mov_to_psr_back-asm_mov_from_reg,r27
    shladd r26=r26,4,r27
    ;;
    mov b0=r26
    br.many b0
    ;;
vmx_asm_mov_to_psr_back:
    adds r18=IA64_VPD_BASE_OFFSET,r21
    tbit.nz p6,p0 = r19, IA64_PSR_I_BIT
    ;;
    ld8 r18=[r18]
    ;;
    adds r26=IA64_VPD_VHPI_OFFSET,r18
    ;;
    ld8 r26=[r26]
    ;;
    // if enable interrupt and vhpi has value, return
    cmp.ne.and p6,p0=r26,r0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    mov r16=r19
    ;;
    VMX_VIRT_SAVE
    ;;
    mov out0=r21
    mov out1=r16
    movl r14=ia64_leave_hypervisor_virt
    ;;
    mov rp=r14
    br.call.sptk.many b6=vmx_vcpu_mov_to_psr_fast
END(vmx_asm_mov_to_psr)


// thash r1=r3
// TODO: add support when pta.vf = 1
ENTRY(vmx_asm_thash)
    extr.u r17=r25,20,7                 // get r3 from opcode in r25
    extr.u r18=r25,6,7                  // get r1 from opcode in r25
    movl r20=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_thash_back1-asm_mov_from_reg,r20
    shladd r17=r17,4,r20                // get addr of MOVE_FROM_REG(r17)
    adds r16=IA64_VPD_BASE_OFFSET,r21   // get vcpu.arch.priveregs
    mov r24=b0                          // save b0
    ;;
    ld8 r16=[r16]                       // get VPD addr
    mov b0=r17
    br.many b0                          // r19 return value
    ;;
vmx_asm_thash_back1:
    shr.u r23=r19,61                    // get RR number
    adds r28=VCPU_VRR0_OFS,r21  // get vcpu->arch.arch_vmx.vrr[0]'s addr
    adds r16=IA64_VPD_VPTA_OFFSET,r16   // get virtual pta
    ;;
    shladd r27=r23,3,r28        // get vcpu->arch.arch_vmx.vrr[r23]'s addr
    ld8 r17=[r16]               // get virtual PTA
    mov r26=1
    ;;
    extr.u r29=r17,2,6// get pta.size
    ld8 r28=[r27]               // get vcpu->arch.arch_vmx.vrr[r23]'s value
    ;;
    // Fall-back to C if VF (long format) is set
    tbit.nz p6,p0=r17,8
    mov b0=r24
    ;;
    (p6) mov r24=EVENT_THASH
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    extr.u r28=r28,2,6      // get rr.ps
    shl r22=r26,r29         // 1UL << pta.size
    ;;
    shr.u r23=r19,r28       // vaddr >> rr.ps
    adds r26=3,r29          // pta.size + 3
    shl r27=r17,3           // pta << 3
    ;;
    shl r23=r23,3           // (vaddr >> rr.ps) << 3
    shr.u r27=r27,r26       // (pta << 3) >> (pta.size+3)
    movl r16=VRN_MASK
    ;;
    adds r22=-1,r22         // (1UL << pta.size) - 1
    shl r27=r27,r29         // ((pta<<3)>>(pta.size+3))<<pta.size
    and r19=r19,r16         // vaddr & VRN_MASK
    ;;
    and r22=r22,r23         // vhpt_offset
    or r19=r19,r27          // (vadr&VRN_MASK) |(((pta<<3)>>(pta.size + 3))<<pta.size)
    adds r26=asm_mov_to_reg-asm_mov_from_reg,r20
    ;;
    or r19=r19,r22          // calc pval
    shladd r17=r18,4,r26
    adds r30=vmx_resume_to_guest-asm_mov_from_reg,r20
    ;;
    mov b0=r17
    br.many b0
END(vmx_asm_thash)



#define MOV_TO_REG0     \
{;                      \
    nop.b 0x0;          \
    nop.b 0x0;          \
    nop.b 0x0;          \
    ;;                  \
};


#define MOV_TO_REG(n)   \
{;                      \
    mov r##n##=r19;     \
    mov b0=r30;         \
    br.sptk.many b0;    \
    ;;                  \
};


#define MOV_FROM_REG(n) \
{;                      \
    mov r19=r##n##;     \
    mov b0=r30;         \
    br.sptk.many b0;    \
    ;;                  \
};


#define MOV_TO_BANK0_REG(n)                 \
ENTRY_MIN_ALIGN(asm_mov_to_bank0_reg##n##); \
{;                                          \
    mov r26=r2;                             \
    mov r2=r19;                             \
    bsw.1;                                  \
    ;;                                      \
};                                          \
{;                                          \
    mov r##n##=r2;                          \
    nop.b 0x0;                              \
    bsw.0;                                  \
    ;;                                      \
};                                          \
{;                                          \
    mov r2=r26;                             \
    mov b0=r30;                             \
    br.sptk.many b0;                        \
    ;;                                      \
};                                          \
END(asm_mov_to_bank0_reg##n##)


#define MOV_FROM_BANK0_REG(n)                   \
ENTRY_MIN_ALIGN(asm_mov_from_bank0_reg##n##);   \
{;                                              \
    mov r26=r2;                                 \
    nop.b 0x0;                                  \
    bsw.1;                                      \
    ;;                                          \
};                                              \
{;                                              \
    mov r2=r##n##;                              \
    nop.b 0x0;                                  \
    bsw.0;                                      \
    ;;                                          \
};                                              \
{;                                              \
    mov r19=r2;                                 \
    mov r2=r26;                                 \
    mov b0=r30;                                 \
};                                              \
{;                                              \
    nop.b 0x0;                                  \
    nop.b 0x0;                                  \
    br.sptk.many b0;                            \
    ;;                                          \
};                                              \
END(asm_mov_from_bank0_reg##n##)


#define JMP_TO_MOV_TO_BANK0_REG(n)              \
{;                                              \
    nop.b 0x0;                                  \
    nop.b 0x0;                                  \
    br.sptk.many asm_mov_to_bank0_reg##n##;     \
    ;;                                          \
}


#define JMP_TO_MOV_FROM_BANK0_REG(n)            \
{;                                              \
    nop.b 0x0;                                  \
    nop.b 0x0;                                  \
    br.sptk.many asm_mov_from_bank0_reg##n##;   \
    ;;                                          \
}


MOV_FROM_BANK0_REG(16)
MOV_FROM_BANK0_REG(17)
MOV_FROM_BANK0_REG(18)
MOV_FROM_BANK0_REG(19)
MOV_FROM_BANK0_REG(20)
MOV_FROM_BANK0_REG(21)
MOV_FROM_BANK0_REG(22)
MOV_FROM_BANK0_REG(23)
MOV_FROM_BANK0_REG(24)
MOV_FROM_BANK0_REG(25)
MOV_FROM_BANK0_REG(26)
MOV_FROM_BANK0_REG(27)
MOV_FROM_BANK0_REG(28)
MOV_FROM_BANK0_REG(29)
MOV_FROM_BANK0_REG(30)
MOV_FROM_BANK0_REG(31)


// mov from reg table
// r19:value, r30: return address
// r26 may be destroyed
ENTRY(asm_mov_from_reg)
    MOV_FROM_REG(0)
    MOV_FROM_REG(1)
    MOV_FROM_REG(2)
    MOV_FROM_REG(3)
    MOV_FROM_REG(4)
    MOV_FROM_REG(5)
    MOV_FROM_REG(6)
    MOV_FROM_REG(7)
    MOV_FROM_REG(8)
    MOV_FROM_REG(9)
    MOV_FROM_REG(10)
    MOV_FROM_REG(11)
    MOV_FROM_REG(12)
    MOV_FROM_REG(13)
    MOV_FROM_REG(14)
    MOV_FROM_REG(15)
    JMP_TO_MOV_FROM_BANK0_REG(16)
    JMP_TO_MOV_FROM_BANK0_REG(17)
    JMP_TO_MOV_FROM_BANK0_REG(18)
    JMP_TO_MOV_FROM_BANK0_REG(19)
    JMP_TO_MOV_FROM_BANK0_REG(20)
    JMP_TO_MOV_FROM_BANK0_REG(21)
    JMP_TO_MOV_FROM_BANK0_REG(22)
    JMP_TO_MOV_FROM_BANK0_REG(23)
    JMP_TO_MOV_FROM_BANK0_REG(24)
    JMP_TO_MOV_FROM_BANK0_REG(25)
    JMP_TO_MOV_FROM_BANK0_REG(26)
    JMP_TO_MOV_FROM_BANK0_REG(27)
    JMP_TO_MOV_FROM_BANK0_REG(28)
    JMP_TO_MOV_FROM_BANK0_REG(29)
    JMP_TO_MOV_FROM_BANK0_REG(30)
    JMP_TO_MOV_FROM_BANK0_REG(31)
    MOV_FROM_REG(32)
    MOV_FROM_REG(33)
    MOV_FROM_REG(34)
    MOV_FROM_REG(35)
    MOV_FROM_REG(36)
    MOV_FROM_REG(37)
    MOV_FROM_REG(38)
    MOV_FROM_REG(39)
    MOV_FROM_REG(40)
    MOV_FROM_REG(41)
    MOV_FROM_REG(42)
    MOV_FROM_REG(43)
    MOV_FROM_REG(44)
    MOV_FROM_REG(45)
    MOV_FROM_REG(46)
    MOV_FROM_REG(47)
    MOV_FROM_REG(48)
    MOV_FROM_REG(49)
    MOV_FROM_REG(50)
    MOV_FROM_REG(51)
    MOV_FROM_REG(52)
    MOV_FROM_REG(53)
    MOV_FROM_REG(54)
    MOV_FROM_REG(55)
    MOV_FROM_REG(56)
    MOV_FROM_REG(57)
    MOV_FROM_REG(58)
    MOV_FROM_REG(59)
    MOV_FROM_REG(60)
    MOV_FROM_REG(61)
    MOV_FROM_REG(62)
    MOV_FROM_REG(63)
    MOV_FROM_REG(64)
    MOV_FROM_REG(65)
    MOV_FROM_REG(66)
    MOV_FROM_REG(67)
    MOV_FROM_REG(68)
    MOV_FROM_REG(69)
    MOV_FROM_REG(70)
    MOV_FROM_REG(71)
    MOV_FROM_REG(72)
    MOV_FROM_REG(73)
    MOV_FROM_REG(74)
    MOV_FROM_REG(75)
    MOV_FROM_REG(76)
    MOV_FROM_REG(77)
    MOV_FROM_REG(78)
    MOV_FROM_REG(79)
    MOV_FROM_REG(80)
    MOV_FROM_REG(81)
    MOV_FROM_REG(82)
    MOV_FROM_REG(83)
    MOV_FROM_REG(84)
    MOV_FROM_REG(85)
    MOV_FROM_REG(86)
    MOV_FROM_REG(87)
    MOV_FROM_REG(88)
    MOV_FROM_REG(89)
    MOV_FROM_REG(90)
    MOV_FROM_REG(91)
    MOV_FROM_REG(92)
    MOV_FROM_REG(93)
    MOV_FROM_REG(94)
    MOV_FROM_REG(95)
    MOV_FROM_REG(96)
    MOV_FROM_REG(97)
    MOV_FROM_REG(98)
    MOV_FROM_REG(99)
    MOV_FROM_REG(100)
    MOV_FROM_REG(101)
    MOV_FROM_REG(102)
    MOV_FROM_REG(103)
    MOV_FROM_REG(104)
    MOV_FROM_REG(105)
    MOV_FROM_REG(106)
    MOV_FROM_REG(107)
    MOV_FROM_REG(108)
    MOV_FROM_REG(109)
    MOV_FROM_REG(110)
    MOV_FROM_REG(111)
    MOV_FROM_REG(112)
    MOV_FROM_REG(113)
    MOV_FROM_REG(114)
    MOV_FROM_REG(115)
    MOV_FROM_REG(116)
    MOV_FROM_REG(117)
    MOV_FROM_REG(118)
    MOV_FROM_REG(119)
    MOV_FROM_REG(120)
    MOV_FROM_REG(121)
    MOV_FROM_REG(122)
    MOV_FROM_REG(123)
    MOV_FROM_REG(124)
    MOV_FROM_REG(125)
    MOV_FROM_REG(126)
    MOV_FROM_REG(127)
END(asm_mov_from_reg)


/* must be in bank 0
 *  parameter:
 *  r31: pr
 *  r24: b0
 *  p2: whether increase IP
 *  p3: whether check vpsr.ic
 */
ENTRY(vmx_resume_to_guest)
    // ip ++
    (p2) mov r16=cr.ipsr
    (p2)dep.z r30=1,IA64_PSR_RI_BIT,1
    adds r19=IA64_VPD_BASE_OFFSET,r21
    ;;
    ld8 r25=[r19]
    (p2) add r16=r30,r16
    ;;
    (p2) mov cr.ipsr=r16
    adds r19= VPD_VPSR_START_OFFSET,r25
    ;;
    ld8 r19=[r19]
    ;;
    mov r23=r31
    mov r17=r0
    //vps_resume_normal/handler
    tbit.z p6,p7 = r19,IA64_PSR_IC_BIT  // p7=vpsr.ic
    (p6) br.cond.sptk.many vmx_vps_resume_handler
    (p7) br.cond.sptk.few vmx_vps_resume_normal
END(vmx_resume_to_guest)


MOV_TO_BANK0_REG(16)
MOV_TO_BANK0_REG(17)
MOV_TO_BANK0_REG(18)
MOV_TO_BANK0_REG(19)
MOV_TO_BANK0_REG(20)
MOV_TO_BANK0_REG(21)
MOV_TO_BANK0_REG(22)
MOV_TO_BANK0_REG(23)
MOV_TO_BANK0_REG(24)
MOV_TO_BANK0_REG(25)
MOV_TO_BANK0_REG(26)
MOV_TO_BANK0_REG(27)
MOV_TO_BANK0_REG(28)
MOV_TO_BANK0_REG(29)
MOV_TO_BANK0_REG(30)
MOV_TO_BANK0_REG(31)


// mov to reg table
// r19:value, r30: return address
ENTRY(asm_mov_to_reg)
    MOV_TO_REG0
    MOV_TO_REG(1)
    MOV_TO_REG(2)
    MOV_TO_REG(3)
    MOV_TO_REG(4)
    MOV_TO_REG(5)
    MOV_TO_REG(6)
    MOV_TO_REG(7)
    MOV_TO_REG(8)
    MOV_TO_REG(9)
    MOV_TO_REG(10)
    MOV_TO_REG(11)
    MOV_TO_REG(12)
    MOV_TO_REG(13)
    MOV_TO_REG(14)
    MOV_TO_REG(15)
    JMP_TO_MOV_TO_BANK0_REG(16)
    JMP_TO_MOV_TO_BANK0_REG(17)
    JMP_TO_MOV_TO_BANK0_REG(18)
    JMP_TO_MOV_TO_BANK0_REG(19)
    JMP_TO_MOV_TO_BANK0_REG(20)
    JMP_TO_MOV_TO_BANK0_REG(21)
    JMP_TO_MOV_TO_BANK0_REG(22)
    JMP_TO_MOV_TO_BANK0_REG(23)
    JMP_TO_MOV_TO_BANK0_REG(24)
    JMP_TO_MOV_TO_BANK0_REG(25)
    JMP_TO_MOV_TO_BANK0_REG(26)
    JMP_TO_MOV_TO_BANK0_REG(27)
    JMP_TO_MOV_TO_BANK0_REG(28)
    JMP_TO_MOV_TO_BANK0_REG(29)
    JMP_TO_MOV_TO_BANK0_REG(30)
    JMP_TO_MOV_TO_BANK0_REG(31)
    MOV_TO_REG(32)
    MOV_TO_REG(33)
    MOV_TO_REG(34)
    MOV_TO_REG(35)
    MOV_TO_REG(36)
    MOV_TO_REG(37)
    MOV_TO_REG(38)
    MOV_TO_REG(39)
    MOV_TO_REG(40)
    MOV_TO_REG(41)
    MOV_TO_REG(42)
    MOV_TO_REG(43)
    MOV_TO_REG(44)
    MOV_TO_REG(45)
    MOV_TO_REG(46)
    MOV_TO_REG(47)
    MOV_TO_REG(48)
    MOV_TO_REG(49)
    MOV_TO_REG(50)
    MOV_TO_REG(51)
    MOV_TO_REG(52)
    MOV_TO_REG(53)
    MOV_TO_REG(54)
    MOV_TO_REG(55)
    MOV_TO_REG(56)
    MOV_TO_REG(57)
    MOV_TO_REG(58)
    MOV_TO_REG(59)
    MOV_TO_REG(60)
    MOV_TO_REG(61)
    MOV_TO_REG(62)
    MOV_TO_REG(63)
    MOV_TO_REG(64)
    MOV_TO_REG(65)
    MOV_TO_REG(66)
    MOV_TO_REG(67)
    MOV_TO_REG(68)
    MOV_TO_REG(69)
    MOV_TO_REG(70)
    MOV_TO_REG(71)
    MOV_TO_REG(72)
    MOV_TO_REG(73)
    MOV_TO_REG(74)
    MOV_TO_REG(75)
    MOV_TO_REG(76)
    MOV_TO_REG(77)
    MOV_TO_REG(78)
    MOV_TO_REG(79)
    MOV_TO_REG(80)
    MOV_TO_REG(81)
    MOV_TO_REG(82)
    MOV_TO_REG(83)
    MOV_TO_REG(84)
    MOV_TO_REG(85)
    MOV_TO_REG(86)
    MOV_TO_REG(87)
    MOV_TO_REG(88)
    MOV_TO_REG(89)
    MOV_TO_REG(90)
    MOV_TO_REG(91)
    MOV_TO_REG(92)
    MOV_TO_REG(93)
    MOV_TO_REG(94)
    MOV_TO_REG(95)
    MOV_TO_REG(96)
    MOV_TO_REG(97)
    MOV_TO_REG(98)
    MOV_TO_REG(99)
    MOV_TO_REG(100)
    MOV_TO_REG(101)
    MOV_TO_REG(102)
    MOV_TO_REG(103)
    MOV_TO_REG(104)
    MOV_TO_REG(105)
    MOV_TO_REG(106)
    MOV_TO_REG(107)
    MOV_TO_REG(108)
    MOV_TO_REG(109)
    MOV_TO_REG(110)
    MOV_TO_REG(111)
    MOV_TO_REG(112)
    MOV_TO_REG(113)
    MOV_TO_REG(114)
    MOV_TO_REG(115)
    MOV_TO_REG(116)
    MOV_TO_REG(117)
    MOV_TO_REG(118)
    MOV_TO_REG(119)
    MOV_TO_REG(120)
    MOV_TO_REG(121)
    MOV_TO_REG(122)
    MOV_TO_REG(123)
    MOV_TO_REG(124)
    MOV_TO_REG(125)
    MOV_TO_REG(126)
    MOV_TO_REG(127)
END(asm_mov_to_reg)
