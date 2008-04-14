/*
 * arch/ia64/vmx/optvfault.S
 * optimize virtualization fault handler
 *
 * Copyright (C) 2006 Intel Co
 *	Xuefei Xu (Anthony Xu) <anthony.xu@intel.com>
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

#define ACCE_MOV_FROM_AR
#define ACCE_MOV_FROM_RR
#define ACCE_MOV_TO_RR
#define ACCE_RSM
#define ACCE_SSM
#define ACCE_MOV_TO_PSR
#define ACCE_THASH

// Inputs are: r21 (= current), r24 (= cause), r25 (= insn), r31 (=saved pr)

ENTRY(vmx_dummy_function)
    br.sptk.many vmx_dummy_function
END(vmx_dummy_function)

/*
 *	Inputs:
 *		r24 : return address
 *  	r25 : vpd
 *		r29 : scratch
 *
 */
GLOBAL_ENTRY(vmx_vps_sync_read)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    br.sptk.many b0
END(vmx_vps_sync_read)

/*
 *	Inputs:
 *		r24 : return address
 *  	r25 : vpd
 *		r29 : scratch
 *
 */
GLOBAL_ENTRY(vmx_vps_sync_write)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    br.sptk.many b0
END(vmx_vps_sync_write)

/*
 *	Inputs:
 *		r23 : pr
 *		r24 : guest b0
 *  	r25 : vpd
 *
 */
GLOBAL_ENTRY(vmx_vps_resume_normal)
    movl r29 = vmx_dummy_function
    ;;
    mov b0=r29
    mov pr=r23,-2
    br.sptk.many b0
END(vmx_vps_resume_normal)

/*
 *	Inputs:
 *		r23 : pr
 *		r24 : guest b0
 *  	r25 : vpd
 *		r17 : isr
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


//mov r1=ar3 (only itc is virtualized)
GLOBAL_ENTRY(vmx_asm_mov_from_ar)
#ifndef ACCE_MOV_FROM_AR
    br.many vmx_virtualization_fault_back
#endif
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
GLOBAL_ENTRY(vmx_asm_mov_from_rr)
#ifndef ACCE_MOV_FROM_RR
    br.many vmx_virtualization_fault_back
#endif
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
GLOBAL_ENTRY(vmx_asm_mov_to_rr)
#ifndef ACCE_MOV_TO_RR
    br.many vmx_virtualization_fault_back
#endif
    add r22=IA64_VCPU_RID_BITS_OFFSET,r21
    extr.u r16=r25,20,7		// r3
    extr.u r17=r25,13,7		// r2
    ;;
    movl r20=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_mov_to_rr_back_1-asm_mov_from_reg,r20
    shladd r16=r16,4,r20	// get r3
    mov r18=b0			// save b0
    ;;
    add r27=VCPU_VRR0_OFS,r21
    mov b0=r16
    br.many b0
    ;;   
vmx_asm_mov_to_rr_back_1:
    adds r30=vmx_asm_mov_to_rr_back_2-asm_mov_from_reg,r20
    shr.u r23=r19,61		// get RR #
    shladd r17=r17,4,r20	// get r2
    ;;
    //if rr7, go back
    cmp.eq p6,p0=7,r23
    mov b0=r18			// restore b0
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;;
    mov r28=r19			// save r3
    mov b0=r17
    br.many b0
vmx_asm_mov_to_rr_back_2: 
    adds r30=vmx_resume_to_guest-asm_mov_from_reg,r20
    shladd r27=r23,3,r27	// address of VRR
    ;;
    ld1 r22=[r22]		// Load rid_bits from domain
    mov b0=r18			// restore b0
    adds r16=IA64_VCPU_STARTING_RID_OFFSET,r21
    ;;
    ld4 r16=[r16]		// load starting_rid
    extr.u r17=r19,8,24		// Extract RID
    ;;
    shr r17=r17,r22		// Shift out used bits
    shl r16=r16,8
    ;;
    add r20=r19,r16
    cmp.ne p6,p0=0,r17	// If reserved RID bits are set, use C fall back.
    (p6) br.cond.dpnt.many vmx_virtualization_fault_back
    ;; //mangling rid 1 and 3
    extr.u r16=r20,8,8
    extr.u r17=r20,24,8
    mov r24=r18		// saved b0 for resume
    ;;
    extr.u r18=r20,2,6 // page size
    dep r20=r16,r20,24,8
    mov b0=r30
    ;;
    dep r20=r17,r20,8,8
    ;; //set ve 1
    dep r20=-1,r20,0,1
    // If ps > PAGE_SHIFT, use PAGE_SHIFT
    cmp.lt p6,p0=PAGE_SHIFT,r18
    ;;
    (p6) mov r18=PAGE_SHIFT
    ;;
    (p6) dep r20=r18,r20,2,6
    ;;	
    st8 [r27]=r19	// Write to vrr.
    // Write to save_rr if rr=0 or rr=4.
    cmp.eq p6,p0=0,r23
    ;;
    cmp.eq.or p6,p0=4,r23
    ;;
    adds r16=IA64_VCPU_MMU_MODE_OFFSET,r21
    (p6) adds r17=IA64_VCPU_META_SAVED_RR0_OFFSET,r21
    ;;
    ld1 r16=[r16]
    cmp.eq p7,p0=r0,r0
    (p6) shladd r17=r23,1,r17
    ;;
    (p6) st8 [r17]=r20
    (p6) cmp.eq p7,p0=VMX_MMU_VIRTUAL,r16 // Set physical rr if in virt mode
    ;;
    (p7) mov rr[r28]=r20
    br.many b0
END(vmx_asm_mov_to_rr)


//rsm 
GLOBAL_ENTRY(vmx_asm_rsm)
#ifndef ACCE_RSM
    br.many vmx_virtualization_fault_back
#endif
    mov r23=r31
    add r16=IA64_VPD_BASE_OFFSET,r21
    extr.u r26=r25,6,21 // Imm21
    extr.u r27=r25,31,2 // I2d
    ;;
    ld8 r16=[r16]
    extr.u r28=r25,36,1 // I
    dep r26=r27,r26,21,2
    ;;
    add r17=VPD_VPSR_START_OFFSET,r16
    //r18 is imm24
    dep r18=r28,r26,23,1
    ;;
    //sync read
    mov r25=r16
    movl r24=vmx_asm_rsm_sync_read_return
    mov r20=b0
    br.sptk.many vmx_vps_sync_read
    ;;
vmx_asm_rsm_sync_read_return:
    ld8 r26=[r17]
    // xenoprof
    // Don't change mPSR.pp.
    // It is manipulated by xenoprof.
    movl r28=IA64_PSR_IC+IA64_PSR_I+IA64_PSR_DT+IA64_PSR_SI+IA64_PSR_PP

    sub r27=-1,r18 // ~imm24
    ;;
    or r28=r27,r28 // Keep IC,I,DT,SI
    and r19=r26,r27 // Update vpsr
    ;;
    st8 [r17]=r19
    mov r24=cr.ipsr
    ;;
    and r24=r24,r28 // Update ipsr
    adds r27=IA64_VCPU_FP_PSR_OFFSET,r21
    ;;
    ld8 r27=[r27]
    ;;
    tbit.nz p8,p0=r27,IA64_PSR_DFH_BIT
    ;;
    (p8) dep r24=-1,r24,IA64_PSR_DFH_BIT,1  // Keep dfh
    ;;
    mov cr.ipsr=r24
    //sync write
    mov r25=r16
    movl r24=vmx_asm_rsm_sync_write_return
    br.sptk.many vmx_vps_sync_write
    ;;
vmx_asm_rsm_sync_write_return:
    add r29=IA64_VCPU_MMU_MODE_OFFSET,r21
    ;;
    ld1 r27=[r29]
    ;;
    cmp.ne p6,p0=VMX_MMU_VIRTUAL,r27
    ;;
    tbit.z.or p6,p0=r18,IA64_PSR_DT_BIT
    (p6) br.dptk vmx_asm_rsm_out
    // DT not cleared or already in phy mode
    ;;
    // Switch to meta physical mode D.
    add r26=IA64_VCPU_META_RID_D_OFFSET,r21
    mov r27=VMX_MMU_PHY_D
    ;;
    ld8 r26=[r26]
    st1 [r29]=r27 
    dep.z r28=4,61,3
    ;;
    mov rr[r0]=r26
    ;;
    mov rr[r28]=r26
    ;;
    srlz.d
vmx_asm_rsm_out:	
    mov r31=r23
    mov r24=r20
    br.many vmx_resume_to_guest
END(vmx_asm_rsm)


//ssm 
GLOBAL_ENTRY(vmx_asm_ssm)
#ifndef ACCE_SSM
    br.many vmx_virtualization_fault_back
#endif
    mov r23=r31
    add r16=IA64_VPD_BASE_OFFSET,r21
    extr.u r26=r25,6,21
    extr.u r27=r25,31,2
    ;;
    ld8 r16=[r16]
    extr.u r28=r25,36,1
    dep r26=r27,r26,21,2
    ;;  //r18 is imm24
    dep r18=r28,r26,23,1
    ;;  
    //sync read
    mov r25=r16
    movl r24=vmx_asm_ssm_sync_read_return
    mov r20=b0
    br.sptk.many vmx_vps_sync_read
    ;;
vmx_asm_ssm_sync_read_return:
    add r27=VPD_VPSR_START_OFFSET,r16
    ;;
    ld8 r17=[r27]		//r17 old vpsr
    dep r28=0,r18,IA64_PSR_PP_BIT,1 // For xenoprof
                                    // Don't change mPSR.pp
                                    // It is maintained by xenoprof.
    ;;
    or r19=r17,r18		//r19 new vpsr
    ;;
    st8 [r27]=r19 // update vpsr
    mov r24=cr.ipsr
    ;;
    or r24=r24,r28
    ;;
    mov cr.ipsr=r24
    //sync_write
    mov r25=r16
    movl r24=vmx_asm_ssm_sync_write_return
    br.sptk.many vmx_vps_sync_write
    ;;
vmx_asm_ssm_sync_write_return:	
    add r29=IA64_VCPU_MMU_MODE_OFFSET,r21
    movl r28=IA64_PSR_DT+IA64_PSR_RT+IA64_PSR_IT
    ;;
    ld1 r30=[r29] // mmu_mode
    ;;
    and r27=r28,r19
    cmp.eq p6,p0=VMX_MMU_VIRTUAL,r30
    ;;
    cmp.ne.or p6,p0=r28,r27 // (vpsr & (it+dt+rt)) /= (it+dt+rt) ie stay in phy
    (p6) br.dptk vmx_asm_ssm_1
    ;;
    add r26=IA64_VCPU_META_SAVED_RR0_OFFSET,r21
    add r27=IA64_VCPU_META_SAVED_RR0_OFFSET+8,r21
    mov r30=VMX_MMU_VIRTUAL
    ;;
    ld8 r26=[r26]
    ld8 r27=[r27]
    st1 [r29]=r30
    dep.z r28=4,61,3
    ;;
    mov rr[r0]=r26
    ;;
    mov rr[r28]=r27
    ;;
    srlz.d
    ;;
vmx_asm_ssm_1:
    tbit.nz p6,p0=r17,IA64_PSR_I_BIT
    ;;
    tbit.z.or p6,p0=r19,IA64_PSR_I_BIT
    (p6) br.dptk vmx_asm_ssm_out
    ;;
    add r29=VPD_VTPR_START_OFFSET,r16
    add r30=VPD_VHPI_START_OFFSET,r16
    ;;
    ld8 r29=[r29]
    ld8 r30=[r30]
    ;;
    extr.u r17=r29,4,4
    extr.u r18=r29,16,1
    ;;
    dep r17=r18,r17,4,1
    mov r31=r23
    mov b0=r20
    ;;
    cmp.gt p6,p0=r30,r17
    (p6) br.dpnt.few vmx_asm_dispatch_vexirq
vmx_asm_ssm_out:	
    mov r31=r23
    mov r24=r20
    br.many vmx_resume_to_guest
END(vmx_asm_ssm)


//mov psr.l=r2 
GLOBAL_ENTRY(vmx_asm_mov_to_psr)
#ifndef ACCE_MOV_TO_PSR
    br.many vmx_virtualization_fault_back
#endif
    mov r23=r31
    add r16=IA64_VPD_BASE_OFFSET,r21
    extr.u r26=r25,13,7 //r2
    ;;
    ld8 r16=[r16]
    movl r24=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_mov_to_psr_back-asm_mov_from_reg,r24
    shladd r26=r26,4,r24
    mov r20=b0
    ;;
    mov b0=r26
    br.many b0
    ;;   
vmx_asm_mov_to_psr_back:
    //sync read
    mov r25=r16
    movl r24=vmx_asm_mov_to_psr_sync_read_return
    br.sptk.many vmx_vps_sync_read
    ;;
vmx_asm_mov_to_psr_sync_read_return:
    add r27=VPD_VPSR_START_OFFSET,r16
    ;;
    ld8 r17=[r27] // r17 old vpsr
    dep r19=0,r19,32,32 // Clear bits 32-63
    ;;   
    dep r18=0,r17,0,32
    ;; 
    or r18=r18,r19 //r18 new vpsr
    ;;
    st8 [r27]=r18 // set vpsr
    //sync write
    mov r25=r16
    movl r24=vmx_asm_mov_to_psr_sync_write_return
    br.sptk.many vmx_vps_sync_write
    ;;
vmx_asm_mov_to_psr_sync_write_return:
    add r22=IA64_VCPU_MMU_MODE_OFFSET,r21
    movl r28=IA64_PSR_DT+IA64_PSR_RT+IA64_PSR_IT
    ;;
    and r27=r28,r18
    and r29=r28,r17
    ;;
    cmp.eq p5,p0=r29,r27 // (old_vpsr & (dt+rt+it)) == (new_vpsr & (dt+rt+it))
    cmp.eq p6,p7=r28,r27 // (new_vpsr & (dt+rt+it)) == (dt+rt+it)
    (p5) br.many vmx_asm_mov_to_psr_1 // no change
    ;;
    //virtual to physical D
    (p7) add r26=IA64_VCPU_META_RID_D_OFFSET,r21
    (p7) add r27=IA64_VCPU_META_RID_D_OFFSET,r21
    (p7) mov r30=VMX_MMU_PHY_D
    ;;
    //physical to virtual
    (p6) add r26=IA64_VCPU_META_SAVED_RR0_OFFSET,r21
    (p6) add r27=IA64_VCPU_META_SAVED_RR0_OFFSET+8,r21
    (p6) mov r30=VMX_MMU_VIRTUAL
    ;;
    ld8 r26=[r26]
    ld8 r27=[r27]
    st1 [r22]=r30
    dep.z r28=4,61,3
    ;;
    mov rr[r0]=r26
    ;;
    mov rr[r28]=r27
    ;;
    srlz.d
    ;;
vmx_asm_mov_to_psr_1:
    mov r24=cr.ipsr
    movl r28=IA64_PSR_IC+IA64_PSR_I+IA64_PSR_DT+IA64_PSR_SI+IA64_PSR_RT
    ;;
    tbit.nz p7,p0=r24,IA64_PSR_PP_BIT           // For xenoprof
    or r27=r19,r28
    dep r24=0,r24,0,32
    ;;
    add r24=r27,r24
    ;;
    adds r27=IA64_VCPU_FP_PSR_OFFSET,r21
    (p7) dep r24=-1,r24,IA64_PSR_PP_BIT,1       // For xenoprof
                                                // Dom't change mPSR.pp
                                                // It is maintaned by xenoprof
    ;;
    ld8 r27=[r27]
    ;;
    tbit.nz p8,p0=r27,IA64_PSR_DFH_BIT
    ;;
    (p8) dep r24=-1,r24,IA64_PSR_DFH_BIT,1
    ;;
    mov cr.ipsr=r24
    tbit.nz p6,p0=r17,IA64_PSR_I_BIT
    ;;
    tbit.z.or p6,p0=r18,IA64_PSR_I_BIT
    (p6) br.dpnt.few vmx_asm_mov_to_psr_out
    ;;
    add r29=VPD_VTPR_START_OFFSET,r16
    add r30=VPD_VHPI_START_OFFSET,r16
    ;;
    ld8 r29=[r29]
    ld8 r30=[r30]
    ;;
    extr.u r17=r29,4,4
    extr.u r18=r29,16,1
    ;;
    dep r17=r18,r17,4,1
    mov r31=r23
    mov b0=r20
    ;;
    cmp.gt p6,p0=r30,r17
    (p6) br.dpnt.few vmx_asm_dispatch_vexirq
vmx_asm_mov_to_psr_out:
    mov r31=r23
    mov r24=r20
    br.many vmx_resume_to_guest
END(vmx_asm_mov_to_psr)


ENTRY(vmx_asm_dispatch_vexirq)
//increment iip
    mov r16=cr.ipsr
    ;;
    extr.u r17=r16,IA64_PSR_RI_BIT,2
    tbit.nz p6,p7=r16,IA64_PSR_RI_BIT+1
    ;;	
    (p6) mov r18=cr.iip
    (p6) mov r17=r0
    (p7) add r17=1,r17
    ;;    
    (p6) add r18=0x10,r18
    dep r16=r17,r16,IA64_PSR_RI_BIT,2
    ;;		
    (p6) mov cr.iip=r18
    mov cr.ipsr=r16
    br.many vmx_dispatch_vexirq
END(vmx_asm_dispatch_vexirq)

// thash r1=r3
// TODO: add support when pta.vf = 1
GLOBAL_ENTRY(vmx_asm_thash)
#ifndef ACCE_THASH
    br.many vmx_virtualization_fault_back
#endif
    extr.u r17=r25,20,7		// get r3 from opcode in r25 
    extr.u r18=r25,6,7		// get r1 from opcode in r25
    movl r20=asm_mov_from_reg
    ;;
    adds r30=vmx_asm_thash_back1-asm_mov_from_reg,r20
    shladd r17=r17,4,r20	// get addr of MOVE_FROM_REG(r17)
    adds r16=IA64_VPD_BASE_OFFSET,r21	// get vcpu.arch.priveregs
    mov r24=b0			// save b0
    ;;
    ld8 r16=[r16]		// get VPD addr
    mov b0=r17
    br.many b0			// r19 return value
    ;;                                                     
vmx_asm_thash_back1:
    shr.u r23=r19,61		// get RR number
    adds r28=VCPU_VRR0_OFS,r21	// get vcpu->arch.arch_vmx.vrr[0]'s addr
    adds r16=IA64_VPD_VPTA_OFFSET,r16	// get virtual pta 
    ;;
    shladd r27=r23,3,r28	// get vcpu->arch.arch_vmx.vrr[r23]'s addr
    ld8 r17=[r16]		// get virtual PTA
    mov r26=1
    ;;
    extr.u r29=r17,2,6		// get pta.size
    ld8 r28=[r27]		// get vcpu->arch.arch_vmx.vrr[r23]'s value
    ;;
    // Fall-back to C if VF (long format) is set
    tbit.nz p6,p0=r17,8
    mov b0=r24
    ;;
(p6) mov r24=EVENT_THASH
(p6) br.cond.dpnt.many vmx_virtualization_fault_back
    extr.u r28=r28,2,6		// get rr.ps
    shl r22=r26,r29		// 1UL << pta.size
    ;;
    shr.u r23=r19,r28		// vaddr >> rr.ps
    adds r26=3,r29		// pta.size + 3 
    shl r27=r17,3		// pta << 3 
    ;;
    shl r23=r23,3		// (vaddr >> rr.ps) << 3
    shr.u r27=r27,r26		// (pta << 3) >> (pta.size+3)
    movl r16=VRN_MASK
    ;;
    adds r22=-1,r22		// (1UL << pta.size) - 1
    shl r27=r27,r29		// ((pta<<3)>>(pta.size+3))<<pta.size
    and r19=r19,r16		// vaddr & VRN_MASK
    ;;
    and r22=r22,r23		// vhpt_offset 
    or r19=r19,r27		// (vadr&VRN_MASK) |(((pta<<3)>>(pta.size + 3))<<pta.size) 
    adds r26=asm_mov_to_reg-asm_mov_from_reg,r20
    ;;
    or r19=r19,r22		// calc pval
    shladd r17=r18,4,r26
    adds r30=vmx_resume_to_guest-asm_mov_from_reg,r20
    ;;
    mov b0=r17
    br.many b0
END(vmx_asm_thash)

#define MOV_TO_REG0	\
{;			\
    nop.b 0x0;		\
    nop.b 0x0;		\
    nop.b 0x0;		\
    ;;			\
};


#define MOV_TO_REG(n)	\
{;			\
    mov r##n##=r19;	\
    mov b0=r30;		\
    br.sptk.many b0;	\
    ;;			\
};


#define MOV_FROM_REG(n)	\
{;			\
    mov r19=r##n##;	\
    mov b0=r30;		\
    br.sptk.many b0;	\
    ;;			\
};


#define MOV_TO_BANK0_REG(n)			\
ENTRY_MIN_ALIGN(asm_mov_to_bank0_reg##n##);	\
{;						\
    mov r26=r2;					\
    mov r2=r19;					\
    bsw.1;					\
    ;;						\
};						\
{;						\
    mov r##n##=r2;				\
    nop.b 0x0;					\
    bsw.0;					\
    ;;						\
};						\
{;						\
    mov r2=r26;					\
    mov b0=r30;					\
    br.sptk.many b0;				\
    ;;						\
};						\
END(asm_mov_to_bank0_reg##n##)


#define MOV_FROM_BANK0_REG(n)			\
ENTRY_MIN_ALIGN(asm_mov_from_bank0_reg##n##);	\
{;						\
    mov r26=r2;					\
    nop.b 0x0;					\
    bsw.1;					\
    ;;						\
};						\
{;						\
    mov r2=r##n##;				\
    nop.b 0x0;					\
    bsw.0;					\
    ;;						\
};						\
{;						\
    mov r19=r2;					\
    mov r2=r26;					\
    mov b0=r30;					\
};						\
{;						\
    nop.b 0x0;					\
    nop.b 0x0;					\
    br.sptk.many b0;				\
    ;;						\
};						\
END(asm_mov_from_bank0_reg##n##)


#define JMP_TO_MOV_TO_BANK0_REG(n)		\
{;						\
    nop.b 0x0;					\
    nop.b 0x0;					\
    br.sptk.many asm_mov_to_bank0_reg##n##;	\
    ;;						\
}    


#define JMP_TO_MOV_FROM_BANK0_REG(n)		\
{;						\
    nop.b 0x0;					\
    nop.b 0x0;					\
    br.sptk.many asm_mov_from_bank0_reg##n##;	\
    ;;						\
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
// r19:	value, r30: return address
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
 * parameter:
 * r31: pr
 * r24: b0
 */
ENTRY(vmx_resume_to_guest)
    mov r16=cr.ipsr
    ;;
    adds r19=IA64_VPD_BASE_OFFSET,r21
    extr.u r17=r16,IA64_PSR_RI_BIT,2
    ;;
    ld8 r25=[r19]
    add r17=1,r17
    ;;
    adds r19= VPD_VPSR_START_OFFSET,r25
    dep r16=r17,r16,IA64_PSR_RI_BIT,2
    ;;
    mov cr.ipsr=r16
    ld8 r19=[r19]
    ;;
    mov r23=r31
    mov r17=r0
    //vps_resume_normal/handler
    tbit.z p6,p7 = r19,IA64_PSR_IC_BIT		// p1=vpsr.ic
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
// r19:	value, r30: return address
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
