/*
 * Copyright (C) 2005 Jimi Xenidis <jimix@watson.ibm.com>, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <asm/config.h>
#include <asm/asm-offsets.h>
#include <asm/reg_defs.h>
#include <asm/msr.h>
#include <asm/processor.h>

#ifdef HAS_FLOAT
save_fp:
	addi	r4, r3, VCPU_fprs - FPR_WIDTH
	stfdu	fr0,FPR_WIDTH(r4)
	stfdu	fr1,FPR_WIDTH(r4)
	stfdu	fr2,FPR_WIDTH(r4)
	stfdu	fr3,FPR_WIDTH(r4)
	stfdu	fr4,FPR_WIDTH(r4)
	stfdu	fr5,FPR_WIDTH(r4)
	stfdu	fr6,FPR_WIDTH(r4)
	stfdu	fr7,FPR_WIDTH(r4)
	stfdu	fr8,FPR_WIDTH(r4)
	stfdu	fr9,FPR_WIDTH(r4)
	stfdu	fr10,FPR_WIDTH(r4)
	stfdu	fr11,FPR_WIDTH(r4)
	stfdu	fr12,FPR_WIDTH(r4)
	stfdu	fr13,FPR_WIDTH(r4)
	stfdu	fr14,FPR_WIDTH(r4)
	stfdu	fr15,FPR_WIDTH(r4)
	stfdu	fr16,FPR_WIDTH(r4)
	stfdu	fr17,FPR_WIDTH(r4)
	stfdu	fr18,FPR_WIDTH(r4)
	stfdu	fr19,FPR_WIDTH(r4)
	stfdu	fr20,FPR_WIDTH(r4)
	stfdu	fr21,FPR_WIDTH(r4)
	stfdu	fr22,FPR_WIDTH(r4)
	stfdu	fr23,FPR_WIDTH(r4)
	stfdu	fr24,FPR_WIDTH(r4)
	stfdu	fr25,FPR_WIDTH(r4)
	stfdu	fr26,FPR_WIDTH(r4)
	stfdu	fr27,FPR_WIDTH(r4)
	stfdu	fr28,FPR_WIDTH(r4)
	stfdu	fr29,FPR_WIDTH(r4)
	stfdu	fr30,FPR_WIDTH(r4)
	stfdu	fr31,FPR_WIDTH(r4)
	mffs	fr0
	stfd	fr0,VCPU_fpscr(r3)
	blr

load_fp:
	lfd	fr0,VCPU_fpscr(r3)
	mtfsf	0xff,fr0

	addi	r4, r3, VCPU_fprs - FPR_WIDTH
	lfdu	fr0,FPR_WIDTH(r4)
	lfdu	fr1,FPR_WIDTH(r4)
	lfdu	fr2,FPR_WIDTH(r4)
	lfdu	fr3,FPR_WIDTH(r4)
	lfdu	fr4,FPR_WIDTH(r4)
	lfdu	fr5,FPR_WIDTH(r4)
	lfdu	fr6,FPR_WIDTH(r4)
	lfdu	fr7,FPR_WIDTH(r4)
	lfdu	fr8,FPR_WIDTH(r4)
	lfdu	fr9,FPR_WIDTH(r4)
	lfdu	fr10,FPR_WIDTH(r4)
	lfdu	fr11,FPR_WIDTH(r4)
	lfdu	fr12,FPR_WIDTH(r4)
	lfdu	fr13,FPR_WIDTH(r4)
	lfdu	fr14,FPR_WIDTH(r4)
	lfdu	fr15,FPR_WIDTH(r4)
	lfdu	fr16,FPR_WIDTH(r4)
	lfdu	fr17,FPR_WIDTH(r4)
	lfdu	fr18,FPR_WIDTH(r4)
	lfdu	fr19,FPR_WIDTH(r4)
	lfdu	fr20,FPR_WIDTH(r4)
	lfdu	fr21,FPR_WIDTH(r4)
	lfdu	fr22,FPR_WIDTH(r4)
	lfdu	fr23,FPR_WIDTH(r4)
	lfdu	fr24,FPR_WIDTH(r4)
	lfdu	fr25,FPR_WIDTH(r4)
	lfdu	fr26,FPR_WIDTH(r4)
	lfdu	fr27,FPR_WIDTH(r4)
	lfdu	fr28,FPR_WIDTH(r4)
	lfdu	fr29,FPR_WIDTH(r4)
	lfdu	fr30,FPR_WIDTH(r4)
	lfdu	fr31,FPR_WIDTH(r4)
	blr
#endif /* HAS_FLOAT */

#ifdef HAS_VMX

#define VCPU_vr(n) (VCPU_vrs + ((n) * 16))

/*
 * We cannot rely on the domain to correctly use VRSAVE
 * so it is required that all VMX registers are saved and restored.
 */
save_vmx:
	mfspr	r0,SPRN_VRSAVE
	stw	r0,VCPU_vrsave(r3)

	addi r0,r3,VCPU_vr(0);	stvxl	vr0,0,r0
	addi r0,r3,VCPU_vr(1);	stvxl	vr1,0,r0
	addi r0,r3,VCPU_vr(2);	stvxl	vr2,0,r0
	addi r0,r3,VCPU_vr(3);	stvxl	vr3,0,r0
	addi r0,r3,VCPU_vr(4);	stvxl	vr4,0,r0
	addi r0,r3,VCPU_vr(5);	stvxl	vr5,0,r0
	addi r0,r3,VCPU_vr(6);	stvxl	vr6,0,r0
	addi r0,r3,VCPU_vr(7);	stvxl	vr7,0,r0
	addi r0,r3,VCPU_vr(8);	stvxl	vr8,0,r0

	/*
	 * By now vr0 should be pushed out so now is a good time to
	 * get the VRSCR which can take a long time and has no dependcies
	 * on the following operations.
	 */
	mfvscr	vr0
	addi r0,r3,VCPU_vscr ;	stvxl	vr0,0,r0

	addi r0,r3,VCPU_vr(9);	stvxl	vr9,0,r0
	addi r0,r3,VCPU_vr(10);	stvxl	vr10,0,r0
	addi r0,r3,VCPU_vr(11);	stvxl	vr11,0,r0
	addi r0,r3,VCPU_vr(12);	stvxl	vr12,0,r0
	addi r0,r3,VCPU_vr(13);	stvxl	vr13,0,r0
	addi r0,r3,VCPU_vr(14);	stvxl	vr14,0,r0
	addi r0,r3,VCPU_vr(15);	stvxl	vr15,0,r0
	addi r0,r3,VCPU_vr(16);	stvxl	vr16,0,r0
	addi r0,r3,VCPU_vr(17);	stvxl	vr17,0,r0
	addi r0,r3,VCPU_vr(18);	stvxl	vr18,0,r0
	addi r0,r3,VCPU_vr(19);	stvxl	vr19,0,r0
	addi r0,r3,VCPU_vr(20);	stvxl	vr20,0,r0
	addi r0,r3,VCPU_vr(21);	stvxl	vr21,0,r0
	addi r0,r3,VCPU_vr(22);	stvxl	vr22,0,r0
	addi r0,r3,VCPU_vr(23);	stvxl	vr23,0,r0
	addi r0,r3,VCPU_vr(24);	stvxl	vr24,0,r0
	addi r0,r3,VCPU_vr(25);	stvxl	vr25,0,r0
	addi r0,r3,VCPU_vr(26);	stvxl	vr26,0,r0
	addi r0,r3,VCPU_vr(27);	stvxl	vr27,0,r0
	addi r0,r3,VCPU_vr(28);	stvxl	vr28,0,r0
	addi r0,r3,VCPU_vr(29);	stvxl	vr29,0,r0
	addi r0,r3,VCPU_vr(30);	stvxl	vr30,0,r0
	addi r0,r3,VCPU_vr(31);	stvxl	vr31,0,r0
	blr

load_vmx:
	lwz	r0,VCPU_vrsave(r3)
	mtspr	SPRN_VRSAVE,r0

	/*
	 * This operation can take a long time so we use vr31 to
	 * eliminate the depency on r0 for the next load
	 */
	addi r0,r3,VCPU_vscr ;	lvxl	vr31,0,r0
	mtvscr	vr31

	addi r0,r3,VCPU_vr(0);	lvxl	vr0,0,r0
	addi r0,r3,VCPU_vr(1);	lvxl	vr1,0,r0
	addi r0,r3,VCPU_vr(2);	lvxl	vr2,0,r0
	addi r0,r3,VCPU_vr(3);	lvxl	vr3,0,r0
	addi r0,r3,VCPU_vr(4);	lvxl	vr4,0,r0
	addi r0,r3,VCPU_vr(5);	lvxl	vr5,0,r0
	addi r0,r3,VCPU_vr(6);	lvxl	vr6,0,r0
	addi r0,r3,VCPU_vr(7);	lvxl	vr7,0,r0
	addi r0,r3,VCPU_vr(8);	lvxl	vr8,0,r0
	addi r0,r3,VCPU_vr(9);	lvxl	vr9,0,r0
	addi r0,r3,VCPU_vr(10);	lvxl	vr10,0,r0
	addi r0,r3,VCPU_vr(11);	lvxl	vr11,0,r0
	addi r0,r3,VCPU_vr(12);	lvxl	vr12,0,r0
	addi r0,r3,VCPU_vr(13);	lvxl	vr13,0,r0
	addi r0,r3,VCPU_vr(14);	lvxl	vr14,0,r0
	addi r0,r3,VCPU_vr(15);	lvxl	vr15,0,r0
	addi r0,r3,VCPU_vr(16);	lvxl	vr16,0,r0
	addi r0,r3,VCPU_vr(17);	lvxl	vr17,0,r0
	addi r0,r3,VCPU_vr(18);	lvxl	vr18,0,r0
	addi r0,r3,VCPU_vr(19);	lvxl	vr19,0,r0
	addi r0,r3,VCPU_vr(20);	lvxl	vr20,0,r0
	addi r0,r3,VCPU_vr(21);	lvxl	vr21,0,r0
	addi r0,r3,VCPU_vr(22);	lvxl	vr22,0,r0
	addi r0,r3,VCPU_vr(23);	lvxl	vr23,0,r0
	addi r0,r3,VCPU_vr(24);	lvxl	vr24,0,r0
	addi r0,r3,VCPU_vr(25);	lvxl	vr25,0,r0
	addi r0,r3,VCPU_vr(26);	lvxl	vr26,0,r0
	addi r0,r3,VCPU_vr(27);	lvxl	vr27,0,r0
	addi r0,r3,VCPU_vr(28);	lvxl	vr28,0,r0
	addi r0,r3,VCPU_vr(29);	lvxl	vr29,0,r0
	addi r0,r3,VCPU_vr(30);	lvxl	vr30,0,r0
	addi r0,r3,VCPU_vr(31);	lvxl	vr31,0,r0
	blr
#endif /* HAS_VMX */

/* void save_float(struct exec_domain *ed) */
_GLOBAL(save_float)
	mflr	r8
#ifdef HAS_FLOAT
	mfmsr	r9		# save msr
	ori	r0,r9,MSR_FP	# turn on FPU
	mtmsr	r0
	bl	save_fp		# uses r3, r4
	mtmsr	r9		# restore msr
#endif /* HAS_FLOAT */
#ifdef HAS_VMX
	mfmsr	r9		# save msr
	oris	r0,r9,MSR_VMX@h	# turn on VMX
	mtmsr	r0
	bl	save_vmx	# uses r3
	mtmsr	r9		# restore msr
#endif /* HAS_VMX */
	mtlr	r8
	blr

/* void load_float(struct exec_domain *ed) */
_GLOBAL(load_float)
	mflr	r8
#ifdef HAS_FLOAT
	mfmsr	r9		# save msr
	ori	r0,r9,MSR_FP	# turn on FPU
	mtmsr	r0
	bl	load_fp	# uses r3, r4
	mtmsr	r9		# restore msr
#endif /* HAS_FLOAT */
#ifdef HAS_VMX
	mfmsr	r9		# save msr
	oris	r0,r9,MSR_VMX@h	# turn on VMX
	mtmsr	r0
	bl	load_vmx	# uses r3
	mtmsr	r9		# restore msr
#endif /* HAS_VMX */
	mtlr	r8
	blr
