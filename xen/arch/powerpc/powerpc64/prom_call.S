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
 *
 */
#include <asm/config.h>
#include <asm/processor.h>
	
	.macro save_gprs rsave, rend, off, rbase
	std \rsave, \off(\rbase)
	.if \rend-\rsave
	save_gprs "(\rsave+1)",\rend,"(\off+8)",\rbase
	.endif
	.endm

	.macro restore_gprs rsave, rend, off, rbase
	ld \rsave, \off(\rbase)
	.if \rend-\rsave
	restore_gprs "(\rsave+1)",\rend,"(\off+8)",\rbase
	.endif
	.endm

/*
 * s32 prom_call(void *arg, ulong base, ulong func, ulong msr);
 * r3 is arg pointer	
 * r4 is RTAS base, should be 0 for OF
 * r5 is Prom vector
 * r6 is the MSR we should use
 */
_GLOBAL(prom_call)
	SET_REG_TO_LABEL(r7, gpr_store)

	std r1, 0(r7)
	std r2, 8(r7)
	SAVE_GPRS r13, r31, 16, r7 # save all volatiles

	/* 
	 * We can stuff the LT, MSR, SRR0/1 into GPRS that the caller
	 * must retore
	 */
	
	mflr    r18
	sradi	r19, r18, 32		/* store lr in r18, r19 */

	mfmsr   r20
	sradi	r21, r20, 32		/* r20,r21 contain caller's msr */

	/* save SRR0/1 */
	mfsrr0	r24
	sradi	r25, r24, 32
	mfsrr1	r26
	sradi	r27, r26, 32

	bl	go_to_real

	/* come back here after rfid in "native_of_call" */
	insrdi	r18, r19, 32, 0		/* restore lr */
	mtlr	r18			

	/* restore SRR0/1 */
	insrdi	r24, r25, 32, 0
	mtsrr0	r24
	insrdi	r26, r27, 32, 0
	mtsrr1	r26


	
	SET_REG_TO_LABEL(r7, gpr_store)

	ld r1, 0(r7)
	ld r2, 8(r7)
	RESTORE_GPRS r13, r31, 16, r7
	blr
		
native_call:	
	mtctr	r5
	bctrl				/* call of or rtas */

	insrdi	r22, r23, 32, 0		/* reconstruct return point iar */
	insrdi	r20, r21, 32, 0		/* reconstruct caller's msr */

	mtsrr0	r22
	mtsrr1	r20
	rfid


go_to_real:
	mflr	r22
	sradi	r23, r22, 32		/* save address we rfid back to*/

	SET_REG_TO_LABEL(r8, native_call)

	mtsrr0	r8
	mtsrr1	r6
	rfid

			
	.data
	.p2align 3
gpr_store:
	.space 8		# r1
	.space 8		# r2
	.space (32 - 13) * 8	# r13 - r31
