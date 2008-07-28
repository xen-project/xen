/*
 * arch/ia64/kernel/relocate_kernel.S
 *
 * Relocate kexec'able kernel and start it
 *
 * Copyright (C) 2005 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2005 Khalid Aziz  <khalid.aziz@hp.com>
 * Copyright (C) 2005 Intel Corp,  Zou Nan hai <nanhai.zou@intel.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
#include <asm/asmmacro.h>
#include <asm/kregs.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mca_asm.h>

/* relocate_new_kernel
 *
 * Do all the unpinning here, as the hypervisor has all the relevant
 * variables and constants. Then go into the reboot_code_buffer to
 * relocaate the new kernel and then branch into purgatory.
 *
 * Based on ia64_jump_to_sal
 *
 * in0: indirection_page
 * in1: start_address
 * in2: boot_param
 * in3: dom0_relocate_new_kernel
 */
GLOBAL_ENTRY(relocate_new_kernel)
	.prologue
	alloc r31=ar.pfs,4,0,4,0
	.body
	rsm psr.i  | psr.ic
{
	flushrs
	srlz.i
}
	movl r18=tlb_purge_done;;
	DATA_VA_TO_PA(r18);;
	mov b1=r18	// Return location
	movl r18=ia64_do_tlb_purge;;
	DATA_VA_TO_PA(r18);;
	mov b2=r18	// doing tlb_flush work
	mov ar.rsc=0	// Put RSE  in enforced lazy, LE mode
	movl r17=1f;;
	DATA_VA_TO_PA(r17);;
	mov cr.iip=r17
	movl r16=IA64_PSR_AC|IA64_PSR_BN|IA64_PSR_IC;;
	mov cr.ipsr=r16
	mov cr.ifs=r0;;
	rfi;;
1:
        /* Invalidate all TLB data/inst */
	br.sptk.many b2;; // jump to tlb purge code

tlb_purge_done:
	mov out0=in0	// out3 is ignored and thus can be garbage
	mov out1=in1
	mov out2=in2
	mov b1=in3
	;;
	br.sptk.many b1;; // jump to dom0-supplied relocate_new_kernel

	/* We should never get here */
END(relocate_new_kernel)

GLOBAL_ENTRY(ia64_dump_cpu_regs)
        .prologue
        alloc loc0=ar.pfs,1,2,0,0
        .body
        mov     ar.rsc=0                // put RSE in enforced lazy mode
        add     loc1=4*8, in0           // save r4 and r5 first
        ;;
{
        flushrs                         // flush dirty regs to backing store
        srlz.i
}
        st8 [loc1]=r4, 8
        ;;
        st8 [loc1]=r5, 8
        ;;
        add loc1=32*8, in0
        mov r4=ar.rnat
        ;;
        st8 [in0]=r0, 8			// r0
        st8 [loc1]=r4, 8		// rnat
        mov r5=pr
        ;;
        st8 [in0]=r1, 8			// r1
        st8 [loc1]=r5, 8		// pr
        mov r4=b0
        ;;
        st8 [in0]=r2, 8			// r2
        st8 [loc1]=r4, 8		// b0
        mov r5=b1;
        ;;
        st8 [in0]=r3, 24		// r3
        st8 [loc1]=r5, 8		// b1
        mov r4=b2
        ;;
        st8 [in0]=r6, 8			// r6
        st8 [loc1]=r4, 8		// b2
	mov r5=b3
        ;;
        st8 [in0]=r7, 8			// r7
        st8 [loc1]=r5, 8		// b3
        mov r4=b4
        ;;
        st8 [in0]=r8, 8			// r8
        st8 [loc1]=r4, 8		// b4
        mov r5=b5
        ;;
        st8 [in0]=r9, 8			// r9
        st8 [loc1]=r5, 8		// b5
        mov r4=b6
        ;;
        st8 [in0]=r10, 8		// r10
        st8 [loc1]=r5, 8		// b6
        mov r5=b7
        ;;
        st8 [in0]=r11, 8		// r11
        st8 [loc1]=r5, 8		// b7
        mov r4=b0
        ;;
        st8 [in0]=r12, 8		// r12
        st8 [loc1]=r4, 8		// ip
        mov r5=loc0
	;;
        st8 [in0]=r13, 8		// r13
        extr.u r5=r5, 0, 38		// ar.pfs.pfm
	mov r4=r0			// user mask
        ;;
        st8 [in0]=r14, 8		// r14
        st8 [loc1]=r5, 8		// cfm
        ;;
        st8 [in0]=r15, 8		// r15
        st8 [loc1]=r4, 8		// user mask
	mov r5=ar.rsc
        ;;
        st8 [in0]=r16, 8		// r16
        st8 [loc1]=r5, 8		// ar.rsc
        mov r4=ar.bsp
        ;;
        st8 [in0]=r17, 8		// r17
        st8 [loc1]=r4, 8		// ar.bsp
        mov r5=ar.bspstore
        ;;
        st8 [in0]=r18, 8		// r18
        st8 [loc1]=r5, 8		// ar.bspstore
        mov r4=ar.rnat
        ;;
        st8 [in0]=r19, 8		// r19
        st8 [loc1]=r4, 8		// ar.rnat
        mov r5=ar.ccv
        ;;
        st8 [in0]=r20, 8		// r20
	st8 [loc1]=r5, 8		// ar.ccv
        mov r4=ar.unat
        ;;
        st8 [in0]=r21, 8		// r21
        st8 [loc1]=r4, 8		// ar.unat
        mov r5 = ar.fpsr
        ;;
        st8 [in0]=r22, 8		// r22
        st8 [loc1]=r5, 8		// ar.fpsr
        mov r4 = ar.unat
        ;;
        st8 [in0]=r23, 8		// r23
        st8 [loc1]=r4, 8		// unat
        mov r5 = ar.fpsr
        ;;
        st8 [in0]=r24, 8		// r24
        st8 [loc1]=r5, 8		// fpsr
        mov r4 = ar.pfs
        ;;
        st8 [in0]=r25, 8		// r25
        st8 [loc1]=r4, 8		// ar.pfs
        mov r5 = ar.lc
        ;;
        st8 [in0]=r26, 8		// r26
        st8 [loc1]=r5, 8		// ar.lc
        mov r4 = ar.ec
        ;;
        st8 [in0]=r27, 8		// r27
        st8 [loc1]=r4, 8		// ar.ec
        mov r5 = ar.csd
        ;;
        st8 [in0]=r28, 8		// r28
        st8 [loc1]=r5, 8		// ar.csd
        mov r4 = ar.ssd
        ;;
        st8 [in0]=r29, 8		// r29
        st8 [loc1]=r4, 8		// ar.ssd
        ;;
        st8 [in0]=r30, 8		// r30
        ;;
	st8 [in0]=r31, 8		// r31
        mov ar.pfs=loc0
        ;;
        br.ret.sptk.many rp
END(ia64_dump_cpu_regs)


