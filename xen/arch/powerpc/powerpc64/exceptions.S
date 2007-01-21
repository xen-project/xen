/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */
 
#include <asm/config.h>
#include <asm/asm-offsets.h>
#include <asm/reg_defs.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/percpu.h>

.macro SAVE_GPR regno uregs
std \regno, (UREGS_gprs + GPR_WIDTH * \regno)(\uregs)
.endm

.macro SAVE_GPRS from to uregs
.ifge \to-\from
SAVE_GPR \from, \uregs
SAVE_GPRS "(\from+1)", \to, \uregs
.endif
.endm

.macro LOAD_GPR regno uregs
ld \regno, (UREGS_gprs + GPR_WIDTH * \regno)(\uregs)
.endm

.macro LOAD_GPRS from to uregs
.ifge \to-\from
LOAD_GPR \from, \uregs
LOAD_GPRS "(\from+1)", \to, \uregs
.endif
.endm

.macro GET_STACK parea srr1
    /* get processor area pointer and save off a couple registers there */
    mtspr SPRN_HSPRG1, \parea
    mfspr \parea, SPRN_HSPRG0
    std r1, PAREA_r1(\parea)
    mfcr r1
    std r1, PAREA_cr(\parea)
    mfspr r1, \srr1
    rldicl. r1, r1, 4, 63               /* test (H)SRR1:HV */
    /* assume we interrupted the guest, in which case we start at top of this
     * processsor's hypervisor stack (as found in parea). */
    ld r1, PAREA_stack(\parea)
    beq 1f
    /* nope, we interrupted the hypervisor. continue on that stack. */
    ld r1, PAREA_r1(\parea)
1:
.endm

/* SAVE_C_STATE: set up enough state to jump to C code
 * r14-r31 are non-volatile in the C ABI, so not saved here
 */
.macro SAVE_C_STATE uregs
    SAVE_GPRS r2, r12, \uregs       /* save r2-r12 */

    mflr r0
    std r0, UREGS_lr(\uregs)        /* save LR */
    mfxer r0
    std r0, UREGS_xer(\uregs)       /* save XER */
.endm

.macro LOAD_C_STATE uregs
    ld r0, UREGS_lr(\uregs)         /* load LR */
    mtlr r0
    ld r0, UREGS_xer(\uregs)       /* load XER */
    mtxer r0
    lwz r0, UREGS_cr(\uregs)        /* load CR */
    mtcr r0

    LOAD_GPRS r2, r12, \uregs       /* load r2-r12 */
.endm

.macro LOADADDR reg symbol
    lis \reg,\symbol@highest
    ori \reg,\reg,\symbol@higher
    rldicr \reg,\reg,32,31
    oris \reg,\reg,\symbol@h
    ori \reg,\reg,\symbol@l
.endm

.macro CALL_CFUNC reg
    ld r2, 8(\reg) /* load function's TOC value */
    ld \reg, 0(\reg)
    mtctr \reg
    bctrl
    nop
.endm

.macro EXCEPTION_HEAD parea continue
    /* make room for cpu_user_regs */
    subi r1, r1, STACK_VOLATILE_AREA + UREGS_sizeof

    /* get all we need from the processor_area */
    std r0, UREGS_r0(r1)            /* get scratch register */
    ld r0, PAREA_r1(\parea)
    std r0, UREGS_r1(r1)            /* save R1 */
    ld r0, PAREA_cr(\parea)
    stw r0, UREGS_cr(r1)            /* save CR */
    mfspr r0, SPRN_HSPRG1
    std r0, UREGS_r13(r1)           /* save R13 from HSPRG1 */

    /* Only _one_ larx is allowed at a time.  Any future use will be
     * rejected until the earlier one (if any) completes.  Since we
     * may have interrupted a larx in the Domain, or Xen we need to
     * clear any larx that may currently exist.  We could probably
     * skip which for hcalls */
    ldx r0, 0, r1
    stdcx. r0, 0, r1

    /* save CTR and use it to jump */
    mfctr r0
    std r0, UREGS_ctr(r1)
    LOADADDR r0, \continue
    mtctr r0
.endm

/* For normal exceptions. */
.macro EXCEPTION_SAVE_STATE uregs
    SAVE_C_STATE \uregs

    /* save DEC */
    mfdec r0
    ld r3, PAREA_vcpu(r13)
    stw r0, VCPU_dec(r3)

    /* save PC, MSR */
    mfspr r0, SPRN_SRR0
    std r0, UREGS_pc(\uregs)
    mfspr r0, SPRN_SRR1
    std r0, UREGS_msr(\uregs)
    li r0, -1 /* we clobbered the OS's SRR0/SRR1 to get here. */
    std r0, UREGS_srr0(\uregs)
    std r0, UREGS_srr1(\uregs)

    /* done with processor_area; re-enable MSR:RI */ 
    mfmsr r0
    ori r0, r0, MSR_RI@l
    mtmsrd r0


.endm

/* For exceptions that use HSRR0/1 (preserving the OS's SRR0/1). */
.macro H_EXCEPTION_SAVE_STATE uregs
    SAVE_C_STATE \uregs

    /* save DEC */
    mfdec r0
    ld r3, PAREA_vcpu(r13)
    stw r0, VCPU_dec(r3)

    /* save PC, MSR */
    mfspr r0, SPRN_HSRR0
    std r0, UREGS_pc(\uregs)
    mfspr r0, SPRN_HSRR1
    std r0, UREGS_msr(\uregs)
    mfspr r0, SPRN_SRR0
    std r0, UREGS_srr0(\uregs)
    mfspr r0, SPRN_SRR1
    std r0, UREGS_srr1(\uregs)

    /* done with processor_area; re-enable MSR:RI */ 
    mfmsr r0
    ori r0, r0, MSR_RI@l
    mtmsrd r0

.endm

/* Hypervisor exception handling code; copied to physical address zero. */
    .align 3
    .globl exception_vectors
exception_vectors:

    . = 0x0 # wild branch to 0
zero:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x0 /* exception vector for GDB stub */
    bctr

    /* The following byte array is where any per-CPU state flags 
     * that can be be used across interrupts.  Currently it is only used
     * to track Cache Inhibited Mode when a Machine Check occurs. */
     /* NOTE: This array is indexed by PIR NOT CPUID */
    . = MCK_CPU_STAT_BASE
    .space NR_CPUS
    . = MCK_GOOD_HID4
    .quad 0        
    . = 0x100 # System Reset
ex_reset:
    /* XXX thread initialization */
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x100 /* exception vector for GDB stub */
    bctr

    . = 0x200 # Machine Check
ex_machcheck:
    /* Restore HID4 to a known state early, we do not recover from
     * machine check yet, but when we do we shoul dbe able to restore
     * HID4 to it proper value */
    mtspr SPRN_HSPRG1, r13
    ld r13, MCK_GOOD_HID4(0)
    sync
    mtspr SPRN_HID4, r13
    isync
    /* Hopefully we don't have to worry about the ERAT */
    mfspr r13, SPRN_HSPRG1
    /* and now back to our regularly schedualed program */
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_machcheck_continued
    li r0, 0x200 /* exception vector for GDB stub */
    bctr

    . = 0x300
ex_dsi:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x300 /* exception vector for GDB stub */
    bctr

    . = 0x380
ex_data_slb:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x380 /* exception vector for GDB stub */
    bctr

    . = 0x400
ex_isi:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x400 /* exception vector for GDB stub */
    bctr

    . = 0x480
ex_inst_slb:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x480 /* exception vector for GDB stub */
    bctr

    . = 0x500
ex_external:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_external_continued
    bctr

    . = 0x600
ex_alignment:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x600 /* exception vector for GDB stub */
    bctr

    . = 0x700
ex_program:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x700 /* exception vector for GDB stub */
    bctr

    . = 0x800
ex_float:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0x800 /* exception vector for GDB stub */
    bctr

    . = 0x900
ex_dec:
    /* delivered to hypervisor when MSR:EE is set... */
#ifdef SLOW_TRAP
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_dec_continued
    bctr
#else
    /* XXX for now just reset DEC and return */
    mtspr SPRN_HSPRG1, r3
    lis r3, 0x7fff
    mtdec r3
    mfspr r3, SPRN_HSPRG1
    rfid
#endif

    . = 0x980
ex_hdec:
    GET_STACK r13 SPRN_HSRR1
    EXCEPTION_HEAD r13 ex_hdec_continued
    bctr

    . = 0xc00
ex_syscall:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_hcall_continued
    bctr

    . = 0xd00
ex_trace:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0xd00 /* exception vector for GDB stub */
    bctr

    . = 0xe00
ex_fp:
    GET_STACK r13 SPRN_SRR1
    EXCEPTION_HEAD r13 ex_program_continued
    li r0, 0xe00 /* exception vector for GDB stub */
    bctr

    .align 3
    .globl exception_vectors_end

exception_vectors_end:
    /* put some stuff here so we see the next symbol */
    .long 0xdeadbeef
    .long 0xdeadbeef

.macro FAST_RESUME
    LOAD_C_STATE r1                     /* restore most C volatiles */

    ld r0, UREGS_ctr(r1)
    mtctr r0

    /* clear MSR:RI/EE to set SRR0/SRR1 */
    li r0, 0
    mtmsrd r0, 1

    ld r0, UREGS_pc(r1)
    mtspr SPRN_HSRR0, r0
    ld r0, UREGS_msr(r1)
    mtspr SPRN_HSRR1, r0

    ld r0, UREGS_srr0(r1)
    mtspr SPRN_SRR0, r0
    ld r0, UREGS_srr1(r1)
    mtspr SPRN_SRR1, r0

    ld r13, UREGS_r13(r1)
    ld r0, UREGS_r0(r1)
    ld r1, UREGS_r1(r1)
    HRFID
    b .                         /* prevent speculative icache fetch */
.endm

/* Not a whole lot just yet */
ex_machcheck_continued:


/* We enter with the exception number in r0. The EXCEPTION_SAVE_STATE macro
 * clobbers r0 though, so we have to move it around a little bit. Not ideal,
 * but hopefully program exception is not performance-critical... Maybe there's
 * a better way, but this works for now. */
ex_program_continued:
    SAVE_GPRS r14, r31, r1              /* save all the non-volatiles */

    /* save these for debug, no needed for restore */
    mfspr r14, SPRN_HID4
    std r14, UREGS_hid4(r1)
    mfdar r14
    std r14, UREGS_dar(r1)
    mfdsisr r14
    stw r14, UREGS_dsisr(r1)

    mr r14, r0
    EXCEPTION_SAVE_STATE r1
    mr r4, r14
    LOADADDR r12, program_exception
    mr r3, r1                           /* pass pointer to cpu_user_regs */
    subi r1, r1, STACK_FRAME_OVERHEAD   /* make a "caller" stack frame */
    CALL_CFUNC r12

    /* reload state and rfid */
    addi r1, r1, STACK_FRAME_OVERHEAD   /* restore stack to cpu_user_regs */
    LOAD_GPRS r14, r31, r1
    FAST_RESUME

ex_external_continued:
    EXCEPTION_SAVE_STATE r1
    LOADADDR r12, do_external
    mr r3, r1                           /* pass pointer to cpu_user_regs */
    subi r1, r1, STACK_FRAME_OVERHEAD   /* make a "caller" stack frame */
    CALL_CFUNC r12

    addi r1, r1, STACK_FRAME_OVERHEAD   /* restore stack to cpu_user_regs */
    b fast_resume

ex_hcall_continued:
    /* We have to save the non-volatiles here in case of a block hcall (which
     * will end up in context_switch()). */
    SAVE_GPRS r14, r31, r1
    EXCEPTION_SAVE_STATE r1
    LOADADDR r12, do_hcall
    mr r3, r1                           /* pass pointer to cpu_user_regs */
    subi r1, r1, STACK_FRAME_OVERHEAD   /* make a "caller" stack frame */
    CALL_CFUNC r12                      /* call hcall handler */

    /* test for pending softirqs, and loop until there are no more. */
    mfmsr r14
    ori r14, r14, MSR_EE
    xori r15, r14, MSR_EE

hcall_test_all_events:
    mtmsrd r15, 1                       /* disable interrupts */
    ld r3, PAREA_vcpu(r13)
    lwz r3, VCPU_processor(r3)
    LOADADDR r4, irq_stat
    sldi r3, r3, IRQSTAT_shift
    add r4, r3, r4
    ld r5, IRQSTAT_pending(r4)
    cmpldi r5, 0
    beq hcall_out                       /* no more softirqs; exit loop */

    LOADADDR r6, do_softirq
    mtmsrd r14, 1                       /* enable interrupts */
    CALL_CFUNC r6                       /* process softirqs */
    b hcall_test_all_events             /* look for more */

hcall_out:
    addi r1, r1, STACK_FRAME_OVERHEAD   /* restore stack to cpu_user_regs */
    LOAD_GPRS r14, r15, r1              /* we clobbered r14/r15 */
    b fast_resume


ex_dec_continued:
    EXCEPTION_SAVE_STATE r1
    LOADADDR r12, do_dec
    mr r3, r1                           /* pass pointer to cpu_user_regs */
    subi r1, r1, STACK_FRAME_OVERHEAD   /* make a "caller" stack frame */
    CALL_CFUNC r12

    addi r1, r1, STACK_FRAME_OVERHEAD   /* restore stack to cpu_user_regs */
    b fast_resume

ex_hdec_continued:
    /* When we get an HDEC, we (almost?) always context_switch, so we need to
     * save the nonvolatiles.  */
    SAVE_GPRS r14, r31, r1
    H_EXCEPTION_SAVE_STATE r1

    LOADADDR r12, do_timer
    mr r3, r1
    subi r1, r1, STACK_FRAME_OVERHEAD   /* make a "caller" stack frame */
    CALL_CFUNC r12

    /* if we are resuming into hypervisor, don't handle softirqs */
    ld r10, (UREGS_msr + STACK_FRAME_OVERHEAD)(r1)
    rldicl. r11, r10, 4, 63             /* test SRR1:HV */
    bne hdec_out

    /* test for pending softirqs, and loop until there are no more. */
    mfmsr r14
    ori r14, r14, MSR_EE
    xori r15, r14, MSR_EE
test_all_events:
    mtmsrd r15, 1                       /* disable interrupts */
    ld r3, PAREA_vcpu(r13)
    lwz r3, VCPU_processor(r3)
    LOADADDR r4, irq_stat
    sldi r3, r3, IRQSTAT_shift
    add r4, r3, r4
    ld r5, IRQSTAT_pending(r4)
    cmpldi r5, 0
    beq hdec_out                        /* no more softirqs; exit loop */

    LOADADDR r6, do_softirq
    mtmsrd r14, 1                       /* enable interrupts */
    CALL_CFUNC r6                       /* process softirqs */
    b test_all_events                   /* look for more */

hdec_out:
    addi r1, r1, STACK_FRAME_OVERHEAD   /* restore stack to cpu_user_regs */
    LOAD_GPRS r14, r15, r1              /* we clobbered r14/r15 in the loop */

/* r1 points to the to-be-restored cpu_user_regs. These could be mid-hypervisor
 * stack (returning into elsewhere in Xen) or at the top of the stack
 * (restoring the domain). */
_GLOBAL(full_resume)
    /* disable MSR:EE, since we could have come from do_softirq() */
    mfmsr r7
    ori r7, r7, MSR_EE
    xori r7, r7, MSR_EE
    mtmsrd r7, 1

    LOAD_GPRS r14, r31, r1              /* restore all non-volatiles */

fast_resume:
    ld r10, UREGS_msr(r1)
    rldicl. r11, r10, 4, 63             /* test SRR1:HV */
    bne 1f                              /* returning to hypervisor */

    /* check for pending irqs */
    mr r3, r1
    subi r1, r1, STACK_FRAME_OVERHEAD
    bl .deliver_ee
    addi r1, r1, STACK_FRAME_OVERHEAD

    /* if we took a DEC in hypervisor mode, we don't want to reload the DEC
     * until we return to the domain. MSR_EE is clear, so the domain will take
     * any impending DEC. */
    ld r3, PAREA_vcpu(r13)
    lwz r0, VCPU_dec(r3)
    mtdec r0

1:
    FAST_RESUME
    /* not reached */

/* move all of the below somewhere else */

_GLOBAL(papr_hcall_jump)
    mtctr r4
    bctr
    /* return to caller via LR */

/* XXX don't need to load all the registers */
_GLOBAL(xen_hvcall_jump)
    mtctr r4
    ld r10, (UREGS_gprs + GPR_WIDTH * 11)(r3)
    ld r9, (UREGS_gprs + GPR_WIDTH * 10)(r3)
    ld r8, (UREGS_gprs + GPR_WIDTH * 9)(r3)
    ld r7, (UREGS_gprs + GPR_WIDTH * 8)(r3)
    ld r6, (UREGS_gprs + GPR_WIDTH * 7)(r3)
    ld r5, (UREGS_gprs + GPR_WIDTH * 6)(r3)
    ld r4, (UREGS_gprs + GPR_WIDTH * 5)(r3)
    ld r3, (UREGS_gprs + GPR_WIDTH * 4)(r3)
    bctr

_GLOBAL(_reset_stack_and_jump)
    ld r2, 8(r3)
    ld r3, 0(r3)
    mtctr r3
    mr r1, r4
    bctr

_GLOBAL(sleep)
    mfmsr r3
    ori r4, r3, MSR_EE
    oris r4, r4, MSR_POW@h
    sync
    mtmsrd r4
    isync
    mtmsrd r3
    blr

/* The primary processor issues a firmware call to spin us up at this
 * address, passing our CPU number in r3.  We only need a function
 * entry point instead of a descriptor since this is never called from
 * C code.
 */	
    .globl spin_start
spin_start:
    /* We discovered by experiment that the ERAT must be flushed early.  */
    isync
    slbia
    isync
	
    /* Do a cache flush for our text, in case the loader didn't */
    LOADADDR(r9, _start)
    LOADADDR(r8, _etext)
4:  dcbf r0,r9
    icbi r0,r9
    addi r9,r9,0x20		/* up to a 4 way set per line */
    cmpld cr0,r9,r8
    blt	4b
    sync
    isync

    /* Write our processor number as an acknowledgment that we're alive.  */
    LOADADDR(r14, __spin_ack)
    stw r3, 0(r14)
    sync
    /* If NR_CPUS is too small, we should just spin forever.  */
    LOADADDR(r15, NR_CPUS)
    cmpd r3, r15
    blt 2f	
    b .
    /* Find our index in the array of processor_area struct pointers.  */
2:  LOADADDR(r14, global_cpu_table)
    mulli r15, r3, 8
    add r14, r14, r15
    /* Spin until the pointer for our processor goes valid.  */
1:  ld r15, 0(r14)
    cmpldi r15, 0
    beq 1b
    /* Dereference the pointer and load our stack pointer.  */
    isync
    ld r1, PAREA_stack(r15)
    li r14, STACK_FRAME_OVERHEAD
    sub r1, r1, r14
    /* Load up the TOC and entry point for the C function to be called.  */
    LOADADDR(r14, secondary_cpu_init)
    ld r2, 8(r14)
    ld r11, 0(r14)
    mtctr r11
    /* Warning: why do we need this synchronizing instruction on 970FX?  */
    isync
    /* Jump into C code now.  */
    bctrl
    nop
    b .
