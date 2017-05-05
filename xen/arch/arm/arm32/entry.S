#include <xen/config.h>
#include <asm/asm_defns.h>
#include <asm/regs.h>
#include <public/xen.h>

#define SAVE_ONE_BANKED(reg)    mrs r11, reg; str r11, [sp, #UREGS_##reg]
#define RESTORE_ONE_BANKED(reg) ldr r11, [sp, #UREGS_##reg]; msr reg, r11

#define SAVE_BANKED(mode) \
        SAVE_ONE_BANKED(SP_##mode) ; SAVE_ONE_BANKED(LR_##mode) ; SAVE_ONE_BANKED(SPSR_##mode)

#define RESTORE_BANKED(mode) \
        RESTORE_ONE_BANKED(SP_##mode) ; RESTORE_ONE_BANKED(LR_##mode) ; RESTORE_ONE_BANKED(SPSR_##mode)

#define SAVE_ALL                                                        \
        sub sp, #(UREGS_SP_usr - UREGS_sp); /* SP, LR, SPSR, PC */      \
        push {r0-r12}; /* Save R0-R12 */                                \
                                                                        \
        mrs r11, ELR_hyp;               /* ELR_hyp is return address. */\
        str r11, [sp, #UREGS_pc];                                       \
                                                                        \
        str lr, [sp, #UREGS_lr];                                        \
                                                                        \
        add r11, sp, #UREGS_kernel_sizeof+4;                            \
        str r11, [sp, #UREGS_sp];                                       \
                                                                        \
        mrc CP32(r11, HSR);             /* Save exception syndrome */   \
        str r11, [sp, #UREGS_hsr];                                      \
                                                                        \
        mrs r11, SPSR_hyp;                                              \
        str r11, [sp, #UREGS_cpsr];                                     \
        and r11, #PSR_MODE_MASK;                                        \
        cmp r11, #PSR_MODE_HYP;                                         \
        blne save_guest_regs

save_guest_regs:
        ldr r11, =0xffffffff  /* Clobber SP which is only valid for hypervisor frames. */
        str r11, [sp, #UREGS_sp]
        SAVE_ONE_BANKED(SP_usr)
        /* LR_usr is the same physical register as lr and is saved in SAVE_ALL */
        SAVE_BANKED(svc)
        SAVE_BANKED(abt)
        SAVE_BANKED(und)
        SAVE_BANKED(irq)
        SAVE_BANKED(fiq)
        SAVE_ONE_BANKED(R8_fiq); SAVE_ONE_BANKED(R9_fiq); SAVE_ONE_BANKED(R10_fiq)
        SAVE_ONE_BANKED(R11_fiq); SAVE_ONE_BANKED(R12_fiq);
        /*
         * Start to check pending virtual abort in the gap of Guest -> HYP
         * world switch.
         *
         * Save ELR_hyp to check whether the pending virtual abort exception
         * takes place while we are doing this trap exception.
         */
        mrs r1, ELR_hyp

        /*
         * Force loads and stores to complete before unmasking asynchronous
         * aborts and forcing the delivery of the exception.
         */
        dsb sy

        /*
         * Unmask asynchronous abort bit. If there is a pending asynchronous
         * abort, the data_abort exception will happen after A bit is cleared.
         */
        cpsie a

        /*
         * This is our single instruction exception window. A pending
         * asynchronous abort is guaranteed to occur at the earliest when we
         * unmask it, and at the latest just after the ISB.
         *
         * If a pending abort occurs, the program will jump to data_abort
         * exception handler, and the ELR_hyp will be set to
         * abort_guest_exit_start or abort_guest_exit_end.
         */
        .global abort_guest_exit_start
abort_guest_exit_start:

        isb

        .global abort_guest_exit_end
abort_guest_exit_end:
        /* Mask CPSR asynchronous abort bit, close the checking window. */
        cpsid a

        /*
         * Compare ELR_hyp and the saved value to check whether we are
         * returning from a valid exception caused by pending virtual
         * abort.
         */
        mrs r2, ELR_hyp
        cmp r1, r2

        /*
         * Not equal, the pending virtual abort exception took place, the
         * initial exception does not have any significance to be handled.
         * Exit ASAP.
         */
        bne return_from_trap

        mov pc, lr

#define DEFINE_TRAP_ENTRY(trap)                                         \
        ALIGN;                                                          \
trap_##trap:                                                            \
        SAVE_ALL;                                                       \
        cpsie i;        /* local_irq_enable */                          \
        adr lr, return_from_trap;                                       \
        mov r0, sp;                                                     \
        mov r11, sp;                                                    \
        bic sp, #7; /* Align the stack pointer (noop on guest trap) */  \
        b do_trap_##trap

#define DEFINE_TRAP_ENTRY_NOIRQ(trap)                                   \
        ALIGN;                                                          \
trap_##trap:                                                            \
        SAVE_ALL;                                                       \
        adr lr, return_from_trap;                                       \
        mov r0, sp;                                                     \
        mov r11, sp;                                                    \
        bic sp, #7; /* Align the stack pointer (noop on guest trap) */  \
        b do_trap_##trap

        .align 5
GLOBAL(hyp_traps_vector)
        .word 0                         /* 0x00 - Reset */
        b trap_undefined_instruction    /* 0x04 - Undefined Instruction */
        b trap_supervisor_call          /* 0x08 - Supervisor Call */
        b trap_prefetch_abort           /* 0x0c - Prefetch Abort */
        b trap_data_abort               /* 0x10 - Data Abort */
        b trap_guest_sync               /* 0x14 - Hypervisor */
        b trap_irq                      /* 0x18 - IRQ */
        b trap_fiq                      /* 0x1c - FIQ */

DEFINE_TRAP_ENTRY(undefined_instruction)
DEFINE_TRAP_ENTRY(supervisor_call)
DEFINE_TRAP_ENTRY(prefetch_abort)
DEFINE_TRAP_ENTRY(data_abort)
DEFINE_TRAP_ENTRY(guest_sync)
DEFINE_TRAP_ENTRY_NOIRQ(irq)
DEFINE_TRAP_ENTRY_NOIRQ(fiq)

return_from_trap:
        mov sp, r11
ENTRY(return_to_new_vcpu32)
        ldr r11, [sp, #UREGS_cpsr]
        and r11, #PSR_MODE_MASK
        cmp r11, #PSR_MODE_HYP
        beq return_to_hypervisor
        /* Fall thru */
return_to_guest:
        mov r11, sp
        bic sp, #7 /* Align the stack pointer */
        bl leave_hypervisor_tail /* Disables interrupts on return */
        mov sp, r11
        RESTORE_ONE_BANKED(SP_usr)
        /* LR_usr is the same physical register as lr and is restored below */
        RESTORE_BANKED(svc)
        RESTORE_BANKED(abt)
        RESTORE_BANKED(und)
        RESTORE_BANKED(irq)
        RESTORE_BANKED(fiq)
        RESTORE_ONE_BANKED(R8_fiq); RESTORE_ONE_BANKED(R9_fiq); RESTORE_ONE_BANKED(R10_fiq)
        RESTORE_ONE_BANKED(R11_fiq); RESTORE_ONE_BANKED(R12_fiq);
        /* Fall thru */
return_to_hypervisor:
        cpsid i
        ldr lr, [sp, #UREGS_lr]
        ldr r11, [sp, #UREGS_pc]
        msr ELR_hyp, r11
        ldr r11, [sp, #UREGS_cpsr]
        msr SPSR_hyp, r11
        pop {r0-r12}
        add sp, #(UREGS_SP_usr - UREGS_sp); /* SP, LR, SPSR, PC */
        clrex
        eret

/*
 * struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next)
 *
 * r0 - prev
 * r1 - next
 *
 * Returns prev in r0
 */
ENTRY(__context_switch)
        add     ip, r0, #VCPU_arch_saved_context
        stmia   ip!, {r4 - sl, fp, sp, lr}      /* Save register state */

        add     r4, r1, #VCPU_arch_saved_context
        ldmia   r4, {r4 - sl, fp, sp, pc}       /* Load registers and return */

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
