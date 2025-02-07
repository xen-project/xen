/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 Vates
 *
 * RISC-V Trap handlers
 */

#include <xen/bug.h>
#include <xen/compiler.h>
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/sched.h>

#include <asm/processor.h>
#include <asm/riscv_encoding.h>
#include <asm/traps.h>

/*
 * Initialize the trap handling.
 *
 * The function is called after MMU is enabled.
 */
void trap_init(void)
{
    unsigned long addr = (unsigned long)&handle_trap;

    csr_write(CSR_STVEC, addr);
}

static const char *decode_trap_cause(unsigned long cause)
{
    static const char *const trap_causes[] = {
        [CAUSE_MISALIGNED_FETCH] = "Instruction Address Misaligned",
        [CAUSE_FETCH_ACCESS] = "Instruction Access Fault",
        [CAUSE_ILLEGAL_INSTRUCTION] = "Illegal Instruction",
        [CAUSE_BREAKPOINT] = "Breakpoint",
        [CAUSE_MISALIGNED_LOAD] = "Load Address Misaligned",
        [CAUSE_LOAD_ACCESS] = "Load Access Fault",
        [CAUSE_MISALIGNED_STORE] = "Store/AMO Address Misaligned",
        [CAUSE_STORE_ACCESS] = "Store/AMO Access Fault",
        [CAUSE_USER_ECALL] = "Environment Call from U-Mode",
        [CAUSE_SUPERVISOR_ECALL] = "Environment Call from S-Mode",
        [CAUSE_MACHINE_ECALL] = "Environment Call from M-Mode",
        [CAUSE_FETCH_PAGE_FAULT] = "Instruction Page Fault",
        [CAUSE_LOAD_PAGE_FAULT] = "Load Page Fault",
        [CAUSE_STORE_PAGE_FAULT] = "Store/AMO Page Fault",
        [CAUSE_FETCH_GUEST_PAGE_FAULT] = "Instruction Guest Page Fault",
        [CAUSE_LOAD_GUEST_PAGE_FAULT] = "Load Guest Page Fault",
        [CAUSE_VIRTUAL_INST_FAULT] = "Virtualized Instruction Fault",
        [CAUSE_STORE_GUEST_PAGE_FAULT] = "Guest Store/AMO Page Fault",
    };

    const char *res = cause < ARRAY_SIZE(trap_causes)
                      ? array_access_nospec(trap_causes, cause)
                      : NULL;

    return res ?: "UNKNOWN";
}

static const char *decode_reserved_interrupt_cause(unsigned long irq_cause)
{
    switch ( irq_cause )
    {
    case IRQ_M_SOFT:
        return "M-mode Software Interrupt";
    case IRQ_M_TIMER:
        return "M-mode Timer Interrupt";
    case IRQ_M_EXT:
        return "M-mode External Interrupt";
    default:
        return "UNKNOWN IRQ type";
    }
}

static const char *decode_interrupt_cause(unsigned long cause)
{
    unsigned long irq_cause = cause & ~CAUSE_IRQ_FLAG;

    switch ( irq_cause )
    {
    case IRQ_S_SOFT:
        return "Supervisor Software Interrupt";
    case IRQ_S_TIMER:
        return "Supervisor Timer Interrupt";
    case IRQ_S_EXT:
        return "Supervisor External Interrupt";
    default:
        return decode_reserved_interrupt_cause(irq_cause);
    }
}

static const char *decode_cause(unsigned long cause)
{
    if ( cause & CAUSE_IRQ_FLAG )
        return decode_interrupt_cause(cause);

    return decode_trap_cause(cause);
}

static void do_unexpected_trap(const struct cpu_user_regs *regs)
{
    unsigned long cause = csr_read(CSR_SCAUSE);

    printk("Unhandled exception: %s\n", decode_cause(cause));

    die();
}

void do_trap(struct cpu_user_regs *cpu_regs)
{
    register_t pc = cpu_regs->sepc;
    unsigned long cause = csr_read(CSR_SCAUSE);

    switch ( cause )
    {
    case CAUSE_ILLEGAL_INSTRUCTION:
        if ( do_bug_frame(cpu_regs, pc) >= 0 )
        {
            if ( !(is_kernel_text(pc) || is_kernel_inittext(pc)) )
            {
                printk("Something wrong with PC: %#lx\n", pc);
                die();
            }

            cpu_regs->sepc += GET_INSN_LENGTH(*(uint16_t *)pc);

            break;
        }
        fallthrough;
    default:
        do_unexpected_trap(cpu_regs);
        break;
    }
}

void vcpu_show_execution_state(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

void show_execution_state(const struct cpu_user_regs *regs)
{
    printk("TODO: Implement show_execution_state(regs)\n");
}

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
    BUG_ON("unimplemented");
}

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    BUG_ON("unimplemented");
    return mc_continue;
}
