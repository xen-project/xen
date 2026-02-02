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

#include <asm/intc.h>
#include <asm/processor.h>
#include <asm/riscv_encoding.h>
#include <asm/traps.h>
#include <asm/vsbi.h>

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

static void dump_general_regs(const struct cpu_user_regs *regs)
{
#define X(regs, name, delim) \
    printk("%-4s: %016lx" delim, #name, (regs)->name)

    X(regs, ra, " "); X(regs, sp, "\n");
    X(regs, gp, " "); X(regs, tp, "\n");
    X(regs, t0, " "); X(regs, t1, "\n");
    X(regs, t2, " "); X(regs, s0, "\n");
    X(regs, s1, " "); X(regs, a0, "\n");
    X(regs, a1, " "); X(regs, a2, "\n");
    X(regs, a3, " "); X(regs, a4, "\n");
    X(regs, a5, " "); X(regs, a6, "\n");
    X(regs, a7, " "); X(regs, s2, "\n");
    X(regs, s3, " "); X(regs, s4, "\n");
    X(regs, s5, " "); X(regs, s6, "\n");
    X(regs, s7, " "); X(regs, s8, "\n");
    X(regs, s9, " "); X(regs, s10, "\n");
    X(regs, s11, " "); X(regs, t3, "\n");
    X(regs, t4, " "); X(regs, t5, "\n");
    X(regs, t6, "\n");

#undef X
}

static void dump_csrs(const char *ctx)
{
    unsigned long v;

#define X(name, csr, fmt, ...) \
    v = csr_read(csr); \
    printk("%-10s: %016lx" fmt, #name, v, ##__VA_ARGS__)

    X(scause, CSR_SCAUSE, " %s[%s]\n", ctx, decode_cause(v));

    X(htval, CSR_HTVAL, " ");  X(htinst, CSR_HTINST, "\n");
    X(hedeleg, CSR_HEDELEG, " "); X(hideleg, CSR_HIDELEG, "\n");
    X(hstatus, CSR_HSTATUS, " [%s%s%s%s%s%s ]\n",
      (v & HSTATUS_VTSR) ? " VTSR" : "",
      (v & HSTATUS_VTVM) ? " VTVM" : "",
      (v & HSTATUS_HU)   ? " HU"   : "",
      (v & HSTATUS_SPVP) ? " SPVP" : "",
      (v & HSTATUS_SPV)  ? " SPV"  : "",
      (v & HSTATUS_GVA)  ? " GVA"  : "");
    X(hgatp, CSR_HGATP, "\n");
    X(hstateen0, CSR_HSTATEEN0, "\n");
    X(stvec, CSR_STVEC, " "); X(vstvec, CSR_VSTVEC, "\n");
    X(sepc, CSR_SEPC, " "); X(vsepc, CSR_VSEPC, "\n");
    X(stval, CSR_STVAL, " "); X(vstval, CSR_VSTVAL, "\n");
    X(status, CSR_SSTATUS, " "); X(vsstatus, CSR_VSSTATUS, "\n");
    X(satp, CSR_SATP, "\n");
    X(vscause, CSR_VSCAUSE, " [%s]\n", decode_cause(v));

#undef X
}

static void do_unexpected_trap(const struct cpu_user_regs *regs)
{
    dump_csrs("Unhandled exception");
    dump_general_regs(regs);

    die();
}

void do_trap(struct cpu_user_regs *cpu_regs)
{
    register_t pc = cpu_regs->sepc;
    unsigned long cause = csr_read(CSR_SCAUSE);

    switch ( cause )
    {
    case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
        /* CAUSE_VIRTUAL_SUPERVISOR_ECALL should come from VS-mode */
        BUG_ON(!(cpu_regs->hstatus & HSTATUS_SPV));

        vsbi_handle_ecall(cpu_regs);
        break;

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
        if ( cause & CAUSE_IRQ_FLAG )
        {
            /* Handle interrupt */
            unsigned long icause = cause & ~CAUSE_IRQ_FLAG;
            bool intr_handled = true;

            switch ( icause )
            {
            case IRQ_S_EXT:
                intc_handle_external_irqs(cpu_regs);
                break;

            default:
                intr_handled = false;
                break;
            }

            if ( intr_handled )
                break;
        }

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
