/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/lib.h>

#include <asm/processor.h>

static const char *exception_name_from_vec(uint32_t vec)
{
    switch ( vec )
    {
    case EXC_SYSTEM_RESET:
        return "System Reset";
    case EXC_MACHINE_CHECK:
        return "Machine Check";
    case EXC_DATA_STORAGE:
        return "Data Storage";
    case EXC_DATA_SEGMENT:
        return "Data Segment";
    case EXC_INSN_STORAGE:
        return "Instruction Storage";
    case EXC_INSN_SEGMENT:
        return "Instruction Segment";
    case EXC_EXTERNAL:
        return "External";
    case EXC_ALIGNMENT:
        return "Alignment";
    case EXC_PROGRAM:
        return "Program";
    case EXC_FPU_UNAVAIL:
        return "Floating-Point Unavailable";
    case EXC_DECREMENTER:
        return "Decrementer";
    case EXC_H_DECREMENTER:
        return "Hypervisor Decrementer";
    case EXC_PRIV_DOORBELL:
        return "Directed Privileged Doorbell";
    case EXC_SYSTEM_CALL:
        return "System Call";
    case EXC_TRACE:
        return "Trace";
    case EXC_H_DATA_STORAGE:
        return "Hypervisor Data Storage";
    case EXC_H_INSN_STORAGE:
        return "Hypervisor Instruction Storage";
    case EXC_H_EMUL_ASST:
        return "Hypervisor Emulation Assistance";
    case EXC_H_MAINTENANCE:
        return "Hypervisor Maintenance";
    case EXC_H_DOORBELL:
        return "Directed Hypervisor Doorbell";
    case EXC_H_VIRT:
        return "Hypervisor Virtualization";
    case EXC_PERF_MON:
        return "Performance Monitor";
    case EXC_VECTOR_UNAVAIL:
        return "Vector Unavailable";
    case EXC_VSX_UNAVAIL:
        return "VSX Unavailable";
    case EXC_FACIL_UNAVAIL:
        return "Facility Unavailable";
    case EXC_H_FACIL_UNAVAIL:
        return "Hypervisor Facility Unavailable";
    default:
        return "(unknown)";
    }
}

void exception_handler(struct cpu_user_regs *regs)
{
    /* TODO: this is currently only useful for debugging */

    printk("UNRECOVERABLE EXCEPTION: %s (0x%04x)\n\n"
           "GPR 0-3   : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 4-7   : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 8-11  : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 12-15 : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 16-19 : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 20-23 : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 24-27 : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n"
           "GPR 28-31 : 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n\n",
           exception_name_from_vec(regs->entry_vector), regs->entry_vector,
           regs->gprs[0], regs->gprs[1], regs->gprs[2], regs->gprs[3],
           regs->gprs[4], regs->gprs[5], regs->gprs[6], regs->gprs[7],
           regs->gprs[8], regs->gprs[9], regs->gprs[10], regs->gprs[11],
           regs->gprs[12], regs->gprs[13], regs->gprs[14], regs->gprs[15],
           regs->gprs[16], regs->gprs[17], regs->gprs[18], regs->gprs[19],
           regs->gprs[20], regs->gprs[21], regs->gprs[22], regs->gprs[23],
           regs->gprs[24], regs->gprs[25], regs->gprs[26], regs->gprs[27],
           regs->gprs[28], regs->gprs[29], regs->gprs[30], regs->gprs[31]);
    printk("LR        : 0x%016lx\n"
           "CTR       : 0x%016lx\n"
           "CR        : 0x%08x\n"
           "PC        : 0x%016lx\n"
           "MSR       : 0x%016lx\n"
           "SRR0      : 0x%016lx\n"
           "SRR1      : 0x%016lx\n"
           "DAR       : 0x%016lx\n"
           "DSISR     : 0x%08x\n",
           regs->lr, regs->ctr, regs->cr, regs->pc, regs->msr, regs->srr0,
           regs->srr1, regs->dar, regs->dsisr);

    die();
}
