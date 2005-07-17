/*
 * debug.c
 * pdb debug functionality for processes.
 */


#include <linux/module.h>
#include <linux/sched.h>
#include <asm-xen/asm-i386/ptrace.h>
#include <asm-xen/xen-public/xen.h>

#include "pdb_module.h"

EXPORT_SYMBOL(pdb_attach);
EXPORT_SYMBOL(pdb_detach);

int
pdb_attach (int pid)
{
    struct task_struct *target;
    u32 rc = 0;

    printk ("pdb attach: 0x%x\n", pid);

    read_lock(&tasklist_lock);
    target = find_task_by_pid(pid);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    force_sig(SIGSTOP, target);                    /* force_sig_specific ??? */

    return rc;
}

int
pdb_detach (int pid)
{
    int rc = 0;
    struct task_struct *target;

    printk ("pdb detach: 0x%x\n", pid);

    read_lock(&tasklist_lock);
    target = find_task_by_pid(pid);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    wake_up_process(target);

    return rc;
}

/*
 * from linux-2.6.11/arch/i386/kernel/ptrace.c::getreg()
 */

static unsigned long
_pdb_get_register (struct task_struct *target, int reg)
{
    unsigned long result = ~0UL;
    unsigned long offset;
    unsigned char *stack = 0L;

    switch (reg)
    {
    case FS:
        result = target->thread.fs;
        break;
    case GS:
        result = target->thread.gs;
        break;
    case DS:
    case ES:
    case SS:
    case CS:
        result = 0xffff;
        /* fall through */
    default:
        if (reg > GS)
            reg -= 2;

        offset = reg * sizeof(long);
        offset -= sizeof(struct pt_regs);
        stack = (unsigned char *)target->thread.esp0;
        stack += offset;
        result &= *((int *)stack);
    }

    return result;
}

int
pdb_read_register (int pid, pdb_op_rd_regs_p op)
{
    int rc = 0;
    struct task_struct *target;

    read_lock(&tasklist_lock);
    target = find_task_by_pid(pid);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    op->reg[ 0] = _pdb_get_register(target, LINUX_EAX);
    op->reg[ 1] = _pdb_get_register(target, LINUX_ECX);
    op->reg[ 2] = _pdb_get_register(target, LINUX_EDX);
    op->reg[ 3] = _pdb_get_register(target, LINUX_EBX);
    op->reg[ 4] = _pdb_get_register(target, LINUX_ESP);
    op->reg[ 5] = _pdb_get_register(target, LINUX_EBP);
    op->reg[ 6] = _pdb_get_register(target, LINUX_ESI);
    op->reg[ 7] = _pdb_get_register(target, LINUX_EDI);
    op->reg[ 8] = _pdb_get_register(target, LINUX_EIP);
    op->reg[ 9] = _pdb_get_register(target, LINUX_EFL);

    op->reg[10] = _pdb_get_register(target, LINUX_CS);
    op->reg[11] = _pdb_get_register(target, LINUX_SS);
    op->reg[12] = _pdb_get_register(target, LINUX_DS);
    op->reg[13] = _pdb_get_register(target, LINUX_ES);
    op->reg[14] = _pdb_get_register(target, LINUX_FS);
    op->reg[15] = _pdb_get_register(target, LINUX_GS);

    return rc;
}

/*
 * from linux-2.6.11/arch/i386/kernel/ptrace.c::putreg()
 */
int
pdb_write_register (int pid, pdb_op_wr_reg_p op)
{
    int rc = 0;
    struct task_struct *target;
    unsigned long offset;
    unsigned char *stack;
    unsigned long value = op->value;

    /*
    printk ("pdb write register: 0x%x %2d 0x%lx\n", pid, op->reg, value);
    */

    read_lock(&tasklist_lock);
    target = find_task_by_pid(pid);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    switch (op->reg)
    {
    case FS:
        target->thread.fs = value;
        return rc;
    case GS:
        target->thread.gs = value;
        return rc;
    case DS:
    case ES:
        value &= 0xffff;
        break;
    case SS:
    case CS:
        value &= 0xffff;
        break;
    case EFL:
        break;
    }

    if (op->reg > GS)
        op->reg -= 2;
    offset = op->reg * sizeof(long);
    offset -= sizeof(struct pt_regs);
    stack = (unsigned char *)target->thread.esp0;
    stack += offset;
    *(unsigned long *) stack = op->value;

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

