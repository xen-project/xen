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
int
pdb_read_register (int pid, pdb_op_rd_reg_p op, unsigned long *dest)
{
    int rc = 0;
    struct task_struct *target;
    unsigned long offset;
    unsigned char *stack = 0L;

    *dest = ~0UL;

    read_lock(&tasklist_lock);
    target = find_task_by_pid(pid);
    if (target)
        get_task_struct(target);
    read_unlock(&tasklist_lock);

    switch (op->reg)
    {
    case FS:
        *dest = target->thread.fs;
        break;
    case GS:
        *dest = target->thread.gs;
        break;
    case DS:
    case ES:
    case SS:
    case CS:
        *dest = 0xffff;
        /* fall through */
    default:
        if (op->reg > GS)
            op->reg -= 2;

        offset = op->reg * sizeof(long);
        offset -= sizeof(struct pt_regs);
        stack = (unsigned char *)target->thread.esp0;
        stack += offset;
        *dest &= *((int *)stack);
    }

    /*
    printk ("pdb read register: 0x%x %2d 0x%p 0x%lx\n", 
            pid, op->reg, stack, *dest);
    */

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

