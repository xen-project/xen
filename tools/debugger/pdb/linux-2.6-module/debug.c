/*
 * debug.c
 * pdb debug functionality for processes.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm-i386/kdebug.h>
#include <asm-xen/asm-i386/processor.h>
#include <asm-xen/asm-i386/ptrace.h>
#include <asm-xen/xen-public/xen.h>
#include "pdb_module.h"
#include "pdb_debug.h"

#define BWC_DEBUG 1
#define BWC_INT3  3
typedef struct bwcpoint                           /* break/watch/catch point */
{
    struct list_head list;
    memory_t address;
    u32 domain;
    u32 process;
    u8  old_value;                            /* old value for software bkpt */
    u8  type;                                                     /* BWC_??? */
} bwcpoint_t, *bwcpoint_p;

static bwcpoint_t bwcpoint_list;

void
pdb_initialize_bwcpoint (void)
{
    memset((void *) &bwcpoint_list, 0, sizeof(bwcpoint_t));
    INIT_LIST_HEAD(&bwcpoint_list.list);

    return;
}


int
pdb_suspend (struct task_struct *target)
{
    u32 rc = 0;

    force_sig(SIGSTOP, target);                    /* force_sig_specific ??? */

    return rc;
}

int
pdb_resume (struct task_struct *target)
{
    int rc = 0;

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
    case LINUX_FS:
        result = target->thread.fs;
        break;
    case LINUX_GS:
        result = target->thread.gs;
        break;
    case LINUX_DS:
    case LINUX_ES:
    case LINUX_SS:
    case LINUX_CS:
        result = 0xffff;
        /* fall through */
    default:
        if (reg > LINUX_GS)
            reg -= 2;

        offset = reg * sizeof(long);
        offset -= sizeof(struct pt_regs);
        stack = (unsigned char *)target->thread.esp0;
        stack += offset;
        result &= *((int *)stack);
    }

    return result;
}

/*
 * from linux-2.6.11/arch/i386/kernel/ptrace.c::putreg()
 */
static void
_pdb_set_register (struct task_struct *target, int reg, unsigned long val)
{
    unsigned long offset;
    unsigned char *stack;
    unsigned long value = val;

    switch (reg)
    {
    case LINUX_FS:
        target->thread.fs = value;
        return;
    case LINUX_GS:
        target->thread.gs = value;
        return;
    case LINUX_DS:
    case LINUX_ES:
        value &= 0xffff;
        break;
    case LINUX_SS:
    case LINUX_CS:
        value &= 0xffff;
        break;
    case LINUX_EFL:
        break;
    }

    if (reg > LINUX_GS)
        reg -= 2;
    offset = reg * sizeof(long);
    offset -= sizeof(struct pt_regs);
    stack = (unsigned char *)target->thread.esp0;
    stack += offset;
    *(unsigned long *) stack = value;

    return;
}

int
pdb_read_registers (struct task_struct *target, pdb_op_rd_regs_p op)
{
    int rc = 0;

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

int
pdb_write_register (struct task_struct *target, pdb_op_wr_reg_p op)
{
    int rc = 0;

    _pdb_set_register(target, op->reg, op->value);

    return rc;
}

int
pdb_access_memory (struct task_struct *target, unsigned long address, 
                   void *buffer, int length, int write)
{
    int rc = 0;

    access_process_vm(target, address, buffer, length, write);

    return rc;
}

int
pdb_continue (struct task_struct *target)
{
    int rc = 0;
    unsigned long eflags;

    eflags = _pdb_get_register(target, LINUX_EFL);
    eflags &= ~X86_EFLAGS_TF;
    _pdb_set_register(target, LINUX_EFL, eflags);

    wake_up_process(target);

    return rc;
}

int
pdb_step (struct task_struct *target)
{
    int rc = 0;
    unsigned long eflags;
    bwcpoint_p bkpt;
    
    eflags = _pdb_get_register(target, LINUX_EFL);
    eflags |= X86_EFLAGS_TF;
    _pdb_set_register(target, LINUX_EFL, eflags);

    bkpt = kmalloc(sizeof(bwcpoint_t), GFP_KERNEL);
    if ( bkpt == NULL )
    {
        printk("error: unable to allocation memory\n");
        return -1;
    }

    bkpt->process = target->pid;
    bkpt->address = 0;
    bkpt->type    = BWC_DEBUG;
    
    list_add(&bkpt->list, &bwcpoint_list.list);

    wake_up_process(target);

    return rc;
}

int
pdb_insert_memory_breakpoint (struct task_struct *target, 
                              memory_t address, u32 length)
{
    int rc = 0;
    bwcpoint_p bkpt;
    u8 breakpoint_opcode = 0xcc;

    printk("insert breakpoint %d:%lx len: %d\n", target->pid, address, length);

    bkpt = kmalloc(sizeof(bwcpoint_t), GFP_KERNEL);
    if ( bkpt == NULL )
    {
        printk("error: unable to allocation memory\n");
        return -1;
    }

    if ( length != 1 )
    {
        printk("error: breakpoint length should be 1\n");
        kfree(bkpt);
        return -1;
    }

    bkpt->process = target->pid;
    bkpt->address = address;
    bkpt->type    = BWC_INT3;

    pdb_access_memory(target, address, &bkpt->old_value, 1, 0);
    pdb_access_memory(target, address, &breakpoint_opcode, 1, 1);
    
    list_add(&bkpt->list, &bwcpoint_list.list);

    printk("breakpoint_set %d:%lx  OLD: 0x%x\n",
           target->pid, address, bkpt->old_value);

    return rc;
}

int
pdb_remove_memory_breakpoint (struct task_struct *target,
                              memory_t address, u32 length)
{
    int rc = 0;
    bwcpoint_p bkpt = NULL;

    printk ("remove breakpoint %d:%lx\n", target->pid, address);

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list.list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( target->pid == bkpt->process && 
             address == bkpt->address     &&
             bkpt->type == BWC_INT3 )
            break;
    }
    
    if (bkpt == &bwcpoint_list || bkpt == NULL)
    {
        printk ("error: no breakpoint found\n");
        return -1;
    }

    list_del(&bkpt->list);

    pdb_access_memory(target, address, &bkpt->old_value, 1, 1);

    kfree(bkpt);

    return rc;
}


/***************************************************************/

int
pdb_exceptions_notify (struct notifier_block *self, unsigned long val,
                       void *data)
{
    struct die_args *args = (struct die_args *)data;

	switch (val) 
    {
	case DIE_DEBUG:
		if (pdb_debug_fn(args->regs, args->trapnr, args->err))
			return NOTIFY_STOP;
		break;
    case DIE_TRAP:
		if (args->trapnr == 3 && pdb_int3_fn(args->regs, args->err))
			return NOTIFY_STOP;
        break;
	case DIE_INT3:          /* without kprobes, we should never see DIE_INT3 */
	case DIE_GPF:
	case DIE_PAGE_FAULT:
	default:
		break;
	}

	return NOTIFY_DONE;
}


int
pdb_debug_fn (struct pt_regs *regs, long error_code, 
                   unsigned int condition)
{
    pdb_response_t resp;
    bwcpoint_p bkpt = NULL;

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list.list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( current->pid == bkpt->process && 
             bkpt->type == BWC_DEBUG )
            break;
    }
    
    if (bkpt == &bwcpoint_list || bkpt == NULL)
    {
        printk("not my debug  0x%x 0x%lx\n", current->pid, regs->eip);
        return 0;
    }

    list_del(&bkpt->list);

    pdb_suspend(current);

    printk("(pdb) debug  pid: %d, eip: 0x%08lx\n", current->pid, regs->eip);

    regs->eflags &= ~X86_EFLAGS_TF;
	set_tsk_thread_flag(current, TIF_SINGLESTEP);

    resp.operation = PDB_OPCODE_STEP;
    resp.process   = current->pid;
    resp.status    = PDB_RESPONSE_OKAY;

    pdb_send_response(&resp);

    return 1;
}


int
pdb_int3_fn (struct pt_regs *regs, long error_code)
{
    pdb_response_t resp;
    bwcpoint_p bkpt = NULL;

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list.list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( current->pid == bkpt->process && 
             regs->eip == bkpt->address    &&
             bkpt->type == BWC_INT3 )
            break;
    }
    
    if (bkpt == &bwcpoint_list || bkpt == NULL)
    {
        printk("not my int3 bkpt  0x%x 0x%lx\n", current->pid, regs->eip);
        return 0;
    }

    printk("(pdb) int3  pid: %d, eip: 0x%08lx\n", current->pid, regs->eip);

    pdb_suspend(current);

    resp.operation = PDB_OPCODE_CONTINUE;
    resp.process   = current->pid;
    resp.status    = PDB_RESPONSE_OKAY;

    pdb_send_response(&resp);

    return 1;
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

