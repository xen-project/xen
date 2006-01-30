/*
 * debug.c
 * pdb debug functionality for processes.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm-i386/kdebug.h>
#include <asm-i386/mach-xen/asm/processor.h>
#include <asm-i386/mach-xen/asm/ptrace.h>
#include <asm-i386/mach-xen/asm/tlbflush.h>
#include <xen/interface/xen.h>
#include "pdb_module.h"
#include "pdb_debug.h"


static int pdb_debug_fn (struct pt_regs *regs, long error_code,
                         unsigned int condition);
static int pdb_int3_fn (struct pt_regs *regs, long error_code);
static int pdb_page_fault_fn (struct pt_regs *regs, long error_code,
                              unsigned int condition);

/***********************************************************************/

typedef struct bwcpoint                           /* break/watch/catch point */
{
    struct list_head list;
    unsigned long address;
    int length;

    uint8_t  type;                                                     /* BWC_??? */
    uint8_t  mode;                   /* for BWC_PAGE, the current protection mode */
    uint32_t process;
    uint8_t  error;                /* error occured when enabling: don't disable. */

    /* original values */
    uint8_t    orig_bkpt;                               /* single byte breakpoint */
    pte_t orig_pte;

    struct list_head watchpt_read_list;     /* read watchpoints on this page */
    struct list_head watchpt_write_list;                            /* write */
    struct list_head watchpt_access_list;                          /* access */
    struct list_head watchpt_disabled_list;                      /* disabled */

    struct bwcpoint *parent;             /* watchpoint: bwc_watch (the page) */
    struct bwcpoint *watchpoint;      /* bwc_watch_step: original watchpoint */
} bwcpoint_t, *bwcpoint_p;

static struct list_head bwcpoint_list = LIST_HEAD_INIT(bwcpoint_list);

#define _pdb_bwcpoint_alloc(_var) \
{ \
    if ( (_var = kmalloc(sizeof(bwcpoint_t), GFP_KERNEL)) == NULL ) \
        printk("error: unable to allocate memory %d\n", __LINE__); \
    else { \
        memset(_var, 0, sizeof(bwcpoint_t)); \
        INIT_LIST_HEAD(&_var->watchpt_read_list); \
        INIT_LIST_HEAD(&_var->watchpt_write_list); \
        INIT_LIST_HEAD(&_var->watchpt_access_list); \
        INIT_LIST_HEAD(&_var->watchpt_disabled_list); \
    } \
}

/***********************************************************************/

static void _pdb_bwc_print_list (struct list_head *, char *, int);

static void
_pdb_bwc_print (bwcpoint_p bwc, char *label, int level)
{
    printk("%s%03d 0x%08lx:0x%02x %c\n", label, bwc->type,
           bwc->address, bwc->length, bwc->error ? 'e' : '-');

    if ( !list_empty(&bwc->watchpt_read_list) )
        _pdb_bwc_print_list(&bwc->watchpt_read_list, "r", level);
    if ( !list_empty(&bwc->watchpt_write_list) )
        _pdb_bwc_print_list(&bwc->watchpt_write_list, "w", level);
    if ( !list_empty(&bwc->watchpt_access_list) )
        _pdb_bwc_print_list(&bwc->watchpt_access_list, "a", level);
    if ( !list_empty(&bwc->watchpt_disabled_list) )
        _pdb_bwc_print_list(&bwc->watchpt_disabled_list, "d", level);
}

static void
_pdb_bwc_print_list (struct list_head *bwc_list, char *label, int level)
{
    struct list_head *ptr;
    int counter = 0;

    list_for_each(ptr, bwc_list)
    {
        bwcpoint_p bwc = list_entry(ptr, bwcpoint_t, list);
        printk("  %s[%02d]%s ", level > 0 ? "  " : "", counter++,
                                level > 0 ? "" : "  ");
        _pdb_bwc_print(bwc, label, level+1);
    }

    if (counter == 0)
    {
        printk("  empty list\n");
    }
}

void
pdb_bwc_print_list (void)
{
    _pdb_bwc_print_list(&bwcpoint_list, " ", 0);
}

bwcpoint_p
pdb_search_watchpoint (uint32_t process, unsigned long address)
{
    bwcpoint_p bwc_watch = (bwcpoint_p) 0;
    bwcpoint_p bwc_entry = (bwcpoint_p) 0;
    struct list_head *ptr;

    list_for_each(ptr, &bwcpoint_list)                /* find bwc page entry */
    {
        bwc_watch = list_entry(ptr, bwcpoint_t, list);
        if (bwc_watch->address == (address & PAGE_MASK)) break;
    }

    if ( !bwc_watch )
    {
        return (bwcpoint_p) 0;
    }

#define __pdb_search_watchpoint_list(__list) \
    list_for_each(ptr, (__list))  \
    { \
        bwc_entry = list_entry(ptr, bwcpoint_t, list); \
        if ( bwc_entry->process == process &&          \
             bwc_entry->address <= address &&          \
             bwc_entry->address + bwc_entry->length > address ) \
            return bwc_entry; \
    }

    __pdb_search_watchpoint_list(&bwc_watch->watchpt_read_list);
    __pdb_search_watchpoint_list(&bwc_watch->watchpt_write_list);
    __pdb_search_watchpoint_list(&bwc_watch->watchpt_access_list);

#undef __pdb_search_watchpoint_list

    return (bwcpoint_p) 0;
}

/*************************************************************/

int
pdb_suspend (struct task_struct *target)
{
    uint32_t rc = 0;

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
pdb_read_register (struct task_struct *target, pdb_op_rd_reg_p op)
{
    int rc = 0;

    switch (op->reg)
    {
    case  0: op->value = _pdb_get_register(target, LINUX_EAX); break;
    case  1: op->value = _pdb_get_register(target, LINUX_ECX); break;
    case  2: op->value = _pdb_get_register(target, LINUX_EDX); break;
    case  3: op->value = _pdb_get_register(target, LINUX_EBX); break;
    case  4: op->value = _pdb_get_register(target, LINUX_ESP); break;
    case  5: op->value = _pdb_get_register(target, LINUX_EBP); break;
    case  6: op->value = _pdb_get_register(target, LINUX_ESI); break;
    case  7: op->value = _pdb_get_register(target, LINUX_EDI); break;
    case  8: op->value = _pdb_get_register(target, LINUX_EIP); break;
    case  9: op->value = _pdb_get_register(target, LINUX_EFL); break;

    case 10: op->value = _pdb_get_register(target, LINUX_CS); break;
    case 11: op->value = _pdb_get_register(target, LINUX_SS); break;
    case 12: op->value = _pdb_get_register(target, LINUX_DS); break;
    case 13: op->value = _pdb_get_register(target, LINUX_ES); break;
    case 14: op->value = _pdb_get_register(target, LINUX_FS); break;
    case 15: op->value = _pdb_get_register(target, LINUX_GS); break;
    }

    return rc;
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

    _pdb_bwcpoint_alloc(bkpt);
    if ( bkpt == NULL )  return -1;

    bkpt->process = target->pid;
    bkpt->address = 0;
    bkpt->type    = BWC_DEBUG;
    
    list_add_tail(&bkpt->list, &bwcpoint_list);

    wake_up_process(target);

    return rc;
}

int
pdb_insert_memory_breakpoint (struct task_struct *target, 
                              unsigned long address, uint32_t length)
{
    int rc = 0;
    bwcpoint_p bkpt;
    uint8_t breakpoint_opcode = 0xcc;

    printk("insert breakpoint %d:%lx len: %d\n", target->pid, address, length);

    if ( length != 1 )
    {
        printk("error: breakpoint length should be 1\n");
        return -1;
    }

    _pdb_bwcpoint_alloc(bkpt);
    if ( bkpt == NULL ) return -1;

    bkpt->process = target->pid;
    bkpt->address = address;
    bkpt->type    = BWC_INT3;

    pdb_access_memory(target, address, &bkpt->orig_bkpt, 1, PDB_MEM_READ);
    pdb_access_memory(target, address, &breakpoint_opcode, 1, PDB_MEM_WRITE);
    
    list_add_tail(&bkpt->list, &bwcpoint_list);

    printk("breakpoint_set %d:%lx  OLD: 0x%x\n",
           target->pid, address, bkpt->orig_bkpt);
    pdb_bwc_print_list();

    return rc;
}

int
pdb_remove_memory_breakpoint (struct task_struct *target,
                              unsigned long address, uint32_t length)
{
    int rc = 0;
    bwcpoint_p bkpt = NULL;

    printk ("remove breakpoint %d:%lx\n", target->pid, address);

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( target->pid == bkpt->process && 
             address == bkpt->address     &&
             bkpt->type == BWC_INT3 )
            break;
    }
    
    if (entry == &bwcpoint_list)
    {
        printk ("error: no breakpoint found\n");
        return -1;
    }

    pdb_access_memory(target, address, &bkpt->orig_bkpt, 1, PDB_MEM_WRITE);

    list_del(&bkpt->list);
    kfree(bkpt);

    pdb_bwc_print_list();

    return rc;
}

#define PDB_PTE_UPDATE   1
#define PDB_PTE_RESTORE  2

int
pdb_change_pte (struct task_struct *target, bwcpoint_p bwc, int mode)
{
    int rc = 0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(target->mm, bwc->address);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))  return -1;

    pud = pud_offset(pgd, bwc->address);
    if (pud_none(*pud) || unlikely(pud_bad(*pud))) return -2;

    pmd = pmd_offset(pud, bwc->address);
    if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) return -3;

    ptep = pte_offset_map(pmd, bwc->address);
    if (!ptep)  return -4;

    switch ( mode )
    {
    case PDB_PTE_UPDATE:      /* added or removed a watchpoint.  update pte. */
    {
        pte_t new_pte;

        if ( pte_val(bwc->parent->orig_pte) == 0 )    /* new watchpoint page */
        {
            bwc->parent->orig_pte = *ptep;
        }

        new_pte = bwc->parent->orig_pte;

        if ( !list_empty(&bwc->parent->watchpt_read_list)  || 
             !list_empty(&bwc->parent->watchpt_access_list) )
        {
            new_pte = pte_rdprotect(new_pte);
        }

        if ( !list_empty(&bwc->parent->watchpt_write_list) ||
             !list_empty(&bwc->parent->watchpt_access_list) )
        {
            new_pte = pte_wrprotect(new_pte);
        }
        
        if ( pte_val(new_pte) != pte_val(*ptep) )
        {
            *ptep = new_pte;
            flush_tlb_mm(target->mm);
        }
        break;
    }
    case PDB_PTE_RESTORE :   /* suspend watchpoint by restoring original pte */
    {
        *ptep = bwc->parent->orig_pte;
        flush_tlb_mm(target->mm);
        break;
    }
    default :
    {
        printk("(linux) unknown mode %d %d\n", mode, __LINE__);
        break;
    }
    }

    pte_unmap(ptep);                /* can i flush the tlb before pte_unmap? */

    return rc;
}

int
pdb_insert_watchpoint (struct task_struct *target, pdb_op_watchpt_p watchpt)
{
    int rc = 0;

    bwcpoint_p bwc_watch;
    bwcpoint_p bwc_entry;
    struct list_head *ptr;
    unsigned long page = watchpt->address & PAGE_MASK;
    struct list_head *watchpoint_list;
    
    printk("insert watchpoint: %d %x %x\n", 
           watchpt->type, watchpt->address, watchpt->length);

    list_for_each(ptr, &bwcpoint_list) /* find existing bwc page entry */
    {
        bwc_watch = list_entry(ptr, bwcpoint_t, list);

        if (bwc_watch->address == page)  goto got_bwc_watch;
    }

    _pdb_bwcpoint_alloc(bwc_watch);                  /* create new bwc:watch */
    if ( bwc_watch == NULL ) return -1;

    bwc_watch->type    = BWC_WATCH;
    bwc_watch->process = target->pid;
    bwc_watch->address = page;

    list_add_tail(&bwc_watch->list, &bwcpoint_list);

 got_bwc_watch:

    switch (watchpt->type)
    {
    case BWC_WATCH_READ:
        watchpoint_list = &bwc_watch->watchpt_read_list; break;
    case BWC_WATCH_WRITE: 
        watchpoint_list = &bwc_watch->watchpt_write_list; break;
    case BWC_WATCH_ACCESS:
        watchpoint_list = &bwc_watch->watchpt_access_list; break;
    default:
        printk("unknown type %d\n", watchpt->type); return -2;
    }

    _pdb_bwcpoint_alloc(bwc_entry);                  /* create new bwc:entry */
    if ( bwc_entry == NULL ) return -1;

    bwc_entry->process = target->pid;
    bwc_entry->address = watchpt->address;
    bwc_entry->length  = watchpt->length;
    bwc_entry->type    = watchpt->type;
    bwc_entry->parent  = bwc_watch;

    list_add_tail(&bwc_entry->list, watchpoint_list);
    pdb_change_pte(target, bwc_entry, PDB_PTE_UPDATE);

    pdb_bwc_print_list();

    return rc;
}

int 
pdb_remove_watchpoint (struct task_struct *target, pdb_op_watchpt_p watchpt)
{
    int rc = 0;
    bwcpoint_p bwc_watch = (bwcpoint_p) NULL;
    bwcpoint_p bwc_entry = (bwcpoint_p) NULL;
    unsigned long page = watchpt->address & PAGE_MASK;
    struct list_head *ptr;
    struct list_head *watchpoint_list;

    printk("remove watchpoint: %d %x %x\n", 
           watchpt->type, watchpt->address, watchpt->length);

    list_for_each(ptr, &bwcpoint_list)                /* find bwc page entry */
    {
        bwc_watch = list_entry(ptr, bwcpoint_t, list);
        if (bwc_watch->address == page) break;
    }

    if ( !bwc_watch )
    {
        printk("(linux) delete watchpoint: can't find bwc page 0x%08x\n",
               watchpt->address);
        return -1;
    }

    switch (watchpt->type)
    {
    case BWC_WATCH_READ:
        watchpoint_list = &bwc_watch->watchpt_read_list; break;
    case BWC_WATCH_WRITE:
        watchpoint_list = &bwc_watch->watchpt_write_list; break;
    case BWC_WATCH_ACCESS:
        watchpoint_list = &bwc_watch->watchpt_access_list; break;
    default:
        printk("unknown type %d\n", watchpt->type); return -2;
    }

    list_for_each(ptr, watchpoint_list)                   /* find watchpoint */
    {
        bwc_entry = list_entry(ptr, bwcpoint_t, list);
        if ( bwc_entry->address == watchpt->address &&
             bwc_entry->length  == watchpt->length ) break;
    }

    if ( !bwc_entry )                           /* or ptr == watchpoint_list */
    {
        printk("(linux) delete watchpoint: can't find watchpoint 0x%08x\n",
               watchpt->address);
        return -1;
    }
    
    list_del(&bwc_entry->list);
    pdb_change_pte(target, bwc_entry, PDB_PTE_UPDATE);
    kfree(bwc_entry);


    if ( list_empty(&bwc_watch->watchpt_read_list)  &&
         list_empty(&bwc_watch->watchpt_write_list) &&
         list_empty(&bwc_watch->watchpt_access_list) )
    {
        list_del(&bwc_watch->list);
        kfree(bwc_watch);
    }

    pdb_bwc_print_list();

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
		if ( pdb_debug_fn(args->regs, args->trapnr, args->err) )
			return NOTIFY_STOP;
		break;
    case DIE_TRAP:
		if ( args->trapnr == 3 && pdb_int3_fn(args->regs, args->err) )
			return NOTIFY_STOP;
        break;
	case DIE_INT3:          /* without kprobes, we should never see DIE_INT3 */
		if ( pdb_int3_fn(args->regs, args->err) )
			return NOTIFY_STOP;
		break;
	case DIE_PAGE_FAULT:
		if ( pdb_page_fault_fn(args->regs, args->trapnr, args->err) )
			return NOTIFY_STOP;
		break;
	case DIE_GPF:
        printk("---------------GPF\n");
        break;
	default:
		break;
	}

	return NOTIFY_DONE;
}


static int
pdb_debug_fn (struct pt_regs *regs, long error_code, 
                   unsigned int condition)
{
    pdb_response_t resp;
    bwcpoint_p bkpt = NULL;
    struct list_head *entry;

    printk("pdb_debug_fn\n");

    list_for_each(entry, &bwcpoint_list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( current->pid == bkpt->process && 
             (bkpt->type == BWC_DEBUG ||                      /* single step */
              bkpt->type == BWC_WATCH_STEP))  /* single step over watchpoint */
            break;
    }
    
    if (entry == &bwcpoint_list)
    {
        printk("not my debug  0x%x 0x%lx\n", current->pid, regs->eip);
        return 0;
    }

    pdb_suspend(current);

    printk("(pdb) %s  pid: %d, eip: 0x%08lx\n", 
           bkpt->type == BWC_DEBUG ? "debug" : "watch-step",
           current->pid, regs->eip);

    regs->eflags &= ~X86_EFLAGS_TF;
	set_tsk_thread_flag(current, TIF_SINGLESTEP);

    switch (bkpt->type)
    {
    case BWC_DEBUG:
        resp.operation = PDB_OPCODE_STEP;
        break;
    case BWC_WATCH_STEP:
    {
        struct list_head *watchpoint_list;
        bwcpoint_p watch_page = bkpt->watchpoint->parent;

        switch (bkpt->watchpoint->type)
        {
        case BWC_WATCH_READ:
            watchpoint_list = &watch_page->watchpt_read_list; break;
        case BWC_WATCH_WRITE: 
            watchpoint_list = &watch_page->watchpt_write_list; break;
        case BWC_WATCH_ACCESS:
            watchpoint_list = &watch_page->watchpt_access_list; break;
        default:
            printk("unknown type %d\n", bkpt->watchpoint->type); return 0;
        }

        resp.operation = PDB_OPCODE_WATCHPOINT;
        list_del_init(&bkpt->watchpoint->list);
        list_add_tail(&bkpt->watchpoint->list, watchpoint_list);
        pdb_change_pte(current, bkpt->watchpoint, PDB_PTE_UPDATE);
        pdb_bwc_print_list();
        break;
    }
    default:
        printk("unknown breakpoint type %d %d\n", __LINE__, bkpt->type);
        return 0;
    }

    resp.process   = current->pid;
    resp.status    = PDB_RESPONSE_OKAY;

    pdb_send_response(&resp);

    list_del(&bkpt->list);
    kfree(bkpt);

    return 1;
}


static int
pdb_int3_fn (struct pt_regs *regs, long error_code)
{
    pdb_response_t resp;
    bwcpoint_p bkpt = NULL;
    unsigned long address = regs->eip - 1;

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( current->pid == bkpt->process && 
             address == bkpt->address      &&
             bkpt->type == BWC_INT3 )
            break;
    }
    
    if (entry == &bwcpoint_list)
    {
        printk("not my int3 bkpt  0x%x 0x%lx\n", current->pid, address);
        return 0;
    }

    printk("(pdb) int3  pid: %d, eip: 0x%08lx\n", current->pid, address);

    pdb_suspend(current);

    resp.operation = PDB_OPCODE_CONTINUE;
    resp.process   = current->pid;
    resp.status    = PDB_RESPONSE_OKAY;

    pdb_send_response(&resp);

    return 1;
}

static int
pdb_page_fault_fn (struct pt_regs *regs, long error_code, 
                   unsigned int condition)
{
    unsigned long cr2;
    unsigned long cr3;
    bwcpoint_p bwc;
    bwcpoint_p watchpt;
    bwcpoint_p bkpt;

    __asm__ __volatile__ ("movl %%cr3,%0" : "=r" (cr3) : );
    __asm__ __volatile__ ("movl %%cr2,%0" : "=r" (cr2) : );

    bwc = pdb_search_watchpoint(current->pid, cr2);
    if ( !bwc )
    {
        return 0;                                                /* not mine */
    }

    printk("page_fault cr2:%08lx err:%lx eip:%08lx\n", 
           cr2, error_code, regs->eip);

    /* disable the watchpoint */
    watchpt = bwc->watchpoint;
    list_del_init(&bwc->list);
    list_add_tail(&bwc->list, &bwc->parent->watchpt_disabled_list);
    pdb_change_pte(current, bwc, PDB_PTE_RESTORE);

    /* single step the faulting instruction */
    regs->eflags |= X86_EFLAGS_TF;

    /* create a bwcpoint entry so we know what to do once we regain control */
    _pdb_bwcpoint_alloc(bkpt);
    if ( bkpt == NULL )  return -1;

    bkpt->process    = current->pid;
    bkpt->address    = 0;
    bkpt->type       = BWC_WATCH_STEP;
    bkpt->watchpoint = bwc;

    /* add to head so we see it first the next time we break */
    list_add(&bkpt->list, &bwcpoint_list);                

    pdb_bwc_print_list();
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

