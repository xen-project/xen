/******************************************************************************
 * Arch-specific dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>
#include <asm/msr.h>
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

extern unsigned int alloc_new_dom_mem(struct domain *, unsigned int);

static int msr_cpu_mask;
static unsigned long msr_addr;
static unsigned long msr_lo;
static unsigned long msr_hi;

static void write_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
        wrmsr(msr_addr, msr_lo, msr_hi);
}

static void read_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
        rdmsr(msr_addr, msr_lo, msr_hi);
}

long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current) )
        return -EPERM;

    switch ( op->cmd )
    {

    case DOM0_MSR:
    {
        if ( op->u.msr.write )
        {
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            msr_lo = op->u.msr.in1;
            msr_hi = op->u.msr.in2;
            smp_call_function(write_msr_for, NULL, 1, 1);
            write_msr_for(NULL);
        }
        else
        {
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            smp_call_function(read_msr_for, NULL, 1, 1);
            read_msr_for(NULL);

            op->u.msr.out1 = msr_lo;
            op->u.msr.out2 = msr_hi;
            copy_to_user(u_dom0_op, op, sizeof(*op));
        }
        ret = 0;
    }
    break;

    case DOM0_SHADOW_CONTROL:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.shadow_control.domain);
        if ( d != NULL )
        {
            ret = shadow_mode_control(d, &op->u.shadow_control);
            put_domain(d);
            copy_to_user(u_dom0_op, op, sizeof(*op));
        } 
    }
    break;

    default:
        ret = -ENOSYS;

    }

    return ret;
}

void arch_getdomaininfo_ctxt(struct domain *d, full_execution_context_t *c)
{ 
    int i;

    c->flags = 0;
    memcpy(&c->cpu_ctxt, 
           &d->thread.user_ctxt,
           sizeof(d->thread.user_ctxt));
    if ( test_bit(DF_DONEFPUINIT, &d->flags) )
        c->flags |= ECF_I387_VALID;
    memcpy(&c->fpu_ctxt,
           &d->thread.i387,
           sizeof(d->thread.i387));
    memcpy(&c->trap_ctxt,
           d->thread.traps,
           sizeof(d->thread.traps));
#ifdef ARCH_HAS_FAST_TRAP
    if ( (d->thread.fast_trap_desc.a == 0) &&
         (d->thread.fast_trap_desc.b == 0) )
        c->fast_trap_idx = 0;
    else
        c->fast_trap_idx = 
            d->thread.fast_trap_idx;
#endif
    c->ldt_base = d->mm.ldt_base;
    c->ldt_ents = d->mm.ldt_ents;
    c->gdt_ents = 0;
    if ( GET_GDT_ADDRESS(d) == GDT_VIRT_START )
    {
        for ( i = 0; i < 16; i++ )
            c->gdt_frames[i] = 
                l1_pgentry_to_pagenr(d->mm.perdomain_pt[i]);
        c->gdt_ents = GET_GDT_ENTRIES(d);
    }
    c->guestos_ss  = d->thread.guestos_ss;
    c->guestos_esp = d->thread.guestos_sp;
    c->pt_base   = 
        pagetable_val(d->mm.pagetable);
    memcpy(c->debugreg, 
           d->thread.debugreg, 
           sizeof(d->thread.debugreg));
    c->event_callback_cs  =
        d->event_selector;
    c->event_callback_eip =
        d->event_address;
    c->failsafe_callback_cs  = 
        d->failsafe_selector;
    c->failsafe_callback_eip = 
        d->failsafe_address;
}
