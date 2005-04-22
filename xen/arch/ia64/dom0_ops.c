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
//#include <asm/msr.h>
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
//#include <xen/shadow.h>
#include <public/sched_ctl.h>

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

static int msr_cpu_mask;
static unsigned long msr_addr;
static unsigned long msr_lo;
static unsigned long msr_hi;

long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op->cmd )
    {

    default:
        ret = -ENOSYS;

    }

    return ret;
}

void arch_getdomaininfo_ctxt(struct domain *d, full_execution_context_t *c)
{ 
    int i;

	dummy();
}
