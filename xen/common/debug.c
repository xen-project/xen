/*
 * debug.c
 *
 * xen pervasive debugger
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <xeno/sched.h>
#include <xeno/event.h>

#define DEBUG_TRACE
#ifdef DEBUG_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

void pdb_do_debug (dom0_op_t *op)
{
    op->u.debug.status = 0;
    op->u.debug.out1 = op->u.debug.in2 + 10;
    op->u.debug.out2 = op->u.debug.in1 + 100;

    TRC(printk("PDB: op:%c, dom:%x, in1:%x, in2:%x\n",
	       op->u.debug.opcode, op->u.debug.domain,
	       op->u.debug.in1, op->u.debug.in2));

    if (op->u.debug.domain == 0)
    {
        op->u.debug.status = 1;
	return;
    }

    switch (op->u.debug.opcode)
    {
        case 'r' :
	{
	    struct task_struct * p = find_domain_by_id(op->u.debug.domain);
	    if ( p != NULL )
	    {
	        if ( (p->flags & PF_CONSTRUCTED) != 0 )
		{
		    wake_up(p);
		    reschedule(p);
		}
		put_task_struct(p);
	    }
	    else
	    {
	        op->u.debug.status = 2;                    /* invalid domain */
	    }
	    break;
	}
        case 's' :
	{
	    unsigned long cpu_mask;
	    struct task_struct * p = find_domain_by_id(op->u.debug.domain);

	    if (p != NULL)
	    {
	        if (p->state != TASK_STOPPED)
		{
		    cpu_mask = mark_guest_event(p, _EVENT_STOP);
		    guest_event_notify(cpu_mask);
		}
		put_task_struct(p);
	    }
	    else
	    {
	        op->u.debug.status = 2;                    /* invalid domain */
	    }
	    break;
	}
        default :
	{
	    printk("PDB error: unknown debug opcode %c (0x%x)\n",
		   op->u.debug.opcode, op->u.debug.opcode);
	}
    }
    return;
}
