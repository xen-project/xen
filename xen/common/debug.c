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
#include <asm/page.h>
#include <asm/pdb.h>

#undef DEBUG_TRACE
#ifdef DEBUG_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/****************************************************************************/

extern u_char pdb_linux_get_value(int pid, unsigned long cr3, 
				  unsigned long addr);

/*
 * interactively call pervasive debugger from a privileged domain
 */
void pdb_do_debug (dom0_op_t *op)
{
    op->u.debug.status = 0;

    TRC(printk("PDB: op:%c, dom:%llu, in1:%x, in2:%x, in3:%x, in4:%x\n",
	       op->u.debug.opcode, op->u.debug.domain,
	       op->u.debug.in1, op->u.debug.in2,
	       op->u.debug.in3, op->u.debug.in4));

    /* NOT NOW
    if (op->u.debug.domain == 0)
    {
        op->u.debug.status = 1;
	return;
    }
    */

    switch (op->u.debug.opcode)
    {
        case 'c' :
	{
	    struct task_struct * p = find_domain_by_id(op->u.debug.domain);
	    if ( p != NULL )
	    {
	        if ( test_bit(PF_CONSTRUCTED, &p->flags) )
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
        case 'r' :
        {
            int loop;
            u_char x;
	    unsigned long cr3;
	    struct task_struct *p;

	    p = find_domain_by_id(op->u.debug.domain);
	    cr3 = pagetable_val(p->mm.pagetable);

            for (loop = 0; loop < op->u.debug.in2; loop++)         /* length */
            { 
                if (loop % 8 == 0)
                {
                    printk ("\n%08x ", op->u.debug.in1 + loop);
                }
                x = pdb_linux_get_value(op->u.debug.in3,
					cr3, op->u.debug.in1 + loop);
                printk (" %02x", x);
            }
            printk ("\n");
	    put_task_struct(p);
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
