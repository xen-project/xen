/*
 * debug.c
 *
 * xen pervasive debugger
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/page.h>
#include <asm/pdb.h>
#include <asm/shadow.h>

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
	    struct domain *d = find_domain_by_id(op->u.debug.domain);
	    if ( d != NULL )
	    {
                domain_unpause_by_systemcontroller(d);
		put_domain(d);
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
	    struct domain *d;

	    d = find_domain_by_id(op->u.debug.domain);
	    if ( shadow_mode(d) )
	      cr3 = pagetable_val(d->mm.shadow_table);
	    else
	      cr3 = pagetable_val(d->mm.pagetable);

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
	    put_domain(d);
            break;
        }
        case 's' :
	{
	    struct domain *d = find_domain_by_id(op->u.debug.domain);

	    if ( d != NULL )
	    {
                domain_pause_by_systemcontroller(d);
		put_domain(d);
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
}
