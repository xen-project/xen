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
#include <asm/domain_page.h>                           /* [un]map_domain_mem */
#include <asm/pdb.h>

#undef DEBUG_TRACE
#ifdef DEBUG_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/****************************************************************************/

extern int pdb_change_values (int domain, u_char *buffer, unsigned long addr,
                              int length, int rw);
extern u_char pdb_linux_get_value (int domain, int pid, unsigned long addr);

/*
 * Set memory in a domain's address space
 * Set "length" bytes at "address" from "domain" to the values in "buffer".
 * Return the number of bytes set, 0 if there was a problem.
 *
 * THIS WILL BECOME A MACRO
 */

int pdb_set_values (int domain, u_char *buffer, unsigned long addr, int length)
{
    int count = pdb_change_values(domain, buffer, addr, length, 2);

    /* this is a bit x86 specific at the moment... */
    if (length == 1 && buffer[0] == 'c' && buffer[1] == 'c')
    {
        /* inserting a new breakpoint */
        pdb_bkpt_add(addr);
        TRC(printk("pdb breakpoint detected at 0x%lx\n", addr));
    }
    else if ( pdb_bkpt_remove(addr) == 0 )
    {
        /* removing a breakpoint */
        TRC(printk("pdb breakpoint cleared at 0x%lx\n", addr));
    }

    return count;
}

/*
 * Read memory from a domain's address space.
 * Fetch "length" bytes at "address" from "domain" into "buffer".
 * Return the number of bytes read, 0 if there was a problem.
 *
 * THIS WILL BECOME A MACRO
 */

int pdb_get_values (int domain, u_char *buffer, unsigned long addr, int length)
{
    return pdb_change_values(domain, buffer, addr, length, 1);
}

/*
 * Change memory in  a domain's address space.
 * Read or write "length" bytes at "address" from "domain" into/from "buffer".
 * Return the number of bytes read, 0 if there was a problem.
 * RW: 1 = read, 2 = write
 */

int pdb_change_values (int domain, u_char *buffer, unsigned long addr,
		       int length, int rw)
{
    struct task_struct *p;
    l2_pgentry_t* l2_table = NULL;
    l1_pgentry_t* l1_table = NULL;
    u_char *page;
    int bytes = 0;

    p = find_domain_by_id(domain);

    if ((addr >> PAGE_SHIFT) == ((addr + length - 1) >> PAGE_SHIFT))
    {
        l2_table = map_domain_mem(pagetable_val(p->mm.pagetable));
	l2_table += l2_table_offset(addr);
	if (!(l2_pgentry_val(*l2_table) & _PAGE_PRESENT)) 
	{
	    printk ("L2:0x%p (0x%lx) \n", l2_table, l2_pgentry_val(*l2_table));
	    goto exit2;
	}

	if (l2_pgentry_val(*l2_table) & _PAGE_PSE)
	{
#define PSE_PAGE_SHIFT           L2_PAGETABLE_SHIFT
#define PSE_PAGE_SIZE	         (1UL << PSE_PAGE_SHIFT)
#define PSE_PAGE_MASK	         (~(PSE_PAGE_SIZE-1))

#define L1_PAGE_BITS ( (ENTRIES_PER_L1_PAGETABLE - 1) << L1_PAGETABLE_SHIFT )

#define pse_pgentry_to_phys(_x) (l2_pgentry_val(_x) & PSE_PAGE_MASK)

	    page = map_domain_mem(pse_pgentry_to_phys(*l2_table) +/* 10 bits */
				  (addr & L1_PAGE_BITS));         /* 10 bits */
	    page += addr & (PAGE_SIZE - 1);                       /* 12 bits */
	}
	else
	{
	    l1_table = map_domain_mem(l2_pgentry_to_phys(*l2_table));
	    l1_table += l1_table_offset(addr); 
	    if (!(l1_pgentry_val(*l1_table) & _PAGE_PRESENT))
	    {
	        printk ("L2:0x%p (0x%lx) L1:0x%p (0x%lx)\n", 
			l2_table, l2_pgentry_val(*l2_table),
			l1_table, l1_pgentry_val(*l1_table));
		goto exit1;
	    }

	    page = map_domain_mem(l1_pgentry_to_phys(*l1_table));
	    page += addr & (PAGE_SIZE - 1);
	}

	switch (rw)
	{
	case 1:                                                      /* read */
	    memcpy (buffer, page, length);
	    bytes = length;
	    break;
	case 2:                                                     /* write */
	    hex2mem (buffer, page, length);
	    bytes = length;
	    break;
	default:                                                  /* unknown */
	    printk ("error: unknown RW flag: %d\n", rw);
	    return 0;
	}

	unmap_domain_mem((void *)page); 
    exit1:
	if (l1_table != NULL)
	    unmap_domain_mem((void *)l1_table);
    exit2:
	unmap_domain_mem((void *)l2_table);
    }
    else
    {
        /* read spans pages. need to recurse */
        printk ("pdb memory SPAN! addr:0x%lx l: %x\n", addr, length);
    }

    put_task_struct(p);
    return bytes;
}


/*
 * interactively call pervasive debugger from a privileged domain
 */
void pdb_do_debug (dom0_op_t *op)
{
    op->u.debug.status = 0;

    TRC(printk("PDB: op:%c, dom:%x, in1:%x, in2:%x, in3:%x, in4:%x\n",
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
        case 'r' :
        {
            int loop;
            u_char x;

            for (loop = 0; loop < op->u.debug.in2; loop++)         /* length */
            { 
                if (loop % 8 == 0)
                {
                    printk ("\n%08x ", op->u.debug.in1 + loop);
                }
                x = pdb_linux_get_value(op->u.debug.domain,        /* domain */
					op->u.debug.in3,             /* pid */
					op->u.debug.in1 + loop);     /* addr */
                printk (" %02x", x);
            }
            printk ("\n");
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
