/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: sched_ops.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Mar 2003
 * 
 * Environment: XenoLinux
 * Description: Dom0 Control interface to scheduler in Xen
 *
 * code based on Andy's vfr parsing code
 *
 * Commands understood by the interface:
 *
 * S <did> <mcu advance> [ <warp> <warp limit> <unwarp limit> ]
 * C <context swith allowance>
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */


#include <linux/proc_fs.h>
#include <asm/hypervisor.h>
#include "dom0_ops.h"

#define SCHED_ENTRY    "sched"
extern struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *sched_pde;


static int sched_read_proc(char *page, char **start, off_t off,
						   int count, int *eof, void *data)
{   
    strcpy(page, readbuf);
    *readbuf = '\0';
    *eof = 1;
    *start = page;
    return strlen(page);
}


static int sched_write_proc(struct file *file, const char *buffer,
							u_long count, void *data)
{
	dom0_op_t op;

	int ret, len;
	int ts, te, tl; /* token start, end, and length */

    /* Only admin can adjust scheduling parameters */
    if ( !capable(CAP_SYS_ADMIN) )
        return -EPERM;

	/* parse the commands  */
	len = count;
	ts = te = 0;

	while ( count && isspace(buffer[ts]) ) { ts++; count--; } // skip spaces.
	te = ts;
	if ( te <= ts ) goto bad;
	tl = te - ts;

	if ( strncmp(&buffer[ts], "S", tl) == 0 )
	{
		op.cmd = NETWORK_OP_ADDRULE;
	}
	else if ( strncmp(&buffer[ts], "C", tl) == 0 )
	{
		op.cmd = NETWORK_OP_DELETERULE;
	}


}


/*
 * main scheduler interface driver driver initialization function.
 */
static int __init init_module(void)
{
    printk(KERN_ALERT "Starting Domain Scheduler Control Interface\n");

    sched_pde = create_proc_entry(SCHED_ENTRY, 0600, xeno_base);
    if ( sched_pde == NULL )
    {
        printk(KERN_ALERT "Unable to create dom scheduler proc entry!");
        return -1;
    }

    sched_pde->read_proc  = sched_read_proc;
    sched_pde->write_proc = sched_write_proc;

    return 0;
}

static void __exit cleanup_module(void)
{
}

module_init(init_module);
module_exit(cleanup_module);

