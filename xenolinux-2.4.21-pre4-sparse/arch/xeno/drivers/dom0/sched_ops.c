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
 * C <context swith allowance>
 * S <did> <mcu advance> <warp> <warp limit> <unwarp limit>
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>

#include "dom0_ops.h"

#define SCHED_ENTRY    "sched"
extern struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *sched_pde;

static unsigned char readbuf[1024];

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

    while ( count && isspace(buffer[ts]) ) { ts++; count--; } /*skip spaces*/
    te = ts;
    while ( count && !isspace(buffer[te]) ) { te++; count--; } /*command end*/
    if ( te <= ts ) goto bad;
    tl = te - ts;

    if ( strncmp(&buffer[ts], "C", tl) == 0 ) {
        op.cmd = DOM0_BVTCTL;
    } else if ( strncmp(&buffer[ts], "S", tl) == 0 ) {
        op.cmd = DOM0_ADJUSTDOM;
    } else
        goto bad;

    /* skip whitspaces and get first parameter */
    ts = te; while ( count &&  isspace(buffer[ts]) ) { ts++; count--; }
    te = ts; while ( count && !isspace(buffer[te]) ) { te++; count--; }
    if ( te <= ts ) goto bad;
    tl = te - ts;
    if ( !isdigit(buffer[ts]) ) goto bad;

    if (op.cmd == DOM0_BVTCTL) {
        /* get context switch allowance  */
        sscanf(&buffer[ts], "%lu", &op.u.bvtctl.ctx_allow);
    } else if (op.cmd == DOM0_ADJUSTDOM) {
        sscanf(&buffer[ts], "%u %lu %lu %lu %lu",
               &op.u.adjustdom.domain,
               &op.u.adjustdom.mcu_adv,
               &op.u.adjustdom.warp,
               &op.u.adjustdom.warpl,
               &op.u.adjustdom.warpu);
    }
    ret = HYPERVISOR_dom0_op(&op);
    return sizeof(op);
    
 bad:
    return -EINVAL;

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

