/******************************************************************************
 * dom0_core.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>

#include "dom0_ops.h"

static struct proc_dir_entry *proc_dom0;

static unsigned char readbuf[1204];

static int dom0_read_proc(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
    strcpy(page, readbuf);
    *readbuf = '\0';
    *eof = 1;
    *start = page;
    return strlen(page);
}


static int dom0_write_proc(struct file *file, const char *buffer, 
                           u_long count, void *data)
{
    dom0_op_t op;
    unsigned char c;
    unsigned int val;
    unsigned char result[20];
    int len = count, ret;

    while ( count )
    {
        c = *buffer++;
        count--;
        val = 0;
        if ( c == 'N' )
        {
            op.cmd = DOM0_NEWDOMAIN;
            while ( count && ((c = *buffer) >= '0') && (c <= '9') )
            {
                val *= 10;
                val += c - '0';
                buffer++; count--;
            }      
            op.u.newdomain.memory_kb = val;
            val = 0;
            if (count && (*buffer == ',')) 
            { 
                buffer++; count--;
                while ( count && ((c = *buffer) >= '0') && (c <= '9') )
                {
                    val *= 10;
                    val += c - '0';
                    buffer++; count--;
                }
            } 
            else 
            {
                val = 1; // default to 1 vif.
            }
            op.u.newdomain.num_vifs = val;
            ret = HYPERVISOR_dom0_op(&op);
        }
        else if ( c == 'K' )
        {
            op.cmd = DOM0_KILLDOMAIN;
            while ( count && ((c = *buffer) >= '0') && (c <= '9') )
            {
                val *= 10;
                val += c - '0';
                buffer++; count--;
            }        
            op.u.killdomain.domain = val;
            ret = HYPERVISOR_dom0_op(&op);
        }
        else
        {
            ret = -ENOSYS;
        }
        
        sprintf(result, "%d\n", ret);
        strcat(readbuf, result);

        while ( count-- && (*buffer++ != '\n') ) continue;
    }

    return len;
}


static int __init init_module(void)
{
    *readbuf = '\0';
    proc_dom0 = create_proc_entry ("dom0", 0600, &proc_root);
    if ( proc_dom0 != NULL )
    {
        proc_dom0->owner      = THIS_MODULE;
        proc_dom0->nlink      = 1;
        proc_dom0->read_proc  = dom0_read_proc;
        proc_dom0->write_proc = dom0_write_proc;
        printk("Successfully installed domain-0 control interface\n");
    }
    return 0;
}


static void __exit cleanup_module(void)
{
    if ( proc_dom0 == NULL ) return;
    remove_proc_entry("dom0", &proc_root);
    proc_dom0 = NULL;
}


module_init(init_module);
module_exit(cleanup_module);
