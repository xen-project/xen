/******************************************************************************
 * dom0_core.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002, K A Fraser, B Dragovic
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/swapctl.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>

#include "dom0_ops.h"

/* Private proc-file data structures. */
typedef struct proc_data {
    unsigned int domain;
    unsigned long map_size;
} dom_procdata_t;

typedef struct proc_mem_data {
    unsigned long pfn;
    int tot_pages;
} proc_memdata_t;

#define XENO_BASE       "xeno"
#define DOM0_CMD_INTF   "dom0_cmd"
#define DOM0_NEWDOM     "new_dom_data"

#define MAX_LEN         16
#define DOM_DIR         "dom"
#define DOM_MEM         "mem"

#define MAP_DISCONT     1

static struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *dom0_cmd_intf;
static struct proc_dir_entry *proc_ft;

unsigned long direct_mmap(unsigned long, unsigned long, pgprot_t, int, int);
int direct_unmap(unsigned long, unsigned long);
int direct_disc_unmap(unsigned long, unsigned long, int);

static unsigned char readbuf[1204];

static int cmd_read_proc(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
    strcpy(page, readbuf);
    *readbuf = '\0';
    *eof = 1;
    *start = page;
    return strlen(page);
}

static void create_proc_dom_entries(int dom)
{
    struct proc_dir_entry * dir;
    dom_procdata_t * dom_data;
    char dir_name[MAX_LEN];

    snprintf(dir_name, MAX_LEN, "%s%d", DOM_DIR, dom);

    dom_data = (dom_procdata_t *)kmalloc(sizeof(dom_procdata_t), GFP_KERNEL);
    dom_data->domain = dom;

    dir = proc_mkdir(dir_name, xeno_base);
    dir->data = dom_data;
}

static ssize_t dom_mem_write(struct file * file, const char * buff, 
	size_t size , loff_t * off)
{
    dom_mem_t mem_data;
    
    copy_from_user(&mem_data, (dom_mem_t *)buff, sizeof(dom_mem_t));
    
    if(direct_disc_unmap(mem_data.vaddr, mem_data.start_pfn, 
        mem_data.tot_pages) == 0){
        return sizeof(sizeof(dom_mem_t));
    } else {
        return -1;
    }
}

static ssize_t dom_mem_read(struct file * file, char * buff, size_t size, loff_t * off)
{
    unsigned long addr;
    pgprot_t prot;

    proc_memdata_t * mem_data = (proc_memdata_t *)((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;

    prot = PAGE_SHARED; 

    /* remap the range using xen specific routines */

    addr = direct_mmap(mem_data->pfn << PAGE_SHIFT, mem_data->tot_pages << PAGE_SHIFT, prot, MAP_DISCONT, mem_data->tot_pages);
    
    copy_to_user((unsigned long *)buff, &addr, sizeof(addr));

    return sizeof(addr);
}

struct file_operations dom_mem_ops = {
    read:    dom_mem_read,
    write:   dom_mem_write,
};

static int dom_map_mem(unsigned int dom, unsigned long pfn, int tot_pages)
{
    int ret = -ENOENT;
    struct proc_dir_entry * pd = xeno_base->subdir;
    struct proc_dir_entry * file;
    proc_memdata_t * memdata;

    while(pd != NULL){

        if((pd->mode & S_IFDIR) && ((dom_procdata_t *)pd->data)->domain == dom){

            /* check if there is already an entry for mem and if so
             * remove it.
             */
            remove_proc_entry(DOM_MEM, pd);

            /* create new entry with parameters describing what to do
             * when it is mmaped.
             */
            file = create_proc_entry(DOM_MEM, 0600, pd);
            if(file != NULL)
            {
                file->owner = THIS_MODULE;
                file->nlink = 1;
                file->proc_fops = &dom_mem_ops;

                memdata = (proc_memdata_t *)kmalloc(sizeof(proc_memdata_t), GFP_KERNEL);
                memdata->pfn = pfn;
                memdata->tot_pages = tot_pages;
                file->data = memdata;

                ret = 0;
                break;
            }
            ret = -EAGAIN;
            break;
        }                    
        pd = pd->next;
    }

    return ret;
}

/* function used to retrieve data associated with new domain */
static ssize_t dom_data_read(struct file * file, char * buff, size_t size, loff_t * off)
{
    dom0_newdomain_t * dom_data = (dom0_newdomain_t *)
        ((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;

    copy_to_user((dom0_newdomain_t *)buff, dom_data, sizeof(dom0_newdomain_t));

    remove_proc_entry(DOM0_NEWDOM, xeno_base);

    kfree(dom_data);

    return sizeof(dom0_newdomain_t);
}

struct file_operations newdom_data_fops = {
    read:    dom_data_read,
};

static int cmd_write_proc(struct file *file, const char *buffer, 
                           u_long count, void *data)
{
    dom0_op_t op;
    int ret = 0;
    struct proc_dir_entry * new_dom_id;
    dom0_newdomain_t * params;

    
    copy_from_user(&op, buffer, sizeof(dom0_op_t));

    /* do some sanity checks */
    if(op.cmd > MAX_CMD){
        ret = -ENOSYS;
        goto out;
    }

    if ( op.cmd == MAP_DOM_MEM )
    {
        ret = dom_map_mem(op.u.dommem.domain, op.u.dommem.start_pfn, 
                        op.u.dommem.tot_pages); 
    }
    else if ( op.cmd == DO_PGUPDATES )
    {
        ret = HYPERVISOR_pt_update((void *)op.u.pgupdate.pgt_update_arr,
                                   op.u.pgupdate.num_pgt_updates);
    }
    else
    {
        ret = HYPERVISOR_dom0_op(&op);

        /* if new domain created, create proc entries */
        if(op.cmd == DOM0_NEWDOMAIN){
            create_proc_dom_entries(ret);

            params = (dom0_newdomain_t *)kmalloc(sizeof(dom0_newdomain_t),
                GFP_KERNEL);
            params->memory_kb = op.u.newdomain.memory_kb;
            params->pg_head = op.u.newdomain.pg_head;
            params->num_vifs = op.u.newdomain.num_vifs;
            params->domain = op.u.newdomain.domain;

            /* now notify user space of the new domain's id */
            new_dom_id = create_proc_entry(DOM0_NEWDOM, 0600, xeno_base);
            if ( new_dom_id != NULL )
            {
                new_dom_id->owner      = THIS_MODULE;
                new_dom_id->nlink      = 1;
                new_dom_id->proc_fops  = &newdom_data_fops; 
                new_dom_id->data       = (void *)params; 
            }

        }

    }
    
out:
    return ret;
    
}

static int __init init_module(void)
{
    /* xeno proc root setup */
    xeno_base = proc_mkdir(XENO_BASE, &proc_root); 

    /* xeno control interface */
    *readbuf = '\0';
    dom0_cmd_intf = create_proc_entry (DOM0_CMD_INTF, 0600, xeno_base);
    if ( dom0_cmd_intf != NULL )
    {
        dom0_cmd_intf->owner      = THIS_MODULE;
        dom0_cmd_intf->nlink      = 1;
        dom0_cmd_intf->read_proc  = cmd_read_proc;
        dom0_cmd_intf->write_proc = cmd_write_proc;
    }

    /* set up /proc entries for dom 0 */
    create_proc_dom_entries(0);

    return 0;
}


static void __exit cleanup_module(void)
{
    if ( dom0_cmd_intf == NULL ) return;
    remove_proc_entry("dom0", &proc_root);
    dom0_cmd_intf = NULL;
}


module_init(init_module);
module_exit(cleanup_module);
