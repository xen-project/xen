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
#include "hypervisor_defs.h"

#define XENO_BASE       "xeno"          // proc file name defs should be in separate .h
#define DOM0_CMD_INTF   "dom0_cmd"
#define DOM0_FT         "frame_table"
#define DOM0_NEWDOM     "new_dom_id"

#define MAX_LEN         16
#define DOM_DIR         "dom"
#define DOM_TS          "task_data"
#define DOM_MEM         "mem"

static struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *dom0_cmd_intf;
static struct proc_dir_entry *proc_ft;

unsigned long direct_mmap(unsigned long, unsigned long, pgprot_t, int, int);
int direct_unmap(unsigned long, unsigned long);
int direct_disc_unmap(unsigned long, unsigned long, int);

/* frame_table mapped from dom0 */
frame_table_t * frame_table;
unsigned long frame_table_len;
unsigned long frame_table_pa;

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

static ssize_t ts_read(struct file * file, char * buff, size_t size, loff_t * off)
{
    dom0_op_t op;
    unsigned long addr;
    pgprot_t prot;
    int ret = 0;

    /* retrieve domain specific data from proc_dir_entry */
    dom_procdata_t * dom_data = (dom_procdata_t *)((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;
    
    /* 
     * get the phys addr of the task struct for the requested
     * domain
     */
    op.cmd = DOM0_MAPTASK;
    op.u.mapdomts.domain = dom_data->domain;
    op.u.mapdomts.ts_phy_addr = -1;

    ret = HYPERVISOR_dom0_op(&op);
    if(ret != 0)
       return -EAGAIN;

    prot = PAGE_SHARED; 

    /* remap the range using xen specific routines */
    addr = direct_mmap(op.u.mapdomts.ts_phy_addr, PAGE_SIZE, prot, 0, 0);
    copy_to_user((unsigned long *)buff, &addr, sizeof(addr));
    dom_data->map_size = PAGE_SIZE;

    return sizeof(addr);
     
}

static ssize_t ts_write(struct file * file, const char * buff, size_t size , loff_t * off)
{
    unsigned long addr;
    dom_procdata_t * dom_data = (dom_procdata_t *)((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;
    
    copy_from_user(&addr, (unsigned long *)buff, sizeof(addr));
    
    if(direct_unmap(addr, dom_data->map_size) == 0){
        return sizeof(addr);
    } else {
        return -1;
    }
}
 
struct file_operations ts_ops = {
    read:   ts_read,
    write:  ts_write,
};

static void create_proc_dom_entries(int dom)
{
    struct proc_dir_entry * dir;
    struct proc_dir_entry * file;
    dom_procdata_t * dom_data;
    char dir_name[MAX_LEN];

    snprintf(dir_name, MAX_LEN, "%s%d", DOM_DIR, dom);

    dom_data = (dom_procdata_t *)kmalloc(sizeof(proc_domdata_t), GFP_KERNEL);
    dom_data->domain = dom;

    dir = proc_mkdir(dir_name, xeno_base);
    dir->data = dom_data;

    file = create_proc_entry(DOM_TS, 0600, dir);
    if(file != NULL)
    {   
        file->owner = THIS_MODULE;
        file->nlink = 1;
        file->proc_fops = &ts_ops;
    
        file->data = dom_data;
    }
}

static ssize_t dom_mem_write(struct file * file, const char * buff, 
	size_t size , loff_t * off)
{
    unsigned long addr;
    proc_memdata_t * mem_data = (proc_memdata_t *)((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;
    
    copy_from_user(&addr, (unsigned long *)buff, sizeof(addr));
    
    if(direct_disc_unmap(addr, mem_data->pfn, mem_data->tot_pages) == 0){
        return sizeof(addr);
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

    addr = direct_mmap(mem_data->pfn << PAGE_SHIFT, mem_data->tot_pages << PAGE_SHIFT, prot, 0, 0);
	printk(KERN_ALERT "bd240 debug: dom_mem_read: %lx, %lx @ %lx\n", mem_data->pfn << PAGE_SHIFT, mem_data->tot_pages << PAGE_SHIFT, addr);

    //addr = direct_mmap(mem_data->pfn, mem_data->tot_pages << PAGE_SHIFT, prot, 1, 
    //                mem_data->tot_pages);
    copy_to_user((unsigned long *)buff, &addr, sizeof(addr));

	printk(KERN_ALERT "bd240 debug: exiting dom_mem_read\n");

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

				printk(KERN_ALERT "bd240 debug: cmd setup dom mem: %lx, %d\n", memdata->pfn, memdata->tot_pages);

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

/* return dom id stored as data pointer to userspace */
static int dom_id_read_proc(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
    char arg[16];
    sprintf(arg, "%d", (int)data);
    strcpy(page, arg);
    remove_proc_entry(DOM0_NEWDOM, xeno_base);
    return sizeof(unsigned int);
}

static int cmd_write_proc(struct file *file, const char *buffer, 
                           u_long count, void *data)
{
    dom0_op_t op;
    int ret = 0;
    struct proc_dir_entry * new_dom_id;
    
    copy_from_user(&op, buffer, sizeof(dom0_op_t));

    /* do some sanity checks */
    if(op.cmd > MAX_CMD){
        ret = -ENOSYS;
        goto out;
    }

    /* is the request intended for hypervisor? */
    if(op.cmd != MAP_DOM_MEM){
        ret = HYPERVISOR_dom0_op(&op);

        /* if new domain created, create proc entries */
        if(op.cmd == DOM0_NEWDOMAIN){
            create_proc_dom_entries(ret);

            /* now notify user space of the new domain's id */
            new_dom_id = create_proc_entry(DOM0_NEWDOM, 0600, xeno_base);
            if ( new_dom_id != NULL )
            {
                new_dom_id->owner      = THIS_MODULE;
                new_dom_id->nlink      = 1;
                new_dom_id->read_proc  = dom_id_read_proc; 
                new_dom_id->data       = (void *)ret; 
            }

        }

    } else {

        ret = dom_map_mem(op.u.reqdommem.domain, op.u.reqdommem.start_pfn, 
                        op.u.reqdommem.tot_pages); 
    }
    
out:
    return ret;
    
}

static ssize_t ft_write(struct file * file, const char * buff, size_t size , loff_t * off)
{
    unsigned long addr;
    
    copy_from_user(&addr, (unsigned long *)buff, sizeof(addr));
    
    if(direct_unmap(addr, frame_table_len) == 0){
        return sizeof(addr);
    } else {
        return -1;
    }
}

static ssize_t ft_read(struct file * file, char * buff, size_t size, loff_t * off)
{
    unsigned long addr;
    pgprot_t prot;

    prot = PAGE_SHARED; 

    /* remap the range using xen specific routines */
    addr = direct_mmap(frame_table_pa, frame_table_len, prot, 0, 0);
    copy_to_user((unsigned long *)buff, &addr, sizeof(addr));

    return sizeof(addr);
     
}

struct file_operations ft_ops = {
    read:   ft_read,
    write: ft_write,
};

static int __init init_module(void)
{
    
    frame_table = (frame_table_t *)start_info.frame_table;
    frame_table_len = start_info.frame_table_len;
    frame_table_pa = start_info.frame_table_pa;

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

    /* frame table mapping, to be mmaped */
    proc_ft = create_proc_entry(DOM0_FT, 0600, xeno_base);
    if(proc_ft != NULL)
    {   
        proc_ft->owner = THIS_MODULE;
        proc_ft->nlink = 1;
        proc_ft->proc_fops = &ft_ops;
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
