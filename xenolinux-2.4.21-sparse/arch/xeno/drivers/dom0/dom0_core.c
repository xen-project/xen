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
#include <linux/seq_file.h>

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

#define MAP_DISCONT     1

extern struct file_operations dom0_phd_fops;

struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *dom0_cmd_intf;
static struct proc_dir_entry *dom_list_intf;

unsigned long direct_mmap(unsigned long, unsigned long, pgprot_t, int, int);
int direct_unmap(unsigned long, unsigned long);

static ssize_t dom_usage_read(struct file * file, char * buff, size_t size, loff_t * off)
{
    char str[256];
    int vifs[32];
    dom0_op_t op;
    network_op_t netop;
    int i, end;
    unsigned int domain;
    static int finished = 0;

    if ( finished )
    {
        finished = 0;
        return 0;
    }

    domain = (unsigned int)
        ((struct proc_dir_entry *)file->f_dentry->d_inode->u.generic_ip)->data;
    op.cmd = DOM0_GETDOMAININFO;

    op.u.getdominfo.domain = domain;

    (void) HYPERVISOR_dom0_op(&op);

    end = snprintf(str, 256, "cpu: %lld\n", op.u.getdominfo.cpu_time);

    netop.cmd = NETWORK_OP_VIFQUERY;
    netop.u.vif_query.domain = domain;
    netop.u.vif_query.buf = vifs;

    (void) HYPERVISOR_network_op(&netop);

    for(i = 1; i <= vifs[0]; i++) {
        netop.cmd = NETWORK_OP_VIFGETINFO;
        netop.u.vif_getinfo.domain = domain;
        netop.u.vif_getinfo.vif = vifs[i];

        (void) HYPERVISOR_network_op(&netop);

        end += snprintf(str + end, 255 - end,
                        "vif%d: sent %lld bytes (%lld packets) "
                        "received %lld bytes (%lld packets)\n",
                        vifs[i],
                        netop.u.vif_getinfo.total_bytes_sent,
                        netop.u.vif_getinfo.total_packets_sent,
                        netop.u.vif_getinfo.total_bytes_received,
                        netop.u.vif_getinfo.total_packets_received);
    }

    if (*off >= end + 1) return 0;
    
    copy_to_user(buff, str, end);

    finished = 1;

    return end + 1;
}

struct file_operations dom_usage_ops = {
    read:    dom_usage_read
};


static void create_proc_dom_entries(int dom)
{
    struct proc_dir_entry * dir;
    dom_procdata_t * dom_data;
    char dir_name[16];
    struct proc_dir_entry * file;

    sprintf(dir_name, "dom%d", dom);

    dom_data = (dom_procdata_t *)kmalloc(sizeof(dom_procdata_t), GFP_KERNEL);
    dom_data->domain = dom;

    dir = proc_mkdir(dir_name, xeno_base);
    dir->data = dom_data;
    
    file = create_proc_entry("usage", 0600, dir);
    if (file != NULL)
    {
        file->owner         = THIS_MODULE;
        file->nlink         = 1;
        file->proc_fops     = &dom_usage_ops;
        file->data          = (void *) dom;
    }

    file = create_proc_entry("phd", 0600, dir);
    if (file != NULL)
    {
        file->owner         = THIS_MODULE;
        file->nlink         = 1;
        file->proc_fops     = &dom0_phd_fops;
        file->data          = (void *) dom;
    }
}

static ssize_t dom_mem_write(struct file * file, const char * buff, 
                             size_t size , loff_t * off)
{
    dom_mem_t mem_data;
    
    printk("dom_mem_write called: Shouldn't happen.\n");

    copy_from_user(&mem_data, (dom_mem_t *)buff, sizeof(dom_mem_t));
    
    if ( direct_unmap(mem_data.vaddr, 
                      mem_data.tot_pages << PAGE_SHIFT) == 0 ) {
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

    printk("Calling direct_mmap with pfn %x, tot pages %x.\n",
	   mem_data->pfn, mem_data->tot_pages);

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
	    /* XXX does this not leak the memdata? */
            remove_proc_entry("mem", pd);

            /* create new entry with parameters describing what to do
             * when it is mmaped.
             */
            file = create_proc_entry("mem", 0600, pd);
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

    remove_proc_entry("new_dom_data", xeno_base);

    kfree(dom_data);

    return sizeof(dom0_newdomain_t);
}

struct file_operations newdom_data_fops = {
    read:    dom_data_read,
};

static int dom0_cmd_write(struct file *file, const char *buffer, size_t size,
			  loff_t *off)
{
    dom0_op_t op;
    int ret = 0;
    
    copy_from_user(&op, buffer, sizeof(dom0_op_t));

    if ( op.cmd == MAP_DOM_MEM )
    {
        ret = dom_map_mem(op.u.dommem.domain, op.u.dommem.start_pfn, 
                          op.u.dommem.tot_pages); 
      /* This is now an ioctl, and shouldn't be being written to
	 the command file. */
	//      printk("map_dom_mem dom0_cmd used!\n");
	//      ret = -EOPNOTSUPP;
    }
    else if ( op.cmd == DO_PGUPDATES )
    {
        ret = HYPERVISOR_pt_update((void *)op.u.pgupdate.pgt_update_arr,
                                   op.u.pgupdate.num_pgt_updates);
    }
    else if (op.cmd == DOM0_CREATEDOMAIN)
    {
        /* This is now handled through an ioctl interface. Trying to
	   do it this way means the /proc files for the new domain
	   don't get created properly. */
        ret = -EOPNOTSUPP;
    }
    else
    {
        ret = HYPERVISOR_dom0_op(&op);
    }
    
    return ret;   
}

/***********************************************************************
 *
 * Implementation of /proc/xeno/domains
 */

static dom0_op_t proc_domains_op;
static int proc_domains_finished;
static rwlock_t proc_xeno_domains_lock = RW_LOCK_UNLOCKED;

static void *xeno_domains_next(struct seq_file *s, void *v, loff_t *pos)
{
    int ret;

    if ( pos != NULL )
        ++(*pos); 

    if ( !proc_domains_finished ) 
    {
        proc_domains_op.u.getdominfo.domain++;
        ret = HYPERVISOR_dom0_op(&proc_domains_op);
        if ( ret < 0 ) 
            proc_domains_finished = 1;
    }
  
    return (proc_domains_finished) ? NULL : &proc_domains_op;
}

static void *xeno_domains_start(struct seq_file *s, loff_t *ppos)
{ 
    loff_t pos = *ppos;
  
    write_lock (&proc_xeno_domains_lock);
    proc_domains_op.cmd = DOM0_GETDOMAININFO;
    proc_domains_op.u.getdominfo.domain = 0;
    (void)HYPERVISOR_dom0_op(&proc_domains_op);
    proc_domains_finished = 0;
  
    while (pos > 0) {
        pos --;
        xeno_domains_next (s, NULL, NULL);
    }
  
    return (proc_domains_finished) ? NULL : &proc_domains_op;
}

static void xeno_domains_stop(struct seq_file *s, void *v)
{ 
    write_unlock (&proc_xeno_domains_lock);
}

static int xeno_domains_show(struct seq_file *s, void *v)
{ 
    dom0_op_t *di = v;
  
    /*
     * Output one domain's details to dom0.
     *
     * If you update this format string then change xi_list to match.
     */

    seq_printf (s, 
                "%8d %2d %1d %2d %8d %8ld %p %8d %s\n",
                di -> u.getdominfo.domain, 
                di -> u.getdominfo.processor,
                di -> u.getdominfo.has_cpu,
                di -> u.getdominfo.state,
                di -> u.getdominfo.hyp_events,
                di -> u.getdominfo.mcu_advance,
                (void *)di -> u.getdominfo.pg_head,
                di -> u.getdominfo.tot_pages,
                di -> u.getdominfo.name);

    return 0;
}

struct seq_operations xeno_domains_op = {
    .start          = xeno_domains_start,
    .next           = xeno_domains_next,
    .stop           = xeno_domains_stop,
    .show           = xeno_domains_show,
};

static int xeno_domains_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &xeno_domains_op);
}

static struct file_operations proc_xeno_domains_operations = {
    open:           xeno_domains_open,
    read:           seq_read,
    llseek:         seq_lseek,
    release:        seq_release,
};

static int handle_dom0_cmd_createdomain(unsigned long data)
{
  struct dom0_createdomain_args argbuf;
  int namelen;
  dom0_op_t op;
  int ret;

  if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
    return -EFAULT;

  op.cmd = DOM0_CREATEDOMAIN;
  op.u.newdomain.domain = -666;
  op.u.newdomain.memory_kb = argbuf.kb_mem;
  op.u.newdomain.num_vifs = 0; /* Not used anymore, I hope... */
  namelen = strnlen_user(argbuf.name, MAX_DOMAIN_NAME);
  if (copy_from_user(op.u.newdomain.name, argbuf.name, namelen + 1))
    return -EFAULT;

  /* Error checking?  The old code deosn't appear to do any, and I
     can't see where the return values are documented... */
  ret = HYPERVISOR_dom0_op(&op);

  if (op.u.newdomain.domain == -666) {
    /* HACK: We use this to detect whether the create actually
       succeeded, because Xen doesn't appear to want to tell us... */

    /* The only time I've actually got this to happen was when trying
       to crate a domain with more memory than is actually in the
       machine, so we guess the error code is ENOMEM. */
    return -ENOMEM;
  }

  /* Create proc entries */
  ret = op.u.newdomain.domain;
  create_proc_dom_entries(ret);

  return ret;
}

static unsigned long handle_dom0_cmd_mapdommem(unsigned long data)
{
  struct dom0_mapdommem_args argbuf;
  unsigned long addr;

  if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
    return -EFAULT;
  /* This seems to be assuming that the root of the page table is in
     the first frame of the new domain's physical memory? */
  /* XXX do I really mean this? */
  /* XXX what happens if userspace forgets to do the unmap? */
  printk("direct_maping w/ start pfn %x, tot_pages %x.\n",
	 argbuf.start_pfn, argbuf.tot_pages);

  addr = direct_mmap(argbuf.start_pfn << PAGE_SHIFT,
		     argbuf.tot_pages << PAGE_SHIFT,
		     PAGE_SHARED,
		     MAP_DISCONT,
		     argbuf.tot_pages);

  printk("Picked vaddr %x.\n", addr);

  return addr;
}

static int handle_dom0_cmd_unmapdommem(unsigned long data)
{
  struct dom0_unmapdommem_args argbuf;

  if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
    return -EFAULT;

  return direct_disc_unmap(argbuf.vaddr, argbuf.start_pfn,
			   argbuf.tot_pages);
}

static int dom0_cmd_ioctl(struct inode *inode, struct file *file,
			  unsigned int cmd, unsigned long data)
{
  printk("dom0_cmd ioctl command %x\n", cmd);
  switch (cmd) {
  case IOCTL_DOM0_CREATEDOMAIN:
    return handle_dom0_cmd_createdomain(data);
  case IOCTL_DOM0_MAPDOMMEM:
    return handle_dom0_cmd_mapdommem(data);
  case IOCTL_DOM0_UNMAPDOMMEM:
    return handle_dom0_cmd_unmapdommem(data);
  default:
    printk("Unknown dom0_cmd ioctl!\n");
    return -EINVAL;
  }
}

/***********************************************************************/


static struct file_operations dom0_cmd_file_ops = {
  write : dom0_cmd_write,
  ioctl : dom0_cmd_ioctl
};

static int __init init_module(void)
{
    /* xeno proc root setup */
    xeno_base = proc_mkdir("xeno", &proc_root); 

    /* xeno control interface */
    dom0_cmd_intf = create_proc_entry("dom0_cmd", 0600, xeno_base);

    if ( dom0_cmd_intf != NULL )
    {
        dom0_cmd_intf->owner      = THIS_MODULE;
        dom0_cmd_intf->nlink      = 1;
	dom0_cmd_intf->proc_fops  = &dom0_cmd_file_ops;
    }

    /* domain list interface */
    dom_list_intf = create_proc_entry("domains", 0400, xeno_base);
    if ( dom_list_intf != NULL )
    {
        dom_list_intf->owner = THIS_MODULE;
        dom_list_intf->nlink = 1;
        dom_list_intf->proc_fops = &proc_xeno_domains_operations;
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
