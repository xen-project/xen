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
#include <asm/dom0.h>

#include "dom0_ops.h"

#define MAP_DISCONT 1

/* Private proc-file data structures. */
typedef struct proc_data {
    unsigned int domain;
    unsigned long map_size;
} dom_procdata_t;

/* XXX this certainly shouldn't be here. */
extern struct file_operations dom0_phd_fops;

struct proc_dir_entry *xeno_base;
static struct proc_dir_entry *dom0_cmd_intf;
static struct proc_dir_entry *dom_list_intf;

int direct_unmap(struct mm_struct *, unsigned long, unsigned long);
unsigned long direct_mmap(unsigned long phys_addr, unsigned long size, 
			  pgprot_t prot, int flag, int tot_pages);
struct list_head * find_direct(struct list_head *, unsigned long);

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

static struct file_operations dom_usage_ops = {
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

/***********************************************************************
 *
 * Implementation of /proc/xeno/domains
 */

static dom0_op_t proc_domains_op;
static int proc_domains_finished;
static DECLARE_MUTEX(proc_xeno_domains_lock);

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
  
    down (&proc_xeno_domains_lock);
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
    up(&proc_xeno_domains_lock);
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

static struct seq_operations xeno_domains_op = {
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

/***********************************************************************
 *
 * Implementation of /proc/xeno/dom0_cmd
 */

static int dom0_cmd_write(struct file *file, const char *buffer, size_t size,
			  loff_t *off)
{
    dom0_op_t op;
    
    copy_from_user(&op, buffer, sizeof(dom0_op_t));

    return HYPERVISOR_dom0_op(&op);
}

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
  op.u.newdomain.num_vifs = 0; /* Not used anymore -- it's done in
				  BUILDDOMAIN. */
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
       to create a domain with more memory than is actually in the
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

  if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
    return -EFAULT;

  return direct_mmap(argbuf.start_pfn << PAGE_SHIFT,
		     argbuf.tot_pages << PAGE_SHIFT,
		     PAGE_SHARED,
		     MAP_DISCONT,
		     argbuf.tot_pages);
}

static int handle_dom0_cmd_unmapdommem(unsigned long data)
{
  struct dom0_unmapdommem_args argbuf;

  if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
    return -EFAULT;

  return direct_unmap(current->mm, argbuf.vaddr,
		      argbuf.tot_pages << PAGE_SHIFT);
}

static int handle_dom0_cmd_dopgupdates(unsigned long data)
{
    struct dom0_dopgupdates_args argbuf;
    struct list_head *entry;
    direct_mmap_node_t *node;

    if (copy_from_user(&argbuf, (void *)data, sizeof(argbuf)))
	return -EFAULT;

    /* argbuf.pgt_update_arr had better be direct mapped... */
    entry = find_direct(&current->mm->context.direct_list,
			argbuf.pgt_update_arr);
    if (entry == &current->mm->context.direct_list)
	return -EINVAL;
    node = list_entry(entry, direct_mmap_node_t, list);
    if (node->vm_start > argbuf.pgt_update_arr ||
	node->vm_end <= argbuf.pgt_update_arr * sizeof(page_update_request_t))
	return -EINVAL;
    
    return HYPERVISOR_pt_update((void *)argbuf.pgt_update_arr,
				argbuf.num_pgt_updates);
}

static int dom0_cmd_ioctl(struct inode *inode, struct file *file,
			  unsigned int cmd, unsigned long data)
{
  switch (cmd) {
  case IOCTL_DOM0_CREATEDOMAIN:
    return handle_dom0_cmd_createdomain(data);
  case IOCTL_DOM0_MAPDOMMEM:
    return handle_dom0_cmd_mapdommem(data);
  case IOCTL_DOM0_UNMAPDOMMEM:
    return handle_dom0_cmd_unmapdommem(data);
  case IOCTL_DOM0_DOPGUPDATES:
    return handle_dom0_cmd_dopgupdates(data);
  default:
    return -ENOTTY; /* It isn't obvious why this is the correct error
		       code when an ioctl isn't recognised, but it
		       does appear to be what's used in the rest of
		       the kernel. */
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
