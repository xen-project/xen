/******************************************************************************
 * core.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002-2004, K A Fraser, B Dragovic
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
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
#include <asm/proc_cmd.h>
#include <asm/hypervisor-ifs/dom0_ops.h>
#include <asm/xen_proc.h>

static struct proc_dir_entry *privcmd_intf;

static int privcmd_ioctl(struct inode *inode, struct file *file,
                         unsigned int cmd, unsigned long data)
{
    int ret = -ENOSYS;

    switch ( cmd )
    {
    case IOCTL_PRIVCMD_HYPERCALL:
    {
        privcmd_hypercall_t hypercall;
  
        if ( copy_from_user(&hypercall, (void *)data, sizeof(hypercall)) )
            return -EFAULT;

        __asm__ __volatile__ (
            "pushl %%ebx; pushl %%ecx; pushl %%edx; pushl %%esi; pushl %%edi; "
            "movl  4(%%eax),%%ebx ;"
            "movl  8(%%eax),%%ecx ;"
            "movl 12(%%eax),%%edx ;"
            "movl 16(%%eax),%%esi ;"
            "movl 20(%%eax),%%edi ;"
            "movl   (%%eax),%%eax ;"
            TRAP_INSTR "; "
            "popl %%edi; popl %%esi; popl %%edx; popl %%ecx; popl %%ebx"
            : "=a" (ret) : "0" (&hypercall) : "memory" );

    }
    break;

    case IOCTL_PRIVCMD_MMAP:
    {
#define PRIVCMD_MMAP_SZ 32
	privcmd_mmap_t mmapcmd;
	privcmd_mmap_entry_t msg[PRIVCMD_MMAP_SZ], *p;
	int i, rc;

        if ( copy_from_user(&mmapcmd, (void *)data, sizeof(mmapcmd)) )
            return -EFAULT;

	p = mmapcmd.entry;

	for (i=0; i<mmapcmd.num; i+=PRIVCMD_MMAP_SZ, p+=PRIVCMD_MMAP_SZ)
	{
	    int j, n = ((mmapcmd.num-i)>PRIVCMD_MMAP_SZ)?
		PRIVCMD_MMAP_SZ:(mmapcmd.num-i);
	    if ( copy_from_user(&msg, p, n*sizeof(privcmd_mmap_entry_t)) )
		return -EFAULT;
	    
	    for (j=0;j<n;j++)
	    {
		struct vm_area_struct *vma = 
		    find_vma( current->mm, msg[j].va );

		if (!vma)
		    return -EINVAL;

		if (msg[j].va > PAGE_OFFSET)
		    return -EINVAL;

		if (msg[j].va + (msg[j].npages<<PAGE_SHIFT) > vma->vm_end)
		    return -EINVAL;

		if (rc = direct_remap_area_pages(vma->vm_mm, 
					    msg[j].va&PAGE_MASK, 
					    msg[j].mfn<<PAGE_SHIFT, 
					    msg[j].npages<<PAGE_SHIFT, 
					    vma->vm_page_prot,
					    mmapcmd.dom))
		    return rc;
	    }
	}
	ret = 0;
    }
    break;

    case IOCTL_PRIVCMD_INITDOMAIN_EVTCHN:
    {
        extern int initdom_ctrlif_domcontroller_port;
        ret = initdom_ctrlif_domcontroller_port;
    }
    break;
    
    default:
        ret = -EINVAL;
    	break;
    }
    return ret;
}

static int privcmd_mmap(struct file * file, struct vm_area_struct * vma)
{
printk(KERN_ALERT"privcmd_mmap\n");
	/* DONTCOPY is essential for Xen as copy_page_range is broken. */
	vma->vm_flags |= VM_RESERVED | VM_IO | VM_DONTCOPY;

	return 0;
}

static struct file_operations privcmd_file_ops = {
  ioctl : privcmd_ioctl,
  mmap:   privcmd_mmap
};


static int __init init_module(void)
{
    if ( !(start_info.flags & SIF_PRIVILEGED) )
        return 0;

    privcmd_intf = create_xen_proc_entry("privcmd", 0400);
    if ( privcmd_intf != NULL )
    {
        privcmd_intf->owner      = THIS_MODULE;
        privcmd_intf->nlink      = 1;
        privcmd_intf->proc_fops  = &privcmd_file_ops;
    }

    return 0;
}


static void __exit cleanup_module(void)
{
    if ( privcmd_intf == NULL ) return;
    remove_xen_proc_entry("privcmd");
    privcmd_intf = NULL;
}


module_init(init_module);
module_exit(cleanup_module);
