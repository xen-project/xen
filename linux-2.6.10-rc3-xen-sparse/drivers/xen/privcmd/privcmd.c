/******************************************************************************
 * privcmd.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002-2004, K A Fraser, B Dragovic
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm-xen/linux-public/privcmd.h>
#include <asm-xen/xen-public/dom0_ops.h>
#include <asm-xen/xen_proc.h>

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

    case IOCTL_PRIVCMD_INITDOMAIN_EVTCHN:
    {
        extern int initdom_ctrlif_domcontroller_port;
        ret = initdom_ctrlif_domcontroller_port;
    }
    break;
    
#if defined(CONFIG_XEN_PRIVILEGED_GUEST)
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
     
            for ( j = 0; j < n; j++ )
            {
                struct vm_area_struct *vma = 
                    find_vma( current->mm, msg[j].va );

                if ( !vma )
                    return -EINVAL;

                if ( msg[j].va > PAGE_OFFSET )
                    return -EINVAL;

                if ( (msg[j].va + (msg[j].npages<<PAGE_SHIFT)) > vma->vm_end )
                    return -EINVAL;

                if ( (rc = direct_remap_area_pages(vma->vm_mm, 
                                                   msg[j].va&PAGE_MASK, 
                                                   msg[j].mfn<<PAGE_SHIFT, 
                                                   msg[j].npages<<PAGE_SHIFT, 
                                                   vma->vm_page_prot,
                                                   mmapcmd.dom)) < 0 )
                    return rc;
            }
        }
        ret = 0;
    }
    break;

    case IOCTL_PRIVCMD_MMAPBATCH:
    {
#define MAX_DIRECTMAP_MMU_QUEUE 130
        mmu_update_t u[MAX_DIRECTMAP_MMU_QUEUE], *w, *v;
        privcmd_mmapbatch_t m;
        struct vm_area_struct *vma = NULL;
        unsigned long *p, addr;
        unsigned long mfn;
        int i;

        if ( copy_from_user(&m, (void *)data, sizeof(m)) )
        { ret = -EFAULT; goto batch_err; }

        vma = find_vma( current->mm, m.addr );

        if ( !vma )
        { ret = -EINVAL; goto batch_err; }

        if ( m.addr > PAGE_OFFSET )
        { ret = -EFAULT; goto batch_err; }

        if ( (m.addr + (m.num<<PAGE_SHIFT)) > vma->vm_end )
        { ret = -EFAULT; goto batch_err; }

        u[0].ptr  = MMU_EXTENDED_COMMAND;
        u[0].val  = MMUEXT_SET_FOREIGNDOM;
        u[0].val |= (unsigned long)m.dom << 16;
        v = w = &u[1];

        p = m.arr;
        addr = m.addr;
        for ( i = 0; i < m.num; i++, addr += PAGE_SIZE, p++ )
        {
            if ( get_user(mfn, p) )
                return -EFAULT;

            v->val = (mfn << PAGE_SHIFT) | pgprot_val(vma->vm_page_prot);

            __direct_remap_area_pages(vma->vm_mm,
                                      addr, 
                                      PAGE_SIZE, 
                                      v);

            if ( unlikely(HYPERVISOR_mmu_update(u, v - u + 1, NULL) < 0) )
                put_user( 0xF0000000 | mfn, p );

            v = w;
        }
        ret = 0;
        break;

    batch_err:
        printk("batch_err ret=%d vma=%p addr=%lx num=%d arr=%p %lx-%lx\n", 
               ret, vma, m.addr, m.num, m.arr, vma->vm_start, vma->vm_end);
        break;
    }
    break;
#endif

    case IOCTL_PRIVCMD_GET_MACH2PHYS_START_MFN:
    {
	unsigned long m2p_start_mfn = 
	    HYPERVISOR_shared_info->arch.mfn_to_pfn_start;

	if( put_user( m2p_start_mfn, (unsigned long *) data ) )
	    ret = -EFAULT;
	else
	    ret = 0;
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
    /* DONTCOPY is essential for Xen as copy_page_range is broken. */
    vma->vm_flags |= VM_RESERVED | VM_IO | VM_DONTCOPY;

    return 0;
}

static struct file_operations privcmd_file_ops = {
    ioctl : privcmd_ioctl,
    mmap:   privcmd_mmap
};


static int __init privcmd_init(void)
{
    if ( !(xen_start_info.flags & SIF_PRIVILEGED) )
        return 0;

    privcmd_intf = create_xen_proc_entry("privcmd", 0400);
    if ( privcmd_intf != NULL )
        privcmd_intf->proc_fops = &privcmd_file_ops;

    return 0;
}

__initcall(privcmd_init);
