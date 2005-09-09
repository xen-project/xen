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
#include <linux/kthread.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm-xen/linux-public/privcmd.h>
#include <asm-xen/xen-public/dom0_ops.h>
#include <asm-xen/xen_proc.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define pud_t pgd_t
#define pud_offset(d, va) d
#endif

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

#if defined(__i386__)
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
#elif defined (__x86_64__)
        {
            long ign1, ign2, ign3;
            __asm__ __volatile__ (
                "movq %8,%%r10; movq %9,%%r8;" TRAP_INSTR
                : "=a" (ret), "=D" (ign1), "=S" (ign2), "=d" (ign3)
                : "0" ((unsigned long)hypercall.op), 
                "1" ((unsigned long)hypercall.arg[0]), 
                "2" ((unsigned long)hypercall.arg[1]),
                "3" ((unsigned long)hypercall.arg[2]), 
                "g" ((unsigned long)hypercall.arg[3]),
                "g" ((unsigned long)hypercall.arg[4])
                : "r11","rcx","r8","r10","memory");
        }
#endif
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

                if ( (rc = direct_remap_pfn_range(vma->vm_mm, 
                                                   msg[j].va&PAGE_MASK, 
                                                   msg[j].mfn, 
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
        mmu_update_t u;
        privcmd_mmapbatch_t m;
        struct vm_area_struct *vma = NULL;
        unsigned long *p, addr;
        unsigned long mfn, ptep;
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

        p = m.arr;
        addr = m.addr;
        for ( i = 0; i < m.num; i++, addr += PAGE_SIZE, p++ )
        {
            if ( get_user(mfn, p) )
                return -EFAULT;

            ret = create_lookup_pte_addr(vma->vm_mm, addr, &ptep);
            if (ret)
                goto batch_err;

            u.val = pte_val_ma(pfn_pte_ma(mfn, vma->vm_page_prot));
            u.ptr = ptep;

            if ( unlikely(HYPERVISOR_mmu_update(&u, 1, NULL, m.dom) < 0) )
                put_user(0xF0000000 | mfn, p);
        }

        ret = 0;
        break;

    batch_err:
        printk("batch_err ret=%d vma=%p addr=%lx num=%d arr=%p %lx-%lx\n", 
               ret, vma, m.addr, m.num, m.arr,
               vma ? vma->vm_start : 0, vma ? vma->vm_end : 0);
        break;
    }
    break;
#endif

    case IOCTL_PRIVCMD_GET_MACH2PHYS_START_MFN:
    {
        unsigned long m2pv = (unsigned long)machine_to_phys_mapping;
        pgd_t *pgd = pgd_offset_k(m2pv);
        pud_t *pud = pud_offset(pgd, m2pv);
        pmd_t *pmd = pmd_offset(pud, m2pv);
        unsigned long m2p_start_mfn = (*(unsigned long *)pmd) >> PAGE_SHIFT; 
        ret = put_user(m2p_start_mfn, (unsigned long *)data) ? -EFAULT: 0;
    }
    break;

    case IOCTL_PRIVCMD_INITDOMAIN_STORE:
    {
        extern int do_xenbus_probe(void*);
        unsigned long page;

        if (xen_start_info->store_evtchn != 0) {
            ret = xen_start_info->store_mfn;
            break;
        }

        /* Allocate page. */
        page = get_zeroed_page(GFP_KERNEL);
        if (!page) {
            ret = -ENOMEM;
            break;
        }

        /* We don't refcnt properly, so set reserved on page.
         * (this allocation is permanent) */
        SetPageReserved(virt_to_page(page));

        /* Initial connect. Setup channel and page. */
        xen_start_info->store_evtchn = data;
        xen_start_info->store_mfn = pfn_to_mfn(virt_to_phys((void *)page) >>
                                              PAGE_SHIFT);
        ret = xen_start_info->store_mfn;

        /* We'll return then this will wait for daemon to answer */
        kthread_run(do_xenbus_probe, NULL, "xenbus_probe");
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
    privcmd_intf = create_xen_proc_entry("privcmd", 0400);
    if ( privcmd_intf != NULL )
        privcmd_intf->proc_fops = &privcmd_file_ops;

    return 0;
}

__initcall(privcmd_init);
