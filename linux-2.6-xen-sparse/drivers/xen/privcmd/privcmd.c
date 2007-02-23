/******************************************************************************
 * privcmd.c
 * 
 * Interface to privileged domain-0 commands.
 * 
 * Copyright (c) 2002-2004, K A Fraser, B Dragovic
 */

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
#include <asm/hypervisor.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/hypervisor.h>
#include <xen/public/privcmd.h>
#include <xen/interface/xen.h>
#include <xen/interface/dom0_ops.h>
#include <xen/xen_proc.h>

static struct proc_dir_entry *privcmd_intf;
static struct proc_dir_entry *capabilities_intf;

#ifndef HAVE_ARCH_PRIVCMD_MMAP
static int privcmd_enforce_singleshot_mapping(struct vm_area_struct *vma);
#endif

static int privcmd_ioctl(struct inode *inode, struct file *file,
			 unsigned int cmd, unsigned long data)
{
	int ret = -ENOSYS;
	void __user *udata = (void __user *) data;

	switch (cmd) {
	case IOCTL_PRIVCMD_HYPERCALL: {
		privcmd_hypercall_t hypercall;
  
		if (copy_from_user(&hypercall, udata, sizeof(hypercall)))
			return -EFAULT;

#if defined(__i386__)
		if (hypercall.op >= (PAGE_SIZE >> 5))
			break;
		__asm__ __volatile__ (
			"pushl %%ebx; pushl %%ecx; pushl %%edx; "
			"pushl %%esi; pushl %%edi; "
			"movl  8(%%eax),%%ebx ;"
			"movl 16(%%eax),%%ecx ;"
			"movl 24(%%eax),%%edx ;"
			"movl 32(%%eax),%%esi ;"
			"movl 40(%%eax),%%edi ;"
			"movl   (%%eax),%%eax ;"
			"shll $5,%%eax ;"
			"addl $hypercall_page,%%eax ;"
			"call *%%eax ;"
			"popl %%edi; popl %%esi; popl %%edx; "
			"popl %%ecx; popl %%ebx"
			: "=a" (ret) : "0" (&hypercall) : "memory" );
#elif defined (__x86_64__)
		if (hypercall.op < (PAGE_SIZE >> 5)) {
			long ign1, ign2, ign3;
			__asm__ __volatile__ (
				"movq %8,%%r10; movq %9,%%r8;"
				"shll $5,%%eax ;"
				"addq $hypercall_page,%%rax ;"
				"call *%%rax"
				: "=a" (ret), "=D" (ign1),
				  "=S" (ign2), "=d" (ign3)
				: "0" ((unsigned int)hypercall.op),
				"1" (hypercall.arg[0]),
				"2" (hypercall.arg[1]),
				"3" (hypercall.arg[2]),
				"g" (hypercall.arg[3]),
				"g" (hypercall.arg[4])
				: "r8", "r10", "memory" );
		}
#elif defined (__ia64__)
		ret = privcmd_hypercall(&hypercall);
#endif
	}
	break;

	case IOCTL_PRIVCMD_MMAP: {
		privcmd_mmap_t mmapcmd;
		privcmd_mmap_entry_t msg;
		privcmd_mmap_entry_t __user *p;
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma;
		unsigned long va;
		int i, rc;

		if (!is_initial_xendomain())
			return -EPERM;

		if (copy_from_user(&mmapcmd, udata, sizeof(mmapcmd)))
			return -EFAULT;

		p = mmapcmd.entry;
		if (copy_from_user(&msg, p, sizeof(msg)))
			return -EFAULT;

		down_read(&mm->mmap_sem);

		vma = find_vma(mm, msg.va);
		rc = -EINVAL;
		if (!vma || (msg.va != vma->vm_start) ||
		    !privcmd_enforce_singleshot_mapping(vma))
			goto mmap_out;

		va = vma->vm_start;

		for (i = 0; i < mmapcmd.num; i++) {
			rc = -EFAULT;
			if (copy_from_user(&msg, p, sizeof(msg)))
				goto mmap_out;

			/* Do not allow range to wrap the address space. */
			rc = -EINVAL;
			if ((msg.npages > (LONG_MAX >> PAGE_SHIFT)) ||
			    ((unsigned long)(msg.npages << PAGE_SHIFT) >= -va))
				goto mmap_out;

			/* Range chunks must be contiguous in va space. */
			if ((msg.va != va) ||
			    ((msg.va+(msg.npages<<PAGE_SHIFT)) > vma->vm_end))
				goto mmap_out;

			if ((rc = direct_remap_pfn_range(
				vma,
				msg.va & PAGE_MASK, 
				msg.mfn, 
				msg.npages << PAGE_SHIFT, 
				vma->vm_page_prot,
				mmapcmd.dom)) < 0)
				goto mmap_out;

			p++;
			va += msg.npages << PAGE_SHIFT;
		}

		rc = 0;

	mmap_out:
		up_read(&mm->mmap_sem);
		ret = rc;
	}
	break;

	case IOCTL_PRIVCMD_MMAPBATCH: {
		privcmd_mmapbatch_t m;
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma;
		xen_pfn_t __user *p;
		unsigned long addr, mfn, nr_pages;
		int i;

		if (!is_initial_xendomain())
			return -EPERM;

		if (copy_from_user(&m, udata, sizeof(m)))
			return -EFAULT;

		nr_pages = m.num;
		if ((m.num <= 0) || (nr_pages > (LONG_MAX >> PAGE_SHIFT)))
			return -EINVAL;

		down_read(&mm->mmap_sem);

		vma = find_vma(mm, m.addr);
		if (!vma ||
		    (m.addr != vma->vm_start) ||
		    ((m.addr + (nr_pages << PAGE_SHIFT)) != vma->vm_end) ||
		    !privcmd_enforce_singleshot_mapping(vma)) {
			up_read(&mm->mmap_sem);
			return -EINVAL;
		}

		p = m.arr;
		addr = m.addr;
		for (i = 0; i < nr_pages; i++, addr += PAGE_SIZE, p++) {
			if (get_user(mfn, p)) {
				up_read(&mm->mmap_sem);
				return -EFAULT;
			}

			ret = direct_remap_pfn_range(vma, addr & PAGE_MASK,
						     mfn, PAGE_SIZE,
						     vma->vm_page_prot, m.dom);
			if (ret < 0)
				put_user(0xF0000000 | mfn, p);
		}

		up_read(&mm->mmap_sem);
		ret = 0;
	}
	break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#ifndef HAVE_ARCH_PRIVCMD_MMAP
static struct page *privcmd_nopage(struct vm_area_struct *vma,
				   unsigned long address,
				   int *type)
{
	return NOPAGE_SIGBUS;
}

static struct vm_operations_struct privcmd_vm_ops = {
	.nopage = privcmd_nopage
};

static int privcmd_mmap(struct file * file, struct vm_area_struct * vma)
{
	/* Unsupported for auto-translate guests. */
	if (xen_feature(XENFEAT_auto_translated_physmap))
		return -ENOSYS;

	/* DONTCOPY is essential for Xen as copy_page_range is broken. */
	vma->vm_flags |= VM_RESERVED | VM_IO | VM_DONTCOPY;
	vma->vm_ops = &privcmd_vm_ops;
	vma->vm_private_data = NULL;

	return 0;
}

static int privcmd_enforce_singleshot_mapping(struct vm_area_struct *vma)
{
	return (xchg(&vma->vm_private_data, (void *)1) == NULL);
}
#endif

static struct file_operations privcmd_file_ops = {
	.ioctl = privcmd_ioctl,
	.mmap  = privcmd_mmap,
};

static int capabilities_read(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	int len = 0;
	*page = 0;

	if (is_initial_xendomain())
		len = sprintf( page, "control_d\n" );

	*eof = 1;
	return len;
}

static int __init privcmd_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	privcmd_intf = create_xen_proc_entry("privcmd", 0400);
	if (privcmd_intf != NULL)
		privcmd_intf->proc_fops = &privcmd_file_ops;

	capabilities_intf = create_xen_proc_entry("capabilities", 0400 );
	if (capabilities_intf != NULL)
		capabilities_intf->read_proc = capabilities_read;

	return 0;
}

__initcall(privcmd_init);
