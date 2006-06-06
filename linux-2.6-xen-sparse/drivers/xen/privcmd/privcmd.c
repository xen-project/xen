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

#define NR_HYPERCALLS 64
static DECLARE_BITMAP(hypercall_permission_map, NR_HYPERCALLS);

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

		/* Check hypercall number for validity. */
		if (hypercall.op >= NR_HYPERCALLS)
			return -EINVAL;
		if (!test_bit(hypercall.op, hypercall_permission_map))
			return -EINVAL;

#if defined(__i386__)
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
		{
			long ign1, ign2, ign3;
			__asm__ __volatile__ (
				"movq %8,%%r10; movq %9,%%r8;"
				"shlq $5,%%rax ;"
				"addq $hypercall_page,%%rax ;"
				"call *%%rax"
				: "=a" (ret), "=D" (ign1),
				  "=S" (ign2), "=d" (ign3)
				: "0" ((unsigned long)hypercall.op), 
				"1" ((unsigned long)hypercall.arg[0]), 
				"2" ((unsigned long)hypercall.arg[1]),
				"3" ((unsigned long)hypercall.arg[2]), 
				"g" ((unsigned long)hypercall.arg[3]),
				"g" ((unsigned long)hypercall.arg[4])
				: "r8", "r10", "memory" );
		}
#elif defined (__ia64__)
		__asm__ __volatile__ (
			";; mov r14=%2; mov r15=%3; "
			"mov r16=%4; mov r17=%5; mov r18=%6;"
			"mov r2=%1; break 0x1000;; mov %0=r8 ;;"
			: "=r" (ret)
			: "r" (hypercall.op),
			"r" (hypercall.arg[0]),
			"r" (hypercall.arg[1]),
			"r" (hypercall.arg[2]),
			"r" (hypercall.arg[3]),
			"r" (hypercall.arg[4])
			: "r14","r15","r16","r17","r18","r2","r8","memory");
#endif
	}
	break;

#if defined(CONFIG_XEN_PRIVILEGED_GUEST)
	case IOCTL_PRIVCMD_MMAP: {
#define PRIVCMD_MMAP_SZ 32
		privcmd_mmap_t mmapcmd;
		privcmd_mmap_entry_t msg[PRIVCMD_MMAP_SZ];
		privcmd_mmap_entry_t __user *p;
		int i, rc;

		if (copy_from_user(&mmapcmd, udata, sizeof(mmapcmd)))
			return -EFAULT;

		p = mmapcmd.entry;

		for (i = 0; i < mmapcmd.num;
		     i += PRIVCMD_MMAP_SZ, p += PRIVCMD_MMAP_SZ) {
			int j, n = ((mmapcmd.num-i)>PRIVCMD_MMAP_SZ)?
				PRIVCMD_MMAP_SZ:(mmapcmd.num-i);

			if (copy_from_user(&msg, p,
					   n*sizeof(privcmd_mmap_entry_t)))
				return -EFAULT;
     
			for (j = 0; j < n; j++) {
				struct vm_area_struct *vma = 
					find_vma( current->mm, msg[j].va );

				if (!vma)
					return -EINVAL;

				if (msg[j].va > PAGE_OFFSET)
					return -EINVAL;

				if ((msg[j].va + (msg[j].npages << PAGE_SHIFT))
				    > vma->vm_end )
					return -EINVAL;

				if ((rc = direct_remap_pfn_range(
					vma,
					msg[j].va&PAGE_MASK, 
					msg[j].mfn, 
					msg[j].npages<<PAGE_SHIFT, 
					vma->vm_page_prot,
					mmapcmd.dom)) < 0)
					return rc;
			}
		}
		ret = 0;
	}
	break;

	case IOCTL_PRIVCMD_MMAPBATCH: {
		privcmd_mmapbatch_t m;
		struct vm_area_struct *vma = NULL;
		xen_pfn_t __user *p;
		unsigned long addr, mfn; 
		int i;

		if (copy_from_user(&m, udata, sizeof(m))) {
			ret = -EFAULT;
			goto batch_err;
		}

		if (m.dom == DOMID_SELF) {
			ret = -EINVAL;
			goto batch_err;
		}

		vma = find_vma(current->mm, m.addr);
		if (!vma) {
			ret = -EINVAL;
			goto batch_err;
		}

		if (m.addr > PAGE_OFFSET) {
			ret = -EFAULT;
			goto batch_err;
		}

		if ((m.addr + (m.num<<PAGE_SHIFT)) > vma->vm_end) {
			ret = -EFAULT;
			goto batch_err;
		}

		p = m.arr;
		addr = m.addr;
		for (i = 0; i < m.num; i++, addr += PAGE_SIZE, p++) {
			if (get_user(mfn, p))
				return -EFAULT;

			ret = direct_remap_pfn_range(vma, addr & PAGE_MASK,
						     mfn, PAGE_SIZE,
						     vma->vm_page_prot, m.dom);
			if (ret < 0)
				put_user(0xF0000000 | mfn, p);
		}

		ret = 0;
		break;

	batch_err:
		printk("batch_err ret=%d vma=%p addr=%lx "
		       "num=%d arr=%p %lx-%lx\n", 
		       ret, vma, (unsigned long)m.addr, m.num, m.arr,
		       vma ? vma->vm_start : 0, vma ? vma->vm_end : 0);
		break;
	}
	break;
#endif

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#ifndef HAVE_ARCH_PRIVCMD_MMAP
static int privcmd_mmap(struct file * file, struct vm_area_struct * vma)
{
	/* DONTCOPY is essential for Xen as copy_page_range is broken. */
	vma->vm_flags |= VM_RESERVED | VM_IO | VM_DONTCOPY;

	return 0;
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

	if (xen_start_info->flags & SIF_INITDOMAIN)
		len = sprintf( page, "control_d\n" );

	*eof = 1;
	return len;
}

static int __init privcmd_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	/* Set of hypercalls that privileged applications may execute. */
	set_bit(__HYPERVISOR_acm_op,           hypercall_permission_map);
	set_bit(__HYPERVISOR_dom0_op,          hypercall_permission_map);
	set_bit(__HYPERVISOR_event_channel_op, hypercall_permission_map);
	set_bit(__HYPERVISOR_memory_op,        hypercall_permission_map);
	set_bit(__HYPERVISOR_mmu_update,       hypercall_permission_map);
	set_bit(__HYPERVISOR_mmuext_op,        hypercall_permission_map);
	set_bit(__HYPERVISOR_xen_version,      hypercall_permission_map);
	set_bit(__HYPERVISOR_sched_op,         hypercall_permission_map);
	set_bit(__HYPERVISOR_sched_op_compat,  hypercall_permission_map);
	set_bit(__HYPERVISOR_event_channel_op_compat,
		hypercall_permission_map);

	privcmd_intf = create_xen_proc_entry("privcmd", 0400);
	if (privcmd_intf != NULL)
		privcmd_intf->proc_fops = &privcmd_file_ops;

	capabilities_intf = create_xen_proc_entry("capabilities", 0400 );
	if (capabilities_intf != NULL)
		capabilities_intf->read_proc = capabilities_read;

	return 0;
}

__initcall(privcmd_init);
