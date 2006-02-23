/*
 * linux/arch/i386/kernel/sysenter.c
 *
 * (C) Copyright 2002 Linus Torvalds
 *
 * This file contains the needed initializations to support sysenter.
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/mm.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>

extern asmlinkage void sysenter_entry(void);

void enable_sep_cpu(void)
{
#ifdef CONFIG_X86_SYSENTER
	int cpu = get_cpu();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);

	if (!boot_cpu_has(X86_FEATURE_SEP)) {
		put_cpu();
		return;
	}

	tss->ss1 = __KERNEL_CS;
	tss->esp1 = sizeof(struct tss_struct) + (unsigned long) tss;
	wrmsr(MSR_IA32_SYSENTER_CS, __KERNEL_CS, 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, tss->esp1, 0);
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long) sysenter_entry, 0);
	put_cpu();	
#endif
}

/*
 * These symbols are defined by vsyscall.o to mark the bounds
 * of the ELF DSO images included therein.
 */
extern const char vsyscall_int80_start, vsyscall_int80_end;
extern const char vsyscall_sysenter_start, vsyscall_sysenter_end;
static void *syscall_page;

int __init sysenter_setup(void)
{
	syscall_page = (void *)get_zeroed_page(GFP_ATOMIC);

#ifdef CONFIG_X86_SYSENTER
	if (boot_cpu_has(X86_FEATURE_SEP)) {
		memcpy(syscall_page,
		       &vsyscall_sysenter_start,
		       &vsyscall_sysenter_end - &vsyscall_sysenter_start);
		return 0;
	}
#endif

	memcpy(syscall_page,
	       &vsyscall_int80_start,
	       &vsyscall_int80_end - &vsyscall_int80_start);

	return 0;
}

static struct page*
syscall_nopage(struct vm_area_struct *vma, unsigned long adr, int *type)
{
	struct page *p = virt_to_page(adr - vma->vm_start + syscall_page);
	get_page(p);
	return p;
}

/* Prevent VMA merging */
static void syscall_vma_close(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct syscall_vm_ops = {
	.close = syscall_vma_close,
	.nopage = syscall_nopage,
};

/* Setup a VMA at program startup for the vsyscall page */
int arch_setup_additional_pages(struct linux_binprm *bprm, int exstack)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	int ret;

	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma)
		return -ENOMEM;

	memset(vma, 0, sizeof(struct vm_area_struct));
	/* Could randomize here */
	vma->vm_start = VSYSCALL_BASE;
	vma->vm_end = VSYSCALL_BASE + PAGE_SIZE;
	/* MAYWRITE to allow gdb to COW and set breakpoints */
	vma->vm_flags = VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYEXEC|VM_MAYWRITE;
	vma->vm_flags |= mm->def_flags;
	vma->vm_page_prot = protection_map[vma->vm_flags & 7];
	vma->vm_ops = &syscall_vm_ops;
	vma->vm_mm = mm;

	down_write(&mm->mmap_sem);
	if ((ret = insert_vm_struct(mm, vma))) {
		up_write(&mm->mmap_sem);
		kmem_cache_free(vm_area_cachep, vma);
		return ret;
	}
	mm->total_vm++;
	up_write(&mm->mmap_sem);
	return 0;
}

struct vm_area_struct *get_gate_vma(struct task_struct *tsk)
{
	return NULL;
}

int in_gate_area(struct task_struct *task, unsigned long addr)
{
	return 0;
}

int in_gate_area_no_task(unsigned long addr)
{
	return 0;
}
