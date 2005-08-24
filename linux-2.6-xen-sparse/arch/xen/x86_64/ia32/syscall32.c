/* Copyright 2002,2003 Andi Kleen, SuSE Labs */

/* vsyscall handling for 32bit processes. Map a stub page into it 
   on demand because 32bit cannot reach the kernel's fixmaps */

#include <linux/mm.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/stringify.h>
#include <linux/security.h>
#include <asm/proto.h>
#include <asm/tlbflush.h>
#include <asm/ia32_unistd.h>

#define USE_INT80

#ifdef USE_INT80
/* 32bit VDSOs mapped into user space. */ 
asm(".section \".init.data\",\"aw\"\n"
    "syscall32_int80:\n"
    ".incbin \"arch/xen/x86_64/ia32/vsyscall-int80.so\"\n"
    "syscall32_int80_end:\n"
    "syscall32_syscall:\n"
    ".incbin \"arch/xen/x86_64/ia32/vsyscall-syscall.so\"\n"
    "syscall32_syscall_end:\n"
    "syscall32_sysenter:\n"
    ".incbin \"arch/xen/x86_64/ia32/vsyscall-sysenter.so\"\n"
    "syscall32_sysenter_end:\n"
    ".previous");

extern unsigned char syscall32_int80[], syscall32_int80_end[];
#else
/* 32bit VDSOs mapped into user space. */ 
asm(".section \".init.data\",\"aw\"\n"
    "syscall32_syscall:\n"
    ".incbin \"arch/xen/x86_64/ia32/vsyscall-syscall.so\"\n"
    "syscall32_syscall_end:\n"
    "syscall32_sysenter:\n"
    ".incbin \"arch/xen/x86_64/ia32/vsyscall-sysenter.so\"\n"
    "syscall32_sysenter_end:\n"
    ".previous");

static int use_sysenter = -1;
#endif

extern unsigned char syscall32_syscall[], syscall32_syscall_end[];
extern unsigned char syscall32_sysenter[], syscall32_sysenter_end[];
extern int sysctl_vsyscall32;

char *syscall32_page; 

static struct page *
syscall32_nopage(struct vm_area_struct *vma, unsigned long adr, int *type)
{
	struct page *p = virt_to_page(adr - vma->vm_start + syscall32_page);
	get_page(p);
	return p;
}

/* Prevent VMA merging */
static void syscall32_vma_close(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct syscall32_vm_ops = {
	.close = syscall32_vma_close,
	.nopage = syscall32_nopage,
};

struct linux_binprm;

/* Setup a VMA at program startup for the vsyscall page */
int syscall32_setup_pages(struct linux_binprm *bprm, int exstack)
{
	int npages = (VSYSCALL32_END - VSYSCALL32_BASE) >> PAGE_SHIFT;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;

	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma)
		return -ENOMEM;
	if (security_vm_enough_memory(npages)) {
		kmem_cache_free(vm_area_cachep, vma);
		return -ENOMEM;
	}

	memset(vma, 0, sizeof(struct vm_area_struct));
	/* Could randomize here */
	vma->vm_start = VSYSCALL32_BASE;
	vma->vm_end = VSYSCALL32_END;
	/* MAYWRITE to allow gdb to COW and set breakpoints */
	vma->vm_flags = VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYEXEC|VM_MAYEXEC|VM_MAYWRITE;
	vma->vm_flags |= mm->def_flags;
	vma->vm_page_prot = protection_map[vma->vm_flags & 7];
	vma->vm_ops = &syscall32_vm_ops;
	vma->vm_mm = mm;

	down_write(&mm->mmap_sem);
	insert_vm_struct(mm, vma);
	mm->total_vm += npages;
	up_write(&mm->mmap_sem);
	return 0;
}

static int __init init_syscall32(void)
{ 
	syscall32_page = (void *)get_zeroed_page(GFP_KERNEL); 
	if (!syscall32_page) 
		panic("Cannot allocate syscall32 page"); 

#ifdef USE_INT80
	/*
	 * At this point we use int 0x80.
	 */
	memcpy(syscall32_page, syscall32_int80,
	       syscall32_int80_end - syscall32_int80);
#else

 	if (use_sysenter > 0) {
 		memcpy(syscall32_page, syscall32_sysenter,
 		       syscall32_sysenter_end - syscall32_sysenter);
 	} else {
  		memcpy(syscall32_page, syscall32_syscall,
  		       syscall32_syscall_end - syscall32_syscall);
  	}	
#endif
	return 0;
} 

/*
 * This must be done early in case we have an initrd containing 32-bit
 * binaries (e.g., hotplug). This could be pushed upstream to arch/x86_64.
 */	
core_initcall(init_syscall32); 

/* May not be __init: called during resume */
void syscall32_cpu_init(void)
{
#ifndef USE_INT80
	if (use_sysenter < 0)
 		use_sysenter = (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL);

	/* Load these always in case some future AMD CPU supports
	   SYSENTER from compat mode too. */
	checking_wrmsrl(MSR_IA32_SYSENTER_CS, (u64)(__KERNEL_CS | 3));
	checking_wrmsrl(MSR_IA32_SYSENTER_ESP, 0ULL);
	checking_wrmsrl(MSR_IA32_SYSENTER_EIP, (u64)ia32_sysenter_target);

	wrmsrl(MSR_CSTAR, ia32_cstar_target);
#endif
}
