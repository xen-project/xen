/*
 *  linux/arch/x86_64/kernel/head.S -- start in 32bit and switch to 64bit
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright (C) 2000 Pavel Machek <pavel@suse.cz>
 *  Copyright (C) 2000 Karsten Keil <kkeil@suse.de>
 *  Copyright (C) 2001,2002 Andi Kleen <ak@suse.de>
 *
 *  $Id: head.S,v 1.49 2002/03/19 17:39:25 ak Exp $
 *
 *  Jun Nakajima <jun.nakajima@intel.com>
 *    Modified for Xen                                
 */


#include <linux/linkage.h>

.section __xen_guest
	.ascii	"GUEST_OS=linux,GUEST_VER=2.6"
	.ascii	",XEN_VER=xen-3.0"
	.ascii	",VIRT_BASE=0xffffffff80000000"
	.ascii	",HYPERCALL_PAGE=0x10a" /* __pa(hypercall_page) >> 12 */
	.ascii	",LOADER=generic"
	.byte	0
      
#include <linux/threads.h>
#include <linux/init.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/cache.h>
	
/* we are not able to switch in one step to the final KERNEL ADRESS SPACE
 * because we need identity-mapped pages on setup so define __START_KERNEL to
 * 0x100000 for this stage
 * 
 */

	.text
	.code64
	.globl startup_64
startup_64:
ENTRY(_start)
	movq %rsi,xen_start_info(%rip)

#ifdef CONFIG_SMP
ENTRY(startup_64_smp)
#endif /* CONFIG_SMP */

	cld

	movq init_rsp(%rip),%rsp
	/* zero EFLAGS after setting rsp */
	pushq $0
	popfq
	movq	initial_code(%rip),%rax
	jmp	*%rax

	/* SMP bootup changes these two */	
	.globl	initial_code
initial_code:
	.quad	x86_64_start_kernel
	.globl init_rsp
init_rsp:
	.quad  init_thread_union+THREAD_SIZE-8

ENTRY(early_idt_handler)
	xorl %eax,%eax
	movq 8(%rsp),%rsi	# get rip
	movq (%rsp),%rdx
	leaq early_idt_msg(%rip),%rdi
1:	hlt                     # generate #GP
	jmp 1b

early_idt_msg:
	.asciz "PANIC: early exception rip %lx error %lx cr2 %lx\n"

#if 0
ENTRY(lgdt_finish)
        movl $(__USER_DS),%eax          # DS/ES contains default USER segment
        movw %ax,%ds
        movw %ax,%es
        movl $(__KERNEL_DS),%eax        
        movw %ax,%ss                    # after changing gdt.
        popq %rax                       # get the retrun address
        pushq $(__KERNEL_CS)
        pushq %rax
        lretq
#endif 

ENTRY(stext)
ENTRY(_stext)

	$page = 0
#define NEXT_PAGE(name) \
	$page = $page + 1; \
	.org $page * 0x1000; \
	phys_/**/name = $page * 0x1000 + __PHYSICAL_START; \
ENTRY(name)

NEXT_PAGE(init_level4_pgt)
	/* This gets initialized in x86_64_start_kernel */
	.fill	512,8,0

        /*
         * We update two pgd entries to make kernel and user pgd consistent
         * at pgd_populate(). It can be used for kernel modules. So we place 
         * this page here for those cases to avoid memory corruption.
         * We also use this page to establish the initiali mapping for
         * vsyscall area.
         */
NEXT_PAGE(init_level4_user_pgt)
	.fill	512,8,0

	/*
	 * In Xen the following pre-initialized pgt entries are re-initialized.
	 */
NEXT_PAGE(level3_kernel_pgt)
	.fill	510,8,0
	/* (2^48-(2*1024*1024*1024)-((2^39)*511))/(2^30) = 510 */
	.quad	phys_level2_kernel_pgt | 0x007
	.fill	1,8,0

NEXT_PAGE(level2_ident_pgt)
	/* 40MB for bootup. 	*/
	i = 0
	.rept 20
	.quad	i << 21 | 0x083
	i = i + 1
	.endr
	/* Temporary mappings for the super early allocator in arch/x86_64/mm/init.c */
	.globl temp_boot_pmds
temp_boot_pmds:
	.fill	492,8,0

NEXT_PAGE(level2_kernel_pgt)
	/* 40MB kernel mapping. The kernel code cannot be bigger than that.
	   When you change this change KERNEL_TEXT_SIZE in page.h too. */
	/* (2^48-(2*1024*1024*1024)-((2^39)*511)-((2^30)*510)) = 0 */
	i = 0
	.rept 20
	.quad	i << 21 | 0x183
	i = i + 1
	.endr
	/* Module mapping starts here */
	.fill	492,8,0
	
        /*
         * This is used for vsyscall area mapping as we have a different
         * level4 page table for user.
         */
NEXT_PAGE(level3_user_pgt)
        .fill	512,8,0

NEXT_PAGE(cpu_gdt_table)
/* The TLS descriptors are currently at a different place compared to i386.
   Hopefully nobody expects them at a fixed place (Wine?) */
	.quad	0x0000000000000000	/* NULL descriptor */
	.quad	0x0			/* unused */
	.quad	0x00affa000000ffff	/* __KERNEL_CS */
	.quad	0x00cff2000000ffff	/* __KERNEL_DS */
       	.quad	0x00cffa000000ffff	/* __USER32_CS */
	.quad	0x00cff2000000ffff	/* __USER_DS, __USER32_DS  */		
	.quad	0x00affa000000ffff	/* __USER_CS */
	.quad	0x00cffa000000ffff	/* __KERNEL32_CS */        
	.quad	0,0			/* TSS */
	.quad	0,0			/* LDT */
	.quad   0,0,0			/* three TLS descriptors */ 
	.quad	0			/* unused */
gdt_end:
#if 0
	/* asm/segment.h:GDT_ENTRIES must match this */	
	/* This should be a multiple of the cache line size */
	/* GDTs of other CPUs are now dynamically allocated */

	/* zero the remaining page */
	.fill PAGE_SIZE / 8 - GDT_ENTRIES,8,0
#endif

NEXT_PAGE(empty_zero_page)

NEXT_PAGE(level3_physmem_pgt)
	.quad	phys_level2_kernel_pgt | 0x007	/* so that __va works even before pagetable_init */

NEXT_PAGE(hypercall_page)
.if (phys_hypercall_page - 0x10a000)
	/* cause compiler error if the hypercall_page is at a
	 * different address than expected. */
	.quad	__adjust_hypercall_page_in_header
.endif
	.fill	512,8,0

#undef NEXT_PAGE

	.data

#ifndef CONFIG_XEN
#ifdef CONFIG_ACPI_SLEEP
	.align PAGE_SIZE
ENTRY(wakeup_level4_pgt)
	.quad	phys_level3_ident_pgt | 0x007
	.fill	255,8,0
	.quad	phys_level3_physmem_pgt | 0x007
	.fill	254,8,0
	/* (2^48-(2*1024*1024*1024))/(2^39) = 511 */
	.quad	phys_level3_kernel_pgt | 0x007
#endif

#ifndef CONFIG_HOTPLUG_CPU
	__INITDATA
#endif
	/*
	 * This default setting generates an ident mapping at address 0x100000
	 * and a mapping for the kernel that precisely maps virtual address
	 * 0xffffffff80000000 to physical address 0x000000. (always using
	 * 2Mbyte large pages provided by PAE mode)
	 */
	.align PAGE_SIZE
ENTRY(boot_level4_pgt)
	.quad	phys_level3_ident_pgt | 0x007
	.fill	255,8,0
	.quad	phys_level3_physmem_pgt | 0x007
	.fill	254,8,0
	/* (2^48-(2*1024*1024*1024))/(2^39) = 511 */
	.quad	phys_level3_kernel_pgt | 0x007
#endif

	.data

	.align 16
	.globl cpu_gdt_descr
cpu_gdt_descr:
	.word	gdt_end-cpu_gdt_table
gdt:
	.quad	cpu_gdt_table
#ifdef CONFIG_SMP
	.rept	NR_CPUS-1
	.word	0
	.quad	0
	.endr
#endif

/* We need valid kernel segments for data and code in long mode too
 * IRET will check the segment types  kkeil 2000/10/28
 * Also sysret mandates a special GDT layout 
 */
		 		
.align PAGE_SIZE

ENTRY(idt_table)	
	.rept   256
	.quad   0
	.quad 	0
	.endr

