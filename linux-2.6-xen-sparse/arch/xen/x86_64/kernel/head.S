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
	.ascii	"GUEST_OS=linux,GUEST_VER=2.6,XEN_VER=3.0,VIRT_BASE=0xffffffff80000000"
	.ascii	",LOADER=generic"
/*	.ascii	",PT_MODE_WRITABLE" */
	.byte	0
                
      
#include <linux/threads.h>
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

	/*
	 * This default setting generates an ident mapping at address 0x100000
	 * and a mapping for the kernel that precisely maps virtual address
	 * 0xffffffff80000000 to physical address 0x000000. (always using
	 * 2Mbyte large pages provided by PAE mode)
	 */
.org 0x1000
ENTRY(init_level4_pgt)
	.fill	512,8,0

        /*
         * We update two pgd entries to make kernel and user pgd consistent
         * at pgd_populate(). It can be used for kernel modules. So we place 
         * this page here for those cases to avoid memory corruption.
         * We also use this page to establish the initiali mapping for
         * vsyscall area.
         */
.org 0x2000
ENTRY(init_level4_user_pgt)
	.fill	512,8,0

	/*
	 * In Xen the following pre-initialized pgt entries are re-initialized.
	 */
.org 0x3000
ENTRY(level3_kernel_pgt)
	.fill	510,8,0
	/* (2^48-(2*1024*1024*1024)-((2^39)*511))/(2^30) = 510 */
	.quad	0x0000000000105007		/* -> level2_kernel_pgt */
	.fill	1,8,0

.org 0x4000
ENTRY(level2_ident_pgt)
	/* 40MB for bootup. 	*/
	.quad	0x0000000000000283
	.quad	0x0000000000200183
	.quad	0x0000000000400183
	.quad	0x0000000000600183
	.quad	0x0000000000800183
	.quad	0x0000000000A00183
	.quad	0x0000000000C00183
	.quad	0x0000000000E00183
	.quad	0x0000000001000183
	.quad	0x0000000001200183
	.quad	0x0000000001400183
	.quad	0x0000000001600183
	.quad	0x0000000001800183
	.quad	0x0000000001A00183
	.quad	0x0000000001C00183
	.quad	0x0000000001E00183
	.quad	0x0000000002000183
	.quad	0x0000000002200183
	.quad	0x0000000002400183
	.quad	0x0000000002600183
	/* Temporary mappings for the super early allocator in arch/x86_64/mm/init.c */
	.globl temp_boot_pmds
temp_boot_pmds:
	.fill	492,8,0

.org 0x5000
ENTRY(level2_kernel_pgt)
	/* 40MB kernel mapping. The kernel code cannot be bigger than that.
	   When you change this change KERNEL_TEXT_SIZE in page.h too. */
	/* (2^48-(2*1024*1024*1024)-((2^39)*511)-((2^30)*510)) = 0 */
	.quad	0x0000000000000183
	.quad	0x0000000000200183
	.quad	0x0000000000400183
	.quad	0x0000000000600183
	.quad	0x0000000000800183
	.quad	0x0000000000A00183
	.quad	0x0000000000C00183
	.quad	0x0000000000E00183
	.quad	0x0000000001000183
	.quad	0x0000000001200183
	.quad	0x0000000001400183
	.quad	0x0000000001600183
	.quad	0x0000000001800183
	.quad	0x0000000001A00183
	.quad	0x0000000001C00183
	.quad	0x0000000001E00183
	.quad	0x0000000002000183
	.quad	0x0000000002200183
	.quad	0x0000000002400183
	.quad	0x0000000002600183
	/* Module mapping starts here */
	.fill	492,8,0
	
        /*
         * This is used for vsyscall area mapping as we have a different
         * level4 page table for user.
         */
.org 0x6000
ENTRY(level3_user_pgt)
        .fill	512,8,0

.org 0x7000
ENTRY(cpu_gdt_table)
/* The TLS descriptors are currently at a different place compared to i386.
   Hopefully nobody expects them at a fixed place (Wine?) */
	.quad	0x0000000000000000	/* NULL descriptor */
	.quad	0x008ffa000000ffff	/* __KERNEL_COMPAT32_CS */	
	.quad	0x00affa000000ffff	/* __KERNEL_CS */
	.quad	0x00cff2000000ffff	/* __KERNEL_DS */
	
       	.quad	0x00cffa000000ffff	/* __USER32_CS */
	.quad	0x00cff2000000ffff	/* __USER_DS, __USER32_DS  */		
	.quad	0x00affa000000ffff	/* __USER_CS */
	.quad	0x00cffa000000ffff	/* __KERNEL32_CS */        
	.quad	0,0			/* TSS */
	.quad	0,0			/* LDT */
	.quad   0,0,0			/* three TLS descriptors */ 
	.quad	0			/* unused now?   __KERNEL16_CS - 16bit PM for S3 wakeup. */

gdt_end:
#if 0
	/* asm/segment.h:GDT_ENTRIES must match this */	
	/* This should be a multiple of the cache line size */
	/* GDTs of other CPUs: */	
	.fill (GDT_SIZE * NR_CPUS) - (gdt_end - cpu_gdt_table)
#endif

.org 0x8000
ENTRY(empty_zero_page)

.org 0x9000
ENTRY(empty_bad_page)

.org 0xa000
ENTRY(empty_bad_pte_table)

.org 0xb000
ENTRY(empty_bad_pmd_table)

.org 0xc000
ENTRY(level3_physmem_pgt)
	.quad	0x0000000000105007		/* -> level2_kernel_pgt (so that __va works even before pagetable_init) */

	
	.org 0xd000
#ifdef CONFIG_ACPI_SLEEP
ENTRY(wakeup_level4_pgt)
	.quad	0x0000000000102007		/* -> level3_ident_pgt */
	.fill	255,8,0
	.quad	0x000000000010a007
	.fill	254,8,0
	/* (2^48-(2*1024*1024*1024))/(2^39) = 511 */
	.quad	0x0000000000103007		/* -> level3_kernel_pgt */
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
		 		
#if 0        		 		
.align L1_CACHE_BYTES
#endif
	.align  L1_CACHE_BYTES
ENTRY(idt_table)	
	.rept   256
	.quad   0
	.quad 	0
	.endr

