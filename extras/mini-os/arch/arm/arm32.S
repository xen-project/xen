@ Offset of the kernel within the RAM. This is a Linux/zImage convention which we
@ rely on for now.
#define ZIMAGE_KERNEL_OFFSET 0x8000

.section .text

.globl _start
_start:
	@ zImage header
.rept   8
        mov     r0, r0
.endr
        b       reset
        .word   0x016f2818      @ Magic numbers to help the loader
        .word   0		@ zImage start address (0 = relocatable)
        .word   _edata - _start @ zImage end address (excludes bss section)
	@ end of zImage header

@ Called at boot time. Sets up MMU, exception vectors and stack, and then calls C arch_init() function.
@ => r2 -> DTB
@ <= never returns
@ Note: this boot code needs to be within the first (1MB - ZIMAGE_KERNEL_OFFSET) of _start.
reset:
	@ Problem: the C code wants to be at a known address (_start), but Xen might
	@ load us anywhere. We initialise the MMU (mapping virtual to physical @ addresses)
	@ so everything ends up where the code expects it to be.
	@
	@ We calculate the offet between where the linker thought _start would be and where
	@ it actually is and initialise the page tables to have that offset for every page.
	@
	@ When we turn on the MMU, we're still executing at the old address. We don't want
	@ the code to disappear from under us. So we have to do the mapping in stages:
	@
	@ 1. set up a mapping to our current page from both its current and desired addresses
	@ 2. enable the MMU
	@ 3. jump to the new address
	@ 4. remap all the other pages with the calculated offset

	adr	r1, _start		@ r1 = physical address of _start
	ldr	r3, =_start		@ r3 = (desired) virtual address of _start
	sub 	r9, r1, r3		@ r9 = (physical - virtual) offset

	ldr	r7, =_page_dir		@ r7 = (desired) virtual addr of translation table
	add	r1, r7, r9		@ r1 = physical addr of translation table

	@ Tell the system where our page table is located.
	@ This is the 16 KB top-level translation table, in which
	@ each word maps one 1MB virtual section to a physical section.
	@ Note: We leave TTBCR as 0, meaning that only TTBR0 is used and
	@ we use the short-descriptor format (32-bit physical addresses).
	orr	r0, r1, #0b0001011	@ Sharable, Inner/Outer Write-Back Write-Allocate Cacheable
	mcr	p15, 0, r0, c2, c0, 0	@ set TTBR0

	@ Set access permission for domains.
	@ Domains are deprecated, but we have to configure them anyway.
	@ We mark every page as being domain 0 and set domain 0 to "client mode"
	@ (client mode = use access flags in page table).
	mov	r0, #1			@ 1 = client
	mcr	p15, 0, r0, c3, c0, 0	@ DACR

	@ Template (flags) for a 1 MB page-table entry.
	@ TEX[2:0] C B = 001 1 1 (outer and inner write-back, write-allocate)
	ldr	r8, =(0x2 +  		/* Section entry */ \
		      0xc +  		/* C B */ \
		      (3 << 10) + 	/* Read/write */ \
		      (1 << 12) +	/* TEX */ \
		      (1 << 16) +	/* Sharable */ \
		      (1<<19))		/* Non-secure */
	@ r8 = template page table entry

	@ Add an entry for the current physical section, at the old and new
	@ addresses. It's OK if they're the same.
	mov	r0, pc, lsr#20
	mov	r0, r0, lsl#20		@ r0 = physical address of this code's section start
	orr	r3, r0, r8		@ r3 = table entry for this section
	ldr	r4, =_start		@ r4 = desired virtual address of this section
	str	r3, [r1, r4, lsr#18] 	@ map desired virtual section to this code
	str	r3, [r1, r0, lsr#18]	@ map current section to this code too

	@ Invalidate TLB
	dsb				@ Caching is off, but must still prevent reordering
	mcr	p15, 0, r1, c8, c7, 0	@ TLBIALL

	@ Enable MMU / SCTLR
	mrc	p15, 0, r1, c1, c0, 0	@ SCTLR
	orr	r1, r1, #3 << 11	@ enable icache, branch prediction
	orr	r1, r1, #4 + 1		@ enable dcache, MMU
	mcr	p15, 0, r1, c1, c0, 0	@ SCTLR
	isb

	ldr	r1, =stage2		@ Virtual address of stage2
	bx	r1

@ Called once the MMU is enabled. The boot code and the page table are mapped,
@ but nothing else is yet.
@
@ => r2 -> dtb (physical)
@    r7 = virtual address of page table
@    r8 = section entry template (flags)
@    r9 = desired physical - virtual offset
@    pc -> somewhere in newly-mapped virtual code section
stage2:
	@ Invalidate TLB
	mcr	p15, 0, r1, c8, c7, 0	@ TLBIALL
	isb

	@ The new mapping has now taken effect:
	@ r7 -> page_dir

	@ Fill in the whole top-level translation table (at page_dir).
	@ Populate the whole pagedir with 1MB section descriptors.

	mov	r1, r7			@ r1 -> first section entry
	add	r3, r1, #4*4*1024	@ limit (4 GB address space, 4 byte entries)
	orr	r0, r8, r9		@ r0 = entry mapping section zero to start of physical RAM
1:
	str	r0, [r1],#4		@ write the section entry
	add	r0, r0, #1 << 20 	@ next physical page (wraps)
	cmp	r1, r3
	bne	1b

	@ Invalidate TLB
	dsb
	mcr	p15, 0, r1, c8, c7, 0	@ TLBIALL
	isb

	@ Set VBAR -> exception_vector_table
	@ SCTLR.V = 0
	adr	r0, exception_vector_table
	mcr	p15, 0, r0, c12, c0, 0

	@ Enable hardware floating point:
	@ 1. Access to CP10 and CP11 must be enabled in the Coprocessor Access
	@    Control Register (CP15.CACR):
	mrc	p15, 0, r1, c1, c0, 2		@ CACR
	orr	r1, r1, #(3 << 20) + (3 << 22)	@ full access for CP10 & CP11
	mcr	p15, 0, r1, c1, c0, 2
	@ 2. The EN bit in the FPEXC register must be set:
	vmrs	r0, FPEXC
	orr	r0, r0, #1<<30		@ EN (enable)
	vmsr	FPEXC, r0

	@ Initialise 16 KB stack
	ldr	sp, =_boot_stack_end

	sub	r0, r2, r9		@ r0 -> device tree (virtual address)
	mov	r1, r9			@ r1 = physical_address_offset

	b	arch_init

.pushsection .bss
@ Note: calling arch_init zeroes out this region.
.align 12
.globl shared_info_page
shared_info_page:
	.fill (1024), 4, 0x0

.align 3
.globl irqstack
.globl irqstack_end
irqstack:
	.fill (1024), 4, 0x0
irqstack_end:

.popsection

@ exception base address
.align 5
.globl exception_vector_table
@ Note: remember to call CLREX if returning from an exception:
@ "The architecture enables the local monitor to treat any exclusive store as
@  matching a previous LDREX address. For this reason, use of the CLREX
@  instruction to clear an existing tag is required on context switches."
@ -- ARM Cortex-A Series Programmer’s Guide (Version: 4.0)
exception_vector_table:
	b	. @ reset
	b	. @ undefined instruction
	b	. @ supervisor call
	b	. @ prefetch call
	b	. @ prefetch abort
	b	. @ data abort
	b	irq_handler @ irq
	.word 0xe7f000f0    @ abort on FIQ

@ Call fault_undefined_instruction in "Undefined mode"
bug:
	.word	0xe7f000f0    	@ und/udf - a "Permanently Undefined" instruction

irq_handler:
	ldr	sp, =irqstack_end
	push	{r0 - r12, r14}

	ldr	r0, IRQ_handler
	cmp	r0, #0
	beq	bug
	blx	r0		@ call handler

	@ Return from IRQ
	pop	{r0 - r12, r14}
	clrex
	subs	pc, lr, #4

.globl IRQ_handler
IRQ_handler:
	.long	0x0


.globl __arch_switch_threads
@ => r0 = &prev->sp
@    r1 = &next->sp
@ <= returns to next thread's saved return address
__arch_switch_threads:
	push	{r4-r11}	@ Store callee-saved registers to old thread's stack
	stmia	r0, {sp, lr}	@ Store current sp and ip to prev's struct thread

	ldmia	r1, {sp, lr}	@ Load new sp, ip from next's struct thread
	pop	{r4-r11}	@ Load callee-saved registers from new thread's stack

	bx	lr

@ This is called if you try to divide by zero. For now, we make a supervisor call,
@ which will make us halt.
.globl raise
raise:
	svc	0

.globl arm_start_thread
arm_start_thread:
	pop	{r0, r1}
	@ r0 = user data
	@ r1 -> thread's main function
	ldr	lr, =exit_thread
	bx	r1
