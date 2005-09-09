
#include <linux/config.h>

.section __xen_guest
	.ascii	"GUEST_OS=linux,GUEST_VER=2.6"
	.ascii	",XEN_VER=3.0"
	.ascii	",VIRT_BASE=0xC0000000"
#ifdef CONFIG_X86_PAE
	.ascii	",PAE=yes"
#else
	.ascii	",PAE=no"
#endif
#ifdef CONFIG_XEN_SHADOW_MODE
	.ascii	",SHADOW=translate"
#endif
	.ascii	",LOADER=generic"
	.byte	0

.text
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/thread_info.h>
#include <asm/asm_offsets.h>
#include <asm-xen/xen-public/arch-x86_32.h>

/*
 * References to members of the new_cpu_data structure.
 */

#define X86		new_cpu_data+CPUINFO_x86
#define X86_VENDOR	new_cpu_data+CPUINFO_x86_vendor
#define X86_MODEL	new_cpu_data+CPUINFO_x86_model
#define X86_MASK	new_cpu_data+CPUINFO_x86_mask
#define X86_HARD_MATH	new_cpu_data+CPUINFO_hard_math
#define X86_CPUID	new_cpu_data+CPUINFO_cpuid_level
#define X86_CAPABILITY	new_cpu_data+CPUINFO_x86_capability
#define X86_VENDOR_ID	new_cpu_data+CPUINFO_x86_vendor_id

ENTRY(startup_32)
	movl %esi,xen_start_info

#ifdef CONFIG_SMP
ENTRY(startup_32_smp)
#endif /* CONFIG_SMP */

	cld

	/* Set up the stack pointer */
	lss stack_start,%esp

checkCPUtype:

	/* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	cpuid
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	movl $1,%eax		# Use the CPUID instruction to get CPU type
	cpuid
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

	incb ready

	xorl %eax,%eax			# Clear FS/GS and LDT
	movl %eax,%fs
	movl %eax,%gs
	cld			# gcc2 wants the direction flag cleared at all times

#ifdef CONFIG_SMP
	movb ready, %cl	
	cmpb $1,%cl
	je 1f			# the first CPU calls start_kernel
				# all other CPUs call initialize_secondary
	call initialize_secondary
	jmp L6
1:
#endif /* CONFIG_SMP */
	call start_kernel
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.

ENTRY(lgdt_finish)
	movl $(__KERNEL_DS),%eax	# reload all the segment registers
	movw %ax,%ss			# after changing gdt.

	movl $(__USER_DS),%eax		# DS/ES contains default USER segment
	movw %ax,%ds
	movw %ax,%es

	popl %eax			# reload CS by intersegment return
	pushl $(__KERNEL_CS)
	pushl %eax
	lret

ENTRY(stack_start)
	.long init_thread_union+THREAD_SIZE
	.long __BOOT_DS

ready:	.byte 0

.globl idt_descr
.globl cpu_gdt_descr

	ALIGN
	.word 0				# 32-bit align idt_desc.address
idt_descr:
	.word IDT_ENTRIES*8-1		# idt contains 256 entries
	.long idt_table

# boot GDT descriptor (later on used by CPU#0):
	.word 0				# 32 bit align gdt_desc.address
cpu_gdt_descr:
	.word GDT_SIZE
	.long cpu_gdt_table

	.fill NR_CPUS-1,8,0		# space for the other GDT descriptors

.org 0x1000
ENTRY(empty_zero_page)

.org 0x2000
ENTRY(cpu_gdt_table)
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* 0x0b reserved */
	.quad 0x0000000000000000	/* 0x13 reserved */
	.quad 0x0000000000000000	/* 0x1b reserved */
	.quad 0x0000000000000000	/* 0x20 unused */
	.quad 0x0000000000000000	/* 0x28 unused */
	.quad 0x0000000000000000	/* 0x33 TLS entry 1 */
	.quad 0x0000000000000000	/* 0x3b TLS entry 2 */
	.quad 0x0000000000000000	/* 0x43 TLS entry 3 */
	.quad 0x0000000000000000	/* 0x4b reserved */
	.quad 0x0000000000000000	/* 0x53 reserved */
	.quad 0x0000000000000000	/* 0x5b reserved */

#ifdef CONFIG_X86_PAE
	.quad 0x00cfbb00000067ff	/* 0x60 kernel 4GB code at 0x00000000 */
	.quad 0x00cfb300000067ff	/* 0x68 kernel 4GB data at 0x00000000 */
	.quad 0x00cffb00000067ff	/* 0x73 user 4GB code at 0x00000000 */
	.quad 0x00cff300000067ff	/* 0x7b user 4GB data at 0x00000000 */
#else
	.quad 0x00cfbb000000c3ff	/* 0x60 kernel 4GB code at 0x00000000 */
	.quad 0x00cfb3000000c3ff	/* 0x68 kernel 4GB data at 0x00000000 */
	.quad 0x00cffb000000c3ff	/* 0x73 user 4GB code at 0x00000000 */
	.quad 0x00cff3000000c3ff	/* 0x7b user 4GB data at 0x00000000 */
#endif

	.quad 0x0000000000000000	/* 0x80 TSS descriptor */
	.quad 0x0000000000000000	/* 0x88 LDT descriptor */

	/* Segments used for calling PnP BIOS */
	.quad 0x0000000000000000	/* 0x90 32-bit code */
	.quad 0x0000000000000000	/* 0x98 16-bit code */
	.quad 0x0000000000000000	/* 0xa0 16-bit data */
	.quad 0x0000000000000000	/* 0xa8 16-bit data */
	.quad 0x0000000000000000	/* 0xb0 16-bit data */
	/*
	 * The APM segments have byte granularity and their bases
	 * and limits are set at run time.
	 */
	.quad 0x0000000000000000	/* 0xb8 APM CS    code */
	.quad 0x0000000000000000	/* 0xc0 APM CS 16 code (16 bit) */
	.quad 0x0000000000000000	/* 0xc8 APM DS    data */

	.quad 0x0000000000000000	/* 0xd0 - ESPFIX 16-bit SS */
	.quad 0x0000000000000000	/* 0xd8 - unused */
	.quad 0x0000000000000000	/* 0xe0 - unused */
	.quad 0x0000000000000000	/* 0xe8 - unused */
	.quad 0x0000000000000000	/* 0xf0 - unused */
	.quad 0x0000000000000000	/* 0xf8 - GDT entry 31: double-fault TSS */
	.fill GDT_ENTRIES-32,8,0

.org 0x3000
ENTRY(default_ldt)

.org 0x4000
/*
 * Real beginning of normal "text" segment
 */
ENTRY(stext)
ENTRY(_stext)
