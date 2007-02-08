/*
 * Compatibility kexec handler.
 */

#include <xen/config.h>

#include <asm/asm_defns.h>
#include <asm/msr.h>
#include <asm/page.h>

.text

        .code64

ENTRY(compat_machine_kexec)
        /* x86/64                        x86/32  */
        /* %rdi - relocate_new_kernel_t  CALL    */
        /* %rsi - indirection page       4(%esp) */
        /* %rdx - page_list              8(%esp) */
        /* %rcx - start address         12(%esp) */
        /*        cpu has pae           16(%esp) */

        /* Shim the 64 bit page_list into a 32 bit page_list. */
        mov $12,%r9
        lea compat_page_list(%rip), %rbx
1:      dec %r9
        movl (%rdx,%r9,8),%eax
        movl %eax,(%rbx,%r9,4)
        test %r9,%r9
        jnz 1b

        movq %rbx,%rdx
        mov $__PAGE_OFFSET,%rbx
        sub %rbx, %rdx

        /*
         * Setup an identity mapped region in PML4[0] of idle page
         * table.
         */
        lea idle_pg_table_l3(%rip),%rax
        sub %rbx,%rax
        or  $0x63,%rax
        mov %rax, idle_pg_table(%rip)

        /* Switch to idle page table. */
        movq $(idle_pg_table - __PAGE_OFFSET), %rax
        movq %rax, %cr3

        /* Jump to low identity mapping in compatibility mode. */
        ljmp *compatibility_mode_far(%rip)
        ud2

compatibility_mode_far:
        .long compatibility_mode - __PAGE_OFFSET
        .long __HYPERVISOR_CS32

        .code32

compatibility_mode:
        /* Setup some sane segments. */
        movl $__HYPERVISOR_DS32, %eax
        movl %eax, %ds
        movl %eax, %es
        movl %eax, %fs
        movl %eax, %gs
        movl %eax, %ss

        /* Push arguments onto stack. */
        pushl $1   /* 16(%esp) - cpu has pae */
        pushl %ecx /* 12(%esp) - start address */
        pushl %edx /*  8(%esp) - page list */
        pushl %esi /*  4(%esp) - indirection page */
        pushl %edi /*  0(%esp) - CALL */

        /* Disable paging and therefore leave 64 bit mode. */
        movl %cr0, %eax
        andl $~X86_CR0_PG, %eax
        movl %eax, %cr0

        /* Switch to 32 bit page table. */
        movl  $compat_pg_table - __PAGE_OFFSET, %eax
        movl  %eax, %cr3

        /* Clear MSR_EFER[LME], disabling long mode */
        movl    $MSR_EFER,%ecx
        rdmsr
        btcl    $_EFER_LME,%eax
        wrmsr

        /* Re-enable paging, but only 32 bit mode now. */
        movl %cr0, %eax
        orl $X86_CR0_PG, %eax
        movl %eax, %cr0

        popl %eax
        call *%eax
        ud2

compat_page_list:
        .fill 12,4,0

        .align 32,0

        /*
         * These compat page tables contain an identity mapping of the
         * first 1G of the physical address space.
         */
compat_pg_table:
        .long compat_pg_table_l2 + 0*PAGE_SIZE + 0x01 - __PAGE_OFFSET, 0
        .long 0, 0
        .long 0, 0
        .long 0, 0

        .align 4096,0

compat_pg_table_l2:
        .macro identmap from=0, count=512
        .if \count-1
        identmap "(\from+0)","(\count/2)"
        identmap "(\from+(0x200000*(\count/2)))","(\count/2)"
        .else
        .quad 0x00000000000000e3 + \from
        .endif
        .endm

        identmap
