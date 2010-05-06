/*
 * Compatibility kexec handler.
 */

/*
 * NOTE: We rely on Xen not relocating itself above the 4G boundary. This is
 * currently true but if it ever changes then compat_pg_table will
 * need to be moved back below 4G at run time.
 */

#include <xen/config.h>

#include <asm/asm_defns.h>
#include <asm/msr.h>
#include <asm/page.h>

/* The unrelocated physical address of a symbol. */
#define SYM_PHYS(sym)          ((sym) - __XEN_VIRT_START)

/* Load physical address of symbol into register and relocate it. */
#define RELOCATE_SYM(sym,reg)  mov $SYM_PHYS(sym), reg ; \
                               add xen_phys_start(%rip), reg

/*
 * Relocate a physical address in memory. Size of temporary register
 * determines size of the value to relocate.
 */
#define RELOCATE_MEM(addr,reg) mov addr(%rip), reg ; \
                               add xen_phys_start(%rip), reg ; \
                               mov reg, addr(%rip)

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

        RELOCATE_SYM(compat_page_list,%rdx)

        /* Relocate compatibility mode entry point address. */
        RELOCATE_MEM(compatibility_mode_far,%eax)

        /* Relocate compat_pg_table. */
        RELOCATE_MEM(compat_pg_table,     %rax)
        RELOCATE_MEM(compat_pg_table+0x8, %rax)
        RELOCATE_MEM(compat_pg_table+0x10,%rax)
        RELOCATE_MEM(compat_pg_table+0x18,%rax)

        /*
         * Setup an identity mapped region in PML4[0] of idle page
         * table.
         */
        RELOCATE_SYM(l3_identmap,%rax)
        or  $0x63,%rax
        mov %rax, idle_pg_table(%rip)

        /* Switch to idle page table. */
        RELOCATE_SYM(idle_pg_table,%rax)
        movq %rax, %cr3

        /* Switch to identity mapped compatibility stack. */
        RELOCATE_SYM(compat_stack,%rax)
        movq %rax, %rsp

        /* Save xen_phys_start for 32 bit code. */
        movq xen_phys_start(%rip), %rbx

        /* Jump to low identity mapping in compatibility mode. */
        ljmp *compatibility_mode_far(%rip)
        ud2

compatibility_mode_far:
        .long SYM_PHYS(compatibility_mode)
        .long __HYPERVISOR_CS32

        /*
         * We use 5 words of stack for the arguments passed to the kernel. The
         * kernel only uses 1 word before switching to its own stack. Allocate
         * 16 words to give "plenty" of room.
         */
        .fill 16,4,0
compat_stack:

        .code32

#undef RELOCATE_SYM
#undef RELOCATE_MEM

/*
 * Load physical address of symbol into register and relocate it. %rbx
 * contains xen_phys_start(%rip) saved before jump to compatibility
 * mode.
 */
#define RELOCATE_SYM(sym,reg) mov $SYM_PHYS(sym), reg ; \
                              add %ebx, reg

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
        RELOCATE_SYM(compat_pg_table, %eax)
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
        jmp 1f
1:

        popl %eax
        call *%eax
        ud2

        .data
        .align 4
compat_page_list:
        .fill 12,4,0

        .align 32,0

        /*
         * These compat page tables contain an identity mapping of the
         * first 4G of the physical address space.
         */
compat_pg_table:
        .long SYM_PHYS(compat_pg_table_l2) + 0*PAGE_SIZE + 0x01, 0
        .long SYM_PHYS(compat_pg_table_l2) + 1*PAGE_SIZE + 0x01, 0
        .long SYM_PHYS(compat_pg_table_l2) + 2*PAGE_SIZE + 0x01, 0
        .long SYM_PHYS(compat_pg_table_l2) + 3*PAGE_SIZE + 0x01, 0

        .section .data.page_aligned, "aw", @progbits
        .align PAGE_SIZE,0
compat_pg_table_l2:
        .macro identmap from=0, count=512
        .if \count-1
        identmap "(\from+0)","(\count/2)"
        identmap "(\from+(0x200000*(\count/2)))","(\count/2)"
        .else
        .quad 0x00000000000000e3 + \from
        .endif
        .endm

        identmap 0x00000000
        identmap 0x40000000
        identmap 0x80000000
        identmap 0xc0000000
