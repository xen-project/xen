#include <os.h>
#include <arch_limits.h>
#include <xen/arch-x86_64.h>

/* For simplicity, we keep all of this into just one data page */
.data
.globl _boot_page
_boot_page:
        .align __PAGE_SIZE

/*
 * The following data is initialized from C code
 */

/* Pte of this page */
.globl _boot_page_entry
_boot_page_entry:
        .quad 0

/* mmuext_op structure */
/* Set new page directory */
_boot_mmuext:
        /* Op # */
        .long MMUEXT_NEW_BASEPTR
        .long 0 /* pad */

        /* MFN of target page table directory */
.globl _boot_pdmfn
_boot_pdmfn:
        .quad 0

        /* Unused */
        .quad 0

/* Unpin old page directory */
        /* Op # */
        .long MMUEXT_UNPIN_TABLE
        .long 0 /* pad */

        /* MFN of old page table directory */
.globl _boot_oldpdmfn
_boot_oldpdmfn:
        .quad 0

        /* Unused */
        .quad 0

/* Target stack address, also target virtual address of this page */
.globl _boot_stack
_boot_stack:
        .quad 0
.globl _boot_target
_boot_target:
        .quad 0

/* Target start info */
.globl _boot_start_info
_boot_start_info:
        .quad 0

/* Target start address */
.globl _boot_start
_boot_start:
        .quad 0

/*
 * Boot target OS, does not return
 */
.globl _boot
_boot:
        /* Project ourselves at the target place. */
        movq    _boot_target, %rdi
        movq    _boot_page_entry, %rsi
        movq    $2, %rdx /* UVMF_INVLPG */
        movq    $__HYPERVISOR_update_va_mapping, %rax
        syscall
        testq   %rax, %rax
        jz      0f
        ud2

0:
        /* Go there. */
        movq    $(0f - _boot_page), %rax
        movq    _boot_target, %rbx
        addq    %rbx, %rax
        jmpq    *%rax
0:
        
        /* Load target page table and unpin old page table.  */
        /* We shouldn't have any problem since in the new page table our page is
           mapped at the same place.  */
        leaq    _boot_mmuext(%rip), %rdi
        movq    $2, %rsi
        xorq    %rdx, %rdx
        movq    $0x7FF0, %r10 /* DOMID_SELF */
        movq    $__HYPERVISOR_mmuext_op, %rax
        syscall
        testq   %rax, %rax
        jns     0f
        ud2

0:
        /* Initialize registers.  */
        movq    _boot_stack(%rip), %rsp
        movq    _boot_start_info(%rip), %rsi

        /* Jump!  */
        jmpq    *_boot_start(%rip)
