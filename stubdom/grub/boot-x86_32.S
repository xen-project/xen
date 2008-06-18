#include <os.h>
#include <arch_limits.h>
#include <xen/arch-x86_32.h>

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
_boot_page_entry_lo:
        .long 0
_boot_page_entry_hi:
        .long 0

/* mmuext_op structure */
/* Set new page directory */
_boot_mmuext:
        /* Op # */
        .long MMUEXT_NEW_BASEPTR

        /* MFN of target page table directory */
.globl _boot_pdmfn
_boot_pdmfn:
        .long 0

        /* Unused */
        .long 0

/* Unpin old page directory */
        /* Op # */
        .long MMUEXT_UNPIN_TABLE

        /* MFN of old page table directory */
.globl _boot_oldpdmfn
_boot_oldpdmfn:
        .long 0

        /* Unused */
        .long 0

/* Target stack address, also target virtual address of this page */
.globl _boot_stack
_boot_stack:
        .long 0
        .long __KERNEL_SS
.globl _boot_target
_boot_target:
        .long 0

/* Target start info */
.globl _boot_start_info
_boot_start_info:
        .long 0

/* Target start address */
.globl _boot_start
_boot_start:
        .long 0

/*
 * Boot target OS, does not return
 */
.globl _boot
_boot:
        /* Project ourselves at the target place. */
        movl    _boot_target, %ebx
        movl    %ebx, %ebp     /* also keep it in ebp for relative addressing */
        movl    _boot_page_entry_lo, %ecx
        movl    _boot_page_entry_hi, %edx
        movl    $2, %esi /* UVMF_INVLPG */
        movl    $__HYPERVISOR_update_va_mapping, %eax
        int     $0x82
        testl   %eax, %eax
        jz      0f
        ud2

0:
        /* Go there. */
        movl    $(0f - _boot_page), %eax
        movl    _boot_target, %ebx
        addl    %ebx, %eax
        jmpl    *%eax
0:
        
        /* Load target page table and unpin old page table.  */
        /* We shouldn't have any problem since in the new page table our page is
           mapped at the same place.  */
        leal    (_boot_mmuext-_boot_page)(%ebp), %ebx
        movl    $2, %ecx
        xorl    %edx, %edx
        movl    $0x7FF0, %esi /* DOMID_SELF */
        movl    $__HYPERVISOR_mmuext_op, %eax
        int     $0x82
        testl   %eax, %eax
        jns     0f
        ud2

0:
        /* Initialize registers.  */
        lss     (_boot_stack-_boot_page)(%ebp), %esp
        movl    (_boot_start_info-_boot_page)(%ebp), %esi

        /* Jump!  */
        jmpl    *(_boot_start-_boot_page)(%ebp)
