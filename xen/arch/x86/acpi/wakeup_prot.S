#include <asm/msr-index.h>
#include <asm/page.h>
#include <asm/processor.h>

        .file __FILE__
        .text
        .code64

ENTRY(do_suspend_lowlevel)
        push    %rbp
        push    %rbx
        push    %r12
        push    %r13
        push    %r14
        push    %r15

        mov     %rsp, saved_rsp(%rip)

        mov     %cr0, %rax
        mov     %rax, saved_cr0(%rip)

#ifdef CONFIG_XEN_SHSTK
        mov     $1, %eax
        rdsspq  %rax
        mov     %rax, saved_ssp(%rip)
#endif

        /* enter sleep state physically */
        mov     $3, %edi
        call    acpi_enter_sleep_state

        /* It seems we didn't suspend.  Get out of here. */
        jmp     .Lsuspend_err

        /*
         * do_suspend_lowlevel() is arranged to behave as a regular function
         * call, even if hardware actually goes to sleep in the middle.
         *
         * The trampoline re-intercepts here.  State is:
         *  - 64bit mode
         *  - %cr3 => idle_pg_table[]
         *
         * Everything else, including the stack, needs restoring.
         */
ENTRY(s3_resume)
        lgdt    boot_gdtr(%rip)

        mov     saved_cr0(%rip), %rax
        mov     %rax, %cr0

        mov     $__HYPERVISOR_DS64, %eax
        mov     %eax, %ss
        mov     saved_rsp(%rip), %rsp

        /* Reload code selector */
        pushq   $__HYPERVISOR_CS
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:
#ifdef CONFIG_XEN_SHSTK
        /*
         * Restoring SSP is a little complicated, because we are intercepting
         * an in-use shadow stack.  Write a temporary token under the stack,
         * so SETSSBSY will successfully load a value useful for us, then
         * reset MSR_PL0_SSP to its usual value and pop the temporary token.
         */
        mov     saved_rsp(%rip), %rdi
        cmpq    $1, %rdi
        je      .L_shstk_done

        /* Set up MSR_S_CET. */
        mov     $MSR_S_CET, %ecx
        xor     %edx, %edx
        mov     $CET_SHSTK_EN | CET_WRSS_EN, %eax
        wrmsr

        /* Construct the temporary supervisor token under SSP. */
        sub     $8, %rdi

        /* Load it into MSR_PL0_SSP. */
        mov     $MSR_PL0_SSP, %ecx
        mov     %rdi, %rdx
        shr     $32, %rdx
        mov     %edi, %eax
        wrmsr

        /* Enable CET.  MSR_INTERRUPT_SSP_TABLE is set up later in load_system_tables(). */
        mov     $XEN_MINIMAL_CR4 | X86_CR4_CET, %ebx
        mov     %rbx, %cr4

        /* Write the temporary token onto the shadow stack, and activate it. */
        wrssq   %rdi, (%rdi)
        setssbsy

        /* Reset MSR_PL0_SSP back to its normal value. */
        and     $~(STACK_SIZE - 1), %eax
        or      $(PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8, %eax
        wrmsr

        /* Pop the temporary token off the stack. */
        mov     $2, %eax
        incsspd %eax
.L_shstk_done:
#endif

        call    load_system_tables

.Lsuspend_err:
        pop     %r15
        pop     %r14
        pop     %r13
        pop     %r12
        pop     %rbx
        pop     %rbp
        ret

.data
        .align 16

saved_rsp:      .quad   0
saved_cr0:      .quad   0
#ifdef CONFIG_XEN_SHSTK
saved_ssp:      .quad   0
#endif

GLOBAL(saved_magic)
        .long   0x9abcdef0
