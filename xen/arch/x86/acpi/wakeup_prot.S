#include <asm/asm_defns.h>
#include <asm/msr-index.h>
#include <asm/page.h>
#include <asm/processor.h>

        .file __FILE__
        .text
        .code64

FUNC(do_suspend_lowlevel)
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
LABEL(s3_resume)
        lgdt    boot_gdtr(%rip)

        mov     saved_cr0(%rip), %rax
        mov     %rax, %cr0

        mov     $__HYPERVISOR_DS64, %eax
        mov     %eax, %ds
        mov     %eax, %es
        mov     %eax, %fs
        mov     %eax, %gs
        mov     %eax, %ss
        mov     saved_rsp(%rip), %rsp

        /* Reload code selector */
        pushq   $__HYPERVISOR_CS
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:

        GET_STACK_END(15)

        /* Enable minimal CR4 features, sync cached state. */
        mov     $XEN_MINIMAL_CR4, %eax
        mov     %rax, STACK_CPUINFO_FIELD(cr4)(%r15)
        mov     %rax, %cr4

        /* Set up early exceptions and CET before entering C properly. */
        call    percpu_early_traps_init

#if defined(CONFIG_XEN_SHSTK) || defined(CONFIG_XEN_IBT)
        call    xen_msr_s_cet_value
        test    %eax, %eax
        jz      .L_cet_done

        /* Set up MSR_S_CET. */
        mov     $MSR_S_CET, %ecx
        xor     %edx, %edx
        wrmsr

        /* Enable CR4.CET. */
        mov     $X86_CR4_CET, %ecx
        or      STACK_CPUINFO_FIELD(cr4)(%r15), %rcx
        mov     %rcx, STACK_CPUINFO_FIELD(cr4)(%r15)
        mov     %rcx, %cr4

        /* WARNING! CALL/RET now fatal (iff SHSTK) until RSTORSSP loads SSP */

#if defined(CONFIG_XEN_SHSTK)
        test    $CET_SHSTK_EN, %al
        jz      .L_cet_done

        /*
         * Restoring SSP is a little complicated, because we are intercepting
         * an in-use shadow stack.  Write a Restore Token under the stack, and
         * use RSTORSSP to load it.  RSTORSSP converts the token to a
         * Previous-SSP Token, which we discard.
         */
        mov     saved_ssp(%rip), %rdi

        /* Calculate MSR_PL0_SSP from SSP. */
        mov     $MSR_PL0_SSP, %ecx
        mov     %rdi, %rdx
        shr     $32, %rdx
        mov     %edi, %eax
        and     $~(STACK_SIZE - 1), %eax
        or      $(PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8, %eax
        wrmsr

        /*
         * A Restore Token's value is &token + 8 + 64BIT (bit 0).
         * We want to put this on the shstk at SSP - 8.
         */
        lea     1(%rdi), %rax
        sub     $8, %rdi
        wrssq   %rax, (%rdi)
        rstorssp (%rdi)

        /* Discard the Previous-SSP Token from the shstk. */
        mov     $2, %eax
        incsspd %eax
#endif /* CONFIG_XEN_SHSTK */
.L_cet_done:
#endif /* CONFIG_XEN_SHSTK || CONFIG_XEN_IBT */

        /* Load all CR4 settings. */
        mov     mmu_cr4_features(%rip), %rax
        mov     %rax, STACK_CPUINFO_FIELD(cr4)(%r15)
        mov     %rax, %cr4

        call    mtrr_bp_restore

.Lsuspend_err:
        pop     %r15
        pop     %r14
        pop     %r13
        pop     %r12
        pop     %rbx
        pop     %rbp
        RET
END(do_suspend_lowlevel)

.data
        .align 16

saved_rsp:      .quad   0
saved_cr0:      .quad   0
#ifdef CONFIG_XEN_SHSTK
saved_ssp:      .quad   0
#endif

ASM_INT(saved_magic, 0x9abcdef0)
