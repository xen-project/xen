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

GLOBAL(saved_magic)
        .long   0x9abcdef0
