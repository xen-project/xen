        .file __FILE__
        .text
        .code64

#define GREG(x)         %r##x
#define SAVED_GREG(x)   saved_r##x(%rip)
#define DECLARE_GREG(x) saved_r##x:     .quad   0
#define SAVE_GREG(x)    movq GREG(x), SAVED_GREG(x)
#define LOAD_GREG(x)    movq SAVED_GREG(x), GREG(x)

#define REF(x)          x(%rip)

ENTRY(do_suspend_lowlevel)
        push    %rbp
        push    %rbx
        push    %r12
        push    %r13
        push    %r14
        push    %r15

        SAVE_GREG(sp)

        mov     %cr0, GREG(ax)
        mov     GREG(ax), REF(saved_cr0)

        call    save_rest_processor_state

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

        /* mmu_cr4_features contains latest cr4 setting */
        mov     REF(mmu_cr4_features), GREG(ax)
        mov     GREG(ax), %cr4

        mov     REF(saved_cr0), GREG(ax)
        mov     GREG(ax), %cr0

        mov     $__HYPERVISOR_DS64, %eax
        mov     %eax, %ss
        LOAD_GREG(sp)

        /* Reload code selector */
        pushq   $__HYPERVISOR_CS
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:

        call restore_rest_processor_state

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

GLOBAL(saved_magic)
        .long   0x9abcdef0

        .align 8
DECLARE_GREG(sp)

saved_cr0:      .quad   0
