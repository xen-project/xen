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

        SAVE_GREG(sp)
        SAVE_GREG(ax)
        SAVE_GREG(bx)
        SAVE_GREG(cx)
        SAVE_GREG(dx)
        SAVE_GREG(bp)
        SAVE_GREG(si)
        SAVE_GREG(di)

        SAVE_GREG(8)     # save r8...r15
        SAVE_GREG(9)
        SAVE_GREG(10)
        SAVE_GREG(11)
        SAVE_GREG(12)
        SAVE_GREG(13)
        SAVE_GREG(14)
        SAVE_GREG(15)
        pushfq;
        popq    SAVED_GREG(flags)

        mov     %ss, REF(saved_ss)

        mov     %cr0, GREG(ax)
        mov     GREG(ax), REF(saved_cr0)

        mov     %cr3, GREG(ax)
        mov     GREG(ax), REF(saved_cr3)

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
         *
         * Everything else, including the stack, needs restoring.
         */
ENTRY(s3_resume)
        lgdt    boot_gdtr(%rip)

        /* mmu_cr4_features contains latest cr4 setting */
        mov     REF(mmu_cr4_features), GREG(ax)
        mov     GREG(ax), %cr4

        mov     REF(saved_cr3), GREG(ax)
        mov     GREG(ax), %cr3

        mov     REF(saved_cr0), GREG(ax)
        mov     GREG(ax), %cr0

        mov     REF(saved_ss), %ss
        LOAD_GREG(sp)

        /* Reload code selector */
        pushq   $__HYPERVISOR_CS
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:
        pushq   SAVED_GREG(flags)
        popfq

        call restore_rest_processor_state

        LOAD_GREG(bp)
        LOAD_GREG(ax)
        LOAD_GREG(bx)
        LOAD_GREG(cx)
        LOAD_GREG(dx)
        LOAD_GREG(si)
        LOAD_GREG(di)
        LOAD_GREG(8)     # save r8...r15
        LOAD_GREG(9)
        LOAD_GREG(10)
        LOAD_GREG(11)
        LOAD_GREG(12)
        LOAD_GREG(13)
        LOAD_GREG(14)
        LOAD_GREG(15)
.Lsuspend_err:
        ret

.data
        .align 16

GLOBAL(saved_magic)
        .long   0x9abcdef0

saved_ss:        .word   0

        .align 8
DECLARE_GREG(sp)
DECLARE_GREG(bp)
DECLARE_GREG(ax)
DECLARE_GREG(bx)
DECLARE_GREG(cx)
DECLARE_GREG(dx)
DECLARE_GREG(si)
DECLARE_GREG(di)
DECLARE_GREG(flags)

DECLARE_GREG(8)
DECLARE_GREG(9)
DECLARE_GREG(10)
DECLARE_GREG(11)
DECLARE_GREG(12)
DECLARE_GREG(13)
DECLARE_GREG(14)
DECLARE_GREG(15)

saved_cr0:      .quad   0
saved_cr3:      .quad   0
