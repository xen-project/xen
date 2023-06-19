#include <asm/asm.h>
#include <asm/riscv_encoding.h>

        .section .text.header, "ax", %progbits

        /*
         * OpenSBI pass to start():
         *   a0 -> hart_id ( bootcpu_id )
         *   a1 -> dtb_base 
         */
ENTRY(start)
        /* Mask all interrupts */
        csrw    CSR_SIE, zero

        /*
         * Disable FPU to detect illegal usage of
         * floating point in kernel space
         */
        li      t0, SSTATUS_FS
        csrc    CSR_SSTATUS, t0

        /* Clear the BSS */
        la      t3, __bss_start
        la      t4, __bss_end
.L_clear_bss:
        REG_S   zero, (t3)
        add     t3, t3, __SIZEOF_POINTER__
        bltu    t3, t4, .L_clear_bss

        jal     reset_stack

        tail    start_xen

        .section .text, "ax", %progbits

ENTRY(reset_stack)
        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        ret

