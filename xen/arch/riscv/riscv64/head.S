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

        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        tail    start_xen
