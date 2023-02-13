#include <asm/riscv_encoding.h>

        .section .text.header, "ax", %progbits

ENTRY(start)
        /* Mask all interrupts */
        csrw    CSR_SIE, zero

        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        tail    start_xen
