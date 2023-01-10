        .section .text.header, "ax", %progbits

ENTRY(start)
        la      sp, cpu0_boot_stack
        li      t0, STACK_SIZE
        add     sp, sp, t0

        tail    start_xen
