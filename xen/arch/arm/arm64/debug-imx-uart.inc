/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Early printk for the classic i.MX UART IP (i.MX8M family).
 * The UART is expected to be fully initialized by the bootloader.
 *
 * Copyright 2026 Open-EP (E-Paper) Community
 */

#include <asm/imx-uart.h>

/*
 * Wait for the UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb, c
1:
        ldr   w\c, [\xb, #UTS]        /* <- Test register */
        tst   w\c, #UTS_TXFULL        /* Check TX FIFO full bit */
        b.ne  1b                      /* Wait until there is room */
.endm

/*
 * UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
        str   \wt, [\xb, #URTX0]      /* -> Transmitter register */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
