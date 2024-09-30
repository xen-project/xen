/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/arm64/debug-linflex.inc
 *
 * NXP LINFlexD UART specific debug code
 *
 * Andrei Cherechesu <andrei.cherechesu@nxp.com>
 * Copyright 2018, 2021, 2023-2024 NXP
 */

#include <asm/asm_defns.h>
#include <asm/linflex-uart.h>

/*
 * wait LINFlexD UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register number
 */
.macro early_uart_ready xb, c
    ldr   w\c, [\xb, #UARTCR]       /* <= Control Register */
    and   w\c, w\c, #UARTCR_TFBM    /* Check Buffer/FIFO (0/1) Mode */
    cbz   w\c, 2f                   /* Buffer Mode => return */
1:
    ldrb  w\c, [\xb, #UARTSR]       /* <= Status Register */
    tst   w\c, #UARTSR_DTFTFF       /* FIFO Mode => Check DTF bit */
    b.ne  1b
2:
.endm

/*
 * LINFlexD UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
    strb  \wt, [\xb, #BDRL]

    ldr   \wt, [\xb, #UARTCR]       /* <= Control Register */
    and   \wt, \wt, #UARTCR_TFBM    /* Check Buffer/FIFO (0/1) Mode */
    cbnz  \wt, 2f                   /* FIFO Mode => goto exit */

3:  /* Buffer Mode */
    ldrb  \wt, [\xb, #UARTSR]       /* <= Status Register */
    and   \wt, \wt, #UARTSR_DTFTFF  /* Check Transmission Completed */
    cbz   \wt, 3b

    ldr   \wt, [\xb, #UARTSR]       /* <= Status Register */
    orr   \wt, \wt, #UARTSR_DTFTFF  /* Clear DTF bit */
    str   \wt, [\xb, #UARTSR]
2:
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
