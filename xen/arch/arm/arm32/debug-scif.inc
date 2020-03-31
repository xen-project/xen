/*
 * xen/arch/arm/arm32/debug-scif.inc
 *
 * SCIF(A) specific debug code
 *
 * Oleksandr Tyshchenko <oleksandr.tyshchenko@globallogic.com>
 * Copyright (C) 2014, Globallogic.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/scif-uart.h>

#ifdef CONFIG_EARLY_UART_SCIF_VERSION_NONE
#define STATUS_REG    SCIF_SCFSR
#define TX_FIFO_REG   SCIF_SCFTDR
#elif CONFIG_EARLY_UART_SCIF_VERSION_A
#define STATUS_REG    SCIFA_SCASSR
#define TX_FIFO_REG   SCIFA_SCAFTDR
#endif

/*
 * Wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register
 */
.macro early_uart_ready rb rc
1:
        ldrh   \rc, [\rb, #STATUS_REG]   /* Read status register */
        tst    \rc, #SCFSR_TDFE          /* Check TDFE bit */
        beq    1b                        /* Wait for the UART to be ready */
.endm

/*
 * UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit
 */
.macro early_uart_transmit rb rt
        strb   \rt, [\rb, #TX_FIFO_REG]                  /* Write data register */
        ldrh   \rt, [\rb, #STATUS_REG]                   /* Read status register */
        and    \rt, \rt, #(~(SCFSR_TEND | SCFSR_TDFE))   /* Clear TEND and TDFE bits */
        strh   \rt, [\rb, #STATUS_REG]                   /* Write status register */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
