/*
 * xen/arch/arm/arm32/debug-scif.inc
 *
 * SCIF specific debug code
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

/* SCIF UART wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register
 */
.macro early_uart_ready rb rc
1:
        ldrh   \rc, [\rb, #SCIF_SCFSR]   /* <- SCFSR (status register) */
        tst    \rc, #SCFSR_TDFE          /* Check TDFE bit */
        beq    1b                        /* Wait for the UART to be ready */
.endm

/* SCIF UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit
 */
.macro early_uart_transmit rb rt
        strb   \rt, [\rb, #SCIF_SCFTDR]                  /* -> SCFTDR (data register) */
        ldrh   \rt, [\rb, #SCIF_SCFSR]                   /* <- SCFSR (status register) */
        and    \rt, \rt, #(~(SCFSR_TEND | SCFSR_TDFE))   /* Clear TEND and TDFE bits */
        strh   \rt, [\rb, #SCIF_SCFSR]                   /* -> SCFSR (status register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
