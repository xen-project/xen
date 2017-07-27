/*
 * xen/arch/arm/arm64/debug-scif.inc
 *
 * SCIF specific debug code
 *
 * Oleksandr Tyshchenko <oleksandr.tyshchenko@globallogic.com>
 * Iurii Konovalenko <iurii.konovalenko@globallogic.com>
 * Iurii Mykhalskyi <iurii.mykhalskyi@globallogic.com>
 * Copyright (C) 2014-2016, Globallogic.
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

/*
 * SCIF UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
        ldrh   w\c, [\xb, #SCIF_SCFSR]   /* <- SCFSR (status register) */
        tst    w\c, #SCFSR_TDFE          /* Check TDFE bit */
        beq    1b                        /* Wait for the UART to be ready */
.endm

/*
 * SCIF UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
        strb   \wt, [\xb, #SCIF_SCFTDR]                  /* -> SCFTDR (data register) */
        ldrh   \wt, [\xb, #SCIF_SCFSR]                   /* <- SCFSR (status register) */
        and    \wt, \wt, #(~(SCFSR_TEND | SCFSR_TDFE))   /* Clear TEND and TDFE bits */
        strh   \wt, [\xb, #SCIF_SCFSR]                   /* -> SCFSR (status register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
