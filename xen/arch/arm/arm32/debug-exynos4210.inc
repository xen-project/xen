/*
 * xen/arch/arm/arm32/debug-exynos4210.inc
 *
 * Exynos 5 specific debug code
 *
 * Copyright (c) 2013 Citrix Systems.
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

#include <asm/exynos4210-uart.h>

/* Exynos 5 UART wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register */
.macro early_uart_ready rb rc
1:
        ldr   \rc, [\rb, #UTRSTAT]   /* <- UTRSTAT (Flag register) */
        tst   \rc, #UTRSTAT_TXFE     /* Check BUSY bit */
        beq   1b                     /* Wait for the UART to be ready */
.endm

/* Exynos 5 UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit */
.macro early_uart_transmit rb rt
        str   \rt, [\rb, #UTXH]      /* -> UTXH (Data Register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
