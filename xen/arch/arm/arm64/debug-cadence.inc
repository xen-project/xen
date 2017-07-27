/*
 * xen/arch/arm/arm64/debug-cadence.S
 *
 * Cadence UART specific debug code
 *
 * Copyright (c) 2015 Xilinx Inc.
 * Written by Edgar E. Iglesias.
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

#include <asm/asm_defns.h>
#include <asm/cadence-uart.h>

/*
 * Cadence UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register number
 */
.macro early_uart_ready xb, c
1:
        ldrh  w\c, [\xb, #R_UART_SR]
        tst   w\c, #UART_SR_INTR_TFUL
        b.ne  1b
.endm

/*
 * Cadence UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
        strb  \wt, [\xb, #R_UART_TX]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
