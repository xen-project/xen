/*
 * xen/arch/arm/arm64/debug-mvebu.inc
 *
 * MVEBU specific debug code.
 *
 * Copyright (c) 2018, Amit Singh Tomar <amittomer25@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#define UART_STATUS_REG     0x0c
#define UART_TX_REG         0x04

/*
 * MVEBU UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
        ldrh   w\c, [\xb, #UART_STATUS_REG] /* status register */
        tst    w\c, #(1 << 11)              /* Check TXFIFO FULL bit */
        b.ne   1b                           /* Wait for the UART to be ready */
.endm

/*
 * MVEBU UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
	strb  \wt, [\xb, #UART_TX_REG]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
