/*
 * xen/arch/arm/arm64/debug-meson.inc
 *
 * MESON specific debug code.
 *
 * Copyright (c) 2019, Amit Singh Tomar <amittomer25@gmail.com>.
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

#define AML_UART_WFIFO_REG      0x00
#define AML_UART_STATUS_REG     0x0c

#define AML_UART_TX_FIFO_FULL   21

.macro early_uart_init xb, c
/* Uart has already been initialized by Firmware, for instance by TF-A */
.endm

/*
 * MESON UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
        ldr     w\c, [\xb, #AML_UART_STATUS_REG]        /* status register */
        tbnz    w\c, #AML_UART_TX_FIFO_FULL, 1b         /* Check TXFIFO FULL bit */
.endm

/*
 * MESON UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
        str    \wt, [\xb, #AML_UART_WFIFO_REG]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
