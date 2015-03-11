/*
 * xen/include/asm-arm/cadence-uart.h
 *
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
 * Copyright (C) 2015 Xilinx Inc.
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

#ifndef __ASM_ARM_CADENCE_UART_H__
#define __ASM_ARM_CADENCE_UART_H__

#define R_UART_CR    0x00
#define UART_CR_RX_RST       0x01
#define UART_CR_TX_RST       0x02
#define UART_CR_RX_ENABLE    0x04
#define UART_CR_RX_DISABLE   0x08
#define UART_CR_TX_ENABLE    0x10
#define UART_CR_TX_DISABLE   0x20

#define R_UART_MR    0x04
#define UART_MR_NO_PARITY    0x20

#define R_UART_IER   0x08
#define R_UART_IDR   0x0C
#define R_UART_IMR   0x10
#define R_UART_CISR  0x14
#define R_UART_RTRIG 0x20
#define R_UART_SR    0x2C
#define UART_SR_INTR_RTRIG   0x01
#define UART_SR_INTR_REMPTY  0x02
#define UART_SR_INTR_TEMPTY  0x08
#define UART_SR_INTR_TFUL    0x10

#define R_UART_TX    0x30
#define R_UART_RX    0x30

#endif /* __ASM_ARM_CADENCE_UART_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
