/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Register definitions for the classic i.MX UART IP
 * ("fsl,imx6q-uart" compatible), used as the console UART on the
 * i.MX8M family.
 *
 * Register layout taken from Linux drivers/tty/serial/imx.c.
 *
 * Copyright 2026 Open-EP (E-Paper) Community
 */

#ifndef ASM_IMX_UART_H
#define ASM_IMX_UART_H

#include <xen/const.h>

#define URXD0           0x00   /* Receiver Register */
#define URTX0           0x40   /* Transmitter Register */
#define UCR1            0x80   /* Control Register 1 */
#define UCR2            0x84   /* Control Register 2 */
#define USR1            0x94   /* Status Register 1 */
#define USR2            0x98   /* Status Register 2 */
#define UTS             0xb4   /* Test Register */

#define URXD_RX_DATA    0xff

#define UCR1_UARTEN     BIT(0, U)   /* UART enable */
#define UCR1_ATDMAEN    BIT(2, U)   /* Aging DMA timer enable */
#define UCR1_TXDMAEN    BIT(3, U)   /* Transmitter ready DMA enable */
#define UCR1_TXMPTYEN   BIT(6, U)   /* Transmitter empty interrupt enable */
#define UCR1_RXDMAEN    BIT(8, U)   /* Receiver ready DMA enable */
#define UCR1_RRDYEN     BIT(9, U)   /* Receiver ready interrupt enable */
#define UCR1_TRDYEN     BIT(13, U)  /* Transmitter ready interrupt enable */

#define UCR2_SRST       BIT(0, U)   /* 0 = issue software reset */
#define UCR2_RXEN       BIT(1, U)   /* Receiver enable */
#define UCR2_TXEN       BIT(2, U)   /* Transmitter enable */

#define USR1_TRDY       BIT(13, U)  /* Transmitter ready */

#define USR2_RDR        BIT(0, U)   /* Receive data ready */
#define USR2_ORE        BIT(1, U)   /* Overrun error */

#define UTS_TXFULL      BIT(4, U)   /* TX FIFO full */
#define UTS_RXEMPTY     BIT(5, U)   /* RX FIFO empty */
#define UTS_TXEMPTY     BIT(6, U)   /* TX FIFO empty */

#endif /* ASM_IMX_UART_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
