/*
 * xen/include/asm-arm/pl011-uart.h
 *
 * Common constant definition between early printk and the UART driver
 * for the pl011 UART
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
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

#ifndef __ASM_ARM_PL011_H
#define __ASM_ARM_PL011_H

/* PL011 register addresses */
#define DR     (0x00)
#define RSR    (0x04)
#define FR     (0x18)
#define ILPR   (0x20)
#define IBRD   (0x24)
#define FBRD   (0x28)
#define LCR_H  (0x2c)
#define CR     (0x30)
#define IFLS   (0x34)
#define IMSC   (0x38)
#define RIS    (0x3c)
#define MIS    (0x40)
#define ICR    (0x44)
#define DMACR  (0x48)

/* CR bits */
#define CTSEN  (1<<15) /* automatic CTS hardware flow control */
#define RTSEN  (1<<14) /* automatic RTS hardware flow control */
#define RTS    (1<<11) /* RTS signal */
#define DTR    (1<<10) /* DTR signal */
#define RXE    (1<<9) /* Receive enable */
#define TXE    (1<<8) /* Transmit enable */
#define UARTEN (1<<0) /* UART enable */

/* FR bits */
#define TXFE   (1<<7) /* TX FIFO empty */
#define RXFE   (1<<4) /* RX FIFO empty */
#define TXFF   (1<<5) /* TX FIFO full */
#define RXFF   (1<<6) /* RX FIFO full */
#define BUSY   (1<<3) /* Transmit is not complete */

/* LCR_H bits */
#define SPS    (1<<7) /* Stick parity select */
#define FEN    (1<<4) /* FIFO enable */
#define STP2   (1<<3) /* Two stop bits select */
#define EPS    (1<<2) /* Even parity select */
#define PEN    (1<<1) /* Parity enable */
#define BRK    (1<<0) /* Send break */

/* Interrupt bits (IMSC, MIS, ICR) */
#define OEI   (1<<10) /* Overrun Error interrupt mask */
#define BEI   (1<<9)  /* Break Error interrupt mask */
#define PEI   (1<<8)  /* Parity Error interrupt mask */
#define FEI   (1<<7)  /* Framing Error interrupt mask */
#define RTI   (1<<6)  /* Receive Timeout interrupt mask */
#define TXI   (1<<5)  /* Transmit interrupt mask */
#define RXI   (1<<4)  /* Receive interrupt mask */
#define DSRMI (1<<3)  /* nUARTDSR Modem interrupt mask */
#define DCDMI (1<<2)  /* nUARTDCD Modem interrupt mask */
#define CTSMI (1<<1)  /* nUARTCTS Modem interrupt mask */
#define RIMI  (1<<0)  /* nUARTRI Modem interrupt mask */
#define ALLI  OEI|BEI|PEI|FEI|RTI|TXI|RXI|DSRMI|DCDMI|CTSMI|RIMI

#endif /* __ASM_ARM_PL011_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
