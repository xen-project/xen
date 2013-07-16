/*
 * xen/include/xen/ns16550-uart.h
 *
 * This header is extracted from driver/char/ns16550.c
 *
 * Common constant definition between early printk and the UART driver
 * for the 16550-series UART
 *
 * Copyright (c) 2003-2005, K A Fraser
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

#ifndef __XEN_NS16550_UART_H__
#define __XEN_NS16550_UART_H__

/* Register offsets */
#define UART_RBR          0x00    /* receive buffer       */
#define UART_THR          0x00    /* transmit holding     */
#define UART_IER          0x01    /* interrupt enable     */
#define UART_IIR          0x02    /* interrupt identity   */
#define UART_FCR          0x02    /* FIFO control         */
#define UART_LCR          0x03    /* line control         */
#define UART_MCR          0x04    /* Modem control        */
#define UART_LSR          0x05    /* line status          */
#define UART_MSR          0x06    /* Modem status         */
#define UART_DLL          0x00    /* divisor latch (ls) (DLAB=1) */
#define UART_DLM          0x01    /* divisor latch (ms) (DLAB=1) */

/* Interrupt Enable Register */
#define UART_IER_ERDAI    0x01    /* rx data recv'd       */
#define UART_IER_ETHREI   0x02    /* tx reg. empty        */
#define UART_IER_ELSI     0x04    /* rx line status       */
#define UART_IER_EMSI     0x08    /* MODEM status         */

/* Interrupt Identificatiegister */
#define UART_IIR_NOINT    0x01    /* no interrupt pending */
#define UART_UART_IIR_IMA 0x06    /* interrupt identity:  */
#define UART_UART_IIR_LSI 0x06    /*  - rx line status    */
#define UART_UART_IIR_RDA 0x04    /*  - rx data recv'd    */
#define UART_UART_IIR_THR 0x02    /*  - tx reg. empty     */
#define UART_UART_IIR_MSI 0x00    /*  - MODEM status      */

/* FIFO Control Register */
#define UART_FCR_ENABLE   0x01    /* enable FIFO          */
#define UART_FCR_CLRX     0x02    /* clear Rx FIFO        */
#define UART_FCR_CLTX     0x04    /* clear Tx FIFO        */
#define UART_FCR_DMA      0x10    /* enter DMA mode       */
#define UART_FCR_TRG1     0x00    /* Rx FIFO trig lev 1   */
#define UART_FCR_TRG4     0x40    /* Rx FIFO trig lev 4   */
#define UART_FCR_TRG8     0x80    /* Rx FIFO trig lev 8   */
#define UART_FCR_TRG14    0xc0    /* Rx FIFO trig lev 14  */

/* Line Control Register */
#define UART_LCR_DLAB     0x80    /* Divisor Latch Access */

/* Modem Control Register */
#define UART_MCR_DTR      0x01    /* Data Terminal Ready  */
#define UART_MCR_RTS      0x02    /* Request to Send      */
#define UART_MCR_OUT2     0x08    /* OUT2: interrupt mask */
#define UART_MCR_LOOP     0x10    /* Enable loopback test mode */

/* Line Status Register */
#define UART_LSR_DR       0x01    /* Data ready           */
#define UART_LSR_OE       0x02    /* Overrun              */
#define UART_LSR_PE       0x04    /* Parity error         */
#define UART_LSR_FE       0x08    /* Framing error        */
#define UART_LSR_BI       0x10    /* Break                */
#define UART_LSR_THRE     0x20    /* Xmit hold reg empty  */
#define UART_LSR_TEMT     0x40    /* Xmitter empty        */
#define UART_LSR_ERR      0x80    /* Error                */

/* These parity settings can be ORed directly into the LCR. */
#define UART_PARITY_NONE  (0<<3)
#define UART_PARITY_ODD   (1<<3)
#define UART_PARITY_EVEN  (3<<3)
#define UART_PARITY_MARK  (5<<3)
#define UART_PARITY_SPACE (7<<3)

/* Frequency of external clock source. This definition assumes PC platform. */
#define UART_CLOCK_HZ     1843200

/* Resume retry settings */
#define RESUME_DELAY      MILLISECS(10)
#define RESUME_RETRIES    100

#endif /* __XEN_NS16550_UART_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
