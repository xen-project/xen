/*
 * xen/include/xen/8250-uart.h
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

#ifndef __XEN_8250_UART_H__
#define __XEN_8250_UART_H__

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
#define UART_USR          0x1f    /* Status register (DW) */
#define UART_DLL          0x00    /* divisor latch (ls) (DLAB=1) */
#define UART_DLM          0x01    /* divisor latch (ms) (DLAB=1) */
#define UART_XR_EFR       0x09    /* Enhanced function register (Exar) */

/* Interrupt Enable Register */
#define UART_IER_ERDAI    0x01    /* rx data recv'd       */
#define UART_IER_ETHREI   0x02    /* tx reg. empty        */
#define UART_IER_ELSI     0x04    /* rx line status       */
#define UART_IER_EMSI     0x08    /* MODEM status         */

/* Interrupt Identification Register */
#define UART_IIR_NOINT    0x01    /* no interrupt pending */
#define UART_IIR_IMA      0x06    /* interrupt identity:  */
#define UART_IIR_LSI      0x06    /*  - rx line status    */
#define UART_IIR_RDA      0x04    /*  - rx data recv'd    */
#define UART_IIR_THR      0x02    /*  - tx reg. empty     */
#define UART_IIR_MSI      0x00    /*  - MODEM status      */
#define UART_IIR_BSY      0x07    /*  - busy detect (DW) */

/* FIFO Control Register */
#define UART_FCR_ENABLE   0x01    /* enable FIFO          */
#define UART_FCR_CLRX     0x02    /* clear Rx FIFO        */
#define UART_FCR_CLTX     0x04    /* clear Tx FIFO        */
#define UART_FCR_DMA      0x10    /* enter DMA mode       */
#define UART_FCR_TRG1     0x00    /* Rx FIFO trig lev 1   */
#define UART_FCR_TRG4     0x40    /* Rx FIFO trig lev 4   */
#define UART_FCR_TRG8     0x80    /* Rx FIFO trig lev 8   */
#define UART_FCR_TRG14    0xc0    /* Rx FIFO trig lev 14  */

/*
 * Note: The FIFO trigger levels are chip specific:
 *	RX:76 = 00  01  10  11	TX:54 = 00  01  10  11
 * PC16550D:	 1   4   8  14		xx  xx  xx  xx
 * TI16C550A:	 1   4   8  14          xx  xx  xx  xx
 * TI16C550C:	 1   4   8  14          xx  xx  xx  xx
 * ST16C550:	 1   4   8  14		xx  xx  xx  xx
 * ST16C650:	 8  16  24  28		16   8  24  30	PORT_16650V2
 * NS16C552:	 1   4   8  14		xx  xx  xx  xx
 * ST16C654:	 8  16  56  60		 8  16  32  56	PORT_16654
 * TI16C750:	 1  16  32  56		xx  xx  xx  xx	PORT_16750
 * TI16C752:	 8  16  56  60		 8  16  32  56
 * Tegra:	 1   4   8  14		16   8   4   1	PORT_TEGRA
 */
#define UART_FCR_R_TRIG_00 0x00
#define UART_FCR_R_TRIG_01 0x40
#define UART_FCR_R_TRIG_10 0x80
#define UART_FCR_R_TRIG_11 0xc0
#define UART_FCR_T_TRIG_00 0x00
#define UART_FCR_T_TRIG_01 0x10
#define UART_FCR_T_TRIG_10 0x20
#define UART_FCR_T_TRIG_11 0x30

/* Line Control Register */
#define UART_LCR_DLAB     0x80    /* Divisor Latch Access */

/*
 * Access to some registers depends on register access / configuration
 * mode.
 */
#define UART_LCR_CONF_MODE_A	UART_LCR_DLAB	/* Configuration mode A */
#define UART_LCR_CONF_MODE_B	0xBF		/* Configuration mode B */

/* Modem Control Register */
#define UART_MCR_DTR      0x01    /* Data Terminal Ready  */
#define UART_MCR_RTS      0x02    /* Request to Send      */
#define UART_MCR_OUT2     0x08    /* OUT2: interrupt mask */
#define UART_MCR_LOOP     0x10    /* Enable loopback test mode */
#define UART_MCR_TCRTLR   0x40    /* Access TCR/TLR (TI16C752, EFR[4]=1) */

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

/* Bits in Exar specific UART_XR_EFR register */
#define UART_EFR_ECB      0x10

/* Resume retry settings */
#define RESUME_DELAY      MILLISECS(10)
#define RESUME_RETRIES    100

#endif /* __XEN_8250_UART_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
