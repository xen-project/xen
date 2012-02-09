/*
 * xen/drivers/char/pl011.c
 *
 * Driver for ARM PrimeCell PL011 UART.
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

#include <xen/config.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/init.h>
#include <xen/irq.h>

static struct pl011 {
    unsigned int baud, clock_hz, data_bits, parity, stop_bits, irq;
    volatile uint32_t *regs;
    /* UART with IRQ line: interrupt-driven I/O. */
    struct irqaction irqaction;
    /* /\* UART with no IRQ line: periodically-polled I/O. *\/ */
    /* struct timer timer; */
    /* unsigned int timeout_ms; */
    /* bool_t probing, intr_works; */
} pl011_com[2] = {{0}};

/* PL011 register addresses */
#define DR     (0x00/4)
#define RSR    (0x04/4)
#define FR     (0x18/4)
#define ILPR   (0x20/4)
#define IBRD   (0x24/4)
#define FBRD   (0x28/4)
#define LCR_H  (0x2c/4)
#define CR     (0x30/4)
#define IFLS   (0x34/4)
#define IMSC   (0x38/4)
#define RIS    (0x3c/4)
#define MIS    (0x40/4)
#define ICR    (0x44/4)
#define DMACR  (0x48/4)

/* CR bits */
#define RXE    (1<<9) /* Receive enable */
#define TXE    (1<<8) /* Transmit enable */
#define UARTEN (1<<0) /* UART enable */

/* FR bits */
#define TXFE   (1<<7) /* TX FIFO empty */
#define RXFE   (1<<4) /* RX FIFO empty */

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

/* These parity settings can be ORed directly into the LCR. */
#define PARITY_NONE  (0)
#define PARITY_ODD   (PEN)
#define PARITY_EVEN  (PEN|EPS)
#define PARITY_MARK  (PEN|SPS)
#define PARITY_SPACE (PEN|EPS|SPS)

static void pl011_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct pl011 *uart = port->uart;
    unsigned int status = uart->regs[MIS];

    if ( status )
    {
        do
        {
            uart->regs[ICR] = status & ~(TXI|RTI|RXI);

            if ( status & (RTI|RXI) )
                serial_rx_interrupt(port, regs);

            /* TODO
                if ( status & (DSRMI|DCDMI|CTSMI|RIMI) )
                ...
            */

            if ( status & (TXI) )
                serial_tx_interrupt(port, regs);

            status = uart->regs[MIS];
        } while (status != 0);
    }
}

static void __init pl011_init_preirq(struct serial_port *port)
{
    struct pl011 *uart = port->uart;
    unsigned int divisor;

    /* No interrupts, please. */
    uart->regs[IMSC] = ALLI;

    /* Definitely no DMA */
    uart->regs[DMACR] = 0x0;

    /* Line control and baud-rate generator. */
    if ( uart->baud != BAUD_AUTO )
    {
        /* Baud rate specified: program it into the divisor latch. */
        divisor = (uart->clock_hz << 2) / uart->baud; /* clk << 6 / bd << 4 */
        uart->regs[FBRD] = divisor & 0x3f;
        uart->regs[IBRD] = divisor >> 6;
    }
    else
    {
        /* Baud rate already set: read it out from the divisor latch. */
        divisor = (uart->regs[IBRD] << 6) | uart->regs[FBRD];
        uart->baud = (uart->clock_hz << 2) / divisor;
    }
    /* This write must follow FBRD and IBRD writes. */
    uart->regs[LCR_H] = ( (uart->data_bits - 5) << 5
                          | FEN
                          | ((uart->stop_bits - 1) << 3)
                          | uart->parity );

    /* Clear errors */
    uart->regs[RSR] = 0;

    /* Mask and clear the interrupts */
    uart->regs[IMSC] = ALLI;
    uart->regs[ICR] = ALLI;

    /* Enable the UART for RX and TX; no flow ctrl */
    uart->regs[CR] = RXE | TXE | UARTEN;

    /* Tell the serial framework about our fine 156-character FIFO */
    port->tx_fifo_size = 16;
}

static void __init pl011_init_postirq(struct serial_port *port)
{
    struct pl011 *uart = port->uart;
    int rc;

    if ( uart->irq > 0 )
    {
        uart->irqaction.handler = pl011_interrupt;
        uart->irqaction.name    = "pl011";
        uart->irqaction.dev_id  = port;
        if ( (rc = setup_irq(uart->irq, &uart->irqaction)) != 0 )
            printk("ERROR: Failed to allocate pl011 IRQ %d\n", uart->irq);
    }

    /* Clear pending error interrupts */
    uart->regs[ICR] = OEI|BEI|PEI|FEI;

    /* Unmask interrupts */
    uart->regs[IMSC] = RTI|DSRMI|DCDMI|CTSMI|RIMI;
}

static void pl011_suspend(struct serial_port *port)
{
    BUG(); // XXX
}

static void pl011_resume(struct serial_port *port)
{
    BUG(); // XXX
}

static int pl011_tx_empty(struct serial_port *port)
{
    struct pl011 *uart = port->uart;
    return !!(uart->regs[FR] & TXFE);
}

static void pl011_putc(struct serial_port *port, char c)
{
    struct pl011 *uart = port->uart;
    uart->regs[DR] = (uint32_t) (unsigned char) c;
}

static int pl011_getc(struct serial_port *port, char *pc)
{
    struct pl011 *uart = port->uart;

    if ( uart->regs[FR] & RXFE )
        return 0;

    *pc = uart->regs[DR] & 0xff;
    return 1;
}

static int pl011_irq(struct serial_port *port)
{
    struct pl011 *uart = port->uart;
    return ((uart->irq > 0) ? uart->irq : -1);
}

static struct uart_driver __read_mostly pl011_driver = {
    .init_preirq  = pl011_init_preirq,
    .init_postirq = pl011_init_postirq,
    .endboot      = NULL,
    .suspend      = pl011_suspend,
    .resume       = pl011_resume,
    .tx_empty     = pl011_tx_empty,
    .putc         = pl011_putc,
    .getc         = pl011_getc,
    .irq          = pl011_irq
};

/* TODO: Parse UART config from device-tree or command-line */

void __init pl011_init(int index, unsigned long register_base_address)
{
    struct pl011 *uart;

    if ( (index < 0) || (index > 1) )
        return;

    uart = &pl011_com[index];

    uart->clock_hz  = 7372800;
    uart->baud      = 115200;
    uart->data_bits = 8;
    uart->parity    = PARITY_NONE;
    uart->stop_bits = 1;
    uart->irq       = 37; /* TODO Need to find this from devicetree */
    uart->regs      = (uint32_t *) register_base_address;

    /* Register with generic serial driver. */
    serial_register_uart(uart - pl011_com, &pl011_driver, uart);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
