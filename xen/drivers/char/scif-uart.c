/*
 * xen/drivers/char/scif-uart.c
 *
 * Driver for SCIF (Serial communication interface with FIFO)
 * compatible UART.
 *
 * Oleksandr Tyshchenko <oleksandr.tyshchenko@globallogic.com>
 * Copyright (C) 2014, Globallogic.
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
#include <xen/errno.h>
#include <xen/serial.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/delay.h>
#include <asm/device.h>
#include <asm/scif-uart.h>
#include <asm/io.h>

#define PARITY_NONE    0
#define PARITY_EVEN    1
#define PARITY_ODD     2

#define scif_readb(uart, off)          readb((uart)->regs + (off))
#define scif_writeb(uart, off, val)    writeb((val), (uart)->regs + (off))

#define scif_readw(uart, off)          readw((uart)->regs + (off))
#define scif_writew(uart, off, val)    writew((val), (uart)->regs + (off))

static struct scif_uart {
    unsigned int irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} scif_com = {0};

static void scif_uart_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct scif_uart *uart = port->uart;
    uint16_t status, ctrl;

    ctrl = scif_readw(uart, SCIF_SCSCR);
    status = scif_readw(uart, SCIF_SCFSR) & ~SCFSR_TEND;
    /* Ignore next flag if TX Interrupt is disabled */
    if ( !(ctrl & SCSCR_TIE) )
        status &= ~SCFSR_TDFE;

    while ( status != 0 )
    {
        /* TX Interrupt */
        if ( status & SCFSR_TDFE )
            serial_tx_interrupt(port, regs);

        /* RX Interrupt */
        if ( status & (SCFSR_RDF | SCFSR_DR) )
            serial_rx_interrupt(port, regs);

        /* Error Interrupt */
        if ( status & SCIF_ERRORS )
            scif_writew(uart, SCIF_SCFSR, ~SCIF_ERRORS);
        if ( scif_readw(uart, SCIF_SCLSR) & SCLSR_ORER )
            scif_writew(uart, SCIF_SCLSR, 0);

        ctrl = scif_readw(uart, SCIF_SCSCR);
        status = scif_readw(uart, SCIF_SCFSR) & ~SCFSR_TEND;
        /* Ignore next flag if TX Interrupt is disabled */
        if ( !(ctrl & SCSCR_TIE) )
            status &= ~SCFSR_TDFE;
    }
}

static void __init scif_uart_init_preirq(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;

    /*
     * Wait until last bit has been transmitted. This is needed for a smooth
     * transition when we come from early printk
     */
    while ( !(scif_readw(uart, SCIF_SCFSR) & SCFSR_TEND) );

    /* Disable TX/RX parts and all interrupts */
    scif_writew(uart, SCIF_SCSCR, 0);

    /* Reset TX/RX FIFOs */
    scif_writew(uart, SCIF_SCFCR, SCFCR_RFRST | SCFCR_TFRST);

    /* Clear all errors and flags */
    scif_readw(uart, SCIF_SCFSR);
    scif_writew(uart, SCIF_SCFSR, 0);
    scif_readw(uart, SCIF_SCLSR);
    scif_writew(uart, SCIF_SCLSR, 0);

    /* Setup trigger level for TX/RX FIFOs */
    scif_writew(uart, SCIF_SCFCR, SCFCR_RTRG11 | SCFCR_TTRG11);

    /* Enable TX/RX parts */
    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) |
                 SCSCR_TE | SCSCR_RE);
}

static void __init scif_uart_init_postirq(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;
    int rc;

    uart->irqaction.handler = scif_uart_interrupt;
    uart->irqaction.name    = "scif_uart";
    uart->irqaction.dev_id  = port;

    if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
        dprintk(XENLOG_ERR, "Failed to allocated scif_uart IRQ %d\n",
                uart->irq);

    /* Clear all errors */
    if ( scif_readw(uart, SCIF_SCFSR) & SCIF_ERRORS )
        scif_writew(uart, SCIF_SCFSR, ~SCIF_ERRORS);
    if ( scif_readw(uart, SCIF_SCLSR) & SCLSR_ORER )
        scif_writew(uart, SCIF_SCLSR, 0);

    /* Enable TX/RX and Error Interrupts  */
    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) |
                 SCSCR_TIE | SCSCR_RIE | SCSCR_REIE);
}

static void scif_uart_suspend(struct serial_port *port)
{
    BUG();
}

static void scif_uart_resume(struct serial_port *port)
{
    BUG();
}

static int scif_uart_tx_ready(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;
    uint16_t cnt;

    /* Check for empty space in TX FIFO */
    if ( !(scif_readw(uart, SCIF_SCFSR) & SCFSR_TDFE) )
        return 0;

     /* Check number of data bytes stored in TX FIFO */
    cnt = scif_readw(uart, SCIF_SCFDR) >> 8;
    ASSERT( cnt >= 0 && cnt <= SCIF_FIFO_MAX_SIZE );

    return (SCIF_FIFO_MAX_SIZE - cnt);
}

static void scif_uart_putc(struct serial_port *port, char c)
{
    struct scif_uart *uart = port->uart;

    scif_writeb(uart, SCIF_SCFTDR, c);
    /* Clear required TX flags */
    scif_writew(uart, SCIF_SCFSR, scif_readw(uart, SCIF_SCFSR) &
                 ~(SCFSR_TEND | SCFSR_TDFE));
}

static int scif_uart_getc(struct serial_port *port, char *pc)
{
    struct scif_uart *uart = port->uart;

    /* Check for available data bytes in RX FIFO */
    if ( !(scif_readw(uart, SCIF_SCFSR) & (SCFSR_RDF | SCFSR_DR)) )
        return 0;

    *pc = scif_readb(uart, SCIF_SCFRDR);

    /* dummy read */
    scif_readw(uart, SCIF_SCFSR);
    /* Clear required RX flags */
    scif_writew(uart, SCIF_SCFSR, ~(SCFSR_RDF | SCFSR_DR));

    return 1;
}

static int __init scif_uart_irq(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *scif_vuart_info(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;

    return &uart->vuart;
}

static void scif_uart_start_tx(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;

    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) | SCSCR_TIE);
}

static void scif_uart_stop_tx(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;

    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) & ~SCSCR_TIE);
}

static struct uart_driver __read_mostly scif_uart_driver = {
    .init_preirq  = scif_uart_init_preirq,
    .init_postirq = scif_uart_init_postirq,
    .endboot      = NULL,
    .suspend      = scif_uart_suspend,
    .resume       = scif_uart_resume,
    .tx_ready     = scif_uart_tx_ready,
    .putc         = scif_uart_putc,
    .getc         = scif_uart_getc,
    .irq          = scif_uart_irq,
    .start_tx     = scif_uart_start_tx,
    .stop_tx      = scif_uart_stop_tx,
    .vuart_info   = scif_vuart_info,
};

static int __init scif_uart_init(struct dt_device_node *dev,
                                 const void *data)
{
    const char *config = data;
    struct scif_uart *uart;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &scif_com;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("scif-uart: Unable to retrieve the base"
                     " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("scif-uart: Unable to retrieve the IRQ\n");
        return res;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("scif-uart: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr  = addr;
    uart->vuart.size       = size;
    uart->vuart.data_off   = SCIF_SCFTDR;
    uart->vuart.status_off = SCIF_SCFSR;
    uart->vuart.status     = SCFSR_TDFE;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &scif_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match scif_uart_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("renesas,scif"),
    { /* sentinel */ },
};

DT_DEVICE_START(scif_uart, "SCIF UART", DEVICE_SERIAL)
    .dt_match = scif_uart_dt_match,
    .init = scif_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
