/*
 * xen/drivers/char/scif-uart.c
 *
 * Driver for SCIF(A) (Serial communication interface with FIFO (A))
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

#define scif_readb(uart, off)          readb((uart)->regs + (off))
#define scif_writeb(uart, off, val)    writeb((val), (uart)->regs + (off))

#define scif_readw(uart, off)          readw((uart)->regs + (off))
#define scif_writew(uart, off, val)    writew((val), (uart)->regs + (off))

static struct scif_uart {
    unsigned int irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
    const struct port_params *params;
} scif_com = {0};

enum port_types
{
    SCIF_PORT,
    SCIFA_PORT,
    NR_PORTS,
};

struct port_params
{
    unsigned int status_reg;
    unsigned int tx_fifo_reg;
    unsigned int rx_fifo_reg;
    unsigned int overrun_reg;
    unsigned int overrun_mask;
    unsigned int error_mask;
    unsigned int irq_flags;
    unsigned int fifo_size;
};

static const struct port_params port_params[NR_PORTS] =
{
    [SCIF_PORT] =
    {
        .status_reg   = SCIF_SCFSR,
        .tx_fifo_reg  = SCIF_SCFTDR,
        .rx_fifo_reg  = SCIF_SCFRDR,
        .overrun_reg  = SCIF_SCLSR,
        .overrun_mask = SCLSR_ORER,
        .error_mask   = SCFSR_PER | SCFSR_FER | SCFSR_BRK | SCFSR_ER,
        .irq_flags    = SCSCR_RIE | SCSCR_TIE | SCSCR_REIE,
        .fifo_size    = 16,
    },

    [SCIFA_PORT] =
    {
        .status_reg   = SCIFA_SCASSR,
        .tx_fifo_reg  = SCIFA_SCAFTDR,
        .rx_fifo_reg  = SCIFA_SCAFRDR,
        .overrun_reg  = SCIFA_SCASSR,
        .overrun_mask = SCASSR_ORER,
        .error_mask   = SCASSR_PER | SCASSR_FER | SCASSR_BRK | SCASSR_ER,
        .irq_flags    = SCASCR_RIE | SCASCR_TIE | SCASCR_DRIE | SCASCR_ERIE |
                        SCASCR_BRIE,
        .fifo_size    = 64,
    },
};

static void scif_uart_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct scif_uart *uart = port->uart;
    const struct port_params *params = uart->params;
    uint16_t status, ctrl;

    ctrl = scif_readw(uart, SCIF_SCSCR);
    status = scif_readw(uart, params->status_reg) & ~SCFSR_TEND;
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
        if ( status & params->error_mask )
            scif_writew(uart, params->status_reg, ~params->error_mask);
        if ( scif_readw(uart, params->overrun_reg) & params->overrun_mask )
            scif_writew(uart, params->overrun_reg, ~params->overrun_mask);

        ctrl = scif_readw(uart, SCIF_SCSCR);
        status = scif_readw(uart, params->status_reg) & ~SCFSR_TEND;
        /* Ignore next flag if TX Interrupt is disabled */
        if ( !(ctrl & SCSCR_TIE) )
            status &= ~SCFSR_TDFE;
    }
}

static void __init scif_uart_init_preirq(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;
    const struct port_params *params = uart->params;

    /*
     * Wait until last bit has been transmitted. This is needed for a smooth
     * transition when we come from early printk
     */
    while ( !(scif_readw(uart, params->status_reg) & SCFSR_TEND) );

    /* Disable TX/RX parts and all interrupts */
    scif_writew(uart, SCIF_SCSCR, 0);

    /* Reset TX/RX FIFOs */
    scif_writew(uart, SCIF_SCFCR, SCFCR_RFRST | SCFCR_TFRST);

    /* Clear all errors and flags */
    scif_readw(uart, params->status_reg);
    scif_writew(uart, params->status_reg, 0);
    scif_readw(uart, params->overrun_reg);
    scif_writew(uart, params->overrun_reg, 0);

    /* Setup trigger level for TX/RX FIFOs */
    scif_writew(uart, SCIF_SCFCR, SCFCR_RTRG11 | SCFCR_TTRG11);

    /* Enable TX/RX parts */
    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) |
                 SCSCR_TE | SCSCR_RE);
}

static void __init scif_uart_init_postirq(struct serial_port *port)
{
    struct scif_uart *uart = port->uart;
    const struct port_params *params = uart->params;
    int rc;

    uart->irqaction.handler = scif_uart_interrupt;
    uart->irqaction.name    = "scif_uart";
    uart->irqaction.dev_id  = port;

    if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
        dprintk(XENLOG_ERR, "Failed to allocated scif_uart IRQ %d\n",
                uart->irq);

    /* Clear all errors */
    if ( scif_readw(uart, params->status_reg) & params->error_mask )
        scif_writew(uart, params->status_reg, ~params->error_mask);
    if ( scif_readw(uart, params->overrun_reg) & params->overrun_mask )
        scif_writew(uart, params->overrun_reg, ~params->overrun_mask);

    /* Enable TX/RX and Error Interrupts  */
    scif_writew(uart, SCIF_SCSCR, scif_readw(uart, SCIF_SCSCR) |
                params->irq_flags);
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
    const struct port_params *params = uart->params;
    uint16_t cnt;

    /* Check for empty space in TX FIFO */
    if ( !(scif_readw(uart, params->status_reg) & SCFSR_TDFE) )
        return 0;

     /* Check number of data bytes stored in TX FIFO */
    cnt = scif_readw(uart, SCIF_SCFDR) >> 8;
    ASSERT( cnt <= params->fifo_size );

    return (params->fifo_size - cnt);
}

static void scif_uart_putc(struct serial_port *port, char c)
{
    struct scif_uart *uart = port->uart;
    const struct port_params *params = uart->params;

    scif_writeb(uart, params->tx_fifo_reg, c);
    /* Clear required TX flags */
    scif_writew(uart, params->status_reg,
                scif_readw(uart, params->status_reg) &
                ~(SCFSR_TEND | SCFSR_TDFE));
}

static int scif_uart_getc(struct serial_port *port, char *pc)
{
    struct scif_uart *uart = port->uart;
    const struct port_params *params = uart->params;

    /* Check for available data bytes in RX FIFO */
    if ( !(scif_readw(uart, params->status_reg) & (SCFSR_RDF | SCFSR_DR)) )
        return 0;

    *pc = scif_readb(uart, params->rx_fifo_reg);

    /* dummy read */
    scif_readw(uart, params->status_reg);
    /* Clear required RX flags */
    scif_writew(uart, params->status_reg, ~(SCFSR_RDF | SCFSR_DR));

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

static const struct dt_device_match scif_uart_dt_match[] __initconst =
{
    { .compatible = "renesas,scif",  .data = (void *)SCIF_PORT },
    { .compatible = "renesas,scifa", .data = (void *)SCIFA_PORT },
    { /* sentinel */ },
};

static int __init scif_uart_init(struct dt_device_node *dev,
                                 const void *data)
{
    const struct dt_device_match *match;
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

    match = dt_match_node(scif_uart_dt_match, dev);
    ASSERT( match );
    uart->params = &port_params[(enum port_types)match->data];

    uart->vuart.base_addr  = addr;
    uart->vuart.size       = size;
    uart->vuart.data_off   = uart->params->tx_fifo_reg;
    uart->vuart.status_off = uart->params->status_reg;
    uart->vuart.status     = SCFSR_TDFE;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &scif_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

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
