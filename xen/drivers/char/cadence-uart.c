/*
 * xen/drivers/char/cadence-uart.c
 *
 * Driver for Cadence UART in Xilinx ZynqMP.
 *
 * Written by Edgar E. Iglesias <edgar.iglesias@gmail.com>
 * Copyright (c) 2015 Xilinx Inc.
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
#include <xen/serial.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <asm/device.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/cadence-uart.h>
#include <asm/io.h>

static struct cuart {
    unsigned int irq;
    void __iomem *regs;
    /* UART with IRQ line: interrupt-driven I/O. */
    struct irqaction irqaction;
    struct vuart_info vuart;
} cuart_com = {0};

#define cuart_read(uart, off)           readl((uart)->regs + (off))
#define cuart_write(uart, off,val)      writel((val), (uart)->regs + (off))

static void cuart_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct cuart *uart = port->uart;
    unsigned int status;

    do {
        status = cuart_read(uart, R_UART_SR);
        /* ACK.  */
        if ( status & UART_SR_INTR_RTRIG )
        {
            serial_rx_interrupt(port, regs);
            cuart_write(uart, R_UART_CISR, UART_SR_INTR_RTRIG);
        }
    } while ( status & UART_SR_INTR_RTRIG );
}

static void __init cuart_init_preirq(struct serial_port *port)
{
    struct cuart *uart = port->uart;

    cuart_write(uart, R_UART_MR, UART_MR_NO_PARITY);
    /* Enable and Reset both the RX and TX paths.  */
    cuart_write(uart, R_UART_CR, UART_CR_RX_RST | UART_CR_TX_RST |
                      UART_CR_RX_ENABLE | UART_CR_TX_ENABLE);
}

static void __init cuart_init_postirq(struct serial_port *port)
{
    struct cuart *uart = port->uart;
    int rc;

    if ( uart->irq > 0 )
    {
        uart->irqaction.handler = cuart_interrupt;
        uart->irqaction.name    = "cadence-uart";
        uart->irqaction.dev_id  = port;
        if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
            printk("ERROR: Failed to allocate cadence-uart IRQ %d\n", uart->irq);
    }

    /* Clear pending error interrupts */
    cuart_write(uart, R_UART_RTRIG, 1);
    cuart_write(uart, R_UART_CISR, ~0);

    /* Unmask interrupts */
    cuart_write(uart, R_UART_IDR, ~0);
    cuart_write(uart, R_UART_IER, UART_SR_INTR_RTRIG);
}

static void cuart_suspend(struct serial_port *port)
{
    BUG();
}

static void cuart_resume(struct serial_port *port)
{
    BUG();
}

static int cuart_tx_ready(struct serial_port *port)
{
    struct cuart *uart = port->uart;
    unsigned int status = cuart_read(uart, R_UART_SR);

    return !( status & UART_SR_INTR_TFUL );
}

static void cuart_putc(struct serial_port *port, char c)
{
    struct cuart *uart = port->uart;

    cuart_write(uart, R_UART_TX, (uint32_t)(unsigned char)c);
}

static int cuart_getc(struct serial_port *port, char *pc)
{
    struct cuart *uart = port->uart;

    if ( cuart_read(uart, R_UART_SR) & UART_SR_INTR_REMPTY )
        return 0;

    *pc = cuart_read(uart, R_UART_RX) & 0xff;
    return 1;
}

static int __init cuart_irq(struct serial_port *port)
{
    struct cuart *uart = port->uart;

    return ( (uart->irq > 0) ? uart->irq : -1 );
}

static const struct vuart_info *cuart_vuart(struct serial_port *port)
{
    struct cuart *uart = port->uart;

    return &uart->vuart;
}

static struct uart_driver __read_mostly cuart_driver = {
    .init_preirq  = cuart_init_preirq,
    .init_postirq = cuart_init_postirq,
    .endboot      = NULL,
    .suspend      = cuart_suspend,
    .resume       = cuart_resume,
    .tx_ready     = cuart_tx_ready,
    .putc         = cuart_putc,
    .getc         = cuart_getc,
    .irq          = cuart_irq,
    .vuart_info   = cuart_vuart,
};

static int __init cuart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct cuart *uart;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &cuart_com;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("cadence: Unable to retrieve the base"
               " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("cadence: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("cadence: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = R_UART_RX;
    uart->vuart.status_off = R_UART_SR;
    uart->vuart.status = UART_SR_INTR_TEMPTY;

    /* Register with generic serial driver. */
    serial_register_uart(SERHND_DTUART, &cuart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match cuart_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("cdns,uart-r1p8"),
    DT_MATCH_COMPATIBLE("cdns,uart-r1p12"),
    { /* sentinel */ },
};

DT_DEVICE_START(cuart, "Cadence UART", DEVICE_SERIAL)
    .dt_match = cuart_dt_match,
    .init = cuart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
