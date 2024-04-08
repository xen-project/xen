/*
 * xen/drivers/char/imx-lpuart.c
 *
 * Driver for i.MX LPUART.
 *
 * Peng Fan <peng.fan@nxp.com>
 * Copyright 2022 NXP
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

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/serial.h>
#include <asm/device.h>
#include <asm/imx-lpuart.h>
#include <asm/io.h>

#define imx_lpuart_read(uart, off)       readl((uart)->regs + (off))
#define imx_lpuart_write(uart, off, val) writel((val), (uart)->regs + (off))

static struct imx_lpuart {
    uint32_t irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} imx8_com;

static void imx_lpuart_interrupt(int irq, void *data)
{
    struct serial_port *port = data;
    struct imx_lpuart *uart = port->uart;
    uint32_t sts, rxcnt;

    sts = imx_lpuart_read(uart, UARTSTAT);
    rxcnt = imx_lpuart_read(uart, UARTWATER) >> UARTWATER_RXCNT_OFF;

    if ( (sts & UARTSTAT_RDRF) || (rxcnt > 0) )
	    serial_rx_interrupt(port);

    if ( sts & UARTSTAT_TDRE )
	    serial_tx_interrupt(port);

    imx_lpuart_write(uart, UARTSTAT, sts);
}

static void __init imx_lpuart_init_preirq(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;
    uint32_t ctrl, old_ctrl, bd;

    old_ctrl = imx_lpuart_read(uart, UARTCTRL);
    ctrl = (old_ctrl & ~UARTCTRL_M) | UARTCTRL_TE | UARTCTRL_RE;
    bd = imx_lpuart_read(uart, UARTBAUD);

    while ( !(imx_lpuart_read(uart, UARTSTAT) & UARTSTAT_TC) )
	    cpu_relax();

    /* Disable transmit and receive */
    imx_lpuart_write(uart, UARTCTRL, old_ctrl & ~(UARTCTRL_TE | UARTCTRL_RE));

    /* Reuse firmware baudrate settings, only disable DMA here */
    bd &= ~(UARTBAUD_TDMAE | UARTBAUD_RDMAE);

    imx_lpuart_write(uart, UARTMODIR, 0);
    imx_lpuart_write(uart, UARTBAUD, bd);
    imx_lpuart_write(uart, UARTCTRL, ctrl);
}

static void __init imx_lpuart_init_postirq(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;
    uint32_t temp;

    uart->irqaction.handler = imx_lpuart_interrupt;
    uart->irqaction.name = "imx_lpuart";
    uart->irqaction.dev_id = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        dprintk(XENLOG_ERR, "Failed to allocate imx_lpuart IRQ %d\n",
                uart->irq);
        return;
    }

    /* Enable interrupts */
    temp = imx_lpuart_read(uart, UARTCTRL);
    temp |= (UARTCTRL_RIE | UARTCTRL_TIE);
    temp |= UARTCTRL_ILIE;
    imx_lpuart_write(uart, UARTCTRL, temp);
}

static int imx_lpuart_tx_ready(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;

    return imx_lpuart_read(uart, UARTSTAT) & UARTSTAT_TC;
}

static void imx_lpuart_putc(struct serial_port *port, char c)
{
    struct imx_lpuart *uart = port->uart;

    while ( !(imx_lpuart_read(uart, UARTSTAT) & UARTSTAT_TDRE) )
        cpu_relax();

    imx_lpuart_write(uart, UARTDATA, c);
}

static int imx_lpuart_getc(struct serial_port *port, char *pc)
{
    struct imx_lpuart *uart = port->uart;
    int ch;

    while ( !(imx_lpuart_read(uart, UARTSTAT) & UARTSTAT_RDRF) )
	    return 0;

    ch = imx_lpuart_read(uart, UARTDATA);
    *pc = ch & 0xff;

    if ( imx_lpuart_read(uart, UARTSTAT) &  UARTSTAT_OR )
        imx_lpuart_write(uart, UARTSTAT, UARTSTAT_OR);

    return 1;
}

static int __init imx_lpuart_irq(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *imx_lpuart_vuart_info(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;

    return &uart->vuart;
}

static void imx_lpuart_start_tx(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;
    uint32_t temp;

    /* Wait until empty */
    while ( !(imx_lpuart_read(uart, UARTSTAT) & UARTSTAT_TDRE) )
	    cpu_relax();

    temp = imx_lpuart_read(uart, UARTCTRL);
    imx_lpuart_write(uart, UARTCTRL, (temp | UARTCTRL_TIE));
}

static void imx_lpuart_stop_tx(struct serial_port *port)
{
    struct imx_lpuart *uart = port->uart;
    uint32_t temp;

    temp = imx_lpuart_read(uart, UARTCTRL);
    temp &= ~(UARTCTRL_TIE | UARTCTRL_TCIE);
    imx_lpuart_write(uart, UARTCTRL, temp);
}

static struct uart_driver __read_mostly imx_lpuart_driver = {
    .init_preirq = imx_lpuart_init_preirq,
    .init_postirq = imx_lpuart_init_postirq,
    .tx_ready = imx_lpuart_tx_ready,
    .putc = imx_lpuart_putc,
    .getc = imx_lpuart_getc,
    .irq = imx_lpuart_irq,
    .start_tx = imx_lpuart_start_tx,
    .stop_tx = imx_lpuart_stop_tx,
    .vuart_info = imx_lpuart_vuart_info,
};

static int __init imx_lpuart_init(struct dt_device_node *dev,
                                  const void *data)
{
    const char *config = data;
    struct imx_lpuart *uart;
    int res;
    paddr_t addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &imx8_com;

    res = dt_device_get_paddr(dev, 0, &addr, &size);
    if ( res )
    {
        printk("imx8-lpuart: Unable to retrieve the base"
               " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("imx8-lpuart: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("imx8-lpuart: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = UARTDATA;
    /* tmp from uboot */
    uart->vuart.status_off = UARTSTAT;
    uart->vuart.status = UARTSTAT_TDRE;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &imx_lpuart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match imx_lpuart_dt_compat[] __initconst =
{
    DT_MATCH_COMPATIBLE("fsl,imx8qxp-lpuart"),
    { /* sentinel */ },
};

DT_DEVICE_START(imx_lpuart, "i.MX LPUART", DEVICE_SERIAL)
    .dt_match = imx_lpuart_dt_compat,
    .init = imx_lpuart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
