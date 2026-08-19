/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Driver for the classic i.MX UART IP ("fsl,imx6q-uart"), used as the
 * console UART on the i.MX8M family (e.g. i.MX8MP).
 *
 * Baudrate and pin configuration are inherited from the bootloader.
 *
 * Copyright 2026 Open-EP (E-Paper) Community
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/serial.h>
#include <asm/device.h>
#include <asm/imx-uart.h>
#include <asm/io.h>

#define imx_uart_read(uart, off)       readl((uart)->regs + (off))
#define imx_uart_write(uart, off, val) writel((val), (uart)->regs + (off))

static struct imx_uart {
    uint32_t irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} imx8m_com;

static void imx_uart_interrupt(int irq, void *data)
{
    struct serial_port *port = data;
    struct imx_uart *uart = port->uart;

    if ( imx_uart_read(uart, USR2) & USR2_RDR )
        serial_rx_interrupt(port);

    /*
     * USR1_TRDY is a raw status bit, set whenever the transmitter has
     * room regardless of whether the TX interrupt is enabled.  Only treat
     * it as a TX interrupt when TRDYEN is set, otherwise an RX-only
     * interrupt would spuriously enter serial_tx_interrupt().
     */
    if ( (imx_uart_read(uart, USR1) & USR1_TRDY) &&
         (imx_uart_read(uart, UCR1) & UCR1_TRDYEN) )
        serial_tx_interrupt(port);
}

static void __init imx_uart_init_preirq(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;
    uint32_t ucr1, ucr2;

    /*
     * Reuse the bootloader settings; only enable the UART and both
     * directions.  The console uses UCR1 interrupts (RRDYEN/TRDYEN)
     * exclusively, so just clear UCR1's interrupt and DMA enables.
     */
    ucr1 = imx_uart_read(uart, UCR1);
    ucr1 &= ~(UCR1_RRDYEN | UCR1_TRDYEN | UCR1_TXMPTYEN | UCR1_RXDMAEN |
              UCR1_TXDMAEN | UCR1_ATDMAEN);
    ucr1 |= UCR1_UARTEN;
    imx_uart_write(uart, UCR1, ucr1);

    ucr2 = imx_uart_read(uart, UCR2);
    ucr2 |= UCR2_SRST | UCR2_RXEN | UCR2_TXEN;
    imx_uart_write(uart, UCR2, ucr2);
}

static void __init imx_uart_init_postirq(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;
    uint32_t ucr1;

    uart->irqaction.handler = imx_uart_interrupt;
    uart->irqaction.name = "imx_uart";
    uart->irqaction.dev_id = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        dprintk(XENLOG_ERR, "Failed to allocate imx_uart IRQ %u\n", uart->irq);
        return;
    }

    /* Enable the receiver ready interrupt */
    ucr1 = imx_uart_read(uart, UCR1);
    ucr1 |= UCR1_RRDYEN;
    imx_uart_write(uart, UCR1, ucr1);
}

static int imx_uart_tx_ready(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;

    return !(imx_uart_read(uart, UTS) & UTS_TXFULL);
}

static void imx_uart_putc(struct serial_port *port, char c)
{
    struct imx_uart *uart = port->uart;

    while ( imx_uart_read(uart, UTS) & UTS_TXFULL )
        cpu_relax();

    imx_uart_write(uart, URTX0, c);
}

static int imx_uart_getc(struct serial_port *port, char *pc)
{
    struct imx_uart *uart = port->uart;

    if ( !(imx_uart_read(uart, USR2) & USR2_RDR) )
        return 0;

    *pc = imx_uart_read(uart, URXD0) & URXD_RX_DATA;

    if ( imx_uart_read(uart, USR2) & USR2_ORE )
        imx_uart_write(uart, USR2, USR2_ORE);

    return 1;
}

static int __init imx_uart_irq(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *imx_uart_vuart_info(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;

    return &uart->vuart;
}

static void imx_uart_start_tx(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;
    uint32_t ucr1;

    ucr1 = imx_uart_read(uart, UCR1);
    imx_uart_write(uart, UCR1, ucr1 | UCR1_TRDYEN);
}

static void imx_uart_stop_tx(struct serial_port *port)
{
    struct imx_uart *uart = port->uart;
    uint32_t ucr1;

    ucr1 = imx_uart_read(uart, UCR1);
    imx_uart_write(uart, UCR1, ucr1 & ~UCR1_TRDYEN);
}

static struct uart_driver __read_mostly imx_uart_driver = {
    .init_preirq = imx_uart_init_preirq,
    .init_postirq = imx_uart_init_postirq,
    .tx_ready = imx_uart_tx_ready,
    .putc = imx_uart_putc,
    .getc = imx_uart_getc,
    .irq = imx_uart_irq,
    .start_tx = imx_uart_start_tx,
    .stop_tx = imx_uart_stop_tx,
    .vuart_info = imx_uart_vuart_info,
};

static int __init imx_uart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct imx_uart *uart;
    int res;
    paddr_t addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &imx8m_com;

    res = dt_device_get_paddr(dev, 0, &addr, &size);
    if ( res )
    {
        printk("imx-uart: Unable to retrieve the base address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("imx-uart: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("imx-uart: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = URTX0;
    uart->vuart.status_off = UTS;
    uart->vuart.status = UTS_TXEMPTY | UTS_RXEMPTY;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &imx_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match imx_uart_dt_compat[] __initconst =
{
    DT_MATCH_COMPATIBLE("fsl,imx6q-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(imx_uart, "i.MX UART", DEVICE_SERIAL)
    .dt_match = imx_uart_dt_compat,
    .init = imx_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
