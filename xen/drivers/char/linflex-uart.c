/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/drivers/char/linflex-uart.c
 *
 * Driver for NXP LINFlexD UART.
 *
 * Andrei Cherechesu <andrei.cherechesu@nxp.com>
 * Copyright 2018, 2021-2022, 2024 NXP
 */

#include <xen/config.h>
#include <xen/console.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/serial.h>
#include <asm/device.h>
#include <asm/io.h>
#include <asm/linflex-uart.h>

#define LINFLEX_CLK_FREQ        (125000000)
#define LINFLEX_MAX_BAUDRATE    (2000000)
#define LINFLEX_BAUDRATE        (115200)
#define LINFLEX_LDIV_MULTIPLIER (16)

static struct linflex_uart {
    uint32_t baud, clock_hz;
    uint32_t irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} linflex_com;

static uint32_t linflex_uart_readl(const struct linflex_uart *uart,
                                   uint32_t off)
{
    return readl(uart->regs + off);
}

static void linflex_uart_writel(const struct linflex_uart *uart, uint32_t off,
                                uint32_t val)
{
    writel(val, uart->regs + off);
}

static void linflex_uart_writeb(const struct linflex_uart *uart, uint32_t off,
                                uint8_t val)
{
    writeb(val, uart->regs + off);
}

static uint32_t linflex_uart_get_osr(uint32_t uartcr)
{
    return (uartcr & UARTCR_OSR) >> UARTCR_OSR_SHIFT;
}

static bool linflex_uart_tx_fifo_mode(const struct linflex_uart *uart)
{
    return !!(linflex_uart_readl(uart, UARTCR) & UARTCR_TFBM);
}

static bool linflex_uart_rx_fifo_mode(const struct linflex_uart *uart)
{
    return !!(linflex_uart_readl(uart, UARTCR) & UARTCR_RFBM);
}

static uint32_t linflex_uart_ldiv_multiplier(const struct linflex_uart *uart)
{
    uint32_t uartcr, mul = LINFLEX_LDIV_MULTIPLIER;

    uartcr = linflex_uart_readl(uart, UARTCR);
    if ( uartcr & UARTCR_ROSE )
        mul = linflex_uart_get_osr(uartcr);

    return mul;
}

static void linflex_uart_flush(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;

    if ( linflex_uart_tx_fifo_mode(uart) )
        while ( linflex_uart_readl(uart, UARTCR) & UARTCR_TDFLTFC )
            cpu_relax();

    if ( linflex_uart_rx_fifo_mode(uart) )
        while ( linflex_uart_readl(uart, UARTCR) & UARTCR_RDFLRFC )
            cpu_relax();
}

static void __init linflex_uart_init_preirq(struct serial_port *port)
{
    struct linflex_uart *uart = port->uart;
    uint32_t ibr, fbr, divisr, dividr, ctrl;

    /* Disable RX/TX before init mode */
    ctrl = linflex_uart_readl(uart, UARTCR);
    ctrl &= ~(UARTCR_RXEN | UARTCR_TXEN);
    linflex_uart_writel(uart, UARTCR, ctrl);

    /*
     * Smoothen the transition from early_printk by waiting
     * for all pending characters to transmit
     */
    linflex_uart_flush(port);

    /* Init mode */
    ctrl = LINCR1_INIT;
    linflex_uart_writel(uart, LINCR1, ctrl);

    /* Waiting for init mode entry */
    while ( (linflex_uart_readl(uart, LINSR) & LINSR_LINS) != LINSR_LINS_INIT )
        cpu_relax();

    /* Set Master Mode */
    ctrl |= LINCR1_MME;
    linflex_uart_writel(uart, LINCR1, ctrl);

    if ( uart->baud > LINFLEX_MAX_BAUDRATE )
        uart->baud = LINFLEX_MAX_BAUDRATE;

    /* Provide data bits, parity, stop bit, etc */
    divisr = uart->clock_hz;
    dividr = uart->baud * linflex_uart_ldiv_multiplier(uart);

    ibr = divisr / dividr;
    fbr = ((divisr % dividr) * 16 / dividr) & 0xF;

    linflex_uart_writel(uart, LINIBRR, ibr);
    linflex_uart_writel(uart, LINFBRR, fbr);

    /* Set preset timeout register value */
    linflex_uart_writel(uart, UARTPTO, 0xF);

    /* Setting UARTCR[UART] bit is required for writing other bits in UARTCR */
    linflex_uart_writel(uart, UARTCR, UARTCR_UART);

    /* 8 bit data, no parity, UART mode, Buffer mode */
    linflex_uart_writel(uart, UARTCR, UARTCR_PC1 | UARTCR_PC0 | UARTCR_WL0 |
                        UARTCR_UART);

    /* end init mode */
    ctrl = linflex_uart_readl(uart, LINCR1);
    ctrl &= ~LINCR1_INIT;
    linflex_uart_writel(uart, LINCR1, ctrl);

    /* Enable RX/TX after exiting init mode */
    ctrl = linflex_uart_readl(uart, UARTCR);
    ctrl |= UARTCR_RXEN | UARTCR_TXEN;
    linflex_uart_writel(uart, UARTCR, ctrl);
}

static void linflex_uart_interrupt(int irq, void *data)
{
    struct serial_port *port = data;
    const struct linflex_uart *uart = port->uart;
    uint32_t sts;

    sts = linflex_uart_readl(uart, UARTSR);

    if ( sts & UARTSR_DRFRFE )
        serial_rx_interrupt(port);

    if ( sts & UARTSR_DTFTFF )
        serial_tx_interrupt(port);
}

static void __init linflex_uart_init_postirq(struct serial_port *port)
{
    struct linflex_uart *uart = port->uart;
    uint32_t temp;

    uart->irqaction.handler = linflex_uart_interrupt;
    uart->irqaction.name = "linflex_uart";
    uart->irqaction.dev_id = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        printk("linflex-uart: Failed to allocate IRQ %d\n", uart->irq);
        return;
    }

    /* Enable interrupts */
    temp = linflex_uart_readl(uart, LINIER);
    temp |= (LINIER_DRIE | LINIER_DTIE);
    linflex_uart_writel(uart, LINIER, temp);
    printk("linflex-uart: IRQ %d enabled\n", uart->irq);
}

static int linflex_uart_tx_ready(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;

    if ( linflex_uart_tx_fifo_mode(uart) )
        return (linflex_uart_readl(uart, UARTSR) & UARTSR_DTFTFF) == 0 ? 1 : 0;

    /*
     * Buffer Mode => TX is waited to be ready after sending a char,
     * so we can assume it is always ready before.
     */
    return 1;
}

static void linflex_uart_putc(struct serial_port *port, char c)
{
    const struct linflex_uart *uart = port->uart;
    uint32_t uartsr;

    if ( c == '\n' )
        linflex_uart_putc(port, '\r');

    linflex_uart_writeb(uart, BDRL, c);

    /* Buffer Mode */
    if ( !linflex_uart_tx_fifo_mode(uart) )
    {
        while ( (linflex_uart_readl(uart, UARTSR) & UARTSR_DTFTFF) == 0 )
                cpu_relax();

        uartsr = linflex_uart_readl(uart, UARTSR) | (UARTSR_DTFTFF);
        linflex_uart_writel(uart, UARTSR, uartsr);
    }
}

static int linflex_uart_getc(struct serial_port *port, char *pc)
{
    const struct linflex_uart *uart = port->uart;
    uint32_t ch, uartsr, rx_fifo_mode;

    rx_fifo_mode = linflex_uart_rx_fifo_mode(uart);

    if ( rx_fifo_mode )
        while ( linflex_uart_readl(uart, UARTSR) & UARTSR_DRFRFE )
            cpu_relax();
    else
        while ( !(linflex_uart_readl(uart, UARTSR) & UARTSR_DRFRFE) )
            cpu_relax();

    ch = linflex_uart_readl(uart, BDRM);
    *pc = ch & 0xff;

    if ( !rx_fifo_mode ) {
        uartsr = linflex_uart_readl(uart, UARTSR) | UARTSR_DRFRFE;
        linflex_uart_writel(uart, UARTSR, uartsr);
    }

    return 1;
}

static int __init linflex_uart_irq(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *linflex_vuart_info(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;

    return &uart->vuart;
}

static void linflex_uart_start_tx(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;
    uint32_t temp;

    temp = linflex_uart_readl(uart, LINIER);
    linflex_uart_writel(uart, LINIER, temp | LINIER_DTIE);
}

static void linflex_uart_stop_tx(struct serial_port *port)
{
    const struct linflex_uart *uart = port->uart;
    uint32_t temp;

    temp = linflex_uart_readl(uart, LINIER);
    temp &= ~(LINIER_DTIE);
    linflex_uart_writel(uart, LINIER, temp);
}

static struct uart_driver __read_mostly linflex_uart_driver = {
    .init_preirq = linflex_uart_init_preirq,
    .init_postirq = linflex_uart_init_postirq,
    .tx_ready = linflex_uart_tx_ready,
    .putc = linflex_uart_putc,
    .flush = linflex_uart_flush,
    .getc = linflex_uart_getc,
    .irq = linflex_uart_irq,
    .start_tx = linflex_uart_start_tx,
    .stop_tx = linflex_uart_stop_tx,
    .vuart_info = linflex_vuart_info,
};

static int __init linflex_uart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct linflex_uart *uart;
    paddr_t addr, size;
    uint32_t baud = 0;
    int res;

    if ( strcmp(config, "") )
    {
        baud = simple_strtoul(config, &config, 10);
        if ( strcmp(config, "") )
            printk("linflex-uart: Only baud rate is configurable, discarding other options: %s\n",
                   config);
    }
    else
    {
        /* Configuration not provided, use a default one */
        baud = LINFLEX_BAUDRATE;
        printk("linflex-uart: Baud rate not provided, using %d as default\n",
               baud);
    }

    uart = &linflex_com;

    res = dt_device_get_paddr(dev, 0, &addr, &size);
    if ( res )
    {
        printk("linflex-uart: Unable to retrieve the base address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("linflex-uart: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("linflex-uart: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->baud = baud;
    uart->clock_hz = LINFLEX_CLK_FREQ;

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = BDRL;
    uart->vuart.status_off = UARTSR;
    uart->vuart.status = UARTSR_DTFTFF;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &linflex_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match linflex_uart_dt_compat[] __initconst =
{
    DT_MATCH_COMPATIBLE("nxp,s32g2-linflexuart"),
    DT_MATCH_COMPATIBLE("nxp,s32g3-linflexuart"),
    DT_MATCH_COMPATIBLE("fsl,s32v234-linflexuart"),
    { /* sentinel */ },
};

DT_DEVICE_START(linflex_uart, "NXP LINFlexD UART", DEVICE_SERIAL)
    .dt_match = linflex_uart_dt_compat,
    .init = linflex_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
