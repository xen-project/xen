/*
 * xen/drivers/char/exynos4210-uart.c
 *
 * Driver for Exynos 4210 UART.
 *
 * Anthony PERARD <anthony.perard@citrix.com>
 * Copyright (c) 2012 Citrix Systems.
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
#include <asm/device.h>
#include <asm/exynos4210-uart.h>
#include <asm/io.h>

static struct exynos4210_uart {
    unsigned int baud, clock_hz, data_bits, parity, stop_bits;
    unsigned int irq;
    void *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} exynos4210_com = {0};

/* These parity settings can be ORed directly into the ULCON. */
#define PARITY_NONE  (0)
#define PARITY_ODD   (0x4)
#define PARITY_EVEN  (0x5)
#define FORCED_CHECKED_AS_ONE (0x6)
#define FORCED_CHECKED_AS_ZERO (0x7)

#define exynos4210_read(uart, off)          readl((uart)->regs + off)
#define exynos4210_write(uart, off, val)    writel(val, (uart->regs) + off)

static void exynos4210_uart_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct exynos4210_uart *uart = port->uart;
    unsigned int status;

    status = exynos4210_read(uart, UINTP);

    while ( status != 0 )
    {
        /* Clear all pending interrupts
         * but should take care of ERROR and MODEM
         */

        if ( status & UINTM_ERROR )
        {
            uint32_t error_bit;

            error_bit = exynos4210_read(uart, UERSTAT);

            if ( error_bit & UERSTAT_OVERRUN )
                dprintk(XENLOG_ERR, "uart: overrun error\n");
            if ( error_bit & UERSTAT_PARITY )
                dprintk(XENLOG_ERR, "uart: parity error\n");
            if ( error_bit & UERSTAT_FRAME )
                dprintk(XENLOG_ERR, "uart: frame error\n");
            if ( error_bit & UERSTAT_BREAK )
                dprintk(XENLOG_ERR, "uart: break detected\n");
            /* Clear error pending interrupt */
            exynos4210_write(uart, UINTP, UINTM_ERROR);
        }


        if ( status & (UINTM_RXD | UINTM_ERROR) )
        {
            /* uart->regs[UINTM] |= RXD|ERROR; */
            serial_rx_interrupt(port, regs);
            /* uart->regs[UINTM] &= ~(RXD|ERROR); */
            exynos4210_write(uart, UINTP, UINTM_RXD | UINTM_ERROR);
        }

        if ( status & (UINTM_TXD | UINTM_MODEM) )
        {
            /* uart->regs[UINTM] |= TXD|MODEM; */
            serial_tx_interrupt(port, regs);
            /* uart->regs[UINTM] &= ~(TXD|MODEM); */
            exynos4210_write(uart, UINTP, UINTM_TXD | UINTM_MODEM);
        }

        status = exynos4210_read(uart, UINTP);
    }
}

static void __init exynos4210_uart_init_preirq(struct serial_port *port)
{
    struct exynos4210_uart *uart = port->uart;
    unsigned int divisor;
    uint32_t ulcon;

    /* reset, TX/RX disables */
    exynos4210_write(uart, UCON, 0);

    /* No Interrupt, auto flow control */
    exynos4210_write(uart, UMCON, 0);

    /* Line control and baud-rate generator. */
    if ( uart->baud != BAUD_AUTO )
    {
        /* Baud rate specified: program it into the divisor latch. */
        divisor = ((uart->clock_hz) / (uart->baud)) - 1;
        /* FIXME: will use a hacked divisor, assuming the src clock and bauds */
        exynos4210_write(uart, UFRACVAL, 53);
        exynos4210_write(uart, UBRDIV, 4);
    }
    else
    {
        /*
         * TODO: should be updated
         * Baud rate already set: read it out from the divisor latch.
         * divisor = (uart->regs[IBRD] << 6) | uart->regs[FBRD];
         * uart->baud = (uart->clock_hz << 2) / divisor;
         */
    }

    /*
     * Number of bits per character
     * 0 => 5 bits
     * 1 => 6 bits
     * 2 => 7 bits
     * 3 => 8 bits
     */
    ASSERT(uart->data_bits >= 5 && uart->data_bits <= 8);
    ulcon = (uart->data_bits - 5);

    /*
     * Stop bits
     * 0 => 1 stop bit per frame
     * 1 => 2 stop bit per frame
     */
    ASSERT(uart->stop_bits >= 1 && uart->stop_bits <= 2);
    ulcon |= (uart->stop_bits - 1) << ULCON_STOPB_SHIFT;


    /* Parity */
    ulcon |= uart->parity << ULCON_PARITY_SHIFT;

    exynos4210_write(uart, ULCON, ulcon);

    /* Mask and clear the interrupts */
    exynos4210_write(uart, UINTM, UINTM_ALLI);
    exynos4210_write(uart, UINTP, UINTM_ALLI);

    /* reset FIFO */
    exynos4210_write(uart, UFCON, UFCON_FIFO_RESET);

    /* TODO: Add timeout to avoid infinite loop */
    while ( exynos4210_read(uart, UFCON) & UFCON_FIFO_RESET )
        ;

    /*
     * Enable FIFO and set the trigger level of Tx FIFO
     * The trigger level is always set to b101, an interrupt will be
     * generated when data count of Tx FIFO is less than or equal to the
     * following value:
     * UART0 => 160 bytes
     * UART1 => 40 bytes
     * UART2 => 10 bytes
     * UART3 => 10 bytes
     */
    exynos4210_write(uart, UFCON, UFCON_FIFO_TX_TRIGGER | UFCON_FIFO_EN);

    /*
     * Enable the UART for Rx and Tx
     *   - Use only interrupt request
     *   - Interrupts are level trigger
     *   - Enable Rx timeout
     */
    exynos4210_write(uart, UCON,
                     UCON_RX_IRQ_LEVEL | UCON_TX_IRQ_LEVEL | UCON_RX_IRQ |
                     UCON_TX_IRQ | UCON_RX_TIMEOUT);
}

static void __init exynos4210_uart_init_postirq(struct serial_port *port)
{
    struct exynos4210_uart *uart = port->uart;
    int rc;

    uart->irqaction.handler = exynos4210_uart_interrupt;
    uart->irqaction.name    = "exynos4210_uart";
    uart->irqaction.dev_id  = port;

    if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
        dprintk(XENLOG_ERR, "Failed to allocated exynos4210_uart IRQ %d\n",
                uart->irq);

    /* Unmask interrupts */
    exynos4210_write(uart, UINTM, ~UINTM_ALLI);

    /* Clear pending interrupts */
    exynos4210_write(uart, UINTP, UINTM_ALLI);

    /* Enable interrupts */
    exynos4210_write(uart, UMCON, exynos4210_read(uart, UMCON) | UMCON_INT_EN);
}

static void exynos4210_uart_suspend(struct serial_port *port)
{
    BUG(); // XXX
}

static void exynos4210_uart_resume(struct serial_port *port)
{
    BUG(); // XXX
}

static int exynos4210_uart_tx_ready(struct serial_port *port)
{
    struct exynos4210_uart *uart = port->uart;

    /* Tx fifo full ? */
    if ( exynos4210_read(uart, UFSTAT) & UFSTAT_TX_FULL )
        return 0;
    else
    {
        uint32_t val = exynos4210_read(uart, UFSTAT);

        val = (val & UFSTAT_TX_COUNT_MASK) >> UFSTAT_TX_COUNT_SHIFT;

        /* XXX: Here we assume that we use UART 2/3, on the others
         * UART the buffer is bigger
         */
        ASSERT(val >= 0 && val <= FIFO_MAX_SIZE);

        return (FIFO_MAX_SIZE - val);
    }
}

static void exynos4210_uart_putc(struct serial_port *port, char c)
{
    struct exynos4210_uart *uart = port->uart;

    exynos4210_write(uart, UTXH, (uint32_t)(unsigned char)c);
}

static int exynos4210_uart_getc(struct serial_port *port, char *pc)
{
    struct exynos4210_uart *uart = port->uart;
    uint32_t ufstat = exynos4210_read(uart, UFSTAT);
    uint32_t count;

    count = (ufstat & UFSTAT_RX_COUNT_MASK) >> UFSTAT_RX_COUNT_SHIFT;

    /* Check if Rx fifo is full or if the is something in it */
    if ( ufstat & UFSTAT_RX_FULL || count )
    {
        *pc = exynos4210_read(uart, URXH) & URXH_DATA_MASK;
        return 1;
    }
    else
        return 0;
}

static int __init exynos4210_uart_irq(struct serial_port *port)
{
    struct exynos4210_uart *uart = port->uart;

    return uart->irq;
}

static const struct vuart_info *exynos4210_vuart_info(struct serial_port *port)
{
    struct exynos4210_uart *uart = port->uart;

    return &uart->vuart;
}

static struct uart_driver __read_mostly exynos4210_uart_driver = {
    .init_preirq  = exynos4210_uart_init_preirq,
    .init_postirq = exynos4210_uart_init_postirq,
    .endboot      = NULL,
    .suspend      = exynos4210_uart_suspend,
    .resume       = exynos4210_uart_resume,
    .tx_ready     = exynos4210_uart_tx_ready,
    .putc         = exynos4210_uart_putc,
    .getc         = exynos4210_uart_getc,
    .irq          = exynos4210_uart_irq,
    .vuart_info   = exynos4210_vuart_info,
};

/* TODO: Parse UART config from the command line */
static int __init exynos4210_uart_init(struct dt_device_node *dev,
                                       const void *data)
{
    const char *config = data;
    struct exynos4210_uart *uart;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &exynos4210_com;

    /* uart->clock_hz  = 0x16e3600; */
    uart->baud      = BAUD_AUTO;
    uart->data_bits = 8;
    uart->parity    = PARITY_NONE;
    uart->stop_bits = 1;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("exynos4210: Unable to retrieve the base"
               " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("exynos4210: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("exynos4210: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = UTXH;
    uart->vuart.status_off = UTRSTAT;
    uart->vuart.status = UTRSTAT_TXE | UTRSTAT_TXFE;

    /* Register with generic serial driver. */
    serial_register_uart(SERHND_DTUART, &exynos4210_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match exynos4210_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("samsung,exynos4210-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(exynos4210, "Exynos 4210 UART", DEVICE_SERIAL)
        .dt_match = exynos4210_dt_match,
        .init = exynos4210_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
