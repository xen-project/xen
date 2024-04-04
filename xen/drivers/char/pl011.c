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

#include <xen/console.h>
#include <xen/serial.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <asm/device.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/pl011-uart.h>
#include <asm/io.h>

static struct pl011 {
    unsigned int data_bits, parity, stop_bits;
    unsigned int irq;
    void __iomem *regs;
    /* UART with IRQ line: interrupt-driven I/O. */
    struct irqaction irqaction;
    struct vuart_info vuart;
    /* /\* UART with no IRQ line: periodically-polled I/O. *\/ */
    /* struct timer timer; */
    /* unsigned int timeout_ms; */
    /* bool probing, intr_works; */
    bool sbsa;  /* ARM SBSA generic interface */
    bool mmio32; /* 32-bit only MMIO */
} pl011_com = {0};

/* These parity settings can be ORed directly into the LCR. */
#define PARITY_NONE  (0)
#define PARITY_ODD   (PEN)
#define PARITY_EVEN  (PEN|EPS)
#define PARITY_MARK  (PEN|SPS)
#define PARITY_SPACE (PEN|EPS|SPS)

/*
 * By default, PL011 accesses shall be done using 8/16-bit accessors to
 * support legacy devices that cannot cope with 32-bit. On the other hand,
 * there are implementations of PL011 that can only handle 32-bit MMIO. Also,
 * SBSA v2.x requires 32-bit accesses. Note that for default case, we use
 * largest-common accessors (i.e. 16-bit) not to end up using different ones
 * depending on the actual register size.
 */
static inline void
pl011_write(struct pl011 *uart, unsigned int offset, unsigned int val)
{
    if ( uart->mmio32 )
        writel(val, uart->regs + offset);
    else
        writew(val, uart->regs + offset);
}

static inline unsigned int pl011_read(struct pl011 *uart, unsigned int offset)
{
    if ( uart->mmio32 )
        return readl(uart->regs + offset);

    return readw(uart->regs + offset);
}

static unsigned int pl011_intr_status(struct pl011 *uart)
{
    /* UARTMIS is not documented in SBSA v2.x, so use UARTRIS/UARTIMSC. */
    return (pl011_read(uart, RIS) & pl011_read(uart, IMSC));
}

static void pl011_interrupt(int irq, void *data)
{
    struct serial_port *port = data;
    struct pl011 *uart = port->uart;
    unsigned int status = pl011_intr_status(uart);

    if ( status )
    {
        do
        {
            pl011_write(uart, ICR, status & ~(TXI|RTI|RXI));

            if ( status & (RTI|RXI) )
                serial_rx_interrupt(port);

            /* TODO
                if ( status & (DSRMI|DCDMI|CTSMI|RIMI) )
                ...
            */

            if ( status & (TXI) )
                serial_tx_interrupt(port);

            status = pl011_intr_status(uart);
        } while (status != 0);
    }
}

static void __init pl011_init_preirq(struct serial_port *port)
{
    struct pl011 *uart = port->uart;
    unsigned int cr;

    /* No interrupts, please. */
    pl011_write(uart, IMSC, 0);

    if ( !uart->sbsa )
    {
        /* Definitely no DMA */
        pl011_write(uart, DMACR, 0x0);

        /* This write must follow FBRD and IBRD writes. */
        pl011_write(uart, LCR_H, (uart->data_bits - 5) << 5
                                | FEN
                                | ((uart->stop_bits - 1) << 3)
                                | uart->parity);
    }
    /* Clear errors */
    pl011_write(uart, RSR, 0);

    /* Mask and clear the interrupts */
    pl011_write(uart, IMSC, 0);
    pl011_write(uart, ICR, ALLI);

    if ( !uart->sbsa )
    {
        /* Enable the UART for RX and TX; keep RTS and DTR */
        cr = pl011_read(uart, CR);
        cr &= RTS | DTR;
        pl011_write(uart, CR, cr | RXE | TXE | UARTEN);
    }
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
        if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
            printk("ERROR: Failed to allocate pl011 IRQ %d\n", uart->irq);
    }

    /* Clear pending error interrupts */
    pl011_write(uart, ICR, OEI|BEI|PEI|FEI);

    /* Unmask interrupts */
    pl011_write(uart, IMSC, RTI|OEI|BEI|PEI|FEI|TXI|RXI);
}

static int pl011_tx_ready(struct serial_port *port)
{
    struct pl011 *uart = port->uart;

    return ((pl011_read(uart, FR) & TXFE) ? 16 : 0);
}

static void pl011_putc(struct serial_port *port, char c)
{
    struct pl011 *uart = port->uart;

    pl011_write(uart, DR, (uint32_t)(unsigned char)c);
}

static int pl011_getc(struct serial_port *port, char *pc)
{
    struct pl011 *uart = port->uart;

    if ( pl011_read(uart, FR) & RXFE )
        return 0;

    *pc = pl011_read(uart, DR) & 0xff;
    return 1;
}

static int __init pl011_irq(struct serial_port *port)
{
    struct pl011 *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *pl011_vuart(struct serial_port *port)
{
    struct pl011 *uart = port->uart;

    return &uart->vuart;
}

static void pl011_tx_stop(struct serial_port *port)
{
    struct pl011 *uart = port->uart;

    pl011_write(uart, IMSC, pl011_read(uart, IMSC) & ~(TXI));
}

static void pl011_tx_start(struct serial_port *port)
{
    struct pl011 *uart = port->uart;

    pl011_write(uart, IMSC, pl011_read(uart, IMSC) | (TXI));
}

static struct uart_driver __read_mostly pl011_driver = {
    .init_preirq  = pl011_init_preirq,
    .init_postirq = pl011_init_postirq,
    .tx_ready     = pl011_tx_ready,
    .putc         = pl011_putc,
    .getc         = pl011_getc,
    .irq          = pl011_irq,
    .start_tx     = pl011_tx_start,
    .stop_tx      = pl011_tx_stop,
    .vuart_info   = pl011_vuart,
};

static int __init
pl011_uart_init(int irq, paddr_t addr, paddr_t size, bool sbsa, bool mmio32)
{
    struct pl011 *uart;

    uart = &pl011_com;
    uart->irq       = irq;
    uart->data_bits = 8;
    uart->parity    = PARITY_NONE;
    uart->stop_bits = 1;
    uart->sbsa      = sbsa;

    /* Set 32-bit MMIO also for SBSA since v2.x requires it */
    uart->mmio32 = (mmio32 || sbsa);

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("pl011: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = DR;
    uart->vuart.status_off = FR;
    uart->vuart.status = 0;

    /* Register with generic serial driver. */
    serial_register_uart(SERHND_DTUART, &pl011_driver, uart);

    return 0;
}

/* TODO: Parse UART config from the command line */
static int __init pl011_dt_uart_init(struct dt_device_node *dev,
                                     const void *data)
{
    const char *config = data;
    int res;
    paddr_t addr, size;
    uint32_t io_width;
    bool mmio32 = false, sbsa;

    if ( strcmp(config, "") )
    {
        printk("WARNING: UART configuration is not supported\n");
    }

    res = dt_device_get_paddr(dev, 0, &addr, &size);
    if ( res )
    {
        printk("pl011: Unable to retrieve the base"
               " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("pl011: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }

    /* See linux Documentation/devicetree/bindings/serial/pl011.yaml */
    if ( dt_property_read_u32(dev, "reg-io-width", &io_width) )
    {
        if ( io_width == 4 )
            mmio32 = true;
        else if ( io_width != 1 )
        {
            printk("pl011: Unsupported reg-io-width (%"PRIu32")\n", io_width);
            return -EINVAL;
        }
    }

    sbsa = dt_device_is_compatible(dev, "arm,sbsa-uart");

    res = pl011_uart_init(res, addr, size, sbsa, mmio32);
    if ( res < 0 )
    {
        printk("pl011: Unable to initialize\n");
        return res;
    }

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match pl011_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("arm,pl011"),
    /* No need for a separate struct as SBSA UART is a subset of PL011 */
    DT_MATCH_COMPATIBLE("arm,sbsa-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(pl011, "PL011 UART", DEVICE_SERIAL)
        .dt_match = pl011_dt_match,
        .init = pl011_dt_uart_init,
DT_DEVICE_END

#ifdef CONFIG_ACPI
#include <xen/acpi.h>

static int __init pl011_acpi_uart_init(const void *data)
{
    acpi_status status;
    struct acpi_table_spcr *spcr = NULL;
    int res;
    bool sbsa;

    status = acpi_get_table(ACPI_SIG_SPCR, 0,
                            (struct acpi_table_header **)&spcr);

    if ( ACPI_FAILURE(status) )
    {
        printk("pl011: Failed to get SPCR table\n");
        return -EINVAL;
    }

    sbsa = (spcr->interface_type == ACPI_DBG2_SBSA ||
            spcr->interface_type == ACPI_DBG2_SBSA_32);

    /* trigger/polarity information is not available in spcr */
    irq_set_type(spcr->interrupt, IRQ_TYPE_LEVEL_HIGH);

    /* TODO - mmio32 proper handling (for now set to true) */
    res = pl011_uart_init(spcr->interrupt, spcr->serial_port.address,
                          PAGE_SIZE, sbsa, true);
    if ( res < 0 )
    {
        printk("pl011: Unable to initialize\n");
        return res;
    }

    return 0;
}

ACPI_DEVICE_START(apl011, "PL011 UART", DEVICE_SERIAL)
        .class_type = ACPI_DBG2_PL011,
        .init = pl011_acpi_uart_init,
ACPI_DEVICE_END

ACPI_DEVICE_START(asbsa_uart, "SBSA UART", DEVICE_SERIAL)
    .class_type = ACPI_DBG2_SBSA,
    .init = pl011_acpi_uart_init,
ACPI_DEVICE_END

ACPI_DEVICE_START(asbsa32_uart, "SBSA32 UART", DEVICE_SERIAL)
    .class_type = ACPI_DBG2_SBSA_32,
    .init = pl011_acpi_uart_init,
ACPI_DEVICE_END

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
