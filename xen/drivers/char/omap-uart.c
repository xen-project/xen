/*
 * omap-uart.c
 * Based on drivers/char/ns16550.c
 *
 * Driver for OMAP-UART controller
 *
 * Copyright (C) 2013, Chen Baozi <baozich@gmail.com>
 *
 * Note: This driver is made separate from 16550-series UART driver as
 * omap platform has some specific configurations
 */

#include <xen/config.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/device_tree.h>
#include <asm/device.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/8250-uart.h>
#include <asm/io.h>

#define REG_SHIFT 2

/* Register offsets */
#define UART_OMAP_EFR    0x02   /* Enhanced feature register */
#define UART_OMAP_MDR1   0x08   /* Mode definition register 1 */
#define UART_OMAP_SCR    0x10   /* Supplementary control register */
#define UART_OMAP_SSR    0x11   /* Supplementary status register */
#define UART_OMAP_SYSC   0x15   /* System configuration register */
#define UART_OMAP_TXFIFO_LVL   0x1A   /* TX FIFO level register */

/* Enhanced feature register */
#define UART_OMAP_EFR_ECB   0x10   /* Enhanced control bit */

/* Mode definition register 1 */
#define UART_OMAP_MDR1_16X_MODE   0x00   /* UART 16x mode           */
#define UART_OMAP_MDR1_DISABLE    0x07   /* Disable (default state) */

/* Supplementary control register bitmasks */
#define UART_OMAP_SCR_RX_TRIG_GRANU1_MASK   (1 << 7)

/* Supplementary status register bitmasks */
#define UART_OMAP_SSR_TX_FIFO_FULL_MASK   (1 << 0)

/* System configuration register */
#define UART_OMAP_SYSC_DEF_CONF   0x0d   /* autoidle mode, wakeup is enabled */

#define omap_read(uart, off)       readl((uart)->regs + (off<<REG_SHIFT))
#define omap_write(uart, off, val) writel((val), (uart)->regs + (off<<REG_SHIFT))

static struct omap_uart {
    u32 baud, clock_hz, data_bits, parity, stop_bits, fifo_size;
    unsigned int irq;
    char __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} omap_com = {0};

static void omap_uart_interrupt(int irq, void *data, struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct omap_uart *uart = port->uart;
    u32 lsr;
    uint32_t reg;

    while ( !(omap_read(uart, UART_IIR) & UART_IIR_NOINT) )
    {
        lsr = omap_read(uart, UART_LSR) & 0xff;
	if ( lsr & UART_LSR_THRE )
            serial_tx_interrupt(port, regs);
	if ( lsr & UART_LSR_DR )
            serial_rx_interrupt(port, regs);

        if ( port->txbufc == port->txbufp ) {
            reg = omap_read(uart, UART_IER);
            omap_write(uart, UART_IER, reg & (~UART_IER_ETHREI));
        }
    };
}

static void baud_protocol_setup(struct omap_uart *uart)
{
    u32 dll, dlh, efr;
    unsigned int divisor;

    divisor = uart->clock_hz / (uart->baud << 4);
    dll = divisor & 0xff;
    dlh = divisor >> 8;

    /*
     * Switch to register configuration mode B to access the UART_OMAP_EFR
     * register.
     */
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_B);
    /*
     * Enable access to the UART_IER[7:4] bit field.
     */
    efr = omap_read(uart, UART_OMAP_EFR);
    omap_write(uart, UART_OMAP_EFR, efr|UART_OMAP_EFR_ECB);
    /*
     * Switch to register operation mode to access the UART_IER register.
     */
    omap_write(uart, UART_LCR, 0);
    /*
     * Clear the UART_IER register (set the UART_IER[4] SLEEP_MODE bit
     * to 0 to change the UART_DLL and UART_DLM register). Set the
     * UART_IER register value to 0x0000.
     */
    omap_write(uart, UART_IER, 0);
    /*
     * Switch to register configuartion mode B to access the UART_DLL and
     * UART_DLM registers.
     */
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_B);
    /*
     * Load divisor value.
     */
    omap_write(uart, UART_DLL, dll);
    omap_write(uart, UART_DLM, dlh);
    /*
     * Restore the UART_OMAP_EFR
     */
    omap_write(uart, UART_OMAP_EFR, efr);
    /*
     * Load the new protocol formatting (parity, stop-bit, character length)
     * and switch to register operational mode.
     */
    omap_write(uart, UART_LCR, (uart->data_bits - 5) |
               ((uart->stop_bits - 1) << 2) | uart->parity);
}

static void fifo_setup(struct omap_uart *uart)
{
    u32 lcr, efr, mcr;
    /*
     * Switch to register configuration mode B to access the UART_OMAP_EFR
     * register.
     */
    lcr = omap_read(uart, UART_LCR);
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_B);
    /*
     * Enable register submode TCR_TLR to access the UART_OMAP_TLR register.
     */
    efr = omap_read(uart, UART_OMAP_EFR);
    omap_write(uart, UART_OMAP_EFR, efr|UART_OMAP_EFR_ECB);
    /*
     * Switch to register configuration mode A to access the UART_MCR
     * register.
     */
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_A);
    /*
     * Enable register submode TCR_TLR to access the UART_OMAP_TLR register
     */
    mcr = omap_read(uart, UART_MCR);
    omap_write(uart, UART_MCR, mcr|UART_MCR_TCRTLR);
    /*
     * Enable the FIFO; load the new FIFO trigger and the new DMA mode.
     */
    omap_write(uart, UART_FCR, UART_FCR_R_TRIG_01|
               UART_FCR_T_TRIG_10|UART_FCR_ENABLE);
    /*
     * Switch to register configuration mode B to access the UART_EFR
     * register.
     */
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_B);
    /*
     * Load the new FIFO triggers and the new DMA mode bit.
     */
    omap_write(uart, UART_OMAP_SCR, UART_OMAP_SCR_RX_TRIG_GRANU1_MASK);
    /*
     * Restore the UART_OMAP_EFR[4] value.
     */
    omap_write(uart, UART_OMAP_EFR, efr);
    /*
     * Switch to register configuration mode A to access the UART_MCR
     * register.
     */
    omap_write(uart, UART_LCR, UART_LCR_CONF_MODE_A);
    /*
     * Restore UART_MCR[6] value.
     */
    omap_write(uart, UART_MCR, mcr);
    /*
     * Restore UART_LCR value.
     */
    omap_write(uart, UART_LCR, lcr);

    uart->fifo_size = 64;
}

static void __init omap_uart_init_preirq(struct serial_port *port)
{
    struct omap_uart *uart = port->uart;

    /*
     * Clear the FIFO buffers.
     */
    omap_write(uart, UART_FCR, UART_FCR_ENABLE);
    omap_write(uart, UART_FCR, UART_FCR_ENABLE|UART_FCR_CLRX|UART_FCR_CLTX);
    omap_write(uart, UART_FCR, 0);

    /*
     * The TRM says the mode should be disabled while UART_DLL and UART_DHL
     * are being changed so we disable before setup, then enable.
     */
    omap_write(uart, UART_OMAP_MDR1, UART_OMAP_MDR1_DISABLE);

    /* Baud rate & protocol format setup */
    baud_protocol_setup(uart);

    /* FIFO setup */
    fifo_setup(uart);

    /* No flow control */
    omap_write(uart, UART_MCR, UART_MCR_DTR|UART_MCR_RTS);

    omap_write(uart, UART_OMAP_MDR1, UART_OMAP_MDR1_16X_MODE);

    /* setup idle mode */
    omap_write(uart, UART_OMAP_SYSC, UART_OMAP_SYSC_DEF_CONF);
}

static void __init omap_uart_init_postirq(struct serial_port *port)
{
    struct omap_uart *uart = port->uart;

    uart->irqaction.handler = omap_uart_interrupt;
    uart->irqaction.name = "omap_uart";
    uart->irqaction.dev_id = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        dprintk(XENLOG_ERR, "Failed to allocated omap_uart IRQ %d\n",
                uart->irq);
        return;
    }

    /* Enable interrupts */
    omap_write(uart, UART_IER, UART_IER_ERDAI|UART_IER_ETHREI|UART_IER_ELSI);
}

static void omap_uart_suspend(struct serial_port *port)
{
    BUG();
}

static void omap_uart_resume(struct serial_port *port)
{
    BUG();
}

static int omap_uart_tx_ready(struct serial_port *port)
{
    struct omap_uart *uart = port->uart;
    uint32_t reg;
    uint8_t cnt;

    reg = omap_read(uart, UART_IER);
    omap_write(uart, UART_IER, reg | UART_IER_ETHREI);

    /* Check for empty space in TX FIFO */
    if ( omap_read(uart, UART_OMAP_SSR) & UART_OMAP_SSR_TX_FIFO_FULL_MASK )
        return 0;

    /* Check number of data bytes stored in TX FIFO */
    cnt = omap_read(uart, UART_OMAP_TXFIFO_LVL);
    ASSERT( cnt >= 0 && cnt <= uart->fifo_size );

    return (uart->fifo_size - cnt);
}

static void omap_uart_putc(struct serial_port *port, char c)
{
    struct omap_uart *uart = port->uart;

    omap_write(uart, UART_THR, (uint32_t)(unsigned char)c);
}

static int omap_uart_getc(struct serial_port *port, char *pc)
{
    struct omap_uart *uart = port->uart;

    if ( !(omap_read(uart, UART_LSR) & UART_LSR_DR) )
	return 0;

    *pc = omap_read(uart, UART_RBR) & 0xff;
    return 1;
}

static int __init omap_uart_irq(struct serial_port *port)
{
    struct omap_uart *uart = port->uart;

    return ((uart->irq > 0) ? uart->irq : -1);
}

static const struct vuart_info *omap_vuart_info(struct serial_port *port)
{
    struct omap_uart *uart = port->uart;

    return &uart->vuart;
}

static struct uart_driver __read_mostly omap_uart_driver = {
    .init_preirq = omap_uart_init_preirq,
    .init_postirq = omap_uart_init_postirq,
    .endboot = NULL,
    .suspend = omap_uart_suspend,
    .resume = omap_uart_resume,
    .tx_ready = omap_uart_tx_ready,
    .putc = omap_uart_putc,
    .getc = omap_uart_getc,
    .irq = omap_uart_irq,
    .vuart_info = omap_vuart_info,
};

static int __init omap_uart_init(struct dt_device_node *dev,
                                 const void *data)
{
    const char *config = data;
    struct omap_uart *uart;
    u32 clkspec;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &omap_com;

    res = dt_property_read_u32(dev, "clock-frequency", &clkspec);
    if ( !res )
    {
        printk("omap-uart: Unable to retrieve the clock frequency\n");
        return -EINVAL;
    }

    uart->clock_hz = clkspec;
    uart->baud = 115200;
    uart->data_bits = 8;
    uart->parity = UART_PARITY_NONE;
    uart->stop_bits = 1;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("omap-uart: Unable to retrieve the base"
               " address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("omap-uart: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }
    uart->irq = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("omap-uart: Unable to map the UART memory\n");
        return -ENOMEM;
    }


    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = UART_THR;
    uart->vuart.status_off = UART_LSR << REG_SHIFT;
    uart->vuart.status = UART_LSR_THRE;

    /* Register with generic serial driver */
    serial_register_uart(SERHND_DTUART, &omap_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match omap_uart_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("ti,omap4-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(omap_uart, "OMAP UART", DEVICE_SERIAL)
    .dt_match = omap_uart_dt_match,
    .init = omap_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
