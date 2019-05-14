/*
 * xen/drivers/char/meson-uart.c
 *
 * Driver for Amlogic MESON UART
 *
 * Copyright (c) 2019, Amit Singh Tomar <amittomer25@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/irq.h>
#include <xen/serial.h>
#include <xen/vmap.h>
#include <asm/io.h>

/* Register offsets */
#define AML_UART_WFIFO_REG              0x00
#define AML_UART_RFIFO_REG              0x04
#define AML_UART_CONTROL_REG            0x08
#define AML_UART_STATUS_REG             0x0c
#define AML_UART_MISC_REG               0x10

/* UART_CONTROL bits */
#define AML_UART_TX_RST                 BIT(22, UL)
#define AML_UART_RX_RST                 BIT(23, UL)
#define AML_UART_CLEAR_ERR              BIT(24, UL)
#define AML_UART_RX_INT_EN              BIT(27, UL)
#define AML_UART_TX_INT_EN              BIT(28, UL)

/* UART_STATUS bits */
#define AML_UART_RX_FIFO_EMPTY          BIT(20, UL)
#define AML_UART_TX_FIFO_FULL           BIT(21, UL)
#define AML_UART_TX_FIFO_EMPTY          BIT(22, UL)
#define AML_UART_TX_CNT_MASK            GENMASK(14, 8)

/* AML_UART_MISC bits */
#define AML_UART_XMIT_IRQ(c)            (((c) & 0xff) << 8)
#define AML_UART_RECV_IRQ(c)            ((c) & 0xff)

#define TX_FIFO_SIZE                    64

#define setbits(addr, set)              writel((readl(addr) | (set)), (addr))
#define clrbits(addr, clear)            writel((readl(addr) & ~(clear)), (addr))

static struct meson_uart {
    unsigned int irq;
    void __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} meson_com;

static void meson_uart_interrupt(int irq, void *data,
                                 struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct meson_uart *uart = port->uart;
    uint32_t st = readl(uart->regs + AML_UART_STATUS_REG);

    if ( !(st & AML_UART_RX_FIFO_EMPTY) )
        serial_rx_interrupt(port, regs);

    if ( !(st & AML_UART_TX_FIFO_FULL) )
        serial_tx_interrupt(port, regs);
}

static void __init meson_uart_init_preirq(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    /* Reset UART */
    setbits(uart->regs + AML_UART_CONTROL_REG,
            (AML_UART_RX_RST | AML_UART_TX_RST | AML_UART_CLEAR_ERR));

    clrbits(uart->regs + AML_UART_CONTROL_REG,
            (AML_UART_RX_RST | AML_UART_TX_RST | AML_UART_CLEAR_ERR));

    /* Disable Rx/Tx interrupts */
    clrbits(uart->regs + AML_UART_CONTROL_REG,
               (AML_UART_RX_INT_EN | AML_UART_TX_INT_EN));
}

static void __init meson_uart_init_postirq(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    uart->irqaction.handler = meson_uart_interrupt;
    uart->irqaction.name    = "meson_uart";
    uart->irqaction.dev_id  = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        printk("Failed to allocated Meson UART IRQ %d\n", uart->irq);
        return;
    }

    /*
     * Configure Rx/Tx interrupts based on bytes in FIFO, these bits have
     * taken from Linux driver
     */
    writel((AML_UART_RECV_IRQ(1) | AML_UART_XMIT_IRQ(TX_FIFO_SIZE / 2)),
           uart->regs + AML_UART_MISC_REG);

    /* Make sure Rx/Tx interrupts are enabled now */
    setbits(uart->regs + AML_UART_CONTROL_REG,
            (AML_UART_RX_INT_EN | AML_UART_TX_INT_EN));
}

static void meson_uart_suspend(struct serial_port *port)
{
    BUG();
}

static void meson_uart_resume(struct serial_port *port)
{
    BUG();
}

static void meson_uart_putc(struct serial_port *port, char c)
{
    struct meson_uart *uart = port->uart;

    writel(c, uart->regs + AML_UART_WFIFO_REG);
}

static int meson_uart_getc(struct serial_port *port, char *c)
{
    struct meson_uart *uart = port->uart;

    if ( (readl(uart->regs + AML_UART_STATUS_REG) & AML_UART_RX_FIFO_EMPTY) )
        return 0;

    *c = readl(uart->regs + AML_UART_RFIFO_REG) & 0xff;

    return 1;
}

static int __init meson_irq(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    return uart->irq;
}

static const struct vuart_info *meson_vuart_info(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    return &uart->vuart;
}

static void meson_uart_stop_tx(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    clrbits(uart->regs + AML_UART_CONTROL_REG, AML_UART_TX_INT_EN);
}

static void meson_uart_start_tx(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;

    setbits(uart->regs + AML_UART_CONTROL_REG, AML_UART_TX_INT_EN);
}

static int meson_uart_tx_ready(struct serial_port *port)
{
    struct meson_uart *uart = port->uart;
    uint32_t reg;

    reg = readl(uart->regs + AML_UART_STATUS_REG);

    if ( reg & AML_UART_TX_FIFO_EMPTY )
        return TX_FIFO_SIZE;
    if ( reg & AML_UART_TX_FIFO_FULL )
        return 0;

    return (reg & AML_UART_TX_CNT_MASK) >> 8;
}

static struct uart_driver __read_mostly meson_uart_driver = {
    .init_preirq  = meson_uart_init_preirq,
    .init_postirq = meson_uart_init_postirq,
    .endboot      = NULL,
    .suspend      = meson_uart_suspend,
    .resume       = meson_uart_resume,
    .putc         = meson_uart_putc,
    .getc         = meson_uart_getc,
    .tx_ready     = meson_uart_tx_ready,
    .stop_tx      = meson_uart_stop_tx,
    .start_tx     = meson_uart_start_tx,
    .irq          = meson_irq,
    .vuart_info   = meson_vuart_info,
};

static int __init meson_uart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct meson_uart *uart;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &meson_com;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("meson: Unable to retrieve the base address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("meson: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }

    uart->irq  = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("meson: Unable to map the UART\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = AML_UART_WFIFO_REG;
    uart->vuart.status_off = AML_UART_STATUS_REG;
    uart->vuart.status = AML_UART_RX_FIFO_EMPTY | AML_UART_TX_FIFO_EMPTY;

    /* Register with generic serial driver. */
    serial_register_uart(SERHND_DTUART, &meson_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match meson_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("amlogic,meson-uart"),
    DT_MATCH_COMPATIBLE("amlogic,meson6-uart"),
    DT_MATCH_COMPATIBLE("amlogic,meson8-uart"),
    DT_MATCH_COMPATIBLE("amlogic,meson8b-uart"),
    DT_MATCH_COMPATIBLE("amlogic,meson-gx-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(meson, "Amlogic UART", DEVICE_SERIAL)
    .dt_match = meson_dt_match,
    .init = meson_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
*/
