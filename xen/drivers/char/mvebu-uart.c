/*
 * xen/drivers/char/mvebu3700-uart.c
 *
 * Driver for Marvell MVEBU UART.
 *
 * Copyright (c) 2018, Amit Singh Tomar <amittomer25@gmail.com>.
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
#define UART_RX_REG             0x00

#define UART_TX_REG             0x04

#define UART_CTRL_REG           0x08
#define CTRL_TXFIFO_RST         BIT(15)
#define CTRL_RXFIFO_RST         BIT(14)
#define CTRL_TX_RDY_INT         BIT(5)
#define CTRL_RX_RDY_INT         BIT(4)
#define CTRL_BRK_DET_INT        BIT(3)
#define CTRL_FRM_ERR_INT        BIT(2)
#define CTRL_PAR_ERR_INT        BIT(1)
#define CTRL_OVR_ERR_INT        BIT(0)
#define CTRL_ERR_INT            (CTRL_BRK_DET_INT | CTRL_FRM_ERR_INT | \
                                 CTRL_PAR_ERR_INT | CTRL_OVR_ERR_INT)

#define UART_STATUS_REG         0x0c
#define STATUS_TXFIFO_EMP       BIT(13)
#define STATUS_TXFIFO_FUL       BIT(11)
#define STATUS_TXFIFO_HFL       BIT(10)
#define STATUS_TX_RDY           BIT(5)
#define STATUS_RX_RDY           BIT(4)
#define STATUS_BRK_DET          BIT(3)
#define STATUS_FRM_ERR          BIT(2)
#define STATUS_PAR_ERR          BIT(1)
#define STATUS_OVR_ERR          BIT(0)
#define STATUS_BRK_ERR          (STATUS_BRK_DET | STATUS_FRM_ERR | \
                                 STATUS_PAR_ERR | STATUS_OVR_ERR)

#define TX_FIFO_SIZE            32

static struct mvebu3700_uart {
    unsigned int irq;
    void __iomem *regs;
    struct irqaction irqaction;
    struct vuart_info vuart;
} mvebu3700_com = {0};

#define mvebu3700_read(uart, off)           readl((uart)->regs + off)
#define mvebu3700_write(uart, off, val)     writel(val, (uart->regs) + off)

static void mvebu3700_uart_interrupt(int irq, void *data,
                                     struct cpu_user_regs *regs)
{
    struct serial_port *port = data;
    struct mvebu3700_uart *uart = port->uart;
    uint32_t st = mvebu3700_read(uart, UART_STATUS_REG);

    if ( st & (STATUS_RX_RDY | STATUS_OVR_ERR | STATUS_FRM_ERR |
               STATUS_BRK_DET) )
        serial_rx_interrupt(port, regs);

    if ( st & STATUS_TX_RDY )
        serial_tx_interrupt(port, regs);
}

static void __init mvebu3700_uart_init_preirq(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;
    uint32_t reg;

    reg = mvebu3700_read(uart, UART_CTRL_REG);
    reg |= (CTRL_TXFIFO_RST | CTRL_RXFIFO_RST);
    mvebu3700_write(uart, UART_CTRL_REG, reg);

    /* Before we make IRQ request, clear the error bits of state register. */
    reg = mvebu3700_read(uart, UART_STATUS_REG);
    reg |= STATUS_BRK_ERR;
    mvebu3700_write(uart, UART_STATUS_REG, reg);

    /* Clear error interrupts. */
    mvebu3700_write(uart, UART_CTRL_REG, CTRL_ERR_INT);

    /* Disable Rx/Tx interrupts. */
    reg = mvebu3700_read(uart, UART_CTRL_REG);
    reg &= ~(CTRL_RX_RDY_INT | CTRL_TX_RDY_INT);
    mvebu3700_write(uart, UART_CTRL_REG, reg);
}

static void __init mvebu3700_uart_init_postirq(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;
    uint32_t reg;

    uart->irqaction.handler = mvebu3700_uart_interrupt;
    uart->irqaction.name    = "mvebu3700_uart";
    uart->irqaction.dev_id  = port;

    if ( setup_irq(uart->irq, 0, &uart->irqaction) != 0 )
    {
        printk("Failed to allocated mvebu3700_uart IRQ %d\n", uart->irq);
        return;
    }

    /* Make sure Rx/Tx interrupts are enabled now */
    reg = mvebu3700_read(uart, UART_CTRL_REG);
    reg |= (CTRL_RX_RDY_INT | CTRL_TX_RDY_INT);
    mvebu3700_write(uart, UART_CTRL_REG, reg);
}

static void mvebu3700_uart_suspend(struct serial_port *port)
{
    BUG();
}

static void mvebu3700_uart_resume(struct serial_port *port)
{
    BUG();
}

static void mvebu3700_uart_putc(struct serial_port *port, char c)
{
    struct mvebu3700_uart *uart = port->uart;

    mvebu3700_write(uart, UART_TX_REG, c);
}

static int mvebu3700_uart_getc(struct serial_port *port, char *c)
{
    struct mvebu3700_uart *uart = port->uart;

    if ( !(mvebu3700_read(uart, UART_STATUS_REG) & STATUS_RX_RDY) )
        return 0;

    *c = mvebu3700_read(uart, UART_RX_REG) & 0xff;

    return 1;
}

static int __init mvebu3700_irq(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;

    return uart->irq;
}

static const struct vuart_info *mvebu3700_vuart_info(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;

    return &uart->vuart;
}

static void mvebu3700_uart_stop_tx(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;
    uint32_t reg;

    reg = mvebu3700_read(uart, UART_CTRL_REG);
    reg &= ~CTRL_TX_RDY_INT;
    mvebu3700_write(uart, UART_CTRL_REG, reg);
}

static void mvebu3700_uart_start_tx(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;
    uint32_t reg;

    reg = mvebu3700_read(uart, UART_CTRL_REG);
    reg |= CTRL_TX_RDY_INT;
    mvebu3700_write(uart, UART_CTRL_REG, reg);
}

static int mvebu3700_uart_tx_ready(struct serial_port *port)
{
    struct mvebu3700_uart *uart = port->uart;
    uint32_t reg;

    reg = mvebu3700_read(uart, UART_STATUS_REG);

    if ( reg & STATUS_TXFIFO_EMP )
        return TX_FIFO_SIZE;
    if ( reg & STATUS_TXFIFO_FUL )
        return 0;
    if ( reg & STATUS_TXFIFO_HFL )
        return TX_FIFO_SIZE / 2;

    /*
     * If we reach here, we don't know the number of free char in FIFO
     * but we are sure that neither the FIFO is full nor empty.
     * So, let's just return at least 1.
     */
    return 1;
}

static struct uart_driver __read_mostly mvebu3700_uart_driver = {
    .init_preirq  = mvebu3700_uart_init_preirq,
    .init_postirq = mvebu3700_uart_init_postirq,
    .endboot      = NULL,
    .suspend      = mvebu3700_uart_suspend,
    .resume       = mvebu3700_uart_resume,
    .putc         = mvebu3700_uart_putc,
    .getc         = mvebu3700_uart_getc,
    .tx_ready     = mvebu3700_uart_tx_ready,
    .stop_tx      = mvebu3700_uart_stop_tx,
    .start_tx     = mvebu3700_uart_start_tx,
    .irq          = mvebu3700_irq,
    .vuart_info   = mvebu3700_vuart_info,
};

static int __init mvebu_uart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct mvebu3700_uart *uart;
    int res;
    u64 addr, size;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    uart = &mvebu3700_com;

    res = dt_device_get_address(dev, 0, &addr, &size);
    if ( res )
    {
        printk("mvebu3700: Unable to retrieve the base address of the UART\n");
        return res;
    }

    res = platform_get_irq(dev, 0);
    if ( res < 0 )
    {
        printk("mvebu3700: Unable to retrieve the IRQ\n");
        return -EINVAL;
    }

    uart->irq  = res;

    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("mvebu3700: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr = addr;
    uart->vuart.size = size;
    uart->vuart.data_off = UART_CTRL_REG;
    uart->vuart.status_off = UART_STATUS_REG;
    uart->vuart.status = STATUS_TX_RDY | STATUS_RX_RDY;

    /* Register with generic serial driver. */
    serial_register_uart(SERHND_DTUART, &mvebu3700_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match mvebu_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("marvell,armada-3700-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(mvebu, "Marvell Armada-3700 UART", DEVICE_SERIAL)
    .dt_match = mvebu_dt_match,
    .init = mvebu_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
