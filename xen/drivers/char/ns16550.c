/******************************************************************************
 * ns16550.c
 * 
 * Driver for 16550-series UARTs. This driver is to be kept within Xen as
 * it permits debugging of seriously-toasted machines (e.g., in situations
 * where a device driver within a guest OS would be inaccessible).
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/console.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/iocap.h>
#include <asm/io.h>

/*
 * Configure serial port with a string:
 *   <baud>[/<clock_hz>][,DPS[,<io-base>[,<irq>]]].
 * The tail of the string can be omitted if platform defaults are sufficient.
 * If the baud rate is pre-configured, perhaps by a bootloader, then 'auto'
 * can be specified in place of a numeric baud rate. Polled mode is specified
 * by requesting irq 0.
 */
static char __initdata opt_com1[30] = "";
static char __initdata opt_com2[30] = "";
string_param("com1", opt_com1);
string_param("com2", opt_com2);

static struct ns16550 {
    int baud, clock_hz, data_bits, parity, stop_bits, irq;
    unsigned long io_base;   /* I/O port or memory-mapped I/O address. */
    char *remapped_io_base;  /* Remapped virtual address of mmap I/O.  */ 
    /* UART with IRQ line: interrupt-driven I/O. */
    struct irqaction irqaction;
    /* UART with no IRQ line: periodically-polled I/O. */
    struct timer timer;
    unsigned int timeout_ms;
} ns16550_com[2] = { { 0 } };

/* Register offsets */
#define RBR             0x00    /* receive buffer       */
#define THR             0x00    /* transmit holding     */
#define IER             0x01    /* interrupt enable     */
#define IIR             0x02    /* interrupt identity   */
#define FCR             0x02    /* FIFO control         */
#define LCR             0x03    /* line control         */
#define MCR             0x04    /* Modem control        */
#define LSR             0x05    /* line status          */
#define MSR             0x06    /* Modem status         */
#define DLL             0x00    /* divisor latch (ls) (DLAB=1) */
#define DLM             0x01    /* divisor latch (ms) (DLAB=1) */

/* Interrupt Enable Register */
#define IER_ERDAI       0x01    /* rx data recv'd       */
#define IER_ETHREI      0x02    /* tx reg. empty        */
#define IER_ELSI        0x04    /* rx line status       */
#define IER_EMSI        0x08    /* MODEM status         */

/* Interrupt Identification Register */
#define IIR_NOINT       0x01    /* no interrupt pending */
#define IIR_IMASK       0x06    /* interrupt identity:  */
#define IIR_LSI         0x06    /*  - rx line status    */
#define IIR_RDAI        0x04    /*  - rx data recv'd    */
#define IIR_THREI       0x02    /*  - tx reg. empty     */
#define IIR_MSI         0x00    /*  - MODEM status      */

/* FIFO Control Register */
#define FCR_ENABLE      0x01    /* enable FIFO          */
#define FCR_CLRX        0x02    /* clear Rx FIFO        */
#define FCR_CLTX        0x04    /* clear Tx FIFO        */
#define FCR_DMA         0x10    /* enter DMA mode       */
#define FCR_TRG1        0x00    /* Rx FIFO trig lev 1   */
#define FCR_TRG4        0x40    /* Rx FIFO trig lev 4   */
#define FCR_TRG8        0x80    /* Rx FIFO trig lev 8   */
#define FCR_TRG14       0xc0    /* Rx FIFO trig lev 14  */

/* Line Control Register */
#define LCR_DLAB        0x80    /* Divisor Latch Access */

/* Modem Control Register */
#define MCR_DTR         0x01    /* Data Terminal Ready  */
#define MCR_RTS         0x02    /* Request to Send      */
#define MCR_OUT2        0x08    /* OUT2: interrupt mask */
#define MCR_LOOP        0x10    /* Enable loopback test mode */

/* Line Status Register */
#define LSR_DR          0x01    /* Data ready           */
#define LSR_OE          0x02    /* Overrun              */
#define LSR_PE          0x04    /* Parity error         */
#define LSR_FE          0x08    /* Framing error        */
#define LSR_BI          0x10    /* Break                */
#define LSR_THRE        0x20    /* Xmit hold reg empty  */
#define LSR_TEMT        0x40    /* Xmitter empty        */
#define LSR_ERR         0x80    /* Error                */

/* These parity settings can be ORed directly into the LCR. */
#define PARITY_NONE     (0<<3)
#define PARITY_ODD      (1<<3)
#define PARITY_EVEN     (3<<3)
#define PARITY_MARK     (5<<3)
#define PARITY_SPACE    (7<<3)

/* Frequency of external clock source. This definition assumes PC platform. */
#define UART_CLOCK_HZ   1843200

static char ns_read_reg(struct ns16550 *uart, int reg)
{
    if ( uart->remapped_io_base == NULL )
        return inb(uart->io_base + reg);
    return readb(uart->remapped_io_base + reg);
}

static void ns_write_reg(struct ns16550 *uart, int reg, char c)
{
    if ( uart->remapped_io_base == NULL )
        return outb(c, uart->io_base + reg);
    writeb(c, uart->remapped_io_base + reg);
}

static void ns16550_interrupt(
    int irq, void *dev_id, struct cpu_user_regs *regs)
{
    struct serial_port *port = dev_id;
    struct ns16550 *uart = port->uart;

    while ( !(ns_read_reg(uart, IIR) & IIR_NOINT) )
    {
        char lsr = ns_read_reg(uart, LSR);
        if ( lsr & LSR_THRE )
            serial_tx_interrupt(port, regs);
        if ( lsr & LSR_DR )
            serial_rx_interrupt(port, regs);
    }
}

static void ns16550_poll(void *data)
{
    struct serial_port *port = data;
    struct ns16550 *uart = port->uart;
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    while ( ns_read_reg(uart, LSR) & LSR_DR )
        serial_rx_interrupt(port, regs);

    if ( ns_read_reg(uart, LSR) & LSR_THRE )
        serial_tx_interrupt(port, regs);

    set_timer(&uart->timer, NOW() + MILLISECS(uart->timeout_ms));
}

static int ns16550_tx_empty(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    return !!(ns_read_reg(uart, LSR) & LSR_THRE);
}

static void ns16550_putc(struct serial_port *port, char c)
{
    struct ns16550 *uart = port->uart;
    ns_write_reg(uart, THR, c);
}

static int ns16550_getc(struct serial_port *port, char *pc)
{
    struct ns16550 *uart = port->uart;

    if ( !(ns_read_reg(uart, LSR) & LSR_DR) )
        return 0;

    *pc = ns_read_reg(uart, RBR);
    return 1;
}

static void __devinit ns16550_init_preirq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    unsigned char lcr;
    unsigned int  divisor;

    /* I/O ports are distinguished by their size (16 bits). */
    if ( uart->io_base >= 0x10000 )
        uart->remapped_io_base = (char *)ioremap(uart->io_base, 8);

    lcr = (uart->data_bits - 5) | ((uart->stop_bits - 1) << 2) | uart->parity;

    /* No interrupts. */
    ns_write_reg(uart, IER, 0);

    /* Line control and baud-rate generator. */
    ns_write_reg(uart, LCR, lcr | LCR_DLAB);
    if ( uart->baud != BAUD_AUTO )
    {
        /* Baud rate specified: program it into the divisor latch. */
        divisor = uart->clock_hz / (uart->baud << 4);
        ns_write_reg(uart, DLL, (char)divisor);
        ns_write_reg(uart, DLM, (char)(divisor >> 8));
    }
    else
    {
        /* Baud rate already set: read it out from the divisor latch. */
        divisor  = ns_read_reg(uart, DLL);
        divisor |= ns_read_reg(uart, DLM) << 8;
        uart->baud = uart->clock_hz / (divisor << 4);
    }
    ns_write_reg(uart, LCR, lcr);

    /* No flow ctrl: DTR and RTS are both wedged high to keep remote happy. */
    ns_write_reg(uart, MCR, MCR_DTR | MCR_RTS);

    /* Enable and clear the FIFOs. Set a large trigger threshold. */
    ns_write_reg(uart, FCR, FCR_ENABLE | FCR_CLRX | FCR_CLTX | FCR_TRG14);

    /* Check this really is a 16550+. Otherwise we have no FIFOs. */
    if ( ((ns_read_reg(uart, IIR) & 0xc0) == 0xc0) &&
         ((ns_read_reg(uart, FCR) & FCR_TRG14) == FCR_TRG14) )
        port->tx_fifo_size = 16;
}

static void __devinit ns16550_init_postirq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    int rc, bits;

    if ( uart->irq < 0 )
        return;

    serial_async_transmit(port);

    if ( uart->irq == 0 )
    {
        /* Polled mode. Calculate time to fill RX FIFO and/or empty TX FIFO. */
        bits = uart->data_bits + uart->stop_bits + !!uart->parity;
        uart->timeout_ms = max_t(
            unsigned int, 1, (bits * port->tx_fifo_size * 1000) / uart->baud);
        init_timer(&uart->timer, ns16550_poll, port, 0);
        set_timer(&uart->timer, NOW() + MILLISECS(uart->timeout_ms));
    }
    else
    {
        uart->irqaction.handler = ns16550_interrupt;
        uart->irqaction.name    = "ns16550";
        uart->irqaction.dev_id  = port;
        if ( (rc = setup_irq(uart->irq, &uart->irqaction)) != 0 )
            printk("ERROR: Failed to allocate ns16550 IRQ %d\n", uart->irq);

        /* Master interrupt enable; also keep DTR/RTS asserted. */
        ns_write_reg(uart, MCR, MCR_OUT2 | MCR_DTR | MCR_RTS);

        /* Enable receive and transmit interrupts. */
        ns_write_reg(uart, IER, IER_ERDAI | IER_ETHREI);
    }
}

#ifdef CONFIG_X86
static void __init ns16550_endboot(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    if ( ioports_deny_access(dom0, uart->io_base, uart->io_base + 7) != 0 )
        BUG();
}
#else
#define ns16550_endboot NULL
#endif

static int ns16550_irq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    return ((uart->irq > 0) ? uart->irq : -1);
}

static struct uart_driver ns16550_driver = {
    .init_preirq  = ns16550_init_preirq,
    .init_postirq = ns16550_init_postirq,
    .endboot      = ns16550_endboot,
    .tx_empty     = ns16550_tx_empty,
    .putc         = ns16550_putc,
    .getc         = ns16550_getc,
    .irq          = ns16550_irq
};

static int __init parse_parity_char(int c)
{
    switch ( c )
    {
    case 'n':
        return PARITY_NONE;
    case 'o': 
        return PARITY_ODD;
    case 'e': 
        return PARITY_EVEN;
    case 'm': 
        return PARITY_MARK;
    case 's': 
        return PARITY_SPACE;
    }
    return 0;
}

static int __init check_existence(struct ns16550 *uart)
{
    unsigned char status, scratch, scratch2, scratch3;

    /*
     * We can't poke MMIO UARTs until they get I/O remapped later. Assume that
     * if we're getting MMIO UARTs, the arch code knows what it's doing.
     */
    if ( uart->io_base >= 0x10000 )
        return 1;

    /*
     * Do a simple existence test first; if we fail this,
     * there's no point trying anything else.
     */
    scratch = ns_read_reg(uart, IER);
    ns_write_reg(uart, IER, 0);

    /*
     * Mask out IER[7:4] bits for test as some UARTs (e.g. TL
     * 16C754B) allow only to modify them if an EFR bit is set.
     */
    scratch2 = ns_read_reg(uart, IER) & 0x0f;
    ns_write_reg(uart, IER, 0x0F);
    scratch3 = ns_read_reg(uart, IER) & 0x0f;
    ns_write_reg(uart, IER, scratch);
    if ( (scratch2 != 0) || (scratch3 != 0x0F) )
        return 0;

    /*
     * Check to see if a UART is really there.
     * Use loopback test mode.
     */
    ns_write_reg(uart, MCR, MCR_LOOP | 0x0A);
    status = ns_read_reg(uart, MSR) & 0xF0;
    return (status == 0x90);
}

#define PARSE_ERR(_f, _a...)                 \
    do {                                     \
        printk( "ERROR: " _f "\n" , ## _a ); \
        return;                              \
    } while ( 0 )

static void __init ns16550_parse_port_config(
    struct ns16550 *uart, const char *conf)
{
    int baud;

    /* No user-specified configuration? */
    if ( (conf == NULL) || (*conf == '\0') )
    {
        /* Some platforms may automatically probe the UART configuartion. */
        if ( uart->baud != 0 )
            goto config_parsed;
        return;
    }

    if ( strncmp(conf, "auto", 4) == 0 )
    {
        uart->baud = BAUD_AUTO;
        conf += 4;
    }
    else if ( (baud = simple_strtoul(conf, &conf, 10)) != 0 )
        uart->baud = baud;

    if ( *conf == '/')
    {
        conf++;
        uart->clock_hz = simple_strtoul(conf, &conf, 0) << 4;
    }

    if ( *conf != ',' )
        goto config_parsed;
    conf++;

    uart->data_bits = simple_strtoul(conf, &conf, 10);

    uart->parity = parse_parity_char(*conf);
    conf++;

    uart->stop_bits = simple_strtoul(conf, &conf, 10);

    if ( *conf == ',' )
    {
        conf++;
        uart->io_base = simple_strtoul(conf, &conf, 0);

        if ( *conf == ',' )
        {
            conf++;
            uart->irq = simple_strtoul(conf, &conf, 10);
        }
    }

 config_parsed:
    /* Sanity checks. */
    if ( (uart->baud != BAUD_AUTO) &&
         ((uart->baud < 1200) || (uart->baud > 115200)) )
        PARSE_ERR("Baud rate %d outside supported range.", uart->baud);
    if ( (uart->data_bits < 5) || (uart->data_bits > 8) )
        PARSE_ERR("%d data bits are unsupported.", uart->data_bits);
    if ( (uart->stop_bits < 1) || (uart->stop_bits > 2) )
        PARSE_ERR("%d stop bits are unsupported.", uart->stop_bits);
    if ( uart->io_base == 0 )
        PARSE_ERR("I/O base address must be specified.");
    if ( !check_existence(uart) )
        PARSE_ERR("16550-compatible serial UART not present");

    /* Register with generic serial driver. */
    serial_register_uart(uart - ns16550_com, &ns16550_driver, uart);
}

void __init ns16550_init(int index, struct ns16550_defaults *defaults)
{
    struct ns16550 *uart;

    if ( (index < 0) || (index > 1) )
        return;

    uart = &ns16550_com[index];

    uart->baud      = (defaults->baud ? :
                       console_has((index == 0) ? "com1" : "com2")
                       ? BAUD_AUTO : 0);
    uart->clock_hz  = UART_CLOCK_HZ;
    uart->data_bits = defaults->data_bits;
    uart->parity    = parse_parity_char(defaults->parity);
    uart->stop_bits = defaults->stop_bits;
    uart->irq       = defaults->irq;
    uart->io_base   = defaults->io_base;

    ns16550_parse_port_config(uart, (index == 0) ? opt_com1 : opt_com2);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
