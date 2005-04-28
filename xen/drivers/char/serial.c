/******************************************************************************
 * serial.c
 * 
 * Driver for 16550-series UARTs. This driver is to be kept within Xen as
 * it permits debugging of seriously-toasted machines (e.g., in situations
 * where a device driver within a guest OS would be inaccessible).
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/keyhandler.h> 
#include <xen/reboot.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/physdev.h>
#include <asm/io.h>

/* Config serial port with a string <baud>,DPS,<io-base>,<irq>. */
static char opt_com1[30] = OPT_COM1_STR, opt_com2[30] = OPT_COM2_STR;
string_param("com1", opt_com1);
string_param("com2", opt_com2);

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

/* FIFO control register */
#define FCR_ENABLE      0x01    /* enable FIFO          */
#define FCR_CLRX        0x02    /* clear Rx FIFO        */
#define FCR_CLTX        0x04    /* clear Tx FIFO        */
#define FCR_DMA         0x10    /* enter DMA mode       */
#define FCR_TRG1        0x00    /* Rx FIFO trig lev 1   */
#define FCR_TRG4        0x40    /* Rx FIFO trig lev 4   */
#define FCR_TRG8        0x80    /* Rx FIFO trig lev 8   */
#define FCR_TRG14       0xc0    /* Rx FIFO trig lev 14  */

/* Line control register */
#define LCR_DLAB        0x80    /* Divisor Latch Access */

/* Modem Control Register */
#define MCR_DTR         0x01    /* Data Terminal Ready  */
#define MCR_RTS         0x02    /* Request to Send      */
#define MCR_OUT2        0x08    /* OUT2: interrupt mask */

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

#define RXBUFSZ 32
#define MASK_RXBUF_IDX(_i) ((_i)&(RXBUFSZ-1))
struct uart {
    int              baud, data_bits, parity, stop_bits, io_base, irq;
    serial_rx_fn     rx_lo, rx_hi, rx;
    spinlock_t       lock;
    unsigned char    rxbuf[RXBUFSZ];
    unsigned int     rxbufp, rxbufc;
    struct irqaction irqaction;
};

static struct uart com[2] = {
    { 0, 0, 0, 0, 0x3f8, 4,
      NULL, NULL, NULL,
      SPIN_LOCK_UNLOCKED },
    { 0, 0, 0, 0, 0x2f8, 3,
      NULL, NULL, NULL,
      SPIN_LOCK_UNLOCKED }
};

#define UART_ENABLED(_u) ((_u)->baud != 0)
#define DISABLE_UART(_u) ((_u)->baud = 0)


/***********************
 * PRIVATE FUNCTIONS
 */

static void uart_rx(struct uart *uart, struct cpu_user_regs *regs)
{
    unsigned char c;

    if ( !UART_ENABLED(uart) )
        return;

    /*
     * No need for the uart spinlock here. Only the uart's own interrupt
     * handler will read from the RBR and the handler isn't reentrant.
     * Calls to serial_getc() will disable this handler before proceeding.
     */
    while ( inb(uart->io_base + LSR) & LSR_DR )
    {
        c = inb(uart->io_base + RBR);
        if ( uart->rx != NULL )
            uart->rx(c, regs);
        else if ( (c & 0x80) && (uart->rx_hi != NULL) )
            uart->rx_hi(c&0x7f, regs);
        else if ( !(c & 0x80) && (uart->rx_lo != NULL) )
            uart->rx_lo(c&0x7f, regs);
        else if ( (uart->rxbufp - uart->rxbufc) != RXBUFSZ )
            uart->rxbuf[MASK_RXBUF_IDX(uart->rxbufp++)] = c;            
    }
}

static void serial_interrupt(
    int irq, void *dev_id, struct cpu_user_regs *regs)
{
    uart_rx((struct uart *)dev_id, regs);
}

static inline void __serial_putc(
    struct uart *uart, int handle, unsigned char c)
{
    unsigned long flags;
    int space;

    if ( (c == '\n') && (handle & SERHND_COOKED) )
        __serial_putc(uart, handle, '\r');

    if ( handle & SERHND_HI )
        c |= 0x80;
    else if ( handle & SERHND_LO )
        c &= 0x7f;

    do { 
        spin_lock_irqsave(&uart->lock, flags);
        space = arch_serial_putc(uart, c);
        spin_unlock_irqrestore(&uart->lock, flags);
    }
    while ( !space );
}

#define PARSE_ERR(_f, _a...)                 \
    do {                                     \
        printk( "ERROR: " _f "\n" , ## _a ); \
        DISABLE_UART(uart);                  \
        return;                              \
} while ( 0 )
        
static void parse_port_config(char *conf, struct uart *uart)
{
    if ( *conf == '\0' )
        return;

    uart->baud = simple_strtol(conf, &conf, 10);
    if ( (uart->baud < 1200) || (uart->baud > 115200) )
        PARSE_ERR("Baud rate %d outside supported range.", uart->baud);

    if ( *conf != ',' )
        PARSE_ERR("Missing data/parity/stop specifiers.");

    conf++;

    uart->data_bits = simple_strtol(conf, &conf, 10);
    if ( (uart->data_bits < 5) || (uart->data_bits > 8) )
        PARSE_ERR("%d data bits are unsupported.", uart->data_bits);

    switch ( *conf )
    {
    case 'n':
        uart->parity = PARITY_NONE;
        break;
    case 'o': 
        uart->parity =  PARITY_ODD;
        break;
    case 'e': 
        uart->parity =  PARITY_EVEN;
        break;
    case 'm': 
        uart->parity =  PARITY_MARK;
        break;
    case 's': 
        uart->parity =  PARITY_SPACE;
        break;

    default:
        PARSE_ERR("Invalid parity specifier '%c'.", *conf);
    }

    conf++;

    uart->stop_bits = simple_strtol(conf, &conf, 10);
    if ( (uart->stop_bits < 1) || (uart->stop_bits > 2) )
        PARSE_ERR("%d stop bits are unsupported.", uart->stop_bits);

    if ( *conf == ',' )
    {
        conf++;

        uart->io_base = simple_strtol(conf, &conf, 0);
        if ( (uart->io_base <= 0x0000) || (uart->io_base > 0xfff0) )
            PARSE_ERR("I/O port base 0x%x is outside the supported range.",
                      uart->io_base);

        if ( *conf != ',' )
            PARSE_ERR("Missing IRQ specifier.");
            
        conf++;
            
        uart->irq = simple_strtol(conf, &conf, 10);
        if ( (uart->irq <= 0) || (uart->irq >= 32) )
            PARSE_ERR("IRQ %d is outside the supported range.", uart->irq);
    }
}

static void uart_config_stage1(struct uart *uart)
{
    unsigned char lcr;

    if ( !UART_ENABLED(uart) )
        return;

    lcr = (uart->data_bits - 5) | ((uart->stop_bits - 1) << 2) | uart->parity;

    /* No interrupts. */
    outb(0, uart->io_base + IER);

    /* Line control and baud-rate generator. */
    outb(lcr | LCR_DLAB,    uart->io_base + LCR);
    outb(115200/uart->baud, uart->io_base + DLL); /* baud lo */
    outb(0,                 uart->io_base + DLM); /* baud hi */
    outb(lcr,               uart->io_base + LCR); /* parity, data, stop */

    /* No flow ctrl: DTR and RTS are both wedged high to keep remote happy. */
    outb(MCR_DTR | MCR_RTS, uart->io_base + MCR);

    /* Enable and clear the FIFOs. Set a large trigger threshold. */
    outb(FCR_ENABLE | FCR_CLRX | FCR_CLTX | FCR_TRG14, uart->io_base + FCR);
}

static void uart_config_stage2(struct uart *uart)
{
    int rc;

    if ( !UART_ENABLED(uart) )
        return;

    uart->irqaction.handler = serial_interrupt;
    uart->irqaction.name    = "serial";
    uart->irqaction.dev_id  = uart;
    if ( (rc = setup_irq(uart->irq, &uart->irqaction)) != 0 )
        printk("ERROR: Failed to allocate serial IRQ %d\n", uart->irq);

    /* For sanity, clear the receive FIFO. */
    outb(FCR_ENABLE | FCR_CLRX | FCR_TRG14, uart->io_base + FCR);

    /* Master interrupt enable; also keep DTR/RTS asserted. */
    outb(MCR_OUT2 | MCR_DTR | MCR_RTS, uart->io_base + MCR);

    /* Enable receive interrupts. */
    outb(IER_ERDAI, uart->io_base + IER);
}


/***********************
 * PUBLIC FUNCTIONS
 */

void serial_init_stage1(void)
{
    parse_port_config(opt_com1, &com[0]);
    parse_port_config(opt_com2, &com[1]);

    uart_config_stage1(&com[0]);
    uart_config_stage1(&com[1]);
}

void serial_init_stage2(void)
{
    uart_config_stage2(&com[0]);
    uart_config_stage2(&com[1]);
}

int parse_serial_handle(char *conf)
{
    int handle;

    /* Silently fail if user has explicitly requested no serial I/O. */
    if ( strcmp(conf, "none") == 0 )
        return -1;

    if ( strncmp(conf, "com", 3) != 0 )
        goto fail;

    switch ( conf[3] )
    {
    case '1':
        handle = 0;
        break;
    case '2':
        handle = 1;
        break;
    default:
        goto fail;
    }

#ifndef NO_UART_CONFIG_OK
    if ( !UART_ENABLED(&com[handle]) )
    {
        printk("ERROR: cannot use unconfigured serial port COM%d\n", handle+1);
        return -1;
    }
#endif

    if ( conf[4] == 'H' )
        handle |= SERHND_HI;
    else if ( conf[4] == 'L' )
        handle |= SERHND_LO;

    handle |= SERHND_COOKED;

    return handle;

 fail:
    printk("ERROR: bad serial-interface specification '%s'\n", conf);
    return -1;
}

void serial_set_rx_handler(int handle, serial_rx_fn fn)
{
    struct uart *uart = &com[handle & SERHND_IDX];
    unsigned long flags;

    if ( handle == -1 )
        return;

    spin_lock_irqsave(&uart->lock, flags);

    if ( uart->rx != NULL )
        goto fail;

    if ( handle & SERHND_LO )
    {
        if ( uart->rx_lo != NULL )
            goto fail;
        uart->rx_lo = fn;        
    }
    else if ( handle & SERHND_HI )
    {
        if ( uart->rx_hi != NULL )
            goto fail;
        uart->rx_hi = fn;
    }
    else
    {
        if ( (uart->rx_hi != NULL) || (uart->rx_lo != NULL) )
            goto fail;
        uart->rx = fn;
    }

    spin_unlock_irqrestore(&uart->lock, flags);
    return;

 fail:
    spin_unlock_irqrestore(&uart->lock, flags);
    printk("ERROR: Conflicting receive handlers for COM%d\n", 
           handle & SERHND_IDX);
}

void serial_putc(int handle, unsigned char c)
{
    struct uart *uart = &com[handle & SERHND_IDX];

    if ( handle == -1 )
        return;

    __serial_putc(uart, handle, c);
}

void serial_puts(int handle, const char *s)
{
    struct uart *uart = &com[handle & SERHND_IDX];

    if ( handle == -1 )
        return;

    while ( *s != '\0' )
        __serial_putc(uart, handle, *s++);
}

/* Returns TRUE if given character (*pc) matches the serial handle. */
static int byte_matches(int handle, unsigned char *pc)
{
    if ( !(handle & SERHND_HI) )
    {
        if ( !(handle & SERHND_LO) || !(*pc & 0x80) )
            return 1;
    }
    else if ( *pc & 0x80 )
    {
        *pc &= 0x7f;
        return 1;
    }
    return 0;
}

unsigned char irq_serial_getc(int handle)
{
    struct uart *uart = &com[handle & SERHND_IDX];
    unsigned char c;


    while ( uart->rxbufp != uart->rxbufc )
    {
        c = uart->rxbuf[MASK_RXBUF_IDX(uart->rxbufc++)];
        if ( byte_matches(handle, &c) )
            goto out;
    }
    
    /* We now wait for the UART to receive a suitable character. */
    do {
        while ( (inb(uart->io_base + LSR) & LSR_DR) == 0 )
            barrier();
        c = inb(uart->io_base + RBR);
    }
    while ( !byte_matches(handle, &c) );
    
 out:
    return c;
}

unsigned char serial_getc(int handle)
{
    struct uart *uart = &com[handle & SERHND_IDX];
    unsigned char c;
    unsigned long flags;

    spin_lock_irqsave(&uart->lock, flags);

    while ( uart->rxbufp != uart->rxbufc )
    {
        c = uart->rxbuf[MASK_RXBUF_IDX(uart->rxbufc++)];
        if ( byte_matches(handle, &c) )
            goto out;
    }
    
    disable_irq(uart->irq);

    c = irq_serial_getc(handle);
    
    enable_irq(uart->irq);
 out:
    spin_unlock_irqrestore(&uart->lock, flags);
    return c;
}

void serial_force_unlock(int handle)
{
    struct uart *uart = &com[handle & SERHND_IDX];
    if ( handle != -1 )
        uart->lock = SPIN_LOCK_UNLOCKED;
}

void serial_endboot(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( UART_ENABLED(&com[i]) )
            physdev_modify_ioport_access_range(dom0, 0, com[i].io_base, 8);
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
