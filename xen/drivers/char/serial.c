/******************************************************************************
 * serial.c
 * 
 * Framework for serial device drivers.
 * 
 * Copyright (c) 2003-2008, K A Fraser
 */

#include <xen/delay.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/serial.h>
#include <xen/cache.h>

/* Never drop characters, even if the async transmit buffer fills. */
/* #define SERIAL_NEVER_DROP_CHARS 1 */

unsigned int __read_mostly serial_txbufsz = 16384;
size_param("serial_tx_buffer", serial_txbufsz);

#define mask_serial_rxbuf_idx(_i) ((_i)&(serial_rxbufsz-1))
#define mask_serial_txbuf_idx(_i) ((_i)&(serial_txbufsz-1))

static struct serial_port com[SERHND_IDX + 1] = {
    [0 ... SERHND_IDX] = {
        .rx_lock = SPIN_LOCK_UNLOCKED,
        .tx_lock = SPIN_LOCK_UNLOCKED
    }
};

static bool_t __read_mostly post_irq;

static inline void serial_start_tx(struct serial_port *port)
{
    if ( port->driver->start_tx != NULL )
        port->driver->start_tx(port);
}

static inline void serial_stop_tx(struct serial_port *port)
{
    if ( port->driver->stop_tx != NULL )
        port->driver->stop_tx(port);
}

void serial_rx_interrupt(struct serial_port *port, struct cpu_user_regs *regs)
{
    char c;
    serial_rx_fn fn = NULL;
    unsigned long flags;

    spin_lock_irqsave(&port->rx_lock, flags);

    if ( port->driver->getc(port, &c) )
    {
        if ( port->rx != NULL )
            fn = port->rx;
        else if ( (c & 0x80) && (port->rx_hi != NULL) )
            fn = port->rx_hi;
        else if ( !(c & 0x80) && (port->rx_lo != NULL) )
            fn = port->rx_lo;
        else if ( (port->rxbufp - port->rxbufc) != serial_rxbufsz )
            port->rxbuf[mask_serial_rxbuf_idx(port->rxbufp++)] = c;            
    }

    spin_unlock_irqrestore(&port->rx_lock, flags);

    if ( fn != NULL )
        (*fn)(c & 0x7f, regs);
}

void serial_tx_interrupt(struct serial_port *port, struct cpu_user_regs *regs)
{
    int i, n;
    unsigned long flags;

    local_irq_save(flags);

    /*
     * Avoid spinning for a long time: if there is a long-term lock holder
     * then we know that they'll be stuffing bytes into the transmitter which
     * will therefore not be empty for long.
     */
    while ( !spin_trylock(&port->tx_lock) )
    {
        if ( port->driver->tx_ready(port) <= 0 )
            goto out;
        cpu_relax();
    }

    if ( port->txbufc == port->txbufp )
    {
        /* Disable TX. nothing to send */
        serial_stop_tx(port);
        spin_unlock(&port->tx_lock);
        goto out;
    }
    else
    {
        if ( port->driver->tx_ready(port) )
            serial_start_tx(port);
    }
    for ( i = 0, n = port->driver->tx_ready(port); i < n; i++ )
    {
        if ( port->txbufc == port->txbufp )
            break;
        port->driver->putc(
            port, port->txbuf[mask_serial_txbuf_idx(port->txbufc++)]);
    }
    if ( i && port->driver->flush )
        port->driver->flush(port);

    spin_unlock(&port->tx_lock);

 out:
    local_irq_restore(flags);
}

static void __serial_putc(struct serial_port *port, char c)
{
    if ( (port->txbuf != NULL) && !port->sync )
    {
        /* Interrupt-driven (asynchronous) transmitter. */

        if ( port->tx_quench )
        {
            /* Buffer filled and we are dropping characters. */
            if ( (port->txbufp - port->txbufc) > (serial_txbufsz / 2) )
                return;
            port->tx_quench = 0;
        }

        if ( (port->txbufp - port->txbufc) == serial_txbufsz )
        {
            if ( port->tx_log_everything )
            {
                /* Buffer is full: we spin waiting for space to appear. */
                int n;

                while ( (n = port->driver->tx_ready(port)) == 0 )
                    cpu_relax();
                if ( n > 0 )
                {
                    /* Enable TX before sending chars */
                    serial_start_tx(port);
                    while ( n-- )
                        port->driver->putc(
                            port,
                            port->txbuf[mask_serial_txbuf_idx(port->txbufc++)]);
                    port->txbuf[mask_serial_txbuf_idx(port->txbufp++)] = c;
                }
            }
            else
            {
                /* Buffer is full: drop chars until buffer is half empty. */
                port->tx_quench = 1;
            }
            return;
        }

        if ( ((port->txbufp - port->txbufc) == 0) &&
             port->driver->tx_ready(port) > 0 )
        {
            /* Enable TX before sending chars */
            serial_start_tx(port);
            /* Buffer and UART FIFO are both empty, and port is available. */
            port->driver->putc(port, c);
        }
        else
        {
            /* Normal case: buffer the character. */
            port->txbuf[mask_serial_txbuf_idx(port->txbufp++)] = c;
        }
    }
    else if ( port->driver->tx_ready )
    {
        int n;

        /* Synchronous finite-capacity transmitter. */
        while ( !(n = port->driver->tx_ready(port)) )
            cpu_relax();
        if ( n > 0 )
        {
            /* Enable TX before sending chars */
            serial_start_tx(port);
            port->driver->putc(port, c);
        }
    }
    else
    {
        /* Simple synchronous transmitter. */
        serial_start_tx(port);
        port->driver->putc(port, c);
    }
}

void serial_putc(int handle, char c)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;

    port = &com[handle & SERHND_IDX];
    if ( !port->driver || !port->driver->putc )
        return;

    spin_lock_irqsave(&port->tx_lock, flags);

    if ( (c == '\n') && (handle & SERHND_COOKED) )
        __serial_putc(port, '\r' | ((handle & SERHND_HI) ? 0x80 : 0x00));

    if ( handle & SERHND_HI )
        c |= 0x80;
    else if ( handle & SERHND_LO )
        c &= 0x7f;

    __serial_putc(port, c);

    if ( port->driver->flush )
        port->driver->flush(port);

    spin_unlock_irqrestore(&port->tx_lock, flags);
}

void serial_puts(int handle, const char *s, size_t nr)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;

    port = &com[handle & SERHND_IDX];
    if ( !port->driver || !port->driver->putc )
        return;

    spin_lock_irqsave(&port->tx_lock, flags);

    for ( ; nr > 0; nr--, s++ )
    {
        char c = *s;

        if ( (c == '\n') && (handle & SERHND_COOKED) )
            __serial_putc(port, '\r' | ((handle & SERHND_HI) ? 0x80 : 0x00));

        if ( handle & SERHND_HI )
            c |= 0x80;
        else if ( handle & SERHND_LO )
            c &= 0x7f;

        __serial_putc(port, c);
    }

    if ( port->driver->flush )
        port->driver->flush(port);

    spin_unlock_irqrestore(&port->tx_lock, flags);
}

char serial_getc(int handle)
{
    struct serial_port *port;
    char c;
    unsigned long flags;

    if ( handle == -1 )
        return '\0';

    port = &com[handle & SERHND_IDX];
    if ( !port->driver || !port->driver->getc )
        return '\0';

    do {
        for ( ; ; )
        {
            spin_lock_irqsave(&port->rx_lock, flags);
            
            if ( port->rxbufp != port->rxbufc )
            {
                c = port->rxbuf[mask_serial_rxbuf_idx(port->rxbufc++)];
                spin_unlock_irqrestore(&port->rx_lock, flags);
                break;
            }
            
            if ( port->driver->getc(port, &c) )
            {
                spin_unlock_irqrestore(&port->rx_lock, flags);
                break;
            }

            spin_unlock_irqrestore(&port->rx_lock, flags);

            cpu_relax();
            udelay(100);
        }
    } while ( ((handle & SERHND_LO) &&  (c & 0x80)) ||
              ((handle & SERHND_HI) && !(c & 0x80)) );
    
    return c & 0x7f;
}

int __init serial_parse_handle(char *conf)
{
    int handle, flags = 0;

    if ( !strncmp(conf, "dbgp", 4) && (!conf[4] || conf[4] == ',') )
    {
        handle = SERHND_DBGP;
        goto common;
    }

    if ( !strncmp(conf, "dtuart", 6) )
    {
        handle = SERHND_DTUART;
        goto common;
    }

    if ( strncmp(conf, "com", 3) )
        goto fail;

    switch ( conf[3] )
    {
    case '1':
        handle = SERHND_COM1;
        break;
    case '2':
        handle = SERHND_COM2;
        break;
    default:
        goto fail;
    }

    if ( conf[4] == 'H' )
        flags |= SERHND_HI;
    else if ( conf[4] == 'L' )
        flags |= SERHND_LO;

 common:
    if ( !com[handle].driver )
        goto fail;

    if ( !post_irq )
        com[handle].state = serial_parsed;
    else if ( com[handle].state != serial_initialized )
    {
        if ( com[handle].driver->init_postirq )
            com[handle].driver->init_postirq(&com[handle]);
        com[handle].state = serial_initialized;
    }

    return handle | flags | SERHND_COOKED;

 fail:
    return -1;
}

void __init serial_set_rx_handler(int handle, serial_rx_fn fn)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;

    port = &com[handle & SERHND_IDX];

    spin_lock_irqsave(&port->rx_lock, flags);

    if ( port->rx != NULL )
        goto fail;

    if ( handle & SERHND_LO )
    {
        if ( port->rx_lo != NULL )
            goto fail;
        port->rx_lo = fn;        
    }
    else if ( handle & SERHND_HI )
    {
        if ( port->rx_hi != NULL )
            goto fail;
        port->rx_hi = fn;
    }
    else
    {
        if ( (port->rx_hi != NULL) || (port->rx_lo != NULL) )
            goto fail;
        port->rx = fn;
    }

    spin_unlock_irqrestore(&port->rx_lock, flags);
    return;

 fail:
    spin_unlock_irqrestore(&port->rx_lock, flags);
    printk("ERROR: Conflicting receive handlers for COM%d\n", 
           handle & SERHND_IDX);
}

void serial_force_unlock(int handle)
{
    struct serial_port *port;

    if ( handle == -1 )
        return;

    port = &com[handle & SERHND_IDX];

    spin_lock_init(&port->rx_lock);
    spin_lock_init(&port->tx_lock);

    serial_start_sync(handle);
}

void serial_start_sync(int handle)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;
    
    port = &com[handle & SERHND_IDX];

    spin_lock_irqsave(&port->tx_lock, flags);

    if ( port->sync++ == 0 )
    {
        while ( (port->txbufp - port->txbufc) != 0 )
        {
            int n;

            while ( !(n = port->driver->tx_ready(port)) )
                cpu_relax();
            if ( n < 0 )
                /* port is unavailable and might not come up until reenabled by
                   dom0, we can't really do proper sync */
                break;
            serial_start_tx(port);
            port->driver->putc(
                port, port->txbuf[mask_serial_txbuf_idx(port->txbufc++)]);
        }
        if ( port->driver->flush )
            port->driver->flush(port);
    }

    spin_unlock_irqrestore(&port->tx_lock, flags);
}

void serial_end_sync(int handle)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;
    
    port = &com[handle & SERHND_IDX];

    spin_lock_irqsave(&port->tx_lock, flags);

    port->sync--;

    spin_unlock_irqrestore(&port->tx_lock, flags);
}

void serial_start_log_everything(int handle)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;
    
    port = &com[handle & SERHND_IDX];

    spin_lock_irqsave(&port->tx_lock, flags);
    port->tx_log_everything++;
    port->tx_quench = 0;
    spin_unlock_irqrestore(&port->tx_lock, flags);
}

void serial_end_log_everything(int handle)
{
    struct serial_port *port;
    unsigned long flags;

    if ( handle == -1 )
        return;
    
    port = &com[handle & SERHND_IDX];

    spin_lock_irqsave(&port->tx_lock, flags);
    port->tx_log_everything--;
    spin_unlock_irqrestore(&port->tx_lock, flags);
}

void __init serial_init_preirq(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].driver && com[i].driver->init_preirq )
            com[i].driver->init_preirq(&com[i]);
}

void __init serial_init_irq(void)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].driver && com[i].driver->init_irq )
            com[i].driver->init_irq(&com[i]);
}

void __init serial_init_postirq(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].state == serial_parsed )
        {
            if ( com[i].driver->init_postirq )
                com[i].driver->init_postirq(&com[i]);
            com[i].state = serial_initialized;
        }
    post_irq = 1;
}

void __init serial_endboot(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].driver && com[i].driver->endboot )
            com[i].driver->endboot(&com[i]);
}

int __init serial_irq(int idx)
{
    if ( (idx >= 0) && (idx < ARRAY_SIZE(com)) &&
         com[idx].driver && com[idx].driver->irq )
        return com[idx].driver->irq(&com[idx]);

    return -1;
}

const struct vuart_info *serial_vuart_info(int idx)
{
    if ( (idx >= 0) && (idx < ARRAY_SIZE(com)) &&
         com[idx].driver && com[idx].driver->vuart_info )
        return com[idx].driver->vuart_info(&com[idx]);

    return NULL;
}

void serial_suspend(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].state == serial_initialized && com[i].driver->suspend )
            com[i].driver->suspend(&com[i]);
}

void serial_resume(void)
{
    int i;
    for ( i = 0; i < ARRAY_SIZE(com); i++ )
        if ( com[i].state == serial_initialized && com[i].driver->resume )
            com[i].driver->resume(&com[i]);
}

void __init serial_register_uart(int idx, struct uart_driver *driver,
                                 void *uart)
{
    /* Store UART-specific info. */
    com[idx].driver = driver;
    com[idx].uart   = uart;
}

void __init serial_async_transmit(struct serial_port *port)
{
    BUG_ON(!port->driver->tx_ready);
    if ( port->txbuf != NULL )
        return;
    if ( serial_txbufsz < PAGE_SIZE )
        serial_txbufsz = PAGE_SIZE;
    while ( serial_txbufsz & (serial_txbufsz - 1) )
        serial_txbufsz &= serial_txbufsz - 1;
    port->txbuf = alloc_xenheap_pages(
        get_order_from_bytes(serial_txbufsz), 0);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
