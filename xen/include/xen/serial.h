/******************************************************************************
 * serial.h
 * 
 * Framework for serial device drivers.
 * 
 * Copyright (c) 2003-2008, K A Fraser
 */

#ifndef __XEN_SERIAL_H__
#define __XEN_SERIAL_H__

#include <xen/init.h>
#include <xen/spinlock.h>

struct cpu_user_regs;

/* Register a character-receive hook on the specified COM port. */
typedef void (*serial_rx_fn)(char, struct cpu_user_regs *);
void serial_set_rx_handler(int handle, serial_rx_fn fn);

/* Number of characters we buffer for a polling receiver. */
#define serial_rxbufsz 32

/* Number of characters we buffer for an interrupt-driven transmitter. */
extern unsigned int serial_txbufsz;

struct uart_driver;

enum serial_port_state {
    serial_unused,
    serial_parsed,
    serial_initialized
};

struct vuart_info {
    paddr_t base_addr;          /* Base address of the UART */
    unsigned long size;         /* Size of the memory region */
    unsigned long data_off;     /* Data register offset */
    unsigned long status_off;   /* Status register offset */
    unsigned long status;       /* Ready status value */
};

struct serial_port {
    /* Uart-driver parameters. */
    struct uart_driver *driver;
    void               *uart;
    enum serial_port_state state;
    /* Transmit data buffer (interrupt-driven uart). */
    char               *txbuf;
    unsigned int        txbufp, txbufc;
    bool_t              tx_quench;
    int                 tx_log_everything;
    /* Force synchronous transmit. */
    int                 sync;
    /* Receiver callback functions (asynchronous receivers). */
    serial_rx_fn        rx_lo, rx_hi, rx;
    /* Receive data buffer (polling receivers). */
    char                rxbuf[serial_rxbufsz];
    unsigned int        rxbufp, rxbufc;
    /* Serial I/O is concurrency-safe. */
    spinlock_t          rx_lock, tx_lock;
};

struct uart_driver {
    /* Driver initialisation (pre- and post-IRQ subsystem setup). */
    void (*init_preirq)(struct serial_port *);
    void (*init_postirq)(struct serial_port *);
    /* Hook to clean up after Xen bootstrap (before domain 0 runs). */
    void (*endboot)(struct serial_port *);
    /* Driver suspend/resume. */
    void (*suspend)(struct serial_port *);
    void (*resume)(struct serial_port *);
    /* Return number of characters the port can hold for transmit,
     * or -EIO if port is inaccesible */
    int (*tx_ready)(struct serial_port *);
    /* Put a character onto the serial line. */
    void (*putc)(struct serial_port *, char);
    /* Flush accumulated characters. */
    void (*flush)(struct serial_port *);
    /* Get a character from the serial line: returns 0 if none available. */
    int  (*getc)(struct serial_port *, char *);
    /* Get IRQ number for this port's serial line: returns -1 if none. */
    int  (*irq)(struct serial_port *);
    /* Unmask TX interrupt */
    void  (*start_tx)(struct serial_port *);
    /* Mask TX interrupt */
    void  (*stop_tx)(struct serial_port *);
    /* Get serial information */
    const struct vuart_info *(*vuart_info)(struct serial_port *);
};

/* 'Serial handles' are composed from the following fields. */
#define SERHND_IDX      (3<<0) /* COM1, COM2, DBGP, DTUART?               */
# define SERHND_COM1    (0<<0)
# define SERHND_COM2    (1<<0)
# define SERHND_DBGP    (2<<0)
# define SERHND_DTUART  (0<<0) /* Steal SERHND_COM1 value */
#define SERHND_HI       (1<<2) /* Mux/demux each transferred char by MSB. */
#define SERHND_LO       (1<<3) /* Ditto, except that the MSB is cleared.  */
#define SERHND_COOKED   (1<<4) /* Newline/carriage-return translation?    */

/* Two-stage initialisation (before/after IRQ-subsystem initialisation). */
void serial_init_preirq(void);
void serial_init_postirq(void);

/* Clean-up hook before domain 0 runs. */
void serial_endboot(void);

/* Takes a config string and creates a numeric handle on the COM port. */
int serial_parse_handle(char *conf);

/* Transmit a single character via the specified COM port. */
void serial_putc(int handle, char c);

/* Transmit a NULL-terminated string via the specified COM port. */
void serial_puts(int handle, const char *s);

/*
 * An alternative to registering a character-receive hook. This function
 * will not return until a character is available. It can safely be
 * called with interrupts disabled.
 */
char serial_getc(int handle);

/* Forcibly prevent serial lockup when the system is in a bad way. */
/* (NB. This also forces an implicit serial_start_sync()). */
void serial_force_unlock(int handle);

/* Start/end a synchronous region (temporarily disable interrupt-driven tx). */
void serial_start_sync(int handle);
void serial_end_sync(int handle);

/* Start/end a region where we will wait rather than drop characters. */
void serial_start_log_everything(int handle);
void serial_end_log_everything(int handle);

/* Return irq number for specified serial port (identified by index). */
int serial_irq(int idx);

/* Retrieve basic UART information to emulate it (base address, size...) */
const struct vuart_info* serial_vuart_info(int idx);

/* Serial suspend/resume. */
void serial_suspend(void);
void serial_resume(void);

/*
 * Initialisation and helper functions for uart drivers.
 */
/* Register a uart on serial port @idx (e.g., @idx==0 is COM1). */
void serial_register_uart(int idx, struct uart_driver *driver, void *uart);
/* Place the serial port into asynchronous transmit mode. */
void serial_async_transmit(struct serial_port *port);
/* Process work in interrupt context. */
void serial_rx_interrupt(struct serial_port *port, struct cpu_user_regs *regs);
void serial_tx_interrupt(struct serial_port *port, struct cpu_user_regs *regs);

/*
 * Initialisers for individual uart drivers.
 */
/* NB. Any default value can be 0 if it is unknown and must be specified. */
struct ns16550_defaults {
    int baud;      /* default baud rate; BAUD_AUTO == pre-configured */
    int data_bits; /* default data bits (5, 6, 7 or 8) */
    int parity;    /* default parity (n, o, e, m or s) */
    int stop_bits; /* default stop bits (1 or 2) */
    int irq;       /* default irq */
    unsigned long io_base; /* default io_base address */
};
void ns16550_init(int index, struct ns16550_defaults *defaults);
void ehci_dbgp_init(void);

void arm_uart_init(void);

struct physdev_dbgp_op;
int dbgp_op(const struct physdev_dbgp_op *);

/* Baud rate was pre-configured before invoking the UART driver. */
#define BAUD_AUTO (-1)

#endif /* __XEN_SERIAL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
