/******************************************************************************
 * serial.h
 * 
 * Framework for serial device drivers.
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#ifndef __XEN_SERIAL_H__
#define __XEN_SERIAL_H__

struct cpu_user_regs;

/* Register a character-receive hook on the specified COM port. */
typedef void (*serial_rx_fn)(char, struct cpu_user_regs *);
void serial_set_rx_handler(int handle, serial_rx_fn fn);

/* Number of characters we buffer for a polling receiver. */
#define RXBUFSZ 32
#define MASK_RXBUF_IDX(_i) ((_i)&(RXBUFSZ-1))

struct uart_driver;

struct serial_port {
    /* Uart-driver parameters. */
    struct uart_driver *driver;
    void               *uart;
    /* Receiver callback functions (asynchronous receivers). */
    serial_rx_fn        rx_lo, rx_hi, rx;
    /* Receive data buffer (polling receivers). */
    char                rxbuf[RXBUFSZ];
    unsigned int        rxbufp, rxbufc;
    /* Serial I/O is concurrency-safe. */
    spinlock_t          lock;
};

struct uart_driver {
    /* Driver initialisation (pre- and post-IRQ subsystem setup). */
    void (*init_preirq)(struct serial_port *);
    void (*init_postirq)(struct serial_port *);
    /* Hook to clean up after Xen bootstrap (before domain 0 runs). */
    void (*endboot)(struct serial_port *);
    /* Put a char onto the serial line. */
    void (*putc)(struct serial_port *, char);
    /* Get a char from the serial line: returns FALSE if no char available. */
    int  (*getc)(struct serial_port *, char *);
};

/* 'Serial handles' are composed from the following fields. */
#define SERHND_IDX      (1<<0) /* COM1 or COM2?                           */
#define SERHND_HI       (1<<1) /* Mux/demux each transferred char by MSB. */
#define SERHND_LO       (1<<2) /* Ditto, except that the MSB is cleared.  */
#define SERHND_COOKED   (1<<3) /* Newline/carriage-return translation?    */

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
void serial_force_unlock(int handle);

/* Register a uart on serial port @idx (e.g., @idx==0 is COM1). */
void serial_register_uart(int idx, struct uart_driver *driver, void *uart);

/* Driver helper function: process receive work in interrupt context. */
void serial_rx_interrupt(struct serial_port *port, struct cpu_user_regs *regs);

/*
 * Initialisers for individual uart drivers.
 */
void ns16550_init(void);

#endif /* __XEN_SERIAL_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
