/******************************************************************************
 * serial.h
 * 
 * Driver for 16550-series UARTs. This driver is to be kept within Xen as
 * it permits debugging of seriously-toasted machines (e.g., in situations
 * where a device driver within a guest OS would be inaccessible).
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#ifndef __XEN_SERIAL_H__
#define __XEN_SERIAL_H__

#include <xen/irq.h>
#include <asm/regs.h>
#include <asm/serial.h>

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

/* Register a character-receive hook on the specified COM port. */
typedef void (*serial_rx_fn)(unsigned char, struct cpu_user_regs *);
void serial_set_rx_handler(int handle, serial_rx_fn fn);

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

/* 'Serial handles' are comprise the following fields. */
#define SERHND_IDX      (1<<0) /* COM1 or COM2?                           */
#define SERHND_HI       (1<<1) /* Mux/demux each transferred char by MSB. */
#define SERHND_LO       (1<<2) /* Ditto, except that the MSB is cleared.  */
#define SERHND_COOKED   (1<<3) /* Newline/carriage-return translation?    */

/* Two-stage initialisation (before/after IRQ-subsystem initialisation). */
void serial_init_stage1(void);
void serial_init_stage2(void);

/* Takes a config string and creates a numeric handle on the COM port. */
int parse_serial_handle(char *conf);

/* Transmit a single character via the specified COM port. */
void serial_putc(int handle, unsigned char c);

/* Transmit a NULL-terminated string via the specified COM port. */
void serial_puts(int handle, const char *s);

/*
 * An alternative to registering a character-receive hook. This function
 * will not return until a character is available. It can safely be
 * called with interrupts disabled.
 */
unsigned char serial_getc(int handle);
/* 
 * Same as serial_getc but can also be called from interrupt handlers.
 */
unsigned char irq_serial_getc(int handle);

void serial_force_unlock(int handle);

void serial_endboot(void);

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
