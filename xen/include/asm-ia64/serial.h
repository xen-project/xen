#ifndef __ASM_SERIAL_H__
#define __ASM_SERIAL_H__

#include <asm/regs.h>
#include <asm/irq.h>
#include <xen/serial.h>
#include <asm/hpsim_ssc.h>

#if 1
#define arch_serial_putc(_uart, _c)					\
	( platform_is_hp_ski() ? (ia64_ssc(c,0,0,0,SSC_PUTCHAR), 1) :	\
	( longs_peak_putc(c), 1 ))
#else
#define arch_serial_putc(_uart, _c)					\
	( platform_is_hp_ski() ? (ia64_ssc(c,0,0,0,SSC_PUTCHAR), 1) :	\
	( (inb((_uart)->io_base + LSR) & LSR_THRE) ?    		\
	(outb((_c), (_uart)->io_base + THR), 1) : 0 ))
#endif


#define OPT_COM1_STR "115200"
#define OPT_COM2_STR ""

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

#define UART_ENABLED(_u) ((_u)->baud != 0)
#define DISABLE_UART(_u) ((_u)->baud = 0)

/* 'Serial handles' are comprise the following fields. */
#define SERHND_IDX      (1<<0) /* COM1 or COM2?                           */

unsigned char irq_serial_getc(int handle);

void serial_force_unlock(int handle);

#endif /* __ASM_SERIAL_H__ */
