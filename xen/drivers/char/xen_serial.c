#include <asm-i386/io.h>
#include <xeno/sched.h>    /* this has request_irq() proto for some reason */
#include <xeno/keyhandler.h> 
#include <xeno/reboot.h>
#include <xeno/irq.h>
#include <asm/pdb.h>

/* Register offsets */
#define NS16550_RBR	0x00	/* receive buffer	*/
#define NS16550_THR	0x00	/* transmit holding	*/
#define NS16550_IER	0x01	/* interrupt enable	*/
#define NS16550_IIR	0x02	/* interrupt identity	*/
#define NS16550_FCR     0x02    /* FIFO control         */
#define NS16550_LCR	0x03	/* line control		*/
#define NS16550_MCR	0x04	/* MODEM control	*/
#define NS16550_LSR	0x05	/* line status		*/
#define NS16550_MSR	0x06	/* MODEM status		*/
#define NS16550_SCR	0x07	/* scratch		*/
#define NS16550_DDL	0x00	/* divisor latch (ls) ( DLAB=1)	*/
#define NS16550_DLM	0x01	/* divisor latch (ms) ( DLAB=1)	*/

/* Interrupt enable register */
#define NS16550_IER_ERDAI	0x01	/* rx data recv'd	*/
#define NS16550_IER_ETHREI	0x02	/* tx reg. empty	*/
#define NS16550_IER_ELSI	0x04	/* rx line status	*/
#define NS16550_IER_EMSI	0x08	/* MODEM status		*/

/* FIFO control register */
#define NS16550_FCR_ENABLE      0x01    /* enable FIFO          */
#define NS16550_FCR_CLRX        0x02    /* clear Rx FIFO        */
#define NS16550_FCR_CLTX        0x04    /* clear Tx FIFO        */
#define NS16550_FCR_DMA         0x10    /* enter DMA mode       */
#define NS16550_FCR_TRG1        0x00    /* Rx FIFO trig lev 1   */
#define NS16550_FCR_TRG4        0x40    /* Rx FIFO trig lev 4   */
#define NS16550_FCR_TRG8        0x80    /* Rx FIFO trig lev 8   */
#define NS16550_FCR_TRG14       0xc0    /* Rx FIFO trig lev 14  */

/* MODEM control register */
#define NS16550_MCR_DTR 	0x01	/* Data Terminal Ready	*/
#define NS16550_MCR_RTS 	0x02	/* Request to Send	*/
#define NS16550_MCR_OUT1        0x04    /* OUT1: unused         */
#define NS16550_MCR_OUT2        0x08    /* OUT2: interrupt mask */
#define NS16550_MCR_LOOP	0x10	/* Loop			*/

#define LSR_DR   0x01  /* Data ready */
#define LSR_OE   0x02  /* Overrun */
#define LSR_PE   0x04  /* Parity error */
#define LSR_FE   0x08  /* Framing error */
#define LSR_BI   0x10  /* Break */
#define LSR_THRE 0x20  /* Xmit holding register empty */
#define LSR_TEMT 0x40  /* Xmitter empty */
#define LSR_ERR  0x80  /* Error */

#define SERIAL_COM1 0x3f8
#define SERIAL_COM2 0x2f8

int serial_com_base = SERIAL_COM1;
int debug_com_base  = SERIAL_COM1;


static int serial_echo = 0;       /* default is not to echo; change with '~' */

void toggle_echo(u_char key, void *dev_id, struct pt_regs *regs) 
{
    serial_echo = !serial_echo; 
}

void debug_set_com_port(int port)
{
    debug_com_base = port == 1 ? SERIAL_COM1 : SERIAL_COM2;
}

int debug_testchar()                                /* character available? */
{
    return (inb(debug_com_base + NS16550_LSR) & LSR_DR);
}

u_char debug_getchar()
{
    while (! (inb(debug_com_base + NS16550_LSR) & LSR_DR));/* wait for char */
    return inb(debug_com_base + NS16550_RBR);
}

void debug_putch(u_char c)
{
    while (! (inb(debug_com_base + NS16550_LSR) & LSR_THRE));
                                                            /* wait for idle */
    outb(c, debug_com_base + NS16550_RBR);
}

void debug_putchar(u_char c)
{
    debug_putch(c);
    if (c == '\n') debug_putch('\r');
}



int serial_testchar()                                /* character available? */
{
    return (inb(serial_com_base + NS16550_LSR) & LSR_DR);
}

u_char serial_getchar()
{
    while (! (inb(serial_com_base + NS16550_LSR) & LSR_DR));/* wait for char */
    return inb(serial_com_base + NS16550_RBR);
}

void serial_putch(u_char c)
{
    while (! (inb(serial_com_base + NS16550_LSR) & LSR_THRE));
                                                            /* wait for idle */
    outb(c, serial_com_base + NS16550_RBR);
}

void serial_putchar(u_char c)
{
    serial_putch(c);
    if ( c == '\n' )
        serial_putch('\r');
}

static spinlock_t serial_lock;

static void serial_rx_int(int irq, void *dev_id, struct pt_regs *regs)
{
    u_char c; 
    key_handler *handler; 
    unsigned long flags;

    spin_lock_irqsave(&serial_lock, flags);

    while ( serial_testchar() )
    {
        c = serial_getchar();

	if ( c & 0x80 )
	{
	    pdb_serial_input(c & 0x7f, regs);
	}
	else
	{
	    if ( (handler = get_key_handler(c)) != NULL ) 
  	        (*handler)(c, dev_id, regs); 

	    if ( serial_echo ) 
	        serial_putch(c);
	}
    }

    spin_unlock_irqrestore(&serial_lock, flags);
}

void initialize_serial() 
{
    int rc; 

    if ( !SERIAL_ENABLED )
        return;

    spin_lock_init(&serial_lock);
    
    /* setup key handler */
    add_key_handler('~', toggle_echo, "toggle serial echo");
    
    /* This assumes we have a 16550. It's pretty darned likely really! */
    /* Clear FIFOs, enable, trigger at 1 byte */
    outb(NS16550_FCR_TRG1 | NS16550_FCR_ENABLE |
         NS16550_FCR_CLRX  | NS16550_FCR_CLTX, 
         serial_com_base + NS16550_FCR);

    /* Enable receive interrupts. Also remember to keep DTR/RTS asserted. */
    outb(NS16550_MCR_OUT2|NS16550_MCR_DTR|NS16550_MCR_RTS, 
         serial_com_base + NS16550_MCR);
    outb(NS16550_IER_ERDAI, 
         serial_com_base + NS16550_IER );

    if( (rc = request_irq(4, serial_rx_int, SA_NOPROFILE, "serial", 0)) )
	printk("initialize_serial: failed to get IRQ4, rc=%d\n", rc); 
}
