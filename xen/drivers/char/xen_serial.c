#include <asm-i386/io.h>
#include <xeno/sched.h>    /* this has request_irq() proto for some reason */
#include <xeno/keyhandler.h> 
#include <xeno/reboot.h>
#include <xeno/irq.h>

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

#define SERIAL_BASE 0x3f8  /* XXX SMH: horrible hardwired COM1   */

static int serial_echo = 0;   /* default is not to echo; change with 'e' */


void toggle_echo(u_char key, void *dev_id, struct pt_regs *regs) 
{
    serial_echo = !serial_echo; 
}

static void serial_rx_int(int irq, void *dev_id, struct pt_regs *regs)
{
    u_char c; 
    key_handler *handler; 

    while ( (inb(SERIAL_BASE + NS16550_LSR) & 1) == 1 )
    {
        c = inb(SERIAL_BASE + NS16550_RBR);

        if( (handler = get_key_handler(c)) != NULL ) 
            (*handler)(c, dev_id, regs); 

        if ( serial_echo ) 
            printk("%c", c);
    } 
}

void initialize_serial() 
{
    int fifo, rc; 
    
    /* setup key handler */
    add_key_handler('~', toggle_echo, "toggle serial echo");
    
    /* This assumes we have a 16550. It's pretty darned likely really! */
    /* Clear FIFOs, enable, trigger at 1 byte */
    outb(NS16550_FCR_TRG1 | NS16550_FCR_ENABLE |
         NS16550_FCR_CLRX  | NS16550_FCR_CLTX, 
         SERIAL_BASE+NS16550_FCR);

    /* Enable receive interrupts. Also remember to keep DTR/RTS asserted. */
    outb(NS16550_MCR_OUT2|NS16550_MCR_DTR|NS16550_MCR_RTS, 
         SERIAL_BASE + NS16550_MCR);
    outb(NS16550_IER_ERDAI, 
         SERIAL_BASE + NS16550_IER );

    if((rc = request_irq(4, serial_rx_int, SA_NOPROFILE, "serial", 0)))
	printk("initialize_serial: failed to get IRQ4, rc=%d\n", rc); 
}
