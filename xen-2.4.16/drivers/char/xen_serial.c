#include <asm-i386/io.h>
#include <xeno/sched.h>    /* this has request_irq() proto for some reason */


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



/* 
** We keep an array of 'handlers' for each key code between 0 and 255; 
** this is intended to allow very simple debugging routines (toggle 
** debug flag, dump registers, reboot, etc) to be hooked in in a slightly
** nicer fashion than just editing this file :-) 
*/

#define KEY_MAX 256
typedef void key_handler(u_char key); 

static key_handler *key_table[KEY_MAX]; 
    
void add_key_handler(u_char key, key_handler *handler) 
{
    if(key_table[key] != NULL) 
	printk("Warning: overwriting handler for key 0x%x\n", key); 

    key_table[key] = handler; 
    return; 
}



static int serial_echo = 0;   /* default is not to echo; change with 'e' */

void toggle_echo(u_char key) 
{
    serial_echo = !serial_echo; 
    return; 
}


void halt_machine(u_char key) 
{
    /* This is 'debug me please' => just dump info and halt machine */
    printk("serial_rx_int: got EOT => halting machine.\n"); 
    printk("<not actually halting for now>\n"); 
    return; 
}



static void serial_rx_int(int irq, void *dev_id, struct pt_regs *regs)
{
    u_char c; 

    /* XXX SMH: should probably check this is an RX interrupt :-) */

    /* clear the interrupt by reading the character */
    c = inb(SERIAL_BASE + NS16550_RBR );

    /* if there's a handler, call it: we trust it won't screw us too badly */
    if(key_table[c]) 
	(*key_table[c])(c); 

    if(serial_echo) 
	printk("%c", c); 

    return; 
}


void initialize_serial() 
{
    int i, fifo, rc; 

    /* first initialize key handler table */
    for(i = 0; i < KEY_MAX; i++) 
	key_table[i] = (key_handler *)NULL; 

    /* setup own handlers */
    add_key_handler(0x01, toggle_echo);    /* <esc> to toggle echo */
    add_key_handler(0x04, halt_machine);   /* CTRL-D to 'halt' */

    
    /* Should detect this, but must be a ns16550a at least, surely? */
    fifo = 1;  
    if(fifo) {
	/* Clear FIFOs, enable, trigger at 1 byte */
	outb(NS16550_FCR_TRG1 | NS16550_FCR_ENABLE |
	     NS16550_FCR_CLRX  | NS16550_FCR_CLTX, SERIAL_BASE+NS16550_FCR);
    }

    outb(NS16550_MCR_OUT2, SERIAL_BASE + NS16550_MCR);   /* Modem control */
    outb(NS16550_IER_ERDAI, SERIAL_BASE + NS16550_IER ); /* Setup interrupts */

    /* XXX SMH: this is a hack; probably is IRQ4 but grab both anyway */
    if((rc = request_irq(4, serial_rx_int, 0, "serial", (void *)0x1234)))
	printk("initialize_serial: failed to get IRQ4, rc=%d\n", rc); 

    if((rc = request_irq(3, serial_rx_int, 0, "serial", (void *)0x1234)))
	printk("initialize_serial: failed to get IRQ3, rc=%d\n", rc); 
    
    return; 
}
