#include <asm-i386/io.h>

#define KEYBOARD_IRQ 1

#define KBD_STATUS_REG	     0x64 /* Status register (R) */
#define KBD_CNTL_REG	     0x64 /* Controller command register (W) */
#define KBD_DATA_REG	     0x60 /* Keyboard data register (R/W) */

/* register status bits */
#define KBD_STAT_OBF 	     0x01 /* Keyboard output buffer full */
#define KBD_STAT_IBF 	     0x02 /* Keyboard input buffer full */
#define KBD_STAT_SELFTEST    0x04 /* Self test successful */
#define KBD_STAT_CMD	     0x08 /* Last write was a command write (0=data) */

#define KBD_STAT_UNLOCKED    0x10 /* Zero if keyboard locked */
#define KBD_STAT_MOUSE_OBF   0x20 /* Mouse output buffer full */
#define KBD_STAT_GTO 	     0x40 /* General receive/xmit timeout */
#define KBD_STAT_PERR 	     0x80 /* Parity error */

#define kbd_read_input() inb(KBD_DATA_REG)
#define kbd_read_status() inb(KBD_STATUS_REG)


static void
dispatch_scancode (unsigned char scancode)
{
    /*
     * we could be a bit more clever here, but why?
     * just add a jump to your debug routine for the appropriate character.
     */
    switch (scancode)
    {
    case 0x01 :                                                       /* esc */
	printk ("<esc>");
	break;
    case 0x9e :                                                         /* a */
	printk ("a");
	break;
    case 0x9f :                                                         /* s */
	printk ("s");
	break;
    case 0xae :                                                         /* c */
	printk ("c");
	break;
    case 0xb0 :                                                         /* b */
	printk ("b");
	break;
    case 0xbb :                                                        /* f1 */
	printk ("<f1>");
	break;
    case 0xbc :                                                        /* f2 */
	printk ("<f2>");
	break;
    case 0xbd :                                                        /* f3 */
	printk ("<f3>");
	break;
    case 0xbe :                                                        /* f4 */
	printk ("<f4>");
	break;
    case 0xbf :                                                        /* f5 */
	/* xen_block_dump_state(); */
	break;
    default :
	/* printk ("%x ", scancode); */
    }

    return; 
}


/* regs should be struct pt_regs */

static void keyboard_interrupt(int irq, void *dev_id, void *regs)
{
    unsigned char status = kbd_read_status();
    unsigned int work = 10000;
    
    while ((--work > 0) && (status & KBD_STAT_OBF))
    {
	unsigned char scancode;
	
	scancode = kbd_read_input();
	
	if (!(status & (KBD_STAT_GTO | KBD_STAT_PERR)))
	{
	    if (status & KBD_STAT_MOUSE_OBF)
		/* mouse event, ignore */;
	    else
		dispatch_scancode (scancode);
	}
	status = kbd_read_status();
    }
    
    if (!work)
	printk(KERN_ERR "pc_keyb: controller jammed (0x%02X).\n", status);
    
    return;
}


extern int request_irq(unsigned int, 
		       void (*handler)(int, void *, struct pt_regs *),
		       unsigned long, const char *, void *);


void initialize_keyboard()
{
    if(!request_irq(KEYBOARD_IRQ, keyboard_interrupt, 0, "keyboard", NULL))
	printk("initialize_keyboard: failed to alloc IRQ %d\n", KEYBOARD_IRQ); 

    return; 
}

