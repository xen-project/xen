#include <asm-i386/io.h>
#include <asm-i386/irq.h>
#include <xeno/sched.h>    /* this has request_irq() proto for some reason */
#include <xeno/keyhandler.h>  

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


static int keyboard_shift = 0;
static int keyboard_control = 0;
static int keyboard_echo = 0;

/* the following is pretty gross... 
 * stop reading if you don't want to throw up!
 */

static unsigned char keymap_normal[] =
{
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 ,'1','2', '3','4','5','6',    '7','8','9','0', '-','=','\b','\t',
  'q','w','e','r', 't','y','u','i',    'o','p','[',']','\r', 0 ,'a','s',
  'd','f','g','h', 'j','k','l',';',   '\'','`', 0 ,'#', 'z','x','c','v',
  'b','n','m',',', '.','/', 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 ,'\\', 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 
};

static unsigned char keymap_shift[] =
{
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 ,'!','"', '#','$','%','^',    '&','*','(',')', '_','+','\b','\t',
  'Q','W','E','R', 'T','Y','U','I',    'O','P','{','}','\r', 0 ,'A','S',
  'D','F','G','H', 'J','K','L',':',    '@', 0 , 0 ,'~', 'Z','X','C','V',
  'B','N','M','<', '>','?', 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 ,'|', 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 
};


static unsigned char keymap_control[] =
{ /* same as normal, except for a-z -> 1 to 26 */
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 ,'1','2', '3','4','5','6',    '7','8','9','0', '-','=','\b','\t',
   17, 23, 5 , 18,  20, 25, 21, 9 ,     15, 16,'[',']','\r', 0 , 1 , 19,
   4 , 6 , 7 , 8 ,  10, 11, 12,';',   '\'','`', 0 ,'#', 26, 24, 3 , 22,
   2 , 14, 13,',', '.','/', 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 ,'\\', 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 
};


static unsigned char convert_scancode (unsigned char scancode)
{
    unsigned char value = 0;

    switch (scancode) {

    case 0xbb: /* F1 */
	keyboard_echo = !keyboard_echo;
	break;

    case 0xba: /* caps lock UP */
    case 0x9d: /* ctrl (left) UP */
	keyboard_control = 0;
	break;

    case 0x3a: /* caps lock DOWN */
    case 0x1d: /* ctrl (left) DOWN */
	keyboard_control = 1;
	break;

    case 0xaa: /* shift (left) UP */
    case 0xb6: /* shift (right) UP */
	keyboard_shift = 0;
	break;

    case 0x2a: /* shift (left) DOWN */
    case 0x36: /* shift (right) DOWN */
	keyboard_shift = 1;
	break;

    default:   /* normal keys */
	if (keyboard_control)
	    value = keymap_control[scancode];
	else if (keyboard_shift)
	    value = keymap_shift[scancode];
	else
	    value = keymap_normal[scancode];

    }

    if (value && keyboard_echo) printk ("%c", value);

    return value;
}

static void keyboard_interrupt(int irq, void *dev_id, struct pt_regs *regs)
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
	    else {
		unsigned char key; 
		key_handler *handler; 
		
		if((key = convert_scancode (scancode)) && 
		   (handler = get_key_handler(key))) 
		    (*handler)(key, dev_id, regs); 
		
	    }
	}
	status = kbd_read_status();
    }
    
    if (!work)
	printk(KERN_ERR "pc_keyb: controller jammed (0x%02X).\n", status);
    
    return;
}


void initialize_keyboard()
{
    if(request_irq(KEYBOARD_IRQ, keyboard_interrupt, SA_NOPROFILE, "keyboard", NULL))
	printk("initialize_keyboard: failed to alloc IRQ %d\n", KEYBOARD_IRQ); 

    return; 
}

