#include <asm-i386/io.h>
#include <asm-i386/irq.h>
#include <xeno/sched.h>    /* this has request_irq() proto for some reason */
#include <xeno/keyhandler.h>  
#include <hypervisor-ifs/kbd.h>
#include <xeno/event.h>

/* Hash-defines torn from <linux/pc_keyb.h> and <asm/keyboard.h> */

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

#define KEYBOARD_IRQ 1
#define kbd_write_output(val) outb(val, KBD_DATA_REG)
#define kbd_write_command(val) outb(val, KBD_CNTL_REG)

#define AUX_IRQ 12


/* THIS SECTION DEALS WITH CONFIG_XEN_ATTENTION_KEY */

// always set for now.  potentially moved to config.in later.
#define CONFIG_XEN_ATTENTION_KEY

#ifdef CONFIG_XEN_ATTENTION_KEY

static int xen_attention_key_down = 0;
#define XEN_ATTENTION_KEY 0x46 // scroll lock
#define KBD_SCANCODE_KEYUP_MASK 0x80

#undef KBD_DEBUG

/* naive scancode -> key mappings for internal xen use */

static unsigned char keymap_normal[] =
{
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
   0 , 0 ,'1','2', '3','4','5','6',    '7','8','9','0', '-','=','\b','\t',
   17, 23, 5 , 18,  20, 25, 21, 9 ,     15, 16,'[',']','\r', 0 , 1 , 19,
   4 , 6 , 7 , 8 ,  10, 11, 12,';',   '\'','`', 0 ,'#', 26, 24, 3 , 22,
   2 , 14, 13,',', '.','/', 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,

   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 ,'\\', 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,
   0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 ,     0 , 0 , 0 , 0 ,  0 , 0 , 0 , 0 
};


static int keyboard_shift = 0;
static int keyboard_control = 0;
static int keyboard_echo = 0;

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
        // dont process key-down events
        if(!(scancode & KBD_SCANCODE_KEYUP_MASK)) break; 

	scancode = scancode & (~KBD_SCANCODE_KEYUP_MASK); 
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

#endif /* CONFIG_XEN_ATTENTION_KEY */


/* THIS SECTION DEALS WITH STORING A RING OF PENDING EVENTS */

// store kbd events waiting to be processed by guest os
#define KBD_RING_SIZE        64 
static int kbd_ring[KBD_RING_SIZE]; 
static int kbd_ring_prod = 0;
static int kbd_ring_cons = 0;

#define KBD_RING_INC(_i)     (((_i)+1) & (KBD_RING_SIZE-1))
#define KBD_RING_FULL (KBD_RING_INC(kbd_ring_prod)  == kbd_ring_cons)
#define KBD_RING_EMPTY (kbd_ring_prod == kbd_ring_cons)

// these assume locking has already been taken care of
static void kbd_ring_push(unsigned char status, unsigned char scancode) {
  if(KBD_RING_FULL) return;
  kbd_ring[kbd_ring_prod] = KBD_CODE(scancode, status);
  kbd_ring_prod = KBD_RING_INC(kbd_ring_prod);
}

static int kbd_ring_pop() {
  int ret;
  if(KBD_RING_EMPTY) {
    // read directly from controller - no events waiting in ring
    unsigned char status = kbd_read_status();
    unsigned char scancode = kbd_read_input(); 
    return KBD_CODE(scancode, status);
  }
  ret = kbd_ring[kbd_ring_cons];
  kbd_ring_cons = KBD_RING_INC(kbd_ring_cons);
  return ret;
}


/* THIS SECTION DEALS WITH COMMUNICATING PS2 EVENTS/CMDS WITH GUEST OS */

// ownership of keyboard - current defaulting to dom0
#define KBD_ISOWNER(p) (p->domain == 0) 
#define KBD_OWNER find_domain_by_id(0) 

// need lock as there may be _two_ interrupts at play, keyboard and mouse, as well as guest os actions
static spinlock_t kbd_lock;


long do_kbd_op(unsigned char op, unsigned char val)
{
  // check for domain 0
#ifdef KBD_DEBUG
  printk("do_kbd_op: op %2x, val %2x, prod %d, cons %d\n", op, val, kbd_ring_prod, kbd_ring_cons); 
#endif

  if ( !KBD_ISOWNER(current) ) return -EPERM;  

  switch(op) {
  case KBD_OP_WRITEOUTPUT:
    kbd_write_output(val);
    return 0L;
  case KBD_OP_WRITECOMMAND:
    kbd_write_command(val);
    return 0L;
  case KBD_OP_READ: {
    unsigned long flags;
    unsigned long ret;
    spin_lock_irqsave(&kbd_lock, flags);
    ret = kbd_ring_pop();
    spin_unlock_irqrestore(&kbd_lock, flags);
    return ret;
  }
  }

  return -EINVAL;
}


static void keyboard_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
  unsigned char status;
  unsigned int work = 1000;
  unsigned long cpu_mask;
  unsigned long flags;
  spin_lock_irqsave(&kbd_lock, flags);
  status = kbd_read_status();
#ifdef KBD_DEBUG
    printk("keyboard_interrupt irq %d, status 0x%2x\n", irq, status);
#endif
    while ((--work > 0) && (status & KBD_STAT_OBF))
    {      
      unsigned char scancode;
      scancode = kbd_read_input();
      //printk("scancode 0x%2x\n", scancode);
      
#ifdef CONFIG_XEN_ATTENTION_KEY
      if(!(status & (KBD_STAT_GTO | KBD_STAT_PERR | KBD_STAT_MOUSE_OBF))) {
	if ((scancode & (~KBD_SCANCODE_KEYUP_MASK)) == XEN_ATTENTION_KEY) {
	  xen_attention_key_down = !(scancode & KBD_SCANCODE_KEYUP_MASK);
	  //printk("xen_attention_key_down %d\n", xen_attention_key_down);
	} else if (xen_attention_key_down) {
	  key_handler *handler; 
	  unsigned char key = convert_scancode(scancode); 
	  if(key && (handler = get_key_handler(key))) 
	    (*handler)(key, dev_id, regs); 
	  
	  status = kbd_read_status();
	  continue; // do not send key to guest os
	}
      }
#endif
      
      if (!(status & (KBD_STAT_GTO | KBD_STAT_PERR))) {
	kbd_ring_push(status, scancode);

	cpu_mask = mark_guest_event(KBD_OWNER, _EVENT_KBD);
        guest_event_notify(cpu_mask);

	status = kbd_read_status();
	scancode = kbd_read_input();
      }
    }
    
    if (!work)
      printk(KERN_ERR "xen_keyb: controller jammed (0x%02X).\n", status);

    spin_unlock_irqrestore(&kbd_lock, flags);
}
    
    

void initialize_keyboard()
{
  spin_lock_init(&kbd_lock);

  if(request_irq(KEYBOARD_IRQ, keyboard_interrupt, SA_NOPROFILE, "keyboard", NULL)) {
    printk("initialize_keyboard: failed to alloc IRQ %d\n", KEYBOARD_IRQ); 
    return;
  }

  if(request_irq(AUX_IRQ, keyboard_interrupt, SA_NOPROFILE, "PS/2 Mouse", NULL)) {
    printk("initialize_keyboard: failed to alloc IRQ %d\n", AUX_IRQ); 
    return;
  }

#ifdef KBD_DEBUG
  printk("PS/2 keyboard and mouse interface ok");
#endif
}

