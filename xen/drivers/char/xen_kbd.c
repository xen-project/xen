#include <asm-i386/io.h>
#include <asm-i386/irq.h>
#include <xeno/sched.h>
#include <xeno/keyhandler.h>  
#include <hypervisor-ifs/kbd.h>
#include <xeno/event.h>
#include <xeno/console.h>

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

#define KEYBOARD_IRQ  1
#define AUX_IRQ      12

#define kbd_write_output(val) outb(val, KBD_DATA_REG)
#define kbd_write_command(val) outb(val, KBD_CNTL_REG)

#ifdef CONFIG_XEN_ATTENTION_KEY

static int xen_attention_key_down = 0;
#define XEN_ATTENTION_KEY 0x46 /* Scroll Lock */
#define KBD_SCANCODE_KEYUP_MASK 0x80

/* Simple scancode-to-key mappings for internal Xen use. */

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


static int keyboard_shift = 0;

static unsigned char convert_scancode (unsigned char scancode)
{
    unsigned char value = 0;

    switch ( scancode ) 
    {

    case 0xaa: /* shift (left) UP */
    case 0xb6: /* shift (right) UP */
	keyboard_shift = 0;
	break;

    case 0x2a: /* shift (left) DOWN */
    case 0x36: /* shift (right) DOWN */
	keyboard_shift = 1;
	break;

    default:
        /* Only process key-up events */
        if(!(scancode & KBD_SCANCODE_KEYUP_MASK)) 
            break; 
	scancode = scancode & ~KBD_SCANCODE_KEYUP_MASK; 
	if (keyboard_shift)
	    value = keymap_shift[scancode];
	else
	    value = keymap_normal[scancode];
        break;
    }

    return value;
}

#endif /* CONFIG_XEN_ATTENTION_KEY */


/* We store kbd events awaiting receive by a guest OS in a ring buffer. */
#define KBD_RING_SIZE 64 
static int kbd_ring[KBD_RING_SIZE]; 
static int kbd_ring_prod = 0;
static int kbd_ring_cons = 0;

#define KBD_RING_INC(_i) (((_i)+1) & (KBD_RING_SIZE-1))
#define KBD_RING_FULL    (KBD_RING_INC(kbd_ring_prod) == kbd_ring_cons)
#define KBD_RING_EMPTY   (kbd_ring_prod == kbd_ring_cons)

static void kbd_ring_push(unsigned char status, unsigned char scancode)
{
    if ( KBD_RING_FULL )
        return;
    
    kbd_ring[kbd_ring_prod] = KBD_CODE(scancode, status);
    kbd_ring_prod = KBD_RING_INC(kbd_ring_prod);
}

static int kbd_ring_pop(void)
{
    int ret;

    if ( KBD_RING_EMPTY )
    {
        /* Read directly from controller - no events waiting in ring. */
        unsigned char status = kbd_read_status();
        unsigned char scancode = kbd_read_input(); 
        ret = KBD_CODE(scancode, status);
    }
    else
    {
        ret = kbd_ring[kbd_ring_cons];
        kbd_ring_cons = KBD_RING_INC(kbd_ring_cons);
    }

    return ret;
}


/*
 * NB. Lock is essential as there are two distinct interrupts (keyboard + aux).
 * Also interrupts may disturb guest OS actions.
 */
static spinlock_t kbd_lock;

long do_kbd_op(unsigned char op, unsigned char val)
{
    unsigned long flags;
    long ret = -EINVAL;

    if ( !CONSOLE_ISOWNER(current) ) 
        return -EPERM;  

    spin_lock_irqsave(&kbd_lock, flags);

    switch ( op )
    {
    case KBD_OP_WRITEOUTPUT:
        kbd_write_output(val);
        ret = 0L;
        break;
    case KBD_OP_WRITECOMMAND:
        kbd_write_command(val);
        ret = 0L;
        break;
    case KBD_OP_READ:
        ret = kbd_ring_pop();
        break;
    }

    spin_unlock_irqrestore(&kbd_lock, flags);

    return ret;
}


static void keyboard_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned char status, scancode;
    unsigned int work = 1000;
    unsigned long cpu_mask = 0, flags;
    struct task_struct *p = CONSOLE_OWNER;

    spin_lock_irqsave(&kbd_lock, flags);

    while ( (--work > 0) && ((status = kbd_read_status()) & KBD_STAT_OBF) )
    {
        scancode = kbd_read_input();
      
#ifdef CONFIG_XEN_ATTENTION_KEY
        if ( !(status & (KBD_STAT_GTO | KBD_STAT_PERR | KBD_STAT_MOUSE_OBF)) )
        {
            if ( (scancode & (~KBD_SCANCODE_KEYUP_MASK)) == XEN_ATTENTION_KEY )
            {
                xen_attention_key_down = !(scancode & KBD_SCANCODE_KEYUP_MASK);
            } 
            else if ( xen_attention_key_down )
            {
                key_handler *handler; 
                unsigned char key;
                spin_unlock_irqrestore(&kbd_lock, flags);
                key = convert_scancode(scancode); 
                if ( key && (handler = get_key_handler(key)) )
                    (*handler)(key, dev_id, regs); 
                spin_lock_irqsave(&kbd_lock, flags);
                continue;
            }
        }
#endif
      
        if ( p != NULL )
        {
            kbd_ring_push(status, scancode);
            cpu_mask |= mark_guest_event(CONSOLE_OWNER, _EVENT_KBD);
        }
    }
    
    if ( !work )
        printk(KERN_ERR "xen_keyb: controller jammed (0x%02X).\n", status);

    spin_unlock_irqrestore(&kbd_lock, flags);

    if ( p != NULL )
    {
        put_task_struct(p);
        guest_event_notify(cpu_mask);
    }    
}
    
    

void initialize_keyboard()
{
    spin_lock_init(&kbd_lock);

    if( request_irq(KEYBOARD_IRQ, keyboard_interrupt, 
                    SA_NOPROFILE, "keyboard", NULL)) 
    {
        printk("initialize_keyboard: failed to alloc IRQ %d\n", KEYBOARD_IRQ); 
        return;
    }

    if ( request_irq(AUX_IRQ, keyboard_interrupt, 
                     SA_NOPROFILE, "PS/2 Mouse", NULL)) 
    {
        printk("initialize_keyboard: failed to alloc IRQ %d\n", AUX_IRQ); 
        return;
    }
}

