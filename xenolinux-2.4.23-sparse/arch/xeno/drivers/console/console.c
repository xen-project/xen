/******************************************************************************
 * console.c
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/major.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/console.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/hypervisor.h>

#define XENO_TTY_MINOR 123

/*** Useful function for console debugging -- goes straight to Xen ****/
asmlinkage int xprintk(const char *fmt, ...)
{
    va_list args;
    int printk_len;
    static char printk_buf[1024];
    
    /* Emit the output into the temporary buffer */
    va_start(args, fmt);
    printk_len = vsnprintf(printk_buf, sizeof(printk_buf), fmt, args);
    va_end(args);
    
    /* Send the processed output directly to Xen. */
    (void)HYPERVISOR_console_write(printk_buf, printk_len);

    return 0;
}



/******************** Kernel console driver ********************************/

static void xen_console_write(struct console *co, const char *s, unsigned count)
{
#define STRLEN 256
    static char str[STRLEN];
    static int pos = 0;
    int len;
    
    /* We buffer output until we see a newline, or until the buffer is full. */
    while ( count != 0 )
    {
        len = ((STRLEN - pos) > count) ? count : STRLEN - pos;
        memcpy(str + pos, s, len);
        pos   += len;
        s     += len;
        count -= len;
        if ( (pos == STRLEN) || (str[pos-1] == '\n') )
        {
            (void)HYPERVISOR_console_write(str, pos);
            pos = 0;
        }
    }
}

static kdev_t xen_console_device(struct console *c)
{
    /*
     * This is the magic that binds our "struct console" to our
     * "tty_struct", defined below.
     */
    return MKDEV(TTY_MAJOR, XENO_TTY_MINOR);
}

static struct console xen_console_info = {
    name:		"xencons", /* Used to be xen_console, but we're only
				      actually allowed 8 charcters including
				      the terminator... */
    write:		xen_console_write,
    device:             xen_console_device,
    flags:		CON_PRINTBUFFER,
    index:		-1,
};

void xen_console_init(void)
{
  xprintk("xen_console_init\n");
  register_console(&xen_console_info);
}


/******************** Initial /dev/console *********************************/


static struct tty_driver xeno_console_driver;
static int xeno_console_refcount;
static struct tty_struct *xeno_console_table[1];
static struct termios *xeno_console_termios[1];
static struct termios *xeno_console_termios_locked[1];

static int xeno_console_write_room(struct tty_struct *tty)
{
    return INT_MAX;
}

static int xeno_console_chars_in_buffer(struct tty_struct *tty)
{
    return 0;
}

static inline int xeno_console_xmit(int ch)
{
    char _ch = ch;
    xen_console_write(NULL, &_ch, 1);
    return 1;
}

static int xeno_console_write(struct tty_struct *tty, int from_user,
                       const u_char * buf, int count)
{
    int i;

    if ( from_user && verify_area(VERIFY_READ, buf, count) )
    {
        return -EINVAL;
    }

    for ( i = 0; i < count; i++ )
    {
        char ch;
        if ( from_user )
        {
            __get_user(ch, buf + i);
        }
        else
        {
            ch = buf[i];
        }
        xeno_console_xmit(ch);
    }
    return i;
}

static void xeno_console_put_char(struct tty_struct *tty, u_char ch)
{
    xeno_console_xmit(ch);
}

static int xeno_console_open(struct tty_struct *tty, struct file *filp)
{
    int line;

    MOD_INC_USE_COUNT;
    line = MINOR(tty->device) - tty->driver.minor_start;
    if ( line )
    {
        MOD_DEC_USE_COUNT;
        return -ENODEV;
    }

    tty->driver_data = NULL;

    return 0;
}

static void xeno_console_close(struct tty_struct *tty, struct file *filp)
{
    MOD_DEC_USE_COUNT;
}

int __init xeno_con_init(void)
{
    memset(&xeno_console_driver, 0, sizeof(struct tty_driver));
    xeno_console_driver.magic           = TTY_DRIVER_MAGIC;
    xeno_console_driver.driver_name     = "xeno_console";
    xeno_console_driver.name            = "xencon";
    xeno_console_driver.major           = TTY_MAJOR;
    xeno_console_driver.minor_start     = XENO_TTY_MINOR;
    xeno_console_driver.num             = 1;
    xeno_console_driver.type            = TTY_DRIVER_TYPE_SERIAL;
    xeno_console_driver.subtype         = SERIAL_TYPE_NORMAL;
    xeno_console_driver.init_termios    = tty_std_termios;
    xeno_console_driver.flags           = TTY_DRIVER_REAL_RAW | TTY_DRIVER_NO_DEVFS;
    xeno_console_driver.refcount        = &xeno_console_refcount;
    xeno_console_driver.table           = xeno_console_table;
    xeno_console_driver.termios         = xeno_console_termios;
    xeno_console_driver.termios_locked  = xeno_console_termios_locked;
    /* Functions */
    xeno_console_driver.open            = xeno_console_open;
    xeno_console_driver.close           = xeno_console_close;
    xeno_console_driver.write           = xeno_console_write;
    xeno_console_driver.write_room      = xeno_console_write_room;
    xeno_console_driver.put_char        = xeno_console_put_char;
    xeno_console_driver.chars_in_buffer = xeno_console_chars_in_buffer;

    if ( tty_register_driver(&xeno_console_driver) )
    {
        printk(KERN_ERR "Couldn't register Xeno console driver\n");
    }
    else
    {
        printk("Xeno console successfully installed\n");
    }

    return 0;
}

void __exit xeno_con_fini(void)
{
    int ret;

    ret = tty_unregister_driver(&xeno_console_driver);
    if ( ret != 0 )
    {
        printk(KERN_ERR "Unable to unregister Xeno console driver: %d\n", ret);
    }
}

module_init(xeno_con_init);
module_exit(xeno_con_fini);

