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

/******************** Kernel console driver ********************************/

static void kconsole_write(struct console *co, const char *s, unsigned count)
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

static kdev_t kconsole_device(struct console *c)
{
    /*
     * This is the magic that binds our "struct console" to our
     * "tty_struct", defined below.
     */
    return MKDEV(TTY_MAJOR, 0);
}

static struct console kconsole_info = {
    name:		"xenocon",
    write:		kconsole_write,
    device:             kconsole_device,
    flags:		CON_PRINTBUFFER,
    index:		-1,
};

void xeno_console_init(void)
{
    register_console(&kconsole_info);
}


/******************** Initial /dev/console *********************************/


static struct tty_driver console_driver;
static int console_refcount;
static struct tty_struct *console_table[1];
static struct termios *console_termios[1];
static struct termios *console_termios_locked[1];

static int console_write_room(struct tty_struct *tty)
{
    return INT_MAX;
}

static int console_chars_in_buffer(struct tty_struct *tty)
{
    return 0;
}

static inline int console_xmit(int ch)
{
    char _ch = ch;
    kconsole_write(NULL, &_ch, 1);
    return 1;
}

static int console_write(struct tty_struct *tty, int from_user,
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
        console_xmit(ch);
    }
    return i;
}

static void console_put_char(struct tty_struct *tty, u_char ch)
{
    console_xmit(ch);
}

static int console_open(struct tty_struct *tty, struct file *filp)
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

static void console_close(struct tty_struct *tty, struct file *filp)
{
    MOD_DEC_USE_COUNT;
}

static int __init console_ini(void)
{
    memset(&console_driver, 0, sizeof(struct tty_driver));
    console_driver.magic           = TTY_DRIVER_MAGIC;
    console_driver.driver_name     = "xeno_console";
    console_driver.name            = "console";
    console_driver.major           = TTY_MAJOR;
    console_driver.minor_start     = 0;
    console_driver.num             = 1;
    console_driver.type            = TTY_DRIVER_TYPE_SERIAL;
    console_driver.subtype         = SERIAL_TYPE_NORMAL;
    console_driver.init_termios    = tty_std_termios;
    console_driver.flags           = TTY_DRIVER_REAL_RAW;
    console_driver.refcount        = &console_refcount;
    console_driver.table           = console_table;
    console_driver.termios         = console_termios;
    console_driver.termios_locked  = console_termios_locked;
    /* Functions */
    console_driver.open            = console_open;
    console_driver.close           = console_close;
    console_driver.write           = console_write;
    console_driver.write_room      = console_write_room;
    console_driver.put_char        = console_put_char;
    console_driver.chars_in_buffer = console_chars_in_buffer;

    if ( tty_register_driver(&console_driver) )
    {
        printk(KERN_ERR "Couldn't register Xeno console driver\n");
    }
    else
    {
        printk("Xeno console successfully installed\n");
    }

    return 0;
}

static void __exit console_fin(void)
{
    int ret;

    ret = tty_unregister_driver(&console_driver);
    if ( ret != 0 )
    {
        printk(KERN_ERR "Unable to unregister Xeno console driver: %d\n", ret);
    }
}

module_init(console_ini);
module_exit(console_fin);

