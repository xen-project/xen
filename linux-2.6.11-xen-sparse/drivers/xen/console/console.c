/******************************************************************************
 * console.c
 * 
 * Virtual console driver.
 * 
 * Copyright (c) 2002-2004, K A Fraser.
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/version.h>
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
#include <asm-xen/xen-public/event_channel.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/ctrl_if.h>

/*
 * Modes:
 *  'xencons=off'  [XC_OFF]:     Console is disabled.
 *  'xencons=tty'  [XC_TTY]:     Console attached to '/dev/tty[0-9]+'.
 *  'xencons=ttyS' [XC_SERIAL]:  Console attached to '/dev/ttyS[0-9]+'.
 *                 [XC_DEFAULT]: DOM0 -> XC_SERIAL ; all others -> XC_TTY.
 * 
 * NB. In mode XC_TTY, we create dummy consoles for tty2-63. This suppresses
 * warnings from standard distro startup scripts.
 */
static enum { XC_OFF, XC_DEFAULT, XC_TTY, XC_SERIAL } xc_mode = XC_DEFAULT;

static int __init xencons_setup(char *str)
{
    if ( !strcmp(str, "tty") )
        xc_mode = XC_TTY;
    else if ( !strcmp(str, "ttyS") )
        xc_mode = XC_SERIAL;
    else if ( !strcmp(str, "off") )
        xc_mode = XC_OFF;
    return 1;
}
__setup("xencons=", xencons_setup);

/* The kernel and user-land drivers share a common transmit buffer. */
#define WBUF_SIZE     4096
#define WBUF_MASK(_i) ((_i)&(WBUF_SIZE-1))
static char wbuf[WBUF_SIZE];
static unsigned int wc, wp; /* write_cons, write_prod */

/* This lock protects accesses to the common transmit buffer. */
static spinlock_t xencons_lock = SPIN_LOCK_UNLOCKED;

/* Common transmit-kick routine. */
static void __xencons_tx_flush(void);

/* This task is used to defer sending console data until there is space. */
static void xencons_tx_flush_task_routine(void *data);

static DECLARE_TQUEUE(xencons_tx_flush_task, 
                      xencons_tx_flush_task_routine,
                      NULL);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static struct tty_driver *xencons_driver;
#else
static struct tty_driver xencons_driver;
#endif


/******************** Kernel console driver ********************************/

static void kcons_write(
    struct console *c, const char *s, unsigned int count)
{
    int           i;
    unsigned long flags;

    spin_lock_irqsave(&xencons_lock, flags);
    
    for ( i = 0; i < count; i++ )
    {
        if ( (wp - wc) >= (WBUF_SIZE - 1) )
            break;
        if ( (wbuf[WBUF_MASK(wp++)] = s[i]) == '\n' )
            wbuf[WBUF_MASK(wp++)] = '\r';
    }

    __xencons_tx_flush();

    spin_unlock_irqrestore(&xencons_lock, flags);
}

static void kcons_write_dom0(
    struct console *c, const char *s, unsigned int count)
{
    int rc;

    while ( count > 0 )
    {
        if ( (rc = HYPERVISOR_console_io(CONSOLEIO_write,
                                         count, (char *)s)) > 0 )
        {
            count -= rc;
            s += rc;
        }
	else
	    break;
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static struct tty_driver *kcons_device(struct console *c, int *index)
{
    *index = c->index;
    return xencons_driver;
}
#else
static kdev_t kcons_device(struct console *c)
{
    return MKDEV(TTY_MAJOR, (xc_mode == XC_SERIAL) ? 64 : 1);
}
#endif

static struct console kcons_info = {
    device:  kcons_device,
    flags:   CON_PRINTBUFFER,
    index:   -1
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define __RETCODE 0
static int __init xen_console_init(void)
#else
#define __RETCODE
void xen_console_init(void)
#endif
{
    if ( xen_start_info.flags & SIF_INITDOMAIN )
    {
        if ( xc_mode == XC_DEFAULT )
            xc_mode = XC_SERIAL;
        kcons_info.write = kcons_write_dom0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	if ( xc_mode == XC_SERIAL )
	    kcons_info.flags |= CON_ENABLED;
#endif
    }
    else
    {
        if ( xc_mode == XC_DEFAULT )
            xc_mode = XC_TTY;
        kcons_info.write = kcons_write;
    }

    if ( xc_mode == XC_OFF )
        return __RETCODE;

    if ( xc_mode == XC_SERIAL )
        strcpy(kcons_info.name, "ttyS");
    else
        strcpy(kcons_info.name, "tty");

    register_console(&kcons_info);
    return __RETCODE;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
console_initcall(xen_console_init);
#endif

/*** Useful function for console debugging -- goes straight to Xen. ***/
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
    kcons_write_dom0(NULL, printk_buf, printk_len);

    return 0;
}

/*** Forcibly flush console data before dying. ***/
void xencons_force_flush(void)
{
    ctrl_msg_t msg;
    int        sz;

    /* Emergency console is synchronous, so there's nothing to flush. */
    if ( xen_start_info.flags & SIF_INITDOMAIN )
        return;

    /*
     * We use dangerous control-interface functions that require a quiescent
     * system and no interrupts. Try to ensure this with a global cli().
     */
    local_irq_disable();	/* XXXsmp */

    /* Spin until console data is flushed through to the domain controller. */
    while ( (wc != wp) && !ctrl_if_transmitter_empty() )
    {
        /* Interrupts are disabled -- we must manually reap responses. */
        ctrl_if_discard_responses();

        if ( (sz = wp - wc) == 0 )
            continue;
        if ( sz > sizeof(msg.msg) )
            sz = sizeof(msg.msg);
        if ( sz > (WBUF_SIZE - WBUF_MASK(wc)) )
            sz = WBUF_SIZE - WBUF_MASK(wc);

        msg.type    = CMSG_CONSOLE;
        msg.subtype = CMSG_CONSOLE_DATA;
        msg.length  = sz;
        memcpy(msg.msg, &wbuf[WBUF_MASK(wc)], sz);
            
        if ( ctrl_if_send_message_noblock(&msg, NULL, 0) == 0 )
            wc += sz;
    }
}


/******************** User-space console driver (/dev/console) ************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define DRV(_d)         (_d)
#define TTY_INDEX(_tty) ((_tty)->index)
#else
static int xencons_refcount;
static struct tty_struct *xencons_table[MAX_NR_CONSOLES];
#define DRV(_d)         (&(_d))
#define TTY_INDEX(_tty) (MINOR((_tty)->device) - xencons_driver.minor_start)
#endif

static struct termios *xencons_termios[MAX_NR_CONSOLES];
static struct termios *xencons_termios_locked[MAX_NR_CONSOLES];
static struct tty_struct *xencons_tty;
static int xencons_priv_irq;
static char x_char;

/* Non-privileged receive callback. */
static void xencons_rx(ctrl_msg_t *msg, unsigned long id)
{
    int           i;
    unsigned long flags;

    spin_lock_irqsave(&xencons_lock, flags);
    if ( xencons_tty != NULL )
    {
        for ( i = 0; i < msg->length; i++ )
            tty_insert_flip_char(xencons_tty, msg->msg[i], 0);
        tty_flip_buffer_push(xencons_tty);
    }
    spin_unlock_irqrestore(&xencons_lock, flags);

    msg->length = 0;
    ctrl_if_send_response(msg);
}

/* Privileged and non-privileged transmit worker. */
static void __xencons_tx_flush(void)
{
    int        sz, work_done = 0;
    ctrl_msg_t msg;

    if ( xen_start_info.flags & SIF_INITDOMAIN )
    {
        if ( x_char )
        {
            kcons_write_dom0(NULL, &x_char, 1);
            x_char = 0;
            work_done = 1;
        }

        while ( wc != wp )
        {
            sz = wp - wc;
            if ( sz > (WBUF_SIZE - WBUF_MASK(wc)) )
                sz = WBUF_SIZE - WBUF_MASK(wc);
            kcons_write_dom0(NULL, &wbuf[WBUF_MASK(wc)], sz);
            wc += sz;
            work_done = 1;
        }
    }
    else
    {
        while ( x_char )
        {
            msg.type    = CMSG_CONSOLE;
            msg.subtype = CMSG_CONSOLE_DATA;
            msg.length  = 1;
            msg.msg[0]  = x_char;

            if ( ctrl_if_send_message_noblock(&msg, NULL, 0) == 0 )
                x_char = 0;
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
                break;

            work_done = 1;
        }

        while ( wc != wp )
        {
            sz = wp - wc;
            if ( sz > sizeof(msg.msg) )
                sz = sizeof(msg.msg);
            if ( sz > (WBUF_SIZE - WBUF_MASK(wc)) )
                sz = WBUF_SIZE - WBUF_MASK(wc);

            msg.type    = CMSG_CONSOLE;
            msg.subtype = CMSG_CONSOLE_DATA;
            msg.length  = sz;
            memcpy(msg.msg, &wbuf[WBUF_MASK(wc)], sz);
            
            if ( ctrl_if_send_message_noblock(&msg, NULL, 0) == 0 )
                wc += sz;
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
                break;

            work_done = 1;
        }
    }

    if ( work_done && (xencons_tty != NULL) )
    {
        wake_up_interruptible(&xencons_tty->write_wait);
        if ( (xencons_tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
             (xencons_tty->ldisc.write_wakeup != NULL) )
            (xencons_tty->ldisc.write_wakeup)(xencons_tty);
    }
}

/* Non-privileged transmit kicker. */
static void xencons_tx_flush_task_routine(void *data)
{
    unsigned long flags;
    spin_lock_irqsave(&xencons_lock, flags);
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);
}

/* Privileged receive callback and transmit kicker. */
static irqreturn_t xencons_priv_interrupt(int irq, void *dev_id,
                                          struct pt_regs *regs)
{
    static char   rbuf[16];
    int           i, l;
    unsigned long flags;

    spin_lock_irqsave(&xencons_lock, flags);

    if ( xencons_tty != NULL )
    {
        /* Receive work. */
        while ( (l = HYPERVISOR_console_io(CONSOLEIO_read, 16, rbuf)) > 0 )
            for ( i = 0; i < l; i++ )
                tty_insert_flip_char(xencons_tty, rbuf[i], 0);
        if ( xencons_tty->flip.count != 0 )
            tty_flip_buffer_push(xencons_tty);
    }

    /* Transmit work. */
    __xencons_tx_flush();

    spin_unlock_irqrestore(&xencons_lock, flags);

    return IRQ_HANDLED;
}

static int xencons_write_room(struct tty_struct *tty)
{
    return WBUF_SIZE - (wp - wc);
}

static int xencons_chars_in_buffer(struct tty_struct *tty)
{
    return wp - wc;
}

static void xencons_send_xchar(struct tty_struct *tty, char ch)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return;

    spin_lock_irqsave(&xencons_lock, flags);
    x_char = ch;
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);
}

static void xencons_throttle(struct tty_struct *tty)
{
    if ( TTY_INDEX(tty) != 0 )
        return;

    if ( I_IXOFF(tty) )
        xencons_send_xchar(tty, STOP_CHAR(tty));
}

static void xencons_unthrottle(struct tty_struct *tty)
{
    if ( TTY_INDEX(tty) != 0 )
        return;

    if ( I_IXOFF(tty) )
    {
        if ( x_char != 0 )
            x_char = 0;
        else
            xencons_send_xchar(tty, START_CHAR(tty));
    }
}

static void xencons_flush_buffer(struct tty_struct *tty)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return;

    spin_lock_irqsave(&xencons_lock, flags);
    wc = wp = 0;
    spin_unlock_irqrestore(&xencons_lock, flags);
}

static inline int __xencons_put_char(int ch)
{
    char _ch = (char)ch;
    if ( (wp - wc) == WBUF_SIZE )
        return 0;
    wbuf[WBUF_MASK(wp++)] = _ch;
    return 1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int xencons_write(struct tty_struct *tty, const unsigned char *buf,
			 int count)
{
    int i;
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return count;

    spin_lock_irqsave(&xencons_lock, flags);

    for ( i = 0; i < count; i++ )
        if ( !__xencons_put_char(buf[i]) )
            break;

    if ( i != 0 )
        __xencons_tx_flush();

    spin_unlock_irqrestore(&xencons_lock, flags);

    return i;
}
#else
static int xencons_write(struct tty_struct *tty, int from_user,
			 const u_char *buf, int count)
{
    int i;
    unsigned long flags;

    if ( from_user && verify_area(VERIFY_READ, buf, count) )
        return -EINVAL;

    if ( TTY_INDEX(tty) != 0 )
        return count;

    spin_lock_irqsave(&xencons_lock, flags);

    for ( i = 0; i < count; i++ )
    {
        char ch;
        if ( from_user )
            __get_user(ch, buf + i);
        else
            ch = buf[i];
        if ( !__xencons_put_char(ch) )
            break;
    }

    if ( i != 0 )
        __xencons_tx_flush();

    spin_unlock_irqrestore(&xencons_lock, flags);

    return i;
}
#endif

static void xencons_put_char(struct tty_struct *tty, u_char ch)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return;

    spin_lock_irqsave(&xencons_lock, flags);
    (void)__xencons_put_char(ch);
    spin_unlock_irqrestore(&xencons_lock, flags);
}

static void xencons_flush_chars(struct tty_struct *tty)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return;

    spin_lock_irqsave(&xencons_lock, flags);
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);    
}

static void xencons_wait_until_sent(struct tty_struct *tty, int timeout)
{
    unsigned long orig_jiffies = jiffies;

    if ( TTY_INDEX(tty) != 0 )
        return;

    while ( DRV(tty->driver)->chars_in_buffer(tty) )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
        if ( signal_pending(current) )
            break;
        if ( (timeout != 0) && time_after(jiffies, orig_jiffies + timeout) )
            break;
    }
    
    set_current_state(TASK_RUNNING);
}

static int xencons_open(struct tty_struct *tty, struct file *filp)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return 0;

    spin_lock_irqsave(&xencons_lock, flags);
    tty->driver_data = NULL;
    if ( xencons_tty == NULL )
        xencons_tty = tty;
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);    

    return 0;
}

static void xencons_close(struct tty_struct *tty, struct file *filp)
{
    unsigned long flags;

    if ( TTY_INDEX(tty) != 0 )
        return;

    if ( tty->count == 1 )
    {
        tty->closing = 1;
        tty_wait_until_sent(tty, 0);
        if ( DRV(tty->driver)->flush_buffer != NULL )
            DRV(tty->driver)->flush_buffer(tty);
        if ( tty->ldisc.flush_buffer != NULL )
            tty->ldisc.flush_buffer(tty);
        tty->closing = 0;
        spin_lock_irqsave(&xencons_lock, flags);
        xencons_tty = NULL;
        spin_unlock_irqrestore(&xencons_lock, flags);    
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static struct tty_operations xencons_ops = {
    .open = xencons_open,
    .close = xencons_close,
    .write = xencons_write,
    .write_room = xencons_write_room,
    .put_char = xencons_put_char,
    .flush_chars = xencons_flush_chars,
    .chars_in_buffer = xencons_chars_in_buffer,
    .send_xchar = xencons_send_xchar,
    .flush_buffer = xencons_flush_buffer,
    .throttle = xencons_throttle,
    .unthrottle = xencons_unthrottle,
    .wait_until_sent = xencons_wait_until_sent,
};

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
static const char *xennullcon_startup(void)
{
    return NULL;
}

static int xennullcon_dummy(void)
{
    return 0;
}

#define DUMMY	(void *)xennullcon_dummy

/*
 *  The console `switch' structure for the dummy console
 *
 *  Most of the operations are dummies.
 */

const struct consw xennull_con = {
    .owner =		THIS_MODULE,
    .con_startup =	xennullcon_startup,
    .con_init =		DUMMY,
    .con_deinit =	DUMMY,
    .con_clear =	DUMMY,
    .con_putc =		DUMMY,
    .con_putcs =	DUMMY,
    .con_cursor =	DUMMY,
    .con_scroll =	DUMMY,
    .con_bmove =	DUMMY,
    .con_switch =	DUMMY,
    .con_blank =	DUMMY,
    .con_font_set =	DUMMY,
    .con_font_get =	DUMMY,
    .con_font_default =	DUMMY,
    .con_font_copy =	DUMMY,
    .con_set_palette =	DUMMY,
    .con_scrolldelta =	DUMMY,
};
#endif
#endif

static int __init xencons_init(void)
{
    int rc;

    if ( xc_mode == XC_OFF )
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    xencons_driver = alloc_tty_driver((xc_mode == XC_SERIAL) ? 
                                      1 : MAX_NR_CONSOLES);
    if ( xencons_driver == NULL )
        return -ENOMEM;
#else
    memset(&xencons_driver, 0, sizeof(struct tty_driver));
    xencons_driver.magic       = TTY_DRIVER_MAGIC;
    xencons_driver.refcount    = &xencons_refcount;
    xencons_driver.table       = xencons_table;
    xencons_driver.num         = (xc_mode == XC_SERIAL) ? 1 : MAX_NR_CONSOLES;
#endif

    DRV(xencons_driver)->major           = TTY_MAJOR;
    DRV(xencons_driver)->type            = TTY_DRIVER_TYPE_SERIAL;
    DRV(xencons_driver)->subtype         = SERIAL_TYPE_NORMAL;
    DRV(xencons_driver)->init_termios    = tty_std_termios;
    DRV(xencons_driver)->flags           = 
        TTY_DRIVER_REAL_RAW | TTY_DRIVER_RESET_TERMIOS | TTY_DRIVER_NO_DEVFS;
    DRV(xencons_driver)->termios         = xencons_termios;
    DRV(xencons_driver)->termios_locked  = xencons_termios_locked;

    if ( xc_mode == XC_SERIAL )
    {
        DRV(xencons_driver)->name        = "ttyS";
        DRV(xencons_driver)->minor_start = 64;
	DRV(xencons_driver)->name_base   = 0;
    }
    else
    {
        DRV(xencons_driver)->name        = "tty";
        DRV(xencons_driver)->minor_start = 1;
	DRV(xencons_driver)->name_base   = 1;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    tty_set_operations(xencons_driver, &xencons_ops);
#else
    xencons_driver.open            = xencons_open;
    xencons_driver.close           = xencons_close;
    xencons_driver.write           = xencons_write;
    xencons_driver.write_room      = xencons_write_room;
    xencons_driver.put_char        = xencons_put_char;
    xencons_driver.flush_chars     = xencons_flush_chars;
    xencons_driver.chars_in_buffer = xencons_chars_in_buffer;
    xencons_driver.send_xchar      = xencons_send_xchar;
    xencons_driver.flush_buffer    = xencons_flush_buffer;
    xencons_driver.throttle        = xencons_throttle;
    xencons_driver.unthrottle      = xencons_unthrottle;
    xencons_driver.wait_until_sent = xencons_wait_until_sent;
#endif

    if ( (rc = tty_register_driver(DRV(xencons_driver))) != 0 )
    {
        printk("WARNING: Failed to register Xen virtual "
               "console driver as '%s%d'\n",
               DRV(xencons_driver)->name, DRV(xencons_driver)->name_base);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        put_tty_driver(xencons_driver);
        xencons_driver = NULL;
#endif
        return rc;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    tty_register_device(xencons_driver, 0, NULL);
#endif

    if ( xen_start_info.flags & SIF_INITDOMAIN )
    {
        xencons_priv_irq = bind_virq_to_irq(VIRQ_CONSOLE);
        (void)request_irq(xencons_priv_irq,
                          xencons_priv_interrupt, 0, "console", NULL);
    }
    else
    {
        (void)ctrl_if_register_receiver(CMSG_CONSOLE, xencons_rx, 0);
    }

    printk("Xen virtual console successfully installed as %s\n",
           DRV(xencons_driver)->name);
    
    return 0;
}

module_init(xencons_init);
