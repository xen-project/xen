/******************************************************************************
 * console.c
 * 
 * Virtual console driver.
 * 
 * Copyright (c) 2002-2004, K A Fraser.
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
#include <asm-xen/evtchn.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/hypervisor.h>
#include <asm/hypervisor-ifs/event_channel.h>
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
__setup("xencons", xencons_setup);

/* The kernel and user-land drivers share a common transmit buffer. */
#define WBUF_SIZE     4096
#define WBUF_MASK(_i) ((_i)&(WBUF_SIZE-1))
static char wbuf[WBUF_SIZE];
static unsigned int wc, wp; /* write_cons, write_prod */

/* This lock protects accesses to the common transmit buffer. */
static spinlock_t xencons_lock = SPIN_LOCK_UNLOCKED;

static struct tty_driver *xencons_driver;

#define NUM_XENCONS 1

/* Common transmit-kick routine. */
static void __xencons_tx_flush(void);

/* This task is used to defer sending console data until there is space. */
static void xencons_tx_flush_task_routine(void *data);
#if 0				/* XXXcl tq */
static struct tq_struct xencons_tx_flush_task = {
    routine: xencons_tx_flush_task_routine
};
#else
static DECLARE_WORK(xencons_tx_flush_task, xencons_tx_flush_task_routine,
                    NULL);
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
        if ( (rc = HYPERVISOR_console_io(CONSOLEIO_write, count, (char *)s)) > 0 )
        {
            count -= rc;
            s += rc;
        }
	else
	    break;
    }
}

static struct tty_driver *kcons_device(struct console *c, int *index)
{
    *index = c->index;
    return xencons_driver;
}

static struct console kcons_info = {
    device:  kcons_device,
    flags:   CON_PRINTBUFFER,
    index:   -1
};

static int __init xen_console_init(void)
{
    if ( start_info.flags & SIF_INITDOMAIN )
    {
        if ( xc_mode == XC_DEFAULT )
            xc_mode = XC_SERIAL;
        kcons_info.write = kcons_write_dom0;
    }
    else
    {
        if ( xc_mode == XC_DEFAULT )
            xc_mode = XC_TTY;
        kcons_info.write = kcons_write;
    }

    if ( xc_mode == XC_OFF )
        return 0;

    if ( xc_mode == XC_SERIAL )
        strcpy(kcons_info.name, "ttyS");
    else
        strcpy(kcons_info.name, "tty");

    register_console(&kcons_info);
    return 0;
}
console_initcall(xen_console_init);


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
    if ( start_info.flags & SIF_INITDOMAIN )
        return;

    /*
     * We use dangerous control-interface functions that require a quiescent
     * system and no interrupts. Try to ensure this with a global cli().
     */
    cli();

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

    if ( start_info.flags & SIF_INITDOMAIN )
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
#if 0				/* XXXcl tq */
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
#else
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
#endif
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
#if 0				/* XXXcl tq */
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
#else
            else if ( ctrl_if_enqueue_space_callback(&xencons_tx_flush_task) )
#endif
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
static irqreturn_t xencons_priv_interrupt(int irq, void *dev_id, struct pt_regs *regs)
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

    spin_lock_irqsave(&xencons_lock, flags);
    x_char = ch;
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);
}

static void xencons_throttle(struct tty_struct *tty)
{
    if ( I_IXOFF(tty) )
        xencons_send_xchar(tty, STOP_CHAR(tty));
}

static void xencons_unthrottle(struct tty_struct *tty)
{
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

static int xencons_write(struct tty_struct *tty, int from_user,
                       const u_char * buf, int count)
{
    int i;
    unsigned long flags;

    if ( from_user && verify_area(VERIFY_READ, buf, count) )
        return -EINVAL;

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

static void xencons_put_char(struct tty_struct *tty, u_char ch)
{
    unsigned long flags;

    spin_lock_irqsave(&xencons_lock, flags);
    (void)__xencons_put_char(ch);
    spin_unlock_irqrestore(&xencons_lock, flags);
}

static void xencons_flush_chars(struct tty_struct *tty)
{
    unsigned long flags;

    spin_lock_irqsave(&xencons_lock, flags);
    __xencons_tx_flush();
    spin_unlock_irqrestore(&xencons_lock, flags);    
}

static void xencons_wait_until_sent(struct tty_struct *tty, int timeout)
{
    unsigned long orig_jiffies = jiffies;

    while ( tty->driver->chars_in_buffer(tty) )
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
    int line;
    unsigned long flags;

    MOD_INC_USE_COUNT;
    line = tty->index;
    if ( line < 0 || line >= NUM_XENCONS )
    {
        MOD_DEC_USE_COUNT;
        return -ENODEV;
    }

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

    if ( tty->count == 1 )
    {
        tty->closing = 1;
        tty_wait_until_sent(tty, 0);
        if ( tty->driver->flush_buffer != NULL )
            tty->driver->flush_buffer(tty);
        if ( tty->ldisc.flush_buffer != NULL )
            tty->ldisc.flush_buffer(tty);
        tty->closing = 0;
        spin_lock_irqsave(&xencons_lock, flags);
        xencons_tty = NULL;
        spin_unlock_irqrestore(&xencons_lock, flags);    
    }

    MOD_DEC_USE_COUNT;
}

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

static int __init xencons_init(void)
{
    xencons_driver = alloc_tty_driver(NUM_XENCONS); /* XXX */
    if (!xencons_driver)
	return -ENOMEM;

    xencons_driver->major           = TTY_MAJOR;
    xencons_driver->type            = TTY_DRIVER_TYPE_SERIAL;
    xencons_driver->subtype         = SERIAL_TYPE_NORMAL;
    xencons_driver->init_termios    = tty_std_termios;
    xencons_driver->flags           = 
        TTY_DRIVER_REAL_RAW | TTY_DRIVER_RESET_TERMIOS | TTY_DRIVER_NO_DEVFS;
    xencons_driver->termios         = xencons_termios;
    xencons_driver->termios_locked  = xencons_termios_locked;

    if ( xc_mode == XC_OFF )
        return 0;

    if ( xc_mode == XC_SERIAL )
    {
        xencons_driver->name        = "ttyS";
        xencons_driver->minor_start = 64;
        xencons_driver->num         = 1;
    }
    else
    {
        xencons_driver->name        = "tty";
        xencons_driver->minor_start = 1;
        xencons_driver->num         = MAX_NR_CONSOLES;
    }

    tty_set_operations(xencons_driver, &xencons_ops);

    if ( tty_register_driver(xencons_driver) )
        panic("Couldn't register Xen virtual console driver as %s\n",xencons_driver->name);

    if ( start_info.flags & SIF_INITDOMAIN )
    {
        xencons_priv_irq = bind_virq_to_irq(VIRQ_CONSOLE);
        (void)request_irq(xencons_priv_irq,
                          xencons_priv_interrupt, 0, "console", NULL);
    }
    else
    {
        (void)ctrl_if_register_receiver(CMSG_CONSOLE, xencons_rx, 0);
    }

    printk("Xen virtual console successfully installed as %s\n",xencons_driver->name);
    
    return 0;
}

static void __exit xencons_fini(void)
{
    int ret;

    if ( (ret = tty_unregister_driver(xencons_driver)) != 0 )
        printk(KERN_ERR "Unable to unregister Xen console driver: %d\n", ret);

    if ( start_info.flags & SIF_INITDOMAIN )
    {
        free_irq(xencons_priv_irq, NULL);
        unbind_virq_from_irq(VIRQ_CONSOLE);
    }
    else
    {
        ctrl_if_unregister_receiver(CMSG_CONSOLE, xencons_rx);
    }
}

module_init(xencons_init);
module_exit(xencons_fini);
