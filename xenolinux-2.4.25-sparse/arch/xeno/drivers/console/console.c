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
#include <asm/evtchn.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/hypervisor.h>
#include <asm/hypervisor-ifs/event_channel.h>
#include <asm/control_if.h>

static spinlock_t xeno_console_lock = SPIN_LOCK_UNLOCKED;

#define XENO_TTY_MINOR 123

/******************** Kernel console driver ********************************/

static void nonpriv_conwrite(const char *s, unsigned int count)
{
    control_if_t *ctrl_if;
    evtchn_op_t   evtchn_op;
    int           src, dst, p;

    ctrl_if = (control_if_t *)((char *)HYPERVISOR_shared_info + 2048);

    while ( count != 0 )
    {
        /* Wait for the request ring to drain. */
        while ( ctrl_if->tx_resp_prod != ctrl_if->tx_req_prod )
            barrier();

        p = MASK_CONTROL_IDX(ctrl_if->tx_req_prod);
        
        ctrl_if->tx_ring[p].type    = CMSG_CONSOLE;
        ctrl_if->tx_ring[p].subtype = CMSG_CONSOLE_DATA;
        ctrl_if->tx_ring[p].id      = 0xaa;
        src = dst = 0;
        while ( (src < count) && (dst < (sizeof(ctrl_if->tx_ring[p].msg)-1)) )
        {
            if ( (ctrl_if->tx_ring[p].msg[dst++] = s[src++]) == '\n' )
                ctrl_if->tx_ring[p].msg[dst++] = '\r';
        }
        ctrl_if->tx_ring[p].length = dst;
        
        ctrl_if->tx_req_prod++;
        evtchn_op.cmd = EVTCHNOP_send;
        evtchn_op.u.send.local_port = 0;
        (void)HYPERVISOR_event_channel_op(&evtchn_op);
        
        s     += src;
        count -= src;
    }
}

static void priv_conwrite(const char *s, unsigned int count)
{
    int rc;

    while ( count > 0 )
    {
        if ( (rc = HYPERVISOR_console_io(CONSOLEIO_write, count, s)) > 0 )
        {
            count -= rc;
            s += rc;
        }
    }
}

static void xen_console_write(struct console *co, const char *s, 
                              unsigned int count)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    if ( !(start_info.flags & SIF_INITDOMAIN) )
        nonpriv_conwrite(s, count);
    else
        priv_conwrite(s, count);
    spin_unlock_irqrestore(&xeno_console_lock, flags);
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
    register_console(&xen_console_info);
}


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
    xen_console_write(NULL, printk_buf, printk_len);

    return 0;
}


/******************** User-space console driver (/dev/console) ************/

static struct tty_driver xeno_console_driver;
static int xeno_console_refcount;
static struct tty_struct *xeno_console_table[1];
static struct termios *xeno_console_termios[1];
static struct termios *xeno_console_termios_locked[1];
static struct tty_struct *xeno_console_tty;

#define WBUF_SIZE     1024
#define WBUF_MASK(_i) ((_i)&(WBUF_SIZE-1))
static char wbuf[WBUF_SIZE], x_char;
static unsigned int wc, wp; /* write_cons, write_prod */

static void __do_console_io(void)
{
    control_if_t    *ctrl_if;
    control_msg_t   *msg;
    evtchn_op_t      evtchn_op;
    CONTROL_RING_IDX c;
    int              i, l, work_done = 0;
    static char      rbuf[16];

    if ( xeno_console_tty == NULL )
        return;

    /* Special-case I/O handling for domain 0. */
    if ( start_info.flags & SIF_INITDOMAIN )
    {
        /* Receive work. */
        while ( (l = HYPERVISOR_console_io(CONSOLEIO_read, 16, rbuf)) > 0 )
            for ( i = 0; i < l; i++ )
                tty_insert_flip_char(xeno_console_tty, rbuf[i], 0);
        if ( xeno_console_tty->flip.count != 0 )
            tty_flip_buffer_push(xeno_console_tty);

        /* Transmit work. */
        while ( wc != wp )
        {
            l = wp - wc;
            if ( l > (WBUF_SIZE - WBUF_MASK(wc)) )
                l = WBUF_SIZE - WBUF_MASK(wc);
            priv_conwrite(&wbuf[WBUF_MASK(wc)], l);
            wc += l;
            wake_up_interruptible(&xeno_console_tty->write_wait);
            if ( (xeno_console_tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
                 (xeno_console_tty->ldisc.write_wakeup != NULL) )
                (xeno_console_tty->ldisc.write_wakeup)(xeno_console_tty);
        }

        return;
    }

    /* Acknowledge the notification. */
    evtchn_clear_port(0);

    ctrl_if = (control_if_t *)((char *)HYPERVISOR_shared_info + 2048);
    
    /* Receive work. */
    for ( c = ctrl_if->rx_resp_prod; c != ctrl_if->rx_req_prod; c++ )
    {
        msg = &ctrl_if->rx_ring[MASK_CONTROL_IDX(c)];
        if ( (msg->type == CMSG_CONSOLE) &&
             (msg->subtype == CMSG_CONSOLE_DATA) )
        {
            for ( i = 0; i < msg->length; i++ )
                tty_insert_flip_char(xeno_console_tty, msg->msg[i], 0);
        }
        msg->length = 0;
    }
    if ( ctrl_if->rx_resp_prod != c )
    {
        ctrl_if->rx_resp_prod = c;
        work_done = 1;
        tty_flip_buffer_push(xeno_console_tty);
    }
    
    /* Transmit work. */
    for ( c = ctrl_if->tx_req_prod; 
          (c - ctrl_if->tx_resp_prod) != CONTROL_RING_SIZE; 
          c++ )
    {
        if ( (wc == wp) && (x_char == 0) )
            break;
        msg = &ctrl_if->tx_ring[MASK_CONTROL_IDX(c)];
        msg->type    = CMSG_CONSOLE;
        msg->subtype = CMSG_CONSOLE_DATA;
        msg->id      = 0xaa;
        l = 0;
        if ( x_char != 0 ) /* Handle XON/XOFF urgently. */
        {
            msg->msg[l++] = x_char;
            x_char = 0;
        }
        while ( (l < sizeof(msg->msg)) && (wc != wp) )
            msg->msg[l++] = wbuf[WBUF_MASK(wc++)];
        msg->length = l;
    }
    if ( ctrl_if->tx_req_prod != c )
    {
        ctrl_if->tx_req_prod = c;
        work_done = 1;
        /* There might be something for waiters to do. */
        wake_up_interruptible(&xeno_console_tty->write_wait);
        if ( (xeno_console_tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
             (xeno_console_tty->ldisc.write_wakeup != NULL) )
            (xeno_console_tty->ldisc.write_wakeup)(xeno_console_tty);
    }

    if ( work_done )
    {
        /* Send a notification to the controller. */
        evtchn_op.cmd = EVTCHNOP_send;
        evtchn_op.u.send.local_port = 0;
        (void)HYPERVISOR_event_channel_op(&evtchn_op);
    }
}

/* This is the callback entry point for domains != 0. */
static void control_event(unsigned int port)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    __do_console_io();
    spin_unlock_irqrestore(&xeno_console_lock, flags);
}

/* This is the callback entry point for domain 0. */
static void control_irq(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    __do_console_io();
    spin_unlock_irqrestore(&xeno_console_lock, flags);    
}

static int xeno_console_write_room(struct tty_struct *tty)
{
    return WBUF_SIZE - (wp - wc);
}

static int xeno_console_chars_in_buffer(struct tty_struct *tty)
{
    return wp - wc;
}

static void xeno_console_send_xchar(struct tty_struct *tty, char ch)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    x_char = ch;
    __do_console_io();
    spin_unlock_irqrestore(&xeno_console_lock, flags);
}

static void xeno_console_throttle(struct tty_struct *tty)
{
    if ( I_IXOFF(tty) )
        xeno_console_send_xchar(tty, STOP_CHAR(tty));
}

static void xeno_console_unthrottle(struct tty_struct *tty)
{
    if ( I_IXOFF(tty) )
    {
        if ( x_char != 0 )
            x_char = 0;
        else
            xeno_console_send_xchar(tty, START_CHAR(tty));
    }
}

static void xeno_console_flush_buffer(struct tty_struct *tty)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    wc = wp = 0;
    spin_unlock_irqrestore(&xeno_console_lock, flags);
}

static inline int __xeno_console_put_char(int ch)
{
    char _ch = (char)ch;
    if ( (wp - wc) == WBUF_SIZE )
        return 0;
    wbuf[WBUF_MASK(wp++)] = _ch;
    return 1;
}

static int xeno_console_write(struct tty_struct *tty, int from_user,
                       const u_char * buf, int count)
{
    int i;
    unsigned long flags;

    if ( from_user && verify_area(VERIFY_READ, buf, count) )
        return -EINVAL;

    spin_lock_irqsave(&xeno_console_lock, flags);

    for ( i = 0; i < count; i++ )
    {
        char ch;
        if ( from_user )
            __get_user(ch, buf + i);
        else
            ch = buf[i];
        if ( !__xeno_console_put_char(ch) )
            break;
    }

    if ( i != 0 )
        __do_console_io();

    spin_unlock_irqrestore(&xeno_console_lock, flags);

    return i;
}

static void xeno_console_put_char(struct tty_struct *tty, u_char ch)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    (void)__xeno_console_put_char(ch);
    spin_unlock_irqrestore(&xeno_console_lock, flags);
}

static void xeno_console_flush_chars(struct tty_struct *tty)
{
    unsigned long flags;
    spin_lock_irqsave(&xeno_console_lock, flags);
    __do_console_io();
    spin_unlock_irqrestore(&xeno_console_lock, flags);    
}

static void xeno_console_wait_until_sent(struct tty_struct *tty, int timeout)
{
    unsigned long orig_jiffies = jiffies;

    while ( tty->driver.chars_in_buffer(tty) )
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

static int xeno_console_open(struct tty_struct *tty, struct file *filp)
{
    int line;
    unsigned long flags;

    MOD_INC_USE_COUNT;
    line = MINOR(tty->device) - tty->driver.minor_start;
    if ( line != 0 )
    {
        MOD_DEC_USE_COUNT;
        return -ENODEV;
    }

    spin_lock_irqsave(&xeno_console_lock, flags);
    tty->driver_data = NULL;
    if ( xeno_console_tty == NULL )
        xeno_console_tty = tty;
    __do_console_io();
    spin_unlock_irqrestore(&xeno_console_lock, flags);    

    return 0;
}

static void xeno_console_close(struct tty_struct *tty, struct file *filp)
{
    unsigned long flags;

    if ( tty->count == 1 )
    {
        tty->closing = 1;
        tty_wait_until_sent(tty, 0);
        if ( tty->driver.flush_buffer != NULL )
            tty->driver.flush_buffer(tty);
        if ( tty->ldisc.flush_buffer != NULL )
            tty->ldisc.flush_buffer(tty);
        tty->closing = 0;
        spin_lock_irqsave(&xeno_console_lock, flags);
        xeno_console_tty = NULL;
        spin_unlock_irqrestore(&xeno_console_lock, flags);    
    }

    MOD_DEC_USE_COUNT;
}

int __init xeno_con_init(void)
{
    memset(&xeno_console_driver, 0, sizeof(struct tty_driver));
    xeno_console_driver.magic           = TTY_DRIVER_MAGIC;
    xeno_console_driver.name            = "xencons";
    xeno_console_driver.major           = TTY_MAJOR;
    xeno_console_driver.minor_start     = XENO_TTY_MINOR;
    xeno_console_driver.num             = 1;
    xeno_console_driver.type            = TTY_DRIVER_TYPE_SERIAL;
    xeno_console_driver.subtype         = SERIAL_TYPE_NORMAL;
    xeno_console_driver.init_termios    = tty_std_termios;
    xeno_console_driver.flags           = 
        TTY_DRIVER_REAL_RAW | TTY_DRIVER_RESET_TERMIOS | TTY_DRIVER_NO_DEVFS;
    xeno_console_driver.refcount        = &xeno_console_refcount;
    xeno_console_driver.table           = xeno_console_table;
    xeno_console_driver.termios         = xeno_console_termios;
    xeno_console_driver.termios_locked  = xeno_console_termios_locked;

    xeno_console_driver.open            = xeno_console_open;
    xeno_console_driver.close           = xeno_console_close;
    xeno_console_driver.write           = xeno_console_write;
    xeno_console_driver.write_room      = xeno_console_write_room;
    xeno_console_driver.put_char        = xeno_console_put_char;
    xeno_console_driver.flush_chars     = xeno_console_flush_chars;
    xeno_console_driver.chars_in_buffer = xeno_console_chars_in_buffer;
    xeno_console_driver.send_xchar      = xeno_console_send_xchar;
    xeno_console_driver.flush_buffer    = xeno_console_flush_buffer;
    xeno_console_driver.throttle        = xeno_console_throttle;
    xeno_console_driver.unthrottle      = xeno_console_unthrottle;
    xeno_console_driver.wait_until_sent = xeno_console_wait_until_sent;

    if ( tty_register_driver(&xeno_console_driver) )
        panic("Couldn't register Xeno console driver\n");

    if ( !(start_info.flags & SIF_INITDOMAIN) )
    {
        if ( evtchn_request_port(0, control_event) != 0 )
            BUG();
        control_event(0); /* kickstart the console */
    }
    else
    {
        request_irq(HYPEREVENT_IRQ(_EVENT_CONSOLE), 
                    control_irq, 0, "console", NULL);
        control_irq(0, NULL, NULL); /* kickstart the console */
    }

    printk("Xeno console successfully installed\n");
    
    return 0;
}

void __exit xeno_con_fini(void)
{
    int ret;

    ret = tty_unregister_driver(&xeno_console_driver);
    if ( ret != 0 )
        printk(KERN_ERR "Unable to unregister Xeno console driver: %d\n", ret);

    if ( !(start_info.flags & SIF_INITDOMAIN) )
        (void)evtchn_free_port(0);
}

module_init(xeno_con_init);
module_exit(xeno_con_fini);

