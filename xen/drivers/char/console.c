/******************************************************************************
 * console.c
 * 
 * Emergency console I/O for Xen and the domain-0 guest OS.
 * 
 * Copyright (c) 2002-2004, K A Fraser.
 */

#include <stdarg.h>
#include <xen/config.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/mm.h>
#include <xen/delay.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/debugger.h>
#include <asm/io.h>

/* console: comma-separated list of console outputs. */
static char opt_console[30] = OPT_CONSOLE_STR;
string_param("console", opt_console);

/* conswitch: a character pair controlling console switching. */
/* Char 1: CTRL+<char1> is used to switch console input between Xen and DOM0 */
/* Char 2: If this character is 'x', then do not auto-switch to DOM0 when it */
/*         boots. Any other value, or omitting the char, enables auto-switch */
static unsigned char opt_conswitch[5] = "a";
string_param("conswitch", opt_conswitch);

/* sync_console: force synchronous console output (useful for debugging). */
static int opt_sync_console;
boolean_param("sync_console", opt_sync_console);

static int xpos, ypos;
static unsigned char *video;

#define CONRING_SIZE 16384
#define CONRING_IDX_MASK(i) ((i)&(CONRING_SIZE-1))
static char conring[CONRING_SIZE];
static unsigned int conringc, conringp;

static char printk_prefix[16] = "";

static int sercon_handle = -1;
static int vgacon_enabled = 0;

spinlock_t console_lock = SPIN_LOCK_UNLOCKED;

/*
 * *******************************************************
 * *************** OUTPUT TO VGA CONSOLE *****************
 * *******************************************************
 */

/* VGA text (mode 3) definitions. */
#define COLUMNS     80
#define LINES       25
#define ATTRIBUTE    7

/* Clear the screen and initialize VIDEO, XPOS and YPOS.  */
static void cls(void)
{
    memset(video, 0, COLUMNS * LINES * 2);
    xpos = ypos = 0;
    outw(10+(1<<(5+8)), 0x3d4); /* cursor off */
}

static int detect_video(void *video_base)
{
    volatile u16 *p = (volatile u16 *)video_base;
    u16 saved1 = p[0], saved2 = p[1];
    int video_found = 1;

    p[0] = 0xAA55;
    p[1] = 0x55AA;
    if ( (p[0] != 0xAA55) || (p[1] != 0x55AA) )
        video_found = 0;

    p[0] = 0x55AA;
    p[1] = 0xAA55;
    if ( (p[0] != 0x55AA) || (p[1] != 0xAA55) )
        video_found = 0;

    p[0] = saved1;
    p[1] = saved2;

    return video_found;
}

static int detect_vga(void)
{
    /*
     * Look at a number of well-known locations. Even if video is not at
     * 0xB8000 right now, it will appear there when we set up text mode 3.
     * 
     * We assume if there is any sign of a video adaptor then it is at least
     * VGA-compatible (surely noone runs CGA, EGA, .... these days?).
     * 
     * These checks are basically to detect headless server boxes.
     */
    return (detect_video(__va(0xA0000)) || 
            detect_video(__va(0xB0000)) || 
            detect_video(__va(0xB8000)));
}

/* This is actually code from vgaHWRestore in an old version of XFree86 :-) */
static void init_vga(void)
{
    /* The following VGA state was saved from a chip in text mode 3. */
    static unsigned char regs[] = {
        /* Sequencer registers */
        0x03, 0x00, 0x03, 0x00, 0x02,
        /* CRTC registers */
        0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f, 0x00, 0x4f, 0x20,
        0x0e, 0x00, 0x00, 0x01, 0xe0, 0x9c, 0x8e, 0x8f, 0x28, 0x1f, 0x96,
        0xb9, 0xa3, 0xff,
        /* Graphic registers */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0xff,
        /* Attribute registers */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07, 0x38, 0x39, 0x3a,
        0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x0c, 0x00, 0x0f, 0x08, 0x00
    };

    int i, j = 0;
    volatile unsigned char tmp;

    if ( !vgacon_enabled )
        return;

    if ( !detect_vga() )
    {
        printk("No VGA adaptor detected!\n");
        vgacon_enabled = 0;
        return;
    }

    video = __va(0xB8000);

    tmp = inb(0x3da);
    outb(0x00, 0x3c0);
    
    for ( i = 0; i < 5;  i++ )
        outw((regs[j++] << 8) | i, 0x3c4);
    
    /* Ensure CRTC registers 0-7 are unlocked by clearing bit 7 of CRTC[17]. */
    outw(((regs[5+17] & 0x7F) << 8) | 17, 0x3d4);
    
    for ( i = 0; i < 25; i++ ) 
        outw((regs[j++] << 8) | i, 0x3d4);
    
    for ( i = 0; i < 9;  i++ )
        outw((regs[j++] << 8) | i, 0x3ce);
    
    for ( i = 0; i < 21; i++ )
    {
        tmp = inb(0x3da);
        outb(i, 0x3c0); 
        outb(regs[j++], 0x3c0);
    }
    
    tmp = inb(0x3da);
    outb(0x20, 0x3c0);

    cls();
}

static void put_newline(void)
{
    xpos = 0;
    ypos++;

    if (ypos >= LINES)
    {
        static char zeroarr[2*COLUMNS] = { 0 };
        ypos = LINES-1;
        memcpy((char*)video, 
               (char*)video + 2*COLUMNS, (LINES-1)*2*COLUMNS);
        memcpy((char*)video + (LINES-1)*2*COLUMNS, 
               zeroarr, 2*COLUMNS);
    }
}

static void putchar_console(int c)
{
    if ( !vgacon_enabled )
        return;

    if ( c == '\n' )
    {
        put_newline();
    }
    else
    {
        video[(xpos + ypos * COLUMNS) * 2]     = c & 0xFF;
        video[(xpos + ypos * COLUMNS) * 2 + 1] = ATTRIBUTE;
        if ( ++xpos >= COLUMNS )
            put_newline();
    }
}


/*
 * ********************************************************
 * *************** ACCESS TO CONSOLE RING *****************
 * ********************************************************
 */

static void putchar_console_ring(int c)
{
    conring[CONRING_IDX_MASK(conringp++)] = c;
    if ( (conringp - conringc) > CONRING_SIZE )
        conringc = conringp - CONRING_SIZE;
}

long read_console_ring(GUEST_HANDLE(char) str, u32 *pcount, int clear)
{
    unsigned int idx, len, max, sofar, c;
    unsigned long flags;

    max   = *pcount;
    sofar = 0;

    c = conringc;
    while ( c != conringp )
    {
        idx = CONRING_IDX_MASK(c);
        len = conringp - c;
        if ( (idx + len) > CONRING_SIZE )
            len = CONRING_SIZE - idx;
        if ( (sofar + len) > max )
            len = max - sofar;
        if ( copy_to_guest_offset(str, sofar, &conring[idx], len) )
            return -EFAULT;
        sofar += len;
        c += len;
    }

    if ( clear )
    {
        spin_lock_irqsave(&console_lock, flags);
        conringc = conringp;
        spin_unlock_irqrestore(&console_lock, flags);
    }

    *pcount = sofar;
    return 0;
}


/*
 * *******************************************************
 * *************** ACCESS TO SERIAL LINE *****************
 * *******************************************************
 */

/* Characters received over the serial line are buffered for domain 0. */
#define SERIAL_RX_SIZE 128
#define SERIAL_RX_MASK(_i) ((_i)&(SERIAL_RX_SIZE-1))
static char serial_rx_ring[SERIAL_RX_SIZE];
static unsigned int serial_rx_cons, serial_rx_prod;

/* CTRL-<switch_char> switches input direction between Xen and DOM0. */
#define SWITCH_CODE (opt_conswitch[0]-'a'+1)
static int xen_rx = 1; /* FALSE => serial input passed to domain 0. */

static void switch_serial_input(void)
{
    static char *input_str[2] = { "DOM0", "Xen" };
    xen_rx = !xen_rx;
    if ( SWITCH_CODE != 0 )
    {
        printk("*** Serial input -> %s "
               "(type 'CTRL-%c' three times to switch input to %s).\n",
               input_str[xen_rx], opt_conswitch[0], input_str[!xen_rx]);
    }
}

static void __serial_rx(char c, struct cpu_user_regs *regs)
{
    if ( xen_rx )
        return handle_keypress(c, regs);

    /* Deliver input to guest buffer, unless it is already full. */
    if ( (serial_rx_prod-serial_rx_cons) != SERIAL_RX_SIZE )
        serial_rx_ring[SERIAL_RX_MASK(serial_rx_prod++)] = c;
    /* Always notify the guest: prevents receive path from getting stuck. */
    send_guest_virq(dom0->vcpu[0], VIRQ_CONSOLE);
}

static void serial_rx(char c, struct cpu_user_regs *regs)
{
    static int switch_code_count = 0;

    if ( (SWITCH_CODE != 0) && (c == SWITCH_CODE) )
    {
        /* We eat CTRL-<switch_char> in groups of 3 to switch console input. */
        if ( ++switch_code_count == 3 )
        {
            switch_serial_input();
            switch_code_count = 0;
            return;
        }
    }
    else
    {
        switch_code_count = 0;
    }

    /* Finally process the just-received character. */
    __serial_rx(c, regs);
}

static long guest_console_write(GUEST_HANDLE(char) buffer, int count)
{
    char kbuf[128], *kptr;
    int kcount;

    while ( count > 0 )
    {
        while ( serial_tx_space(sercon_handle) < (SERIAL_TXBUFSZ / 2) )
        {
            if ( hypercall_preempt_check() )
                break;
            cpu_relax();
        }

        if ( hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_console_io, "iih",
                CONSOLEIO_write, count, buffer);

        kcount = min_t(int, count, sizeof(kbuf)-1);
        if ( copy_from_guest((char *)kbuf, buffer, kcount) )
            return -EFAULT;
        kbuf[kcount] = '\0';

        serial_puts(sercon_handle, kbuf);

        for ( kptr = kbuf; *kptr != '\0'; kptr++ )
            putchar_console(*kptr);

        guest_handle_add_offset(buffer, kcount);
        count -= kcount;
    }

    return 0;
}

long do_console_io(int cmd, int count, GUEST_HANDLE(char) buffer)
{
    long rc;
    unsigned int idx, len;

#ifndef VERBOSE
    /* Only domain 0 may access the emergency console. */
    if ( current->domain->domain_id != 0 )
        return -EPERM;
#endif

    switch ( cmd )
    {
    case CONSOLEIO_write:
        rc = guest_console_write(buffer, count);
        break;
    case CONSOLEIO_read:
        rc = 0;
        while ( (serial_rx_cons != serial_rx_prod) && (rc < count) )
        {
            idx = SERIAL_RX_MASK(serial_rx_cons);
            len = serial_rx_prod - serial_rx_cons;
            if ( (idx + len) > SERIAL_RX_SIZE )
                len = SERIAL_RX_SIZE - idx;
            if ( (rc + len) > count )
                len = count - rc;
            if ( copy_to_guest_offset(buffer, rc, &serial_rx_ring[idx], len) )
            {
                rc = -EFAULT;
                break;
            }
            rc += len;
            serial_rx_cons += len;
        }
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


/*
 * *****************************************************
 * *************** GENERIC CONSOLE I/O *****************
 * *****************************************************
 */

static inline void __putstr(const char *str)
{
    int c;

    serial_puts(sercon_handle, str);

    while ( (c = *str++) != '\0' )
    {
        putchar_console(c);
        putchar_console_ring(c);
    }
}

void printf(const char *fmt, ...)
{
    static char   buf[1024];
    static int    start_of_line = 1;

    va_list       args;
    char         *p, *q;
    unsigned long flags;

    spin_lock_irqsave(&console_lock, flags);

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);        

    p = buf;
    while ( (q = strchr(p, '\n')) != NULL )
    {
        *q = '\0';
        if ( start_of_line )
            __putstr(printk_prefix);
        __putstr(p);
        __putstr("\n");
        start_of_line = 1;
        p = q + 1;
    }

    if ( *p != '\0' )
    {
        if ( start_of_line )
            __putstr(printk_prefix);
        __putstr(p);
        start_of_line = 0;
    }

    spin_unlock_irqrestore(&console_lock, flags);
}

void set_printk_prefix(const char *prefix)
{
    strcpy(printk_prefix, prefix);
}

void init_console(void)
{
    char *p;

    /* Where should console output go? */
    for ( p = opt_console; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, "com", 3) == 0 )
            sercon_handle = serial_parse_handle(p);
        else if ( strncmp(p, "vga", 3) == 0 )
            vgacon_enabled = 1;
    }

    init_vga();

    serial_set_rx_handler(sercon_handle, serial_rx);

    /* HELLO WORLD --- start-of-day banner text. */
    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);
    printk(" Latest ChangeSet: %s\n\n", XEN_CHANGESET);
    set_printk_prefix("(XEN) ");

    if ( opt_sync_console )
    {
        serial_start_sync(sercon_handle);
        printk("Console output is synchronous.\n");
    }
}

void console_endboot(int disable_vga)
{
    if ( disable_vga )
        vgacon_enabled = 0;

    /*
     * If user specifies so, we fool the switch routine to redirect input
     * straight back to Xen. I use this convoluted method so we still print
     * a useful 'how to switch' message.
     */
    if ( opt_conswitch[1] == 'x' )
        xen_rx = !xen_rx;

    /* Serial input is directed to DOM0 by default. */
    switch_serial_input();
}

void console_force_unlock(void)
{
    console_lock = SPIN_LOCK_UNLOCKED;
    serial_force_unlock(sercon_handle);
}

void console_force_lock(void)
{
    spin_lock(&console_lock);
}

void console_start_sync(void)
{
    serial_start_sync(sercon_handle);
}

void console_end_sync(void)
{
    serial_end_sync(sercon_handle);
}

void console_putc(char c)
{
    serial_putc(sercon_handle, c);
}

int console_getc(void)
{
    return serial_getc(sercon_handle);
}


/*
 * **************************************************************
 * *************** Serial console ring buffer *******************
 * **************************************************************
 */

#ifndef NDEBUG

/* Send output direct to console, or buffer it? */
int debugtrace_send_to_console;

static char        *debugtrace_buf; /* Debug-trace buffer */
static unsigned int debugtrace_prd; /* Producer index     */
static unsigned int debugtrace_kilobytes = 128, debugtrace_bytes;
static unsigned int debugtrace_used;
static spinlock_t   debugtrace_lock = SPIN_LOCK_UNLOCKED;
integer_param("debugtrace", debugtrace_kilobytes);

void debugtrace_dump(void)
{
    unsigned long flags;

    if ( (debugtrace_bytes == 0) || !debugtrace_used )
        return;

    watchdog_disable();

    spin_lock_irqsave(&debugtrace_lock, flags);

    printk("debugtrace_dump() starting\n");

    /* Print oldest portion of the ring. */
    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);
    serial_puts(sercon_handle, &debugtrace_buf[debugtrace_prd]);

    /* Print youngest portion of the ring. */
    debugtrace_buf[debugtrace_prd] = '\0';
    serial_puts(sercon_handle, &debugtrace_buf[0]);

    memset(debugtrace_buf, '\0', debugtrace_bytes);

    printk("debugtrace_dump() finished\n");

    spin_unlock_irqrestore(&debugtrace_lock, flags);

    watchdog_enable();
}

void debugtrace_printk(const char *fmt, ...)
{
    static char    buf[1024];

    va_list       args;
    char         *p;
    unsigned long flags;

    if ( debugtrace_bytes == 0 )
        return;

    debugtrace_used = 1;

    spin_lock_irqsave(&debugtrace_lock, flags);

    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if ( debugtrace_send_to_console )
    {
        serial_puts(sercon_handle, buf);
    }
    else
    {
        for ( p = buf; *p != '\0'; p++ )
        {
            debugtrace_buf[debugtrace_prd++] = *p;            
            /* Always leave a nul byte at the end of the buffer. */
            if ( debugtrace_prd == (debugtrace_bytes - 1) )
                debugtrace_prd = 0;
        }
    }

    spin_unlock_irqrestore(&debugtrace_lock, flags);
}

static int __init debugtrace_init(void)
{
    int order;
    unsigned int kbytes, bytes;

    /* Round size down to next power of two. */
    while ( (kbytes = (debugtrace_kilobytes & (debugtrace_kilobytes-1))) != 0 )
        debugtrace_kilobytes = kbytes;

    bytes = debugtrace_kilobytes << 10;
    if ( bytes == 0 )
        return 0;

    order = get_order_from_bytes(bytes);
    debugtrace_buf = alloc_xenheap_pages(order);
    ASSERT(debugtrace_buf != NULL);

    memset(debugtrace_buf, '\0', bytes);

    debugtrace_bytes = bytes;

    return 0;
}
__initcall(debugtrace_init);

#endif /* !NDEBUG */



/*
 * **************************************************************
 * *************** Debugging/tracing/error-report ***************
 * **************************************************************
 */

void panic(const char *fmt, ...)
{
    va_list args;
    char buf[128];
    unsigned long flags;
    static spinlock_t lock = SPIN_LOCK_UNLOCKED;
    extern void machine_restart(char *);
    
    debugtrace_dump();

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* Spit out multiline message in one go. */
    console_start_sync();
    spin_lock_irqsave(&lock, flags);
    printk("\n****************************************\n");
    printk("Panic on CPU %d:\n", smp_processor_id());
    printk(buf);
    printk("****************************************\n\n");
    printk("Reboot in five seconds...\n");
    spin_unlock_irqrestore(&lock, flags);

    debugger_trap_immediate();

    watchdog_disable();
    mdelay(5000);
    machine_restart(0);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

