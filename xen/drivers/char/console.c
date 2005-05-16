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
#include <xen/keyhandler.h>
#include <xen/mm.h>
#include <asm/uaccess.h>
#include <asm/debugger.h>
#include <asm/io.h>

/* opt_console: comma-separated list of console outputs. */
static char opt_console[30] = OPT_CONSOLE_STR;
string_param("console", opt_console);

/* opt_conswitch: a character pair controlling console switching. */
/* Char 1: CTRL+<char1> is used to switch console input between Xen and DOM0 */
/* Char 2: If this character is 'x', then do not auto-switch to DOM0 when it */
/*         boots. Any other value, or omitting the char, enables auto-switch */
static unsigned char opt_conswitch[5] = "a";
string_param("conswitch", opt_conswitch);

static int xpos, ypos;
static unsigned char *video;

#define CONSOLE_RING_SIZE 16392
typedef struct console_ring_st
{
    char buf[CONSOLE_RING_SIZE];
    unsigned int len;
} console_ring_t;
static console_ring_t console_ring;

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
    if ( console_ring.len < CONSOLE_RING_SIZE )
        console_ring.buf[console_ring.len++] = (char)c;
}

long read_console_ring(unsigned long str, unsigned int count, unsigned cmd)
{
    unsigned int len;
    
    len = (console_ring.len < count) ? console_ring.len : count;
    
    if ( copy_to_user((char *)str, console_ring.buf, len) )
        return -EFAULT;

    if ( cmd & CONSOLE_RING_CLEAR )
        console_ring.len = 0;
    
    return len;
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

static void __serial_rx(unsigned char c, struct cpu_user_regs *regs)
{
    if ( xen_rx )
    {
        handle_keypress(c, regs);
    }
    else if ( (serial_rx_prod-serial_rx_cons) != SERIAL_RX_SIZE )
    {
        serial_rx_ring[SERIAL_RX_MASK(serial_rx_prod)] = c;
        if ( serial_rx_prod++ == serial_rx_cons )
            send_guest_virq(dom0->exec_domain[0], VIRQ_CONSOLE);
    }
}

static void serial_rx(unsigned char c, struct cpu_user_regs *regs)
{
    static int switch_code_count = 0;

    if ( (SWITCH_CODE != 0) && (c == SWITCH_CODE) )
    {
        /* We eat CTRL-<switch_char> in groups of 3 to switch console input. */
        if ( ++switch_code_count == 3 )
        {
            switch_serial_input();
            switch_code_count = 0;
        }
    }
    else
    {
        switch_code_count = 0;
    }

    /* Finally process the just-received character. */
    __serial_rx(c, regs);
}

long do_console_io(int cmd, int count, char *buffer)
{
    char *kbuf;
    long  rc;

#ifndef VERBOSE
    /* Only domain-0 may access the emergency console. */
    if ( current->domain->domain_id != 0 )
        return -EPERM;
#endif

    switch ( cmd )
    {
    case CONSOLEIO_write:
        if ( count > (PAGE_SIZE-1) )
            count = PAGE_SIZE-1;
        if ( (kbuf = (char *)alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        kbuf[count] = '\0';
        rc = count;
        if ( copy_from_user(kbuf, buffer, count) )
            rc = -EFAULT;
        else
            serial_puts(sercon_handle, kbuf);
        free_xenheap_page((unsigned long)kbuf);
        break;
    case CONSOLEIO_read:
        rc = 0;
        while ( (serial_rx_cons != serial_rx_prod) && (rc < count) )
        {
            if ( put_user(serial_rx_ring[SERIAL_RX_MASK(serial_rx_cons)],
                          &buffer[rc]) )
            {
                rc = -EFAULT;
                break;
            }
            rc++;
            serial_rx_cons++;
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
            sercon_handle = parse_serial_handle(p);
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

void console_putc(char c)
{
    serial_putc(sercon_handle, c);
}

int console_getc(void)
{
    return serial_getc(sercon_handle);
}

int irq_console_getc(void)
{
    return irq_serial_getc(sercon_handle);
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
    int _watchdog_on = watchdog_on;
    unsigned long flags;

    if ( (debugtrace_bytes == 0) || !debugtrace_used )
        return;

    /* Watchdog can trigger if we print a really large buffer. */
    watchdog_on = 0;

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

    watchdog_on = _watchdog_on;
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

    order = get_order(bytes);
    debugtrace_buf = (char *)alloc_xenheap_pages(order);
    ASSERT(debugtrace_buf != NULL);

    memset(debugtrace_buf, '\0', bytes);

    debugtrace_bytes = bytes;

    memset(debugtrace_buf, '\0', debugtrace_bytes);

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
    char buf[128], cpustr[10];
    unsigned long flags;
    extern void machine_restart(char *);
    
    debugtrace_dump();

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    debugger_trap_immediate();

    /* Spit out multiline message in one go. */
    spin_lock_irqsave(&console_lock, flags);
    __putstr("\n****************************************\n");
    __putstr("Panic on CPU");
    sprintf(cpustr, "%d", smp_processor_id());
    __putstr(cpustr);
    __putstr(":\n");
    __putstr(buf);
    __putstr("****************************************\n\n");
    __putstr("Reboot in five seconds...\n");
    spin_unlock_irqrestore(&console_lock, flags);

    watchdog_on = 0;
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

