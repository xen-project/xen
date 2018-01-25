/******************************************************************************
 * console.c
 * 
 * Emergency console I/O for Xen and the domain-0 guest OS.
 * 
 * Copyright (c) 2002-2004, K A Fraser.
 *
 * Added printf_ratelimit
 *     Taken from Linux - Author: Andi Kleen (net_ratelimit)
 *     Ported to Xen - Steven Rostedt - Red Hat
 */

#include <xen/version.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/guest_access.h>
#include <xen/watchdog.h>
#include <xen/shutdown.h>
#include <xen/video.h>
#include <xen/kexec.h>
#include <xen/ctype.h>
#include <xen/warning.h>
#include <asm/debugger.h>
#include <asm/div64.h>
#include <xen/hypercall.h> /* for do_console_io */
#include <xen/early_printk.h>
#include <xen/warning.h>

#ifdef CONFIG_X86
#include <xen/consoled.h>
#include <xen/pv_console.h>
#include <asm/guest.h>
#endif

/* console: comma-separated list of console outputs. */
static char __initdata opt_console[30] = OPT_CONSOLE_STR;
string_param("console", opt_console);

/* conswitch: a character pair controlling console switching. */
/* Char 1: CTRL+<char1> is used to switch console input between Xen and DOM0 */
/* Char 2: If this character is 'x', then do not auto-switch to DOM0 when it */
/*         boots. Any other value, or omitting the char, enables auto-switch */
static unsigned char __read_mostly opt_conswitch[3] = "a";
string_runtime_param("conswitch", opt_conswitch);

/* sync_console: force synchronous console output (useful for debugging). */
static bool_t __initdata opt_sync_console;
boolean_param("sync_console", opt_sync_console);
static const char __initconst warning_sync_console[] =
    "WARNING: CONSOLE OUTPUT IS SYNCHRONOUS\n"
    "This option is intended to aid debugging of Xen by ensuring\n"
    "that all output is synchronously delivered on the serial line.\n"
    "However it can introduce SIGNIFICANT latencies and affect\n"
    "timekeeping. It is NOT recommended for production use!\n";

/* console_to_ring: send guest (incl. dom 0) console data to console ring. */
static bool_t __read_mostly opt_console_to_ring;
boolean_param("console_to_ring", opt_console_to_ring);

/* console_timestamps: include a timestamp prefix on every Xen console line. */
enum con_timestamp_mode
{
    TSM_NONE,          /* No timestamps */
    TSM_DATE,          /* [YYYY-MM-DD HH:MM:SS] */
    TSM_DATE_MS,       /* [YYYY-MM-DD HH:MM:SS.mmm] */
    TSM_BOOT           /* [SSSSSS.uuuuuu] */
};

static enum con_timestamp_mode __read_mostly opt_con_timestamp_mode = TSM_NONE;

static int parse_console_timestamps(const char *s);
custom_runtime_param("console_timestamps", parse_console_timestamps);

/* conring_size: allows a large console ring than default (16kB). */
static uint32_t __initdata opt_conring_size;
size_param("conring_size", opt_conring_size);

#define _CONRING_SIZE 16384
#define CONRING_IDX_MASK(i) ((i)&(conring_size-1))
static char __initdata _conring[_CONRING_SIZE];
static char *__read_mostly conring = _conring;
static uint32_t __read_mostly conring_size = _CONRING_SIZE;
static uint32_t conringc, conringp;

static int __read_mostly sercon_handle = -1;

#ifdef CONFIG_X86
static bool __read_mostly opt_console_xen; /* console=xen */
#endif

static DEFINE_SPINLOCK(console_lock);

/*
 * To control the amount of printing, thresholds are added.
 * These thresholds correspond to the XENLOG logging levels.
 * There's an upper and lower threshold for non-guest messages and for
 * guest-provoked messages.  This works as follows, for a given log level L:
 *
 * L < lower_threshold                     : always logged
 * lower_threshold <= L < upper_threshold  : rate-limited logging
 * upper_threshold <= L                    : never logged
 *
 * Note, in the above algorithm, to disable rate limiting simply make
 * the lower threshold equal to the upper.
 */
#ifdef NDEBUG
#define XENLOG_UPPER_THRESHOLD       2 /* Do not print INFO and DEBUG  */
#define XENLOG_LOWER_THRESHOLD       2 /* Always print ERR and WARNING */
#define XENLOG_GUEST_UPPER_THRESHOLD 2 /* Do not print INFO and DEBUG  */
#define XENLOG_GUEST_LOWER_THRESHOLD 0 /* Rate-limit ERR and WARNING   */
#else
#define XENLOG_UPPER_THRESHOLD       4 /* Do not discard anything      */
#define XENLOG_LOWER_THRESHOLD       4 /* Print everything             */
#define XENLOG_GUEST_UPPER_THRESHOLD 4 /* Do not discard anything      */
#define XENLOG_GUEST_LOWER_THRESHOLD 4 /* Print everything             */
#endif
/*
 * The XENLOG_DEFAULT is the default given to printks that
 * do not have any print level associated with them.
 */
#define XENLOG_DEFAULT       1 /* XENLOG_WARNING */
#define XENLOG_GUEST_DEFAULT 1 /* XENLOG_WARNING */

static int __read_mostly xenlog_upper_thresh = XENLOG_UPPER_THRESHOLD;
static int __read_mostly xenlog_lower_thresh = XENLOG_LOWER_THRESHOLD;
static int __read_mostly xenlog_guest_upper_thresh =
    XENLOG_GUEST_UPPER_THRESHOLD;
static int __read_mostly xenlog_guest_lower_thresh =
    XENLOG_GUEST_LOWER_THRESHOLD;

static int parse_loglvl(const char *s);
static int parse_guest_loglvl(const char *s);

/*
 * <lvl> := none|error|warning|info|debug|all
 * loglvl=<lvl_print_always>[/<lvl_print_ratelimit>]
 *  <lvl_print_always>: log level which is always printed
 *  <lvl_print_rlimit>: log level which is rate-limit printed
 * Similar definitions for guest_loglvl, but applies to guest tracing.
 * Defaults: loglvl=warning ; guest_loglvl=none/warning
 */
custom_runtime_param("loglvl", parse_loglvl);
custom_runtime_param("guest_loglvl", parse_guest_loglvl);

static atomic_t print_everything = ATOMIC_INIT(0);

#define ___parse_loglvl(s, ps, lvlstr, lvlnum)          \
    if ( !strncmp((s), (lvlstr), strlen(lvlstr)) ) {    \
        *(ps) = (s) + strlen(lvlstr);                   \
        return (lvlnum);                                \
    }

static int __parse_loglvl(const char *s, const char **ps)
{
    ___parse_loglvl(s, ps, "none",    0);
    ___parse_loglvl(s, ps, "error",   1);
    ___parse_loglvl(s, ps, "warning", 2);
    ___parse_loglvl(s, ps, "info",    3);
    ___parse_loglvl(s, ps, "debug",   4);
    ___parse_loglvl(s, ps, "all",     4);
    return 2; /* sane fallback */
}

static int _parse_loglvl(const char *s, int *lower, int *upper)
{
    *lower = *upper = __parse_loglvl(s, &s);
    if ( *s == '/' )
        *upper = __parse_loglvl(s+1, &s);
    if ( *upper < *lower )
        *upper = *lower;

    return *s ? -EINVAL : 0;
}

static int parse_loglvl(const char *s)
{
    return _parse_loglvl(s, &xenlog_lower_thresh, &xenlog_upper_thresh);
}

static int parse_guest_loglvl(const char *s)
{
    return _parse_loglvl(s, &xenlog_guest_lower_thresh,
                         &xenlog_guest_upper_thresh);
}

static char *loglvl_str(int lvl)
{
    switch ( lvl )
    {
    case 0: return "Nothing";
    case 1: return "Errors";
    case 2: return "Errors and warnings";
    case 3: return "Errors, warnings and info";
    case 4: return "All";
    }
    return "???";
}

static int *__read_mostly upper_thresh_adj = &xenlog_upper_thresh;
static int *__read_mostly lower_thresh_adj = &xenlog_lower_thresh;
static const char *__read_mostly thresh_adj = "standard";

static void do_toggle_guest(unsigned char key, struct cpu_user_regs *regs)
{
    if ( upper_thresh_adj == &xenlog_upper_thresh )
    {
        upper_thresh_adj = &xenlog_guest_upper_thresh;
        lower_thresh_adj = &xenlog_guest_lower_thresh;
        thresh_adj = "guest";
    }
    else
    {
        upper_thresh_adj = &xenlog_upper_thresh;
        lower_thresh_adj = &xenlog_lower_thresh;
        thresh_adj = "standard";
    }
    printk("'%c' pressed -> %s log level adjustments enabled\n",
           key, thresh_adj);
}

static void do_adj_thresh(unsigned char key)
{
    if ( *upper_thresh_adj < *lower_thresh_adj )
        *upper_thresh_adj = *lower_thresh_adj;
    printk("'%c' pressed -> %s log level: %s (rate limited %s)\n",
           key, thresh_adj, loglvl_str(*lower_thresh_adj),
           loglvl_str(*upper_thresh_adj));
}

static void do_inc_thresh(unsigned char key, struct cpu_user_regs *regs)
{
    ++*lower_thresh_adj;
    do_adj_thresh(key);
}

static void do_dec_thresh(unsigned char key, struct cpu_user_regs *regs)
{
    if ( *lower_thresh_adj )
        --*lower_thresh_adj;
    do_adj_thresh(key);
}

/*
 * ********************************************************
 * *************** ACCESS TO CONSOLE RING *****************
 * ********************************************************
 */

static void conring_puts(const char *str)
{
    char c;

    ASSERT(spin_is_locked(&console_lock));

    while ( (c = *str++) != '\0' )
        conring[CONRING_IDX_MASK(conringp++)] = c;

    if ( (uint32_t)(conringp - conringc) > conring_size )
        conringc = conringp - conring_size;
}

long read_console_ring(struct xen_sysctl_readconsole *op)
{
    XEN_GUEST_HANDLE_PARAM(char) str;
    uint32_t idx, len, max, sofar, c, p;

    str   = guest_handle_cast(op->buffer, char),
    max   = op->count;
    sofar = 0;

    c = read_atomic(&conringc);
    p = read_atomic(&conringp);
    if ( op->incremental &&
         (c <= p ? c < op->index && op->index <= p
                 : c < op->index || op->index <= p) )
        c = op->index;

    while ( (c != p) && (sofar < max) )
    {
        idx = CONRING_IDX_MASK(c);
        len = p - c;
        if ( (idx + len) > conring_size )
            len = conring_size - idx;
        if ( (sofar + len) > max )
            len = max - sofar;
        if ( copy_to_guest_offset(str, sofar, &conring[idx], len) )
            return -EFAULT;
        sofar += len;
        c += len;
    }

    if ( op->clear )
    {
        spin_lock_irq(&console_lock);
        conringc = p - c > conring_size ? p - conring_size : c;
        spin_unlock_irq(&console_lock);
    }

    op->count = sofar;
    op->index = c;

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

static void (*serial_steal_fn)(const char *) = early_puts;

int console_steal(int handle, void (*fn)(const char *))
{
    if ( (handle == -1) || (handle != sercon_handle) )
        return 0;

    if ( serial_steal_fn != NULL )
        return -EBUSY;

    serial_steal_fn = fn;
    return 1;
}

void console_giveback(int id)
{
    if ( id == 1 )
        serial_steal_fn = NULL;
}

static void sercon_puts(const char *s)
{
    if ( serial_steal_fn != NULL )
        (*serial_steal_fn)(s);
    else
        serial_puts(sercon_handle, s);

#ifdef CONFIG_X86
    /* Copy all serial output into PV console */
    pv_console_puts(s);
#endif
}

static void dump_console_ring_key(unsigned char key)
{
    uint32_t idx, len, sofar, c;
    unsigned int order;
    char *buf;

    printk("'%c' pressed -> dumping console ring buffer (dmesg)\n", key);

    /* create a buffer in which we'll copy the ring in the correct
       order and NUL terminate */
    order = get_order_from_bytes(conring_size + 1);
    buf = alloc_xenheap_pages(order, 0);
    if ( buf == NULL )
    {
        printk("unable to allocate memory!\n");
        return;
    }

    c = conringc;
    sofar = 0;
    while ( (c != conringp) )
    {
        idx = CONRING_IDX_MASK(c);
        len = conringp - c;
        if ( (idx + len) > conring_size )
            len = conring_size - idx;
        memcpy(buf + sofar, &conring[idx], len);
        sofar += len;
        c += len;
    }
    buf[sofar] = '\0';

    sercon_puts(buf);
    video_puts(buf);

    free_xenheap_pages(buf, order);
}

/* CTRL-<switch_char> switches input direction between Xen and DOM0. */
#define switch_code (opt_conswitch[0]-'a'+1)
static int __read_mostly xen_rx = 1; /* FALSE => input passed to domain 0. */

static void switch_serial_input(void)
{
    static char *input_str[2] = { "DOM0", "Xen" };
    xen_rx = !xen_rx;
    printk("*** Serial input -> %s", input_str[xen_rx]);
    if ( switch_code )
        printk(" (type 'CTRL-%c' three times to switch input to %s)",
               opt_conswitch[0], input_str[!xen_rx]);
    printk("\n");
}

static void __serial_rx(char c, struct cpu_user_regs *regs)
{
    if ( xen_rx )
        return handle_keypress(c, regs);

    /* Deliver input to guest buffer, unless it is already full. */
    if ( (serial_rx_prod-serial_rx_cons) != SERIAL_RX_SIZE )
        serial_rx_ring[SERIAL_RX_MASK(serial_rx_prod++)] = c;
    /* Always notify the guest: prevents receive path from getting stuck. */
    send_global_virq(VIRQ_CONSOLE);

#ifdef CONFIG_X86
    if ( pv_shim && pv_console )
        consoled_guest_tx(c);
#endif
}

static void serial_rx(char c, struct cpu_user_regs *regs)
{
    static int switch_code_count = 0;

    if ( switch_code && (c == switch_code) )
    {
        /* We eat CTRL-<switch_char> in groups of 3 to switch console input. */
        if ( ++switch_code_count == 3 )
        {
            switch_serial_input();
            switch_code_count = 0;
        }
        return;
    }

    for ( ; switch_code_count != 0; switch_code_count-- )
        __serial_rx(switch_code, regs);

    /* Finally process the just-received character. */
    __serial_rx(c, regs);
}

static void notify_dom0_con_ring(unsigned long unused)
{
    send_global_virq(VIRQ_CON_RING);
}
static DECLARE_SOFTIRQ_TASKLET(notify_dom0_con_ring_tasklet,
                               notify_dom0_con_ring, 0);

#ifdef CONFIG_X86
static inline void xen_console_write_debug_port(const char *buf, size_t len)
{
    unsigned long tmp;
    asm volatile ( "rep outsb;"
                   : "=&S" (tmp), "=&c" (tmp)
                   : "0" (buf), "1" (len), "d" (0xe9) );
}
#endif

static long guest_console_write(XEN_GUEST_HANDLE_PARAM(char) buffer, int count)
{
    char kbuf[128];
    int kcount = 0;
    struct domain *cd = current->domain;

    while ( count > 0 )
    {
        if ( kcount && hypercall_preempt_check() )
            return hypercall_create_continuation(
                __HYPERVISOR_console_io, "iih",
                CONSOLEIO_write, count, buffer);

        kcount = min_t(int, count, sizeof(kbuf)-1);
        if ( copy_from_guest(kbuf, buffer, kcount) )
            return -EFAULT;
        kbuf[kcount] = '\0';

        if ( is_hardware_domain(cd) )
        {
            /* Use direct console output as it could be interactive */
            spin_lock_irq(&console_lock);

            sercon_puts(kbuf);
            video_puts(kbuf);

#ifdef CONFIG_X86
            if ( opt_console_xen )
            {
                size_t len = strlen(kbuf);

                if ( xen_guest )
                    xen_hypercall_console_write(kbuf, len);
                else
                    xen_console_write_debug_port(kbuf, len);
            }
#endif

            if ( opt_console_to_ring )
            {
                conring_puts(kbuf);
                tasklet_schedule(&notify_dom0_con_ring_tasklet);
            }

            spin_unlock_irq(&console_lock);
        }
        else
        {
            char *kin = kbuf, *kout = kbuf, c;

            /* Strip non-printable characters */
            for ( ; ; )
            {
                c = *kin++;
                if ( c == '\0' || c == '\n' )
                    break;
                if ( isprint(c) || c == '\t' )
                    *kout++ = c;
            }
            *kout = '\0';
            spin_lock(&cd->pbuf_lock);
            if ( c == '\n' )
            {
                kcount = kin - kbuf;
                cd->pbuf[cd->pbuf_idx] = '\0';
                guest_printk(cd, XENLOG_G_DEBUG "%s%s\n", cd->pbuf, kbuf);
                cd->pbuf_idx = 0;
            }
            else if ( cd->pbuf_idx + kcount < (DOMAIN_PBUF_SIZE - 1) )
            {
                /* buffer the output until a newline */
                memcpy(cd->pbuf + cd->pbuf_idx, kbuf, kcount);
                cd->pbuf_idx += kcount;
            }
            else
            {
                cd->pbuf[cd->pbuf_idx] = '\0';
                guest_printk(cd, XENLOG_G_DEBUG "%s%s\n", cd->pbuf, kbuf);
                cd->pbuf_idx = 0;
            }
            spin_unlock(&cd->pbuf_lock);
        }

        guest_handle_add_offset(buffer, kcount);
        count -= kcount;
    }

    return 0;
}

long do_console_io(int cmd, int count, XEN_GUEST_HANDLE_PARAM(char) buffer)
{
    long rc;
    unsigned int idx, len;

    rc = xsm_console_io(XSM_OTHER, current->domain, cmd);
    if ( rc )
        return rc;

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

static bool_t console_locks_busted;

static void __putstr(const char *str)
{
    ASSERT(spin_is_locked(&console_lock));

    sercon_puts(str);
    video_puts(str);

#ifdef CONFIG_X86
    if ( opt_console_xen )
    {
        size_t len = strlen(str);

        if ( xen_guest )
            xen_hypercall_console_write(str, len);
        else
            xen_console_write_debug_port(str, len);
    }
#endif

    conring_puts(str);

    if ( !console_locks_busted )
        tasklet_schedule(&notify_dom0_con_ring_tasklet);
}

static int printk_prefix_check(char *p, char **pp)
{
    int loglvl = -1;
    int upper_thresh = xenlog_upper_thresh;
    int lower_thresh = xenlog_lower_thresh;

    while ( (p[0] == '<') && (p[1] != '\0') && (p[2] == '>') )
    {
        switch ( p[1] )
        {
        case 'G':
            upper_thresh = xenlog_guest_upper_thresh;
            lower_thresh = xenlog_guest_lower_thresh;
            if ( loglvl == -1 )
                loglvl = XENLOG_GUEST_DEFAULT;
            break;
        case '0' ... '3':
            loglvl = p[1] - '0';
            break;
        }
        p += 3;
    }

    if ( loglvl == -1 )
        loglvl = XENLOG_DEFAULT;

    *pp = p;

    return ((atomic_read(&print_everything) != 0) ||
            (loglvl < lower_thresh) ||
            ((loglvl < upper_thresh) && printk_ratelimit()));
} 

static int parse_console_timestamps(const char *s)
{
    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_con_timestamp_mode = TSM_NONE;
        return 0;
    case 1:
        opt_con_timestamp_mode = TSM_DATE;
        return 0;
    }
    if ( *s == '\0' || /* Compat for old booleanparam() */
         !strcmp(s, "date") )
        opt_con_timestamp_mode = TSM_DATE;
    else if ( !strcmp(s, "datems") )
        opt_con_timestamp_mode = TSM_DATE_MS;
    else if ( !strcmp(s, "boot") )
        opt_con_timestamp_mode = TSM_BOOT;
    else if ( !strcmp(s, "none") )
        opt_con_timestamp_mode = TSM_NONE;
    else
        return -EINVAL;

    return 0;
}

static void printk_start_of_line(const char *prefix)
{
    struct tm tm;
    char tstr[32];
    uint64_t sec, nsec;

    __putstr(prefix);

    switch ( opt_con_timestamp_mode )
    {
    case TSM_DATE:
    case TSM_DATE_MS:
        tm = wallclock_time(&nsec);

        if ( tm.tm_mday == 0 )
            return;

        if ( opt_con_timestamp_mode == TSM_DATE )
            snprintf(tstr, sizeof(tstr), "[%04u-%02u-%02u %02u:%02u:%02u] ",
                     1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        else
            snprintf(tstr, sizeof(tstr),
                     "[%04u-%02u-%02u %02u:%02u:%02u.%03"PRIu64"] ",
                     1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, nsec / 1000000);
        break;

    case TSM_BOOT:
        sec = NOW();
        nsec = do_div(sec, 1000000000);

        snprintf(tstr, sizeof(tstr), "[%5"PRIu64".%06"PRIu64"] ",
                 sec, nsec / 1000);
        break;

    case TSM_NONE:
    default:
        return;
    }

    __putstr(tstr);
}

static void vprintk_common(const char *prefix, const char *fmt, va_list args)
{
    struct vps {
        bool_t continued, do_print;
    }            *state;
    static DEFINE_PER_CPU(struct vps, state);
    static char   buf[1024];
    char         *p, *q;
    unsigned long flags;

    /* console_lock can be acquired recursively from __printk_ratelimit(). */
    local_irq_save(flags);
    spin_lock_recursive(&console_lock);
    state = &this_cpu(state);

    (void)vsnprintf(buf, sizeof(buf), fmt, args);

    p = buf;

    while ( (q = strchr(p, '\n')) != NULL )
    {
        *q = '\0';
        if ( !state->continued )
            state->do_print = printk_prefix_check(p, &p);
        if ( state->do_print )
        {
            if ( !state->continued )
                printk_start_of_line(prefix);
            __putstr(p);
            __putstr("\n");
        }
        state->continued = 0;
        p = q + 1;
    }

    if ( *p != '\0' )
    {
        if ( !state->continued )
            state->do_print = printk_prefix_check(p, &p);
        if ( state->do_print )
        {
            if ( !state->continued )
                printk_start_of_line(prefix);
            __putstr(p);
        }
        state->continued = 1;
    }

    spin_unlock_recursive(&console_lock);
    local_irq_restore(flags);
}

void printk(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintk_common("(XEN) ", fmt, args);
    va_end(args);
}

void guest_printk(const struct domain *d, const char *fmt, ...)
{
    va_list args;
    char prefix[16];

    snprintf(prefix, sizeof(prefix), "(d%d) ", d->domain_id);

    va_start(args, fmt);
    vprintk_common(prefix, fmt, args);
    va_end(args);
}

void __init console_init_preirq(void)
{
    char *p;
    int sh;

    serial_init_preirq();

    /* Where should console output go? */
    for ( p = opt_console; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( !strncmp(p, "vga", 3) )
            video_init();
#ifdef CONFIG_X86
	else if ( !strncmp(p, "pv", 2) )
            pv_console_init();
        else if ( !strncmp(p, "xen", 3) )
            opt_console_xen = true;
#endif
        else if ( !strncmp(p, "none", 4) )
            continue;
        else if ( (sh = serial_parse_handle(p)) >= 0 )
        {
            sercon_handle = sh;
            serial_steal_fn = NULL;
        }
        else
        {
            char *q = strchr(p, ',');
            if ( q != NULL )
                *q = '\0';
            printk("Bad console= option '%s'\n", p);
            if ( q != NULL )
                *q = ',';
        }
    }

    serial_set_rx_handler(sercon_handle, serial_rx);

#ifdef CONFIG_X86
    pv_console_set_rx_handler(serial_rx);
#endif

    /* HELLO WORLD --- start-of-day banner text. */
    spin_lock(&console_lock);
    __putstr(xen_banner());
    spin_unlock(&console_lock);
    printk("Xen version %d.%d%s (%s@%s) (%s) debug=%c " gcov_string " %s\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_compile_by(), xen_compile_domain(),
           xen_compiler(), debug_build() ? 'y' : 'n', xen_compile_date());
    printk("Latest ChangeSet: %s\n", xen_changeset());

    if ( opt_sync_console )
    {
        serial_start_sync(sercon_handle);
        add_taint(TAINT_SYNC_CONSOLE);
        printk("Console output is synchronous.\n");
        warning_add(warning_sync_console);
    }
}

void __init console_init_ring(void)
{
    char *ring;
    unsigned int i, order, memflags;
    unsigned long flags;

    if ( !opt_conring_size )
        return;

    order = get_order_from_bytes(max(opt_conring_size, conring_size));
    memflags = MEMF_bits(crashinfo_maxaddr_bits);
    while ( (ring = alloc_xenheap_pages(order, memflags)) == NULL )
    {
        BUG_ON(order == 0);
        order--;
    }
    opt_conring_size = PAGE_SIZE << order;

    spin_lock_irqsave(&console_lock, flags);
    for ( i = conringc ; i != conringp; i++ )
        ring[i & (opt_conring_size - 1)] = conring[i & (conring_size - 1)];
    conring = ring;
    smp_wmb(); /* Allow users of console_force_unlock() to see larger buffer. */
    conring_size = opt_conring_size;
    spin_unlock_irqrestore(&console_lock, flags);

    printk("Allocated console ring of %u KiB.\n", opt_conring_size >> 10);
}

void __init console_init_postirq(void)
{
    serial_init_postirq();

#ifdef CONFIG_X86
    pv_console_init_postirq();
#endif

    if ( conring != _conring )
        return;

    if ( !opt_conring_size )
        opt_conring_size = num_present_cpus() << (9 + xenlog_lower_thresh);

    console_init_ring();
}

void __init console_endboot(void)
{
    printk("Std. Loglevel: %s", loglvl_str(xenlog_lower_thresh));
    if ( xenlog_upper_thresh != xenlog_lower_thresh )
        printk(" (Rate-limited: %s)", loglvl_str(xenlog_upper_thresh));
    printk("\nGuest Loglevel: %s", loglvl_str(xenlog_guest_lower_thresh));
    if ( xenlog_guest_upper_thresh != xenlog_guest_lower_thresh )
        printk(" (Rate-limited: %s)", loglvl_str(xenlog_guest_upper_thresh));
    printk("\n");

    warning_print();

    video_endboot();

    /*
     * If user specifies so, we fool the switch routine to redirect input
     * straight back to Xen. I use this convoluted method so we still print
     * a useful 'how to switch' message.
     */
    if ( opt_conswitch[1] == 'x' )
        xen_rx = !xen_rx;

    register_keyhandler('w', dump_console_ring_key,
                        "synchronously dump console ring buffer (dmesg)", 0);
    register_irq_keyhandler('+', &do_inc_thresh,
                            "increase log level threshold", 0);
    register_irq_keyhandler('-', &do_dec_thresh,
                            "decrease log level threshold", 0);
    register_irq_keyhandler('G', &do_toggle_guest,
                            "toggle host/guest log level adjustment", 0);

    /* Serial input is directed to DOM0 by default. */
    switch_serial_input();
}

int __init console_has(const char *device)
{
    char *p;

    for ( p = opt_console; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, device, strlen(device)) == 0 )
            return 1;
    }

    return 0;
}

void console_start_log_everything(void)
{
    serial_start_log_everything(sercon_handle);
    atomic_inc(&print_everything);
}

void console_end_log_everything(void)
{
    serial_end_log_everything(sercon_handle);
    atomic_dec(&print_everything);
}

unsigned long console_lock_recursive_irqsave(void)
{
    unsigned long flags;

    local_irq_save(flags);
    spin_lock_recursive(&console_lock);

    return flags;
}

void console_unlock_recursive_irqrestore(unsigned long flags)
{
    spin_unlock_recursive(&console_lock);
    local_irq_restore(flags);
}

void console_force_unlock(void)
{
    watchdog_disable();
    spin_lock_init(&console_lock);
    serial_force_unlock(sercon_handle);
    console_locks_busted = 1;
    console_start_sync();
}

void console_start_sync(void)
{
    atomic_inc(&print_everything);
    serial_start_sync(sercon_handle);
}

void console_end_sync(void)
{
    serial_end_sync(sercon_handle);
    atomic_dec(&print_everything);
}

/*
 * printk rate limiting, lifted from Linux.
 *
 * This enforces a rate limit: not more than one kernel message
 * every printk_ratelimit_ms (millisecs).
 */
int __printk_ratelimit(int ratelimit_ms, int ratelimit_burst)
{
    static DEFINE_SPINLOCK(ratelimit_lock);
    static unsigned long toks = 10 * 5 * 1000;
    static unsigned long last_msg;
    static int missed;
    unsigned long flags;
    unsigned long long now = NOW(); /* ns */
    unsigned long ms;

    do_div(now, 1000000);
    ms = (unsigned long)now;

    spin_lock_irqsave(&ratelimit_lock, flags);
    toks += ms - last_msg;
    last_msg = ms;
    if ( toks > (ratelimit_burst * ratelimit_ms))
        toks = ratelimit_burst * ratelimit_ms;
    if ( toks >= ratelimit_ms )
    {
        int lost = missed;
        missed = 0;
        toks -= ratelimit_ms;
        spin_unlock(&ratelimit_lock);
        if ( lost )
        {
            char lost_str[8];
            snprintf(lost_str, sizeof(lost_str), "%d", lost);
            /* console_lock may already be acquired by printk(). */
            spin_lock_recursive(&console_lock);
            printk_start_of_line("(XEN) ");
            __putstr("printk: ");
            __putstr(lost_str);
            __putstr(" messages suppressed.\n");
            spin_unlock_recursive(&console_lock);
        }
        local_irq_restore(flags);
        return 1;
    }
    missed++;
    spin_unlock_irqrestore(&ratelimit_lock, flags);
    return 0;
}

/* minimum time in ms between messages */
static int __read_mostly printk_ratelimit_ms = 5 * 1000;

/* number of messages we send before ratelimiting */
static int __read_mostly printk_ratelimit_burst = 10;

int printk_ratelimit(void)
{
    return __printk_ratelimit(printk_ratelimit_ms, printk_ratelimit_burst);
}

/*
 * **************************************************************
 * *************** Serial console ring buffer *******************
 * **************************************************************
 */

#ifdef DEBUG_TRACE_DUMP

/* Send output direct to console, or buffer it? */
static volatile int debugtrace_send_to_console;

static char        *debugtrace_buf; /* Debug-trace buffer */
static unsigned int debugtrace_prd; /* Producer index     */
static unsigned int debugtrace_kilobytes = 128, debugtrace_bytes;
static unsigned int debugtrace_used;
static DEFINE_SPINLOCK(debugtrace_lock);
integer_param("debugtrace", debugtrace_kilobytes);

static void debugtrace_dump_worker(void)
{
    if ( (debugtrace_bytes == 0) || !debugtrace_used )
        return;

    printk("debugtrace_dump() starting\n");

    /* Print oldest portion of the ring. */
    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);
    sercon_puts(&debugtrace_buf[debugtrace_prd]);

    /* Print youngest portion of the ring. */
    debugtrace_buf[debugtrace_prd] = '\0';
    sercon_puts(&debugtrace_buf[0]);

    memset(debugtrace_buf, '\0', debugtrace_bytes);

    printk("debugtrace_dump() finished\n");
}

static void debugtrace_toggle(void)
{
    unsigned long flags;

    watchdog_disable();
    spin_lock_irqsave(&debugtrace_lock, flags);

    /*
     * Dump the buffer *before* toggling, in case the act of dumping the
     * buffer itself causes more printk() invocations.
     */
    printk("debugtrace_printk now writing to %s.\n",
           !debugtrace_send_to_console ? "console": "buffer");
    if ( !debugtrace_send_to_console )
        debugtrace_dump_worker();

    debugtrace_send_to_console = !debugtrace_send_to_console;

    spin_unlock_irqrestore(&debugtrace_lock, flags);
    watchdog_enable();

}

void debugtrace_dump(void)
{
    unsigned long flags;

    watchdog_disable();
    spin_lock_irqsave(&debugtrace_lock, flags);

    debugtrace_dump_worker();

    spin_unlock_irqrestore(&debugtrace_lock, flags);
    watchdog_enable();
}

void debugtrace_printk(const char *fmt, ...)
{
    static char    buf[1024];
    static u32 count;

    va_list       args;
    char         *p;
    unsigned long flags;

    if ( debugtrace_bytes == 0 )
        return;

    debugtrace_used = 1;

    spin_lock_irqsave(&debugtrace_lock, flags);

    ASSERT(debugtrace_buf[debugtrace_bytes - 1] == 0);

    snprintf(buf, sizeof(buf), "%u ", ++count);

    va_start(args, fmt);
    (void)vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, args);
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

static void debugtrace_key(unsigned char key)
{
    debugtrace_toggle();
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
    debugtrace_buf = alloc_xenheap_pages(order, 0);
    ASSERT(debugtrace_buf != NULL);

    memset(debugtrace_buf, '\0', bytes);

    debugtrace_bytes = bytes;

    register_keyhandler('T', debugtrace_key,
                        "toggle debugtrace to console/buffer", 0);

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
    unsigned long flags;
    static DEFINE_SPINLOCK(lock);
    static char buf[128];
    
    debugtrace_dump();

    /* Protects buf[] and ensure multi-line message prints atomically. */
    spin_lock_irqsave(&lock, flags);

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    console_start_sync();
    printk("\n****************************************\n");
    printk("Panic on CPU %d:\n", smp_processor_id());
    printk("%s\n", buf);
    printk("****************************************\n\n");
    if ( opt_noreboot )
        printk("Manual reset required ('noreboot' specified)\n");
    else
#ifdef CONFIG_X86
        printk("%s in five seconds...\n", pv_shim ? "Crash" : "Reboot");
#else
        printk("Reboot in five seconds...\n");
#endif

    spin_unlock_irqrestore(&lock, flags);

    debugger_trap_immediate();

#ifdef CONFIG_KEXEC
    kexec_crash();
#endif

    if ( opt_noreboot )
        machine_halt();
    else
        machine_restart(5000);
}

/*
 * **************************************************************
 * ****************** Console suspend/resume ********************
 * **************************************************************
 */

static void suspend_steal_fn(const char *str) { }
static int suspend_steal_id;

int console_suspend(void)
{
    suspend_steal_id = console_steal(sercon_handle, suspend_steal_fn);
    serial_suspend();
    return 0;
}

int console_resume(void)
{
    serial_resume();
    console_giveback(suspend_steal_id);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

