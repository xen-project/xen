/*
 * Standalone EHCI USB debug driver
 *
 * Hardware interface code based on the respective early console driver in
 * Linux; see the Linux source for authorship and copyrights.
 */

#include <xen/console.h>
#include <xen/delay.h>
#include <xen/errno.h>
#include <xen/pci.h>
#include <xen/serial.h>
#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include <public/physdev.h>

/* #define DBGP_DEBUG */

/* EHCI register interface, corresponds to EHCI Revision 0.95 specification */

/* Section 2.2 Host Controller Capability Registers */
struct ehci_caps {
    /*
     * These fields are specified as 8 and 16 bit registers,
     * but some hosts can't perform 8 or 16 bit PCI accesses.
     * some hosts treat caplength and hciversion as parts of a 32-bit
     * register, others treat them as two separate registers, this
     * affects the memory map for big endian controllers.
     */
    u32 hc_capbase;
#define HC_LENGTH(p)      (0x00ff & (p)) /* bits 7:0 / offset 0x00 */
#define HC_VERSION(p)     (0xffff & ((p) >> 16)) /* bits 31:16 / offset 0x02 */

    u32 hcs_params;       /* HCSPARAMS - offset 0x04 */
#define HCS_DEBUG_PORT(p) (((p) >> 20) & 0xf) /* bits 23:20, debug port? */
#define HCS_INDICATOR(p)  ((p) & (1 << 16))   /* true: has port indicators */
#define HCS_N_CC(p)       (((p) >> 12) & 0xf) /* bits 15:12, #companion HCs */
#define HCS_N_PCC(p)      (((p) >> 8) & 0xf)  /* bits 11:8, ports per CC */
#define HCS_PORTROUTED(p) ((p) & (1 << 7))    /* true: port routing */
#define HCS_PPC(p)        ((p) & (1 << 4))    /* true: port power control */
#define HCS_N_PORTS(p)    (((p) >> 0) & 0xf)  /* bits 3:0, ports on HC */

    u32 hcc_params;       /* HCCPARAMS - offset 0x08 */
/* EHCI 1.1 addendum */
#define HCC_32FRAME_PERIODIC_LIST(p) ((p) & (1 << 19))
#define HCC_PER_PORT_CHANGE_EVENT(p) ((p) & (1 << 18))
#define HCC_LPM(p)        ((p) & (1 << 17))
#define HCC_HW_PREFETCH(p) ((p) & (1 << 16))
#define HCC_EXT_CAPS(p)   (((p) >> 8) & 0xff) /* for pci extended caps */
#define HCC_ISOC_CACHE(p) ((p) & (1 << 7))    /* true: can cache isoc frame */
#define HCC_ISOC_THRES(p) (((p) >> 4) & 0x7)  /* bits 6:4, uframes cached */
#define HCC_CANPARK(p)    ((p) & (1 << 2))    /* true: can park on async qh */
#define HCC_PGM_FRAMELISTLEN(p) ((p) & (1 << 1)) /* true: periodic_size changes */
#define HCC_64BIT_ADDR(p) ((p) & 1)           /* true: can use 64-bit addr */

    u8  portroute[8];     /* nibbles for routing - offset 0x0C */
};

/* Section 2.3 Host Controller Operational Registers */
struct ehci_regs {
    /* USBCMD: offset 0x00 */
    u32 command;

/* EHCI 1.1 addendum */
#define CMD_HIRD        (0xf << 24) /* host initiated resume duration */
#define CMD_PPCEE       (1 << 15)   /* per port change event enable */
#define CMD_FSP         (1 << 14)   /* fully synchronized prefetch */
#define CMD_ASPE        (1 << 13)   /* async schedule prefetch enable */
#define CMD_PSPE        (1 << 12)   /* periodic schedule prefetch enable */
/* 23:16 is r/w intr rate, in microframes; default "8" == 1/msec */
#define CMD_PARK        (1 << 11)   /* enable "park" on async qh */
#define CMD_PARK_CNT(c) (((c) >> 8) & 3) /* how many transfers to park for */
#define CMD_LRESET      (1 << 7)    /* partial reset (no ports, etc) */
#define CMD_IAAD        (1 << 6)    /* "doorbell" interrupt async advance */
#define CMD_ASE         (1 << 5)    /* async schedule enable */
#define CMD_PSE         (1 << 4)    /* periodic schedule enable */
/* 3:2 is periodic frame list size */
#define CMD_RESET       (1 << 1)    /* reset HC not bus */
#define CMD_RUN         (1 << 0)    /* start/stop HC */

    /* USBSTS: offset 0x04 */
    u32 status;
#define STS_PPCE_MASK   (0xff << 16) /* Per-Port change event 1-16 */
#define STS_ASS         (1 << 15)   /* Async Schedule Status */
#define STS_PSS         (1 << 14)   /* Periodic Schedule Status */
#define STS_RECL        (1 << 13)   /* Reclamation */
#define STS_HALT        (1 << 12)   /* Not running (any reason) */
/* some bits reserved */
    /* these STS_* flags are also intr_enable bits (USBINTR) */
#define STS_IAA         (1 << 5)    /* Interrupted on async advance */
#define STS_FATAL       (1 << 4)    /* such as some PCI access errors */
#define STS_FLR         (1 << 3)    /* frame list rolled over */
#define STS_PCD         (1 << 2)    /* port change detect */
#define STS_ERR         (1 << 1)    /* "error" completion (overflow, ...) */
#define STS_INT         (1 << 0)    /* "normal" completion (short, ...) */

    /* USBINTR: offset 0x08 */
    u32 intr_enable;

    /* FRINDEX: offset 0x0C */
    u32 frame_index;    /* current microframe number */
    /* CTRLDSSEGMENT: offset 0x10 */
    u32 segment;    /* address bits 63:32 if needed */
    /* PERIODICLISTBASE: offset 0x14 */
    u32 frame_list;    /* points to periodic list */
    /* ASYNCLISTADDR: offset 0x18 */
    u32 async_next;    /* address of next async queue head */

    u32 reserved[9];

    /* CONFIGFLAG: offset 0x40 */
    u32 configured_flag;
#define FLAG_CF         (1 << 0)    /* true: we'll support "high speed" */

    /* PORTSC: offset 0x44 */
    u32 port_status[0];    /* up to N_PORTS */
/* EHCI 1.1 addendum */
#define PORTSC_SUSPEND_STS_ACK   0
#define PORTSC_SUSPEND_STS_NYET  1
#define PORTSC_SUSPEND_STS_STALL 2
#define PORTSC_SUSPEND_STS_ERR   3

#define PORT_DEV_ADDR   (0x7f << 25) /* device address */
#define PORT_SSTS       (0x3 << 23)  /* suspend status */
/* 31:23 reserved */
#define PORT_WKOC_E     (1 << 22)    /* wake on overcurrent (enable) */
#define PORT_WKDISC_E   (1 << 21)    /* wake on disconnect (enable) */
#define PORT_WKCONN_E   (1 << 20)    /* wake on connect (enable) */
/* 19:16 for port testing */
#define PORT_TEST(x)    (((x) & 0xf) << 16) /* Port Test Control */
#define PORT_TEST_PKT   PORT_TEST(0x4) /* Port Test Control - packet test */
#define PORT_TEST_FORCE PORT_TEST(0x5) /* Port Test Control - force enable */
#define PORT_LED_OFF    (0 << 14)
#define PORT_LED_AMBER  (1 << 14)
#define PORT_LED_GREEN  (2 << 14)
#define PORT_LED_MASK   (3 << 14)
#define PORT_OWNER      (1 << 13)    /* true: companion hc owns this port */
#define PORT_POWER      (1 << 12)    /* true: has power (see PPC) */
#define PORT_USB11(x)   (((x) & (3 << 10)) == (1 << 10)) /* USB 1.1 device */
/* 11:10 for detecting lowspeed devices (reset vs release ownership) */
/* 9 reserved */
#define PORT_LPM        (1 << 9)     /* LPM transaction */
#define PORT_RESET      (1 << 8)     /* reset port */
#define PORT_SUSPEND    (1 << 7)     /* suspend port */
#define PORT_RESUME     (1 << 6)     /* resume it */
#define PORT_OCC        (1 << 5)     /* over current change */
#define PORT_OC         (1 << 4)     /* over current active */
#define PORT_PEC        (1 << 3)     /* port enable change */
#define PORT_PE         (1 << 2)     /* port enable */
#define PORT_CSC        (1 << 1)     /* connect status change */
#define PORT_CONNECT    (1 << 0)     /* device connected */
#define PORT_RWC_BITS   (PORT_CSC | PORT_PEC | PORT_OCC)
};

/*
 * Appendix C, Debug port ... intended for use with special "debug devices"
 * that can help if there's no serial console.  (nonstandard enumeration.)
 */
struct ehci_dbg_port {
    u32 control;
#define DBGP_OWNER      (1 << 30)
#define DBGP_ENABLED    (1 << 28)
#define DBGP_DONE       (1 << 16)
#define DBGP_INUSE      (1 << 10)
#define DBGP_ERRCODE(x) (((x) >> 7) & 0x07)
# define DBGP_ERR_BAD    1
# define DBGP_ERR_SIGNAL 2
#define DBGP_ERROR      (1 << 6)
#define DBGP_GO         (1 << 5)
#define DBGP_OUT        (1 << 4)
#define DBGP_LEN        (0xf << 0)
#define DBGP_CLAIM      (DBGP_OWNER | DBGP_ENABLED | DBGP_INUSE)
    u32 pids;
#define DBGP_PID_GET(x)         (((x) >> 16) & 0xff)
#define DBGP_PID_SET(data, tok) (((data) << 8) | (tok))
    u32 data03;
    u32 data47;
    u32 address;
#define DBGP_EPADDR(dev, ep) (((dev) << 8) | (ep))
};

/* CONTROL REQUEST SUPPORT */

/*
 * USB directions
 *
 * This bit flag is used in endpoint descriptors' bEndpointAddress field.
 * It's also one of three fields in control requests bRequestType.
 */
#define USB_DIR_OUT 0           /* to device */
#define USB_DIR_IN  0x80        /* to host */

/*
 * USB types, the second of three bRequestType fields
 */
#define USB_TYPE_MASK     (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS    (0x01 << 5)
#define USB_TYPE_VENDOR   (0x02 << 5)
#define USB_TYPE_RESERVED (0x03 << 5)

/*
 * USB recipients, the third of three bRequestType fields
 */
#define USB_RECIP_MASK      0x1f
#define USB_RECIP_DEVICE    0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT  0x02
#define USB_RECIP_OTHER     0x03
/* From Wireless USB 1.0 */
#define USB_RECIP_PORT      0x04
#define USB_RECIP_RPIPE     0x05

/*
 * Standard requests, for the bRequest field of a SETUP packet.
 *
 * These are qualified by the bRequestType field, so that for example
 * TYPE_CLASS or TYPE_VENDOR specific feature flags could be retrieved
 * by a GET_STATUS request.
 */
#define USB_REQ_GET_STATUS        0x00
#define USB_REQ_CLEAR_FEATURE     0x01
#define USB_REQ_SET_FEATURE       0x03
#define USB_REQ_SET_ADDRESS       0x05
#define USB_REQ_GET_DESCRIPTOR    0x06
#define USB_REQ_SET_DESCRIPTOR    0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE     0x0A
#define USB_REQ_SET_INTERFACE     0x0B
#define USB_REQ_SYNCH_FRAME       0x0C

#define USB_DEVICE_DEBUG_MODE        6    /* (special devices only) */

/**
 * struct usb_ctrlrequest - SETUP data for a USB device control request
 * @bRequestType: matches the USB bmRequestType field
 * @bRequest: matches the USB bRequest field
 * @wValue: matches the USB wValue field (le16 byte order)
 * @wIndex: matches the USB wIndex field (le16 byte order)
 * @wLength: matches the USB wLength field (le16 byte order)
 *
 * This structure is used to send control requests to a USB device.  It matches
 * the different fields of the USB 2.0 Spec section 9.3, table 9-2.  See the
 * USB spec for a fuller description of the different fields, and what they are
 * used for.
 *
 * Note that the driver for any interface can issue control requests.
 * For most devices, interfaces don't coordinate with each other, so
 * such requests may be made at any time.
 */
struct __packed usb_ctrlrequest {
    u8 bRequestType;
    u8 bRequest;
    __le16 wValue;
    __le16 wIndex;
    __le16 wLength;
};

/* USB_DT_DEBUG: for special highspeed devices, replacing serial console */

#define USB_DT_DEBUG    0x0a

struct __packed usb_debug_descriptor {
    u8 bLength;
    u8 bDescriptorType;
    /* bulk endpoints with 8 byte maxpacket */
    u8 bDebugInEndpoint;
    u8 bDebugOutEndpoint;
};

#define USB_DEBUG_DEVNUM 127

/*
 * USB Packet IDs (PIDs)
 */

/* token */
#define USB_PID_OUT           0xe1
#define USB_PID_IN            0x69
#define USB_PID_SOF           0xa5
#define USB_PID_SETUP         0x2d
/* handshake */
#define USB_PID_ACK           0xd2
#define USB_PID_NAK           0x5a
#define USB_PID_STALL         0x1e
#define USB_PID_NYET          0x96
/* data */
#define USB_PID_DATA0         0xc3
#define USB_PID_DATA1         0x4b
#define USB_PID_DATA2         0x87
#define USB_PID_MDATA         0x0f
/* Special */
#define USB_PID_PREAMBLE      0x3c
#define USB_PID_ERR           0x3c
#define USB_PID_SPLIT         0x78
#define USB_PID_PING          0xb4
#define USB_PID_UNDEF_0       0xf0

#define PCI_CLASS_SERIAL_USB_EHCI 0x0c0320
#define PCI_CAP_ID_EHCI_DEBUG     0x0a

#define HUB_ROOT_RESET_TIME   50    /* times are in msec */
#define HUB_SHORT_RESET_TIME  10
#define HUB_LONG_RESET_TIME   200
#define HUB_RESET_TIMEOUT     500

#define DBGP_MAX_PACKET       8
#define DBGP_LOOPS            1000
#define DBGP_TIMEOUT          (250 * 1000) /* us */
#define DBGP_CHECK_INTERVAL   100 /* us */
/* This one can be set arbitrarily - only affects input responsiveness: */
#define DBGP_IDLE_INTERVAL    100 /* ms */

struct ehci_dbgp {
    struct ehci_dbg_port __iomem *ehci_debug;
    enum dbgp_state {
        dbgp_idle,
        dbgp_out,
        dbgp_in,
        dbgp_ctrl,
        dbgp_unsafe /* cannot use debug device during EHCI reset */
    } state;
    unsigned int phys_port;
    struct {
        unsigned int endpoint;
        unsigned int chunk;
        char buf[DBGP_MAX_PACKET];
    } out, in;
    unsigned long timeout;
    struct timer timer;
    spinlock_t *lock;
    bool_t reset_run;
    u8 bus, slot, func, bar;
    u16 pci_cr;
    u32 bar_val;
    unsigned int cap;
    struct ehci_regs __iomem *ehci_regs;
    struct ehci_caps __iomem *ehci_caps;
};

static int ehci_dbgp_external_startup(struct ehci_dbgp *);

static void ehci_dbgp_status(struct ehci_dbgp *dbgp, const char *str)
{
#ifdef DBGP_DEBUG
#define dbgp_printk printk
    if ( !dbgp->ehci_debug )
        return;
    dbgp_printk("dbgp: %s\n", str);
    dbgp_printk("  debug control: %08x\n", readl(&dbgp->ehci_debug->control));
    dbgp_printk("  EHCI cmd     : %08x\n", readl(&dbgp->ehci_regs->command));
    dbgp_printk("  EHCI conf flg: %08x\n",
                readl(&dbgp->ehci_regs->configured_flag));
    dbgp_printk("  EHCI status  : %08x\n", readl(&dbgp->ehci_regs->status));
    dbgp_printk("  EHCI portsc  : %08x\n",
                readl(&dbgp->ehci_regs->port_status[dbgp->phys_port - 1]));
#endif
}

#ifndef DBGP_DEBUG
static inline __attribute__ ((format (printf, 1, 2))) void
dbgp_printk(const char *fmt, ...) { }
#endif

static inline u32 dbgp_len_update(u32 x, u32 len)
{
    return (x & ~DBGP_LEN) | (len & DBGP_LEN) | DBGP_OUT;
}

static inline u32 dbgp_pid_write_update(u32 x, u32 tok)
{
    static u8 data0 = USB_PID_DATA1;

    data0 ^= USB_PID_DATA0 ^ USB_PID_DATA1;
    return (x & 0xffff0000) | (data0 << 8) | (tok & 0xff);
}

static inline u32 dbgp_pid_read_update(u32 x, u32 tok)
{
    return (x & 0xffffff00) | (tok & 0xff);
}

static inline void dbgp_set_data(struct ehci_dbg_port __iomem *ehci_debug,
                                 const void *buf, unsigned int size)
{
    const unsigned char *bytes = buf;
    u32 lo = 0, hi = 0;
    unsigned int i;

    for ( i = 0; i < 4 && i < size; i++ )
        lo |= bytes[i] << (8 * i);
    for ( ; i < 8 && i < size; i++ )
        hi |= bytes[i] << (8 * (i - 4));
    writel(lo, &ehci_debug->data03);
    writel(hi, &ehci_debug->data47);
}

static inline void dbgp_get_data(struct ehci_dbg_port __iomem *ehci_debug,
                                 void *buf, int size)
{
    unsigned char *bytes = buf;
    u32 lo = readl(&ehci_debug->data03);
    u32 hi = readl(&ehci_debug->data47);
    unsigned int i;

    for ( i = 0; i < 4 && i < size; i++ )
        bytes[i] = (lo >> (8 * i)) & 0xff;
    for ( ; i < 8 && i < size; i++ )
        bytes[i] = (hi >> (8 * (i - 4))) & 0xff;
}

static void dbgp_issue_command(struct ehci_dbgp *dbgp, u32 ctrl,
                               enum dbgp_state state)
{
    u32 cmd = readl(&dbgp->ehci_regs->command);

    if ( unlikely(!(cmd & CMD_RUN)) )
    {
        /*
         * If the EHCI controller is not in the run state do extended
         * checks to see if ACPI or some other initialization also
         * reset the EHCI debug port.
         */
        u32 ctrl = readl(&dbgp->ehci_debug->control);

        if ( ctrl & DBGP_ENABLED )
        {
            cmd |= CMD_RUN;
            writel(cmd, &dbgp->ehci_regs->command);
            dbgp->reset_run = 1;
        }
        else if ( dbgp->state != dbgp_unsafe )
        {
            dbgp->state = dbgp_unsafe;
            ehci_dbgp_external_startup(dbgp);
        }
    }

    writel(ctrl | DBGP_GO, &dbgp->ehci_debug->control);
    dbgp->timeout = DBGP_TIMEOUT;
    if ( dbgp->state != dbgp_unsafe )
        dbgp->state = state;
}

static int dbgp_check_for_completion(struct ehci_dbgp *dbgp,
                                     unsigned int interval, u8 *ppid)
{
    u32 ctrl;
    int ret;

    if ( dbgp->state == dbgp_idle )
        return 0;

    ctrl = readl(&dbgp->ehci_debug->control) & ~DBGP_GO;
    if ( !(ctrl & DBGP_DONE) )
    {
        if ( dbgp->timeout > interval )
            dbgp->timeout -= interval;
        else if ( interval )
        {
            /* See the timeout related comment in dbgp_wait_until_done(). */
            dbgp->state = dbgp_unsafe;
            dbgp->timeout = 0;
        }
        return -DBGP_TIMEOUT;
    }

    if ( ctrl & DBGP_ERROR )
    {
        ret = -DBGP_ERRCODE(ctrl);
        if ( ret == -DBGP_ERR_BAD && dbgp->timeout > interval )
            ctrl |= DBGP_GO;
    }
    else
    {
        u8 pid = DBGP_PID_GET(readl(&dbgp->ehci_debug->pids));

        ret = ctrl & DBGP_LEN;
        if ( ppid )
            *ppid = pid;
        else if ( dbgp->state == dbgp_in )
        {
            dbgp_get_data(dbgp->ehci_debug, dbgp->in.buf, ret);
            dbgp->in.chunk = ret;
        }
        else if ( pid == USB_PID_NAK && dbgp->timeout > interval )
            ctrl |= DBGP_GO;
    }

    writel(ctrl, &dbgp->ehci_debug->control);
    if ( ctrl & DBGP_GO )
    {
        dbgp->timeout -= interval;
        return -DBGP_TIMEOUT;
    }

    if ( unlikely(dbgp->reset_run) )
    {
        writel(readl(&dbgp->ehci_regs->command) & ~CMD_RUN,
               &dbgp->ehci_regs->command);
        dbgp->reset_run = 0;
    }

    if ( dbgp->state != dbgp_unsafe )
        dbgp->state = dbgp_idle;

    return ret;
}

static int dbgp_wait_until_complete(struct ehci_dbgp *dbgp, u8 *ppid)
{
    unsigned int loop = DBGP_TIMEOUT;
    int ret;

    do {
        ret = dbgp_check_for_completion(dbgp, 0, ppid);
        if ( ret != -DBGP_TIMEOUT )
            break;
        udelay(1);
    } while ( --loop );

    if ( !ppid && !loop )
        dbgp->state = dbgp_unsafe;

    return ret;
}

static inline void dbgp_mdelay(unsigned int ms)
{
    while ( ms-- )
    {
        unsigned int i;

        for ( i = 0; i < 1000; i++ )
            outb(0x1, 0x80);
    }
}

static void dbgp_breathe(void)
{
    /* Sleep to give the debug port a chance to breathe. */
    dbgp_mdelay(1);
}

static int dbgp_wait_until_done(struct ehci_dbgp *dbgp, u32 ctrl,
                                unsigned int loop)
{
    int ret;

    dbgp->timeout = 0;

    for ( ; ; writel(ctrl | DBGP_GO, &dbgp->ehci_debug->control) )
    {
        u8 pid;

        ret = dbgp_wait_until_complete(dbgp, &pid);
        if ( ret < 0 )
        {
            /*
             * A -DBGP_TIMEOUT failure here means the device has failed,
             * perhaps because it was unplugged, in which case we do not
             * want to hang the system so the dbgp will be marked as unsafe
             * to use. EHCI reset is the only way to recover if you unplug
             * the dbgp device.
             */
            if ( ret == -DBGP_TIMEOUT )
                dbgp->state = dbgp_unsafe;
            if ( ret != -DBGP_ERR_BAD || !--loop )
                break;
        }
        else
        {
            /*
             * If the port is getting full or it has dropped data
             * start pacing ourselves, not necessary but it's friendly.
             */
            if ( pid == USB_PID_NAK || pid == USB_PID_NYET )
                dbgp_breathe();

            /* If we got a NACK, reissue the transmission. */
            if ( pid != USB_PID_NAK || !--loop )
                break;
        }
    }

    return ret;
}

static int dbgp_bulk_write(struct ehci_dbgp *dbgp,
                           unsigned int devnum, unsigned int endpoint,
                           const void *bytes, unsigned int size, u32 *pctrl)
{
    u32 addr, pids, ctrl;

    if ( size > DBGP_MAX_PACKET )
        return -EINVAL;

    addr = DBGP_EPADDR(devnum, endpoint);
    pids = dbgp_pid_write_update(readl(&dbgp->ehci_debug->pids), USB_PID_OUT);
    ctrl = dbgp_len_update(readl(&dbgp->ehci_debug->control), size);
    if ( pctrl )
        *pctrl = ctrl;

    dbgp_set_data(dbgp->ehci_debug, bytes, size);
    writel(addr, &dbgp->ehci_debug->address);
    writel(pids, &dbgp->ehci_debug->pids);
    dbgp_issue_command(dbgp, ctrl, dbgp_out);

    return 0;
}

static int dbgp_bulk_read(struct ehci_dbgp *dbgp,
                          unsigned int devnum, unsigned int endpoint,
                          unsigned int size, u32 *pctrl)
{
    u32 addr, pids, ctrl;

    if ( size > DBGP_MAX_PACKET )
        return -EINVAL;

    addr = DBGP_EPADDR(devnum, endpoint);
    pids = dbgp_pid_read_update(readl(&dbgp->ehci_debug->pids), USB_PID_IN);
    ctrl = readl(&dbgp->ehci_debug->control) & ~DBGP_OUT;

    writel(addr, &dbgp->ehci_debug->address);
    writel(pids, &dbgp->ehci_debug->pids);
    if ( likely(!pctrl) )
        dbgp_issue_command(dbgp, ctrl, dbgp_in);
    else
        dbgp_issue_command(dbgp, *pctrl = ctrl, dbgp_ctrl);

    return 0;
}

static int dbgp_control_msg(struct ehci_dbgp *dbgp, unsigned int devnum,
                            int requesttype, int request, int value,
                            int index, void *data, unsigned int size)
{
    u32 addr, pids, ctrl;
    struct usb_ctrlrequest req;
    bool_t read = (requesttype & USB_DIR_IN) != 0;
    int ret;

    if ( size > (read ? DBGP_MAX_PACKET : 0) )
        return -EINVAL;

    /* Compute the control message */
    req.bRequestType = requesttype;
    req.bRequest = request;
    req.wValue = cpu_to_le16(value);
    req.wIndex = cpu_to_le16(index);
    req.wLength = cpu_to_le16(size);

    pids = DBGP_PID_SET(USB_PID_DATA0, USB_PID_SETUP);
    addr = DBGP_EPADDR(devnum, 0);
    ctrl = dbgp_len_update(readl(&dbgp->ehci_debug->control), sizeof(req));

    /* Send the setup message */
    dbgp_set_data(dbgp->ehci_debug, &req, sizeof(req));
    writel(addr, &dbgp->ehci_debug->address);
    writel(pids, &dbgp->ehci_debug->pids);
    dbgp_issue_command(dbgp, ctrl, dbgp_ctrl);
    ret = dbgp_wait_until_done(dbgp, ctrl, DBGP_LOOPS);
    if ( ret < 0 )
        return ret;

    /* Read the result */
    ret = dbgp_bulk_read(dbgp, devnum, 0, size, &ctrl);
    if ( !ret )
        ret = dbgp_wait_until_done(dbgp, ctrl, DBGP_LOOPS);
    if ( ret > 0 )
    {
        if ( size > ret )
            size = ret;
        dbgp_get_data(dbgp->ehci_debug, data, size);
    }

    return ret;
}

static unsigned int __init __find_dbgp(u8 bus, u8 slot, u8 func)
{
    u32 class = pci_conf_read32(0, bus, slot, func, PCI_CLASS_REVISION);

    if ( (class >> 8) != PCI_CLASS_SERIAL_USB_EHCI )
        return 0;

    return pci_find_cap_offset(0, bus, slot, func, PCI_CAP_ID_EHCI_DEBUG);
}

static unsigned int __init find_dbgp(struct ehci_dbgp *dbgp,
                                     unsigned int ehci_num)
{
    unsigned int bus, slot, func;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( slot = 0; slot < 32; slot++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                unsigned int cap;

                if ( !pci_device_detect(0, bus, slot, func) )
                {
                    if ( !func )
                        break;
                    continue;
                }

                cap = __find_dbgp(bus, slot, func);
                if ( !cap || ehci_num-- )
                {
                    if ( !func && !(pci_conf_read8(PCI_SBDF(0, bus, slot, func),
                                                   PCI_HEADER_TYPE) & 0x80) )
                        break;
                    continue;
                }

                dbgp->bus = bus;
                dbgp->slot = slot;
                dbgp->func = func;
                return cap;
            }
        }
    }

    return 0;
}

static int ehci_dbgp_startup(struct ehci_dbgp *dbgp)
{
    u32 ctrl, cmd, status;
    unsigned int loop;

    /* Claim ownership, but do not enable yet */
    ctrl = readl(&dbgp->ehci_debug->control);
    ctrl |= DBGP_OWNER;
    ctrl &= ~(DBGP_ENABLED | DBGP_INUSE);
    writel(ctrl, &dbgp->ehci_debug->control);
    udelay(1);

    ehci_dbgp_status(dbgp, "EHCI startup");
    /* Start the EHCI. */
    cmd = readl(&dbgp->ehci_regs->command);
    cmd &= ~(CMD_LRESET | CMD_IAAD | CMD_PSE | CMD_ASE | CMD_RESET);
    cmd |= CMD_RUN;
    writel(cmd, &dbgp->ehci_regs->command);

    /* Ensure everything is routed to the EHCI */
    writel(FLAG_CF, &dbgp->ehci_regs->configured_flag);

    /* Wait until the controller is no longer halted. */
    loop = 1000;
    do {
        status = readl(&dbgp->ehci_regs->status);
        if ( !(status & STS_HALT) )
            break;
        udelay(1);
    } while ( --loop );

    if ( !loop )
    {
        dbgp_printk("EHCI cannot be started\n");
        return -ENODEV;
    }
    dbgp_printk("EHCI started\n");

    return 0;
}

static int ehci_dbgp_controller_reset(struct ehci_dbgp *dbgp)
{
    unsigned int loop = 250 * 1000;
    u32 cmd;

    /* Reset the EHCI controller */
    cmd = readl(&dbgp->ehci_regs->command);
    cmd |= CMD_RESET;
    writel(cmd, &dbgp->ehci_regs->command);
    do {
        cmd = readl(&dbgp->ehci_regs->command);
    } while ( (cmd & CMD_RESET) && --loop );

    if ( !loop )
    {
        dbgp_printk("cannot reset EHCI\n");
        return -1;
    }
    ehci_dbgp_status(dbgp, "ehci reset done");

    return 0;
}

static int ehci_reset_port(struct ehci_dbgp *dbgp, unsigned int port)
{
    u32 portsc, delay_time, delay;

    ehci_dbgp_status(dbgp, "reset port");
    /* Reset the USB debug port. */
    portsc = readl(&dbgp->ehci_regs->port_status[port - 1]);
    portsc &= ~PORT_PE;
    portsc |= PORT_RESET;
    writel(portsc, &dbgp->ehci_regs->port_status[port - 1]);

    delay = HUB_ROOT_RESET_TIME;
    for ( delay_time = 0; delay_time < HUB_RESET_TIMEOUT;
          delay_time += delay )
    {
        dbgp_mdelay(delay);
        portsc = readl(&dbgp->ehci_regs->port_status[port - 1]);
        if (!(portsc & PORT_RESET))
            break;
    }

    if ( portsc & PORT_RESET )
    {
        /* force reset to complete */
        unsigned int loop = 100 * 1000;

        writel(portsc & ~(PORT_RWC_BITS | PORT_RESET),
               &dbgp->ehci_regs->port_status[port - 1]);
        do {
            udelay(1);
            portsc = readl(&dbgp->ehci_regs->port_status[port-1]);
        } while ( (portsc & PORT_RESET) && --loop );
    }

    /* Device went away? */
    if ( !(portsc & PORT_CONNECT) )
        return -ENOTCONN;

    /* bomb out completely if something weird happened */
    if ( portsc & PORT_CSC )
        return -EINVAL;

    /* If we've finished resetting, then break out of the loop */
    if ( !(portsc & PORT_RESET) && (portsc & PORT_PE) )
        return 0;

    return -EBUSY;
}

static int ehci_wait_for_port(struct ehci_dbgp *dbgp, unsigned int port)
{
    u32 status;
    unsigned int reps;

    for ( reps = 0; reps < 300; reps++ )
    {
        status = readl(&dbgp->ehci_regs->status);
        if ( status & STS_PCD )
            break;
        dbgp_mdelay(1);
    }

    return ehci_reset_port(dbgp, port) == 0 ? 0 : -ENOTCONN;
}

/* Return 0 on success
 * Return -ENODEV for any general failure
 * Return -EIO if wait for port fails
 */
static int ehci_dbgp_external_startup(struct ehci_dbgp *dbgp)
{
    unsigned int devnum;
    struct usb_debug_descriptor dbgp_desc;
    int ret;
    u32 ctrl, portsc, cmd;
    unsigned int dbg_port = dbgp->phys_port;
    unsigned int tries = 3;
    unsigned int reset_port_tries = 1;
    bool_t try_hard_once = 1;

try_port_reset_again:
    ret = ehci_dbgp_startup(dbgp);
    if ( ret )
        return ret;

    /* Wait for a device to show up in the debug port */
    ret = ehci_wait_for_port(dbgp, dbg_port);
    if ( ret < 0 )
    {
        portsc = readl(&dbgp->ehci_regs->port_status[dbg_port - 1]);
        if ( !(portsc & PORT_CONNECT) && try_hard_once )
        {
            /*
             * Last ditch effort to try to force enable the debug device by
             * using the packet test EHCI command to try and wake it up.
             */
            try_hard_once = 0;
            cmd = readl(&dbgp->ehci_regs->command);
            cmd &= ~CMD_RUN;
            writel(cmd, &dbgp->ehci_regs->command);
            portsc = readl(&dbgp->ehci_regs->port_status[dbg_port - 1]);
            portsc |= PORT_TEST_PKT;
            writel(portsc, &dbgp->ehci_regs->port_status[dbg_port - 1]);
            ehci_dbgp_status(dbgp, "Trying to force debug port online");
            mdelay(50);
            ehci_dbgp_controller_reset(dbgp);
            goto try_port_reset_again;
        }
        else if ( reset_port_tries-- )
            goto try_port_reset_again;
        dbgp_printk("no device found in debug port\n");
        return -EIO;
    }
    ehci_dbgp_status(dbgp, "wait for port done");

    /* Enable the debug port */
    ctrl = readl(&dbgp->ehci_debug->control);
    ctrl |= DBGP_CLAIM;
    writel(ctrl, &dbgp->ehci_debug->control);
    ctrl = readl(&dbgp->ehci_debug->control);
    if ( (ctrl & DBGP_CLAIM) != DBGP_CLAIM )
    {
        dbgp_printk("no device in debug port\n");
        writel(ctrl & ~DBGP_CLAIM, &dbgp->ehci_debug->control);
        return -ENODEV;
    }
    ehci_dbgp_status(dbgp, "debug port enabled");

    /* Completely transfer the debug device to the debug controller */
    portsc = readl(&dbgp->ehci_regs->port_status[dbg_port - 1]);
    portsc &= ~PORT_PE;
    writel(portsc, &dbgp->ehci_regs->port_status[dbg_port - 1]);

    dbgp_mdelay(100);

try_again:
    /* Find the debug device and make it device number 127 */
    for ( devnum = 0; devnum <= 127; devnum++ )
    {
        ret = dbgp_control_msg(dbgp, devnum,
                               USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
                               USB_REQ_GET_DESCRIPTOR, (USB_DT_DEBUG << 8), 0,
                               &dbgp_desc, sizeof(dbgp_desc));
        if ( ret > 0 )
            break;
    }
    if ( devnum > 127 )
    {
        dbgp_printk("could not find attached debug device\n");
        goto err;
    }
    dbgp->out.endpoint = dbgp_desc.bDebugOutEndpoint;
    dbgp->in.endpoint = dbgp_desc.bDebugInEndpoint;

    /* Move the device to 127 if it isn't already there. */
    if ( devnum != USB_DEBUG_DEVNUM )
    {
        ret = dbgp_control_msg(dbgp, devnum,
                               USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
                               USB_REQ_SET_ADDRESS, USB_DEBUG_DEVNUM, 0, NULL, 0);
        if ( ret < 0 )
        {
            dbgp_printk("could not move attached device to %d\n",
                        USB_DEBUG_DEVNUM);
            goto err;
        }
        devnum = USB_DEBUG_DEVNUM;
        dbgp_printk("debug device renamed to 127\n");
    }

    /* Enable the debug interface */
    ret = dbgp_control_msg(dbgp, USB_DEBUG_DEVNUM,
                           USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
                           USB_REQ_SET_FEATURE, USB_DEVICE_DEBUG_MODE,
                           0, NULL, 0);
    if ( ret < 0 )
    {
        dbgp_printk("could not enable the debug device\n");
        goto err;
    }
    dbgp_printk("debug interface enabled\n");

    /* Perform a small write to get the even/odd data state in sync. */
    ret = dbgp_bulk_write(dbgp, USB_DEBUG_DEVNUM, dbgp->out.endpoint,
                          "\n", 1, &ctrl);
    if ( !ret )
        ret = dbgp_wait_until_done(dbgp, ctrl, DBGP_LOOPS);
    if ( ret < 0 )
    {
        dbgp_printk("dbgp_bulk_write failed: %d\n", ret);
        goto err;
    }
    dbgp_printk("small write done\n");
    dbgp->state = dbgp_idle;

    return 0;
err:
    if ( tries-- )
        goto try_again;
    return -ENODEV;
}

typedef void (*set_debug_port_t)(struct ehci_dbgp *, unsigned int);

static void default_set_debug_port(struct ehci_dbgp *dbgp, unsigned int port)
{
}

static set_debug_port_t __read_mostly set_debug_port = default_set_debug_port;

static void nvidia_set_debug_port(struct ehci_dbgp *dbgp, unsigned int port)
{
    u32 dword = pci_conf_read32(0, dbgp->bus, dbgp->slot, dbgp->func, 0x74);

    dword &= ~(0x0f << 12);
    dword |= (port & 0x0f) << 12;
    pci_conf_write32(0, dbgp->bus, dbgp->slot, dbgp->func, 0x74, dword);
    dbgp_printk("set debug port to %u\n", port);
}

static void __init detect_set_debug_port(struct ehci_dbgp *dbgp)
{
    if ( pci_conf_read16(PCI_SBDF(0, dbgp->bus, dbgp->slot, dbgp->func),
                         PCI_VENDOR_ID) == 0x10de )
    {
        dbgp_printk("using nvidia set_debug_port\n");
        set_debug_port = nvidia_set_debug_port;
    }
}

/*
 * The code in ehci_dbgp_bios_handoff() is derived from the USB PCI
 * quirk initialization in Linux.
 */
#define EHCI_USBLEGSUP_BIOS    (1 << 16) /* BIOS semaphore */
#define EHCI_USBLEGCTLSTS      4        /* legacy control/status */
static void ehci_dbgp_bios_handoff(struct ehci_dbgp *dbgp, u32 hcc_params)
{
    u32 cap;
    unsigned int offset = HCC_EXT_CAPS(hcc_params);
    int msec;

    if ( !offset )
        return;

    cap = pci_conf_read32(0, dbgp->bus, dbgp->slot, dbgp->func, offset);
    dbgp_printk("dbgp: EHCI BIOS state %08x\n", cap);

    if ( (cap & 0xff) == 1 && (cap & EHCI_USBLEGSUP_BIOS) )
    {
        dbgp_printk("dbgp: BIOS handoff\n");
        pci_conf_write8(0, dbgp->bus, dbgp->slot, dbgp->func, offset + 3, 1);
    }

    /* if boot firmware now owns EHCI, spin till it hands it over. */
    msec = 1000;
    while ( (cap & EHCI_USBLEGSUP_BIOS) && (msec > 0) )
    {
        mdelay(10);
        msec -= 10;
        cap = pci_conf_read32(0, dbgp->bus, dbgp->slot, dbgp->func, offset);
    }

    if ( cap & EHCI_USBLEGSUP_BIOS )
    {
        /* well, possibly buggy BIOS... try to shut it down,
         * and hope nothing goes too wrong */
        dbgp_printk("dbgp: BIOS handoff failed: %08x\n", cap);
        pci_conf_write8(0, dbgp->bus, dbgp->slot, dbgp->func, offset + 2, 0);
    }

    /* just in case, always disable EHCI SMIs */
    pci_conf_write8(0, dbgp->bus, dbgp->slot, dbgp->func,
                    offset + EHCI_USBLEGCTLSTS, 0);
}

static int ehci_dbgp_setup(struct ehci_dbgp *dbgp)
{
    u32 ctrl, portsc, hcs_params;
    unsigned int i, debug_port, new_debug_port = 0, n_ports;
    unsigned int port_map_tried, playtimes = 3;
    int ret;

    ehci_dbgp_bios_handoff(dbgp, readl(&dbgp->ehci_caps->hcc_params));

try_next_time:
    port_map_tried = 0;

try_next_port:

    hcs_params = readl(&dbgp->ehci_caps->hcs_params);
    debug_port = HCS_DEBUG_PORT(hcs_params);
    dbgp->phys_port = debug_port;
    n_ports = HCS_N_PORTS(hcs_params);

    dbgp_printk("debug_port: %u\n", debug_port);
    dbgp_printk("n_ports:    %u\n", n_ports);
    ehci_dbgp_status(dbgp, "");

    if ( n_ports == 0 )
        return -1;

    for ( i = 1; i <= n_ports; i++ )
    {
        portsc = readl(&dbgp->ehci_regs->port_status[i-1]);
        dbgp_printk("portstatus%d: %08x\n", i, portsc);
    }

    if ( port_map_tried && (new_debug_port != debug_port) )
    {
        if ( --playtimes )
        {
            set_debug_port(dbgp, new_debug_port);
            goto try_next_time;
        }
        return -1;
    }

    /* Only reset the controller if it is not already in the
     * configured state */
    if ( readl(&dbgp->ehci_regs->configured_flag) & FLAG_CF )
        ehci_dbgp_status(dbgp, "ehci skip - already configured");
    else if ( ehci_dbgp_controller_reset(dbgp) != 0 )
        return -1;

    ret = ehci_dbgp_external_startup(dbgp);
    if (ret == -EIO)
        goto next_debug_port;

    if ( ret < 0 )
    {
        /* Things didn't work so remove my claim */
        ctrl = readl(&dbgp->ehci_debug->control);
        ctrl &= ~(DBGP_CLAIM | DBGP_OUT);
        writel(ctrl, &dbgp->ehci_debug->control);
        return -1;
    }

    return 0;

next_debug_port:
    port_map_tried |= 1 << (debug_port - 1);
    new_debug_port = (debug_port % n_ports) + 1;
    if ( port_map_tried != ((1 << n_ports) - 1) )
    {
        set_debug_port(dbgp, new_debug_port);
        goto try_next_port;
    }
    if ( --playtimes )
    {
        set_debug_port(dbgp, new_debug_port);
        goto try_next_time;
    }

    return -1;
}

static inline void _ehci_dbgp_flush(struct ehci_dbgp *dbgp)
{
    if ( dbgp_bulk_write(dbgp, USB_DEBUG_DEVNUM, dbgp->out.endpoint,
                         dbgp->out.buf, dbgp->out.chunk, NULL) )
        BUG();
    dbgp->out.chunk = 0;
}

static void ehci_dbgp_flush(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;
    s_time_t goal;

    if ( !dbgp->out.chunk || !dbgp->ehci_debug || dbgp->state == dbgp_unsafe )
        return;

    if ( dbgp->state == dbgp_idle || !port->sync )
        dbgp_check_for_completion(dbgp, 1, NULL);
    else
        dbgp_wait_until_complete(dbgp, NULL);

    if ( dbgp->state == dbgp_idle )
    {
        _ehci_dbgp_flush(dbgp);

        if ( port->sync )
        {
            dbgp_wait_until_complete(dbgp, NULL);
            return;
        }
    }

    goal = NOW() + MICROSECS(DBGP_CHECK_INTERVAL);
    if ( dbgp->timer.expires > goal )
       set_timer(&dbgp->timer, goal);
}

static void ehci_dbgp_putc(struct serial_port *port, char c)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( unlikely(dbgp->out.chunk >= DBGP_MAX_PACKET) )
        return;

    dbgp->out.buf[dbgp->out.chunk++] = c;

    if ( dbgp->out.chunk == DBGP_MAX_PACKET )
        ehci_dbgp_flush(port);
}

static int ehci_dbgp_tx_ready(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( unlikely(!dbgp->ehci_debug) || unlikely(dbgp->state == dbgp_unsafe) )
        return port->sync || port->tx_log_everything || !port->txbuf;

    if ( dbgp->out.chunk == DBGP_MAX_PACKET )
        ehci_dbgp_flush(port);
    else
        dbgp_check_for_completion(dbgp, 1, NULL);

    if ( dbgp->state != dbgp_idle && dbgp->out.chunk >= DBGP_MAX_PACKET )
        return 0;

    return DBGP_MAX_PACKET - dbgp->out.chunk +
           (dbgp->state == dbgp_idle) * DBGP_MAX_PACKET;
}

static int ehci_dbgp_getc(struct serial_port *port, char *pc)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( !dbgp->in.chunk )
        return 0;

    *pc = *dbgp->in.buf;
    if ( --dbgp->in.chunk )
        memmove(dbgp->in.buf, dbgp->in.buf + 1, dbgp->in.chunk);

    return 1;
}

/* Safe: ehci_dbgp_poll() runs as timer handler, so not reentrant. */
static struct serial_port *poll_port;

static void _ehci_dbgp_poll(struct cpu_user_regs *regs)
{
    struct serial_port *port = poll_port;
    struct ehci_dbgp *dbgp = port->uart;
    unsigned long flags;
    unsigned int timeout = MICROSECS(DBGP_CHECK_INTERVAL);
    bool_t empty = 0;

    if ( !dbgp->ehci_debug )
        return;

    if ( spin_trylock_irqsave(&port->tx_lock, flags) )
    {
        if ( dbgp->state != dbgp_unsafe )
            dbgp_check_for_completion(dbgp, DBGP_CHECK_INTERVAL, NULL);
        if ( dbgp->state == dbgp_idle && dbgp->out.chunk )
            _ehci_dbgp_flush(dbgp);
        if ( dbgp->state == dbgp_idle || dbgp->out.chunk < DBGP_MAX_PACKET )
            empty = 1;
        spin_unlock_irqrestore(&port->tx_lock, flags);
    }

    if ( dbgp->in.chunk )
        serial_rx_interrupt(port, regs);

    if ( empty )
        serial_tx_interrupt(port, regs);

    if ( spin_trylock_irqsave(&port->tx_lock, flags) )
    {
        if ( dbgp->state == dbgp_idle && !dbgp->in.chunk &&
             !dbgp->out.chunk && port->txbufp == port->txbufc )
        {
            if ( dbgp_bulk_read(dbgp, USB_DEBUG_DEVNUM, dbgp->in.endpoint,
                                DBGP_MAX_PACKET, NULL) )
                BUG();
            timeout = MILLISECS(DBGP_IDLE_INTERVAL);
        }
        spin_unlock_irqrestore(&port->tx_lock, flags);
    }

    set_timer(&dbgp->timer, NOW() + timeout);
}

static void ehci_dbgp_poll(void *data)
{
    poll_port = data;
#ifdef run_in_exception_handler
    run_in_exception_handler(_ehci_dbgp_poll);
#else
    _ehci_dbgp_poll(guest_cpu_user_regs());
#endif
}

static bool_t ehci_dbgp_setup_preirq(struct ehci_dbgp *dbgp)
{
    if ( !ehci_dbgp_setup(dbgp) )
        return 1;

    dbgp_printk("ehci_dbgp_setup failed\n");
    dbgp->ehci_debug = NULL;
    return 0;
}

static void __init ehci_dbgp_init_preirq(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;
    u32 debug_port, offset;
    void __iomem *ehci_bar;

    debug_port = pci_conf_read32(0, dbgp->bus, dbgp->slot, dbgp->func,
                                 dbgp->cap);
    offset = (debug_port >> 16) & 0xfff;

    /* double check if the mem space is enabled */
    dbgp->pci_cr = pci_conf_read8(PCI_SBDF(0, dbgp->bus, dbgp->slot,
                                           dbgp->func),
                                  PCI_COMMAND);
    if ( !(dbgp->pci_cr & PCI_COMMAND_MEMORY) )
    {
        dbgp->pci_cr |= PCI_COMMAND_MEMORY;
        pci_conf_write16(0, dbgp->bus, dbgp->slot, dbgp->func, PCI_COMMAND,
                         dbgp->pci_cr);
        dbgp_printk("MMIO for EHCI enabled\n");
    }

    /*
     * FIXME I don't have the bar size so just guess PAGE_SIZE is more
     * than enough.  1k is the biggest that was seen.
     */
    set_fixmap_nocache(FIX_EHCI_DBGP, dbgp->bar_val);
    ehci_bar = fix_to_virt(FIX_EHCI_DBGP);
    ehci_bar += dbgp->bar_val & ~PAGE_MASK;
    dbgp_printk("ehci_bar: %p\n", ehci_bar);

    dbgp->ehci_caps = ehci_bar;
    dbgp->ehci_regs = ehci_bar +
                      HC_LENGTH(readl(&dbgp->ehci_caps->hc_capbase));
    dbgp->ehci_debug = ehci_bar + offset;

    detect_set_debug_port(dbgp);

    if ( ehci_dbgp_setup_preirq(dbgp) )
        ehci_dbgp_status(dbgp, "ehci_dbgp_init_preirq complete");

    dbgp->lock = &port->tx_lock;
}

static void ehci_dbgp_setup_postirq(struct ehci_dbgp *dbgp)
{
    set_timer(&dbgp->timer, NOW() + MILLISECS(1));
}

static void __init ehci_dbgp_init_postirq(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( !dbgp->ehci_debug )
        return;

    serial_async_transmit(port);

    init_timer(&dbgp->timer, ehci_dbgp_poll, port, 0);

    ehci_dbgp_setup_postirq(dbgp);

    pci_hide_device(0, dbgp->bus, PCI_DEVFN(dbgp->slot, dbgp->func));
}

static int ehci_dbgp_check_release(struct ehci_dbgp *dbgp)
{
    struct ehci_dbg_port __iomem *ehci_debug = dbgp->ehci_debug;
    u32 ctrl;
    unsigned int i;

    if ( !ehci_debug )
        return 0;

    for ( i = 0; i < DBGP_MAX_PACKET; ++i )
        if ( dbgp->out.buf[i] )
            return 1;

    /*
     * This means the console is not initialized, or should get shutdown
     * so as to allow for reuse of the USB device, which means it is time
     * to shutdown the USB debug port.
     */
    printk(XENLOG_INFO "Releasing EHCI debug port at %02x:%02x.%u\n",
           dbgp->bus, dbgp->slot, dbgp->func);

    if ( dbgp->timer.function )
        kill_timer(&dbgp->timer);
    dbgp->ehci_debug = NULL;

    ctrl = readl(&ehci_debug->control);
    if ( ctrl & DBGP_ENABLED )
    {
        ctrl &= ~DBGP_CLAIM;
        writel(ctrl, &ehci_debug->control);
    }

    return 0;
}

static void __init ehci_dbgp_endboot(struct serial_port *port)
{
    ehci_dbgp_check_release(port->uart);
}

static void ehci_dbgp_suspend(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( !dbgp->ehci_debug )
        return;

    stop_timer(&dbgp->timer);
    dbgp->timer.expires = 0;

    dbgp->pci_cr = pci_conf_read16(PCI_SBDF(0, dbgp->bus, dbgp->slot,
                                            dbgp->func),
                                   PCI_COMMAND);

    dbgp->state = dbgp_unsafe;
}

static void ehci_dbgp_resume(struct serial_port *port)
{
    struct ehci_dbgp *dbgp = port->uart;

    if ( !dbgp->ehci_debug )
        return;

    pci_conf_write32(0, dbgp->bus, dbgp->slot, dbgp->func, dbgp->bar,
                     dbgp->bar_val);
    pci_conf_write16(0, dbgp->bus, dbgp->slot, dbgp->func,
                     PCI_COMMAND, dbgp->pci_cr);

    ehci_dbgp_setup_preirq(dbgp);
    ehci_dbgp_setup_postirq(dbgp);
}

static struct uart_driver __read_mostly ehci_dbgp_driver = {
    .init_preirq  = ehci_dbgp_init_preirq,
    .init_postirq = ehci_dbgp_init_postirq,
    .endboot      = ehci_dbgp_endboot,
    .suspend      = ehci_dbgp_suspend,
    .resume       = ehci_dbgp_resume,
    .tx_ready     = ehci_dbgp_tx_ready,
    .putc         = ehci_dbgp_putc,
    .flush        = ehci_dbgp_flush,
    .getc         = ehci_dbgp_getc
};

static struct ehci_dbgp ehci_dbgp = { .state = dbgp_unsafe, .phys_port = 1 };

static char __initdata opt_dbgp[30];
string_param("dbgp", opt_dbgp);

void __init ehci_dbgp_init(void)
{
    struct ehci_dbgp *dbgp = &ehci_dbgp;
    u32 debug_port, offset, bar_val;
    const char *e;

    if ( strncmp(opt_dbgp, "ehci", 4) )
        return;

    if ( isdigit(opt_dbgp[4]) || !opt_dbgp[4] )
    {
        unsigned int num = 0;

        if ( opt_dbgp[4] )
            simple_strtoul(opt_dbgp + 4, &e, 10);

        dbgp->cap = find_dbgp(dbgp, num);
        if ( !dbgp->cap )
            return;

        dbgp_printk("Found EHCI debug port on %02x:%02x.%u\n",
                    dbgp->bus, dbgp->slot, dbgp->func);
    }
    else if ( strncmp(opt_dbgp + 4, "@pci", 4) == 0 )
    {
        unsigned int bus, slot, func;

        e = parse_pci(opt_dbgp + 8, NULL, &bus, &slot, &func);
        if ( !e || *e )
            return;

        dbgp->bus = bus;
        dbgp->slot = slot;
        dbgp->func = func;

        if ( !pci_device_detect(0, bus, slot, func) )
            return;

        dbgp->cap = __find_dbgp(bus, slot, func);
        if ( !dbgp->cap )
            return;

        dbgp_printk("Using EHCI debug port on %02x:%02x.%u\n",
                    bus, slot, func);
    }
    else
        return;

    debug_port = pci_conf_read32(0, dbgp->bus, dbgp->slot, dbgp->func,
                                 dbgp->cap);
    dbgp->bar = (debug_port >> 29) & 0x7;
    dbgp->bar = ((dbgp->bar - 1) * 4) + PCI_BASE_ADDRESS_0;
    offset = (debug_port >> 16) & 0xfff;
    dbgp_printk("bar: %02x offset: %03x\n", dbgp->bar, offset);
    if ( dbgp->bar < PCI_BASE_ADDRESS_0 || dbgp->bar > PCI_BASE_ADDRESS_5 )
    {
        dbgp_printk("unsupported/invalid bar\n");
        return;
    }

    dbgp->bar_val = bar_val = pci_conf_read32(0, dbgp->bus, dbgp->slot,
                                              dbgp->func, dbgp->bar);
    dbgp_printk("bar_val: %08x\n", bar_val);
    if ( bar_val & ~PCI_BASE_ADDRESS_MEM_MASK )
    {
        dbgp_printk("only simple 32-bit MMIO BARs supported\n");
        return;
    }
    bar_val &= PCI_BASE_ADDRESS_MEM_MASK;
    if ( !bar_val || !(bar_val + (bar_val & -bar_val)) )
    {
        dbgp_printk("firmware initialization of MMIO BAR required\n");
        return;
    }

    serial_register_uart(SERHND_DBGP, &ehci_dbgp_driver, dbgp);
}

int dbgp_op(const struct physdev_dbgp_op *op)
{
    if ( !ehci_dbgp.ehci_debug )
        return 0;

    switch ( op->bus )
    {
    case PHYSDEVOP_DBGP_BUS_UNKNOWN:
        break;
    case PHYSDEVOP_DBGP_BUS_PCI:
        if ( op->u.pci.seg || ehci_dbgp.bus != op->u.pci.bus ||
            PCI_DEVFN(ehci_dbgp.slot, ehci_dbgp.func) != op->u.pci.devfn )
    default:
            return 0;
        break;
    }

    switch ( op->op )
    {
    case PHYSDEVOP_DBGP_RESET_PREPARE:
        spin_lock_irq(ehci_dbgp.lock);
        ehci_dbgp.state = dbgp_unsafe;
        dbgp_wait_until_complete(&ehci_dbgp, NULL);
        spin_unlock_irq(ehci_dbgp.lock);

        return ehci_dbgp_check_release(&ehci_dbgp);

    case PHYSDEVOP_DBGP_RESET_DONE:
        return ehci_dbgp_external_startup(&ehci_dbgp) ?: 1;
    }

    return -ENOSYS;
}
