/******************************************************************************
 * kernel.c
 * 
 * This file should contain architecture-independent bootstrap and low-level
 * help routines. It's a bit x86/PC specific right now!
 * 
 * Copyright (c) 2002-2003 K A Fraser
 */

#include <stdarg.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/spinlock.h>
#include <xeno/multiboot.h>
#include <xeno/sched.h>
#include <xeno/mm.h>
#include <xeno/delay.h>
#include <xeno/skbuff.h>
#include <xeno/interrupt.h>
#include <xeno/compile.h>
#include <xeno/version.h>
#include <xeno/netdevice.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <asm/byteorder.h>
#include <linux/if_ether.h>
#include <asm/domain_page.h>
#include <xeno/console.h>
#include <xeno/net_headers.h>

kmem_cache_t *task_struct_cachep;

static int xpos, ypos;
static volatile unsigned char *video;

spinlock_t console_lock = SPIN_LOCK_UNLOCKED;

struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};

void init_vga(void);
void init_serial(void);
void start_of_day(void);

/* opt_console: If true, Xen sends logging to the VGA console. */
int opt_console = 1;
/* opt_ser_baud: Baud rate at which logging is sent to COM1. */
/* NB. Default (0) means that serial I/O is disabled. */
unsigned int opt_ser_baud = 0;
/* opt_dom0_mem: Kilobytes of memory allocated to domain 0. */
unsigned int opt_dom0_mem = 16000;
/* opt_ifname: Name of physical network interface to use. */
unsigned char opt_ifname[10] = "eth0";
/* opt_noht: If true, Hyperthreading is ignored. */
int opt_noht=0;
/* opt_noacpi: If true, ACPI tables are not parsed. */
int opt_noacpi=0;
/* opt_nosmp: If true, secondary processors are ignored. */
int opt_nosmp=0;
/* opt_noreboot: If true, machine will need manual reset on error. */
int opt_noreboot=0;
/* opt_ignorebiostables: If true, ACPI and MP tables are ignored. */
/* NB. This flag implies 'nosmp' and 'noacpi'. */
int opt_ignorebiostables=0;
/* opt_watchdog: If true, run a watchdog NMI on each processor. */
int opt_watchdog=0;

static struct {
    unsigned char *name;
    enum { OPT_IP, OPT_STR, OPT_UINT, OPT_BOOL } type;
    void *var;
} opts[] = {
    { "console",          OPT_UINT, &opt_console },
    { "ser_baud",         OPT_UINT, &opt_ser_baud },
    { "dom0_mem",         OPT_UINT, &opt_dom0_mem }, 
    { "ifname",           OPT_STR,  &opt_ifname },
    { "noht",             OPT_BOOL, &opt_noht },
    { "noacpi",           OPT_BOOL, &opt_noacpi },
    { "nosmp",            OPT_BOOL, &opt_nosmp },
    { "noreboot",         OPT_BOOL, &opt_noreboot },
    { "ignorebiostables", OPT_BOOL, &opt_ignorebiostables },
    { "watchdog",         OPT_BOOL, &opt_watchdog },
    { NULL,               0,        NULL     }
};


void cmain (unsigned long magic, multiboot_info_t *mbi)
{
    struct task_struct *new_dom;
    dom0_createdomain_t dom0_params;
    unsigned long max_page;
    unsigned char *cmdline;
    module_t *mod;
    int i;

    /*
     * Note that serial output cannot be done properly until after 
     * command-line arguments have been parsed, and the required baud rate is 
     * known. Any messages before that will be output using the settings of 
     * the bootloader, for example.
     */

    if ( magic != MULTIBOOT_BOOTLOADER_MAGIC )
    {
        init_vga();
        cls();
        printk("Invalid magic number: 0x%x\n", (unsigned)magic);
        for ( ; ; ) ;
    }

    /* Parse the command line. */
    cmdline = (unsigned char *)(mbi->cmdline ? __va(mbi->cmdline) : NULL);
    if ( cmdline != NULL )
    {
        unsigned char *opt_end, *opt;
        while ( *cmdline == ' ' ) cmdline++;
        cmdline = strchr(cmdline, ' ');
        while ( cmdline != NULL )
        {
            while ( *cmdline == ' ' ) cmdline++;
            if ( *cmdline == '\0' ) break;
            opt_end = strchr(cmdline, ' ');
            if ( opt_end != NULL ) *opt_end++ = '\0';
            opt = strchr(cmdline, '=');
            if ( opt != NULL ) *opt++ = '\0';
            for ( i = 0; opts[i].name != NULL; i++ )
            {
                if ( strcmp(opts[i].name, cmdline ) != 0 ) continue;
                switch ( opts[i].type )
                {
                case OPT_IP:
                    if ( opt != NULL )
                        *(unsigned long *)opts[i].var = str_to_quad(opt);
                    break;
                case OPT_STR:
                    if ( opt != NULL )
                        strcpy(opts[i].var, opt);
                    break;
                case OPT_UINT:
                    if ( opt != NULL )
                        *(unsigned int *)opts[i].var =
                            simple_strtol(opt, (char **)&opt, 0);
                    break;
                case OPT_BOOL:
                    *(int *)opts[i].var = 1;
                    break;
                }
            }
            cmdline = opt_end;
        }
    }

    init_serial();
    init_vga();
    cls();

    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);

    /* We require memory and module information. */
    if ( (mbi->flags & 9) != 9 )
    {
        printk("FATAL ERROR: Bad flags passed by bootloader: 0x%x\n", 
               (unsigned)mbi->flags);
        for ( ; ; ) ;
    }

    if ( mbi->mods_count == 0 )
    {
        printk("Require at least one Multiboot module!\n");
        for ( ; ; ) ;
    }

    set_current(&idle0_task);

    max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);
    init_frametable(max_page);
    printk("Initialised all memory on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT));

    init_page_allocator(__pa(&_end), MAX_MONITOR_ADDRESS);
 
    /* These things will get done by do_createdomain() for all other tasks. */
    current->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(current->shared_info, 0, sizeof(shared_info_t));
    set_fs(USER_DS);

    /* Initialise the slab allocator. */
    kmem_cache_init();
    kmem_cache_sizes_init(max_page);

    task_struct_cachep = kmem_cache_create(
        "task_struct_cache", sizeof(struct task_struct),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if ( task_struct_cachep == NULL )
        panic("No slab cache for task structs.");

    start_of_day();

    /* Create initial domain 0. */
    dom0_params.memory_kb = opt_dom0_mem;
    new_dom = do_createdomain(0, 0);
    if ( new_dom == NULL ) panic("Error creating domain 0\n");

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our MAX_DIRECTMAP_ADDRESS in boot/Boot.S The second module, if
     * present, is an initrd ramdisk
     */
    mod = (module_t *)__va(mbi->mods_addr);
    if ( setup_guestos(new_dom, 
                       &dom0_params, 1,
                       (char *)MAX_DIRECTMAP_ADDRESS, 
                       mod[mbi->mods_count-1].mod_end - mod[0].mod_start,
                       __va(mod[0].string),
		       (mbi->mods_count == 2) ?
                       (mod[1].mod_end - mod[1].mod_start):0)
         != 0 ) panic("Could not set up DOM0 guest OS\n");

    wake_up(new_dom);

    startup_cpu_idle_loop();
}


#define SERIAL_BASE 0x3f8
#define RX_BUF      0
#define TX_HOLD     0
#define INT_ENABLE  1
#define INT_IDENT   2
#define DATA_FORMAT 3
#define LINE_CTL    4
#define LINE_STATUS 5
#define LINE_IN     6
#define DIVISOR_LO  0
#define DIVISOR_HI  1

void init_serial(void)
{
    if ( !SERIAL_ENABLED )
        return;

    /* 'opt_ser_baud' baud, no parity, 1 stop bit, 8 data bits. */
    outb(0x83, SERIAL_BASE+DATA_FORMAT);
    outb(115200/opt_ser_baud, SERIAL_BASE+DIVISOR_LO);
    outb(0, SERIAL_BASE+DIVISOR_HI);
    outb(0x03, SERIAL_BASE+DATA_FORMAT);
    
    /* DTR and RTS should both be high, to keep other end happy. */
    outb(0x02, SERIAL_BASE+LINE_CTL);

    /* No interrupts. */
    outb(0x00, SERIAL_BASE+INT_ENABLE);
}


#ifdef CONFIG_OUTPUT_SERIAL
void putchar_serial(unsigned char c)
{
    if ( !SERIAL_ENABLED )
        return;
    if ( c == '\n' ) putchar_serial('\r');
    while ( !(inb(SERIAL_BASE+LINE_STATUS)&(1<<5)) ) barrier();
    outb(c, SERIAL_BASE+TX_HOLD);
}
#else
void putchar_serial(unsigned char c) {}
#endif


#ifdef CONFIG_OUTPUT_CONSOLE

/* VGA text (mode 3) definitions. */
#define COLUMNS	    80
#define LINES	    25
#define ATTRIBUTE    7
#define VIDEO	    __va(0xB8000)

int detect_video(void *video_base)
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

int detect_vga(void)
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
void init_vga(void)
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

    if ( !opt_console )
        return;

    if ( !detect_vga() )
    {
        printk("No VGA adaptor detected!\n");
        opt_console = 0;
        return;
    }

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
}


/* Clear the screen and initialize VIDEO, XPOS and YPOS.  */
void cls(void)
{
    int i;

    if ( !opt_console )
        return;

    video = (unsigned char *) VIDEO;
    
    for (i = 0; i < COLUMNS * LINES * 2; i++)
        *(video + i) = 0;
    
    xpos = 0;
    ypos = 0;
    
    outw(10+(1<<(5+8)), 0x3d4); /* cursor off */
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


void putchar_console(int c)
{
    if ( !opt_console )
        return;

    if ( c == '\n' )
    {
        put_newline();
    }
    else
    {
        *(video + (xpos + ypos * COLUMNS) * 2) = c & 0xFF;
        *(video + (xpos + ypos * COLUMNS) * 2 + 1) = ATTRIBUTE;
        
        xpos++;
        if (xpos >= COLUMNS)
            put_newline();
    }
}

#else

void init_vga(void) {}
void cls(void) {}
void putchar_console(int c) {}

#endif

#ifdef CONFIG_OUTPUT_CONSOLE_RING

void putchar_console_ring(int c)
{
    if (console_ring.len < CONSOLE_RING_SIZE)
        console_ring.buf[console_ring.len++] = (char)c;
}

#else

void putchar_console_ring(int c) {}

#endif


static void putchar(int c)
{
    if ( (c != '\n') && ((c < 32) || (c > 126)) ) return;
    putchar_serial(c);
    putchar_console(c);
    putchar_console_ring(c);
}


static inline void __putstr(const char *str)
{
    while ( *str ) putchar(*str++);
}


void printf (const char *fmt, ...)
{
    va_list args;
    char buf[128];
    const char *p = fmt;
    unsigned long flags;

    /*
     * If the format string contains '%' descriptors then we have to parse it 
     * before printing it. We parse it into a fixed-length buffer. Long 
     * strings should therefore _not_ contain '%' characters!
     */
    if ( strchr(fmt, '%') != NULL )
    {
        va_start(args, fmt);
        (void)vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);        
        p = buf; 
    }

    spin_lock_irqsave(&console_lock, flags);
    while ( *p ) putchar(*p++);
    spin_unlock_irqrestore(&console_lock, flags);
}


void panic(const char *fmt, ...)
{
    va_list args;
    char buf[128];
    unsigned long flags;
    extern void machine_restart(char *);
    
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    /* Spit out multiline message in one go. */
    spin_lock_irqsave(&console_lock, flags);
    __putstr("\n****************************************\n");
    __putstr(buf);
    __putstr("Aieee! CPU");
    sprintf(buf, "%d", smp_processor_id());
    __putstr(buf);
    __putstr(" is toast...\n");
    __putstr("****************************************\n\n");
    __putstr("Reboot in five seconds...\n");
    spin_unlock_irqrestore(&console_lock, flags);

    mdelay(5000);
    machine_restart(0);
}


/* No-op syscall. */
asmlinkage long sys_ni_syscall(void)
{
    return -ENOSYS;
}


unsigned short compute_cksum(unsigned short *buf, int count)
{
    unsigned long sum = 0;
    while ( count-- )
        sum += *buf++;
    while ( sum >> 16 )
	sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short) ~sum;
}


/*
 * Function written by ek247. Exports console output from all domains upwards 
 * to domain0, by stuffing it into a fake network packet.
 */
int console_export(char *str, int len)
{
    struct sk_buff *skb;
    struct iphdr *iph = NULL;  
    struct udphdr *udph = NULL; 
    struct ethhdr *ethh = NULL; 
    int hdr_size = sizeof(struct iphdr) + sizeof(struct udphdr); 
    u8 *skb_data;

    skb = dev_alloc_skb(sizeof(struct ethhdr) + 
                                   hdr_size + len + 20);
    if ( skb == NULL ) return 0;

    skb->dev = the_dev;
    skb_data = (u8 *)map_domain_mem((skb->pf - frame_table) << PAGE_SHIFT);
    skb_reserve(skb, 2);

    /* Get a pointer to each header. */
    ethh = (struct ethhdr *) 
        (skb_data + (skb->data - skb->head));
    iph  = (struct iphdr *)(ethh + 1);
    udph = (struct udphdr *)(iph + 1); 

    skb_reserve(skb, sizeof(struct ethhdr)); 
    skb_put(skb, hdr_size +  len); 

    /* Build IP header. */
    iph->version = 4;
    iph->ihl     = 5;
    iph->tos	 = 0;
    iph->tot_len = htons(hdr_size + len);
    iph->id      = 0xdead;
    iph->frag_off= 0;
    iph->ttl     = 255;
    iph->protocol= 17;
    iph->daddr   = htonl(0xa9fe0100);  /* 169.254.1.0 */
    iph->saddr   = htonl(0xa9fefeff);  /* 169.254.254.255 */
    iph->check	 = 0;
    iph->check   = compute_cksum((__u16 *)iph, sizeof(struct iphdr)/2); 

    /* Build UDP header. */
    udph->source = htons(current->domain);
    udph->dest   = htons(666);
    udph->len    = htons(sizeof(struct udphdr) + len);
    udph->check  = 0;

    /* Build the UDP payload. */
    memcpy((char *)(udph + 1), str, len); 

    /* Fix Ethernet header. */
    memset(ethh->h_source, 0, ETH_ALEN);
    memset(ethh->h_dest,   0, ETH_ALEN);
    ethh->h_proto = htons(ETH_P_IP);
    skb->mac.ethernet= (struct ethhdr *)ethh;

    unmap_domain_mem(skb_data);
    
    skb->dst_vif = find_vif_by_id(0);
    (void)netif_rx(skb);

    return 1;
}


long do_console_write(char *str, unsigned int count)
{
#define SIZEOF_BUF 256
    unsigned char safe_str[SIZEOF_BUF+1];
    unsigned char exported_str[SIZEOF_BUF+2];
    unsigned char dom_id[5];
    unsigned char *p;
    unsigned long flags;
    int j;
    
    if ( count == 0 )
        return 0;

    if ( count > SIZEOF_BUF ) 
        count = SIZEOF_BUF;
    
    if ( copy_from_user(safe_str, str, count) )
        return -EFAULT;
    safe_str[count] = '\0';
    
    p = safe_str;
    while ( *p != '\0' )
    {
        j = 0;

        spin_lock_irqsave(&console_lock, flags);
        
        __putstr("DOM"); 
        sprintf(dom_id, "%d", current->domain);
        __putstr(dom_id);
        __putstr(": ");
        
        while ( (*p != '\0') && (*p != '\n') )
        {
            exported_str[j++] = *p;
            putchar(*p);
            p++;
        }

        if ( *p == '\n' )
            p++;

        putchar('\n');
        
        spin_unlock_irqrestore(&console_lock, flags);

        if ( current->domain != 0 )
        {
            exported_str[j++] = '\n';
            exported_str[j++] = '\0';
            console_export(exported_str, j);
        }
    }

    return 0;
}


void __out_of_line_bug(int line)
{
    printk("kernel BUG in header file at line %d\n", line);
    BUG();
    for ( ; ; ) continue;
}


/*
 * GRAVEYARD
 */
#if 0
    if ( (mbi->flags & (1<<6)) )
    {
        memory_map_t *mmap = (memory_map_t *)mbi->mmap_addr;
        struct e820entry *e820 = E820_MAP;

        while ( (unsigned long)mmap < (mbi->mmap_addr + mbi->mmap_length) )
        {
            e820->addr_lo = mmap->base_addr_low;
            e820->addr_hi = mmap->base_addr_high;
            e820->size_lo = mmap->length_low;
            e820->size_hi = mmap->length_high;
            e820->type    = mmap->type;
            e820++;
            mmap = (memory_map_t *) 
                ((unsigned long)mmap + mmap->size + sizeof (mmap->size));
        }
    }
#endif

