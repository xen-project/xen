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
#include <xeno/serial.h>

kmem_cache_t *task_struct_cachep;

static int xpos, ypos;
static unsigned char *video = __va(0xB8000);

int sercon_handle = -1;
int vgacon_enabled = 0;

spinlock_t console_lock = SPIN_LOCK_UNLOCKED;

struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};

static void init_vga(void);
void start_of_day(void);

/* opt_console: comma-separated list of console outputs. */
unsigned char opt_console[30] = "com1,vga";
/* opt_ser_baud: Baud rate at which logging is sent to COM1. */
/* NB. Default (0) means that serial I/O is disabled. */
/* NB2. THIS OPTION IS DEPRECATED!! */
unsigned int opt_ser_baud = 0;
/* opt_com[12]: Config serial port with a string <baud>,DPS,<io-base>,<irq>. */
unsigned char opt_com1[30] = "", opt_com2[30] = "";
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
/* opt_pdb: Name of serial port for Xen pervasive debugger (and enable pdb) */
unsigned char opt_pdb[10] = "none";

static struct {
    unsigned char *name;
    enum { OPT_IP, OPT_STR, OPT_UINT, OPT_BOOL } type;
    void *var;
} opts[] = {
    { "console",          OPT_STR,  &opt_console },
    { "ser_baud",         OPT_UINT, &opt_ser_baud },
    { "com1",             OPT_STR,  &opt_com1 },
    { "com2",             OPT_STR,  &opt_com2 },
    { "dom0_mem",         OPT_UINT, &opt_dom0_mem }, 
    { "ifname",           OPT_STR,  &opt_ifname },
    { "noht",             OPT_BOOL, &opt_noht },
    { "noacpi",           OPT_BOOL, &opt_noacpi },
    { "nosmp",            OPT_BOOL, &opt_nosmp },
    { "noreboot",         OPT_BOOL, &opt_noreboot },
    { "ignorebiostables", OPT_BOOL, &opt_ignorebiostables },
    { "watchdog",         OPT_BOOL, &opt_watchdog },
    { "pdb",              OPT_STR,  &opt_pdb },
    { NULL,               0,        NULL     }
};


void cmain(unsigned long magic, multiboot_info_t *mbi)
{
    struct task_struct *new_dom;
    dom0_createdomain_t dom0_params;
    unsigned long max_page;
    unsigned char *cmdline, *p;
    module_t *mod;
    int i;

    /* Parse the command-line options. */
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

    /* Backward compatibility with deprecated 'ser_baud=' cmdline option. */
    if ( opt_ser_baud != 0 )
        sprintf(opt_com1, "%u,8n1", opt_ser_baud);

    /* We initialise the serial devices very early so we can get debugging. */
    serial_init_stage1();

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

    /* Set up VGA console output, if it was enabled. */
    init_vga();

    /* HELLO WORLD --- start-of-day banner text. */
    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);

    if ( opt_ser_baud != 0 )
        printk("**WARNING**: Xen option 'ser_baud=' is deprecated! "
               "Use 'com1=' instead.\n");

    if ( magic != MULTIBOOT_BOOTLOADER_MAGIC )
    {
        printk("FATAL ERROR: Invalid magic number: 0x%08lx\n", magic);
        for ( ; ; ) ;
    }

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

    /* The array of pfn_info structures must fit into the reserved area. */
    if ( sizeof(struct pfn_info) > 24 )
    {
        printk("'struct pfn_info' too large to fit in Xen address space!\n");
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

    set_bit(PF_PRIVILEGED, &new_dom->flags);

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


/*********************************
 * Various console code follows...
 */

/* VGA text (mode 3) definitions. */
#define COLUMNS	    80
#define LINES	    25
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


void putchar_console_ring(int c)
{
    if ( console_ring.len < CONSOLE_RING_SIZE )
        console_ring.buf[console_ring.len++] = (char)c;
}


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
    __putstr(p);
    spin_unlock_irqrestore(&console_lock, flags);
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
    
    skb->dst_vif = find_net_vif(0, 0);
    (void)netif_rx(skb);

    return 1;
}


long do_console_write(char *str, unsigned int count)
{
#define SIZEOF_BUF 256
    unsigned char safe_str[SIZEOF_BUF+1];
    unsigned char single_line[SIZEOF_BUF+2];
    unsigned char line_header[30];
    unsigned char *p;
    unsigned char  c;
    unsigned long flags;
    int            j;
    
    if ( count == 0 )
        return 0;

    if ( count > SIZEOF_BUF ) 
        count = SIZEOF_BUF;
    
    if ( copy_from_user(safe_str, str, count) )
        return -EFAULT;
    safe_str[count] = '\0';
    
    sprintf(line_header, "DOM%llu: ", current->domain);
    
    p = safe_str;
    while ( *p != '\0' )
    {
        j = 0;

        while ( (c = *p++) != '\0' )
        {
            if ( c == '\n' )
                break;
            if ( (c < 32) || (c > 126) )
                continue;
            single_line[j++] = c;
        }

        single_line[j++] = '\n';
        single_line[j++] = '\0';

        spin_lock_irqsave(&console_lock, flags);
        __putstr(line_header);
        __putstr(single_line);
        spin_unlock_irqrestore(&console_lock, flags);

        if ( current->domain != 0 )
            console_export(single_line, j);
    }

    return 0;
}


/*********************************
 * Debugging/tracing/error-report.
 */

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


void __out_of_line_bug(int line)
{
    printk("kernel BUG in header file at line %d\n", line);
    BUG();
    for ( ; ; ) continue;
}


/*********************************
 * Simple syscalls.
 */

long do_xen_version(int cmd)
{
    if ( cmd != 0 )
        return -ENOSYS;
    return (XEN_VERSION<<16) | (XEN_SUBVERSION);
}

long do_ni_syscall(void)
{
    /* No-op syscall. */
    return -ENOSYS;
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

