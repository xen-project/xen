#include <stdarg.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/multiboot.h>
#include <xeno/spinlock.h>
#include <xeno/sched.h>
#include <xeno/mm.h>
#include <xeno/delay.h>
#include <xeno/skbuff.h>
#include <xeno/interrupt.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <xeno/dom0_ops.h>
#include <asm/byteorder.h>
#include <linux/if_ether.h>
#include <asm/domain_page.h>

static int xpos, ypos;
static volatile unsigned char *video;

spinlock_t console_lock = SPIN_LOCK_UNLOCKED;

struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};

/* Used by domain.c:setup_guestos */
int nr_mods;
module_t *mod;

void init_vga(void);
void init_serial(void);
void start_of_day(void);

/* Command line options and variables. */
unsigned long opt_dom0_ip = 0;
unsigned int opt_ser_baud = 9600;  /* default baud for COM1 */
unsigned int opt_dom0_mem = 16000; /* default kbytes for DOM0 */
unsigned int opt_ne_base = 0; /* NE2k NICs cannot be probed */
unsigned char opt_ifname[10] = "eth0";
int opt_noht=0, opt_noacpi=0;
enum { OPT_IP, OPT_STR, OPT_UINT, OPT_BOOL };
static struct {
    unsigned char *name;
    int type;
    void *var;
} opts[] = {
    { "ser_baud", OPT_UINT, &opt_ser_baud },
    { "dom0_ip",  OPT_IP,   &opt_dom0_ip },
    { "dom0_mem", OPT_UINT, &opt_dom0_mem }, 
    { "ne_base",  OPT_UINT, &opt_ne_base },
    { "ifname",   OPT_STR,  &opt_ifname },
    { "noht",     OPT_BOOL, &opt_noht },
    { "noacpi",   OPT_BOOL, &opt_noacpi },
    { NULL,       0,        NULL     }
};

void cmain (unsigned long magic, multiboot_info_t *mbi)
{
    struct task_struct *new_dom;
    dom0_newdomain_t dom0_params;
    unsigned long max_page;
    unsigned char *cmdline;
    int i;

    /*
     * Clear the screen. Note that serial output cannot be done properly until 
     * after command-line arguments have been parsed, and the required baud 
     * rate is known. Any messages before that will be output using the
     * seetings of the bootloader, for example. Maybe okay for error msgs...
     */
    init_vga();
    cls();

    if ( magic != MULTIBOOT_BOOTLOADER_MAGIC )
    {
        printk("Invalid magic number: 0x%x\n", (unsigned)magic);
        return;
    }

    /*
     * We require some kind of memory and module information.
     * The rest we can fake!
     */
    if ( (mbi->flags & 9) != 9 )
    {
        printk("Bad flags passed by bootloader: 0x%x\n", (unsigned)mbi->flags);
        return;
    }

    if ( mbi->mods_count == 0 )
    {
        printk("Require at least one module!\n");
        return;
    }

    /* Are mmap_* valid?  */
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

    nr_mods = mbi->mods_count;
    mod     = (module_t *)__va(mbi->mods_addr);

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

    /* INITIALISE SERIAL LINE (printk will work okay from here on). */
    init_serial();

    memcpy(&idle0_task_union, &first_task_struct, sizeof(first_task_struct));

    max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);
    init_frametable(max_page);
    printk("Initialised all memory on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT));

    init_page_allocator(mod[nr_mods-1].mod_end, MAX_MONITOR_ADDRESS);
 
    /* These things will get done by do_newdomain() for all other tasks. */
    current->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(current->shared_info, 0, sizeof(shared_info_t));
    set_fs(USER_DS);
    current->num_net_vifs = 0;

    start_of_day();

    /* Create initial domain 0. */
    dom0_params.num_vifs  = 1;
    dom0_params.memory_kb = opt_dom0_mem;

    if ( opt_dom0_ip == 0 )
        panic("Must specify an IP address for domain 0!\n");

    add_default_net_rule(0, opt_dom0_ip); // add vfr info for dom0

    new_dom = do_newdomain(0, 0);
    if ( new_dom == NULL ) panic("Error creating domain 0\n");
    if ( setup_guestos(new_dom, &dom0_params) != 0 )
    {
        panic("Could not set up DOM0 guest OS\n");
    }
	update_dom_time(new_dom->shared_info);
    wake_up(new_dom);

    cpu_idle();
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
    /* 'opt_ser_baud' baud, no parity, 1 stop bit, 8 data bits. */
    outb(0x83, SERIAL_BASE+DATA_FORMAT);
    outb(115200/opt_ser_baud, SERIAL_BASE+DIVISOR_LO);
    outb(0, SERIAL_BASE+DIVISOR_HI);
    outb(0x03, SERIAL_BASE+DATA_FORMAT);

    /* No interrupts. */
    outb(0x00, SERIAL_BASE+INT_ENABLE);
}


void putchar_serial(unsigned char c)
{
    if ( c == '\n' ) putchar_serial('\r');
    if ( (c != '\n') && (c != '\r') && ((c < 32) || (c > 126)) ) return;
    while ( !(inb(SERIAL_BASE+LINE_STATUS)&(1<<5)) ) barrier();
    outb(c, SERIAL_BASE+TX_HOLD);
}


/* VGA text (mode 3) definitions. */
#define COLUMNS	    80
#define LINES	    25
#define ATTRIBUTE    7
#define VIDEO	    __va(0xB8000)

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

    video = (unsigned char *) VIDEO;
  
    for (i = 0; i < COLUMNS * LINES * 2; i++)
        *(video + i) = 0;

    xpos = 0;
    ypos = 0;

    outw(10+(1<<(5+8)), 0x3d4); /* cursor off */
}


/* Put the character C on the screen.  */
static void putchar (int c)
{
    static char zeroarr[2*COLUMNS] = { 0 };

    putchar_serial(c);

    if (c == '\n' || c == '\r')
    {
    newline:
        xpos = 0;
        ypos++;
        if (ypos >= LINES)
        {
            ypos = LINES-1;
            memcpy((char*)video, 
                   (char*)video + 2*COLUMNS, (LINES-1)*2*COLUMNS);
            memcpy((char*)video + (LINES-1)*2*COLUMNS, 
                   zeroarr, 2*COLUMNS);
        }
        return;
    }

    *(video + (xpos + ypos * COLUMNS) * 2) = c & 0xFF;
    *(video + (xpos + ypos * COLUMNS) * 2 + 1) = ATTRIBUTE;

    xpos++;
    if (xpos >= COLUMNS)
        goto newline;
}

static inline void __putstr(const char *str)
{
    while ( *str ) putchar(*str++);
}

void printf (const char *fmt, ...)
{
    va_list args;
    char buf[1024], *p;
    unsigned long flags;

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
  
    p = buf; 
    spin_lock_irqsave(&console_lock, flags);
    while ( *p ) putchar(*p++);
    spin_unlock_irqrestore(&console_lock, flags);
}

void panic(const char *fmt, ...)
{
    va_list args;
    char buf[1024], *p;
    unsigned long flags;
    extern void machine_restart(char *);
    
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    /* Spit out multiline message in one go. */
    spin_lock_irqsave(&console_lock, flags);
    __putstr("\n****************************************\n");
    p = buf;
    while ( *p ) putchar(*p++);
    __putstr("Aieee! CPU");
    putchar((char)smp_processor_id() + '0');
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
	/* Function written by ek247
	 * Computes IP and UDP checksum.
	 * To be used for the fake console packets
	 * created in console_export
	 */

    unsigned long sum=0;

    while (count--)
    {
        sum+=*buf++;
        if (sum & 0xFFFF0000)
        {
            //carry occured, so wrap around
            sum &=0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}



/* XXX SMH: below is rather vile; pulled in to allow network console */

extern int netif_rx(struct sk_buff *); 
extern struct net_device *the_dev;

typedef struct my_udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} my_udphdr_t; 


typedef struct my_iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
	version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
	ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
} my_iphdr_t; 


typedef struct my_ethhdr {
    unsigned char   h_dest[6];   	
    unsigned char   h_source[6]; 	
    unsigned short  h_proto;        
} my_ethhdr_t; 

/*
 * Function written by ek247. Exports console output from all domains upwards 
 * to domain0, by stuffing it into a fake network packet.
 */
int console_export(char *str, int len)
{
    struct sk_buff *skb;
    struct my_iphdr *iph = NULL;  
    struct my_udphdr *udph = NULL; 
    struct my_ethhdr *ethh = NULL; 
    int hdr_size = sizeof(struct my_iphdr) + sizeof(struct my_udphdr); 
    u8 *skb_data;

    skb = dev_alloc_skb(sizeof(struct my_ethhdr) + 
                                   hdr_size + len + 20);
    if ( skb == NULL ) return 0;

    skb->dev = the_dev;
    skb_data = (u8 *)map_domain_mem((skb->pf - frame_table) << PAGE_SHIFT);
    skb_reserve(skb, 2);

    /* Get a pointer to each header. */
    ethh = (struct my_ethhdr *) 
        (skb_data + (skb->data - skb->head));
    iph  = (struct my_iphdr *)(ethh + 1);
    udph = (struct my_udphdr *)(iph + 1); 

    skb_reserve(skb, sizeof(struct my_ethhdr)); 
    skb_put(skb, hdr_size + len); 

    /* Build IP header. */
    iph->version = 4;
    iph->ihl     = 5;
    iph->frag_off= 0;
    iph->id      = 0xdead;
    iph->ttl     = 255;
    iph->protocol= 17;
    iph->daddr   = htonl(opt_dom0_ip);
    iph->saddr   = htonl(0xa9fe0001); 
    iph->tot_len = htons(hdr_size + len); 
    iph->check	 = 0;
    iph->check   = compute_cksum((__u16 *)iph, sizeof(struct my_iphdr)/2); 

    /* Build UDP header. */
    udph->source = htons(current->domain);
    udph->dest   = htons(666);
    udph->len    = htons(sizeof(struct my_udphdr) + len);
    udph->check  = 0;

    /* Build the UDP payload. */
    memcpy((char *)(udph + 1), str, len); 

    /* Fix Ethernet header. */
    memset(ethh->h_source, 0, ETH_ALEN);
    memset(ethh->h_dest,   0, ETH_ALEN);
    ethh->h_proto = htons(ETH_P_IP);
    skb->mac.ethernet= (struct ethhdr *)ethh;

    /* Keep the net rule tables happy. */
    skb->src_vif = VIF_PHYSICAL_INTERFACE;
    skb->dst_vif = 0;
    
    unmap_domain_mem(skb_data);
    
    (void)netif_rx(skb);

    return 1;
}


long do_console_write(char *str, int count)
{
#define SIZEOF_BUF 256
    unsigned char safe_str[SIZEOF_BUF];
    unsigned char exported_str[SIZEOF_BUF];
    unsigned long flags;
    int i=0;
    int j=0;
    unsigned char prev = '\n';
    
    if ( count > SIZEOF_BUF ) count = SIZEOF_BUF;
    
    if ( copy_from_user(safe_str, str, count) )
        return -EFAULT;
    
    spin_lock_irqsave(&console_lock, flags);

    __putstr("DOM"); 
    putchar(current->domain+'0'); 
    __putstr(": ");
    
    for ( i = 0; i < count; i++ )
    {
	exported_str[j++]=safe_str[i];
	
        if ( !safe_str[i] ) break;
        putchar(prev = safe_str[i]);
    }
    
    if ( prev != '\n' ) putchar('\n');
    
    spin_unlock_irqrestore(&console_lock, flags);
    
    exported_str[j]='\0';
    console_export(exported_str, j-1);
    
    return(0);
}

void __out_of_line_bug(int line)
{
    printk("kernel BUG in header file at line %d\n", line);
    BUG();
    for ( ; ; ) continue;
}
