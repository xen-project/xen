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

/* VGA text definitions. */
#define COLUMNS	    80
#define LINES	    24
#define ATTRIBUTE    7
#define VIDEO	    __va(0xB8000)

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

void init_serial(void);
void start_of_day(void);

/* Command line options and variables. */
unsigned long opt_ipbase=0, opt_nfsserv=0, opt_gateway=0, opt_netmask=0;
unsigned char opt_nfsroot[50]="";
unsigned int opt_dom0_mem = 16000; /* default kbytes for DOM0 */
enum { OPT_IP, OPT_STR, OPT_UINT };
static struct {
    unsigned char *name;
    int type;
    void *var;
} opts[] = {
    { "ipbase",   OPT_IP,   &opt_ipbase  },
    { "nfsserv",  OPT_IP,   &opt_nfsserv },
    { "gateway",  OPT_IP,   &opt_gateway },
    { "netmask",  OPT_IP,   &opt_netmask },
    { "nfsroot",  OPT_STR,  &opt_nfsroot },
    { "dom0_mem", OPT_UINT, &opt_dom0_mem }, 
    { NULL,       0,        NULL     }
};

void cmain (unsigned long magic, multiboot_info_t *mbi)
{
    struct task_struct *new_dom;
    dom0_newdomain_t dom0_params;
    unsigned long max_page, remaining_hypervisor_memory;
    unsigned char *cmdline;
    int i;

    init_serial();
    cls();

    if ( magic != MULTIBOOT_BOOTLOADER_MAGIC )
    {
        printf("Invalid magic number: 0x%x\n", (unsigned)magic);
        return;
    }

    /*
     * We require some kind of memory and module information.
     * The rest we can fake!
     */
    if ( (mbi->flags & 9) != 9 )
    {
        printf("Bad flags passed by bootloader: 0x%x\n", (unsigned)mbi->flags);
        return;
    }

    if ( mbi->mods_count == 0 )
    {
        printf("Require at least one module!\n");
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
            if ( (opt = strchr(cmdline, '=')) == NULL ) break;
            *opt++ = '\0';
            opt_end = strchr(opt, ' ');
            if ( opt_end != NULL ) *opt_end++ = '\0';
            for ( i = 0; opts[i].name != NULL; i++ )
            {
                if ( strcmp(opts[i].name, cmdline ) == 0 )
                {
                    if ( opts[i].type == OPT_IP )
                    {
                        *(unsigned long *)opts[i].var = str_to_quad(opt);
                    }
                    else if(opts[i].type == OPT_STR)
                    {
                        strcpy(opts[i].var, opt);
                    }
                    else /* opts[i].type == OPT_UINT */
                    {
                        *(unsigned int *)opts[i].var = simple_strtol(opt, (char **)&opt, 10);
                    }
                    break;
                }
            }
            cmdline = opt_end;
        }
    }

    memcpy(&idle0_task_union, &first_task_struct, sizeof(first_task_struct));

    max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);
    if ( max_page > (MAX_USABLE_ADDRESS >> PAGE_SHIFT) )
        max_page = MAX_USABLE_ADDRESS >> PAGE_SHIFT;
    /* mem_upper is address of first memory hole in high memory, minus 1MB. */
    /* PS. mem_upper is in kB. */
    remaining_hypervisor_memory = init_frametable(max_page);
    printk("Initialised %luMB of memory on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT), (mbi->mem_upper>>10)+1);

    init_page_allocator(mod[nr_mods-1].mod_end, remaining_hypervisor_memory);
 
    /* These things will get done by do_newdomain() for all other tasks. */
    current->shared_info = (void *)get_free_page(GFP_KERNEL);
    memset(current->shared_info, 0, sizeof(shared_info_t));
    set_fs(USER_DS);
    current->num_net_vifs = 0;

    start_of_day();

    /* Create initial domain 0. */
    dom0_params.num_vifs  = 1;
    dom0_params.memory_kb = opt_dom0_mem;

    new_dom = do_newdomain();
    if ( new_dom == NULL ) panic("Error creating domain 0\n");
    new_dom->processor = 0;
    new_dom->domain    = 0;
    if ( setup_guestos(new_dom, &dom0_params) != 0 )
    {
        panic("Could not set up DOM0 guest OS\n");
    }
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
    /* 9600 baud, no parity, 1 stop bit, 8 data bits. */
    outb(0x83, SERIAL_BASE+DATA_FORMAT);
    outb(12, SERIAL_BASE+DIVISOR_LO);
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


/* Clear the screen and initialize VIDEO, XPOS and YPOS.  */
void cls (void)
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


long do_console_write(char *str, int count)
{
#define SIZEOF_BUF 256
    unsigned char safe_str[SIZEOF_BUF];
    unsigned long flags;
    int i;
    unsigned char prev = '\n';

    if ( count > SIZEOF_BUF ) count = SIZEOF_BUF;

    if ( copy_from_user(safe_str, str, count) )
        return -EFAULT;
        
    spin_lock_irqsave(&console_lock, flags);
    for ( i = 0; i < count; i++ )
    {
        if ( prev == '\n' )
        {
            __putstr("DOM"); 
            putchar(current->domain+'0'); 
            __putstr(": ");
        }
        if ( !safe_str[i] ) break;
        putchar(prev = safe_str[i]);
    }
    if ( prev != '\n' ) putchar('\n');
    spin_unlock_irqrestore(&console_lock, flags);

    return(0);
}
