/*
 *  linux/arch/i386/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

/*
 * This file handles the architecture-dependent parts of initialization
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/tty.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/apm_bios.h>
#ifdef CONFIG_BLK_DEV_RAM
#include <linux/blk.h>
#endif
#include <linux/highmem.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <asm/processor.h>
#include <linux/console.h>
#include <linux/module.h>
#include <asm/mtrr.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/dma.h>
#include <asm/mpspec.h>
#include <asm/mmu_context.h>
#include <asm/hypervisor.h>
#include <asm/hypervisor-ifs/dom0_ops.h>

/*
 * Point at the empty zero page to start with. We map the real shared_info
 * page as soon as fixmap is up and running.
 */
shared_info_t *HYPERVISOR_shared_info = empty_zero_page;

unsigned long *phys_to_machine_mapping;

/*
 * Machine setup..
 */

char ignore_irq13;		/* set if exception 16 works */
struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

unsigned long mmu_cr4_features;
//EXPORT_SYMBOL(mmu_cr4_features);

unsigned char * vgacon_mmap;

/*
 * Bus types ..
 */
#ifdef CONFIG_EISA
int EISA_bus;
#endif
int MCA_bus;

/* for MCA, but anyone else can use it if they want */
unsigned int machine_id;
unsigned int machine_submodel_id;
unsigned int BIOS_revision;
unsigned int mca_pentium_flag;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x10000000;

/*
 * Setup options
 */
struct drive_info_struct { char dummy[32]; } drive_info;
struct screen_info screen_info;
struct apm_info apm_info;
struct sys_desc_table_struct {
    unsigned short length;
    unsigned char table[0];
};

unsigned char aux_device_present;

extern int root_mountflags;
extern char _text, _etext, _edata, _end;

int enable_acpi_smp_table;

/* Raw start-of-day parameters from the hypervisor. */
union start_info_union start_info_union;

#define COMMAND_LINE_SIZE 256
static char command_line[COMMAND_LINE_SIZE];
char saved_command_line[COMMAND_LINE_SIZE];

static void __init parse_mem_cmdline (char ** cmdline_p)
{
    char c = ' ', *to = command_line, *from = saved_command_line;
    int len = 0;

    /* Save unparsed command line copy for /proc/cmdline */
    memcpy(saved_command_line, start_info.cmd_line, COMMAND_LINE_SIZE);
    saved_command_line[COMMAND_LINE_SIZE-1] = '\0';

    for (;;) {
        /*
         * "mem=nopentium" disables the 4MB page tables.
         * "mem=XXX[kKmM]" defines a memory region from HIGH_MEM
         * to <mem>, overriding the bios size.
         * "mem=XXX[KkmM]@XXX[KkmM]" defines a memory region from
         * <start> to <start>+<mem>, overriding the bios size.
         */
        if (c == ' ' && !memcmp(from, "mem=", 4)) {
            if (to != command_line)
                to--;
            if (!memcmp(from+4, "nopentium", 9)) {
                from += 9+4;
            } else if (!memcmp(from+4, "exactmap", 8)) {
                from += 8+4;
            } else {
                (void)memparse(from+4, &from);
                if (*from == '@')
                    (void)memparse(from+1, &from);
            }
        }

        c = *(from++);
        if (!c)
            break;
        if (COMMAND_LINE_SIZE <= ++len)
            break;
        *(to++) = c;
    }
    *to = '\0';
    *cmdline_p = command_line;
}

void __init setup_arch(char **cmdline_p)
{
    unsigned long start_pfn, max_pfn, max_low_pfn;
    unsigned long bootmap_size;
    unsigned long i;

    extern void hypervisor_callback(void);
    extern void failsafe_callback(void);

    extern unsigned long cpu0_pte_quicklist[];
    extern unsigned long cpu0_pgd_quicklist[];

    HYPERVISOR_set_callbacks(
        __KERNEL_CS, (unsigned long)hypervisor_callback,
        __KERNEL_CS, (unsigned long)failsafe_callback);

    boot_cpu_data.pgd_quick = cpu0_pgd_quicklist;
    boot_cpu_data.pte_quick = cpu0_pte_quicklist;

    ROOT_DEV = MKDEV(RAMDISK_MAJOR,0);
    memset(&drive_info, 0, sizeof(drive_info));
    memset(&screen_info, 0, sizeof(screen_info));
    
    /* This is drawn from a dump from vgacon:startup in standard Linux. */
    screen_info.orig_video_mode = 3; 
    screen_info.orig_video_isVGA = 1;
    screen_info.orig_video_lines = 25;
    screen_info.orig_video_cols = 80;
    screen_info.orig_video_ega_bx = 3;
    screen_info.orig_video_points = 16;

    memset(&apm_info.bios, 0, sizeof(apm_info.bios));
    aux_device_present = 0; 
#ifdef CONFIG_BLK_DEV_RAM
    rd_image_start = 0;
    rd_prompt = 0;
    rd_doload = 0;
#endif

    root_mountflags &= ~MS_RDONLY;
    init_mm.start_code = (unsigned long) &_text;
    init_mm.end_code = (unsigned long) &_etext;
    init_mm.end_data = (unsigned long) &_edata;
    init_mm.brk = (unsigned long) &_end;

    parse_mem_cmdline(cmdline_p);

#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((x) << PAGE_SHIFT)

/*
 * 128MB for vmalloc and initrd
 */
#define VMALLOC_RESERVE	(unsigned long)(128 << 20)
#define MAXMEM		(unsigned long)(HYPERVISOR_VIRT_START-PAGE_OFFSET-VMALLOC_RESERVE)
#define MAXMEM_PFN	PFN_DOWN(MAXMEM)
#define MAX_NONPAE_PFN	(1 << 20)

    /*
     * partially used pages are not usable - thus
     * we are rounding upwards:
     */
#ifdef CONFIG_BLK_DEV_INITRD
    if ( start_info.mod_start )
        start_pfn = PFN_UP(__pa(start_info.mod_start + start_info.mod_len));
    else
#endif
    start_pfn = PFN_UP(__pa(&_end));
    max_pfn = start_info.nr_pages;

    /*
     * Determine low and high memory ranges:
     */
    max_low_pfn = max_pfn;
    if (max_low_pfn > MAXMEM_PFN) {
        max_low_pfn = MAXMEM_PFN;
#ifndef CONFIG_HIGHMEM
        /* Maximum memory usable is what is directly addressable */
        printk(KERN_WARNING "Warning only %ldMB will be used.\n",
               MAXMEM>>20);
        if (max_pfn > MAX_NONPAE_PFN)
            printk(KERN_WARNING "Use a PAE enabled kernel.\n");
        else
            printk(KERN_WARNING "Use a HIGHMEM enabled kernel.\n");
#else /* !CONFIG_HIGHMEM */
#ifndef CONFIG_X86_PAE
        if (max_pfn > MAX_NONPAE_PFN) {
            max_pfn = MAX_NONPAE_PFN;
            printk(KERN_WARNING "Warning only 4GB will be used.\n");
            printk(KERN_WARNING "Use a PAE enabled kernel.\n");
        }
#endif /* !CONFIG_X86_PAE */
#endif /* !CONFIG_HIGHMEM */
    }

#ifdef CONFIG_HIGHMEM
    highstart_pfn = highend_pfn = max_pfn;
    if (max_pfn > MAXMEM_PFN) {
        highstart_pfn = MAXMEM_PFN;
        printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
               pages_to_mb(highend_pfn - highstart_pfn));
    }
#endif

    /*
     * Initialize the boot-time allocator, and free up all RAM.
     * Then reserve space for OS image, and the bootmem bitmap.
     */
    bootmap_size = init_bootmem(start_pfn, max_low_pfn);
    free_bootmem(0, PFN_PHYS(max_low_pfn));
    reserve_bootmem(0, PFN_PHYS(start_pfn) + bootmap_size + PAGE_SIZE-1);

    /* Now reserve space for the hypervisor-provided page tables. */
    {
        unsigned long *pgd = (unsigned long *)start_info.pt_base;
        unsigned long  pte;
        int i;
        reserve_bootmem(__pa(pgd), PAGE_SIZE);
        for ( i = 0; i < (HYPERVISOR_VIRT_START>>22); i++ )
        {
            unsigned long pgde = *pgd++;
            if ( !(pgde & 1) ) continue;
            pte = machine_to_phys(pgde & PAGE_MASK);
            reserve_bootmem(pte, PAGE_SIZE);
        }
    }
    cur_pgd = init_mm.pgd = (pgd_t *)start_info.pt_base;

    /* Now initialise the physical->machine mapping table. */
    phys_to_machine_mapping = alloc_bootmem(max_pfn * sizeof(unsigned long));
    for ( i = 0; i < max_pfn; i++ )
    {
        unsigned long pgde, *ppte;
        unsigned long pfn = i + (PAGE_OFFSET >> PAGE_SHIFT);
        pgde = *((unsigned long *)start_info.pt_base + (pfn >> 10));
        ppte = (unsigned long *)machine_to_phys(pgde & PAGE_MASK) + (pfn&1023);
        phys_to_machine_mapping[i] = 
            (*(unsigned long *)__va(ppte)) >> PAGE_SHIFT;
    }

#ifdef CONFIG_BLK_DEV_INITRD
    if (start_info.mod_start) {
        if ((__pa(start_info.mod_start) + start_info.mod_len) <= 
            (max_low_pfn << PAGE_SHIFT)) {
            initrd_start = start_info.mod_start;
            initrd_end   = initrd_start + start_info.mod_len;
            initrd_below_start_ok = 1;
        }
        else {
            printk(KERN_ERR "initrd extends beyond end of memory "
                   "(0x%08lx > 0x%08lx)\ndisabling initrd\n",
                   __pa(start_info.mod_start) + start_info.mod_len,
                   max_low_pfn << PAGE_SHIFT);
            initrd_start = 0;
        }
    }
#endif

    paging_init();

    /* We are privileged guest os - should have IO privileges. */
    if ( start_info.flags & SIF_PRIVILEGED ) 
    {
        dom0_op_t op;
        op.cmd           = DOM0_IOPL;
        op.u.iopl.domain = start_info.dom_id;
        op.u.iopl.iopl   = 1;
        if( HYPERVISOR_dom0_op(&op) != 0 )
            panic("Unable to obtain IOPL, despite being SIF_PRIVILEGED");
        current->thread.io_pl = 1;
    }

    if(start_info.flags & SIF_CONSOLE)
    {
        if( !(start_info.flags & SIF_PRIVILEGED) )
            panic("Xen granted us console access but not privileged status");

#if defined(CONFIG_VT)
#if defined(CONFIG_VGA_CONSOLE)
        conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
        conswitchp = &dummy_con;
#endif
#endif
    }
}

static int cachesize_override __initdata = -1;
static int __init cachesize_setup(char *str)
{
    get_option (&str, &cachesize_override);
    return 1;
}
__setup("cachesize=", cachesize_setup);


static int __init get_model_name(struct cpuinfo_x86 *c)
{
    unsigned int *v;
    char *p, *q;

    if (cpuid_eax(0x80000000) < 0x80000004)
        return 0;

    v = (unsigned int *) c->x86_model_id;
    cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
    cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
    cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
    c->x86_model_id[48] = 0;

    /* Intel chips right-justify this string for some dumb reason;
       undo that brain damage */
    p = q = &c->x86_model_id[0];
    while ( *p == ' ' )
        p++;
    if ( p != q ) {
        while ( *p )
            *q++ = *p++;
        while ( q <= &c->x86_model_id[48] )
            *q++ = '\0';	/* Zero-pad the rest */
    }

    return 1;
}


static void __init display_cacheinfo(struct cpuinfo_x86 *c)
{
    unsigned int n, dummy, ecx, edx, l2size;

    n = cpuid_eax(0x80000000);

    if (n >= 0x80000005) {
        cpuid(0x80000005, &dummy, &dummy, &ecx, &edx);
        printk(KERN_INFO "CPU: L1 I Cache: %dK (%d bytes/line), D cache %dK (%d bytes/line)\n",
               edx>>24, edx&0xFF, ecx>>24, ecx&0xFF);
        c->x86_cache_size=(ecx>>24)+(edx>>24);	
    }

    if (n < 0x80000006)	/* Some chips just has a large L1. */
        return;

    ecx = cpuid_ecx(0x80000006);
    l2size = ecx >> 16;

    /* AMD errata T13 (order #21922) */
    if ((c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 6)) {
        if (c->x86_model == 3 && c->x86_mask == 0)	/* Duron Rev A0 */
            l2size = 64;
        if (c->x86_model == 4 &&
            (c->x86_mask==0 || c->x86_mask==1))	/* Tbird rev A1/A2 */
            l2size = 256;
    }

    /* Intel PIII Tualatin. This comes in two flavours.
     * One has 256kb of cache, the other 512. We have no way
     * to determine which, so we use a boottime override
     * for the 512kb model, and assume 256 otherwise.
     */
    if ((c->x86_vendor == X86_VENDOR_INTEL) && (c->x86 == 6) &&
        (c->x86_model == 11) && (l2size == 0))
        l2size = 256;

    if (c->x86_vendor == X86_VENDOR_CENTAUR) {
	/* VIA C3 CPUs (670-68F) need further shifting. */
	if ((c->x86 == 6) &&
	    ((c->x86_model == 7) || (c->x86_model == 8))) {
		l2size >>= 8;
	}

	/* VIA also screwed up Nehemiah stepping 1, and made
	   it return '65KB' instead of '64KB'
	   - Note, it seems this may only be in engineering samples. */
	if ((c->x86==6) && (c->x86_model==9) &&
	    (c->x86_mask==1) && (l2size==65))
		l2size -= 1;
    }

    /* Allow user to override all this if necessary. */
    if (cachesize_override != -1)
        l2size = cachesize_override;

    if ( l2size == 0 )
        return;		/* Again, no L2 cache is possible */

    c->x86_cache_size = l2size;

    printk(KERN_INFO "CPU: L2 Cache: %dK (%d bytes/line)\n",
           l2size, ecx & 0xFF);
}


static int __init init_amd(struct cpuinfo_x86 *c)
{
    int r;

    /* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
       3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
    clear_bit(0*32+31, &c->x86_capability);
	
    r = get_model_name(c);

    switch(c->x86)
    {
    case 6:	/* An Athlon/Duron. We can trust the BIOS probably */
        break;		
    default:
        panic("Unsupported AMD processor\n");
    }

    display_cacheinfo(c);
    return r;
}


static void __init init_intel(struct cpuinfo_x86 *c)
{
    char *p = NULL;
    unsigned int l1i = 0, l1d = 0, l2 = 0, l3 = 0; /* Cache sizes */

    if (c->cpuid_level > 1) {
        /* supports eax=2  call */
        int i, j, n;
        int regs[4];
        unsigned char *dp = (unsigned char *)regs;

        /* Number of times to iterate */
        n = cpuid_eax(2) & 0xFF;

        for ( i = 0 ; i < n ; i++ ) {
            cpuid(2, &regs[0], &regs[1], &regs[2], &regs[3]);
			
            /* If bit 31 is set, this is an unknown format */
            for ( j = 0 ; j < 3 ; j++ ) {
                if ( regs[j] < 0 ) regs[j] = 0;
            }

            /* Byte 0 is level count, not a descriptor */
            for ( j = 1 ; j < 16 ; j++ ) {
                unsigned char des = dp[j];
                unsigned char dl, dh;
                unsigned int cs;

                dh = des >> 4;
                dl = des & 0x0F;

				/* Black magic... */

                switch ( dh )
                {
                case 0:
                    switch ( dl ) {
                    case 6:
                        /* L1 I cache */
                        l1i += 8;
                        break;
                    case 8:
                        /* L1 I cache */
                        l1i += 16;
                        break;
                    case 10:
                        /* L1 D cache */
                        l1d += 8;
                        break;
                    case 12:
                        /* L1 D cache */
                        l1d += 16;
                        break;
                    default:;
                        /* TLB, or unknown */
                    }
                    break;
                case 2:
                    if ( dl ) {
                        /* L3 cache */
                        cs = (dl-1) << 9;
                        l3 += cs;
                    }
                    break;
                case 4:
                    if ( c->x86 > 6 && dl ) {
                        /* P4 family */
                        /* L3 cache */
                        cs = 128 << (dl-1);
                        l3 += cs;
                        break;
                    }
                    /* else same as 8 - fall through */
                case 8:
                    if ( dl ) {
                        /* L2 cache */
                        cs = 128 << (dl-1);
                        l2 += cs;
                    }
                    break;
                case 6:
                    if (dl > 5) {
                        /* L1 D cache */
                        cs = 8<<(dl-6);
                        l1d += cs;
                    }
                    break;
                case 7:
                    if ( dl >= 8 ) 
                    {
                        /* L2 cache */
                        cs = 64<<(dl-8);
                        l2 += cs;
                    } else {
                        /* L0 I cache, count as L1 */
                        cs = dl ? (16 << (dl-1)) : 12;
                        l1i += cs;
                    }
                    break;
                default:
                    /* TLB, or something else we don't know about */
                    break;
                }
            }
        }
        if ( l1i || l1d )
            printk(KERN_INFO "CPU: L1 I cache: %dK, L1 D cache: %dK\n",
                   l1i, l1d);
        if ( l2 )
            printk(KERN_INFO "CPU: L2 cache: %dK\n", l2);
        if ( l3 )
            printk(KERN_INFO "CPU: L3 cache: %dK\n", l3);

        /*
         * This assumes the L3 cache is shared; it typically lives in
         * the northbridge.  The L1 caches are included by the L2
         * cache, and so should not be included for the purpose of
         * SMP switching weights.
         */
        c->x86_cache_size = l2 ? l2 : (l1i+l1d);
    }

    /* SEP CPUID bug: Pentium Pro reports SEP but doesn't have it */
    if ( c->x86 == 6 && c->x86_model < 3 && c->x86_mask < 3 )
        clear_bit(X86_FEATURE_SEP, &c->x86_capability);
	
    /* Names for the Pentium II/Celeron processors 
       detectable only by also checking the cache size.
       Dixon is NOT a Celeron. */
    if (c->x86 == 6) {
        switch (c->x86_model) {
        case 5:
            if (l2 == 0)
                p = "Celeron (Covington)";
            if (l2 == 256)
                p = "Mobile Pentium II (Dixon)";
            break;
			
        case 6:
            if (l2 == 128)
                p = "Celeron (Mendocino)";
            break;
			
        case 8:
            if (l2 == 128)
                p = "Celeron (Coppermine)";
            break;
        }
    }

    if ( p )
        strcpy(c->x86_model_id, p);
}

void __init get_cpu_vendor(struct cpuinfo_x86 *c)
{
    char *v = c->x86_vendor_id;

    if (!strcmp(v, "GenuineIntel"))
        c->x86_vendor = X86_VENDOR_INTEL;
    else if (!strcmp(v, "AuthenticAMD"))
        c->x86_vendor = X86_VENDOR_AMD;
    else
        c->x86_vendor = X86_VENDOR_UNKNOWN;
}

struct cpu_model_info {
    int vendor;
    int family;
    char *model_names[16];
};

/* Naming convention should be: <Name> [(<Codename>)] */
/* This table only is used unless init_<vendor>() below doesn't set it; */
/* in particular, if CPUID levels 0x80000002..4 are supported, this isn't used */
static struct cpu_model_info cpu_models[] __initdata = {
    { X86_VENDOR_INTEL,	6,
      { "Pentium Pro A-step", "Pentium Pro", NULL, "Pentium II (Klamath)", 
        NULL, "Pentium II (Deschutes)", "Mobile Pentium II",
        "Pentium III (Katmai)", "Pentium III (Coppermine)", NULL,
        "Pentium III (Cascades)", NULL, NULL, NULL, NULL }},
    { X86_VENDOR_AMD,	6, /* Is this this really necessary?? */
      { "Athlon", "Athlon",
        "Athlon", NULL, "Athlon", NULL,
        NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL }}
};

/* Look up CPU names by table lookup. */
static char __init *table_lookup_model(struct cpuinfo_x86 *c)
{
    struct cpu_model_info *info = cpu_models;
    int i;

    if ( c->x86_model >= 16 )
        return NULL;	/* Range check */

    for ( i = 0 ; i < sizeof(cpu_models)/sizeof(struct cpu_model_info) ; i++ ) {
        if ( info->vendor == c->x86_vendor &&
             info->family == c->x86 ) {
            return info->model_names[c->x86_model];
        }
        info++;
    }
    return NULL;		/* Not found */
}



/* Standard macro to see if a specific flag is changeable */
static inline int flag_is_changeable_p(u32 flag)
{
    u32 f1, f2;

    asm("pushfl\n\t"
        "pushfl\n\t"
        "popl %0\n\t"
        "movl %0,%1\n\t"
        "xorl %2,%0\n\t"
        "pushl %0\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %0\n\t"
        "popfl\n\t"
        : "=&r" (f1), "=&r" (f2)
        : "ir" (flag));

    return ((f1^f2) & flag) != 0;
}


/* Probe for the CPUID instruction */
static int __init have_cpuid_p(void)
{
    return flag_is_changeable_p(X86_EFLAGS_ID);
}



/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void __init identify_cpu(struct cpuinfo_x86 *c)
{
    int junk, i;
    u32 xlvl, tfms;

    c->loops_per_jiffy = loops_per_jiffy;
    c->x86_cache_size = -1;
    c->x86_vendor = X86_VENDOR_UNKNOWN;
    c->cpuid_level = -1;	/* CPUID not detected */
    c->x86_model = c->x86_mask = 0;	/* So far unknown... */
    c->x86_vendor_id[0] = '\0'; /* Unset */
    c->x86_model_id[0] = '\0';  /* Unset */
    memset(&c->x86_capability, 0, sizeof c->x86_capability);
    c->hard_math = 1;

    if ( !have_cpuid_p() ) {
        panic("Processor must support CPUID\n");
    } else {
        /* CPU does have CPUID */

        /* Get vendor name */
        cpuid(0x00000000, &c->cpuid_level,
              (int *)&c->x86_vendor_id[0],
              (int *)&c->x86_vendor_id[8],
              (int *)&c->x86_vendor_id[4]);
		
        get_cpu_vendor(c);
        /* Initialize the standard set of capabilities */
        /* Note that the vendor-specific code below might override */

        /* Intel-defined flags: level 0x00000001 */
        if ( c->cpuid_level >= 0x00000001 ) {
            cpuid(0x00000001, &tfms, &junk, &junk,
                  &c->x86_capability[0]);
            c->x86 = (tfms >> 8) & 15;
            c->x86_model = (tfms >> 4) & 15;
            c->x86_mask = tfms & 15;
        } else {
            /* Have CPUID level 0 only - unheard of */
            c->x86 = 4;
        }

        /* AMD-defined flags: level 0x80000001 */
        xlvl = cpuid_eax(0x80000000);
        if ( (xlvl & 0xffff0000) == 0x80000000 ) {
            if ( xlvl >= 0x80000001 )
                c->x86_capability[1] = cpuid_edx(0x80000001);
            if ( xlvl >= 0x80000004 )
                get_model_name(c); /* Default name */
        }

        /* Transmeta-defined flags: level 0x80860001 */
        xlvl = cpuid_eax(0x80860000);
        if ( (xlvl & 0xffff0000) == 0x80860000 ) {
            if (  xlvl >= 0x80860001 )
                c->x86_capability[2] = cpuid_edx(0x80860001);
        }
    }

    printk(KERN_DEBUG "CPU: Before vendor init, caps: %08x %08x %08x, vendor = %d\n",
           c->x86_capability[0],
           c->x86_capability[1],
           c->x86_capability[2],
           c->x86_vendor);

    /*
     * Vendor-specific initialization.  In this section we
     * canonicalize the feature flags, meaning if there are
     * features a certain CPU supports which CPUID doesn't
     * tell us, CPUID claiming incorrect flags, or other bugs,
     * we handle them here.
     *
     * At the end of this section, c->x86_capability better
     * indicate the features this CPU genuinely supports!
     */
    switch ( c->x86_vendor ) {
    case X86_VENDOR_AMD:
        init_amd(c);
        break;

    case X86_VENDOR_INTEL:
        init_intel(c);
        break;

    default:
        panic("Unsupported CPU vendor\n");
    }
	
    printk(KERN_DEBUG "CPU: After vendor init, caps: %08x %08x %08x %08x\n",
           c->x86_capability[0],
           c->x86_capability[1],
           c->x86_capability[2],
           c->x86_capability[3]);


    /* If the model name is still unset, do table lookup. */
    if ( !c->x86_model_id[0] ) {
        char *p;
        p = table_lookup_model(c);
        if ( p )
            strcpy(c->x86_model_id, p);
        else
            /* Last resort... */
            sprintf(c->x86_model_id, "%02x/%02x",
                    c->x86_vendor, c->x86_model);
    }

    /* Now the feature flags better reflect actual CPU features! */

    printk(KERN_DEBUG "CPU:     After generic, caps: %08x %08x %08x %08x\n",
           c->x86_capability[0],
           c->x86_capability[1],
           c->x86_capability[2],
           c->x86_capability[3]);

    /*
     * On SMP, boot_cpu_data holds the common feature set between
     * all CPUs; so make sure that we indicate which features are
     * common between the CPUs.  The first time this routine gets
     * executed, c == &boot_cpu_data.
     */
    if ( c != &boot_cpu_data ) {
        /* AND the already accumulated flags with these */
        for ( i = 0 ; i < NCAPINTS ; i++ )
            boot_cpu_data.x86_capability[i] &= c->x86_capability[i];
    }

    printk(KERN_DEBUG "CPU:             Common caps: %08x %08x %08x %08x\n",
           boot_cpu_data.x86_capability[0],
           boot_cpu_data.x86_capability[1],
           boot_cpu_data.x86_capability[2],
           boot_cpu_data.x86_capability[3]);
}


/* These need to match <asm/processor.h> */
static char *cpu_vendor_names[] __initdata = {
    "Intel", "Cyrix", "AMD", "UMC", "NexGen", "Centaur", "Rise", "Transmeta" };


void __init print_cpu_info(struct cpuinfo_x86 *c)
{
    char *vendor = NULL;

    if (c->x86_vendor < sizeof(cpu_vendor_names)/sizeof(char *))
        vendor = cpu_vendor_names[c->x86_vendor];
    else if (c->cpuid_level >= 0)
        vendor = c->x86_vendor_id;

    if (vendor && strncmp(c->x86_model_id, vendor, strlen(vendor)))
        printk("%s ", vendor);

    if (!c->x86_model_id[0])
        printk("%d86", c->x86);
    else
        printk("%s", c->x86_model_id);

    if (c->x86_mask || c->cpuid_level >= 0) 
        printk(" stepping %02x\n", c->x86_mask);
    else
        printk("\n");
}

/*
 *	Get CPU information for use by the procfs.
 */
static int show_cpuinfo(struct seq_file *m, void *v)
{
    /* 
     * These flag bits must match the definitions in <asm/cpufeature.h>.
     * NULL means this bit is undefined or reserved; either way it doesn't
     * have meaning as far as Linux is concerned.  Note that it's important
     * to realize there is a difference between this table and CPUID -- if
     * applications want to get the raw CPUID data, they should access
     * /dev/cpu/<cpu_nr>/cpuid instead.
	 */
    static char *x86_cap_flags[] = {
        /* Intel-defined */
        "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
        "cx8", "apic", NULL, "sep", "mtrr", "pge", "mca", "cmov",
        "pat", "pse36", "pn", "clflush", NULL, "dts", "acpi", "mmx",
        "fxsr", "sse", "sse2", "ss", NULL, "tm", "ia64", NULL,

        /* AMD-defined */
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, "syscall", NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, "mmxext", NULL,
        NULL, NULL, NULL, NULL, NULL, "lm", "3dnowext", "3dnow",

        /* Transmeta-defined */
        "recovery", "longrun", NULL, "lrti", NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

        /* Other (Linux-defined) */
        "cxmmx", "k6_mtrr", "cyrix_arr", "centaur_mcr", NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    };
    struct cpuinfo_x86 *c = v;
    int i, n = c - cpu_data;
    int fpu_exception;

#ifdef CONFIG_SMP
    if (!(cpu_online_map & (1<<n)))
        return 0;
#endif
    seq_printf(m, "processor\t: %d\n"
               "vendor_id\t: %s\n"
               "cpu family\t: %d\n"
               "model\t\t: %d\n"
               "model name\t: %s\n",
               n,
               c->x86_vendor_id[0] ? c->x86_vendor_id : "unknown",
               c->x86,
               c->x86_model,
               c->x86_model_id[0] ? c->x86_model_id : "unknown");

    if (c->x86_mask || c->cpuid_level >= 0)
        seq_printf(m, "stepping\t: %d\n", c->x86_mask);
    else
        seq_printf(m, "stepping\t: unknown\n");

    if ( test_bit(X86_FEATURE_TSC, &c->x86_capability) ) {
        seq_printf(m, "cpu MHz\t\t: %lu.%03lu\n",
                   cpu_khz / 1000, (cpu_khz % 1000));
    }

    /* Cache size */
    if (c->x86_cache_size >= 0)
        seq_printf(m, "cache size\t: %d KB\n", c->x86_cache_size);
	
	/* We use exception 16 if we have hardware math and we've either seen it or the CPU claims it is internal */
    fpu_exception = c->hard_math && (ignore_irq13 || cpu_has_fpu);
    seq_printf(m, "fdiv_bug\t: %s\n"
               "hlt_bug\t\t: %s\n"
               "f00f_bug\t: %s\n"
               "coma_bug\t: %s\n"
               "fpu\t\t: %s\n"
               "fpu_exception\t: %s\n"
               "cpuid level\t: %d\n"
               "wp\t\t: %s\n"
               "flags\t\t:",
               c->fdiv_bug ? "yes" : "no",
               c->hlt_works_ok ? "no" : "yes",
               c->f00f_bug ? "yes" : "no",
               c->coma_bug ? "yes" : "no",
               c->hard_math ? "yes" : "no",
               fpu_exception ? "yes" : "no",
               c->cpuid_level,
               c->wp_works_ok ? "yes" : "no");

    for ( i = 0 ; i < 32*NCAPINTS ; i++ )
        if ( test_bit(i, &c->x86_capability) &&
             x86_cap_flags[i] != NULL )
            seq_printf(m, " %s", x86_cap_flags[i]);

    seq_printf(m, "\nbogomips\t: %lu.%02lu\n\n",
               c->loops_per_jiffy/(500000/HZ),
               (c->loops_per_jiffy/(5000/HZ)) % 100);
    return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
    return *pos < NR_CPUS ? cpu_data + *pos : NULL;
}
static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
    ++*pos;
    return c_start(m, pos);
}
static void c_stop(struct seq_file *m, void *v)
{
}
struct seq_operations cpuinfo_op = {
    start:	c_start,
    next:	c_next,
    stop:	c_stop,
    show:	show_cpuinfo,
};

unsigned long cpu_initialized __initdata = 0;

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void __init cpu_init (void)
{
    int nr = smp_processor_id();

    if (test_and_set_bit(nr, &cpu_initialized)) {
        printk(KERN_WARNING "CPU#%d already initialized!\n", nr);
        for (;;) __sti();
    }
    printk(KERN_INFO "Initializing CPU#%d\n", nr);

    /*
     * set up and load the per-CPU TSS and LDT
     */
    atomic_inc(&init_mm.mm_count);
    current->active_mm = &init_mm;
    if(current->mm)
        BUG();
    enter_lazy_tlb(&init_mm, current, nr);

    HYPERVISOR_stack_switch(__KERNEL_DS, current->thread.esp0);

    load_LDT(&init_mm);
    flush_page_update_queue();

    /* Force FPU initialization. */
    current->flags &= ~PF_USEDFPU;
    current->used_math = 0;
    stts();
}


/******************************************************************************
 * Time-to-die callback handling.
 */

static void time_to_die(int irq, void *unused, struct pt_regs *regs)
{
    extern void ctrl_alt_del(void);
    ctrl_alt_del();
}

static int __init setup_death_event(void)
{
    (void)request_irq(_EVENT_DIE, time_to_die, 0, "die", NULL);
    return 0;
}

__initcall(setup_death_event);
