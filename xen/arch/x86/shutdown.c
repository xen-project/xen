/******************************************************************************
 * arch/x86/shutdown.c
 *
 * x86-specific shutdown handling.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/dmi.h>
#include <xen/irq.h>
#include <xen/console.h>
#include <xen/shutdown.h>
#include <xen/acpi.h>
#include <asm/msr.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/tboot.h>
#include <asm/apic.h>

enum reboot_type {
        BOOT_TRIPLE = 't',
        BOOT_KBD = 'k',
        BOOT_ACPI = 'a',
        BOOT_BIOS = 'b',
};

static long no_idt[2];
static int reboot_mode;

/*
 * reboot=b[ios] | t[riple] | k[bd] | n[o] [, [w]arm | [c]old]
 * warm   Don't set the cold reboot flag
 * cold   Set the cold reboot flag
 * bios   Reboot by jumping through the BIOS (only for X86_32)
 * triple Force a triple fault (init)
 * kbd    Use the keyboard controller. cold reset (default)
 * acpi   Use the RESET_REG in the FADT
 */
static enum reboot_type reboot_type = BOOT_ACPI;
static void __init set_reboot_type(char *str)
{
    for ( ; ; )
    {
        switch ( *str )
        {
        case 'n': /* no reboot */
            opt_noreboot = 1;
            break;
        case 'w': /* "warm" reboot (no memory testing etc) */
            reboot_mode = 0x1234;
            break;
        case 'c': /* "cold" reboot (with memory testing etc) */
            reboot_mode = 0x0;
            break;
        case 'b':
        case 'a':
        case 'k':
        case 't':
            reboot_type = *str;
            break;
        }
        if ( (str = strchr(str, ',')) == NULL )
            break;
        str++;
    }
}
custom_param("reboot", set_reboot_type);

static inline void kb_wait(void)
{
    int i;

    for ( i = 0; i < 0x10000; i++ )
        if ( (inb_p(0x64) & 0x02) == 0 )
            break;
}

static void __attribute__((noreturn)) __machine_halt(void *unused)
{
    local_irq_disable();
    for ( ; ; )
        halt();
}

void machine_halt(void)
{
    watchdog_disable();
    console_start_sync();
    local_irq_enable();
    smp_call_function(__machine_halt, NULL, 0);
    __machine_halt(NULL);
}

#ifdef __i386__

/* The following code and data reboots the machine by switching to real
   mode and jumping to the BIOS reset entry point, as if the CPU has
   really been reset.  The previous version asked the keyboard
   controller to pulse the CPU reset line, which is more thorough, but
   doesn't work with at least one type of 486 motherboard.  It is easy
   to stop this code working; hence the copious comments. */

static unsigned long long
real_mode_gdt_entries [3] =
{
    0x0000000000000000ULL,      /* Null descriptor */
    0x00009a000000ffffULL,      /* 16-bit real-mode 64k code at 0x00000000 */
    0x000092000100ffffULL       /* 16-bit real-mode 64k data at 0x00000100 */
};

static const struct
{
    unsigned short       size __attribute__ ((packed));
    unsigned long long * base __attribute__ ((packed));
}
real_mode_gdt = { sizeof (real_mode_gdt_entries) - 1, real_mode_gdt_entries },
real_mode_idt = { 0x3ff, NULL };


/* This is 16-bit protected mode code to disable paging and the cache,
   switch to real mode and jump to the BIOS reset code.

   The instruction that switches to real mode by writing to CR0 must be
   followed immediately by a far jump instruction, which set CS to a
   valid value for real mode, and flushes the prefetch queue to avoid
   running instructions that have already been decoded in protected
   mode.

   Clears all the flags except ET, especially PG (paging), PE
   (protected-mode enable) and TS (task switch for coprocessor state
   save).  Flushes the TLB after paging has been disabled.  Sets CD and
   NW, to disable the cache on a 486, and invalidates the cache.  This
   is more like the state of a 486 after reset.  I don't know if
   something else should be done for other chips.

   More could be done here to set up the registers as if a CPU reset had
   occurred; hopefully real BIOSs don't assume much. */

static const unsigned char real_mode_switch [] =
{
    0x0f, 0x20, 0xc0,                           /*    movl  %cr0,%eax        */
    0x66, 0x83, 0xe0, 0x11,                     /*    andl  $0x00000011,%eax */
    0x66, 0x0d, 0x00, 0x00, 0x00, 0x60,         /*    orl   $0x60000000,%eax */
    0x0f, 0x22, 0xc0,                           /*    movl  %eax,%cr0        */
    0x0f, 0x22, 0xd8,                           /*    movl  %eax,%cr3        */
    0x0f, 0x20, 0xc2,                           /*    movl  %cr0,%edx        */
    0x66, 0x81, 0xe2, 0x00, 0x00, 0x00, 0x60,   /*    andl  $0x60000000,%edx */
    0x74, 0x02,                                 /*    jz    f                */
    0x0f, 0x09,                                 /*    wbinvd                 */
    0x24, 0x10,                                 /* f: andb  $0x10,al         */
    0x0f, 0x22, 0xc0                            /*    movl  %eax,%cr0        */
};
#define MAX_LENGTH 0x40
static const unsigned char jump_to_bios [] =
{
    0xea, 0xf0, 0xff, 0x00, 0xf0                /*    ljmp  $0xf000,$0xfff0  */
};

/*
 * Switch to real mode and then execute the code
 * specified by the code and length parameters.
 * We assume that length will aways be less that MAX_LENGTH!
 */
static void machine_real_restart(const unsigned char *code, unsigned length)
{
    local_irq_disable();

    /* Write zero to CMOS register number 0x0f, which the BIOS POST
       routine will recognize as telling it to do a proper reboot.  (Well
       that's what this book in front of me says -- it may only apply to
       the Phoenix BIOS though, it's not clear).  At the same time,
       disable NMIs by setting the top bit in the CMOS address register,
       as we're about to do peculiar things to the CPU. */

    spin_lock(&rtc_lock);
    CMOS_WRITE(0x00, 0x8f);
    spin_unlock(&rtc_lock);

    /* Identity-map virtual address zero. */

    map_pages_to_xen(0, 0, 1, __PAGE_HYPERVISOR|MAP_SMALL_PAGES);
    set_current(idle_vcpu[0]);
    write_ptbase(idle_vcpu[0]);

    /* For the switch to real mode, copy some code to low memory.  It has
       to be in the first 64k because it is running in 16-bit mode, and it
       has to have the same physical and virtual address, because it turns
       off paging.  Copy it near the end of the first page, out of the way
       of BIOS variables. */

    memcpy((void *)(PAGE_SIZE - sizeof(real_mode_switch) - MAX_LENGTH),
           real_mode_switch, sizeof(real_mode_switch));
    memcpy((void *)(PAGE_SIZE - MAX_LENGTH), code, length);

    /* Set up the IDT for real mode. */

    __asm__ __volatile__("lidt %0": : "m" (real_mode_idt));

    /* Set up a GDT from which we can load segment descriptors for real
       mode.  The GDT is not used in real mode; it is just needed here to
       prepare the descriptors. */

    __asm__ __volatile__("lgdt %0": : "m" (real_mode_gdt));

    /* Load the data segment registers, and thus the descriptors ready for
       real mode.  The base address of each segment is 0x100, 16 times the
       selector value being loaded here.  This is so that the segment
       registers don't have to be reloaded after switching to real mode:
       the values are consistent for real mode operation already. */

    __asm__ __volatile__ ("\tmov %0,%%ds\n"
                          "\tmov %0,%%es\n"
                          "\tmov %0,%%fs\n"
                          "\tmov %0,%%gs\n"
                          "\tmov %0,%%ss"
                          :
                          : "r" (0x0010));

    /* Jump to the 16-bit code that we copied earlier.  It disables paging
       and the cache, switches to real mode, and jumps to the BIOS reset
       entry point. */

    __asm__ __volatile__ ("ljmp $0x0008,%0"
                          :
                          : "i" ((void *)(PAGE_SIZE -
                                          sizeof(real_mode_switch) -
                                          MAX_LENGTH)));
}

static int __init set_bios_reboot(struct dmi_system_id *d)
{
    if ( reboot_type != BOOT_BIOS )
    {
        reboot_type = BOOT_BIOS;
        printk("%s series board detected. "
               "Selecting BIOS-method for reboots.\n", d->ident);
    }
    return 0;
}

static struct dmi_system_id __initdata reboot_dmi_table[] = {
    {    /* Handle problems with rebooting on Dell 1300's */
        .callback = set_bios_reboot,
        .ident = "Dell PowerEdge 1300",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 1300/"),
        },
    },
    {    /* Handle problems with rebooting on Dell 300's */
        .callback = set_bios_reboot,
        .ident = "Dell PowerEdge 300",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 300/"),
        },
    },
    {    /* Handle problems with rebooting on Dell 2400's */
        .callback = set_bios_reboot,
        .ident = "Dell PowerEdge 2400",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 2400"),
        },
    },
    {    /* Handle problems with rebooting on HP laptops */
        .callback = set_bios_reboot,
        .ident = "HP Compaq Laptop",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
            DMI_MATCH(DMI_PRODUCT_NAME, "HP Compaq"),
        },
    },
    { }
};

static int __init reboot_init(void)
{
    dmi_check_system(reboot_dmi_table);
    return 0;
}
__initcall(reboot_init);

#else /* __x86_64__ */

#define machine_real_restart(x, y)

#endif

static void __machine_restart(void *pdelay)
{
    machine_restart(*(unsigned int *)pdelay);
}

void machine_restart(unsigned int delay_millisecs)
{
    int i;

    watchdog_disable();
    console_start_sync();
    spin_debug_disable();

    local_irq_enable();

    /* Ensure we are the boot CPU. */
    if ( get_apic_id() != boot_cpu_physical_apicid )
    {
        /* Send IPI to the boot CPU (logical cpu 0). */
        on_selected_cpus(cpumask_of(0), __machine_restart,
                         &delay_millisecs, 0);
        for ( ; ; )
            halt();
    }

    /*
     * We may be called from an interrupt context, and various functions we
     * may need to call (alloc_domheap_pages, map_domain_page, ...) assert that
     * they are not called from interrupt context. This hack keeps them happy.
     */
    local_irq_count(0) = 0;

    smp_send_stop();

    mdelay(delay_millisecs);

    if ( tboot_in_measured_env() )
        tboot_shutdown(TB_SHUTDOWN_REBOOT);

    /* Rebooting needs to touch the page at absolute address 0. */
    *((unsigned short *)__va(0x472)) = reboot_mode;

    for ( ; ; )
    {
        switch ( reboot_type )
        {
        case BOOT_KBD:
            /* Pulse the keyboard reset line. */
            for ( i = 0; i < 100; i++ )
            {
                kb_wait();
                udelay(50);
                outb(0xfe,0x64); /* pulse reset low */
                udelay(50);
            }
            /* fall through */
        case BOOT_TRIPLE:
            asm volatile ( "lidt %0 ; int3" : "=m" (no_idt) );
            break;
        case BOOT_BIOS:
            machine_real_restart(jump_to_bios, sizeof(jump_to_bios));
            break;
        case BOOT_ACPI:
            acpi_reboot();
            break;
        }

        reboot_type = BOOT_KBD;
    }
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
