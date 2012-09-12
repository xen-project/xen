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
#include <xen/efi.h>
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

static void __machine_restart(void *pdelay)
{
    machine_restart(*(unsigned int *)pdelay);
}

void machine_restart(unsigned int delay_millisecs)
{
    unsigned int i, attempt;
    enum reboot_type orig_reboot_type = reboot_type;

    watchdog_disable();
    console_start_sync();
    spin_debug_disable();

    acpi_dmar_reinstate();

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

    efi_reset_system(reboot_mode != 0);

    /* Rebooting needs to touch the page at absolute address 0. */
    *((unsigned short *)__va(0x472)) = reboot_mode;

    for ( attempt = 0; ; attempt++ )
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
            /*
             * If this platform supports ACPI reset, we follow a Windows-style
             * reboot attempt sequence:
             *   ACPI -> KBD -> ACPI -> KBD
             * After this we revert to our usual sequence:
             *   KBD -> TRIPLE -> KBD -> TRIPLE -> KBD -> ...
             */
            reboot_type = (((attempt == 1) && (orig_reboot_type == BOOT_ACPI))
                           ? BOOT_ACPI : BOOT_TRIPLE);
            break;
        case BOOT_TRIPLE:
            asm volatile ( "lidt %0 ; int3" : "=m" (no_idt) );
            reboot_type = BOOT_KBD;
            break;
        case BOOT_BIOS:
            /* unsupported on x86_64 */
            reboot_type = BOOT_KBD;
            break;
        case BOOT_ACPI:
            acpi_reboot();
            reboot_type = BOOT_KBD;
            break;
        }
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
