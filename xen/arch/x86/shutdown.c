/******************************************************************************
 * arch/x86/shutdown.c
 *
 * x86-specific shutdown handling.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/dmi.h>
#include <xen/irq.h>
#include <xen/watchdog.h>
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
#include <asm/guest.h>

enum reboot_type {
        BOOT_INVALID,
        BOOT_TRIPLE = 't',
        BOOT_KBD = 'k',
        BOOT_ACPI = 'a',
        BOOT_CF9 = 'p',
        BOOT_CF9_PWR = 'P',
        BOOT_EFI = 'e',
        BOOT_XEN = 'x',
};

static int reboot_mode;

/*
 * reboot=t[riple] | k[bd] | a[cpi] | p[ci] | n[o] | [e]fi [, [w]arm | [c]old]
 * warm   Don't set the cold reboot flag
 * cold   Set the cold reboot flag
 * no     Suppress automatic reboot after panics or crashes
 * triple Force a triple fault (init)
 * kbd    Use the keyboard controller. cold reset (default)
 * acpi   Use the RESET_REG in the FADT
 * pci    Use the so-called "PCI reset register", CF9
 * Power  Like 'pci' but for a full power-cyle reset
 * efi    Use the EFI reboot (if running under EFI)
 * xen    Use Xen SCHEDOP hypercall (if running under Xen as a guest)
 */
static enum reboot_type reboot_type = BOOT_INVALID;

static int __init set_reboot_type(const char *str)
{
    int rc = 0;

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
        case 'a':
        case 'e':
        case 'k':
        case 'P':
        case 'p':
        case 't':
        case 'x':
            reboot_type = *str;
            break;
        default:
            rc = -EINVAL;
            break;
        }
        if ( (str = strchr(str, ',')) == NULL )
            break;
        str++;
    }

    if ( reboot_type == BOOT_EFI && !efi_enabled(EFI_RS) )
    {
        printk("EFI reboot selected, but no EFI runtime services available.\n"
               "Falling back to default reboot type.\n");
        reboot_type = BOOT_INVALID;
    }

    if ( reboot_type == BOOT_XEN && !xen_guest )
    {
        printk("Xen reboot selected, but Xen hypervisor not detected\n"
               "Falling back to default\n");
        reboot_type = BOOT_INVALID;
    }

    return rc;
}
custom_param("reboot", set_reboot_type);

static inline void kb_wait(void)
{
    int i;

    for ( i = 0; i < 0x10000; i++ )
        if ( (inb_p(0x64) & 0x02) == 0 )
            break;
}

static void noreturn __machine_halt(void *unused)
{
    local_irq_disable();

    if ( reboot_type == BOOT_XEN )
        xen_hypercall_shutdown(SHUTDOWN_poweroff);

    for ( ; ; )
        halt();
}

void machine_halt(void)
{
    watchdog_disable();
    console_start_sync();

    if ( system_state >= SYS_STATE_smp_boot )
    {
        local_irq_enable();
        smp_call_function(__machine_halt, NULL, 0);
    }

    __machine_halt(NULL);
}

static void default_reboot_type(void)
{
    if ( reboot_type != BOOT_INVALID )
        return;

    if ( xen_guest )
        reboot_type = BOOT_XEN;
    else if ( efi_enabled(EFI_RS) )
        reboot_type = BOOT_EFI;
    else if ( acpi_disabled )
        reboot_type = BOOT_KBD;
    else
        reboot_type = BOOT_ACPI;
}

static int __init override_reboot(struct dmi_system_id *d)
{
    enum reboot_type type = (long)d->driver_data;

    if ( type == BOOT_ACPI && acpi_disabled )
        type = BOOT_KBD;

    if ( reboot_type != type )
    {
        static const char *__initdata msg[] =
        {
            [BOOT_KBD]  = "keyboard controller",
            [BOOT_ACPI] = "ACPI",
            [BOOT_CF9]  = "PCI",
        };

        reboot_type = type;
        ASSERT(type >= 0 && type < ARRAY_SIZE(msg) && msg[type]);
        printk("%s series board detected. Selecting %s reboot method.\n",
               d->ident, msg[type]);
    }
    return 0;
}

static struct dmi_system_id __initdata reboot_dmi_table[] = {
    {    /* Handle problems with rebooting on Dell E520's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell E520",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Dell DM061"),
        },
    },
    {    /* Handle problems with rebooting on Dell 1300's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell PowerEdge 1300",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 1300/"),
        },
    },
    {    /* Handle problems with rebooting on Dell 300's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell PowerEdge 300",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 300/"),
        },
    },
    {    /* Handle problems with rebooting on Dell Optiplex 745's SFF */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 745",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 745"),
        },
    },
    {    /* Handle problems with rebooting on Dell Optiplex 745's DFF */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 745",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 745"),
            DMI_MATCH(DMI_BOARD_NAME, "0MM599"),
        },
    },
    {    /* Handle problems with rebooting on Dell Optiplex 745 with 0KW626 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 745",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 745"),
            DMI_MATCH(DMI_BOARD_NAME, "0KW626"),
        },
    },
    {    /* Handle problems with rebooting on Dell Optiplex 330 with 0KP561 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 330",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 330"),
            DMI_MATCH(DMI_BOARD_NAME, "0KP561"),
        },
    },
    {    /* Handle problems with rebooting on Dell Optiplex 360 with 0T656F */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 360",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 360"),
            DMI_MATCH(DMI_BOARD_NAME, "0T656F"),
        },
    },
    {    /* Handle problems with rebooting on Dell OptiPlex 760 with 0G919G */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell OptiPlex 760",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 760"),
            DMI_MATCH(DMI_BOARD_NAME, "0G919G"),
        },
    },
    {    /* Handle problems with rebooting on Dell 2400's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell PowerEdge 2400",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Computer Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "PowerEdge 2400"),
        },
    },
    {    /* Handle problems with rebooting on Dell T5400's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell Precision T5400",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Precision WorkStation T5400"),
        },
    },
    {    /* Handle problems with rebooting on Dell T7400's */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell Precision T7400",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Precision WorkStation T7400"),
        },
    },
    {    /* Handle problems with rebooting on HP laptops */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "HP Compaq Laptop",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
            DMI_MATCH(DMI_PRODUCT_NAME, "HP Compaq"),
        },
    },
    {    /* Handle problems with rebooting on Dell XPS710 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell XPS710",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Dell XPS710"),
        },
    },
    {    /* Handle problems with rebooting on Dell DXP061 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Dell DXP061",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Dell DXP061"),
        },
    },
    {    /* Handle problems with rebooting on Sony VGN-Z540N */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Sony VGN-Z540N",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Sony Corporation"),
            DMI_MATCH(DMI_PRODUCT_NAME, "VGN-Z540N"),
        },
    },
    {    /* Handle problems with rebooting on ASUS P4S800 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "ASUS P4S800",
        .matches = {
            DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
            DMI_MATCH(DMI_BOARD_NAME, "P4S800"),
        },
    },
    {    /* Handle reboot issue on Acer Aspire one */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_KBD,
        .ident = "Acer Aspire One A110",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Acer"),
            DMI_MATCH(DMI_PRODUCT_NAME, "AOA110"),
        },
    },
    {    /* Handle problems with rebooting on Apple MacBook5 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Apple MacBook5",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Apple Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "MacBook5"),
        },
    },
    {    /* Handle problems with rebooting on Apple MacBookPro5 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Apple MacBookPro5",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Apple Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "MacBookPro5"),
        },
    },
    {    /* Handle problems with rebooting on Apple Macmini3,1 */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Apple Macmini3,1",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Apple Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Macmini3,1"),
        },
    },
    {    /* Handle problems with rebooting on the iMac9,1. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Apple iMac9,1",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Apple Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "iMac9,1"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6320. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6320",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6320"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E5420. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E5420",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E5420"),
        },
    },
    {       /* Handle problems with rebooting on the Latitude E6220. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6220",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6220"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6420. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6420",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6420"),
        },
    },
    {    /* Handle problems with rebooting on the OptiPlex 990. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell OptiPlex 990",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 990"),
        },
    },
    {    /* Handle problems with rebooting on the Precision M6600. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell OptiPlex 990",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Precision M6600"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6520. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6520",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6520"),
        },
    },
    {       /* Handle problems with rebooting on the OptiPlex 790. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell OptiPlex 790",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 790"),
        },
    },
    {    /* Handle problems with rebooting on the OptiPlex 990. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell OptiPlex 990",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 990"),
        },
    },
    {    /* Handle problems with rebooting on the OptiPlex 390. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell OptiPlex 390",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 390"),
        },
    },
    {    /* Handle problems with rebooting on Dell OptiPlex 9020. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_ACPI,
        .ident = "Dell OptiPlex 9020",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "OptiPlex 9020"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6320. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6320",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6320"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6420. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6420",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6420"),
        },
    },
    {    /* Handle problems with rebooting on the Latitude E6520. */
        .callback = override_reboot,
        .driver_data = (void *)(long)BOOT_CF9,
        .ident = "Dell Latitude E6520",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
            DMI_MATCH(DMI_PRODUCT_NAME, "Latitude E6520"),
        },
    },
    { }
};

static int __init reboot_init(void)
{
    /*
     * Only do the DMI check if reboot_type hasn't been overridden
     * on the command line
     */
    if ( reboot_type != BOOT_INVALID )
        return 0;

    default_reboot_type();
    dmi_check_system(reboot_dmi_table);
    return 0;
}
__initcall(reboot_init);

static void noreturn __machine_restart(void *pdelay)
{
    machine_restart(*(unsigned int *)pdelay);
}

void machine_restart(unsigned int delay_millisecs)
{
    unsigned int i, attempt;
    enum reboot_type orig_reboot_type;
    const struct desc_ptr no_idt = { 0 };

    watchdog_disable();
    console_start_sync();
    spin_debug_disable();

    /*
     * We may be called from an interrupt context, and various functions we
     * may need to call (alloc_domheap_pages, map_domain_page, ...) assert that
     * they are not called from interrupt context. This hack keeps them happy.
     */
    local_irq_count(0) = 0;

    if ( system_state >= SYS_STATE_smp_boot )
    {
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

        smp_send_stop();
    }

    mdelay(delay_millisecs);

    if ( tboot_in_measured_env() )
    {
        acpi_dmar_reinstate();
        tboot_shutdown(TB_SHUTDOWN_REBOOT);
    }

    /* Just in case reboot_init() didn't run yet. */
    default_reboot_type();
    orig_reboot_type = reboot_type;

    /* Rebooting needs to touch the page at absolute address 0. */
    if ( reboot_type != BOOT_EFI )
        *((unsigned short *)__va(0x472)) = reboot_mode;

    for ( attempt = 0; ; attempt++ )
    {
        switch ( reboot_type )
        {
        case BOOT_INVALID:
            ASSERT_UNREACHABLE();
            /* fall through */
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
        case BOOT_EFI:
            reboot_type = acpi_disabled ? BOOT_KBD : BOOT_ACPI;
            efi_reset_system(reboot_mode != 0);
            *((unsigned short *)__va(0x472)) = reboot_mode;
            break;
        case BOOT_TRIPLE:
            asm volatile ("lidt %0; int3" : : "m" (no_idt));
            reboot_type = BOOT_KBD;
            break;
        case BOOT_ACPI:
            acpi_reboot();
            reboot_type = BOOT_KBD;
            break;
        case BOOT_CF9:
        case BOOT_CF9_PWR:
            {
                u8 cf9 = inb(0xcf9) & ~0x0e;

                /* Request warm, hard, or power-cycle reset. */
                if ( reboot_type == BOOT_CF9_PWR )
                    cf9 |= 0x0a;
                else if ( reboot_mode == 0 )
                    cf9 |= 0x02;
                outb(cf9, 0xcf9);
                udelay(50);
                outb(cf9 | 0x04, 0xcf9); /* Actually do the reset. */
                udelay(50);
            }
            reboot_type = BOOT_ACPI;
            break;

        case BOOT_XEN:
            /*
             * When running in PV shim mode guest shutdown calls are
             * forwarded to L0, hence the only way to get here is if a
             * shim crash happens.
             */
            xen_hypercall_shutdown(pv_shim ? SHUTDOWN_crash : SHUTDOWN_reboot);
            break;
        }
    }
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
