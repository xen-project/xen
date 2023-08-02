/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/boot.h>
#include <asm/early_printk.h>
#include <asm/opal-api.h>
#include <asm/processor.h>
#include <xen/types.h>
#include <xen/libfdt/libfdt.h>
#include <xen/init.h>
#include <xen/lib.h>

/* Global OPAL struct containing entrypoint and base used by opal-calls.S */
struct opal opal;

int64_t opal_console_write(int64_t term_number, uint64_t *length,
                           const void *buffer);
int64_t opal_console_flush(int64_t term_number);
int64_t opal_reinit_cpus(uint64_t flags);

static void opal_putchar(char c)
{
    uint64_t len;

    if ( c == '\n' )
    {
        char buf = '\r';
        len = cpu_to_be64(1);
        opal_console_write(0, &len, &buf);
    }
    len = cpu_to_be64(1);
    opal_console_write(0, &len, &c);
    opal_console_flush(0);
}

void __init boot_opal_init(const void *fdt)
{
    int opal_node;
    const __be64 *opal_base;
    const __be64 *opal_entry;

    if ( fdt_check_header(fdt) < 0 )
    {
        /*
         * NOTE: This won't actually print since the early serial
         * console isn't set up yet.
         */
        early_printk("Booted without valid FDT pointer in r3!\n");
        die();
    }

    opal_node = fdt_path_offset(fdt, "/ibm,opal");
    if ( opal_node < 0 )
    {
        early_printk("Unable to find ibm,opal node!\n");
        die();
    }

    opal_base = fdt_getprop(fdt, opal_node, "opal-base-address", NULL);
    opal_entry = fdt_getprop(fdt, opal_node, "opal-entry-address", NULL);
    if ( !opal_base || !opal_entry )
    {
        early_printk("Failed to get opal-base-address/opal-entry-address "
                     "property from DT!\n");
        die();
    }

    opal.base = be64_to_cpu(*opal_base);
    opal.entry = be64_to_cpu(*opal_entry);

    early_printk_init(opal_putchar);

    /* Ask OPAL to set HID0 for Little Endian interrupts + Radix TLB support */
    opal_reinit_cpus(OPAL_REINIT_CPUS_HILE_LE | OPAL_REINIT_CPUS_MMU_RADIX |
                     OPAL_REINIT_CPUS_MMU_HASH);
}
