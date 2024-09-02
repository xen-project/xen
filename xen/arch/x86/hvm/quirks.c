/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * x86/hvm/quirks.c
 */

#include <xen/types.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/dmi.h>
#include <xen/bitmap.h>
#include <xen/param.h>
#include <asm/hvm/support.h>

int8_t __ro_after_init hvm_port80_allowed = -1;
boolean_param("hvm_port80", hvm_port80_allowed);

static int __init cf_check dmi_hvm_deny_port80(const struct dmi_system_id *id)
{
    printk(XENLOG_WARNING "%s: port 0x80 access %s allowed for HVM guests\n",
           id->ident, hvm_port80_allowed > 0 ? "forcibly" : "not");

    if ( hvm_port80_allowed < 0 )
        hvm_port80_allowed = 0;

    return 0;
}

static int __init cf_check check_port80(void)
{
    /*
     * Quirk table for systems that misbehave (lock up, etc.) if port
     * 0x80 is used:
     */
    static const struct dmi_system_id __initconstrel hvm_no_port80_dmi_table[] =
    {
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "Compaq Presario V6000",
	    DMI_MATCH2(
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B7")),
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion dv9000z",
	    DMI_MATCH2(
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B9")),
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion dv6000",
	    DMI_MATCH2(
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B8")),
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion tx1000",
	    DMI_MATCH2(
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30BF")),
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "Presario F700",
	    DMI_MATCH2(
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30D3")),
        },
        { }
    };

    dmi_check_system(hvm_no_port80_dmi_table);

    if ( !hvm_port80_allowed )
        __set_bit(0x80, hvm_io_bitmap);

    return 0;
}
__initcall(check_port80);
