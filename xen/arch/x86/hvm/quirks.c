/******************************************************************************
 * x86/hvm/quirks.c
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/dmi.h>
#include <xen/bitmap.h>
#include <xen/param.h>
#include <asm/hvm/support.h>

s8 __read_mostly hvm_port80_allowed = -1;
boolean_param("hvm_port80", hvm_port80_allowed);

static int __init dmi_hvm_deny_port80(const struct dmi_system_id *id)
{
    printk(XENLOG_WARNING "%s: port 0x80 access %s allowed for HVM guests\n",
           id->ident, hvm_port80_allowed > 0 ? "forcibly" : "not");

    if ( hvm_port80_allowed < 0 )
        hvm_port80_allowed = 0;

    return 0;
}

static int __init check_port80(void)
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
            .matches  = {
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B7")
            }
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion dv9000z",
            .matches  = {
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B9")
            }
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion dv6000",
            .matches  = {
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30B8")
            }
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "HP Pavilion tx1000",
            .matches  = {
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30BF")
            }
        },
        {
            .callback = dmi_hvm_deny_port80,
            .ident    = "Presario F700",
            .matches  = {
                DMI_MATCH(DMI_BOARD_VENDOR, "Quanta"),
                DMI_MATCH(DMI_BOARD_NAME,   "30D3")
            }
        },
        { }
    };

    dmi_check_system(hvm_no_port80_dmi_table);

    if ( !hvm_port80_allowed )
        __set_bit(0x80, hvm_io_bitmap);

    return 0;
}
__initcall(check_port80);
