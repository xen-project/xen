/*
 * xen/arch/arm/gic-v3-its.c
 *
 * ARM GICv3 Interrupt Translation Service (ITS) support
 *
 * Copyright (C) 2016,2017 - ARM Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/lib.h>
#include <xen/mm.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/io.h>

/*
 * No lock here, as this list gets only populated upon boot while scanning
 * firmware tables for all host ITSes, and only gets iterated afterwards.
 */
LIST_HEAD(host_its_list);

bool gicv3_its_host_has_its(void)
{
    return !list_empty(&host_its_list);
}

static int gicv3_its_init_single_its(struct host_its *hw_its)
{
    uint64_t reg;

    hw_its->its_base = ioremap_nocache(hw_its->addr, hw_its->size);
    if ( !hw_its->its_base )
        return -ENOMEM;

    reg = readq_relaxed(hw_its->its_base + GITS_TYPER);
    hw_its->devid_bits = GITS_TYPER_DEVICE_ID_BITS(reg);
    hw_its->evid_bits = GITS_TYPER_EVENT_ID_BITS(reg);
    hw_its->itte_size = GITS_TYPER_ITT_SIZE(reg);

    return 0;
}

int gicv3_its_init(void)
{
    struct host_its *hw_its;
    int ret;

    list_for_each_entry(hw_its, &host_its_list, entry)
    {
        ret = gicv3_its_init_single_its(hw_its);
        if ( ret )
            return ret;
    }

    return 0;
}

/* Scan the DT for any ITS nodes and create a list of host ITSes out of it. */
void gicv3_its_dt_init(const struct dt_device_node *node)
{
    const struct dt_device_node *its = NULL;
    struct host_its *its_data;

    /*
     * Check for ITS MSI subnodes. If any, add the ITS register
     * frames to the ITS list.
     */
    dt_for_each_child_node(node, its)
    {
        uint64_t addr, size;

        if ( !dt_device_is_compatible(its, "arm,gic-v3-its") )
            continue;

        if ( dt_device_get_address(its, 0, &addr, &size) )
            panic("GICv3: Cannot find a valid ITS frame address");

        its_data = xzalloc(struct host_its);
        if ( !its_data )
            panic("GICv3: Cannot allocate memory for ITS frame");

        its_data->addr = addr;
        its_data->size = size;
        its_data->dt_node = its;

        printk("GICv3: Found ITS @0x%lx\n", addr);

        list_add_tail(&its_data->entry, &host_its_list);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
