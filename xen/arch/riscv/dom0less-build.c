/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/init.h>

#include <asm/p2m.h>

int __init arch_parse_dom0less_node(struct dt_device_node *node,
                                    struct boot_domain *bd)
{
    const char *mmu_type;
    unsigned long bits;
    const char *end;

    if ( dt_property_read_string(node, "mmu-type", &mmu_type) )
    {
        dprintk(XENLOG_WARNING, "mmu-type property is missing in guest domain "
                "node. %s will be used as fallback\n", max_gstage_mode->name);

        bits = P2M_GFN_LEVEL_SHIFT(max_gstage_mode->paging_levels + 1);

        goto out;
    }

    if ( !strcasecmp(mmu_type, "riscv,none") )
    {
        dprintk(XENLOG_ERR, "Bare mode isn't supported by Xen\n");

        return -EOPNOTSUPP;
    }

    if ( strncasecmp(mmu_type, "riscv,sv", 8) )
    {
        dprintk(XENLOG_ERR, "mmu-type value \"%s\" is incorrect\n", mmu_type);

        return -EINVAL;
    }

    bits = simple_strtoul(mmu_type + 8, &end, 10);
    if ( (*end != '\0') || (end == mmu_type + 8) )
    {
        dprintk(XENLOG_ERR, "mmu-type value \"%s\" is incorrect\n", mmu_type);

        return -EINVAL;
    }

 out:
    if ( bits > (UINT8_MAX - P2M_ROOT_EXTRA_BITS) )
    {
        dprintk(XENLOG_ERR, "gstage addr bits value overflows uint8\n");

        return -EINVAL;
    }

    /*
     * The mmu-type property may specify any riscv,sv<N> string, but only the
     * following are currently supported:
     *  - riscv,sv32
     *  - riscv,sv39
     *  - riscv,sv48
     *  - riscv,sv57
     * Any other value will be rejected by find_gstage_mode().
     *
     * P2M_ROOT_EXTRA_BITS is added because for G-stage mode, GPAs are
     * extended by that many bits.
     */
    bd->create_cfg.arch.gaddr_bits = bits + P2M_ROOT_EXTRA_BITS;

    return 0;
}
