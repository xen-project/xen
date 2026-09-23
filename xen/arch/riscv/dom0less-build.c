/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/fdt-kernel.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt.h>

#include <asm/p2m.h>

int __init init_vuart(struct domain *d, struct kernel_info *kinfo,
                      const struct dt_device_node *node)
{
    /* Nothing to do at the moment */

    return 0;
}

int __init init_intc_phandle(struct kernel_info *kinfo, const char *name,
                             const int node_next, const void *pfdt)
{
    if ( dt_node_cmp(name, "intc") == 0 )
    {
        uint32_t phandle_intc = fdt_get_phandle(pfdt, node_next);

        if ( phandle_intc != 0 )
            kinfo->phandle_intc = phandle_intc;

        return 0;
    }

    return 1;
}

int __init make_arch_nodes(struct kernel_info *kinfo)
{
    /* No RISC-V specific nodes need to be made, at the moment. */

    return 0;
}

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

int __init arch_handle_passthrough_prop(struct kernel_info *kinfo,
                                        struct dt_device_node *node)
{
    /* Nothing specific to do for now */
    return 0;
}
