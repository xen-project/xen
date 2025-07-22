/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/unaligned.h>

void __init device_tree_get_reg(const __be32 **cell, uint32_t address_cells,
                                uint32_t size_cells, paddr_t *start,
                                paddr_t *size)
{
    uint64_t dt_start, dt_size;

    /*
     * dt_next_cell will return uint64_t whereas paddr_t may not be 64-bit.
     * Thus, there is an implicit cast from uint64_t to paddr_t.
     */
    dt_start = dt_next_cell(address_cells, cell);
    dt_size = dt_next_cell(size_cells, cell);

    if ( dt_start != (paddr_t)dt_start )
    {
        printk("Physical address greater than max width supported\n");
        WARN();
    }

    if ( dt_size != (paddr_t)dt_size )
    {
        printk("Physical size greater than max width supported\n");
        WARN();
    }

    /*
     * Xen will truncate the address/size if it is greater than the maximum
     * supported width and it will give an appropriate warning.
     */
    *start = dt_start;
    *size = dt_size;
}

u32 __init device_tree_get_u32(const void *fdt, int node,
                               const char *prop_name, u32 dflt)
{
    const struct fdt_property *prop;

    prop = fdt_get_property(fdt, node, prop_name, NULL);
    if ( !prop || prop->len < sizeof(u32) )
        return dflt;

    return fdt32_to_cpu(get_unaligned_t(uint32_t, prop->data));
}

int __init device_tree_for_each_node(const void *fdt, int node,
                                     device_tree_node_func func,
                                     void *data)
{
    /*
     * We only care about relative depth increments, assume depth of
     * node is 0 for simplicity.
     */
    int depth = 0;
    const int first_node = node;
    u32 address_cells[DEVICE_TREE_MAX_DEPTH];
    u32 size_cells[DEVICE_TREE_MAX_DEPTH];
    int ret;

    do {
        const char *name = fdt_get_name(fdt, node, NULL);
        u32 as, ss;

        if ( depth >= DEVICE_TREE_MAX_DEPTH )
        {
            printk("Warning: device tree node `%s' is nested too deep\n",
                   name);
            continue;
        }

        as = depth > 0 ? address_cells[depth-1] : DT_ROOT_NODE_ADDR_CELLS_DEFAULT;
        ss = depth > 0 ? size_cells[depth-1] : DT_ROOT_NODE_SIZE_CELLS_DEFAULT;

        address_cells[depth] = device_tree_get_u32(fdt, node,
                                                   "#address-cells", as);
        size_cells[depth] = device_tree_get_u32(fdt, node,
                                                "#size-cells", ss);

        /* skip the first node */
        if ( node != first_node )
        {
            ret = func(fdt, node, name, depth, as, ss, data);
            if ( ret != 0 )
                return ret;
        }

        node = fdt_next_node(fdt, node, &depth);
    } while ( node >= 0 && depth > 0 );

    return 0;
}

