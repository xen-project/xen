/*
 * Device Tree
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/device_tree.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/stdarg.h>
#include <xen/string.h>
#include <asm/early_printk.h>

struct dt_early_info __initdata early_info;
void *device_tree_flattened;

static void __init get_val(const u32 **cell, u32 cells, u64 *val)
{
    *val = 0;

    while ( cells-- )
    {
        *val <<= 32;
        *val |= fdt32_to_cpu(*(*cell)++);
    }
}

static void __init get_register(const u32 **cell,
                                u32 address_cells, u32 size_cells,
                                u64 *start, u64 *size)
{
    get_val(cell, address_cells, start);
    get_val(cell, size_cells, size);
}

static u32 __init prop_by_name_u32(const void *fdt, int node,
                                   const char *prop_name)
{
    const struct fdt_property *prop;

    prop = fdt_get_property(fdt, node, prop_name, NULL);
    if ( !prop || prop->len < sizeof(u32) )
        return 0; /* default to 0 */

    return fdt32_to_cpu(*(uint32_t*)prop->data);
}

static void __init process_memory_node(const void *fdt, int node,
                                       u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    size_t reg_cells;
    int i;
    int banks;
    const u32 *cell;
    paddr_t start, size;

    if ( address_cells < 1 || size_cells < 1 )
    {
        early_printk("fdt: node `%s': invalid #address-cells or #size-cells",
                     fdt_get_name(fdt, node, NULL));
        return;
    }

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
    {
        early_printk("fdt: node `%s': missing `reg' property\n",
                     fdt_get_name(fdt, node, NULL));
        return;
    }

    cell = (const u32 *)prop->data;
    reg_cells = address_cells + size_cells;
    banks = fdt32_to_cpu(prop->len) / (reg_cells * sizeof(u32));

    for ( i = 0; i < banks && early_info.mem.nr_banks < NR_MEM_BANKS; i++ )
    {
        get_register(&cell, address_cells, size_cells, &start, &size);
        early_info.mem.bank[early_info.mem.nr_banks].start = start;
        early_info.mem.bank[early_info.mem.nr_banks].size = size;
        early_info.mem.nr_banks++;
    }
}

#define MAX_DEPTH 16

static void __init early_scan(const void *fdt)
{
    int node;
    int depth;
    const char *name;
    u32 address_cells[MAX_DEPTH];
    u32 size_cells[MAX_DEPTH];

    for ( node = 0; depth >= 0; node = fdt_next_node(fdt, node, &depth) )
    {
        name = fdt_get_name(fdt, node, NULL);

        if ( depth >= MAX_DEPTH )
        {
            early_printk("fdt: node '%s': nested too deep\n",
                         fdt_get_name(fdt, node, NULL));
            continue;
        }

        address_cells[depth] = prop_by_name_u32(fdt, node, "#address-cells");
        size_cells[depth] = prop_by_name_u32(fdt, node, "#size-cells");

        if ( strncmp(name, "memory", 6) == 0 )
            process_memory_node(fdt, node,
                                address_cells[depth-1], size_cells[depth-1]);
    }
}

static void __init early_print_info(void)
{
    struct dt_mem_info *mi = &early_info.mem;
    int i;

    for ( i = 0; i < mi->nr_banks; i++ )
        early_printk("RAM: %016llx - %016llx\n",
                     mi->bank[i].start,
                     mi->bank[i].start + mi->bank[i].size - 1);
}

/**
 * device_tree_early_init - initialize early info from a DTB
 * @fdt: flattened device tree binary
 *
 * Returns the size of the DTB.
 */
size_t __init device_tree_early_init(const void *fdt)
{
    int ret;

    ret = fdt_check_header(fdt);
    if ( ret < 0 )
        early_panic("No valid device tree\n");

    early_scan(fdt);
    early_print_info();

    return fdt_totalsize(fdt);
}

/**
 * device_tree_get_xen_paddr - get physical address to relocate Xen to
 *
 * Xen is relocated to the top of RAM and aligned to a XEN_PADDR_ALIGN
 * boundary.
 */
paddr_t __init device_tree_get_xen_paddr(void)
{
    struct dt_mem_info *mi = &early_info.mem;
    paddr_t min_size;
    paddr_t paddr = 0, t;
    int i;

    min_size = (_end - _start + (XEN_PADDR_ALIGN-1)) & ~(XEN_PADDR_ALIGN-1);

    /* Find the highest bank with enough space. */
    for ( i = 0; i < mi->nr_banks; i++ )
    {
        if ( mi->bank[i].size >= min_size )
        {
            t = mi->bank[i].start + mi->bank[i].size - min_size;
            if ( t > paddr )
                paddr = t;
        }
    }

    if ( !paddr )
        early_panic("Not enough memory to relocate Xen\n");

    return paddr;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
