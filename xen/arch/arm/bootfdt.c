/*
 * Early Device Tree
 *
 * Copyright (C) 2012-2014 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <asm/setup.h>

static bool_t __init device_tree_node_matches(const void *fdt, int node,
                                              const char *match)
{
    const char *name;
    size_t match_len;

    name = fdt_get_name(fdt, node, NULL);
    match_len = strlen(match);

    /* Match both "match" and "match@..." patterns but not
       "match-foo". */
    return strncmp(name, match, match_len) == 0
        && (name[match_len] == '@' || name[match_len] == '\0');
}

static bool_t __init device_tree_node_compatible(const void *fdt, int node,
                                                 const char *match)
{
    int len, l;
    int mlen;
    const void *prop;

    mlen = strlen(match);

    prop = fdt_getprop(fdt, node, "compatible", &len);
    if ( prop == NULL )
        return 0;

    while ( len > 0 ) {
        if ( !dt_compat_cmp(prop, match) )
            return 1;
        l = strlen(prop) + 1;
        prop += l;
        len -= l;
    }

    return 0;
}

static void __init device_tree_get_reg(const __be32 **cell, u32 address_cells,
                                       u32 size_cells, u64 *start, u64 *size)
{
    *start = dt_next_cell(address_cells, cell);
    *size = dt_next_cell(size_cells, cell);
}

static u32 __init device_tree_get_u32(const void *fdt, int node,
                                      const char *prop_name, u32 dflt)
{
    const struct fdt_property *prop;

    prop = fdt_get_property(fdt, node, prop_name, NULL);
    if ( !prop || prop->len < sizeof(u32) )
        return dflt;

    return fdt32_to_cpu(*(uint32_t*)prop->data);
}

/**
 * device_tree_for_each_node - iterate over all device tree nodes
 * @fdt: flat device tree.
 * @func: function to call for each node.
 * @data: data to pass to @func.
 *
 * Any nodes nested at DEVICE_TREE_MAX_DEPTH or deeper are ignored.
 *
 * Returns 0 if all nodes were iterated over successfully.  If @func
 * returns a value different from 0, that value is returned immediately.
 */
static int __init device_tree_for_each_node(const void *fdt,
                                            device_tree_node_func func,
                                            void *data)
{
    int node;
    int depth;
    u32 address_cells[DEVICE_TREE_MAX_DEPTH];
    u32 size_cells[DEVICE_TREE_MAX_DEPTH];
    int ret;

    for ( node = 0, depth = 0;
          node >=0 && depth >= 0;
          node = fdt_next_node(fdt, node, &depth) )
    {
        const char *name = fdt_get_name(fdt, node, NULL);

        if ( depth >= DEVICE_TREE_MAX_DEPTH )
        {
            printk("Warning: device tree node `%s' is nested too deep\n",
                   name);
            continue;
        }

        address_cells[depth] = device_tree_get_u32(fdt, node, "#address-cells",
                                depth > 0 ? address_cells[depth-1] : 0);
        size_cells[depth] = device_tree_get_u32(fdt, node, "#size-cells",
                                depth > 0 ? size_cells[depth-1] : 0);


        ret = func(fdt, node, name, depth,
                   address_cells[depth-1], size_cells[depth-1], data);
        if ( ret != 0 )
            return ret;
    }
    return 0;
}

static void __init process_memory_node(const void *fdt, int node,
                                       const char *name,
                                       u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    int i;
    int banks;
    const __be32 *cell;
    paddr_t start, size;
    u32 reg_cells = address_cells + size_cells;

    if ( address_cells < 1 || size_cells < 1 )
    {
        printk("fdt: node `%s': invalid #address-cells or #size-cells",
               name);
        return;
    }

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
    {
        printk("fdt: node `%s': missing `reg' property\n", name);
        return;
    }

    cell = (const __be32 *)prop->data;
    banks = fdt32_to_cpu(prop->len) / (reg_cells * sizeof (u32));

    for ( i = 0; i < banks && bootinfo.mem.nr_banks < NR_MEM_BANKS; i++ )
    {
        device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
        if ( !size )
            continue;
        bootinfo.mem.bank[bootinfo.mem.nr_banks].start = start;
        bootinfo.mem.bank[bootinfo.mem.nr_banks].size = size;
        bootinfo.mem.nr_banks++;
    }
}

static void __init process_multiboot_node(const void *fdt, int node,
                                          const char *name,
                                          u32 address_cells, u32 size_cells)
{
    static int kind_guess = 0;
    const struct fdt_property *prop;
    const __be32 *cell;
    bootmodule_kind kind;
    paddr_t start, size;
    const char *cmdline;
    int len;

    if ( fdt_node_check_compatible(fdt, node, "xen,linux-zimage") == 0 ||
         fdt_node_check_compatible(fdt, node, "multiboot,kernel") == 0 )
        kind = BOOTMOD_KERNEL;
    else if ( fdt_node_check_compatible(fdt, node, "xen,linux-initrd") == 0 ||
              fdt_node_check_compatible(fdt, node, "multiboot,ramdisk") == 0 )
        kind = BOOTMOD_RAMDISK;
    else if ( fdt_node_check_compatible(fdt, node, "xen,xsm-policy") == 0 )
        kind = BOOTMOD_XSM;
    else
        kind = BOOTMOD_UNKNOWN;

    /* Guess that first two unknown are kernel and ramdisk respectively. */
    if ( kind == BOOTMOD_UNKNOWN )
    {
        switch ( kind_guess++ )
        {
        case 0: kind = BOOTMOD_KERNEL; break;
        case 1: kind = BOOTMOD_RAMDISK; break;
        default: break;
        }
    }

    prop = fdt_get_property(fdt, node, "reg", &len);
    if ( !prop )
        panic("node %s missing `reg' property\n", name);

    if ( len < dt_cells_to_size(address_cells + size_cells) )
        panic("fdt: node `%s': `reg` property length is too short\n",
                    name);

    cell = (const __be32 *)prop->data;
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);

    prop = fdt_get_property(fdt, node, "bootargs", &len);
    if ( prop )
    {
        if ( len > BOOTMOD_MAX_CMDLINE )
            panic("module %s command line too long\n", name);
        cmdline = prop->data;
    }
    else
        cmdline = NULL;

    add_boot_module(kind, start, size, cmdline);
}

static void __init process_chosen_node(const void *fdt, int node,
                                       const char *name,
                                       u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    paddr_t start, end;
    int len;

    printk("Checking for initrd in /chosen\n");

    prop = fdt_get_property(fdt, node, "linux,initrd-start", &len);
    if ( !prop )
        /* No initrd present. */
        return;
    if ( len != sizeof(u32) && len != sizeof(u64) )
    {
        printk("linux,initrd-start property has invalid length %d\n", len);
        return;
    }
    start = dt_read_number((void *)&prop->data, dt_size_to_cells(len));

    prop = fdt_get_property(fdt, node, "linux,initrd-end", &len);
    if ( !prop )
    {
        printk("linux,initrd-end not present but -start was\n");
        return;
    }
    if ( len != sizeof(u32) && len != sizeof(u64) )
    {
        printk("linux,initrd-end property has invalid length %d\n", len);
        return;
    }
    end = dt_read_number((void *)&prop->data, dt_size_to_cells(len));

    if ( start >= end )
    {
        printk("linux,initrd limits invalid: %"PRIpaddr" >= %"PRIpaddr"\n",
                  start, end);
        return;
    }

    printk("Initrd %"PRIpaddr"-%"PRIpaddr"\n", start, end);

    add_boot_module(BOOTMOD_RAMDISK, start, end-start, NULL);
}

static int __init early_scan_node(const void *fdt,
                                  int node, const char *name, int depth,
                                  u32 address_cells, u32 size_cells,
                                  void *data)
{
    if ( device_tree_node_matches(fdt, node, "memory") )
        process_memory_node(fdt, node, name, address_cells, size_cells);
    else if ( device_tree_node_compatible(fdt, node, "xen,multiboot-module" ) ||
              device_tree_node_compatible(fdt, node, "multiboot,module" ))
        process_multiboot_node(fdt, node, name, address_cells, size_cells);
    else if ( depth == 1 && device_tree_node_matches(fdt, node, "chosen") )
        process_chosen_node(fdt, node, name, address_cells, size_cells);

    return 0;
}

static void __init early_print_info(void)
{
    struct meminfo *mi = &bootinfo.mem;
    struct bootmodules *mods = &bootinfo.modules;
    int i, nr_rsvd;

    for ( i = 0; i < mi->nr_banks; i++ )
        printk("RAM: %"PRIpaddr" - %"PRIpaddr"\n",
                     mi->bank[i].start,
                     mi->bank[i].start + mi->bank[i].size - 1);
    printk("\n");
    for ( i = 0 ; i < mods->nr_mods; i++ )
        printk("MODULE[%d]: %"PRIpaddr" - %"PRIpaddr" %-12s %s\n",
                     i,
                     mods->module[i].start,
                     mods->module[i].start + mods->module[i].size,
                     boot_module_kind_as_string(mods->module[i].kind),
                     mods->module[i].cmdline);
    nr_rsvd = fdt_num_mem_rsv(device_tree_flattened);
    for ( i = 0; i < nr_rsvd; i++ )
    {
        paddr_t s, e;
        if ( fdt_get_mem_rsv(device_tree_flattened, i, &s, &e) < 0 )
            continue;
        /* fdt_get_mem_rsv returns length */
        e += s;
        printk(" RESVD[%d]: %"PRIpaddr" - %"PRIpaddr"\n",
                     i, s, e);
    }
    printk("\n");
}

/**
 * boot_fdt_info - initialize bootinfo from a DTB
 * @fdt: flattened device tree binary
 *
 * Returns the size of the DTB.
 */
size_t __init boot_fdt_info(const void *fdt, paddr_t paddr)
{
    int ret;

    ret = fdt_check_header(fdt);
    if ( ret < 0 )
        panic("No valid device tree\n");

    add_boot_module(BOOTMOD_FDT, paddr, fdt_totalsize(fdt), NULL);

    device_tree_for_each_node((void *)fdt, early_scan_node, NULL);
    early_print_info();

    return fdt_totalsize(fdt);
}

const char *boot_fdt_cmdline(const void *fdt)
{
    int node;
    const struct fdt_property *prop;

    node = fdt_path_offset(fdt, "/chosen");
    if ( node < 0 )
        return NULL;

    prop = fdt_get_property(fdt, node, "xen,xen-bootargs", NULL);
    if ( prop == NULL )
    {
        struct bootmodule *dom0_mod =
            boot_module_find_by_kind(BOOTMOD_KERNEL);

        if (fdt_get_property(fdt, node, "xen,dom0-bootargs", NULL) ||
            ( dom0_mod && dom0_mod->cmdline[0] ) )
            prop = fdt_get_property(fdt, node, "bootargs", NULL);
    }
    if ( prop == NULL )
        return NULL;

    return prop->data;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
