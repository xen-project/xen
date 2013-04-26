/*
 * Device Tree
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 * Copyright 2009 Benjamin Herrenschmidt, IBM Corp
 * benh@kernel.crashing.org
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
#include <xen/cpumask.h>
#include <xen/ctype.h>
#include <xen/lib.h>
#include <asm/early_printk.h>

struct dt_early_info __initdata early_info;
void *device_tree_flattened;
/* Host device tree */
struct dt_device_node *dt_host;

/**
 * struct dt_alias_prop - Alias property in 'aliases' node
 * @link: List node to link the structure in aliases_lookup list
 * @alias: Alias property name
 * @np: Pointer to device_node that the alias stands for
 * @id: Index value from end of alias name
 * @stem: Alias string without the index
 *
 * The structure represents one alias property of 'aliases' node as
 * an entry in aliases_lookup list.
 */
struct dt_alias_prop {
    struct list_head link;
    const char *alias;
    struct dt_device_node *np;
    int id;
    char stem[0];
};

static LIST_HEAD(aliases_lookup);

/* Some device tree functions may be called both before and after the
   console is initialized. */
#define dt_printk(fmt, ...)                         \
    do                                              \
    {                                               \
        if ( system_state == SYS_STATE_early_boot ) \
            early_printk(fmt, ## __VA_ARGS__);      \
        else                                        \
            printk(fmt, ## __VA_ARGS__);            \
    } while (0)

#define ALIGN(x, a) ((x + (a) - 1) & ~((a) - 1));

// #define DEBUG_DT

#ifdef DEBUG_DT
# define dt_dprintk(fmt, args...) dt_printk(XENLOG_DEBUG fmt, ##args)
#else
# define dt_dprintk(fmt, args...) do {} while ( 0 )
#endif

bool_t device_tree_node_matches(const void *fdt, int node, const char *match)
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

bool_t device_tree_type_matches(const void *fdt, int node, const char *match)
{
    const void *prop;

    prop = fdt_getprop(fdt, node, "device_type", NULL);
    if ( prop == NULL )
        return 0;

    return !strcmp(prop, match);
}

bool_t device_tree_node_compatible(const void *fdt, int node, const char *match)
{
    int len, l;
    const void *prop;

    prop = fdt_getprop(fdt, node, "compatible", &len);
    if ( prop == NULL )
        return 0;

    while ( len > 0 ) {
        if ( !strcmp(prop, match) )
            return 1;
        l = strlen(prop) + 1;
        prop += l;
        len -= l;
    }

    return 0;
}

static int device_tree_nr_reg_ranges(const struct fdt_property *prop,
        u32 address_cells, u32 size_cells)
{
    u32 reg_cells = address_cells + size_cells;
    return fdt32_to_cpu(prop->len) / (reg_cells * sizeof(u32));
}

static void __init get_val(const u32 **cell, u32 cells, u64 *val)
{
    *val = 0;

    if ( cells > 2 )
        early_panic("dtb value contains > 2 cells\n");

    while ( cells-- )
    {
        *val <<= 32;
        *val |= fdt32_to_cpu(*(*cell)++);
    }
}

void device_tree_get_reg(const u32 **cell, u32 address_cells, u32 size_cells,
                         u64 *start, u64 *size)
{
    get_val(cell, address_cells, start);
    get_val(cell, size_cells, size);
}

static void set_val(u32 **cell, u32 cells, u64 val)
{
    u32 c = cells;

    while ( c-- )
    {
        (*cell)[c] = cpu_to_fdt32(val);
        val >>= 32;
    }
    (*cell) += cells;
}

void device_tree_set_reg(u32 **cell, u32 address_cells, u32 size_cells,
                         u64 start, u64 size)
{
    set_val(cell, address_cells, start);
    set_val(cell, size_cells, size);
}

u32 device_tree_get_u32(const void *fdt, int node, const char *prop_name,
                        u32 dflt)
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
int device_tree_for_each_node(const void *fdt,
                              device_tree_node_func func, void *data)
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
            dt_printk("Warning: device tree node `%s' is nested too deep\n",
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

struct find_compat {
    const char *compatible;
    int found;
    int node;
    int depth;
    u32 address_cells;
    u32 size_cells;
};

static int _find_compatible_node(const void *fdt,
                             int node, const char *name, int depth,
                             u32 address_cells, u32 size_cells,
                             void *data)
{
    struct find_compat *c = (struct find_compat *) data;

    if (  c->found  )
        return 1;

    if ( device_tree_node_compatible(fdt, node, c->compatible) )
    {
        c->found = 1;
        c->node = node;
        c->depth = depth;
        c->address_cells = address_cells;
        c->size_cells = size_cells;
        return 1;
    }
    return 0;
}

int find_compatible_node(const char *compatible, int *node, int *depth,
                u32 *address_cells, u32 *size_cells)
{
    int ret;
    struct find_compat c;
    c.compatible = compatible;
    c.found = 0;

    ret = device_tree_for_each_node(device_tree_flattened, _find_compatible_node, &c);
    if ( !c.found )
        return ret;
    else
    {
        *node = c.node;
        *depth = c.depth;
        *address_cells = c.address_cells;
        *size_cells = c.size_cells;
        return 1;
    }
}

/**
 * device_tree_bootargs - return the bootargs (the Xen command line)
 * @fdt flat device tree.
 */
const char *device_tree_bootargs(const void *fdt)
{
    int node; 
    const struct fdt_property *prop;

    node = fdt_path_offset(fdt, "/chosen");
    if ( node < 0 )
        return NULL;

    prop = fdt_get_property(fdt, node, "bootargs", NULL);
    if ( prop == NULL )
        return NULL;

    return prop->data;
}

static int dump_node(const void *fdt, int node, const char *name, int depth,
                     u32 address_cells, u32 size_cells, void *data)
{
    char prefix[2*DEVICE_TREE_MAX_DEPTH + 1] = "";
    int i;
    int prop;

    for ( i = 0; i < depth; i++ )
        safe_strcat(prefix, "  ");

    if ( name[0] == '\0' )
        name = "/";
    dt_printk("%s%s:\n", prefix, name);

    for ( prop = fdt_first_property_offset(fdt, node);
          prop >= 0;
          prop = fdt_next_property_offset(fdt, prop) )
    {
        const struct fdt_property *p;

        p = fdt_get_property_by_offset(fdt, prop, NULL);

        dt_printk("%s  %s\n", prefix, fdt_string(fdt, fdt32_to_cpu(p->nameoff)));
    }

    return 0;
}

/**
 * device_tree_dump - print a text representation of a device tree
 * @fdt: flat device tree to print
 */
void device_tree_dump(const void *fdt)
{
    device_tree_for_each_node(fdt, dump_node, NULL);
}


static void __init process_memory_node(const void *fdt, int node,
                                       const char *name,
                                       u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    int i;
    int banks;
    const u32 *cell;
    paddr_t start, size;

    if ( address_cells < 1 || size_cells < 1 )
    {
        early_printk("fdt: node `%s': invalid #address-cells or #size-cells",
                     name);
        return;
    }

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
    {
        early_printk("fdt: node `%s': missing `reg' property\n", name);
        return;
    }

    cell = (const u32 *)prop->data;
    banks = device_tree_nr_reg_ranges(prop, address_cells, size_cells);

    for ( i = 0; i < banks && early_info.mem.nr_banks < NR_MEM_BANKS; i++ )
    {
        device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
        early_info.mem.bank[early_info.mem.nr_banks].start = start;
        early_info.mem.bank[early_info.mem.nr_banks].size = size;
        early_info.mem.nr_banks++;
    }
}

static void __init process_cpu_node(const void *fdt, int node,
                                    const char *name,
                                    u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    const u32 *cell;
    paddr_t start, size;

    if ( address_cells != 1 || size_cells != 0 )
    {
        early_printk("fdt: node `%s': invalid #address-cells or #size-cells",
                     name);
        return;
    }

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
    {
        early_printk("fdt: node `%s': missing `reg' property\n", name);
        return;
    }

    cell = (const u32 *)prop->data;
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);

    cpumask_set_cpu(start, &cpu_possible_map);
}

static void __init process_gic_node(const void *fdt, int node,
                                    const char *name,
                                    u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    const u32 *cell;
    paddr_t start, size;
    int interfaces;

    if ( address_cells < 1 || size_cells < 1 )
    {
        early_printk("fdt: node `%s': invalid #address-cells or #size-cells",
                     name);
        return;
    }

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
    {
        early_printk("fdt: node `%s': missing `reg' property\n", name);
        return;
    }

    cell = (const u32 *)prop->data;
    interfaces = device_tree_nr_reg_ranges(prop, address_cells, size_cells);
    if ( interfaces < 4 )
    {
        early_printk("fdt: node `%s': not enough ranges\n", name);
        return;
    }
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
    early_info.gic.gic_dist_addr = start;
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
    early_info.gic.gic_cpu_addr = start;
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
    early_info.gic.gic_hyp_addr = start;
    device_tree_get_reg(&cell, address_cells, size_cells, &start, &size);
    early_info.gic.gic_vcpu_addr = start;
}

static void __init process_multiboot_node(const void *fdt, int node,
                                          const char *name,
                                          u32 address_cells, u32 size_cells)
{
    const struct fdt_property *prop;
    const u32 *cell;
    int nr;
    struct dt_mb_module *mod;
    int len;

    if ( fdt_node_check_compatible(fdt, node, "xen,linux-zimage") == 0 )
        nr = 1;
    else if ( fdt_node_check_compatible(fdt, node, "xen,linux-initrd") == 0)
        nr = 2;
    else
        early_panic("%s not a known xen multiboot type\n", name);

    mod = &early_info.modules.module[nr];

    prop = fdt_get_property(fdt, node, "reg", NULL);
    if ( !prop )
        early_panic("node %s missing `reg' property\n", name);

    cell = (const u32 *)prop->data;
    device_tree_get_reg(&cell, address_cells, size_cells,
                        &mod->start, &mod->size);

    prop = fdt_get_property(fdt, node, "bootargs", &len);
    if ( prop )
    {
        if ( len > sizeof(mod->cmdline) )
            early_panic("module %d command line too long\n", nr);

        safe_strcpy(mod->cmdline, prop->data);
    }
    else
        mod->cmdline[0] = 0;

    if ( nr > early_info.modules.nr_mods )
        early_info.modules.nr_mods = nr;
}

static int __init early_scan_node(const void *fdt,
                                  int node, const char *name, int depth,
                                  u32 address_cells, u32 size_cells,
                                  void *data)
{
    if ( device_tree_node_matches(fdt, node, "memory") )
        process_memory_node(fdt, node, name, address_cells, size_cells);
    else if ( device_tree_type_matches(fdt, node, "cpu") )
        process_cpu_node(fdt, node, name, address_cells, size_cells);
    else if ( device_tree_node_compatible(fdt, node, "arm,cortex-a15-gic") )
        process_gic_node(fdt, node, name, address_cells, size_cells);
    else if ( device_tree_node_compatible(fdt, node, "xen,multiboot-module" ) )
        process_multiboot_node(fdt, node, name, address_cells, size_cells);

    return 0;
}

static void __init early_print_info(void)
{
    struct dt_mem_info *mi = &early_info.mem;
    struct dt_module_info *mods = &early_info.modules;
    int i;

    for ( i = 0; i < mi->nr_banks; i++ )
        early_printk("RAM: %"PRIpaddr" - %"PRIpaddr"\n",
                     mi->bank[i].start,
                     mi->bank[i].start + mi->bank[i].size - 1);
    early_printk("\n");
    for ( i = 1 ; i < mods->nr_mods + 1; i++ )
        early_printk("MODULE[%d]: %"PRIpaddr" - %"PRIpaddr" %s\n",
                     i,
                     mods->module[i].start,
                     mods->module[i].start + mods->module[i].size,
                     mods->module[i].cmdline);
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

    device_tree_for_each_node((void *)fdt, early_scan_node, NULL);
    early_print_info();

    return fdt_totalsize(fdt);
}

static void __init *unflatten_dt_alloc(unsigned long *mem, unsigned long size,
                                       unsigned long align)
{
    void *res;

    *mem = ALIGN(*mem, align);
    res = (void *)*mem;
    *mem += size;

    return res;
}

/* Find a property with a given name for a given node and return it. */
static const struct dt_property *
dt_find_property(const struct dt_device_node *np,
                 const char *name,
                 u32 *lenp)
{
    const struct dt_property *pp;

    if ( !np )
        return NULL;

    for ( pp = np->properties; pp; pp = pp->next )
    {
        if ( strcmp(pp->name, name) == 0 )
        {
            if ( lenp )
                *lenp = pp->length;
            break;
        }
    }

    return pp;
}

const void *dt_get_property(const struct dt_device_node *np,
                            const char *name, u32 *lenp)
{
    const struct dt_property *pp = dt_find_property(np, name, lenp);

    return pp ? pp->value : NULL;
}

struct dt_device_node *dt_find_node_by_path(const char *path)
{
    struct dt_device_node *np;

    for_each_device_node(dt_host, np)
        if ( np->full_name && (dt_node_cmp(np->full_name, path) == 0) )
            break;

    return np;
}

/**
 * unflatten_dt_node - Alloc and populate a device_node from the flat tree
 * @fdt: The parent device tree blob
 * @mem: Memory chunk to use for allocating device nodes and properties
 * @p: pointer to node in flat tree
 * @dad: Parent struct device_node
 * @allnextpp: pointer to ->allnext from last allocated device_node
 * @fpsize: Size of the node path up at the current depth.
 */
static unsigned long __init unflatten_dt_node(const void *fdt,
                                              unsigned long mem,
                                              unsigned long *p,
                                              struct dt_device_node *dad,
                                              struct dt_device_node ***allnextpp,
                                              unsigned long fpsize)
{
    struct dt_device_node *np;
    struct dt_property *pp, **prev_pp = NULL;
    char *pathp;
    u32 tag;
    unsigned int l, allocl;
    int has_name = 0;
    int new_format = 0;

    tag = be32_to_cpup((__be32 *)(*p));
    if ( tag != FDT_BEGIN_NODE )
    {
        dt_printk(XENLOG_WARNING "Weird tag at start of node: %x\n", tag);
        return mem;
    }
    *p += 4;
    pathp = (char *)*p;
    l = allocl = strlen(pathp) + 1;
    *p = ALIGN(*p + l, 4);

    /* version 0x10 has a more compact unit name here instead of the full
     * path. we accumulate the full path size using "fpsize", we'll rebuild
     * it later. We detect this because the first character of the name is
     * not '/'.
     */
    if ( (*pathp) != '/' )
    {
        new_format = 1;
        if ( fpsize == 0 )
        {
            /* root node: special case. fpsize accounts for path
             * plus terminating zero. root node only has '/', so
             * fpsize should be 2, but we want to avoid the first
             * level nodes to have two '/' so we use fpsize 1 here
             */
            fpsize = 1;
            allocl = 2;
        }
        else
        {
            /* account for '/' and path size minus terminal 0
             * already in 'l'
             */
            fpsize += l;
            allocl = fpsize;
        }
    }

    np = unflatten_dt_alloc(&mem, sizeof(struct dt_device_node) + allocl,
                            __alignof__(struct dt_device_node));
    if ( allnextpp )
    {
        memset(np, 0, sizeof(*np));
        np->full_name = ((char *)np) + sizeof(struct dt_device_node);
        /* By default dom0 owns the device */
        np->used_by = 0;
        if ( new_format )
        {
            char *fn = np->full_name;
            /* rebuild full path for new format */
            if ( dad && dad->parent )
            {
                strlcpy(fn, dad->full_name, allocl);
#ifdef DEBUG_DT
                if ( (strlen(fn) + l + 1) != allocl )
                {
                    dt_dprintk("%s: p: %d, l: %d, a: %d\n",
                               pathp, (int)strlen(fn),
                               l, allocl);
                }
#endif
                fn += strlen(fn);
            }
            *(fn++) = '/';
            memcpy(fn, pathp, l);
        }
        else
            memcpy(np->full_name, pathp, l);
        prev_pp = &np->properties;
        **allnextpp = np;
        *allnextpp = &np->allnext;
        if ( dad != NULL )
        {
            np->parent = dad;
            /* we temporarily use the next field as `last_child'*/
            if ( dad->next == NULL )
                dad->child = np;
            else
                dad->next->sibling = np;
            dad->next = np;
        }
    }
    /* process properties */
    while ( 1 )
    {
        u32 sz, noff;
        const char *pname;

        tag = be32_to_cpup((__be32 *)(*p));
        if ( tag == FDT_NOP )
        {
            *p += 4;
            continue;
        }
        if ( tag != FDT_PROP )
            break;
        *p += 4;
        sz = be32_to_cpup((__be32 *)(*p));
        noff = be32_to_cpup((__be32 *)((*p) + 4));
        *p += 8;
        if ( fdt_version(fdt) < 0x10 )
            *p = ALIGN(*p, sz >= 8 ? 8 : 4);

        pname = fdt_string(fdt, noff);
        if ( pname == NULL )
        {
            dt_dprintk("Can't find property name in list!\n");
            break;
        }
        if ( strcmp(pname, "name") == 0 )
            has_name = 1;
        l = strlen(pname) + 1;
        pp = unflatten_dt_alloc(&mem, sizeof(struct dt_property),
                                __alignof__(struct dt_property));
        if ( allnextpp )
        {
            /* We accept flattened tree phandles either in
             * ePAPR-style "phandle" properties, or the
             * legacy "linux,phandle" properties.  If both
             * appear and have different values, things
             * will get weird.  Don't do that. */
            if ( (strcmp(pname, "phandle") == 0) ||
                 (strcmp(pname, "linux,phandle") == 0) )
            {
                if ( np->phandle == 0 )
                    np->phandle = be32_to_cpup((__be32*)*p);
            }
            /* And we process the "ibm,phandle" property
             * used in pSeries dynamic device tree
             * stuff */
            if ( strcmp(pname, "ibm,phandle") == 0 )
                np->phandle = be32_to_cpup((__be32 *)*p);
            pp->name = pname;
            pp->length = sz;
            pp->value = (void *)*p;
            *prev_pp = pp;
            prev_pp = &pp->next;
        }
        *p = ALIGN((*p) + sz, 4);
    }
    /* with version 0x10 we may not have the name property, recreate
     * it here from the unit name if absent
     */
    if ( !has_name )
    {
        char *p1 = pathp, *ps = pathp, *pa = NULL;
        int sz;

        while ( *p1 )
        {
            if ( (*p1) == '@' )
                pa = p1;
            if ( (*p1) == '/' )
                ps = p1 + 1;
            p1++;
        }
        if ( pa < ps )
            pa = p1;
        sz = (pa - ps) + 1;
        pp = unflatten_dt_alloc(&mem, sizeof(struct dt_property) + sz,
                                __alignof__(struct dt_property));
        if ( allnextpp )
        {
            pp->name = "name";
            pp->length = sz;
            pp->value = pp + 1;
            *prev_pp = pp;
            prev_pp = &pp->next;
            memcpy(pp->value, ps, sz - 1);
            ((char *)pp->value)[sz - 1] = 0;
            dt_dprintk("fixed up name for %s -> %s\n", pathp,
                       (char *)pp->value);
        }
    }
    if ( allnextpp )
    {
        *prev_pp = NULL;
        np->name = dt_get_property(np, "name", NULL);
        np->type = dt_get_property(np, "device_type", NULL);

        if ( !np->name )
            np->name = "<NULL>";
        if ( !np->type )
            np->type = "<NULL>";
    }
    while ( tag == FDT_BEGIN_NODE || tag == FDT_NOP )
    {
        if ( tag == FDT_NOP )
            *p += 4;
        else
            mem = unflatten_dt_node(fdt, mem, p, np, allnextpp, fpsize);
        tag = be32_to_cpup((__be32 *)(*p));
    }
    if ( tag != FDT_END_NODE )
    {
        dt_printk(XENLOG_WARNING "Weird tag at end of node: %x\n", tag);
        return mem;
    }

    *p += 4;
    return mem;
}

/**
 * __unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens a device-tree, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 * @fdt: The fdt to expand
 * @mynodes: The device_node tree created by the call
 */
static void __init __unflatten_device_tree(const void *fdt,
                                           struct dt_device_node **mynodes)
{
    unsigned long start, mem, size;
    struct dt_device_node **allnextp = mynodes;

    dt_dprintk(" -> unflatten_device_tree()\n");

    dt_dprintk("Unflattening device tree:\n");
    dt_dprintk("magic: %#08x\n", fdt_magic(fdt));
    dt_dprintk("size: %#08x\n", fdt_totalsize(fdt));
    dt_dprintk("version: %#08x\n", fdt_version(fdt));

    /* First pass, scan for size */
    start = ((unsigned long)fdt) + fdt_off_dt_struct(fdt);
    size = unflatten_dt_node(fdt, 0, &start, NULL, NULL, 0);
    size = (size | 3) + 1;

    dt_dprintk("  size is %#lx allocating...\n", size);

    /* Allocate memory for the expanded device tree */
    mem = (unsigned long)_xmalloc (size + 4, __alignof__(struct dt_device_node));

    ((__be32 *)mem)[size / 4] = cpu_to_be32(0xdeadbeef);

    dt_dprintk("  unflattening %lx...\n", mem);

    /* Second pass, do actual unflattening */
    start = ((unsigned long)fdt) + fdt_off_dt_struct(fdt);
    unflatten_dt_node(fdt, mem, &start, NULL, &allnextp, 0);
    if ( be32_to_cpup((__be32 *)start) != FDT_END )
        dt_printk(XENLOG_WARNING "Weird tag at end of tree: %08x\n",
                  *((u32 *)start));
    if ( be32_to_cpu(((__be32 *)mem)[size / 4]) != 0xdeadbeef )
        dt_printk(XENLOG_WARNING "End of tree marker overwritten: %08x\n",
                  be32_to_cpu(((__be32 *)mem)[size / 4]));
    *allnextp = NULL;

    dt_dprintk(" <- unflatten_device_tree()\n");
}

static void dt_alias_add(struct dt_alias_prop *ap,
                         struct dt_device_node *np,
                         int id, const char *stem, int stem_len)
{
    ap->np = np;
    ap->id = id;
    strlcpy(ap->stem, stem, stem_len + 1);
    list_add_tail(&ap->link, &aliases_lookup);
    dt_dprintk("adding DT alias:%s: stem=%s id=%d node=%s\n",
               ap->alias, ap->stem, ap->id, dt_node_full_name(np));
}

/**
 * dt_alias_scan - Scan all properties of 'aliases' node
 *
 * The function scans all the properties of 'aliases' node and populate
 * the the global lookup table with the properties.  It returns the
 * number of alias_prop found, or error code in error case.
 */
static void __init dt_alias_scan(void)
{
    const struct dt_property *pp;
    const struct dt_device_node *aliases;

    aliases = dt_find_node_by_path("/aliases");
    if ( !aliases )
        return;

    for_each_property_of_node( aliases, pp )
    {
        const char *start = pp->name;
        const char *end = start + strlen(start);
        struct dt_device_node *np;
        struct dt_alias_prop *ap;
        int id, len;

        /* Skip those we do not want to proceed */
        if ( !strcmp(pp->name, "name") ||
             !strcmp(pp->name, "phandle") ||
             !strcmp(pp->name, "linux,phandle") )
            continue;

        np = dt_find_node_by_path(pp->value);
        if ( !np )
            continue;

        /* walk the alias backwards to extract the id and work out
         * the 'stem' string */
        while ( isdigit(*(end-1)) && end > start )
            end--;
        len = end - start;

        id = simple_strtoll(end, NULL, 10);

        /* Allocate an alias_prop with enough space for the stem */
        ap = _xmalloc(sizeof(*ap) + len + 1, 4);
        if ( !ap )
            continue;
        ap->alias = start;
        dt_alias_add(ap, np, id, start, len);
    }
}

void __init dt_unflatten_host_device_tree(void)
{
    __unflatten_device_tree(device_tree_flattened, &dt_host);
    dt_alias_scan();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
