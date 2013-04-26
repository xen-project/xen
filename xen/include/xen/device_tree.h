/*
 * Device Tree
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __XEN_DEVICE_TREE_H__
#define __XEN_DEVICE_TREE_H__

#include <asm/byteorder.h>
#include <public/xen.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/types.h>

#define DEVICE_TREE_MAX_DEPTH 16

#define NR_MEM_BANKS 8
#define NR_MODULES 2

struct membank {
    paddr_t start;
    paddr_t size;
};

struct dt_mem_info {
    int nr_banks;
    struct membank bank[NR_MEM_BANKS];
};

struct dt_gic_info {
    paddr_t gic_dist_addr;
    paddr_t gic_cpu_addr;
    paddr_t gic_hyp_addr;
    paddr_t gic_vcpu_addr;
};

struct dt_mb_module {
    paddr_t start;
    paddr_t size;
    char cmdline[1024];
};

struct dt_module_info {
    int nr_mods;
    /* Module 0 is Xen itself, followed by the provided modules-proper */
    struct dt_mb_module module[NR_MODULES + 1];
};

struct dt_early_info {
    struct dt_mem_info mem;
    struct dt_gic_info gic;
    struct dt_module_info modules;
};

typedef u32 dt_phandle;

/**
 * dt_property - describe a property for a device
 * @name: name of the property
 * @length: size of the value
 * @value: pointer to data contained in the property
 * @next: pointer to the next property of a specific node
 */
struct dt_property {
    const char *name;
    u32 length;
    void *value;
    struct dt_property *next;
};

/**
 * dt_device_node - describe a node in the device tree
 * @name: name of the node
 * @type: type of the node (ie: memory, cpu, ...)
 * @full_name: full name, it's composed of all the ascendant name separate by /
 * @used_by: who owns the node? (ie: xen, dom0...)
 * @properties: list of properties for the node
 * @child: pointer to the first child
 * @sibling: pointer to the next sibling
 * @allnext: pointer to the next in list of all nodes
 */
struct dt_device_node {
    const char *name;
    const char *type;
    dt_phandle phandle;
    char *full_name;
    domid_t used_by; /* By default it's used by dom0 */

    struct dt_property *properties;
    struct dt_device_node *parent;
    struct dt_device_node *child;
    struct dt_device_node *sibling;
    struct dt_device_node *next; /* TODO: Remove it. Only use to know the last children */
    struct dt_device_node *allnext;

};

typedef int (*device_tree_node_func)(const void *fdt,
                                     int node, const char *name, int depth,
                                     u32 address_cells, u32 size_cells,
                                     void *data);

extern struct dt_early_info early_info;
extern void *device_tree_flattened;

size_t device_tree_early_init(const void *fdt);

void device_tree_get_reg(const u32 **cell, u32 address_cells, u32 size_cells,
                         u64 *start, u64 *size);
void device_tree_set_reg(u32 **cell, u32 address_cells, u32 size_cells,
                         u64 start, u64 size);
u32 device_tree_get_u32(const void *fdt, int node, const char *prop_name,
			u32 dflt);
bool_t device_tree_node_matches(const void *fdt, int node, const char *match);
bool_t device_tree_node_compatible(const void *fdt, int node, const char *match);
int find_compatible_node(const char *compatible, int *node, int *depth,
                u32 *address_cells, u32 *size_cells);
int device_tree_for_each_node(const void *fdt,
                              device_tree_node_func func, void *data);
const char *device_tree_bootargs(const void *fdt);
void device_tree_dump(const void *fdt);

/**
 * dt_unflatten_host_device_tree - Unflatten the host device tree
 *
 * Create a hierarchical device tree for the host DTB to be able
 * to retrieve parents.
 */
void __init dt_unflatten_host_device_tree(void);

/**
 * Host device tree
 * DO NOT modify it!
 */
extern struct dt_device_node *dt_host;

#define dt_node_cmp(s1, s2) strcmp((s1), (s2))
#define dt_compat_cmp(s1, s2, l) strnicmp((s1), (s2), l)

#define for_each_property_of_node(dn, pp)                   \
    for ( pp = dn->properties; pp != NULL; pp = pp->next )

#define for_each_device_node(dt, dn)                         \
    for ( dn = dt; dn != NULL; dn = dn->allnext )

static inline const char *dt_node_full_name(const struct dt_device_node *np)
{
    return (np && np->full_name) ? np->full_name : "<no-node>";
}

/**
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *dt_get_property(const struct dt_device_node *np,
                            const char *name, u32 *lenp);

/**
 * dt_find_node_by_path - Find a node matching a full DT path
 * @path: The full path to match
 *
 * Returns a node pointer.
 */
struct dt_device_node *dt_find_node_by_path(const char *path);
#endif
