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

size_t __init device_tree_early_init(const void *fdt);

void __init device_tree_get_reg(const u32 **cell, u32 address_cells,
                                u32 size_cells,
                                u64 *start, u64 *size);
void __init device_tree_set_reg(u32 **cell, u32 address_cells, u32 size_cells,
                                u64 start, u64 size);
u32 __init device_tree_get_u32(const void *fdt, int node,
                               const char *prop_name, u32 dflt);
bool_t __init device_tree_node_matches(const void *fdt, int node,
                                       const char *match);
bool_t __init device_tree_node_compatible(const void *fdt, int node,
                                          const char *match);
int __init find_compatible_node(const char *compatible, int *node, int *depth,
                                u32 *address_cells, u32 *size_cells);
int __init device_tree_for_each_node(const void *fdt,
                                     device_tree_node_func func, void *data);
const char __init *device_tree_bootargs(const void *fdt);
void __init device_tree_dump(const void *fdt);

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

/* Default #address and #size cells */
#define DT_ROOT_NODE_ADDR_CELLS_DEFAULT 1
#define DT_ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define for_each_property_of_node(dn, pp)                   \
    for ( pp = dn->properties; pp != NULL; pp = pp->next )

#define for_each_device_node(dt, dn)                         \
    for ( dn = dt; dn != NULL; dn = dn->allnext )

/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 dt_read_number(const __be32 *cell, int size)
{
    u64 r = 0;

    while ( size-- )
        r = (r << 32) | be32_to_cpu(*(cell++));
    return r;
}

static inline const char *dt_node_full_name(const struct dt_device_node *np)
{
    return (np && np->full_name) ? np->full_name : "<no-node>";
}

static inline const char *dt_node_name(const struct dt_device_node *np)
{
    return (np && np->name) ? np->name : "<no-node>";
}

static inline bool_t
dt_device_type_is_equal(const struct dt_device_node *device,
                        const char *type)
{
    return !dt_node_cmp(device->type, type);
}

static inline void dt_device_set_used_by(struct dt_device_node *device,
                                         domid_t used_by)
{
    /* TODO: children must inherit to the used_by thing */
    device->used_by = used_by;
}

static inline domid_t dt_device_used_by(const struct dt_device_node *device)
{
    return device->used_by;
}

/**
 * dt_find_compatible_node - Find a node based on type and one of the
 *                           tokens in its "compatible" property
 * @from: The node to start searching from or NULL, the node
 *          you pass will not be searched, only the next one
 *          will; typically, you pass what the previous call
 *          returned.
 * @type: The type string to match "device_type" or NULL to ignore
 * @compatible: The string to match to one of the tokens in the device
 *          "compatible" list.
 *
 * Returns a node pointer.
 */
struct dt_device_node *dt_find_compatible_node(struct dt_device_node *from,
                                               const char *type,
                                               const char *compatible);

/**
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *dt_get_property(const struct dt_device_node *np,
                            const char *name, u32 *lenp);

/**
 * Checks if the given "compat" string matches one of the strings in
 * the device's "compatible" property
 */
bool_t dt_device_is_compatible(const struct dt_device_node *device,
                               const char *compat);

/**
 * dt_machine_is_compatible - Test root of device tree for a given compatible value
 * @compat: compatible string to look for in root node's compatible property.
 *
 * Returns true if the root node has the given value in its
 * compatible property.
 */
bool_t dt_machine_is_compatible(const char *compat);

/**
 * dt_find_node_by_name - Find a node by its "name" property
 * @from: The node to start searching from or NULL, the node
 * you pass will not be searched, only the next one
 *  will; typically, you pass what the previous call
 *  returned. of_node_put() will be called on it
 * @name: The name string to match against
 *
 * Returns a node pointer with refcount incremented, use
 * of_node_put() on it when done.
 */
struct dt_device_node *dt_find_node_by_name(struct dt_device_node *node,
                                            const char *name);

/**
 * df_find_node_by_alias - Find a node matching an alias
 * @alias: The alias to match
 *
 * Returns a node pointer.
 */
struct dt_device_node *dt_find_node_by_alias(const char *alias);

/**
 * dt_find_node_by_path - Find a node matching a full DT path
 * @path: The full path to match
 *
 * Returns a node pointer.
 */
struct dt_device_node *dt_find_node_by_path(const char *path);

/**
 * dt_get_parent - Get a node's parent if any
 * @node: Node to get parent
 *
 * Returns a node pointer.
 */
const struct dt_device_node *dt_get_parent(const struct dt_device_node *node);

/**
 * dt_n_size_cells - Helper to retrieve the number of cell for the size
 * @np: node to get the value
 *
 * This function retrieves for a give device-tree node the number of
 * cell for the size field.
 */
int dt_n_size_cells(const struct dt_device_node *np);

/**
 * dt_n_addr_cells - Helper to retrieve the number of cell for the address
 * @np: node to get the value
 *
 * This function retrieves for a give device-tree node the number of
 * cell for the address field.
 */
int dt_n_addr_cells(const struct dt_device_node *np);

#endif
