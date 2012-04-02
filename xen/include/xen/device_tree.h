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

#include <xen/types.h>

#define DEVICE_TREE_MAX_DEPTH 16

#define NR_MEM_BANKS 8

struct membank {
    paddr_t start;
    paddr_t size;
};

struct dt_mem_info {
    int nr_banks;
    struct membank bank[NR_MEM_BANKS];
};

struct dt_early_info {
    struct dt_mem_info mem;
};

typedef int (*device_tree_node_func)(const void *fdt,
                                     int node, const char *name, int depth,
                                     u32 address_cells, u32 size_cells,
                                     void *data);

extern struct dt_early_info early_info;
extern void *device_tree_flattened;

size_t device_tree_early_init(const void *fdt);
paddr_t device_tree_get_xen_paddr(void);

void device_tree_get_reg(const u32 **cell, u32 address_cells, u32 size_cells,
                         u64 *start, u64 *size);
void device_tree_set_reg(u32 **cell, u32 address_cells, u32 size_cells,
                         u64 start, u64 size);
u32 device_tree_get_u32(const void *fdt, int node, const char *prop_name);
bool_t device_tree_node_matches(const void *fdt, int node, const char *match);
int device_tree_for_each_node(const void *fdt,
                              device_tree_node_func func, void *data);
void device_tree_dump(const void *fdt);

#endif
