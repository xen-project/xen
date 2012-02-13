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

extern struct dt_early_info early_info;

void device_tree_early_init(const void *fdt);
paddr_t device_tree_get_xen_paddr(void);

#endif
