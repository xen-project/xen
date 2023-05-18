/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/include/xen/libfdt/libfdt-xen.h
 *
 * Wrapper functions for device tree. This helps to convert dt values
 * between uint64_t and paddr_t.
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc. All Rights Reserved.
 */

#ifndef LIBFDT_XEN_H
#define LIBFDT_XEN_H

#include <xen/libfdt/libfdt.h>

static inline int fdt_get_mem_rsv_paddr(const void *fdt, int n,
                                        paddr_t *address,
                                        paddr_t *size)
{
    uint64_t dt_addr;
    uint64_t dt_size;
    int ret;

    ret = fdt_get_mem_rsv(fdt, n, &dt_addr, &dt_size);
    if ( ret < 0 )
        return ret;

    if ( dt_addr != (paddr_t)dt_addr )
    {
        printk("Error: Physical address greater than max width supported\n");
        return -FDT_ERR_MAX;
    }

    if ( dt_size != (paddr_t)dt_size )
    {
        printk("Error: Physical size greater than max width supported\n");
        return -FDT_ERR_MAX;
    }

    *address = dt_addr;
    *size = dt_size;

    return ret;
}

#endif /* LIBFDT_XEN_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
