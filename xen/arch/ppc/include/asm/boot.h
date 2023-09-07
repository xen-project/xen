/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_BOOT_H
#define _ASM_PPC_BOOT_H

#include <xen/types.h>

/*
 * OPAL boot interfaces
 */

struct opal {
    uint64_t base;
    uint64_t entry;
};

void boot_opal_init(const void *fdt);

#endif /* _ASM_PPC_BOOT_H */
