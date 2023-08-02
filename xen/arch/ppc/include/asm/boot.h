/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_BOOT_H
#define _ASM_PPC_BOOT_H

#include <xen/types.h>

/*
 * OpenFirmware boot interfaces
 */

enum {
    OF_FAILURE = -1,
    OF_SUCCESS = 0,
};

struct of_service {
    __be32 ofs_service;
    __be32 ofs_nargs;
    __be32 ofs_nrets;
    __be32 ofs_args[10];
};

int enter_of(struct of_service *args, unsigned long entry);
void boot_of_init(unsigned long vec);

/*
 * OPAL boot interfaces
 */

struct opal {
    uint64_t base;
    uint64_t entry;
};

void boot_opal_init(const void *fdt);

#endif /* _ASM_PPC_BOOT_H */
