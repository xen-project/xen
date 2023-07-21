/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_BOOT_H
#define _ASM_PPC_BOOT_H

#include <xen/types.h>

/* a collection of interfaces used during boot. */
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

#endif /* _ASM_PPC_BOOT_H */
