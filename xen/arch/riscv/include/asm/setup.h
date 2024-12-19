/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__SETUP_H
#define ASM__RISCV__SETUP_H

#include <xen/types.h>

#define max_init_domid (0)

void setup_mm(void);

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

#endif /* ASM__RISCV__SETUP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
