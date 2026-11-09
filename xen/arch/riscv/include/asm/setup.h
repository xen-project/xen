/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef RISCV_SETUP_H
#define RISCV_SETUP_H

#include <xen/types.h>

void setup_mm(void);

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

void init_csr_masks(void);

#endif /* RISCV_SETUP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
