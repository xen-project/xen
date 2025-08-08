/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2007, 2008 Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
 */

#ifndef ASM_TRAP_H
#define ASM_TRAP_H

void bsp_early_traps_init(void);
void traps_init(void);
void bsp_traps_reinit(void);
void percpu_traps_init(void);

extern unsigned int ler_msr;

const char *vector_name(unsigned int vec);

#endif /* ASM_TRAP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
