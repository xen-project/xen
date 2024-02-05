/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_CPUFEATURE_H
#define __ASM_RISCV_CPUFEATURE_H

#ifndef __ASSEMBLY__

static inline unsigned int cpu_nr_siblings(unsigned int cpu)
{
    return 1;
}

#endif /* __ASSEMBLY__ */

#endif /* __ASM_RISCV_CPUFEATURE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
