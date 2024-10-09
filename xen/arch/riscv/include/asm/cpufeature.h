/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__CPUFEATURE_H
#define ASM__RISCV__CPUFEATURE_H

#ifndef __ASSEMBLY__

static inline unsigned int cpu_nr_siblings(unsigned int cpu)
{
    return 1;
}

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__CPUFEATURE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
