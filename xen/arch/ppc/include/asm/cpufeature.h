/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_CPUFEATURE_H__
#define __ASM_PPC_CPUFEATURE_H__

static inline int cpu_nr_siblings(unsigned int cpu)
{
    return 1;
}

#endif /* __ASM_PPC_CPUFEATURE_H__ */
