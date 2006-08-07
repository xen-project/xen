#ifndef __ASM_PERFC_H__
#define __ASM_PERFC_H__
#include <asm/mm.h>

static inline void arch_perfc_printall (void)
{
#ifdef PERF_ARRAYS
    ptwr_eip_stat_print();
#endif
}

static inline void arch_perfc_reset (void)
{
#ifdef PERF_ARRAYS
    ptwr_eip_stat_reset();
#endif
}

static inline void arch_perfc_gather (void)
{
}

#endif
