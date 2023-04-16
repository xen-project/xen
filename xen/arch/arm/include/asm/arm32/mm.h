#ifndef __ARM_ARM32_MM_H__
#define __ARM_ARM32_MM_H__

#include <xen/percpu.h>

#include <asm/lpae.h>

DECLARE_PER_CPU(lpae_t *, xen_pgtable);

/*
 * Only a limited amount of RAM, called xenheap, is always mapped on ARM32.
 * For convenience always return false.
 */
static inline bool arch_mfns_in_directmap(unsigned long mfn, unsigned long nr)
{
    return false;
}

bool init_domheap_mappings(unsigned int cpu);

static inline void arch_setup_page_tables(void)
{
}

#endif /* __ARM_ARM32_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
