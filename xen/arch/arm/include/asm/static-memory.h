/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_STATIC_MEMORY_H_
#define __ASM_STATIC_MEMORY_H_

#include <xen/pfn.h>
#include <asm/kernel.h>

#ifdef CONFIG_STATIC_MEMORY

static inline void init_staticmem_bank(const struct membank *bank)
{
    mfn_t bank_start = _mfn(PFN_UP(bank->start));
    unsigned long bank_pages = PFN_DOWN(bank->size);
    mfn_t bank_end = mfn_add(bank_start, bank_pages);

    if ( mfn_x(bank_end) <= mfn_x(bank_start) )
        return;

    unprepare_staticmem_pages(mfn_to_page(bank_start), bank_pages, false);
}

void allocate_static_memory(struct domain *d, struct kernel_info *kinfo,
                            const struct dt_device_node *node);
void assign_static_memory_11(struct domain *d, struct kernel_info *kinfo,
                             const struct dt_device_node *node);
void init_staticmem_pages(void);

#else /* !CONFIG_STATIC_MEMORY */

static inline void allocate_static_memory(struct domain *d,
                                          struct kernel_info *kinfo,
                                          const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}

static inline void assign_static_memory_11(struct domain *d,
                                           struct kernel_info *kinfo,
                                           const struct dt_device_node *node)
{
    ASSERT_UNREACHABLE();
}

static inline void init_staticmem_pages(void) {};

#endif /* CONFIG_STATIC_MEMORY */

#endif /* __ASM_STATIC_MEMORY_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
