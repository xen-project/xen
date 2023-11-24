/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_STATIC_MEMORY_H_
#define __ASM_STATIC_MEMORY_H_

#include <asm/kernel.h>

#ifdef CONFIG_STATIC_MEMORY

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
