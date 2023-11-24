/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_STATIC_SHMEM_H_
#define __ASM_STATIC_SHMEM_H_

#include <asm/kernel.h>

#ifdef CONFIG_STATIC_SHM

int make_resv_memory_node(const struct domain *d, void *fdt, int addrcells,
                          int sizecells, const struct meminfo *mem);

int process_shm(struct domain *d, struct kernel_info *kinfo,
                const struct dt_device_node *node);

static inline int process_shm_chosen(struct domain *d,
                                     struct kernel_info *kinfo)
{
    const struct dt_device_node *node = dt_find_node_by_path("/chosen");

    return process_shm(d, kinfo, node);
}

int process_shm_node(const void *fdt, int node, uint32_t address_cells,
                     uint32_t size_cells);

#else /* !CONFIG_STATIC_SHM */

static inline int make_resv_memory_node(const struct domain *d, void *fdt,
                                        int addrcells, int sizecells,
                                        const struct meminfo *mem)
{
    return 0;
}

static inline int process_shm(struct domain *d, struct kernel_info *kinfo,
                              const struct dt_device_node *node)
{
    return 0;
}

static inline int process_shm_chosen(struct domain *d,
                                     struct kernel_info *kinfo)
{
    return 0;
}

static inline int process_shm_node(const void *fdt, int node,
                                   uint32_t address_cells, uint32_t size_cells)
{
    printk("CONFIG_STATIC_SHM must be enabled for parsing static shared memory nodes\n");
    return -EINVAL;
}

#endif /* CONFIG_STATIC_SHM */

#endif /* __ASM_STATIC_SHMEM_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
