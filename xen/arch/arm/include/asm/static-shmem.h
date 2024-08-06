/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_STATIC_SHMEM_H_
#define __ASM_STATIC_SHMEM_H_

#include <xen/types.h>
#include <asm/kernel.h>
#include <asm/setup.h>

#ifdef CONFIG_STATIC_SHM

/* Worst case /memory node reg element: (addrcells + sizecells) */
#define DT_MEM_NODE_REG_RANGE_SIZE ((NR_MEM_BANKS + NR_SHMEM_BANKS) * 4)

int make_resv_memory_node(const struct kernel_info *kinfo, int addrcells,
                          int sizecells);

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

void early_print_info_shmem(void);

void init_sharedmem_pages(void);

int remove_shm_from_rangeset(const struct kernel_info *kinfo,
                             struct rangeset *rangeset);

int remove_shm_holes_for_domU(const struct kernel_info *kinfo,
                              struct membanks *ext_regions);

int make_shm_resv_memory_node(const struct kernel_info *kinfo, int addrcells,
                              int sizecells);

void shm_mem_node_fill_reg_range(const struct kernel_info *kinfo, __be32 *reg,
                                 int *nr_cells, int addrcells, int sizecells);

static inline struct membanks *
kernel_info_get_shm_mem(struct kernel_info *kinfo)
{
    return container_of(&kinfo->shm_mem.common, struct membanks, common);
}

static inline const struct membanks *
kernel_info_get_shm_mem_const(const struct kernel_info *kinfo)
{
    return container_of(&kinfo->shm_mem.common, const struct membanks, common);
}

#else /* !CONFIG_STATIC_SHM */

/* Worst case /memory node reg element: (addrcells + sizecells) */
#define DT_MEM_NODE_REG_RANGE_SIZE (NR_MEM_BANKS * 4)

static inline int make_resv_memory_node(const struct kernel_info *kinfo,
                                        int addrcells, int sizecells)
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

static inline void init_sharedmem_pages(void) {};

static inline int remove_shm_from_rangeset(const struct kernel_info *kinfo,
                                           struct rangeset *rangeset)
{
    return 0;
}

static inline int remove_shm_holes_for_domU(const struct kernel_info *kinfo,
                                            struct membanks *ext_regions)
{
    return 0;
}

static inline int make_shm_resv_memory_node(const struct kernel_info *kinfo,
                                            int addrcells, int sizecells)
{
    return 0;
}

static inline void shm_mem_node_fill_reg_range(const struct kernel_info *kinfo,
                                               __be32 *reg, int *nr_cells,
                                               int addrcells, int sizecells) {};

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
