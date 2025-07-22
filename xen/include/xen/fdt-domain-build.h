/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __XEN_FDT_DOMAIN_BUILD_H__
#define __XEN_FDT_DOMAIN_BUILD_H__

#include <xen/bootinfo.h>
#include <xen/device_tree.h>
#include <xen/fdt-kernel.h>
#include <xen/mm.h>
#include <xen/types.h>

struct domain;
struct page_info;
struct membanks;

typedef bool (*alloc_domheap_mem_cb)(struct domain *d, struct page_info *pg,
                                     unsigned int order, void *extra);
bool allocate_domheap_memory(struct domain *d, paddr_t tot_size,
                             alloc_domheap_mem_cb cb, void *extra);

bool allocate_bank_memory(struct kernel_info *kinfo, gfn_t sgfn,
                          paddr_t tot_size);
void allocate_memory(struct domain *d, struct kernel_info *kinfo);
int construct_domain(struct domain *d, struct kernel_info *kinfo);
int construct_hwdom(struct kernel_info *kinfo,
                    const struct dt_device_node *node);
int make_chosen_node(const struct kernel_info *kinfo);
int make_cpus_node(const struct domain *d, void *fdt);
int make_hypervisor_node(struct domain *d, const struct kernel_info *kinfo,
                         int addrcells, int sizecells);
int make_memory_node(const struct kernel_info *kinfo, int addrcells,
                     int sizecells, const struct membanks *mem);
int make_timer_node(const struct kernel_info *kinfo);

static inline int get_allocation_size(paddr_t size)
{
    /*
     * get_order_from_bytes returns the order greater than or equal to
     * the given size, but we need less than or equal. Adding one to
     * the size pushes an evenly aligned size into the next order, so
     * we can then unconditionally subtract 1 from the order which is
     * returned.
     */
    return get_order_from_bytes(size + 1) - 1;
}

typedef unsigned long (*copy_to_guest_phys_cb)(struct domain *d,
                                               paddr_t gpa,
                                               void *buf,
                                               unsigned int len);

void initrd_load(struct kernel_info *kinfo,
                 copy_to_guest_phys_cb cb);

void dtb_load(struct kernel_info *kinfo,
              copy_to_guest_phys_cb cb);

int find_unallocated_memory(const struct kernel_info *kinfo,
                            const struct membanks *mem_banks[],
                            unsigned int nr_mem_banks,
                            struct membanks *free_regions,
                            int (*cb)(unsigned long s_gfn,
                                      unsigned long e_gfn,
                                      void *data));

#endif /* __XEN_FDT_DOMAIN_BUILD_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
