/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __XEN_FDT_DOMAIN_BUILD_H__
#define __XEN_FDT_DOMAIN_BUILD_H__

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/fdt-kernel.h>
#include <xen/types.h>

struct domain;
struct page_info;
struct membanks;

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

#endif /* __XEN_FDT_DOMAIN_BUILD_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
