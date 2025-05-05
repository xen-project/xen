/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_GENERIC_DOM0LESS_BUILD_H__
#define __ASM_GENERIC_DOM0LESS_BUILD_H__

#include <xen/stdbool.h>

struct domain;

#ifdef CONFIG_DOM0LESS_BOOT

#include <public/domctl.h>

struct dt_device_node;

/* TODO: remove both when construct_domU() will be moved to common. */
#define XENSTORE_PFN_LATE_ALLOC UINT64_MAX
extern bool need_xenstore;

void create_domUs(void);
bool is_dom0less_mode(void);
void set_xs_domain(struct domain *d);

int construct_domU(struct domain *d, const struct dt_device_node *node);

void arch_create_domUs(struct dt_device_node *node,
                       struct xen_domctl_createdomain *d_cfg,
                       unsigned int flags);

#else /* !CONFIG_DOM0LESS_BOOT */

static inline void create_domUs(void) {}
static inline bool is_dom0less_mode(void)
{
    return false;
}
static inline void set_xs_domain(struct domain *d) {}

#endif /* CONFIG_DOM0LESS_BOOT */

#endif /* __ASM_GENERIC_DOM0LESS_BUILD_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
