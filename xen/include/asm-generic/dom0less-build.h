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

/*
 * List of possible features for dom0less domUs
 *
 * DOM0LESS_ENHANCED_NO_XS:  Notify the OS it is running on top of Xen. All the
 *                           default features (excluding Xenstore) will be
 *                           available. Note that an OS *must* not rely on the
 *                           availability of Xen features if this is not set.
 * DOM0LESS_XENSTORE:        Xenstore will be enabled for the VM. The
 *                           xenstore page allocation is done by Xen at
 *                           domain creation. This feature can't be
 *                           enabled without the DOM0LESS_ENHANCED_NO_XS.
 * DOM0LESS_XS_LEGACY        Xenstore will be enabled for the VM, the
 *                           xenstore page allocation will happen in
 *                           init-dom0less. This feature can't be enabled
 *                           without the DOM0LESS_ENHANCED_NO_XS.
 * DOM0LESS_ENHANCED:        Notify the OS it is running on top of Xen. All the
 *                           default features (including Xenstore) will be
 *                           available. Note that an OS *must* not rely on the
 *                           availability of Xen features if this is not set.
 * DOM0LESS_ENHANCED_LEGACY: Same as before, but using DOM0LESS_XS_LEGACY.

 */
#define DOM0LESS_ENHANCED_NO_XS  BIT(0, U)
#define DOM0LESS_XENSTORE        BIT(1, U)
#define DOM0LESS_XS_LEGACY       BIT(2, U)
#define DOM0LESS_ENHANCED_LEGACY (DOM0LESS_ENHANCED_NO_XS | DOM0LESS_XS_LEGACY)
#define DOM0LESS_ENHANCED        (DOM0LESS_ENHANCED_NO_XS | DOM0LESS_XENSTORE)

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
