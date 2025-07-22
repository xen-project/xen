/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef XEN_DOM0LESS_BUILD_H
#define XEN_DOM0LESS_BUILD_H

#include <xen/stdbool.h>

struct domain;

#ifdef CONFIG_DOM0LESS_BOOT

struct boot_domain;
struct dt_device_node;
struct kernel_info;

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

int arch_parse_dom0less_node(struct dt_device_node *node,
                             struct boot_domain *bd);

int init_vuart(struct domain *d, struct kernel_info *kinfo,
               const struct dt_device_node *node);

int make_intc_domU_node(struct kernel_info *kinfo);
int make_arch_nodes(struct kernel_info *kinfo);

void set_domain_type(struct domain *d, struct kernel_info *kinfo);

int init_intc_phandle(struct kernel_info *kinfo, const char *name,
                      const int node_next, const void *pfdt);

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
