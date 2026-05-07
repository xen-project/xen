/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef XEN_DOMAIN_LAYOUT_H
#define XEN_DOMAIN_LAYOUT_H

#include <xen/paging.h>
#include <xen/sched.h>

/*
 * Is a domain using the host memory layout?
 *
 * domain_use_host_layout() is always False for PV domains (including Dom0).
 *
 * Direct-mapped domains (autotranslated domains with memory allocated
 * contiguously and mapped 1:1 so that GFN == MFN) must use the host
 * memory layout since GFN == MFN by definition.
 *
 * The hardware domain will use the host layout (regardless of
 * direct-mapped) because some OS may rely on specific address ranges
 * for the devices.
 */
static inline bool domain_use_host_layout(const struct domain *d)
{
    return paging_mode_translate(d) &&
           (is_domain_direct_mapped(d) || is_hardware_domain(d));
}

#endif /* XEN_DOMAIN_LAYOUT_H */
