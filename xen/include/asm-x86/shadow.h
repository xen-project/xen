/******************************************************************************
 * include/asm-x86/shadow.h
 * 
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/paging.h>
#include <asm/p2m.h>

/*****************************************************************************
 * Macros to tell which shadow paging mode a domain is in*/

#define shadow_mode_enabled(_d)    paging_mode_shadow(_d)
#define shadow_mode_refcounts(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_refcounts(_d))
#define shadow_mode_log_dirty(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_log_dirty(_d))
#define shadow_mode_translate(_d) (paging_mode_shadow(_d) && \
                                   paging_mode_translate(_d))
#define shadow_mode_external(_d)  (paging_mode_shadow(_d) && \
                                   paging_mode_external(_d))

/*****************************************************************************
 * Entry points into the shadow code */

/* Set up the shadow-specific parts of a domain struct at start of day.
 * Called from paging_domain_init(). */
int shadow_domain_init(struct domain *d, unsigned int domcr_flags);

/* Setup the shadow-specific parts of a vcpu struct. It is called by
 * paging_vcpu_init() in paging.c */
void shadow_vcpu_init(struct vcpu *v);

#ifdef CONFIG_SHADOW_PAGING

/* Enable an arbitrary shadow mode.  Call once at domain creation. */
int shadow_enable(struct domain *d, u32 mode);

/* Enable VRAM dirty bit tracking. */
int shadow_track_dirty_vram(struct domain *d,
                            unsigned long first_pfn,
                            unsigned long nr,
                            XEN_GUEST_HANDLE_PARAM(void) dirty_bitmap);

/* Handler for shadow control ops: operations from user-space to enable
 * and disable ephemeral shadow modes (test mode and log-dirty mode) and
 * manipulate the log-dirty bitmap. */
int shadow_domctl(struct domain *d, 
                  struct xen_domctl_shadow_op *sc,
                  XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

/* Call when destroying a domain */
void shadow_teardown(struct domain *d, bool *preempted);

/* Call once all of the references to the domain have gone away */
void shadow_final_teardown(struct domain *d);

void sh_remove_shadows(struct domain *d, mfn_t gmfn, int fast, int all);

/* Discard _all_ mappings from the domain's shadows. */
void shadow_blow_tables_per_domain(struct domain *d);

/* Set the pool of shadow pages to the required number of pages.
 * Input will be rounded up to at least shadow_min_acceptable_pages(),
 * plus space for the p2m table.
 * Returns 0 for success, non-zero for failure. */
int shadow_set_allocation(struct domain *d, unsigned int pages,
                          bool *preempted);

#else /* !CONFIG_SHADOW_PAGING */

#define shadow_teardown(d, p) ASSERT(is_pv_domain(d))
#define shadow_final_teardown(d) ASSERT(is_pv_domain(d))
#define shadow_enable(d, mode) \
    ({ ASSERT(is_pv_domain(d)); -EOPNOTSUPP; })
#define shadow_track_dirty_vram(d, begin_pfn, nr, bitmap) \
    ({ ASSERT_UNREACHABLE(); -EOPNOTSUPP; })
#define shadow_set_allocation(d, pages, preempted) \
    ({ ASSERT_UNREACHABLE(); -EOPNOTSUPP; })

static inline void sh_remove_shadows(struct domain *d, mfn_t gmfn,
                                     int fast, int all) {}

static inline void shadow_blow_tables_per_domain(struct domain *d) {}

static inline int shadow_domctl(struct domain *d,
                                struct xen_domctl_shadow_op *sc,
                                XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    return -EINVAL;
}

#endif /* CONFIG_SHADOW_PAGING */

/* Remove all shadows of the guest mfn. */
static inline void shadow_remove_all_shadows(struct domain *d, mfn_t gmfn)
{
    /* See the comment about locking in sh_remove_shadows */
    sh_remove_shadows(d, gmfn, 0 /* Be thorough */, 1 /* Must succeed */);
}

#endif /* _XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
