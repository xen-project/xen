/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2005, 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Ryan Harper <ryanh@us.ibm.com>
 */

#ifndef _ASM_SHADOW_H_
#define _ASM_SHADOW_H_

#include <xen/sched.h>

#define shadow_mode_translate(_d) (1)
#define shadow_mode_refcounts(_d) (1)

#define __mfn_to_gpfn(_d, mfn)                         \
    ( (shadow_mode_translate(_d))                      \
      ? machine_to_phys_mapping[(mfn)]                 \
      : (mfn) )

extern void guest_physmap_add_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn);

extern void guest_physmap_remove_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn);

extern void shadow_drop_references(
    struct domain *d, struct page_info *page);

static inline void mark_dirty(struct domain *d, unsigned int mfn)
{
    return;
}
#define gnttab_mark_dirty(d, f) mark_dirty((d), (f))

extern int shadow_domctl(struct domain *d, 
                   xen_domctl_shadow_op_t *sc,
                   XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);
extern unsigned int shadow_teardown(struct domain *d);
extern unsigned int shadow_set_allocation(
    struct domain *d, unsigned int megabytes, int *preempted);

/* Return the size of the shadow2 pool, rounded up to the nearest MB */
static inline unsigned int shadow_get_allocation(struct domain *d)
{
    return (1ULL << (d->arch.htab.order + PAGE_SHIFT)) >> 20;
}

#define guest_physmap_max_mem_pages(d, n) (0)

#endif

