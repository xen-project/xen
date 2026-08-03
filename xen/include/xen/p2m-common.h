#ifndef _XEN_P2M_COMMON_H
#define _XEN_P2M_COMMON_H

#include <xen/mm-frame.h>

/* Set foreign entry in the p2m table */
int set_foreign_p2m_entry(struct domain *d, const struct domain *fd,
                          unsigned long gfn, mfn_t mfn);

/* Remove a page from a domain's p2m table */
int __must_check
guest_physmap_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                          unsigned int page_order);

/* Map MMIO regions in the p2m: start_gfn and nr describe the range in
 *  * the guest physical address space to map, starting from the machine
 *   * frame number mfn. */
int map_mmio_regions(struct domain *d,
                     gfn_t start_gfn,
                     unsigned long nr,
                     mfn_t mfn);
int unmap_mmio_regions(struct domain *d,
                       gfn_t start_gfn,
                       unsigned long nr,
                       mfn_t mfn);

/* Check to see if vcpu should be switched to a different p2m. */
void p2m_altp2m_check(struct vcpu *v, uint16_t idx);

/*
 * Populate-on-Demand
 */

/*
 * Call when decreasing memory reservation to handle PoD entries properly.
 * Returns the number of pages that were successfully processed.
 */
unsigned long
p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn,
                             unsigned int order);

int __must_check check_get_page_from_gfn(struct domain *d, gfn_t gfn,
                                         bool readonly, p2m_type_t *p2mt_p,
                                         struct page_info **page_p);

/*
 * Set the pool of pages to the required number of pages.
 * Returns 0 for success, -ERESTART if preempted (only when can_preempt is
 * true), or a negative error code on failure.
 * Call with d->arch.paging.lock held.
 */
int __must_check p2m_set_allocation(struct domain *d, unsigned long pages,
                                    bool can_preempt);

#endif /* _XEN_P2M_COMMON_H */
