#ifndef _XEN_P2M_COMMON_H
#define _XEN_P2M_COMMON_H

#include <xen/mm.h>

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

/*
 * Populate-on-Demand
 */

/*
 * Call when decreasing memory reservation to handle PoD entries properly.
 * Will return '1' if all entries were handled and nothing more need be done.
 */
int
p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn,
                             unsigned int order);


#endif /* _XEN_P2M_COMMON_H */
