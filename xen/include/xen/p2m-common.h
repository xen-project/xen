#ifndef _XEN_P2M_COMMON_H
#define _XEN_P2M_COMMON_H

/* Map MMIO regions in the p2m: start_gfn and nr describe the range in
 *  * the guest physical address space to map, starting from the machine
 *   * frame number mfn. */
int map_mmio_regions(struct domain *d,
                     unsigned long start_gfn,
                     unsigned long nr,
                     unsigned long mfn);
int unmap_mmio_regions(struct domain *d,
                       unsigned long start_gfn,
                       unsigned long nr,
                       unsigned long mfn);

#endif /* _XEN_P2M_COMMON_H */
