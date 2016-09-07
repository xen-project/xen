#ifndef _XEN_P2M_COMMON_H
#define _XEN_P2M_COMMON_H

#include <public/vm_event.h>

/*
 * Additional access types, which are used to further restrict
 * the permissions given my the p2m_type_t memory type.  Violations
 * caused by p2m_access_t restrictions are sent to the vm_event
 * interface.
 *
 * The access permissions are soft state: when any ambiguous change of page
 * type or use occurs, or when pages are flushed, swapped, or at any other
 * convenient type, the access permissions can get reset to the p2m_domain
 * default.
 */
typedef enum {
    /* Code uses bottom three bits with bitmask semantics */
    p2m_access_n     = 0, /* No access allowed. */
    p2m_access_r     = 1 << 0,
    p2m_access_w     = 1 << 1,
    p2m_access_x     = 1 << 2,
    p2m_access_rw    = p2m_access_r | p2m_access_w,
    p2m_access_rx    = p2m_access_r | p2m_access_x,
    p2m_access_wx    = p2m_access_w | p2m_access_x,
    p2m_access_rwx   = p2m_access_r | p2m_access_w | p2m_access_x,

    p2m_access_rx2rw = 8, /* Special: page goes from RX to RW on write */
    p2m_access_n2rwx = 9, /* Special: page goes from N to RWX on access, *
                           * generates an event but does not pause the
                           * vcpu */

    /* NOTE: Assumed to be only 4 bits right now on x86. */
} p2m_access_t;

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
 * Set access type for a region of gfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access,
                        unsigned int altp2m_idx);

long p2m_set_mem_access_multi(struct domain *d,
                              const XEN_GUEST_HANDLE(const_uint64) pfn_list,
                              const XEN_GUEST_HANDLE(const_uint8) access_list,
                              uint32_t nr, uint32_t start, uint32_t mask,
                              unsigned int altp2m_idx);

/*
 * Get access type for a gfn.
 * If gfn == INVALID_GFN, gets the default access type.
 */
int p2m_get_mem_access(struct domain *d, gfn_t gfn, xenmem_access_t *access);

#endif /* _XEN_P2M_COMMON_H */
