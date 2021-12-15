#ifndef __HVM_CACHEATTR_H__
#define __HVM_CACHEATTR_H__

#include <xen/mm.h>

struct domain;
void hvm_init_cacheattr_region_list(struct domain *d);
void hvm_destroy_cacheattr_region_list(struct domain *d);

/*
 * Check whether gfn is in the pinned range:
 * if yes, return the (non-negative) type
 * if no or ambiguous, return a negative error code
 */
int hvm_get_mem_pinned_cacheattr(struct domain *d, gfn_t gfn,
                                 unsigned int order);


/* Set pinned caching type for a domain. */
int hvm_set_mem_pinned_cacheattr(struct domain *d, uint64_t gfn_start,
                                 uint64_t gfn_end, uint32_t type);

#endif /* __HVM_CACHEATTR_H__ */
