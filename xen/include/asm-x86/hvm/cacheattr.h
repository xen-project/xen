#ifndef __HVM_CACHEATTR_H__
#define __HVM_CACHEATTR_H__

struct hvm_mem_pinned_cacheattr_range {
    struct list_head list;
    uint64_t start, end;
    unsigned int type;
};

void hvm_init_cacheattr_region_list(
    struct domain *d);
void hvm_destroy_cacheattr_region_list(
    struct domain *d);

/*
 * To see guest_fn is in the pinned range or not,
 * if yes, return 1, and set type to value in this range
 * if no,  return 0, and set type to 0
 */
int hvm_get_mem_pinned_cacheattr(
    struct domain *d,
    unsigned long guest_fn,
    unsigned int *type);


/* Set pinned caching type for a domain. */
int hvm_set_mem_pinned_cacheattr(
    struct domain *d,
    unsigned long gfn_start,
    unsigned long gfn_end,
    unsigned int  type);

#endif /* __HVM_CACHEATTR_H__ */
