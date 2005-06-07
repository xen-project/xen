/******************************************************************************
 * domain_page.h
 * 
 * This is a trivial no-op on x86/64, where we can 1:1 map all RAM.
 */

#ifndef __ASM_DOMAIN_PAGE_H__
#define __ASM_DOMAIN_PAGE_H__

#define map_domain_mem(_pa)   phys_to_virt(_pa)
#define unmap_domain_mem(_va) ((void)(_va))

struct domain_mmap_cache { 
};

#define domain_mmap_cache_init(_c)         ((void)(_c))
#define map_domain_mem_with_cache(_p,_c)   (map_domain_mem(_p))
#define unmap_domain_mem_with_cache(_v,_c) ((void)(_v))
#define domain_mmap_cache_destroy(_c)      ((void)(_c))

#endif /* __ASM_DOMAIN_PAGE_H__ */
