/******************************************************************************
 * domain_page.h
 * 
 * This is a trivial no-op on ia64, where we can 1:1 map all RAM.
 */

#ifndef __ASM_DOMAIN_PAGE_H__
#define __ASM_DOMAIN_PAGE_H__

#define map_domain_mem(_pa)   phys_to_virt(_pa)
#define unmap_domain_mem(_va) ((void)(_va))

#endif /* __ASM_DOMAIN_PAGE_H__ */

