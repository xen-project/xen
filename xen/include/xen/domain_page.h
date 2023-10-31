/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 * 
 * Copyright (c) 2003-2006, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_DOMAIN_PAGE_H__
#define __XEN_DOMAIN_PAGE_H__

#include <xen/mm.h>

/*
 * Clear a given page frame, or copy between two of them.
 */
void clear_domain_page(mfn_t mfn);
void copy_domain_page(mfn_t dest, mfn_t source);

#ifdef CONFIG_ARCH_MAP_DOMAIN_PAGE

/*
 * Map a given page frame, returning the mapped virtual address. The page is
 * then accessible within the current VCPU until a corresponding unmap call.
 */
void *map_domain_page(mfn_t mfn);

/*
 * Pass a VA within a page previously mapped in the context of the
 * currently-executing VCPU via a call to map_domain_page().
 */
void unmap_domain_page(const void *ptr);

/*
 * Given a VA from map_domain_page(), return its underlying MFN.
 */
mfn_t domain_page_map_to_mfn(const void *ptr);

/*
 * Similar to the above calls, except the mapping is accessible in all
 * address spaces (not just within the VCPU that created the mapping). Global
 * mappings can also be unmapped from any context.
 */
void *map_domain_page_global(mfn_t mfn);
void unmap_domain_page_global(const void *ptr);

#define __map_domain_page(pg)        map_domain_page(page_to_mfn(pg))

static inline void *__map_domain_page_global(const struct page_info *pg)
{
    return map_domain_page_global(page_to_mfn(pg));
}

#else /* !CONFIG_ARCH_MAP_DOMAIN_PAGE */

#define map_domain_page(mfn)                __mfn_to_virt(mfn_x(mfn))
#define __map_domain_page(pg)               page_to_virt(pg)
#define unmap_domain_page(ptr)              ((void)(ptr))
#define domain_page_map_to_mfn(ptr)         _mfn(__virt_to_mfn((unsigned long)(ptr)))

static inline void *map_domain_page_global(mfn_t mfn)
{
    return __mfn_to_virt(mfn_x(mfn));
}

static inline void *__map_domain_page_global(const struct page_info *pg)
{
    return page_to_virt(pg);
}

static inline void unmap_domain_page_global(const void *va) {};

#endif /* !CONFIG_ARCH_MAP_DOMAIN_PAGE */

#define UNMAP_DOMAIN_PAGE(p) do {   \
    unmap_domain_page(p);           \
    (p) = NULL;                     \
} while ( false )

#endif /* __XEN_DOMAIN_PAGE_H__ */
