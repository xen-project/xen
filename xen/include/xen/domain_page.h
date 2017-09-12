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
void copy_domain_page(mfn_t dst, const mfn_t src);

#ifdef CONFIG_DOMAIN_PAGE

/*
 * Map a given page frame, returning the mapped virtual address. The page is
 * then accessible within the current VCPU until a corresponding unmap call.
 */
void *map_domain_page(mfn_t mfn);

/*
 * Pass a VA within a page previously mapped in the context of the
 * currently-executing VCPU via a call to map_domain_page().
 */
void unmap_domain_page(const void *va);

/* 
 * Given a VA from map_domain_page(), return its underlying MFN.
 */
unsigned long domain_page_map_to_mfn(const void *va);

/*
 * Similar to the above calls, except the mapping is accessible in all
 * address spaces (not just within the VCPU that created the mapping). Global
 * mappings can also be unmapped from any context.
 */
void *map_domain_page_global(mfn_t mfn);
void unmap_domain_page_global(const void *va);

#define __map_domain_page(pg)        map_domain_page(_mfn(__page_to_mfn(pg)))

static inline void *__map_domain_page_global(const struct page_info *pg)
{
    return map_domain_page_global(_mfn(__page_to_mfn(pg)));
}

#else /* !CONFIG_DOMAIN_PAGE */

#define map_domain_page(mfn)                __mfn_to_virt(mfn_x(mfn))
#define __map_domain_page(pg)               page_to_virt(pg)
#define unmap_domain_page(va)               ((void)(va))
#define domain_page_map_to_mfn(va)          virt_to_mfn((unsigned long)(va))

static inline void *map_domain_page_global(mfn_t mfn)
{
    return mfn_to_virt(mfn_x(mfn));
}

static inline void *__map_domain_page_global(const struct page_info *pg)
{
    return page_to_virt(pg);
}

static inline void unmap_domain_page_global(const void *va) {};

#endif /* !CONFIG_DOMAIN_PAGE */

#endif /* __XEN_DOMAIN_PAGE_H__ */
