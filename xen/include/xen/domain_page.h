/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#ifndef __XEN_DOMAIN_PAGE_H__
#define __XEN_DOMAIN_PAGE_H__

#include <xen/config.h>
#include <xen/mm.h>

#ifdef CONFIG_DOMAIN_PAGE

/*
 * Map a given page frame, returning the mapped virtual address. The page is
 * then accessible within the current VCPU until a corresponding unmap call.
 */
extern void *map_domain_page(unsigned long pfn);

/*
 * Pass a VA within a page previously mapped in the context of the
 * currently-executing VCPU via a call to map_domain_pages().
 */
extern void unmap_domain_page(void *va);

/*
 * Similar to the above calls, except the mapping is accessible in all
 * address spaces (not just within the VCPU that created the mapping). Global
 * mappings can also be unmapped from any context.
 */
extern void *map_domain_page_global(unsigned long pfn);
extern void unmap_domain_page_global(void *va);

#define DMCACHE_ENTRY_VALID 1U
#define DMCACHE_ENTRY_HELD  2U

struct domain_mmap_cache {
    unsigned long pfn;
    void         *va;
    unsigned int  flags;
};

static inline void
domain_mmap_cache_init(struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    cache->flags = 0;
}

static inline void *
map_domain_page_with_cache(unsigned long pfn, struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    BUG_ON(cache->flags & DMCACHE_ENTRY_HELD);

    if ( likely(cache->flags & DMCACHE_ENTRY_VALID) )
    {
        cache->flags |= DMCACHE_ENTRY_HELD;
        if ( likely(pfn == cache->pfn) )
            goto done;
        unmap_domain_page(cache->va);
    }

    cache->pfn   = pfn;
    cache->va    = map_domain_page(pfn);
    cache->flags = DMCACHE_ENTRY_HELD | DMCACHE_ENTRY_VALID;

 done:
    return cache->va;
}

static inline void
unmap_domain_page_with_cache(void *va, struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    cache->flags &= ~DMCACHE_ENTRY_HELD;
}

static inline void
domain_mmap_cache_destroy(struct domain_mmap_cache *cache)
{
    ASSERT(cache != NULL);
    BUG_ON(cache->flags & DMCACHE_ENTRY_HELD);

    if ( likely(cache->flags & DMCACHE_ENTRY_VALID) )
    {
        unmap_domain_page(cache->va);
        cache->flags = 0;
    }
}

#else /* !CONFIG_DOMAIN_PAGE */

#define map_domain_page(pfn)                phys_to_virt((pfn)<<PAGE_SHIFT)
#define unmap_domain_page(va)               ((void)(va))

#define map_domain_page_global(pfn)         phys_to_virt((pfn)<<PAGE_SHIFT)
#define unmap_domain_page_global(va)        ((void)(va))

struct domain_mmap_cache { 
};

#define domain_mmap_cache_init(c)           ((void)(c))
#define map_domain_page_with_cache(pfn,c)   (map_domain_page(pfn))
#define unmap_domain_page_with_cache(va,c)  ((void)(va))
#define domain_mmap_cache_destroy(c)        ((void)(c))

#endif /* !CONFIG_DOMAIN_PAGE */

#endif /* __XEN_DOMAIN_PAGE_H__ */
