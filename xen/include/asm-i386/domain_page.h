/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#include <xeno/config.h>
#include <xeno/sched.h>

extern unsigned long *mapcache;
#define MAPCACHE_ENTRIES        1024

/*
 * Maps a given physical address, returning corresponding virtual address.
 * The entire page containing that VA is now accessible until a 
 * corresponding call to unmap_domain_mem().
 */
extern void *map_domain_mem(unsigned long pa);

/*
 * Pass a VA within a page previously mapped with map_domain_mem().
 * That page will then be removed from the mapping lists.
 */
extern void unmap_domain_mem(void *va);

#if 0
#define MAPCACHE_HASH(_pfn)     ((_pfn) & (MAPCACHE_ENTRIES-1))
static inline void *map_domain_mem(unsigned long pa)
{
    unsigned long pfn = pa >> PAGE_SHIFT;
    unsigned long hash = MAPCACHE_HASH(pfn);
    unsigned long *pent = mapcache[smp_processor_id()] + hash;
    void *va = (void *)(MAPCACHE_VIRT_START + 
                        (hash << PAGE_SHIFT) + 
                        (pa & ~PAGE_MASK));
    if ( (*pent & PAGE_MASK) != (pfn << PAGE_SHIFT) )
    {
        *pent = (pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR;
        __flush_tlb_one(va);
    }
    return va;
}
#endif
