/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain page frames into Xen space.
 */

#include <xeno/config.h>
#include <xeno/sched.h>

extern unsigned long *mapcache[NR_CPUS];
#define MAPCACHE_ENTRIES        1024
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
        *pent = (pfn << PAGE_SHIFT) | PAGE_HYPERVISOR;
        __flush_tlb_one(va);
    }
    return va;
}
