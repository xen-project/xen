/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain pages. Based on ideas from the
 * Linux PKMAP code -- the copyrights and credits are retained below.
 */

/*
 * (C) 1999 Andrea Arcangeli, SuSE GmbH, andrea@suse.de
 *          Gerhard Wichert, Siemens AG, Gerhard.Wichert@pdb.siemens.de *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <asm/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>

unsigned long *mapcache;
static unsigned int map_idx, epoch, shadow_epoch[NR_CPUS];
static spinlock_t map_lock = SPIN_LOCK_UNLOCKED;

/* Use a spare PTE bit to mark entries ready for recycling. */
#define READY_FOR_TLB_FLUSH (1<<10)

static void flush_all_ready_maps(void)
{
    unsigned long *cache = mapcache;

    /* A bit skanky -- depends on having an aligned PAGE_SIZE set of PTEs. */
    do {
        if ( (*cache & READY_FOR_TLB_FLUSH) )
            *cache = 0;
    }
    while ( ((unsigned long)(++cache) & ~PAGE_MASK) != 0 );
}


void *map_domain_mem(unsigned long pa)
{
    unsigned long va;
    unsigned int idx, cpu = smp_processor_id();
    unsigned long *cache = mapcache;
#ifndef NDEBUG
    unsigned flush_count = 0;
#endif

    ASSERT(!in_irq());
    perfc_incrc(map_domain_mem_count);

    spin_lock(&map_lock);

    /* Has some other CPU caused a wrap? We must flush if so. */
    if ( epoch != shadow_epoch[cpu] )
    {
        perfc_incrc(domain_page_tlb_flush);
        local_flush_tlb();
        shadow_epoch[cpu] = epoch;
    }

    do {
        idx = map_idx = (map_idx + 1) & (MAPCACHE_ENTRIES - 1);
        if ( unlikely(idx == 0) )
        {
            flush_all_ready_maps();
            perfc_incrc(domain_page_tlb_flush);
            local_flush_tlb();
            shadow_epoch[cpu] = ++epoch;
#ifndef NDEBUG
            if ( unlikely(flush_count++) )
            {
                // we've run out of map cache entries...
                BUG();
            }
#endif
        }
    }
    while ( cache[idx] != 0 );

    cache[idx] = (pa & PAGE_MASK) | __PAGE_HYPERVISOR;

    spin_unlock(&map_lock);

    va = MAPCACHE_VIRT_START + (idx << PAGE_SHIFT) + (pa & ~PAGE_MASK);
    return (void *)va;
}

void unmap_domain_mem(void *va)
{
    unsigned int idx;
    idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;
    mapcache[idx] |= READY_FOR_TLB_FLUSH;
}
