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

#include <xeno/config.h>
#include <xeno/sched.h>
#include <xeno/mm.h>
#include <xeno/perfc.h>
#include <asm/domain_page.h>
#include <asm/pgalloc.h>

static unsigned int map_idx[NR_CPUS];

/* Use a spare PTE bit to mark entries ready for recycling. */
#define READY_FOR_TLB_FLUSH (1<<10)

static void flush_all_ready_maps(void)
{
    unsigned long *cache = mapcache[smp_processor_id()];

    /* A bit skanky -- depends on having an aligned PAGE_SIZE set of PTEs. */
    do { if ( (*cache & READY_FOR_TLB_FLUSH) ) *cache = 0; }
    while ( ((unsigned long)(++cache) & ~PAGE_MASK) != 0 );

    perfc_incr(domain_page_tlb_flush);
    local_flush_tlb();
}


void *map_domain_mem(unsigned long pa)
{
    unsigned long va;
    int cpu = smp_processor_id();
    unsigned int idx;
    unsigned long *cache = mapcache[cpu];
    unsigned long flags;

    local_irq_save(flags);

    for ( ; ; )
    {
        idx = map_idx[cpu] = (map_idx[cpu] + 1) & (MAPCACHE_ENTRIES - 1);
        if ( idx == 0 ) flush_all_ready_maps();
        if ( cache[idx] == 0 ) break;
    }

    cache[idx] = (pa & PAGE_MASK) | __PAGE_HYPERVISOR;

    local_irq_restore(flags);

    va = MAPCACHE_VIRT_START + (idx << PAGE_SHIFT) + (pa & ~PAGE_MASK);
    return (void *)va;
}

void unmap_domain_mem(void *va)
{
    unsigned int idx;
    idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;
    mapcache[smp_processor_id()][idx] |= READY_FOR_TLB_FLUSH;
}
