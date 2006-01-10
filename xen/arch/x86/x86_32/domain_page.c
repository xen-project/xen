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
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>

#define MAPCACHE_ORDER    10
#define MAPCACHE_ENTRIES  (1 << MAPCACHE_ORDER)

/* Use a spare PTE bit to mark entries ready for recycling. */
#define READY_FOR_TLB_FLUSH (1<<10)

static void flush_all_ready_maps(void)
{
    struct mapcache *cache = &current->domain->arch.mapcache;
    unsigned int i;

    for ( i = 0; i < MAPCACHE_ENTRIES; i++ )
        if ( (l1e_get_flags(cache->l1tab[i]) & READY_FOR_TLB_FLUSH) )
            cache->l1tab[i] = l1e_empty();
}

void *map_domain_pages(unsigned long pfn, unsigned int order)
{
    unsigned long va;
    unsigned int idx, i, flags, vcpu = current->vcpu_id;
    struct mapcache *cache = &current->domain->arch.mapcache;
#ifndef NDEBUG
    unsigned int flush_count = 0;
#endif

    ASSERT(!in_irq());
    perfc_incrc(map_domain_page_count);

    /* If we are the idle domain, ensure that we run on our own page tables. */
    if ( unlikely(is_idle_vcpu(current)) )
        __sync_lazy_execstate();

    spin_lock(&cache->lock);

    /* Has some other CPU caused a wrap? We must flush if so. */
    if ( cache->epoch != cache->shadow_epoch[vcpu] )
    {
        perfc_incrc(domain_page_tlb_flush);
        local_flush_tlb();
        cache->shadow_epoch[vcpu] = cache->epoch;
    }

    do {
        idx = cache->cursor = (cache->cursor + 1) & (MAPCACHE_ENTRIES - 1);
        if ( unlikely(idx == 0) )
        {
            ASSERT(flush_count++ == 0);
            flush_all_ready_maps();
            perfc_incrc(domain_page_tlb_flush);
            local_flush_tlb();
            cache->shadow_epoch[vcpu] = ++cache->epoch;
        }

        flags = 0;
        for ( i = 0; i < (1U << order); i++ )
            flags |= l1e_get_flags(cache->l1tab[idx+i]);
    }
    while ( flags & _PAGE_PRESENT );

    for ( i = 0; i < (1U << order); i++ )
        cache->l1tab[idx+i] = l1e_from_pfn(pfn+i, __PAGE_HYPERVISOR);

    spin_unlock(&cache->lock);

    va = MAPCACHE_VIRT_START + (idx << PAGE_SHIFT);
    return (void *)va;
}

void unmap_domain_pages(void *va, unsigned int order)
{
    unsigned int idx, i;
    struct mapcache *cache = &current->domain->arch.mapcache;

    ASSERT((void *)MAPCACHE_VIRT_START <= va);
    ASSERT(va < (void *)MAPCACHE_VIRT_END);

    idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;

    for ( i = 0; i < (1U << order); i++ )
        l1e_add_flags(cache->l1tab[idx+i], READY_FOR_TLB_FLUSH);
}

#define GLOBALMAP_BITS (IOREMAP_MBYTES << (20 - PAGE_SHIFT))
static unsigned long inuse[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned long garbage[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned int inuse_cursor;
static spinlock_t globalmap_lock = SPIN_LOCK_UNLOCKED;

void *map_domain_page_global(unsigned long pfn)
{
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int idx, i;
    unsigned long va;

    ASSERT(!in_irq() && local_irq_is_enabled());

    spin_lock(&globalmap_lock);

    for ( ; ; )
    {
        idx = find_next_zero_bit(inuse, GLOBALMAP_BITS, inuse_cursor);
        va = IOREMAP_VIRT_START + (idx << PAGE_SHIFT);

        /* End of round? If not then we're done in this loop. */
        if ( va < FIXADDR_START )
            break;

        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < ARRAY_SIZE(garbage); i++ )
        {
            unsigned long x = xchg(&garbage[i], 0);
            inuse[i] &= ~x;
        }

        /* /Second/, flush all TLBs to get rid of stale garbage mappings. */
        flush_tlb_all();

        inuse_cursor = 0;
    }

    set_bit(idx, inuse);
    inuse_cursor = idx + 1;

    spin_unlock(&globalmap_lock);

    pl2e = virt_to_xen_l2e(va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(va);
    *pl1e = l1e_from_pfn(pfn, __PAGE_HYPERVISOR);

    return (void *)va;
}

void unmap_domain_page_global(void *va)
{
    unsigned long __va = (unsigned long)va;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int idx;

    /* /First/, we zap the PTE. */
    pl2e = virt_to_xen_l2e(__va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(__va);
    *pl1e = l1e_empty();

    /* /Second/, we add to the garbage map. */
    idx = (__va - IOREMAP_VIRT_START) >> PAGE_SHIFT;
    set_bit(idx, garbage);
}
