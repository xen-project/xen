/******************************************************************************
 * domain_page.h
 * 
 * Allow temporary mapping of domain pages.
 * 
 * Copyright (c) 2003-2006, Keir Fraser <keir@xensource.com>
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/hvm/support.h>

static inline struct vcpu *mapcache_current_vcpu(void)
{
    struct vcpu *v;

    /* In the common case we use the mapcache of the running VCPU. */
    v = current;

    /*
     * If guest_table is NULL, and we are running a paravirtualised guest,
     * then it means we are running on the idle domain's page table and must
     * therefore use its mapcache.
     */
    if ( unlikely(!pagetable_get_pfn(v->arch.guest_table)) && !is_hvm_vcpu(v) )
    {
        /* If we really are idling, perform lazy context switch now. */
        if ( (v = idle_vcpu[smp_processor_id()]) == current )
            __sync_lazy_execstate();
        /* We must now be running on the idle page table. */
        ASSERT(read_cr3() == __pa(idle_pg_table));
    }

    return v;
}

void *map_domain_page(unsigned long mfn)
{
    unsigned long va;
    unsigned int idx, i, vcpu;
    struct vcpu *v;
    struct mapcache *cache;
    struct vcpu_maphash_entry *hashent;

    ASSERT(!in_irq());

    perfc_incr(map_domain_page_count);

    v = mapcache_current_vcpu();

    vcpu  = v->vcpu_id;
    cache = &v->domain->arch.mapcache;

    hashent = &cache->vcpu_maphash[vcpu].hash[MAPHASH_HASHFN(mfn)];
    if ( hashent->mfn == mfn )
    {
        idx = hashent->idx;
        hashent->refcnt++;
        ASSERT(idx < MAPCACHE_ENTRIES);
        ASSERT(hashent->refcnt != 0);
        ASSERT(l1e_get_pfn(cache->l1tab[idx]) == mfn);
        goto out;
    }

    spin_lock(&cache->lock);

    /* Has some other CPU caused a wrap? We must flush if so. */
    if ( unlikely(cache->epoch != cache->shadow_epoch[vcpu]) )
    {
        cache->shadow_epoch[vcpu] = cache->epoch;
        if ( NEED_FLUSH(this_cpu(tlbflush_time), cache->tlbflush_timestamp) )
        {
            perfc_incr(domain_page_tlb_flush);
            local_flush_tlb();
        }
    }

    idx = find_next_zero_bit(cache->inuse, MAPCACHE_ENTRIES, cache->cursor);
    if ( unlikely(idx >= MAPCACHE_ENTRIES) )
    {
        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < ARRAY_SIZE(cache->garbage); i++ )
        {
            unsigned long x = xchg(&cache->garbage[i], 0);
            cache->inuse[i] &= ~x;
        }

        /* /Second/, flush TLBs. */
        perfc_incr(domain_page_tlb_flush);
        local_flush_tlb();
        cache->shadow_epoch[vcpu] = ++cache->epoch;
        cache->tlbflush_timestamp = tlbflush_current_time();

        idx = find_first_zero_bit(cache->inuse, MAPCACHE_ENTRIES);
        ASSERT(idx < MAPCACHE_ENTRIES);
    }

    set_bit(idx, cache->inuse);
    cache->cursor = idx + 1;

    spin_unlock(&cache->lock);

    l1e_write(&cache->l1tab[idx], l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

 out:
    va = MAPCACHE_VIRT_START + (idx << PAGE_SHIFT);
    return (void *)va;
}

void unmap_domain_page(void *va)
{
    unsigned int idx;
    struct vcpu *v;
    struct mapcache *cache;
    unsigned long mfn;
    struct vcpu_maphash_entry *hashent;

    ASSERT(!in_irq());

    ASSERT((void *)MAPCACHE_VIRT_START <= va);
    ASSERT(va < (void *)MAPCACHE_VIRT_END);

    v = mapcache_current_vcpu();

    cache = &v->domain->arch.mapcache;

    idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;
    mfn = l1e_get_pfn(cache->l1tab[idx]);
    hashent = &cache->vcpu_maphash[v->vcpu_id].hash[MAPHASH_HASHFN(mfn)];

    if ( hashent->idx == idx )
    {
        ASSERT(hashent->mfn == mfn);
        ASSERT(hashent->refcnt != 0);
        hashent->refcnt--;
    }
    else if ( hashent->refcnt == 0 )
    {
        if ( hashent->idx != MAPHASHENT_NOTINUSE )
        {
            /* /First/, zap the PTE. */
            ASSERT(l1e_get_pfn(cache->l1tab[hashent->idx]) == hashent->mfn);
            l1e_write(&cache->l1tab[hashent->idx], l1e_empty());
            /* /Second/, mark as garbage. */
            set_bit(hashent->idx, cache->garbage);
        }

        /* Add newly-freed mapping to the maphash. */
        hashent->mfn = mfn;
        hashent->idx = idx;
    }
    else
    {
        /* /First/, zap the PTE. */
        l1e_write(&cache->l1tab[idx], l1e_empty());
        /* /Second/, mark as garbage. */
        set_bit(idx, cache->garbage);
    }
}

void mapcache_init(struct domain *d)
{
    unsigned int i, j;
    struct vcpu_maphash_entry *hashent;

    d->arch.mapcache.l1tab = d->arch.mm_perdomain_pt +
        (GDT_LDT_MBYTES << (20 - PAGE_SHIFT));
    spin_lock_init(&d->arch.mapcache.lock);

    /* Mark all maphash entries as not in use. */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
    {
        for ( j = 0; j < MAPHASH_ENTRIES; j++ )
        {
            hashent = &d->arch.mapcache.vcpu_maphash[i].hash[j];
            hashent->mfn = ~0UL; /* never valid to map */
            hashent->idx = MAPHASHENT_NOTINUSE;
        }
    }
}

#define GLOBALMAP_BITS (IOREMAP_MBYTES << (20 - PAGE_SHIFT))
static unsigned long inuse[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned long garbage[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned int inuse_cursor;
static DEFINE_SPINLOCK(globalmap_lock);

void *map_domain_page_global(unsigned long mfn)
{
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int idx, i;
    unsigned long va;

    ASSERT(!in_irq() && local_irq_is_enabled());

    spin_lock(&globalmap_lock);

    idx = find_next_zero_bit(inuse, GLOBALMAP_BITS, inuse_cursor);
    va = IOREMAP_VIRT_START + (idx << PAGE_SHIFT);
    if ( unlikely(va >= FIXADDR_START) )
    {
        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < ARRAY_SIZE(garbage); i++ )
        {
            unsigned long x = xchg(&garbage[i], 0);
            inuse[i] &= ~x;
        }

        /* /Second/, flush all TLBs to get rid of stale garbage mappings. */
        flush_tlb_all();

        idx = find_first_zero_bit(inuse, GLOBALMAP_BITS);
        va = IOREMAP_VIRT_START + (idx << PAGE_SHIFT);
        ASSERT(va < FIXADDR_START);
    }

    set_bit(idx, inuse);
    inuse_cursor = idx + 1;

    spin_unlock(&globalmap_lock);

    pl2e = virt_to_xen_l2e(va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(va);
    l1e_write(pl1e, l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

    return (void *)va;
}

void unmap_domain_page_global(void *va)
{
    unsigned long __va = (unsigned long)va;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int idx;

    ASSERT(__va >= IOREMAP_VIRT_START);

    /* /First/, we zap the PTE. */
    pl2e = virt_to_xen_l2e(__va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(__va);
    l1e_write(pl1e, l1e_empty());

    /* /Second/, we add to the garbage map. */
    idx = (__va - IOREMAP_VIRT_START) >> PAGE_SHIFT;
    set_bit(idx, garbage);
}

unsigned long mfn_from_mapped_domain_page(void *va) 
{
    unsigned long __va = (unsigned long)va;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int idx;
    struct mapcache *cache;

    if ( (__va >= MAPCACHE_VIRT_START) && (__va < MAPCACHE_VIRT_END) )
    {
        cache = &mapcache_current_vcpu()->domain->arch.mapcache;
        idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;
        return l1e_get_pfn(cache->l1tab[idx]);
    }

    ASSERT(__va >= IOREMAP_VIRT_START);
    pl2e = virt_to_xen_l2e(__va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(__va);
    return l1e_get_pfn(*pl1e);
}
