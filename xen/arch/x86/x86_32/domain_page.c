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
#include <asm/fixmap.h>

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
            sync_local_execstate();
        /* We must now be running on the idle page table. */
        ASSERT(read_cr3() == __pa(idle_pg_table));
    }

    return v;
}

void *map_domain_page(unsigned long mfn)
{
    unsigned long va, flags;
    unsigned int idx, i;
    struct vcpu *v;
    struct mapcache_domain *dcache;
    struct mapcache_vcpu *vcache;
    struct vcpu_maphash_entry *hashent;

    perfc_incr(map_domain_page_count);

    v = mapcache_current_vcpu();
    /* Prevent vcpu pointer being used before initialize. */
    ASSERT((unsigned long)v != 0xfffff000);

    dcache = &v->domain->arch.mapcache;
    vcache = &v->arch.mapcache;

    local_irq_save(flags);

    hashent = &vcache->hash[MAPHASH_HASHFN(mfn)];
    if ( hashent->mfn == mfn )
    {
        idx = hashent->idx;
        hashent->refcnt++;
        ASSERT(idx < MAPCACHE_ENTRIES);
        ASSERT(hashent->refcnt != 0);
        ASSERT(l1e_get_pfn(dcache->l1tab[idx]) == mfn);
        goto out;
    }

    spin_lock(&dcache->lock);

    /* Has some other CPU caused a wrap? We must flush if so. */
    if ( unlikely(dcache->epoch != vcache->shadow_epoch) )
    {
        vcache->shadow_epoch = dcache->epoch;
        if ( NEED_FLUSH(this_cpu(tlbflush_time), dcache->tlbflush_timestamp) )
        {
            perfc_incr(domain_page_tlb_flush);
            flush_tlb_local();
        }
    }

    idx = find_next_zero_bit(dcache->inuse, MAPCACHE_ENTRIES, dcache->cursor);
    if ( unlikely(idx >= MAPCACHE_ENTRIES) )
    {
        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < ARRAY_SIZE(dcache->garbage); i++ )
        {
            unsigned long x = xchg(&dcache->garbage[i], 0);
            dcache->inuse[i] &= ~x;
        }

        /* /Second/, flush TLBs. */
        perfc_incr(domain_page_tlb_flush);
        flush_tlb_local();
        vcache->shadow_epoch = ++dcache->epoch;
        dcache->tlbflush_timestamp = tlbflush_current_time();

        idx = find_first_zero_bit(dcache->inuse, MAPCACHE_ENTRIES);
        BUG_ON(idx >= MAPCACHE_ENTRIES);
    }

    set_bit(idx, dcache->inuse);
    dcache->cursor = idx + 1;

    spin_unlock(&dcache->lock);

    l1e_write(&dcache->l1tab[idx], l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

 out:
    local_irq_restore(flags);
    va = MAPCACHE_VIRT_START + (idx << PAGE_SHIFT);
    return (void *)va;
}

void unmap_domain_page(const void *va)
{
    unsigned int idx;
    struct vcpu *v;
    struct mapcache_domain *dcache;
    unsigned long mfn, flags;
    struct vcpu_maphash_entry *hashent;

    ASSERT((void *)MAPCACHE_VIRT_START <= va);
    ASSERT(va < (void *)MAPCACHE_VIRT_END);

    v = mapcache_current_vcpu();

    dcache = &v->domain->arch.mapcache;

    idx = ((unsigned long)va - MAPCACHE_VIRT_START) >> PAGE_SHIFT;
    mfn = l1e_get_pfn(dcache->l1tab[idx]);
    hashent = &v->arch.mapcache.hash[MAPHASH_HASHFN(mfn)];

    local_irq_save(flags);

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
            ASSERT(l1e_get_pfn(dcache->l1tab[hashent->idx]) == hashent->mfn);
            l1e_write(&dcache->l1tab[hashent->idx], l1e_empty());
            /* /Second/, mark as garbage. */
            set_bit(hashent->idx, dcache->garbage);
        }

        /* Add newly-freed mapping to the maphash. */
        hashent->mfn = mfn;
        hashent->idx = idx;
    }
    else
    {
        /* /First/, zap the PTE. */
        l1e_write(&dcache->l1tab[idx], l1e_empty());
        /* /Second/, mark as garbage. */
        set_bit(idx, dcache->garbage);
    }

    local_irq_restore(flags);
}

void mapcache_domain_init(struct domain *d)
{
    d->arch.mapcache.l1tab = d->arch.mm_perdomain_pt +
        (GDT_LDT_MBYTES << (20 - PAGE_SHIFT));
    spin_lock_init(&d->arch.mapcache.lock);
}

void mapcache_vcpu_init(struct vcpu *v)
{
    unsigned int i;
    struct vcpu_maphash_entry *hashent;

    /* Mark all maphash entries as not in use. */
    for ( i = 0; i < MAPHASH_ENTRIES; i++ )
    {
        hashent = &v->arch.mapcache.hash[i];
        hashent->mfn = ~0UL; /* never valid to map */
        hashent->idx = MAPHASHENT_NOTINUSE;
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

    /* At least half the ioremap space should be available to us. */
    BUILD_BUG_ON(IOREMAP_VIRT_START + (IOREMAP_MBYTES << 19) >= FIXADDR_START);

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
        if ( unlikely(va >= FIXADDR_START) )
        {
            spin_unlock(&globalmap_lock);
            return NULL;
        }
    }

    set_bit(idx, inuse);
    inuse_cursor = idx + 1;

    spin_unlock(&globalmap_lock);

    pl2e = virt_to_xen_l2e(va);
    pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(va);
    l1e_write(pl1e, l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

    return (void *)va;
}

void unmap_domain_page_global(const void *va)
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

/* Translate a map-domain-page'd address to the underlying MFN */
unsigned long domain_page_map_to_mfn(void *va)
{
    l1_pgentry_t *l1e;

    ASSERT( (((unsigned long) va) >= MAPCACHE_VIRT_START) &&
            (((unsigned long) va) <= MAPCACHE_VIRT_END) );
    l1e = &__linear_l1_table[
            l1_linear_offset((unsigned long) va)];
    return l1e_get_pfn(*l1e);
}
