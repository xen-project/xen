/******************************************************************************
 * domain_page.h
 *
 * Allow temporary mapping of domain pages.
 *
 * Copyright (c) 2003-2006, Keir Fraser <keir@xensource.com>
 */

#include <xen/domain_page.h>
#include <xen/efi.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/setup.h>

static DEFINE_PER_CPU(struct vcpu *, override);

static inline struct vcpu *mapcache_current_vcpu(void)
{
    /* In the common case we use the mapcache of the running VCPU. */
    struct vcpu *v = this_cpu(override) ?: current;

    /*
     * When current isn't properly set up yet, this is equivalent to
     * running in an idle vCPU (callers must check for NULL).
     */
    if ( v == INVALID_VCPU )
        return NULL;

    /*
     * When using efi runtime page tables, we have the equivalent of the idle
     * domain's page tables but current may point at another domain's VCPU.
     * Return NULL as though current is not properly set up yet.
     */
    if ( efi_rs_using_pgtables() )
        return NULL;

    /*
     * If guest_table is NULL, and we are running a paravirtualised guest,
     * then it means we are running on the idle domain's page table and must
     * therefore use its mapcache.
     */
    if ( unlikely(pagetable_is_null(v->arch.guest_table)) && is_pv_vcpu(v) )
    {
        /* If we really are idling, perform lazy context switch now. */
        if ( (v = idle_vcpu[smp_processor_id()]) == current )
            sync_local_execstate();
        /* We must now be running on the idle page table. */
        ASSERT(read_cr3() == __pa(idle_pg_table));
    }

    return v;
}

void __init mapcache_override_current(struct vcpu *v)
{
    this_cpu(override) = v;
}

#define mapcache_l2_entry(e) ((e) >> PAGETABLE_ORDER)
#define MAPCACHE_L2_ENTRIES (mapcache_l2_entry(MAPCACHE_ENTRIES - 1) + 1)
#define MAPCACHE_L1ENT(idx) \
    __linear_l1_table[l1_linear_offset(MAPCACHE_VIRT_START + pfn_to_paddr(idx))]

void *map_domain_page(mfn_t mfn)
{
    unsigned long flags;
    unsigned int idx, i;
    struct vcpu *v;
    struct mapcache_domain *dcache;
    struct mapcache_vcpu *vcache;
    struct vcpu_maphash_entry *hashent;

#ifdef NDEBUG
    if ( mfn_x(mfn) <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn_x(mfn));
#endif

    v = mapcache_current_vcpu();
    if ( !v || !is_pv_vcpu(v) )
        return mfn_to_virt(mfn_x(mfn));

    dcache = &v->domain->arch.pv_domain.mapcache;
    vcache = &v->arch.pv_vcpu.mapcache;
    if ( !dcache->inuse )
        return mfn_to_virt(mfn_x(mfn));

    perfc_incr(map_domain_page_count);

    local_irq_save(flags);

    hashent = &vcache->hash[MAPHASH_HASHFN(mfn_x(mfn))];
    if ( hashent->mfn == mfn_x(mfn) )
    {
        idx = hashent->idx;
        ASSERT(idx < dcache->entries);
        hashent->refcnt++;
        ASSERT(hashent->refcnt);
        ASSERT(l1e_get_pfn(MAPCACHE_L1ENT(idx)) == mfn_x(mfn));
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

    idx = find_next_zero_bit(dcache->inuse, dcache->entries, dcache->cursor);
    if ( unlikely(idx >= dcache->entries) )
    {
        unsigned long accum = 0, prev = 0;

        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < BITS_TO_LONGS(dcache->entries); i++ )
        {
            accum |= prev;
            dcache->inuse[i] &= ~xchg(&dcache->garbage[i], 0);
            prev = ~dcache->inuse[i];
        }

        if ( accum | (prev & BITMAP_LAST_WORD_MASK(dcache->entries)) )
            idx = find_first_zero_bit(dcache->inuse, dcache->entries);
        else
        {
            /* Replace a hash entry instead. */
            i = MAPHASH_HASHFN(mfn_x(mfn));
            do {
                hashent = &vcache->hash[i];
                if ( hashent->idx != MAPHASHENT_NOTINUSE && !hashent->refcnt )
                {
                    idx = hashent->idx;
                    ASSERT(l1e_get_pfn(MAPCACHE_L1ENT(idx)) == hashent->mfn);
                    l1e_write(&MAPCACHE_L1ENT(idx), l1e_empty());
                    hashent->idx = MAPHASHENT_NOTINUSE;
                    hashent->mfn = ~0UL;
                    break;
                }
                if ( ++i == MAPHASH_ENTRIES )
                    i = 0;
            } while ( i != MAPHASH_HASHFN(mfn_x(mfn)) );
        }
        BUG_ON(idx >= dcache->entries);

        /* /Second/, flush TLBs. */
        perfc_incr(domain_page_tlb_flush);
        flush_tlb_local();
        vcache->shadow_epoch = ++dcache->epoch;
        dcache->tlbflush_timestamp = tlbflush_current_time();
    }

    set_bit(idx, dcache->inuse);
    dcache->cursor = idx + 1;

    spin_unlock(&dcache->lock);

    l1e_write(&MAPCACHE_L1ENT(idx), l1e_from_mfn(mfn, __PAGE_HYPERVISOR_RW));

 out:
    local_irq_restore(flags);
    return (void *)MAPCACHE_VIRT_START + pfn_to_paddr(idx);
}

void unmap_domain_page(const void *ptr)
{
    unsigned int idx;
    struct vcpu *v;
    struct mapcache_domain *dcache;
    unsigned long va = (unsigned long)ptr, mfn, flags;
    struct vcpu_maphash_entry *hashent;

    if ( va >= DIRECTMAP_VIRT_START )
        return;

    ASSERT(va >= MAPCACHE_VIRT_START && va < MAPCACHE_VIRT_END);

    v = mapcache_current_vcpu();
    ASSERT(v && is_pv_vcpu(v));

    dcache = &v->domain->arch.pv_domain.mapcache;
    ASSERT(dcache->inuse);

    idx = PFN_DOWN(va - MAPCACHE_VIRT_START);
    mfn = l1e_get_pfn(MAPCACHE_L1ENT(idx));
    hashent = &v->arch.pv_vcpu.mapcache.hash[MAPHASH_HASHFN(mfn)];

    local_irq_save(flags);

    if ( hashent->idx == idx )
    {
        ASSERT(hashent->mfn == mfn);
        ASSERT(hashent->refcnt);
        hashent->refcnt--;
    }
    else if ( !hashent->refcnt )
    {
        if ( hashent->idx != MAPHASHENT_NOTINUSE )
        {
            /* /First/, zap the PTE. */
            ASSERT(l1e_get_pfn(MAPCACHE_L1ENT(hashent->idx)) ==
                   hashent->mfn);
            l1e_write(&MAPCACHE_L1ENT(hashent->idx), l1e_empty());
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
        l1e_write(&MAPCACHE_L1ENT(idx), l1e_empty());
        /* /Second/, mark as garbage. */
        set_bit(idx, dcache->garbage);
    }

    local_irq_restore(flags);
}

int mapcache_domain_init(struct domain *d)
{
    struct mapcache_domain *dcache = &d->arch.pv_domain.mapcache;
    unsigned int bitmap_pages;

    ASSERT(is_pv_domain(d));

#ifdef NDEBUG
    if ( !mem_hotplug && max_page <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return 0;
#endif

    BUILD_BUG_ON(MAPCACHE_VIRT_END + PAGE_SIZE * (3 +
                 2 * PFN_UP(BITS_TO_LONGS(MAPCACHE_ENTRIES) * sizeof(long))) >
                 MAPCACHE_VIRT_START + (PERDOMAIN_SLOT_MBYTES << 20));
    bitmap_pages = PFN_UP(BITS_TO_LONGS(MAPCACHE_ENTRIES) * sizeof(long));
    dcache->inuse = (void *)MAPCACHE_VIRT_END + PAGE_SIZE;
    dcache->garbage = dcache->inuse +
                      (bitmap_pages + 1) * PAGE_SIZE / sizeof(long);

    spin_lock_init(&dcache->lock);

    return create_perdomain_mapping(d, (unsigned long)dcache->inuse,
                                    2 * bitmap_pages + 1,
                                    NIL(l1_pgentry_t *), NULL);
}

int mapcache_vcpu_init(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct mapcache_domain *dcache = &d->arch.pv_domain.mapcache;
    unsigned long i;
    unsigned int ents = d->max_vcpus * MAPCACHE_VCPU_ENTRIES;
    unsigned int nr = PFN_UP(BITS_TO_LONGS(ents) * sizeof(long));

    if ( !is_pv_vcpu(v) || !dcache->inuse )
        return 0;

    if ( ents > dcache->entries )
    {
        /* Populate page tables. */
        int rc = create_perdomain_mapping(d, MAPCACHE_VIRT_START, ents,
                                          NIL(l1_pgentry_t *), NULL);

        /* Populate bit maps. */
        if ( !rc )
            rc = create_perdomain_mapping(d, (unsigned long)dcache->inuse,
                                          nr, NULL, NIL(struct page_info *));
        if ( !rc )
            rc = create_perdomain_mapping(d, (unsigned long)dcache->garbage,
                                          nr, NULL, NIL(struct page_info *));

        if ( rc )
            return rc;

        dcache->entries = ents;
    }

    /* Mark all maphash entries as not in use. */
    BUILD_BUG_ON(MAPHASHENT_NOTINUSE < MAPCACHE_ENTRIES);
    for ( i = 0; i < MAPHASH_ENTRIES; i++ )
    {
        struct vcpu_maphash_entry *hashent = &v->arch.pv_vcpu.mapcache.hash[i];

        hashent->mfn = ~0UL; /* never valid to map */
        hashent->idx = MAPHASHENT_NOTINUSE;
    }

    return 0;
}

void *map_domain_page_global(mfn_t mfn)
{
    ASSERT(!in_irq() &&
           ((system_state >= SYS_STATE_boot &&
             system_state < SYS_STATE_active) ||
            local_irq_is_enabled()));

#ifdef NDEBUG
    if ( mfn_x(mfn) <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn_x(mfn));
#endif

    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;

    if ( va >= DIRECTMAP_VIRT_START )
        return;

    ASSERT(va >= VMAP_VIRT_START && va < VMAP_VIRT_END);

    vunmap(ptr);
}

/* Translate a map-domain-page'd address to the underlying MFN */
unsigned long domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    const l1_pgentry_t *pl1e;

    if ( va >= DIRECTMAP_VIRT_START )
        return virt_to_mfn(ptr);

    if ( va >= VMAP_VIRT_START && va < VMAP_VIRT_END )
    {
        pl1e = virt_to_xen_l1e(va);
        BUG_ON(!pl1e);
    }
    else
    {
        ASSERT(va >= MAPCACHE_VIRT_START && va < MAPCACHE_VIRT_END);
        pl1e = &__linear_l1_table[l1_linear_offset(va)];
    }

    return l1e_get_pfn(*pl1e);
}
