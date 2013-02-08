/******************************************************************************
 * domain_page.h
 *
 * Allow temporary mapping of domain pages.
 *
 * Copyright (c) 2003-2006, Keir Fraser <keir@xensource.com>
 */

#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>

static struct vcpu *__read_mostly override;

static inline struct vcpu *mapcache_current_vcpu(void)
{
    /* In the common case we use the mapcache of the running VCPU. */
    struct vcpu *v = override ?: current;

    /*
     * When current isn't properly set up yet, this is equivalent to
     * running in an idle vCPU (callers must check for NULL).
     */
    if ( v == (struct vcpu *)0xfffff000 )
        return NULL;

    /*
     * If guest_table is NULL, and we are running a paravirtualised guest,
     * then it means we are running on the idle domain's page table and must
     * therefore use its mapcache.
     */
    if ( unlikely(pagetable_is_null(v->arch.guest_table)) && !is_hvm_vcpu(v) )
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
    override = v;
}

#define mapcache_l2_entry(e) ((e) >> PAGETABLE_ORDER)
#define MAPCACHE_L2_ENTRIES (mapcache_l2_entry(MAPCACHE_ENTRIES - 1) + 1)
#define DCACHE_L1ENT(dc, idx) \
    ((dc)->l1tab[(idx) >> PAGETABLE_ORDER] \
                [(idx) & ((1 << PAGETABLE_ORDER) - 1)])

void *map_domain_page(unsigned long mfn)
{
    unsigned long flags;
    unsigned int idx, i;
    struct vcpu *v;
    struct mapcache_domain *dcache;
    struct mapcache_vcpu *vcache;
    struct vcpu_maphash_entry *hashent;

#ifdef NDEBUG
    if ( mfn <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn);
#endif

    v = mapcache_current_vcpu();
    if ( !v || is_hvm_vcpu(v) )
        return mfn_to_virt(mfn);

    dcache = &v->domain->arch.pv_domain.mapcache;
    vcache = &v->arch.pv_vcpu.mapcache;
    if ( !dcache->l1tab )
        return mfn_to_virt(mfn);

    perfc_incr(map_domain_page_count);

    local_irq_save(flags);

    hashent = &vcache->hash[MAPHASH_HASHFN(mfn)];
    if ( hashent->mfn == mfn )
    {
        idx = hashent->idx;
        ASSERT(idx < dcache->entries);
        hashent->refcnt++;
        ASSERT(hashent->refcnt);
        ASSERT(l1e_get_pfn(DCACHE_L1ENT(dcache, idx)) == mfn);
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
        unsigned long accum = 0;

        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < BITS_TO_LONGS(dcache->entries); i++ )
        {
            dcache->inuse[i] &= ~xchg(&dcache->garbage[i], 0);
            accum |= ~dcache->inuse[i];
        }

        if ( accum )
            idx = find_first_zero_bit(dcache->inuse, dcache->entries);
        else
        {
            /* Replace a hash entry instead. */
            i = MAPHASH_HASHFN(mfn);
            do {
                hashent = &vcache->hash[i];
                if ( hashent->idx != MAPHASHENT_NOTINUSE && !hashent->refcnt )
                {
                    idx = hashent->idx;
                    ASSERT(l1e_get_pfn(DCACHE_L1ENT(dcache, idx)) ==
                           hashent->mfn);
                    l1e_write(&DCACHE_L1ENT(dcache, idx), l1e_empty());
                    hashent->idx = MAPHASHENT_NOTINUSE;
                    hashent->mfn = ~0UL;
                    break;
                }
                if ( ++i == MAPHASH_ENTRIES )
                    i = 0;
            } while ( i != MAPHASH_HASHFN(mfn) );
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

    l1e_write(&DCACHE_L1ENT(dcache, idx),
              l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

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
    ASSERT(v && !is_hvm_vcpu(v));

    dcache = &v->domain->arch.pv_domain.mapcache;
    ASSERT(dcache->l1tab);

    idx = PFN_DOWN(va - MAPCACHE_VIRT_START);
    mfn = l1e_get_pfn(DCACHE_L1ENT(dcache, idx));
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
            ASSERT(l1e_get_pfn(DCACHE_L1ENT(dcache, hashent->idx)) ==
                   hashent->mfn);
            l1e_write(&DCACHE_L1ENT(dcache, hashent->idx), l1e_empty());
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
        l1e_write(&DCACHE_L1ENT(dcache, idx), l1e_empty());
        /* /Second/, mark as garbage. */
        set_bit(idx, dcache->garbage);
    }

    local_irq_restore(flags);
}

void clear_domain_page(unsigned long mfn)
{
    void *ptr = map_domain_page(mfn);

    clear_page(ptr);
    unmap_domain_page(ptr);
}

void copy_domain_page(unsigned long dmfn, unsigned long smfn)
{
    const void *src = map_domain_page(smfn);
    void *dst = map_domain_page(dmfn);

    copy_page(dst, src);
    unmap_domain_page(dst);
    unmap_domain_page(src);
}

int mapcache_domain_init(struct domain *d)
{
    struct mapcache_domain *dcache = &d->arch.pv_domain.mapcache;
    l3_pgentry_t *l3tab;
    l2_pgentry_t *l2tab;
    unsigned int i, bitmap_pages, memf = MEMF_node(domain_to_node(d));
    unsigned long *end;

    if ( is_hvm_domain(d) || is_idle_domain(d) )
        return 0;

#ifdef NDEBUG
    if ( !mem_hotplug && max_page <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return 0;
#endif

    dcache->l1tab = xzalloc_array(l1_pgentry_t *, MAPCACHE_L2_ENTRIES + 1);
    d->arch.perdomain_l2_pg[MAPCACHE_SLOT] = alloc_domheap_page(NULL, memf);
    if ( !dcache->l1tab || !d->arch.perdomain_l2_pg[MAPCACHE_SLOT] )
        return -ENOMEM;

    clear_domain_page(page_to_mfn(d->arch.perdomain_l2_pg[MAPCACHE_SLOT]));
    l3tab = __map_domain_page(d->arch.perdomain_l3_pg);
    l3tab[l3_table_offset(MAPCACHE_VIRT_START)] =
        l3e_from_page(d->arch.perdomain_l2_pg[MAPCACHE_SLOT],
                      __PAGE_HYPERVISOR);
    unmap_domain_page(l3tab);

    l2tab = __map_domain_page(d->arch.perdomain_l2_pg[MAPCACHE_SLOT]);

    BUILD_BUG_ON(MAPCACHE_VIRT_END + 3 +
                 2 * PFN_UP(BITS_TO_LONGS(MAPCACHE_ENTRIES) * sizeof(long)) >
                 MAPCACHE_VIRT_START + (PERDOMAIN_SLOT_MBYTES << 20));
    bitmap_pages = PFN_UP(BITS_TO_LONGS(MAPCACHE_ENTRIES) * sizeof(long));
    dcache->inuse = (void *)MAPCACHE_VIRT_END + PAGE_SIZE;
    dcache->garbage = dcache->inuse +
                      (bitmap_pages + 1) * PAGE_SIZE / sizeof(long);
    end = dcache->garbage + bitmap_pages * PAGE_SIZE / sizeof(long);

    for ( i = l2_table_offset((unsigned long)dcache->inuse);
          i <= l2_table_offset((unsigned long)(end - 1)); ++i )
    {
        ASSERT(i <= MAPCACHE_L2_ENTRIES);
        dcache->l1tab[i] = alloc_xenheap_pages(0, memf);
        if ( !dcache->l1tab[i] )
        {
            unmap_domain_page(l2tab);
            return -ENOMEM;
        }
        clear_page(dcache->l1tab[i]);
        l2tab[i] = l2e_from_paddr(__pa(dcache->l1tab[i]), __PAGE_HYPERVISOR);
    }

    unmap_domain_page(l2tab);

    spin_lock_init(&dcache->lock);

    return 0;
}

void mapcache_domain_exit(struct domain *d)
{
    struct mapcache_domain *dcache = &d->arch.pv_domain.mapcache;

    if ( is_hvm_domain(d) )
        return;

    if ( dcache->l1tab )
    {
        unsigned long i;

        for ( i = (unsigned long)dcache->inuse; ; i += PAGE_SIZE )
        {
            l1_pgentry_t *pl1e;

            if ( l2_table_offset(i) > MAPCACHE_L2_ENTRIES ||
                 !dcache->l1tab[l2_table_offset(i)] )
                break;

            pl1e = &dcache->l1tab[l2_table_offset(i)][l1_table_offset(i)];
            if ( l1e_get_flags(*pl1e) )
                free_domheap_page(l1e_get_page(*pl1e));
        }

        for ( i = 0; i < MAPCACHE_L2_ENTRIES + 1; ++i )
            free_xenheap_page(dcache->l1tab[i]);

        xfree(dcache->l1tab);
    }
}

int mapcache_vcpu_init(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct mapcache_domain *dcache = &d->arch.pv_domain.mapcache;
    l2_pgentry_t *l2tab;
    unsigned long i;
    unsigned int memf = MEMF_node(vcpu_to_node(v));

    if ( is_hvm_vcpu(v) || !dcache->l1tab )
        return 0;

    l2tab = __map_domain_page(d->arch.perdomain_l2_pg[MAPCACHE_SLOT]);

    while ( dcache->entries < d->max_vcpus * MAPCACHE_VCPU_ENTRIES )
    {
        unsigned int ents = dcache->entries + MAPCACHE_VCPU_ENTRIES;
        l1_pgentry_t *pl1e;

        /* Populate page tables. */
        if ( !dcache->l1tab[i = mapcache_l2_entry(ents - 1)] )
        {
            dcache->l1tab[i] = alloc_xenheap_pages(0, memf);
            if ( !dcache->l1tab[i] )
            {
                unmap_domain_page(l2tab);
                return -ENOMEM;
            }
            clear_page(dcache->l1tab[i]);
            l2tab[i] = l2e_from_paddr(__pa(dcache->l1tab[i]),
                                      __PAGE_HYPERVISOR);
        }

        /* Populate bit maps. */
        i = (unsigned long)(dcache->inuse + BITS_TO_LONGS(ents));
        pl1e = &dcache->l1tab[l2_table_offset(i)][l1_table_offset(i)];
        if ( !l1e_get_flags(*pl1e) )
        {
            struct page_info *pg = alloc_domheap_page(NULL, memf);

            if ( pg )
            {
                clear_domain_page(page_to_mfn(pg));
                *pl1e = l1e_from_page(pg, __PAGE_HYPERVISOR);
                pg = alloc_domheap_page(NULL, memf);
            }
            if ( !pg )
            {
                unmap_domain_page(l2tab);
                return -ENOMEM;
            }

            i = (unsigned long)(dcache->garbage + BITS_TO_LONGS(ents));
            pl1e = &dcache->l1tab[l2_table_offset(i)][l1_table_offset(i)];
            ASSERT(!l1e_get_flags(*pl1e));

            clear_domain_page(page_to_mfn(pg));
            *pl1e = l1e_from_page(pg, __PAGE_HYPERVISOR);
        }

        dcache->entries = ents;
    }

    unmap_domain_page(l2tab);

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

#define GLOBALMAP_BITS (GLOBALMAP_GBYTES << (30 - PAGE_SHIFT))
static unsigned long inuse[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned long garbage[BITS_TO_LONGS(GLOBALMAP_BITS)];
static unsigned int inuse_cursor;
static DEFINE_SPINLOCK(globalmap_lock);

void *map_domain_page_global(unsigned long mfn)
{
    l1_pgentry_t *pl1e;
    unsigned int idx, i;
    unsigned long va;

    ASSERT(!in_irq() && local_irq_is_enabled());

#ifdef NDEBUG
    if ( mfn <= PFN_DOWN(__pa(HYPERVISOR_VIRT_END - 1)) )
        return mfn_to_virt(mfn);
#endif

    spin_lock(&globalmap_lock);

    idx = find_next_zero_bit(inuse, GLOBALMAP_BITS, inuse_cursor);
    va = GLOBALMAP_VIRT_START + pfn_to_paddr(idx);
    if ( unlikely(va >= GLOBALMAP_VIRT_END) )
    {
        /* /First/, clean the garbage map and update the inuse list. */
        for ( i = 0; i < ARRAY_SIZE(garbage); i++ )
            inuse[i] &= ~xchg(&garbage[i], 0);

        /* /Second/, flush all TLBs to get rid of stale garbage mappings. */
        flush_tlb_all();

        idx = find_first_zero_bit(inuse, GLOBALMAP_BITS);
        va = GLOBALMAP_VIRT_START + pfn_to_paddr(idx);
        if ( unlikely(va >= GLOBALMAP_VIRT_END) )
        {
            spin_unlock(&globalmap_lock);
            return NULL;
        }
    }

    set_bit(idx, inuse);
    inuse_cursor = idx + 1;

    spin_unlock(&globalmap_lock);

    pl1e = virt_to_xen_l1e(va);
    if ( !pl1e )
        return NULL;
    l1e_write(pl1e, l1e_from_pfn(mfn, __PAGE_HYPERVISOR));

    return (void *)va;
}

void unmap_domain_page_global(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    l1_pgentry_t *pl1e;

    if ( va >= DIRECTMAP_VIRT_START )
        return;

    ASSERT(va >= GLOBALMAP_VIRT_START && va < GLOBALMAP_VIRT_END);

    /* /First/, we zap the PTE. */
    pl1e = virt_to_xen_l1e(va);
    BUG_ON(!pl1e);
    l1e_write(pl1e, l1e_empty());

    /* /Second/, we add to the garbage map. */
    set_bit(PFN_DOWN(va - GLOBALMAP_VIRT_START), garbage);
}

/* Translate a map-domain-page'd address to the underlying MFN */
unsigned long domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    const l1_pgentry_t *pl1e;

    if ( va >= DIRECTMAP_VIRT_START )
        return virt_to_mfn(ptr);

    if ( va >= GLOBALMAP_VIRT_START && va < GLOBALMAP_VIRT_END )
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
