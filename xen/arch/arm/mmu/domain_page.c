/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/mm.h>
#include <xen/pmap.h>
#include <xen/vmap.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

/* cpu0's domheap page tables */
static DEFINE_PAGE_TABLES(cpu0_dommap, DOMHEAP_SECOND_PAGES);

/*
 * xen_dommap == pages used by map_domain_page, these pages contain
 * the second level pagetables which map the domheap region
 * starting at DOMHEAP_VIRT_START in 2MB chunks.
 */
static DEFINE_PER_CPU(lpae_t *, xen_dommap);

/*
 * Prepare the area that will be used to map domheap pages. They are
 * mapped in 2MB chunks, so we need to allocate the page-tables up to
 * the 2nd level.
 *
 * The caller should make sure the root page-table for @cpu has been
 * allocated.
 */
bool init_domheap_mappings(unsigned int cpu)
{
    unsigned int order = get_order_from_pages(DOMHEAP_SECOND_PAGES);
    lpae_t *root = per_cpu(xen_pgtable, cpu);
    unsigned int i, first_idx;
    lpae_t *domheap;
    mfn_t mfn;

    ASSERT(root);
    ASSERT(!per_cpu(xen_dommap, cpu));

    /*
     * The domheap for cpu0 is initialized before the heap is initialized.
     * So we need to use pre-allocated pages.
     */
    if ( !cpu )
        domheap = cpu0_dommap;
    else
        domheap = alloc_xenheap_pages(order, 0);

    if ( !domheap )
        return false;

    /* Ensure the domheap has no stray mappings */
    memset(domheap, 0, DOMHEAP_SECOND_PAGES * PAGE_SIZE);

    /*
     * Update the first level mapping to reference the local CPUs
     * domheap mapping pages.
     */
    mfn = virt_to_mfn(domheap);
    first_idx = first_table_offset(DOMHEAP_VIRT_START);
    for ( i = 0; i < DOMHEAP_SECOND_PAGES; i++ )
    {
        lpae_t pte = mfn_to_xen_entry(mfn_add(mfn, i), MT_NORMAL);
        pte.pt.table = 1;
        write_pte(&root[first_idx + i], pte);
    }

    per_cpu(xen_dommap, cpu) = domheap;

    return true;
}

void *map_domain_page_global(mfn_t mfn)
{
    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *ptr)
{
    vunmap(ptr);
}

/* Map a page of domheap memory */
void *map_domain_page(mfn_t mfn)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    unsigned long slot_mfn = mfn_x(mfn) & ~XEN_PT_LPAE_ENTRY_MASK;
    vaddr_t va;
    lpae_t pte;
    int i, slot;

    local_irq_save(flags);

    /* The map is laid out as an open-addressed hash table where each
     * entry is a 2MB superpage pte.  We use the available bits of each
     * PTE as a reference count; when the refcount is zero the slot can
     * be reused. */
    for ( slot = (slot_mfn >> XEN_PT_LPAE_SHIFT) % DOMHEAP_ENTRIES, i = 0;
          i < DOMHEAP_ENTRIES;
          slot = (slot + 1) % DOMHEAP_ENTRIES, i++ )
    {
        if ( map[slot].pt.avail < 0xf &&
             map[slot].pt.base == slot_mfn &&
             map[slot].pt.valid )
        {
            /* This slot already points to the right place; reuse it */
            map[slot].pt.avail++;
            break;
        }
        else if ( map[slot].pt.avail == 0 )
        {
            /* Commandeer this 2MB slot */
            pte = mfn_to_xen_entry(_mfn(slot_mfn), MT_NORMAL);
            pte.pt.avail = 1;
            write_pte(map + slot, pte);
            break;
        }

    }
    /* If the map fills up, the callers have misbehaved. */
    BUG_ON(i == DOMHEAP_ENTRIES);

#ifndef NDEBUG
    /* Searching the hash could get slow if the map starts filling up.
     * Cross that bridge when we come to it */
    {
        static int max_tries = 32;
        if ( i >= max_tries )
        {
            dprintk(XENLOG_WARNING, "Domheap map is filling: %i tries\n", i);
            max_tries *= 2;
        }
    }
#endif

    local_irq_restore(flags);

    va = (DOMHEAP_VIRT_START
          + (slot << SECOND_SHIFT)
          + ((mfn_x(mfn) & XEN_PT_LPAE_ENTRY_MASK) << THIRD_SHIFT));

    /*
     * We may not have flushed this specific subpage at map time,
     * since we only flush the 4k page not the superpage
     */
    flush_xen_tlb_range_va_local(va, PAGE_SIZE);

    return (void *)va;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *ptr)
{
    unsigned long flags;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = ((unsigned long)ptr - DOMHEAP_VIRT_START) >> SECOND_SHIFT;

    if ( !ptr )
        return;

    local_irq_save(flags);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    map[slot].pt.avail--;

    local_irq_restore(flags);
}

mfn_t domain_page_map_to_mfn(const void *ptr)
{
    unsigned long va = (unsigned long)ptr;
    lpae_t *map = this_cpu(xen_dommap);
    int slot = (va - DOMHEAP_VIRT_START) >> SECOND_SHIFT;
    unsigned long offset = (va>>THIRD_SHIFT) & XEN_PT_LPAE_ENTRY_MASK;

    if ( (va >= VMAP_VIRT_START) && ((va - VMAP_VIRT_START) < VMAP_VIRT_SIZE) )
        return virt_to_mfn(va);

    ASSERT(slot >= 0 && slot < DOMHEAP_ENTRIES);
    ASSERT(map[slot].pt.avail != 0);

    return mfn_add(lpae_get_mfn(map[slot]), offset);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
