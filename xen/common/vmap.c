#ifdef VMAP_VIRT_START
#include <xen/bitmap.h>
#include <xen/cache.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/spinlock.h>
#include <xen/types.h>
#include <xen/vmap.h>
#include <asm/page.h>

static DEFINE_SPINLOCK(vm_lock);
static void *__read_mostly vm_base;
#define vm_bitmap ((unsigned long *)vm_base)
/* highest allocated bit in the bitmap */
static unsigned int __read_mostly vm_top;
/* total number of bits in the bitmap */
static unsigned int __read_mostly vm_end;
/* lowest known clear bit in the bitmap */
static unsigned int vm_low;

void __init vm_init(void)
{
    unsigned int i, nr;
    unsigned long va;

    vm_base = (void *)VMAP_VIRT_START;
    vm_end = PFN_DOWN(arch_vmap_virt_end() - vm_base);
    vm_low = PFN_UP((vm_end + 7) / 8);
    nr = PFN_UP((vm_low + 7) / 8);
    vm_top = nr * PAGE_SIZE * 8;

    for ( i = 0, va = (unsigned long)vm_bitmap; i < nr; ++i, va += PAGE_SIZE )
    {
        struct page_info *pg = alloc_domheap_page(NULL, 0);

        map_pages_to_xen(va, page_to_mfn(pg), 1, PAGE_HYPERVISOR);
        clear_page((void *)va);
    }
    bitmap_fill(vm_bitmap, vm_low);

    /* Populate page tables for the bitmap if necessary. */
    populate_pt_range(va, 0, vm_low - nr);
}

void *vm_alloc(unsigned int nr, unsigned int align)
{
    unsigned int start, bit;

    if ( !align )
        align = 1;
    else if ( align & (align - 1) )
        align &= -align;

    spin_lock(&vm_lock);
    for ( ; ; )
    {
        struct page_info *pg;

        ASSERT(vm_low == vm_top || !test_bit(vm_low, vm_bitmap));
        for ( start = vm_low; start < vm_top; )
        {
            bit = find_next_bit(vm_bitmap, vm_top, start + 1);
            if ( bit > vm_top )
                bit = vm_top;
            /*
             * Note that this skips the first bit, making the
             * corresponding page a guard one.
             */
            start = (start + align) & ~(align - 1);
            if ( bit < vm_top )
            {
                if ( start + nr < bit )
                    break;
                start = find_next_zero_bit(vm_bitmap, vm_top, bit + 1);
            }
            else
            {
                if ( start + nr <= bit )
                    break;
                start = bit;
            }
        }

        if ( start < vm_top )
            break;

        spin_unlock(&vm_lock);

        if ( vm_top >= vm_end )
            return NULL;

        pg = alloc_domheap_page(NULL, 0);
        if ( !pg )
            return NULL;

        spin_lock(&vm_lock);

        if ( start >= vm_top )
        {
            unsigned long va = (unsigned long)vm_bitmap + vm_top / 8;

            if ( !map_pages_to_xen(va, page_to_mfn(pg), 1, PAGE_HYPERVISOR) )
            {
                clear_page((void *)va);
                vm_top += PAGE_SIZE * 8;
                if ( vm_top > vm_end )
                    vm_top = vm_end;
                continue;
            }
        }

        free_domheap_page(pg);

        if ( start >= vm_top )
        {
            spin_unlock(&vm_lock);
            return NULL;
        }
    }

    for ( bit = start; bit < start + nr; ++bit )
        __set_bit(bit, vm_bitmap);
    if ( bit < vm_top )
        ASSERT(!test_bit(bit, vm_bitmap));
    else
        ASSERT(bit == vm_top);
    if ( start <= vm_low + 2 )
        vm_low = bit;
    spin_unlock(&vm_lock);

    return vm_base + start * PAGE_SIZE;
}

static unsigned int vm_index(const void *va)
{
    unsigned long addr = (unsigned long)va & ~(PAGE_SIZE - 1);
    unsigned int idx;

    if ( addr < VMAP_VIRT_START + (vm_end / 8) ||
         addr >= VMAP_VIRT_START + vm_top * PAGE_SIZE )
        return 0;

    idx = PFN_DOWN(va - vm_base);
    return !test_bit(idx - 1, vm_bitmap) &&
           test_bit(idx, vm_bitmap) ? idx : 0;
}

static unsigned int vm_size(const void *va)
{
    unsigned int start = vm_index(va), end;

    if ( !start )
        return 0;

    end = find_next_zero_bit(vm_bitmap, vm_top, start + 1);

    return min(end, vm_top) - start;
}

void vm_free(const void *va)
{
    unsigned int bit = vm_index(va);

    if ( !bit )
    {
        WARN_ON(va != NULL);
        return;
    }

    spin_lock(&vm_lock);
    if ( bit < vm_low )
    {
        vm_low = bit - 1;
        while ( !test_bit(vm_low - 1, vm_bitmap) )
            --vm_low;
    }
    while ( __test_and_clear_bit(bit, vm_bitmap) )
        if ( ++bit == vm_top )
            break;
    spin_unlock(&vm_lock);
}

void *__vmap(const mfn_t *mfn, unsigned int granularity,
             unsigned int nr, unsigned int align, unsigned int flags)
{
    void *va = vm_alloc(nr * granularity, align);
    unsigned long cur = (unsigned long)va;

    for ( ; va && nr--; ++mfn, cur += PAGE_SIZE * granularity )
    {
        if ( map_pages_to_xen(cur, mfn_x(*mfn), granularity, flags) )
        {
            vunmap(va);
            va = NULL;
        }
    }

    return va;
}

void *vmap(const mfn_t *mfn, unsigned int nr)
{
    return __vmap(mfn, 1, nr, 1, PAGE_HYPERVISOR);
}

void vunmap(const void *va)
{
#ifndef _PAGE_NONE
    unsigned long addr = (unsigned long)va;

    destroy_xen_mappings(addr, addr + PAGE_SIZE * vm_size(va));
#else /* Avoid tearing down intermediate page tables. */
    map_pages_to_xen((unsigned long)va, 0, vm_size(va), _PAGE_NONE);
#endif
    vm_free(va);
}

void *vmalloc(size_t size)
{
    mfn_t *mfn;
    size_t pages, i;
    struct page_info *pg;
    void *va;

    ASSERT(size);

    pages = PFN_UP(size);
    mfn = xmalloc_array(mfn_t, pages);
    if ( mfn == NULL )
        return NULL;

    for ( i = 0; i < pages; i++ )
    {
        pg = alloc_domheap_page(NULL, 0);
        if ( pg == NULL )
            goto error;
        mfn[i] = _mfn(page_to_mfn(pg));
    }

    va = vmap(mfn, pages);
    if ( va == NULL )
        goto error;

    xfree(mfn);
    return va;

 error:
    while ( i-- )
        free_domheap_page(mfn_to_page(mfn_x(mfn[i])));
    xfree(mfn);
    return NULL;
}

void *vzalloc(size_t size)
{
    void *p = vmalloc(size);
    int i;

    if ( p == NULL )
        return NULL;

    for ( i = 0; i < size; i += PAGE_SIZE )
        clear_page(p + i);

    return p;
}

void vfree(void *va)
{
    unsigned int i, pages;
    struct page_info *pg;
    PAGE_LIST_HEAD(pg_list);

    if ( !va )
        return;

    pages = vm_size(va);
    ASSERT(pages);

    for ( i = 0; i < pages; i++ )
        page_list_add(vmap_to_page(va + i * PAGE_SIZE), &pg_list);

    vunmap(va);

    while ( (pg = page_list_remove_head(&pg_list)) != NULL )
        free_domheap_page(pg);
}
#endif
