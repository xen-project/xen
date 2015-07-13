/*
 * Kexec Image
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * Derived from kernel/kexec.c from Linux:
 *
 *   Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>
#include <xen/mm.h>
#include <xen/kexec.h>
#include <xen/kimage.h>

#include <asm/page.h>

/*
 * When kexec transitions to the new kernel there is a one-to-one
 * mapping between physical and virtual addresses.  On processors
 * where you can disable the MMU this is trivial, and easy.  For
 * others it is still a simple predictable page table to setup.
 *
 * The code for the transition from the current kernel to the the new
 * kernel is placed in the page-size control_code_buffer.  This memory
 * must be identity mapped in the transition from virtual to physical
 * addresses.
 *
 * The assembly stub in the control code buffer is passed a linked list
 * of descriptor pages detailing the source pages of the new kernel,
 * and the destination addresses of those source pages.  As this data
 * structure is not used in the context of the current OS, it must
 * be self-contained.
 *
 * The code has been made to work with highmem pages and will use a
 * destination page in its final resting place (if it happens
 * to allocate it).  The end product of this is that most of the
 * physical address space, and most of RAM can be used.
 *
 * Future directions include:
 *  - allocating a page table with the control code buffer identity
 *    mapped, to simplify machine_kexec and make kexec_on_panic more
 *    reliable.
 */

/*
 * KIMAGE_NO_DEST is an impossible destination address..., for
 * allocating pages whose destination address we do not care about.
 */
#define KIMAGE_NO_DEST (-1UL)

/*
 * Offset of the last entry in an indirection page.
 */
#define KIMAGE_LAST_ENTRY (PAGE_SIZE/sizeof(kimage_entry_t) - 1)


static int kimage_is_destination_range(struct kexec_image *image,
                                       paddr_t start, paddr_t end);
static struct page_info *kimage_alloc_page(struct kexec_image *image,
                                           paddr_t dest);

static struct page_info *kimage_alloc_zeroed_page(unsigned memflags)
{
    struct page_info *page;

    page = alloc_domheap_page(NULL, memflags);
    if ( !page )
        return NULL;

    clear_domain_page(_mfn(page_to_mfn(page)));

    return page;
}

static int do_kimage_alloc(struct kexec_image **rimage, paddr_t entry,
                           unsigned long nr_segments,
                           xen_kexec_segment_t *segments, uint8_t type)
{
    struct kexec_image *image;
    unsigned long i;
    int result;

    /* Allocate a controlling structure */
    result = -ENOMEM;
    image = xzalloc(typeof(*image));
    if ( !image )
        goto out;

    image->entry_maddr = entry;
    image->type = type;
    image->nr_segments = nr_segments;
    image->segments = segments;

    image->next_crash_page = kexec_crash_area.start;

    INIT_PAGE_LIST_HEAD(&image->control_pages);
    INIT_PAGE_LIST_HEAD(&image->dest_pages);
    INIT_PAGE_LIST_HEAD(&image->unusable_pages);

    /*
     * Verify we have good destination addresses.  The caller is
     * responsible for making certain we don't attempt to load the new
     * image into invalid or reserved areas of RAM.  This just
     * verifies it is an address we can use.
     *
     * Since the kernel does everything in page size chunks ensure the
     * destination addresses are page aligned.  Too many special cases
     * crop of when we don't do this.  The most insidious is getting
     * overlapping destination addresses simply because addresses are
     * changed to page size granularity.
     */
    result = -EADDRNOTAVAIL;
    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mstart, mend;

        mstart = image->segments[i].dest_maddr;
        mend   = mstart + image->segments[i].dest_size;
        if ( (mstart & ~PAGE_MASK) || (mend & ~PAGE_MASK) )
            goto out;
    }

    /*
     * Verify our destination addresses do not overlap.  If we allowed
     * overlapping destination addresses through very weird things can
     * happen with no easy explanation as one segment stops on
     * another.
     */
    result = -EINVAL;
    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mstart, mend;
        unsigned long j;

        mstart = image->segments[i].dest_maddr;
        mend   = mstart + image->segments[i].dest_size;
        for (j = 0; j < i; j++ )
        {
            paddr_t pstart, pend;
            pstart = image->segments[j].dest_maddr;
            pend   = pstart + image->segments[j].dest_size;
            /* Do the segments overlap? */
            if ( (mend > pstart) && (mstart < pend) )
                goto out;
        }
    }

    /*
     * Ensure our buffer sizes are strictly less than our memory
     * sizes.  This should always be the case, and it is easier to
     * check up front than to be surprised later on.
     */
    result = -EINVAL;
    for ( i = 0; i < nr_segments; i++ )
    {
        if ( image->segments[i].buf_size > image->segments[i].dest_size )
            goto out;
    }

    /* 
     * Page for the relocation code must still be accessible after the
     * processor has switched to 32-bit mode.
     */
    result = -ENOMEM;
    image->control_code_page = kimage_alloc_control_page(image, MEMF_bits(32));
    if ( !image->control_code_page )
        goto out;
    result = machine_kexec_add_page(image,
                                    page_to_maddr(image->control_code_page),
                                    page_to_maddr(image->control_code_page));
    if ( result < 0 )
        goto out;

    /* Add an empty indirection page. */
    result = -ENOMEM;
    image->entry_page = kimage_alloc_control_page(image, 0);
    if ( !image->entry_page )
        goto out;
    result = machine_kexec_add_page(image, page_to_maddr(image->entry_page),
                                    page_to_maddr(image->entry_page));
    if ( result < 0 )
        goto out;

    image->head = page_to_maddr(image->entry_page);

    result = 0;
out:
    if ( result == 0 )
        *rimage = image;
    else if ( image )
    {
        image->segments = NULL; /* caller frees segments after an error */
        kimage_free(image);
    }

    return result;

}

static int kimage_normal_alloc(struct kexec_image **rimage, paddr_t entry,
                               unsigned long nr_segments,
                               xen_kexec_segment_t *segments)
{
    return do_kimage_alloc(rimage, entry, nr_segments, segments,
                           KEXEC_TYPE_DEFAULT);
}

static int kimage_crash_alloc(struct kexec_image **rimage, paddr_t entry,
                              unsigned long nr_segments,
                              xen_kexec_segment_t *segments)
{
    unsigned long i;

    /* Verify we have a valid entry point */
    if ( (entry < kexec_crash_area.start)
         || (entry > kexec_crash_area.start + kexec_crash_area.size))
        return -EADDRNOTAVAIL;

    /*
     * Verify we have good destination addresses.  Normally
     * the caller is responsible for making certain we don't
     * attempt to load the new image into invalid or reserved
     * areas of RAM.  But crash kernels are preloaded into a
     * reserved area of ram.  We must ensure the addresses
     * are in the reserved area otherwise preloading the
     * kernel could corrupt things.
     */
    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mstart, mend;

        if ( guest_handle_is_null(segments[i].buf.h) )
            continue;

        mstart = segments[i].dest_maddr;
        mend = mstart + segments[i].dest_size;
        /* Ensure we are within the crash kernel limits. */
        if ( (mstart < kexec_crash_area.start )
             || (mend > kexec_crash_area.start + kexec_crash_area.size))
            return -EADDRNOTAVAIL;
    }

    /* Allocate and initialize a controlling structure. */
    return do_kimage_alloc(rimage, entry, nr_segments, segments,
                           KEXEC_TYPE_CRASH);
}

static int kimage_is_destination_range(struct kexec_image *image,
                                       paddr_t start,
                                       paddr_t end)
{
    unsigned long i;

    for ( i = 0; i < image->nr_segments; i++ )
    {
        paddr_t mstart, mend;

        mstart = image->segments[i].dest_maddr;
        mend = mstart + image->segments[i].dest_size;
        if ( (end > mstart) && (start < mend) )
            return 1;
    }

    return 0;
}

static void kimage_free_page_list(struct page_list_head *list)
{
    struct page_info *page, *next;

    page_list_for_each_safe(page, next, list)
    {
        page_list_del(page, list);
        free_domheap_page(page);
    }
}

static struct page_info *kimage_alloc_normal_control_page(
    struct kexec_image *image, unsigned memflags)
{
    /*
     * Control pages are special, they are the intermediaries that are
     * needed while we copy the rest of the pages to their final
     * resting place.  As such they must not conflict with either the
     * destination addresses or memory the kernel is already using.
     *
     * The only case where we really need more than one of these are
     * for architectures where we cannot disable the MMU and must
     * instead generate an identity mapped page table for all of the
     * memory.
     *
     * At worst this runs in O(N) of the image size.
     */
    struct page_list_head extra_pages;
    struct page_info *page = NULL;

    INIT_PAGE_LIST_HEAD(&extra_pages);

    /*
     * Loop while I can allocate a page and the page allocated is a
     * destination page.
     */
    do {
        unsigned long mfn, emfn;
        paddr_t addr, eaddr;

        page = kimage_alloc_zeroed_page(memflags);
        if ( !page )
            break;
        mfn   = page_to_mfn(page);
        emfn  = mfn + 1;
        addr  = page_to_maddr(page);
        eaddr = addr + PAGE_SIZE;
        if ( kimage_is_destination_range(image, addr, eaddr) )
        {
            page_list_add(page, &extra_pages);
            page = NULL;
        }
    } while ( !page );

    if ( page )
    {
        /* Remember the allocated page... */
        page_list_add(page, &image->control_pages);

        /*
         * Because the page is already in it's destination location we
         * will never allocate another page at that address.
         * Therefore kimage_alloc_page will not return it (again) and
         * we don't need to give it an entry in image->segments[].
         */
    }
    /*
     * Deal with the destination pages I have inadvertently allocated.
     *
     * Ideally I would convert multi-page allocations into single page
     * allocations, and add everything to image->dest_pages.
     *
     * For now it is simpler to just free the pages.
     */
    kimage_free_page_list(&extra_pages);

    return page;
}

static struct page_info *kimage_alloc_crash_control_page(struct kexec_image *image)
{
    /*
     * Control pages are special, they are the intermediaries that are
     * needed while we copy the rest of the pages to their final
     * resting place.  As such they must not conflict with either the
     * destination addresses or memory the kernel is already using.
     *
     * Control pages are also the only pags we must allocate when
     * loading a crash kernel.  All of the other pages are specified
     * by the segments and we just memcpy into them directly.
     *
     * The only case where we really need more than one of these are
     * for architectures where we cannot disable the MMU and must
     * instead generate an identity mapped page table for all of the
     * memory.
     *
     * Given the low demand this implements a very simple allocator
     * that finds the first hole of the appropriate size in the
     * reserved memory region, and allocates all of the memory up to
     * and including the hole.
     */
    paddr_t hole_start, hole_end;
    struct page_info *page = NULL;

    hole_start = PAGE_ALIGN(image->next_crash_page);
    hole_end   = hole_start + PAGE_SIZE;
    while ( hole_end <= kexec_crash_area.start + kexec_crash_area.size )
    {
        unsigned long i;

        /* See if I overlap any of the segments. */
        for ( i = 0; i < image->nr_segments; i++ )
        {
            paddr_t mstart, mend;

            mstart = image->segments[i].dest_maddr;
            mend   = mstart + image->segments[i].dest_size;
            if ( (hole_end > mstart) && (hole_start < mend) )
            {
                /* Advance the hole to the end of the segment. */
                hole_start = PAGE_ALIGN(mend);
                hole_end   = hole_start + PAGE_SIZE;
                break;
            }
        }
        /* If I don't overlap any segments I have found my hole! */
        if ( i == image->nr_segments )
        {
            page = maddr_to_page(hole_start);
            break;
        }
    }
    if ( page )
    {
        image->next_crash_page = hole_end;
        clear_domain_page(_mfn(page_to_mfn(page)));
    }

    return page;
}


struct page_info *kimage_alloc_control_page(struct kexec_image *image,
                                            unsigned memflags)
{
    struct page_info *pages = NULL;

    switch ( image->type )
    {
    case KEXEC_TYPE_DEFAULT:
        pages = kimage_alloc_normal_control_page(image, memflags);
        break;
    case KEXEC_TYPE_CRASH:
        pages = kimage_alloc_crash_control_page(image);
        break;
    }
    return pages;
}

static int kimage_add_entry(struct kexec_image *image, kimage_entry_t entry)
{
    kimage_entry_t *entries;

    if ( image->next_entry == KIMAGE_LAST_ENTRY )
    {
        struct page_info *page;

        page = kimage_alloc_page(image, KIMAGE_NO_DEST);
        if ( !page )
            return -ENOMEM;

        entries = __map_domain_page(image->entry_page);
        entries[image->next_entry] = page_to_maddr(page) | IND_INDIRECTION;
        unmap_domain_page(entries);

        image->entry_page = page;
        image->next_entry = 0;
    }

    entries = __map_domain_page(image->entry_page);
    entries[image->next_entry] = entry;
    image->next_entry++;
    unmap_domain_page(entries);

    return 0;
}

static int kimage_set_destination(struct kexec_image *image,
                                  paddr_t destination)
{
    return kimage_add_entry(image, (destination & PAGE_MASK) | IND_DESTINATION);
}


static int kimage_add_page(struct kexec_image *image, paddr_t maddr)
{
    return kimage_add_entry(image, (maddr & PAGE_MASK) | IND_SOURCE);
}


static void kimage_free_extra_pages(struct kexec_image *image)
{
    kimage_free_page_list(&image->dest_pages);
    kimage_free_page_list(&image->unusable_pages);
}

static void kimage_terminate(struct kexec_image *image)
{
    kimage_entry_t *entries;

    entries = __map_domain_page(image->entry_page);
    entries[image->next_entry] = IND_DONE;
    unmap_domain_page(entries);
}

/*
 * Iterate over all the entries in the indirection pages.
 *
 * Call unmap_domain_page(ptr) after the loop exits.
 */
#define for_each_kimage_entry(image, ptr, entry)                        \
    for ( ptr = map_domain_page(_mfn(paddr_to_pfn(image->head)));       \
          (entry = *ptr) && !(entry & IND_DONE);                        \
          ptr = (entry & IND_INDIRECTION) ?                             \
              (unmap_domain_page(ptr), map_domain_page(_mfn(paddr_to_pfn(entry)))) \
              : ptr + 1 )

static void kimage_free_entry(kimage_entry_t entry)
{
    struct page_info *page;

    page = mfn_to_page(entry >> PAGE_SHIFT);
    free_domheap_page(page);
}

static void kimage_free_all_entries(struct kexec_image *image)
{
    kimage_entry_t *ptr, entry;
    kimage_entry_t ind = 0;

    if ( !image->head )
        return;

    for_each_kimage_entry(image, ptr, entry)
    {
        if ( entry & IND_INDIRECTION )
        {
            /* Free the previous indirection page */
            if ( ind & IND_INDIRECTION )
                kimage_free_entry(ind);
            /* Save this indirection page until we are done with it. */
            ind = entry;
        }
        else if ( entry & IND_SOURCE )
            kimage_free_entry(entry);
    }
    unmap_domain_page(ptr);

    /* Free the final indirection page. */
    if ( ind & IND_INDIRECTION )
        kimage_free_entry(ind);
}

void kimage_free(struct kexec_image *image)
{
    if ( !image )
        return;

    kimage_free_extra_pages(image);
    kimage_free_all_entries(image);
    kimage_free_page_list(&image->control_pages);
    xfree(image->segments);
    xfree(image);
}

static kimage_entry_t *kimage_dst_used(struct kexec_image *image,
                                       paddr_t maddr)
{
    kimage_entry_t *ptr, entry;
    unsigned long destination = 0;

    for_each_kimage_entry(image, ptr, entry)
    {
        if ( entry & IND_DESTINATION )
            destination = entry & PAGE_MASK;
        else if ( entry & IND_SOURCE )
        {
            if ( maddr == destination )
                return ptr;
            destination += PAGE_SIZE;
        }
    }
    unmap_domain_page(ptr);

    return NULL;
}

static struct page_info *kimage_alloc_page(struct kexec_image *image,
                                           paddr_t destination)
{
    /*
     * Here we implement safeguards to ensure that a source page is
     * not copied to its destination page before the data on the
     * destination page is no longer useful.
     *
     * To do this we maintain the invariant that a source page is
     * either its own destination page, or it is not a destination
     * page at all.
     *
     * That is slightly stronger than required, but the proof that no
     * problems will not occur is trivial, and the implementation is
     * simply to verify.
     *
     * When allocating all pages normally this algorithm will run in
     * O(N) time, but in the worst case it will run in O(N^2) time.
     * If the runtime is a problem the data structures can be fixed.
     */
    struct page_info *page;
    paddr_t addr;
    int ret;

    /*
     * Walk through the list of destination pages, and see if I have a
     * match.
     */
    page_list_for_each(page, &image->dest_pages)
    {
        addr = page_to_maddr(page);
        if ( addr == destination )
        {
            page_list_del(page, &image->dest_pages);
            goto found;
        }
    }
    page = NULL;
    for (;;)
    {
        kimage_entry_t *old;

        /* Allocate a page, if we run out of memory give up. */
        page = kimage_alloc_zeroed_page(0);
        if ( !page )
            return NULL;
        addr = page_to_maddr(page);

        /* If it is the destination page we want use it. */
        if ( addr == destination )
            break;

        /* If the page is not a destination page use it. */
        if ( !kimage_is_destination_range(image, addr,
                                          addr + PAGE_SIZE) )
            break;

        /*
         * I know that the page is someones destination page.  See if
         * there is already a source page for this destination page.
         * And if so swap the source pages.
         */
        old = kimage_dst_used(image, addr);
        if ( old )
        {
            /* If so move it. */
            mfn_t old_mfn = _mfn(*old >> PAGE_SHIFT);
            mfn_t mfn = _mfn(addr >> PAGE_SHIFT);

            copy_domain_page(mfn, old_mfn);
            clear_domain_page(old_mfn);
            *old = (addr & ~PAGE_MASK) | IND_SOURCE;
            unmap_domain_page(old);

            page = mfn_to_page(mfn_x(old_mfn));
            break;
        }
        else
        {
            /*
             * Place the page on the destination list; I will use it
             * later.
             */
            page_list_add(page, &image->dest_pages);
        }
    }
found:
    ret = machine_kexec_add_page(image, page_to_maddr(page),
                                 page_to_maddr(page));
    if ( ret < 0 )
    {
        free_domheap_page(page);
        return NULL;
    }
    return page;
}

static int kimage_load_normal_segment(struct kexec_image *image,
                                      xen_kexec_segment_t *segment)
{
    unsigned long to_copy;
    unsigned long src_offset;
    paddr_t dest, end;
    int ret;

    to_copy = segment->buf_size;
    src_offset = 0;
    dest = segment->dest_maddr;

    ret = kimage_set_destination(image, dest);
    if ( ret < 0 )
        return ret;

    while ( to_copy )
    {
        unsigned long dest_mfn;
        struct page_info *page;
        void *dest_va;
        size_t size;

        dest_mfn = dest >> PAGE_SHIFT;

        size = min_t(unsigned long, PAGE_SIZE, to_copy);

        page = kimage_alloc_page(image, dest);
        if ( !page )
            return -ENOMEM;
        ret = kimage_add_page(image, page_to_maddr(page));
        if ( ret < 0 )
            return ret;

        dest_va = __map_domain_page(page);
        ret = copy_from_guest_offset(dest_va, segment->buf.h, src_offset, size);
        unmap_domain_page(dest_va);
        if ( ret )
            return -EFAULT;

        to_copy -= size;
        src_offset += size;
        dest += PAGE_SIZE;
    }

    /* Remainder of the destination should be zeroed. */
    end = segment->dest_maddr + segment->dest_size;
    for ( ; dest < end; dest += PAGE_SIZE )
        kimage_add_entry(image, IND_ZERO);

    return 0;
}

static int kimage_load_crash_segment(struct kexec_image *image,
                                     xen_kexec_segment_t *segment)
{
    /*
     * For crash dumps kernels we simply copy the data from user space
     * to it's destination.
     */
    paddr_t dest;
    unsigned long sbytes, dbytes;
    int ret = 0;
    unsigned long src_offset = 0;

    sbytes = segment->buf_size;
    dbytes = segment->dest_size;
    dest = segment->dest_maddr;

    while ( dbytes )
    {
        unsigned long dest_mfn;
        void *dest_va;
        size_t schunk, dchunk;

        dest_mfn = dest >> PAGE_SHIFT;

        dchunk = PAGE_SIZE;
        schunk = min(dchunk, sbytes);

        dest_va = map_domain_page(_mfn(dest_mfn));
        if ( !dest_va )
            return -EINVAL;

        ret = copy_from_guest_offset(dest_va, segment->buf.h, src_offset, schunk);
        memset(dest_va + schunk, 0, dchunk - schunk);

        unmap_domain_page(dest_va);
        if ( ret )
            return -EFAULT;

        dbytes -= dchunk;
        sbytes -= schunk;
        dest += dchunk;
        src_offset += schunk;
    }

    return 0;
}

static int kimage_load_segment(struct kexec_image *image, xen_kexec_segment_t *segment)
{
    int result = -ENOMEM;
    paddr_t addr;

    if ( !guest_handle_is_null(segment->buf.h) )
    {
        switch ( image->type )
        {
        case KEXEC_TYPE_DEFAULT:
            result = kimage_load_normal_segment(image, segment);
            break;
        case KEXEC_TYPE_CRASH:
            result = kimage_load_crash_segment(image, segment);
            break;
        }
    }

    for ( addr = segment->dest_maddr & PAGE_MASK;
          addr < segment->dest_maddr + segment->dest_size; addr += PAGE_SIZE )
    {
        result = machine_kexec_add_page(image, addr, addr);
        if ( result < 0 )
            break;
    }

    return result;
}

int kimage_alloc(struct kexec_image **rimage, uint8_t type, uint16_t arch,
                 uint64_t entry_maddr,
                 uint32_t nr_segments, xen_kexec_segment_t *segment)
{
    int result;

    switch( type )
    {
    case KEXEC_TYPE_DEFAULT:
        result = kimage_normal_alloc(rimage, entry_maddr, nr_segments, segment);
        break;
    case KEXEC_TYPE_CRASH:
        result = kimage_crash_alloc(rimage, entry_maddr, nr_segments, segment);
        break;
    default:
        result = -EINVAL;
        break;
    }
    if ( result < 0 )
        return result;

    (*rimage)->arch = arch;

    return result;
}

int kimage_load_segments(struct kexec_image *image)
{
    int s;
    int result;

    for ( s = 0; s < image->nr_segments; s++ ) {
        result = kimage_load_segment(image, &image->segments[s]);
        if ( result < 0 )
            return result;
    }
    kimage_terminate(image);
    return 0;
}

kimage_entry_t *kimage_entry_next(kimage_entry_t *entry, bool_t compat)
{
    if ( compat )
        return (kimage_entry_t *)((uint32_t *)entry + 1);
    return entry + 1;
}

unsigned long kimage_entry_mfn(kimage_entry_t *entry, bool_t compat)
{
    if ( compat )
        return *(uint32_t *)entry >> PAGE_SHIFT;
    return *entry >> PAGE_SHIFT;
}

unsigned long kimage_entry_ind(kimage_entry_t *entry, bool_t compat)
{
    if ( compat )
        return *(uint32_t *)entry & 0xf;
    return *entry & 0xf;
}

int kimage_build_ind(struct kexec_image *image, unsigned long ind_mfn,
                     bool_t compat)
{
    void *page;
    kimage_entry_t *entry;
    int ret = 0;
    paddr_t dest = KIMAGE_NO_DEST;

    page = map_domain_page(_mfn(ind_mfn));
    if ( !page )
        return -ENOMEM;

    /*
     * Walk the guest-supplied indirection pages, adding entries to
     * the image's indirection pages.
     */
    for ( entry = page; ;  )
    {
        unsigned long ind;
        unsigned long mfn;

        ind = kimage_entry_ind(entry, compat);
        mfn = kimage_entry_mfn(entry, compat);

        switch ( ind )
        {
        case IND_DESTINATION:
            dest = (paddr_t)mfn << PAGE_SHIFT;
            ret = kimage_set_destination(image, dest);
            if ( ret < 0 )
                goto done;
            break;
        case IND_INDIRECTION:
            unmap_domain_page(page);
            page = map_domain_page(_mfn(mfn));
            entry = page;
            continue;
        case IND_DONE:
            kimage_terminate(image);
            goto done;
        case IND_SOURCE:
        {
            struct page_info *guest_page, *xen_page;

            guest_page = mfn_to_page(mfn);
            if ( !get_page(guest_page, current->domain) )
            {
                ret = -EFAULT;
                goto done;
            }

            xen_page = kimage_alloc_page(image, dest);
            if ( !xen_page )
            {
                put_page(guest_page);
                ret = -ENOMEM;
                goto done;
            }

            copy_domain_page(_mfn(page_to_mfn(xen_page)), _mfn(mfn));
            put_page(guest_page);

            ret = kimage_add_page(image, page_to_maddr(xen_page));
            if ( ret < 0 )
                goto done;

            ret = machine_kexec_add_page(image, dest, dest);
            if ( ret < 0 )
                goto done;

            dest += PAGE_SIZE;
            break;
        }
        default:
            ret = -EINVAL;
            goto done;
        }
        entry = kimage_entry_next(entry, compat);
    }
done:
    unmap_domain_page(page);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
