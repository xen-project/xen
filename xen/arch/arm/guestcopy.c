#include <xen/lib.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/guest_access.h>

static unsigned long raw_copy_to_guest_helper(void *to, const void *from,
                                              unsigned len, int flush_dcache)
{
    /* XXX needs to handle faults */
    unsigned offset = (vaddr_t)to & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = get_page_from_gva(current, (vaddr_t) to, GV2M_WRITE);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += offset;
        memcpy(p, from, size);
        if ( flush_dcache )
            clean_dcache_va_range(p, size);

        unmap_domain_page(p - offset);
        put_page(page);
        len -= size;
        from += size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
    return raw_copy_to_guest_helper(to, from, len, 0);
}

unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len)
{
    return raw_copy_to_guest_helper(to, from, len, 1);
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    /* XXX needs to handle faults */
    unsigned offset = (vaddr_t)to & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = get_page_from_gva(current, (vaddr_t) to, GV2M_WRITE);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += offset;
        memset(p, 0x00, size);

        unmap_domain_page(p - offset);
        put_page(page);
        len -= size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }

    return 0;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    unsigned offset = (vaddr_t)from & ~PAGE_MASK;

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)(PAGE_SIZE - offset));
        struct page_info *page;

        page = get_page_from_gva(current, (vaddr_t) from, GV2M_READ);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += ((vaddr_t)from & (~PAGE_MASK));

        memcpy(to, p, size);

        unmap_domain_page(p);
        put_page(page);
        len -= size;
        from += size;
        to += size;
        /*
         * After the first iteration, guest virtual address is correctly
         * aligned to PAGE_SIZE.
         */
        offset = 0;
    }
    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
