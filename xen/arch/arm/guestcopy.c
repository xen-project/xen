#include <xen/config.h>
#include <xen/lib.h>
#include <xen/domain_page.h>

#include <asm/mm.h>
#include <asm/guest_access.h>

static unsigned long raw_copy_to_guest_helper(void *to, const void *from,
                                              unsigned len, int flush_dcache)
{
    /* XXX needs to handle faults */
    unsigned offset = (vaddr_t)to & ~PAGE_MASK;

    while ( len )
    {
        paddr_t g;
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);

        if ( gvirt_to_maddr((vaddr_t) to, &g) )
            return len;

        p = map_domain_page(g>>PAGE_SHIFT);
        p += offset;
        memcpy(p, from, size);
        if ( flush_dcache )
            clean_xen_dcache_va_range(p, size);

        unmap_domain_page(p - offset);
        len -= size;
        from += size;
        to += size;
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
        paddr_t g;
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);

        if ( gvirt_to_maddr((vaddr_t) to, &g) )
            return len;

        p = map_domain_page(g>>PAGE_SHIFT);
        p += offset;
        memset(p, 0x00, size);

        unmap_domain_page(p - offset);
        len -= size;
        to += size;
        offset = 0;
    }

    return 0;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    unsigned offset = (vaddr_t)from & ~PAGE_MASK;

    while ( len )
    {
        paddr_t g;
        void *p;
        unsigned size = min(len, (unsigned)(PAGE_SIZE - offset));

        if ( gvirt_to_maddr((vaddr_t) from & PAGE_MASK, &g) )
            return len;

        p = map_domain_page(g>>PAGE_SHIFT);
        p += ((vaddr_t)from & (~PAGE_MASK));

        memcpy(to, p, size);

        unmap_domain_page(p);
        len -= size;
        from += size;
        to += size;
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
