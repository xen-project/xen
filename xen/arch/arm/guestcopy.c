#include <xen/config.h>
#include <xen/lib.h>
#include <xen/domain_page.h>

#include <asm/mm.h>
#include <asm/guest_access.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
    /* XXX needs to handle faults */
    unsigned offset = ((unsigned long)to & ~PAGE_MASK);

    while ( len )
    {
        paddr_t g = gvirt_to_maddr((uint32_t) to);
        void *p = map_domain_page(g>>PAGE_SHIFT);
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);

        p += offset;
        memcpy(p, from, size);

        unmap_domain_page(p - offset);
        len -= size;
        from += size;
        to += size;
        offset = 0;
    }

    return 0;
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    /* XXX needs to handle faults */
    unsigned offset = ((unsigned long)to & ~PAGE_MASK);

    while ( len )
    {
        paddr_t g = gvirt_to_maddr((uint32_t) to);
        void *p = map_domain_page(g>>PAGE_SHIFT);
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);

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
    while ( len )
    {
        paddr_t g = gvirt_to_maddr((uint32_t) from & PAGE_MASK);
        void *p = map_domain_page(g>>PAGE_SHIFT);
        unsigned size = min(len, (unsigned)(PAGE_SIZE - ((unsigned)from & (~PAGE_MASK))));

        p += ((unsigned long)from & (~PAGE_MASK));

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
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
