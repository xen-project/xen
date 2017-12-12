#include <xen/lib.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/guest_access.h>

#define COPY_flush_dcache   (1U << 0)
#define COPY_from_guest     (0U << 1)
#define COPY_to_guest       (1U << 1)
#define COPY_ipa            (0U << 2)
#define COPY_linear         (1U << 2)

typedef union
{
    struct
    {
        struct vcpu *v;
    } gva;

    struct
    {
        struct domain *d;
    } gpa;
} copy_info_t;

#define GVA_INFO(vcpu) ((copy_info_t) { .gva = { vcpu } })
#define GPA_INFO(domain) ((copy_info_t) { .gpa = { domain } })

static struct page_info *translate_get_page(copy_info_t info, uint64_t addr,
                                            bool linear, bool write)
{
    p2m_type_t p2mt;
    struct page_info *page;

    if ( linear )
        return get_page_from_gva(info.gva.v, addr,
                                 write ? GV2M_WRITE : GV2M_READ);

    page = get_page_from_gfn(info.gpa.d, paddr_to_pfn(addr), &p2mt, P2M_ALLOC);

    if ( !page )
        return NULL;

    if ( !p2m_is_ram(p2mt) )
    {
        put_page(page);
        return NULL;
    }

    return page;
}

static unsigned long copy_guest(void *buf, uint64_t addr, unsigned int len,
                                copy_info_t info, unsigned int flags)
{
    /* XXX needs to handle faults */
    unsigned offset = addr & ~PAGE_MASK;

    BUILD_BUG_ON((sizeof(addr)) < sizeof(vaddr_t));
    BUILD_BUG_ON((sizeof(addr)) < sizeof(paddr_t));

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = translate_get_page(info, addr, flags & COPY_linear,
                                  flags & COPY_to_guest);
        if ( page == NULL )
            return len;

        p = __map_domain_page(page);
        p += offset;
        if ( flags & COPY_to_guest )
        {
            /*
             * buf will be NULL when the caller request to zero the
             * guest memory.
             */
            if ( buf )
                memcpy(p, buf, size);
            else
                memset(p, 0, size);
        }
        else
            memcpy(buf, p, size);

        if ( flags & COPY_flush_dcache )
            clean_dcache_va_range(p, size);

        unmap_domain_page(p - offset);
        put_page(page);
        len -= size;
        buf += size;
        addr += size;
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
    return copy_guest((void *)from, (vaddr_t)to, len,
                      GVA_INFO(current), COPY_to_guest | COPY_linear);
}

unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len)
{
    return copy_guest((void *)from, (vaddr_t)to, len, GVA_INFO(current),
                      COPY_to_guest | COPY_flush_dcache | COPY_linear);
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    return copy_guest(NULL, (vaddr_t)to, len, GVA_INFO(current),
                      COPY_to_guest | COPY_linear);
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    return copy_guest(to, (vaddr_t)from, len, GVA_INFO(current),
                      COPY_from_guest | COPY_linear);
}

unsigned long copy_to_guest_phys_flush_dcache(struct domain *d,
                                              paddr_t gpa,
                                              void *buf,
                                              unsigned int len)
{
    return copy_guest(buf, gpa, len, GPA_INFO(d),
                      COPY_to_guest | COPY_ipa | COPY_flush_dcache);
}

int access_guest_memory_by_ipa(struct domain *d, paddr_t gpa, void *buf,
                               uint32_t size, bool is_write)
{
    unsigned long left;
    int flags = COPY_ipa;

    flags |= is_write ? COPY_to_guest : COPY_from_guest;

    left = copy_guest(buf, gpa, size, GPA_INFO(d), flags);

    return (!left) ? 0 : -EINVAL;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
