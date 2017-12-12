#include <xen/lib.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/guest_access.h>

#define COPY_flush_dcache   (1U << 0)
#define COPY_from_guest     (0U << 1)
#define COPY_to_guest       (1U << 1)

typedef union
{
    struct
    {
        struct vcpu *v;
    } gva;
} copy_info_t;

#define GVA_INFO(vcpu) ((copy_info_t) { .gva = { vcpu } })

static unsigned long copy_guest(void *buf, uint64_t addr, unsigned int len,
                                copy_info_t info, unsigned int flags)
{
    /* XXX needs to handle faults */
    unsigned offset = addr & ~PAGE_MASK;

    BUILD_BUG_ON((sizeof(addr)) < sizeof(vaddr_t));

    while ( len )
    {
        void *p;
        unsigned size = min(len, (unsigned)PAGE_SIZE - offset);
        struct page_info *page;

        page = get_page_from_gva(info.gva.v, addr,
                                 (flags & COPY_to_guest) ? GV2M_WRITE : GV2M_READ);
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
                      GVA_INFO(current), COPY_to_guest);
}

unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len)
{
    return copy_guest((void *)from, (vaddr_t)to, len, GVA_INFO(current),
                      COPY_to_guest | COPY_flush_dcache);
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    return copy_guest(NULL, (vaddr_t)to, len, GVA_INFO(current),
                      COPY_to_guest);
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    return copy_guest(to, (vaddr_t)from, len, GVA_INFO(current),
                      COPY_from_guest);
}

/*
 * Temporarily map one physical guest page and copy data to or from it.
 * The data to be copied cannot cross a page boundary.
 */
int access_guest_memory_by_ipa(struct domain *d, paddr_t gpa, void *buf,
                               uint32_t size, bool is_write)
{
    struct page_info *page;
    uint64_t offset = gpa & ~PAGE_MASK;  /* Offset within the mapped page */
    p2m_type_t p2mt;
    void *p;

    /* Do not cross a page boundary. */
    if ( size > (PAGE_SIZE - offset) )
    {
        printk(XENLOG_G_ERR "d%d: guestcopy: memory access crosses page boundary.\n",
               d->domain_id);
        return -EINVAL;
    }

    page = get_page_from_gfn(d, paddr_to_pfn(gpa), &p2mt, P2M_ALLOC);
    if ( !page )
    {
        printk(XENLOG_G_ERR "d%d: guestcopy: failed to get table entry.\n",
               d->domain_id);
        return -EINVAL;
    }

    if ( !p2m_is_ram(p2mt) )
    {
        put_page(page);
        printk(XENLOG_G_ERR "d%d: guestcopy: guest memory should be RAM.\n",
               d->domain_id);
        return -EINVAL;
    }

    p = __map_domain_page(page);

    if ( is_write )
        memcpy(p + offset, buf, size);
    else
        memcpy(buf, p + offset, size);

    unmap_domain_page(p);
    put_page(page);

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
