/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/domain_page.h>
#include <xen/page-size.h>
#include <xen/sched.h>
#include <xen/string.h>

#include <asm/guest_access.h>

#define COPY_from_guest     0U
#define COPY_to_guest       BIT(0, U)
#define COPY_gpa            0U
#define COPY_gva            BIT(1, U)

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
                                            bool gva, bool write)
{
    p2m_type_t p2mt;
    struct page_info *page;

    /*
     * Not implemented yet.
     *
     * If gva == true, the operation will likely require a struct vcpu
     * rather than just a struct domain. For this reason copy_info_t is
     * already passed here instead of only struct domain.
     */
    BUG_ON(gva);

    page = get_page_from_gfn(info.gpa.d, paddr_to_pfn(addr), &p2mt, P2M_ALLOC);

    if ( !page )
        return NULL;

    if ( write ? p2mt != p2m_ram_rw : !p2m_is_ram(p2mt) )
    {
        put_page(page);
        return NULL;
    }

    return page;
}

static unsigned long copy_guest(void *buf, uint64_t addr, unsigned long len,
                                copy_info_t info, unsigned int flags)
{
    unsigned int offset = PAGE_OFFSET(addr);

    BUILD_BUG_ON((sizeof(addr)) < sizeof(vaddr_t));
    BUILD_BUG_ON((sizeof(addr)) < sizeof(paddr_t));

    while ( len )
    {
        void *p;
        unsigned long size = min(len, PAGE_SIZE + 0UL - offset);
        struct page_info *page;

        page = translate_get_page(info, addr, flags & COPY_gva,
                                  flags & COPY_to_guest);
        if ( !page )
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

        unmap_domain_page(p);
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

unsigned long copy_to_guest_phys(struct domain *d, paddr_t gpa, void *buf,
                                 unsigned long len)
{
    return copy_guest(buf, gpa, len, GPA_INFO(d),
                      COPY_to_guest | COPY_gpa);
}
