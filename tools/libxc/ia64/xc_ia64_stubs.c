#include "xg_private.h"
#include "xenguest.h"
#include "xc_private.h"
#include "xc_elf.h"
#include <stdlib.h>
#include <zlib.h>
#include "xen/arch-ia64.h"
#include <xen/hvm/ioreq.h>

/* this is a very ugly way of getting FPSR_DEFAULT.  struct ia64_fpreg is
 * mysteriously declared in two places: /usr/include/asm/fpu.h and
 * /usr/include/bits/sigcontext.h.  The former also defines FPSR_DEFAULT,
 * the latter doesn't but is included (indirectly) by xg_private.h */
#define __ASSEMBLY__
#include <asm/fpu.h>
#undef __IA64_UL
#define __IA64_UL(x)           ((unsigned long)(x))
#undef __ASSEMBLY__

unsigned long
xc_ia64_fpsr_default(void)
{
    return FPSR_DEFAULT;
}

/*  
    VMM uses put_user to copy pfn_list to guest buffer, this maybe fail,
    VMM doesn't handle this now.
    This method will touch guest buffer to make sure the buffer's mapping
    is tracked by VMM,
 */
int
xc_ia64_get_pfn_list(int xc_handle, uint32_t domid, xen_pfn_t *pfn_buf,
                     unsigned int start_page, unsigned int nr_pages)
{
    struct xen_domctl domctl;
    int num_pfns,ret;
    unsigned int __start_page, __nr_pages;
    xen_pfn_t *__pfn_buf;

    __start_page = start_page;
    __nr_pages = nr_pages;
    __pfn_buf = pfn_buf;
  
    while (__nr_pages) {
        domctl.cmd = XEN_DOMCTL_getmemlist;
        domctl.domain = (domid_t)domid;
        domctl.u.getmemlist.max_pfns = __nr_pages;
        domctl.u.getmemlist.start_pfn =__start_page;
        domctl.u.getmemlist.num_pfns = 0;
        set_xen_guest_handle(domctl.u.getmemlist.buffer, __pfn_buf);

        if (mlock(__pfn_buf, __nr_pages * sizeof(xen_pfn_t)) != 0) {
            PERROR("Could not lock pfn list buffer");
            return -1;
        }

        ret = do_domctl(xc_handle, &domctl);

        (void)munlock(__pfn_buf, __nr_pages * sizeof(xen_pfn_t));

        num_pfns = domctl.u.getmemlist.num_pfns;
        __start_page += num_pfns;
        __nr_pages -= num_pfns;
        __pfn_buf += num_pfns;

        if (ret < 0)
            // dummy write to make sure this tlb mapping is tracked by VMM
            *__pfn_buf = 0;
        else
            return nr_pages;
    }
    return nr_pages;
}

int
xc_get_pfn_list(int xc_handle, uint32_t domid, uint64_t *pfn_buf,
                unsigned long max_pfns)
{
    return xc_ia64_get_pfn_list(xc_handle, domid, (xen_pfn_t *)pfn_buf,
                                0, max_pfns);
}

long
xc_get_max_pages(int xc_handle, uint32_t domid)
{
    struct xen_domctl domctl;
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)domid;
    return ((do_domctl(xc_handle, &domctl) < 0)
            ? -1 : domctl.u.getdomaininfo.max_pages);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
