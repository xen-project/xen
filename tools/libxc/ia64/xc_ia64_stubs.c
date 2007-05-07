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

int
xc_ia64_get_pfn_list(int xc_handle, uint32_t domid, xen_pfn_t *pfn_buf,
                     unsigned int start_page, unsigned int nr_pages)
{
    DECLARE_DOMCTL;
    int ret;

    domctl.cmd = XEN_DOMCTL_getmemlist;
    domctl.domain = (domid_t)domid;
    domctl.u.getmemlist.max_pfns = nr_pages;
    domctl.u.getmemlist.start_pfn = start_page;
    domctl.u.getmemlist.num_pfns = 0;
    set_xen_guest_handle(domctl.u.getmemlist.buffer, pfn_buf);

    if (lock_pages(pfn_buf, nr_pages * sizeof(xen_pfn_t)) != 0) {
        PERROR("Could not lock pfn list buffer");
        return -1;
    }
    ret = do_domctl(xc_handle, &domctl);
    unlock_pages(pfn_buf, nr_pages * sizeof(xen_pfn_t));

    return ret < 0 ? -1 : nr_pages;
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
