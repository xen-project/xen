/*
 * Xen domain builder -- xen booter.
 *
 * This is the code which actually boots a fresh
 * prepared domain image as xen guest domain.
 *
 * ==>  this is the only domain bilder code piece
 *          where xen hypercalls are allowed        <==
 *
 * This code is licenced under the GPL.
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <zlib.h>

#include "xg_private.h"
#include "xc_dom.h"
#include <xen/hvm/params.h>

/* ------------------------------------------------------------------------ */

static int setup_hypercall_page(struct xc_dom_image *dom)
{
    DECLARE_DOMCTL;
    xen_pfn_t pfn;
    int rc;

    if ( dom->parms.virt_hypercall == -1 )
        return 0;
    pfn = (dom->parms.virt_hypercall - dom->parms.virt_base)
        >> XC_DOM_PAGE_SHIFT(dom);

    xc_dom_printf("%s: vaddr=0x%" PRIx64 " pfn=0x%" PRIpfn "\n", __FUNCTION__,
                  dom->parms.virt_hypercall, pfn);
    domctl.cmd = XEN_DOMCTL_hypercall_init;
    domctl.domain = dom->guest_domid;
    domctl.u.hypercall_init.gmfn = xc_dom_p2m_guest(dom, pfn);
    rc = do_domctl(dom->guest_xc, &domctl);
    if ( rc != 0 )
        xc_dom_panic(XC_INTERNAL_ERROR, "%s: HYPERCALL_INIT failed (rc=%d)\n",
                     __FUNCTION__, rc);
    return rc;
}

static int launch_vm(int xc, domid_t domid, void *ctxt)
{
    DECLARE_DOMCTL;
    int rc;

    xc_dom_printf("%s: called, ctxt=%p\n", __FUNCTION__, ctxt);
    memset(&domctl, 0, sizeof(domctl));
    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = domid;
    domctl.u.vcpucontext.vcpu = 0;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);
    rc = do_domctl(xc, &domctl);
    if ( rc != 0 )
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)\n", __FUNCTION__, rc);
    return rc;
}

static int clear_page(struct xc_dom_image *dom, xen_pfn_t pfn)
{
    xen_pfn_t dst;
    int rc;

    if ( pfn == 0 )
        return 0;

    dst = xc_dom_p2m_host(dom, pfn);
    xc_dom_printf("%s: pfn 0x%" PRIpfn ", mfn 0x%" PRIpfn "\n",
                  __FUNCTION__, pfn, dst);
    rc = xc_clear_domain_page(dom->guest_xc, dom->guest_domid, dst);
    if ( rc != 0 )
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: xc_clear_domain_page failed (pfn 0x%" PRIpfn
                     ", rc=%d)\n", __FUNCTION__, pfn, rc);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* arch stuff: x86 bits                                                     */

#if defined(__i386__) || defined(__x86_64__)


static int x86_compat(int xc, domid_t domid, char *guest_type)
{
    static const struct {
        char           *guest;
        uint32_t        size;
    } types[] = {
        { "xen-3.0-x86_32p", 32 },
        { "xen-3.0-x86_64",  64 },
    };
    DECLARE_DOMCTL;
    int i,rc;

    memset(&domctl, 0, sizeof(domctl));
    domctl.domain = domid;
    domctl.cmd    = XEN_DOMCTL_set_address_size;
    for ( i = 0; i < sizeof(types)/sizeof(types[0]); i++ )
        if ( !strcmp(types[i].guest, guest_type) )
            domctl.u.address_size.size = types[i].size;
    if ( domctl.u.address_size.size == 0 )
        /* nothing to do */
        return 0;

    xc_dom_printf("%s: guest %s, address size %" PRId32 "\n", __FUNCTION__,
                  guest_type, domctl.u.address_size.size);
    rc = do_domctl(xc, &domctl);
    if ( rc != 0 )
        xc_dom_printf("%s: warning: failed (rc=%d)\n",
                      __FUNCTION__, rc);
    return rc;
}


static int x86_shadow(int xc, domid_t domid)
{
    int rc, mode;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    mode = XEN_DOMCTL_SHADOW_ENABLE_REFCOUNT |
        XEN_DOMCTL_SHADOW_ENABLE_TRANSLATE;

    rc = xc_shadow_control(xc, domid,
                           XEN_DOMCTL_SHADOW_OP_ENABLE,
                           NULL, 0, NULL, mode, NULL);
    if ( rc != 0 )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: SHADOW_OP_ENABLE (mode=0x%x) failed (rc=%d)\n",
                     __FUNCTION__, mode, rc);
        return rc;
    }
    xc_dom_printf("%s: shadow enabled (mode=0x%x)\n", __FUNCTION__, mode);
    return rc;
}

static int arch_setup_meminit(struct xc_dom_image *dom)
{
    int rc = 0;

    x86_compat(dom->guest_xc, dom->guest_domid, dom->guest_type);
    if ( xc_dom_feature_translated(dom) )
    {
        dom->shadow_enabled = 1;
        rc = x86_shadow(dom->guest_xc, dom->guest_domid);
    }
    return rc;
}

static int arch_setup_bootearly(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootlate(struct xc_dom_image *dom)
{
    static const struct {
        char *guest;
        unsigned long pgd_type;
    } types[] = {
        { "xen-3.0-x86_32",  MMUEXT_PIN_L2_TABLE},
        { "xen-3.0-x86_32p", MMUEXT_PIN_L3_TABLE},
        { "xen-3.0-x86_64",  MMUEXT_PIN_L4_TABLE},
    };
    unsigned long pgd_type = 0;
    shared_info_t *shared_info;
    xen_pfn_t shinfo;
    int i, rc;

    for ( i = 0; i < sizeof(types) / sizeof(types[0]); i++ )
        if ( !strcmp(types[i].guest, dom->guest_type) )
            pgd_type = types[i].pgd_type;

    if ( !xc_dom_feature_translated(dom) )
    {
        /* paravirtualized guest */
        xc_dom_unmap_one(dom, dom->pgtables_seg.pfn);
        rc = pin_table(dom->guest_xc, pgd_type,
                       xc_dom_p2m_host(dom, dom->pgtables_seg.pfn),
                       dom->guest_domid);
        if ( rc != 0 )
        {
            xc_dom_panic(XC_INTERNAL_ERROR,
                         "%s: pin_table failed (pfn 0x%" PRIpfn ", rc=%d)\n",
                         __FUNCTION__, dom->pgtables_seg.pfn, rc);
            return rc;
        }
        shinfo = dom->shared_info_mfn;
    }
    else
    {
        /* paravirtualized guest with auto-translation */
        struct xen_add_to_physmap xatp;
        int i;

        /* Map shared info frame into guest physmap. */
        xatp.domid = dom->guest_domid;
        xatp.space = XENMAPSPACE_shared_info;
        xatp.idx = 0;
        xatp.gpfn = dom->shared_info_pfn;
        rc = xc_memory_op(dom->guest_xc, XENMEM_add_to_physmap, &xatp);
        if ( rc != 0 )
        {
            xc_dom_panic(XC_INTERNAL_ERROR, "%s: mapping shared_info failed "
                         "(pfn=0x%" PRIpfn ", rc=%d)\n",
                         __FUNCTION__, xatp.gpfn, rc);
            return rc;
        }

        /* Map grant table frames into guest physmap. */
        for ( i = 0; ; i++ )
        {
            xatp.domid = dom->guest_domid;
            xatp.space = XENMAPSPACE_grant_table;
            xatp.idx = i;
            xatp.gpfn = dom->total_pages + i;
            rc = xc_memory_op(dom->guest_xc, XENMEM_add_to_physmap, &xatp);
            if ( rc != 0 )
            {
                if ( (i > 0) && (errno == EINVAL) )
                {
                    xc_dom_printf("%s: %d grant tables mapped\n", __FUNCTION__,
                                  i);
                    break;
                }
                xc_dom_panic(XC_INTERNAL_ERROR,
                             "%s: mapping grant tables failed " "(pfn=0x%"
                             PRIpfn ", rc=%d)\n", __FUNCTION__, xatp.gpfn, rc);
                return rc;
            }
        }
        shinfo = dom->shared_info_pfn;
    }

    /* setup shared_info page */
    xc_dom_printf("%s: shared_info: pfn 0x%" PRIpfn ", mfn 0x%" PRIpfn "\n",
                  __FUNCTION__, dom->shared_info_pfn, dom->shared_info_mfn);
    shared_info = xc_map_foreign_range(dom->guest_xc, dom->guest_domid,
                                       PAGE_SIZE_X86,
                                       PROT_READ | PROT_WRITE,
                                       shinfo);
    if ( shared_info == NULL )
        return -1;
    dom->arch_hooks->shared_info(dom, shared_info);
    munmap(shared_info, PAGE_SIZE_X86);

    return 0;
}

/* ------------------------------------------------------------------------ */
/* arch stuff: ia64                                                         */

#elif defined(__ia64__)

static int arch_setup_meminit(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootearly(struct xc_dom_image *dom)
{
    DECLARE_DOMCTL;
    int rc;

    xc_dom_printf("%s: setup firmware\n", __FUNCTION__);

    memset(&domctl, 0, sizeof(domctl));
    domctl.cmd = XEN_DOMCTL_arch_setup;
    domctl.domain = dom->guest_domid;
    domctl.u.arch_setup.flags = 0;

    domctl.u.arch_setup.bp = (dom->start_info_pfn << PAGE_SHIFT)
        + sizeof(start_info_t);
    /* 3 = start info page, xenstore page and console page */
    domctl.u.arch_setup.maxmem = (dom->total_pages - 3) << PAGE_SHIFT;
    rc = do_domctl(dom->guest_xc, &domctl);
    return rc;
}

static int arch_setup_bootlate(struct xc_dom_image *dom)
{
    unsigned int page_size = XC_DOM_PAGE_SIZE(dom);
    shared_info_t *shared_info;

    /* setup shared_info page */
    xc_dom_printf("%s: shared_info: mfn 0x%" PRIpfn "\n",
                  __FUNCTION__, dom->shared_info_mfn);
    shared_info = xc_map_foreign_range(dom->guest_xc, dom->guest_domid,
                                       page_size,
                                       PROT_READ | PROT_WRITE,
                                       dom->shared_info_mfn);
    if ( shared_info == NULL )
        return -1;
    dom->arch_hooks->shared_info(dom, shared_info);
    munmap(shared_info, page_size);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* arch stuff: powerpc                                                      */

#elif defined(__powerpc64__)

static int arch_setup_meminit(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootearly(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootlate(struct xc_dom_image *dom)
{
    start_info_t *si =
        xc_dom_pfn_to_ptr(dom, dom->start_info_pfn, 1);

    xc_dom_printf("%s: TODO: setup devtree\n", __FUNCTION__);

#if 0
    load_devtree(dom->guest_xc,
                 dom->guest_domid,
                 dom->p2m_host,
                 devtree,           // FIXME
                 devtree_addr,      // FIXME
                 dom->ramdisk_seg.vstart,
                 dom->ramdisk_seg.vend - dom->ramdisk_seg.vstart,
                 si,
                 dom->start_info_pfn << PAGE_SHIFT);
#endif
    return rc;
}

/* ------------------------------------------------------------------------ */
/* arch stuff: other                                                        */

#else

static int arch_setup_meminit(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootearly(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

static int arch_setup_bootlate(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

#endif /* arch stuff */

/* ------------------------------------------------------------------------ */

int xc_dom_compat_check(struct xc_dom_image *dom)
{
    xen_capabilities_info_t xen_caps;
    char *item, *ptr;
    int match, found = 0;

    strcpy(xen_caps, dom->xen_caps);
    for ( item = strtok_r(xen_caps, " ", &ptr);
          item != NULL ; item = strtok_r(NULL, " ", &ptr) )
    {
        match = !strcmp(dom->guest_type, item);
        xc_dom_printf("%s: supported guest type: %s%s\n", __FUNCTION__,
                      item, match ? " <= matches" : "");
        if ( match )
            found++;
    }
    if ( !found )
        xc_dom_panic(XC_INVALID_KERNEL,
                     "%s: guest type %s not supported by xen kernel, sorry\n",
                     __FUNCTION__, dom->guest_type);

    return found;
}

int xc_dom_boot_xen_init(struct xc_dom_image *dom, int xc, domid_t domid)
{
    dom->guest_xc = xc;
    dom->guest_domid = domid;

    dom->xen_version = xc_version(dom->guest_xc, XENVER_version, NULL);
    if ( xc_version(xc, XENVER_capabilities, &dom->xen_caps) < 0 )
    {
        xc_dom_panic(XC_INTERNAL_ERROR, "can't get xen capabilities");
        return -1;
    }
    xc_dom_printf("%s: ver %d.%d, caps %s\n", __FUNCTION__,
                  dom->xen_version >> 16, dom->xen_version & 0xff,
                  dom->xen_caps);
    return 0;
}

int xc_dom_boot_mem_init(struct xc_dom_image *dom)
{
    long rc;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    if ( (rc = arch_setup_meminit(dom)) != 0 )
        return rc;

    /* allocate guest memory */
    rc = xc_domain_memory_populate_physmap(dom->guest_xc, dom->guest_domid,
                                           dom->total_pages, 0, 0,
                                           dom->p2m_host);
    if ( rc != 0 )
    {
        xc_dom_panic(XC_OUT_OF_MEMORY,
                     "%s: can't allocate low memory for domain\n",
                     __FUNCTION__);
        return rc;
    }

    return 0;
}

void *xc_dom_boot_domU_map(struct xc_dom_image *dom, xen_pfn_t pfn,
                           xen_pfn_t count)
{
    int page_shift = XC_DOM_PAGE_SHIFT(dom);
    privcmd_mmap_entry_t *entries;
    void *ptr;
    int i, rc;

    entries = xc_dom_malloc(dom, count * sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: failed to mmap domU pages 0x%" PRIpfn "+0x%" PRIpfn
                     " [malloc]\n", __FUNCTION__, pfn, count);
        return NULL;
    }

    ptr = mmap(NULL, count << page_shift, PROT_READ | PROT_WRITE,
               MAP_SHARED, dom->guest_xc, 0);
    if ( ptr == MAP_FAILED )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: failed to mmap domU pages 0x%" PRIpfn "+0x%" PRIpfn
                     " [mmap]\n", __FUNCTION__, pfn, count);
        return NULL;
    }

    for ( i = 0; i < count; i++ )
    {
        entries[i].va = (uintptr_t) ptr + (i << page_shift);
        entries[i].mfn = xc_dom_p2m_host(dom, pfn + i);
        entries[i].npages = 1;
    }

    rc = xc_map_foreign_ranges(dom->guest_xc, dom->guest_domid,
                               entries, count);
    if ( rc < 0 )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: failed to mmap domU pages 0x%" PRIpfn "+0x%" PRIpfn
                     " [xenctl, rc=%d]\n", __FUNCTION__, pfn, count, rc);
        return NULL;
    }
    return ptr;
}

int xc_dom_boot_image(struct xc_dom_image *dom)
{
    DECLARE_DOMCTL;
    void *ctxt;
    int rc;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    /* misc ia64 stuff*/
    if ( (rc = arch_setup_bootearly(dom)) != 0 )
        return rc;

    /* collect some info */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = dom->guest_domid;
    rc = do_domctl(dom->guest_xc, &domctl);
    if ( rc != 0 )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: getdomaininfo failed (rc=%d)\n", __FUNCTION__, rc);
        return rc;
    }
    if ( domctl.domain != dom->guest_domid )
    {
        xc_dom_panic(XC_INTERNAL_ERROR,
                     "%s: Huh? domid mismatch (%d != %d)\n", __FUNCTION__,
                     domctl.domain, dom->guest_domid);
        return -1;
    }
    dom->shared_info_mfn = domctl.u.getdomaininfo.shared_info_frame;

    /* sanity checks */
    if ( !xc_dom_compat_check(dom) )
        return -1;

    /* initial mm setup */
    if ( (rc = xc_dom_update_guest_p2m(dom)) != 0 )
        return rc;
    if ( dom->arch_hooks->setup_pgtables )
        if ( (rc = dom->arch_hooks->setup_pgtables(dom)) != 0 )
            return rc;

    if ( (rc = clear_page(dom, dom->console_pfn)) != 0 )
        return rc;
    if ( (rc = clear_page(dom, dom->xenstore_pfn)) != 0 )
        return rc;

    /* start info page */
    if ( dom->arch_hooks->start_info )
        dom->arch_hooks->start_info(dom);

    /* hypercall page */
    if ( (rc = setup_hypercall_page(dom)) != 0 )
        return rc;
    xc_dom_log_memory_footprint(dom);

    /* misc x86 stuff */
    if ( (rc = arch_setup_bootlate(dom)) != 0 )
        return rc;

    /* let the vm run */
    ctxt = xc_dom_malloc(dom, PAGE_SIZE * 2 /* FIXME */ );
    memset(ctxt, 0, PAGE_SIZE * 2);
    if ( (rc = dom->arch_hooks->vcpu(dom, ctxt)) != 0 )
        return rc;
    xc_dom_unmap_all(dom);
    rc = launch_vm(dom->guest_xc, dom->guest_domid, ctxt);

    return rc;
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
