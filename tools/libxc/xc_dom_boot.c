/*
 * Xen domain builder -- xen booter.
 *
 * This is the code which actually boots a fresh
 * prepared domain image as xen guest domain.
 *
 * ==>  this is the only domain builder code piece
 *          where xen hypercalls are allowed        <==
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
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

    DOMPRINTF("%s: vaddr=0x%" PRIx64 " pfn=0x%" PRIpfn "", __FUNCTION__,
                  dom->parms.virt_hypercall, pfn);
    domctl.cmd = XEN_DOMCTL_hypercall_init;
    domctl.domain = dom->guest_domid;
    domctl.u.hypercall_init.gmfn = xc_dom_p2m_guest(dom, pfn);
    rc = do_domctl(dom->xch, &domctl);
    if ( rc != 0 )
        xc_dom_panic(dom->xch,
                     XC_INTERNAL_ERROR, "%s: HYPERCALL_INIT failed (rc=%d)",
                     __FUNCTION__, rc);
    return rc;
}

static int launch_vm(xc_interface *xch, domid_t domid, xc_hypercall_buffer_t *ctxt)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(ctxt);
    int rc;

    xc_dom_printf(xch, "%s: called, ctxt=%p", __FUNCTION__, ctxt);
    memset(&domctl, 0, sizeof(domctl));
    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = domid;
    domctl.u.vcpucontext.vcpu = 0;
    xc_set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);
    rc = do_domctl(xch, &domctl);
    if ( rc != 0 )
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)", __FUNCTION__, rc);
    return rc;
}

static int clear_page(struct xc_dom_image *dom, xen_pfn_t pfn)
{
    xen_pfn_t dst;
    int rc;

    if ( pfn == 0 )
        return 0;

    dst = xc_dom_p2m_host(dom, pfn);
    DOMPRINTF("%s: pfn 0x%" PRIpfn ", mfn 0x%" PRIpfn "",
              __FUNCTION__, pfn, dst);
    rc = xc_clear_domain_page(dom->xch, dom->guest_domid, dst);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: xc_clear_domain_page failed (pfn 0x%" PRIpfn
                     ", rc=%d)", __FUNCTION__, pfn, rc);
    return rc;
}


/* ------------------------------------------------------------------------ */

int xc_dom_compat_check(struct xc_dom_image *dom)
{
    xen_capabilities_info_t xen_caps;
    char *item, *ptr;
    int match, found = 0;

    strncpy(xen_caps, dom->xen_caps, XEN_CAPABILITIES_INFO_LEN - 1);
    xen_caps[XEN_CAPABILITIES_INFO_LEN - 1] = '\0';

    for ( item = strtok_r(xen_caps, " ", &ptr);
          item != NULL ; item = strtok_r(NULL, " ", &ptr) )
    {
        match = !strcmp(dom->guest_type, item);
        DOMPRINTF("%s: supported guest type: %s%s", __FUNCTION__,
                  item, match ? " <= matches" : "");
        if ( match )
            found++;
    }
    if ( !found )
        xc_dom_panic(dom->xch, XC_INVALID_KERNEL,
                     "%s: guest type %s not supported by xen kernel, sorry",
                     __FUNCTION__, dom->guest_type);

    return found;
}

int xc_dom_boot_xen_init(struct xc_dom_image *dom, xc_interface *xch, domid_t domid)
{
    dom->xch = xch;
    dom->guest_domid = domid;

    dom->xen_version = xc_version(xch, XENVER_version, NULL);
    if ( xc_version(xch, XENVER_capabilities, &dom->xen_caps) < 0 )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR, "can't get xen capabilities");
        return -1;
    }
    DOMPRINTF("%s: ver %d.%d, caps %s", __FUNCTION__,
              dom->xen_version >> 16, dom->xen_version & 0xff,
              dom->xen_caps);
    return 0;
}

int xc_dom_boot_mem_init(struct xc_dom_image *dom)
{
    long rc;

    DOMPRINTF_CALLED(dom->xch);

    rc = arch_setup_meminit(dom);
    if ( rc != 0 )
    {
        xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                     "%s: can't allocate low memory for domain",
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
    int i;
    int err;

    entries = xc_dom_malloc(dom, count * sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: failed to mmap domU pages 0x%" PRIpfn "+0x%" PRIpfn
                     " [malloc]", __FUNCTION__, pfn, count);
        return NULL;
    }

    for ( i = 0; i < count; i++ )
        entries[i].mfn = xc_dom_p2m_host(dom, pfn + i);

    ptr = xc_map_foreign_ranges(dom->xch, dom->guest_domid,
                count << page_shift, PROT_READ | PROT_WRITE, 1 << page_shift,
                entries, count);
    if ( ptr == NULL )
    {
        err = errno;
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: failed to mmap domU pages 0x%" PRIpfn "+0x%" PRIpfn
                     " [mmap, errno=%i (%s)]", __FUNCTION__, pfn, count,
                     err, strerror(err));
        return NULL;
    }

    return ptr;
}

int xc_dom_boot_image(struct xc_dom_image *dom)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(vcpu_guest_context_any_t, ctxt);
    int rc;

    ctxt = xc_hypercall_buffer_alloc(dom->xch, ctxt, sizeof(*ctxt));
    if ( ctxt == NULL )
        return -1;

    DOMPRINTF_CALLED(dom->xch);

    /* misc ia64 stuff*/
    if ( (rc = arch_setup_bootearly(dom)) != 0 )
        return rc;

    /* collect some info */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = dom->guest_domid;
    rc = do_domctl(dom->xch, &domctl);
    if ( rc != 0 )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: getdomaininfo failed (rc=%d)", __FUNCTION__, rc);
        return rc;
    }
    if ( domctl.domain != dom->guest_domid )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: Huh? domid mismatch (%d != %d)", __FUNCTION__,
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
    memset(ctxt, 0, sizeof(ctxt));
    if ( (rc = dom->arch_hooks->vcpu(dom, ctxt)) != 0 )
        return rc;
    xc_dom_unmap_all(dom);
    rc = launch_vm(dom->xch, dom->guest_domid, HYPERCALL_BUFFER(ctxt));

    xc_hypercall_buffer_free(dom->xch, ctxt);
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
