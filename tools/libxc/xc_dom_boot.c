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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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
#include "xc_core.h"
#include <xen/hvm/params.h>
#include <xen/grant_table.h>

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
    domctl.u.hypercall_init.gmfn = xc_dom_p2m(dom, pfn);
    rc = do_domctl(dom->xch, &domctl);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: HYPERCALL_INIT failed: %d - %s)",
                     __FUNCTION__, errno, strerror(errno));
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

int xc_dom_boot_xen_init(struct xc_dom_image *dom, xc_interface *xch, uint32_t domid)
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

    rc = dom->arch_hooks->meminit(dom);
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
        entries[i].mfn = xc_dom_p2m(dom, pfn + i);

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
    xc_dominfo_t info;
    int rc;

    DOMPRINTF_CALLED(dom->xch);

    /* misc stuff*/
    if ( (rc = dom->arch_hooks->bootearly(dom)) != 0 )
        return rc;

    /* collect some info */
    rc = xc_domain_getinfo(dom->xch, dom->guest_domid, 1, &info);
    if ( rc < 0 )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: getdomaininfo failed (rc=%d)", __FUNCTION__, rc);
        return rc;
    }
    if ( rc == 0 || info.domid != dom->guest_domid )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: Huh? No domains found (nr_domains=%d) "
                     "or domid mismatch (%d != %d)", __FUNCTION__,
                     rc, info.domid, dom->guest_domid);
        return -1;
    }
    dom->shared_info_mfn = info.shared_info_frame;

    /* sanity checks */
    if ( !xc_dom_compat_check(dom) )
        return -1;

    /* initial mm setup */
    if ( (rc = xc_dom_update_guest_p2m(dom)) != 0 )
        return rc;
    if ( dom->arch_hooks->setup_pgtables )
        if ( (rc = dom->arch_hooks->setup_pgtables(dom)) != 0 )
            return rc;

    /* start info page */
    if ( dom->arch_hooks->start_info )
        dom->arch_hooks->start_info(dom);

    /* hypercall page */
    if ( (rc = setup_hypercall_page(dom)) != 0 )
        return rc;
    xc_dom_log_memory_footprint(dom);

    /* misc x86 stuff */
    if ( (rc = dom->arch_hooks->bootlate(dom)) != 0 )
        return rc;

    /* let the vm run */
    if ( (rc = dom->arch_hooks->vcpu(dom)) != 0 )
        return rc;
    xc_dom_unmap_all(dom);

    return rc;
}

static xen_pfn_t xc_dom_gnttab_setup(xc_interface *xch, uint32_t domid)
{
    gnttab_setup_table_t setup;
    DECLARE_HYPERCALL_BUFFER(xen_pfn_t, gmfnp);
    int rc;
    xen_pfn_t gmfn;

    gmfnp = xc_hypercall_buffer_alloc(xch, gmfnp, sizeof(*gmfnp));
    if (gmfnp == NULL)
        return -1;

    setup.dom = domid;
    setup.nr_frames = 1;
    set_xen_guest_handle(setup.frame_list, gmfnp);
    setup.status = 0;

    rc = xc_gnttab_op(xch, GNTTABOP_setup_table, &setup, sizeof(setup), 1);
    gmfn = *gmfnp;
    xc_hypercall_buffer_free(xch, gmfnp);

    if ( rc != 0 || setup.status != GNTST_okay )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to setup domU grant table "
                     "[errno=%d, status=%" PRId16 "]\n",
                     __FUNCTION__, rc != 0 ? errno : 0, setup.status);
        return -1;
    }

    return gmfn;
}

int xc_dom_gnttab_seed(xc_interface *xch, uint32_t domid,
                       xen_pfn_t console_gmfn,
                       xen_pfn_t xenstore_gmfn,
                       uint32_t console_domid,
                       uint32_t xenstore_domid)
{

    xen_pfn_t gnttab_gmfn;
    grant_entry_v1_t *gnttab;

    gnttab_gmfn = xc_dom_gnttab_setup(xch, domid);
    if ( gnttab_gmfn == -1 )
        return -1;

    gnttab = xc_map_foreign_range(xch,
                                  domid,
                                  PAGE_SIZE,
                                  PROT_READ|PROT_WRITE,
                                  gnttab_gmfn);
    if ( gnttab == NULL )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to map domU grant table "
                     "[errno=%d]\n",
                     __FUNCTION__, errno);
        return -1;
    }

    if ( domid != console_domid  && console_gmfn != -1)
    {
        gnttab[GNTTAB_RESERVED_CONSOLE].flags = GTF_permit_access;
        gnttab[GNTTAB_RESERVED_CONSOLE].domid = console_domid;
        gnttab[GNTTAB_RESERVED_CONSOLE].frame = console_gmfn;
    }
    if ( domid != xenstore_domid && xenstore_gmfn != -1)
    {
        gnttab[GNTTAB_RESERVED_XENSTORE].flags = GTF_permit_access;
        gnttab[GNTTAB_RESERVED_XENSTORE].domid = xenstore_domid;
        gnttab[GNTTAB_RESERVED_XENSTORE].frame = xenstore_gmfn;
    }

    if ( munmap(gnttab, PAGE_SIZE) == -1 )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to unmap domU grant table "
                     "[errno=%d]\n",
                     __FUNCTION__, errno);
        return -1;
    }

    /* Guest shouldn't really touch its grant table until it has
     * enabled its caches. But lets be nice. */
    xc_domain_cacheflush(xch, domid, gnttab_gmfn, 1);

    return 0;
}

int xc_dom_gnttab_hvm_seed(xc_interface *xch, uint32_t domid,
                           xen_pfn_t console_gpfn,
                           xen_pfn_t xenstore_gpfn,
                           uint32_t console_domid,
                           uint32_t xenstore_domid)
{
    int rc;
    xen_pfn_t scratch_gpfn;
    struct xen_add_to_physmap xatp = {
        .domid = domid,
        .space = XENMAPSPACE_grant_table,
        .idx   = 0,
    };
    struct xen_remove_from_physmap xrfp = {
        .domid = domid,
    };

    rc = xc_core_arch_get_scratch_gpfn(xch, domid, &scratch_gpfn);
    if ( rc < 0 )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to get a scratch gfn "
                     "[errno=%d]\n",
                     __FUNCTION__, errno);
        return -1;
    }
    xatp.gpfn = scratch_gpfn;
    xrfp.gpfn = scratch_gpfn;

    xc_dom_printf(xch, "%s: called, pfn=0x%"PRI_xen_pfn, __FUNCTION__,
                  scratch_gpfn);


    rc = do_memory_op(xch, XENMEM_add_to_physmap, &xatp, sizeof(xatp));
    if ( rc != 0 )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to add gnttab to physmap "
                     "[errno=%d]\n",
                     __FUNCTION__, errno);
        return -1;
    }

    rc = xc_dom_gnttab_seed(xch, domid,
                            console_gpfn, xenstore_gpfn,
                            console_domid, xenstore_domid);
    if (rc != 0)
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to seed gnttab entries\n",
                     __FUNCTION__);
        (void) do_memory_op(xch, XENMEM_remove_from_physmap, &xrfp, sizeof(xrfp));
        return -1;
    }

    rc = do_memory_op(xch, XENMEM_remove_from_physmap, &xrfp, sizeof(xrfp));
    if (rc != 0)
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: failed to remove gnttab from physmap "
                     "[errno=%d]\n",
                     __FUNCTION__, errno);
        return -1;
    }

    return 0;
}

int xc_dom_gnttab_init(struct xc_dom_image *dom)
{
    if ( xc_dom_translated(dom) ) {
        return xc_dom_gnttab_hvm_seed(dom->xch, dom->guest_domid,
                                      dom->console_pfn, dom->xenstore_pfn,
                                      dom->console_domid, dom->xenstore_domid);
    } else {
        return xc_dom_gnttab_seed(dom->xch, dom->guest_domid,
                                  xc_dom_p2m(dom, dom->console_pfn),
                                  xc_dom_p2m(dom, dom->xenstore_pfn),
                                  dom->console_domid, dom->xenstore_domid);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
