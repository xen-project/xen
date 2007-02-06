/*
 * Xen domain builder -- ia64 bits.
 *
 * Most architecture-specific code for ia64 goes here.
 *   - fill architecture-specific structs.
 *
 * This code is licenced under the GPL.
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <xen/xen.h>

#include "xg_private.h"
#include "xc_dom.h"

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    /* allocate special pages */
    dom->low_top--; /* shared_info */
    dom->xenstore_pfn = --dom->low_top;
    dom->console_pfn = --dom->low_top;
    dom->start_info_pfn = --dom->low_top;
    return 0;
}

static int start_info(struct xc_dom_image *dom)
{
    start_info_t *si =
	xc_dom_pfn_to_ptr(dom, dom->start_info_pfn, 1);

    xc_dom_printf("%s\n", __FUNCTION__);

    snprintf(si->magic, sizeof(si->magic), "xen-%d.%d-powerpc64HV", 3, 0);

    si->nr_pages = dom->total_pages;
    si->shared_info = (dom->total_pages - 1) << PAGE_SHIFT;
    si->store_mfn = dom->xenstore_pfn;
    si->store_evtchn = dom->store_evtchn;
    si->console.domU.mfn = dom->console_pfn;
    si->console.domU.evtchn = dom->console_evtchn;
    return 0;
}

static int shared_info(struct xc_dom_image *dom, void *ptr)
{
    shared_info_t *shared_info = ptr;
    int i;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    memset(shared_info, 0, sizeof(*shared_info));
    return 0;
}

static int vcpu(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_t *ctxt = ptr;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    memset(&ctxt->user_regs, 0x55, sizeof(ctxt.user_regs));
    ctxt->user_regs.pc = dsi->v_kernentry;
    ctxt->user_regs.msr = 0;
    ctxt->user_regs.gprs[1] = 0; /* Linux uses its own stack */
    ctxt->user_regs.gprs[3] = devtree_addr;
    ctxt->user_regs.gprs[4] = kern_addr;
    ctxt->user_regs.gprs[5] = 0;

    /* There is a buggy kernel that does not zero the "local_paca", so
     * we must make sure this register is 0 */
    ctxt->user_regs.gprs[13] = 0;

    return 0;
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_arch = {
    .guest_type = "xen-3.0-powerpc64",
    .page_shift = FIXME,
    .alloc_magic_pages = alloc_magic_pages,
    .start_info = start_info,
    .shared_info = shared_info,
    .vcpu = vcpu,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_arch);
}
