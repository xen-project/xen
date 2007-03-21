/*
 * Xen domain builder -- powerpc bits.
 *
 * Most architecture-specific code for powerpc goes here.
 *
 * This code is licenced under the GPL.
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors: Gerd Hoffmann <kraxel@suse.de>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <xen/xen.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "powerpc64/flatdevtree.h"
#include "powerpc64/mk_flatdevtree.h"

#define RMA_LOG 26 /* 64 MB */
#define EXTENT_LOG 24 /* 16 MB */
#define EXTENT_ORDER (EXTENT_LOG - PAGE_SHIFT)

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    struct ft_cxt devtree;
    void *guest_devtree;
    unsigned long shadow_mb;
    int rma_pages;
    int rc;

    /* Allocate special pages from the end of the RMA. */
    rma_pages = 1 << (dom->realmodearea_log - PAGE_SHIFT);
    dom->shared_info_pfn = --rma_pages;
    dom->console_pfn = --rma_pages;
    dom->xenstore_pfn = --rma_pages;

    /* Gather shadow allocation info for the device tree. */
    rc = xc_shadow_control(dom->guest_xc, dom->guest_domid,
                           XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION, NULL, 0, 
                           &shadow_mb, 0, NULL);
    if (rc < 0 || shadow_mb == 0) {
        xc_dom_printf("Couldn't get shadow allocation size or it was 0.\n");
        return rc;
    }

    /* Build device tree. */
    rc = make_devtree(&devtree, dom, shadow_mb);
    if (rc < 0) {
        xc_dom_printf("Failed to create flattened device tree.\n");
        return rc;
    }

    /* Find a spot for it. */
    rc = xc_dom_alloc_segment(dom, &dom->devicetree_seg, "devtree", 0,
                              devtree.bph->totalsize);
    if (rc)
        goto out;

    /* Copy the device tree into place. */
    guest_devtree = xc_dom_seg_to_ptr(dom, &dom->devicetree_seg);
    if (!guest_devtree) {
        xc_dom_printf("Couldn't map guest memory for device tree.\n");
        rc = -1;
        goto out;
    }
    memcpy(guest_devtree, devtree.bph, devtree.bph->totalsize);

out:
    free_devtree(&devtree);
    return rc;
}

static int shared_info(struct xc_dom_image *dom, void *ptr)
{
    shared_info_t *shared_info = ptr;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    memset(shared_info, 0, sizeof(*shared_info));
    return 0;
}

static int vcpu(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_t *ctxt = ptr;

    memset(ctxt, 0x55, sizeof(*ctxt));
    ctxt->user_regs.pc = dom->parms.virt_entry;
    ctxt->user_regs.msr = 0;
    ctxt->user_regs.gprs[1] = 0; /* Linux uses its own stack */
    ctxt->user_regs.gprs[3] = dom->devicetree_seg.pfn << PAGE_SHIFT;
    ctxt->user_regs.gprs[4] = dom->kernel_seg.pfn << PAGE_SHIFT;
    ctxt->user_regs.gprs[5] = 0;

    /* There is a buggy kernel that does not zero the "local_paca", so
     * we must make sure this register is 0 */
    ctxt->user_regs.gprs[13] = 0;

    xc_dom_printf("%s: initial vcpu:\n", __FUNCTION__);
    xc_dom_printf("  pc 0x%016"PRIx64", msr 0x%016"PRIx64"\n"
                  "  r1-5 %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64
                  " %016"PRIx64"\n",
                  ctxt->user_regs.pc, ctxt->user_regs.msr,
                  ctxt->user_regs.gprs[1],
                  ctxt->user_regs.gprs[2],
                  ctxt->user_regs.gprs[3],
                  ctxt->user_regs.gprs[4],
                  ctxt->user_regs.gprs[5]);

    return 0;
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_arch = {
    .guest_type = "xen-3.0-powerpc64",
    .page_shift = PAGE_SHIFT,
    .alloc_magic_pages = alloc_magic_pages,
    .shared_info = shared_info,
    .vcpu = vcpu,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_arch);
}

int arch_setup_meminit(struct xc_dom_image *dom)
{
    xen_pfn_t *extent_list;
    unsigned long total_mem = dom->total_pages << PAGE_SHIFT;
    unsigned long rma_bytes;
    unsigned long rma_nr_pages;
    unsigned long nr_extents;
    int rc = 0;
    int i;

    /* XXX RMA size is processor-dependent. */
    dom->realmodearea_log = RMA_LOG;
    rma_bytes = 1 << dom->realmodearea_log;
    rma_nr_pages = rma_bytes >> PAGE_SHIFT;

    xc_dom_printf("dom%u memory: %lu MB RMA, %lu MB additional.\n",
            dom->guest_domid, rma_bytes >> 20, (total_mem - rma_bytes) >> 20);

    if (total_mem < rma_bytes) {
        xc_dom_printf("Domain must have at least %lu MB\n", rma_bytes >> 20);
        return -EINVAL;
    }

    /* Allocate the first chunk of memory. */
    rc = xc_alloc_real_mode_area(dom->guest_xc, dom->guest_domid,
                                 dom->realmodearea_log);
    if (rc) {
        xc_dom_printf("Failed to allocate real mode area.\n");
        return rc;
    }

    /* Allocate p2m map. */
    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) * dom->total_pages);
    if (dom->p2m_host == NULL) {
        xc_dom_printf("Couldn't allocate p2m map.\n");
        return -ENOMEM;
    }

    nr_extents = (dom->total_pages - rma_nr_pages) >> EXTENT_ORDER;
    if (nr_extents) {
        /* Allocate extent list for populate_physmap() call. */
        extent_list = xc_dom_malloc(dom, sizeof(xen_pfn_t) * nr_extents);
        if (extent_list == NULL) {
            xc_dom_printf("Couldn't allocate extent list.\n");
            return -ENOMEM;
        }

        /* Allocate the remaining (non-RMA) memory. */
        for (i = 0; i < nr_extents; i++) {
            /* Use PFNs above the RMA memory we already allocated. */
            extent_list[i] = rma_nr_pages + i * (1<<EXTENT_ORDER);
        }
        rc = xc_domain_memory_populate_physmap(dom->guest_xc, dom->guest_domid,
                                               nr_extents, EXTENT_ORDER, 0,
                                               extent_list);
        if (rc < 0) {
            xc_dom_printf("populate_physmap(0x%lx extents order %u) -> 0x%x\n",
                          nr_extents, EXTENT_ORDER, rc);
            return rc;
        }
    }

    /* Populate the p2m map. */
    rc = xc_get_pfn_list(dom->guest_xc, dom->guest_domid, dom->p2m_host,
                         dom->total_pages);
    if (rc < 0) {
        xc_dom_printf("Couldn't get p2m translation.\n");
        return rc;
    }

    xc_dom_printf("%s: success\n", __func__);

    return 0;
}

int arch_setup_bootearly(struct xc_dom_image *dom)
{
    xc_dom_printf("%s: doing nothing\n", __FUNCTION__);
    return 0;
}

int arch_setup_bootlate(struct xc_dom_image *dom)
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
