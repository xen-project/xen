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
#include <xen/foreign/ia64.h>

#include "xg_private.h"
#include "xc_dom.h"

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    /* allocate special pages */
    dom->console_pfn = dom->total_pages -1;
    dom->xenstore_pfn = dom->total_pages -2;
    dom->start_info_pfn = dom->total_pages -3;
    return 0;
}

static int start_info_ia64(struct xc_dom_image *dom)
{
    start_info_ia64_t *start_info =
	xc_dom_pfn_to_ptr(dom, dom->start_info_pfn, 1);
    struct xen_ia64_boot_param_ia64 *bp =
	(struct xen_ia64_boot_param_ia64 *)(start_info + 1);

    xc_dom_printf("%s\n", __FUNCTION__);

    memset(start_info, 0, sizeof(*start_info));
    sprintf(start_info->magic, dom->guest_type);
    start_info->flags = dom->flags;
    start_info->nr_pages = dom->total_pages;
    start_info->store_mfn = dom->xenstore_pfn;
    start_info->store_evtchn = dom->xenstore_evtchn;
    start_info->console.domU.mfn = dom->console_pfn;
    start_info->console.domU.evtchn = dom->console_evtchn;

    if (dom->ramdisk_blob)
    {
	start_info->mod_start = dom->ramdisk_seg.vstart;
	start_info->mod_len = dom->ramdisk_seg.vend - dom->ramdisk_seg.vstart;
	bp->initrd_start = start_info->mod_start;
	bp->initrd_size = start_info->mod_len;
    }
    bp->command_line = (dom->start_info_pfn << PAGE_SHIFT_IA64)
	    + offsetof(start_info_t, cmd_line);
    if (dom->cmdline)
    {
	strncpy((char *)start_info->cmd_line, dom->cmdline, MAX_GUEST_CMDLINE);
	start_info->cmd_line[MAX_GUEST_CMDLINE - 1] = '\0';
    }
    return 0;
}

static int shared_info_ia64(struct xc_dom_image *dom, void *ptr)
{
    shared_info_ia64_t *shared_info = ptr;
    int i;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    memset(shared_info, 0, sizeof(*shared_info));
    for (i = 0; i < MAX_VIRT_CPUS; i++)
	shared_info->vcpu_info[i].evtchn_upcall_mask = 1;
    shared_info->arch.start_info_pfn = dom->start_info_pfn;
    return 0;
}

extern unsigned long xc_ia64_fpsr_default(void);

static int vcpu_ia64(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_ia64_t *ctxt = ptr;

    xc_dom_printf("%s: called\n", __FUNCTION__);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->flags = 0;
    ctxt->user_regs.cr_ipsr = 0;	/* all necessary bits filled by hypervisor */
    ctxt->user_regs.cr_iip = dom->parms.virt_entry;
    ctxt->user_regs.cr_ifs = (uint64_t) 1 << 63;
#ifdef __ia64__			/* FIXME */
    ctxt->user_regs.ar_fpsr = xc_ia64_fpsr_default();
#endif
    ctxt->user_regs.r28 = (dom->start_info_pfn << PAGE_SHIFT_IA64)
	+ sizeof(start_info_ia64_t);
    return 0;
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_arch = {
    .guest_type = "xen-3.0-ia64",
    .page_shift = PAGE_SHIFT_IA64,
    .alloc_magic_pages = alloc_magic_pages,
    .start_info = start_info_ia64,
    .shared_info = shared_info_ia64,
    .vcpu = vcpu_ia64,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_arch);
}
