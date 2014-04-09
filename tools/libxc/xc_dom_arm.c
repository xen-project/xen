/*
 * Xen domain builder -- ARM
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
 * Copyright (c) 2011, Citrix Systems
 */
#include <inttypes.h>

#include <xen/xen.h>
#include <xen/io/protocols.h>

#include "xg_private.h"
#include "xc_dom.h"

#define NR_MAGIC_PAGES 2
#define CONSOLE_PFN_OFFSET 0
#define XENSTORE_PFN_OFFSET 1

/* get guest IO ABI protocol */
const char *xc_domain_get_native_protocol(xc_interface *xch,
                                          uint32_t domid)
{
    return XEN_IO_PROTO_ABI_ARM;
}

/* ------------------------------------------------------------------------ */
/*
 * arm guests are hybrid and start off with paging disabled, therefore no
 * pagetables and nothing to do here.
 */
static int count_pgtables_arm(struct xc_dom_image *dom)
{
    DOMPRINTF_CALLED(dom->xch);
    return 0;
}

static int setup_pgtables_arm(struct xc_dom_image *dom)
{
    DOMPRINTF_CALLED(dom->xch);
    return 0;
}

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    int rc, i;
    xen_pfn_t p2m[NR_MAGIC_PAGES];

    DOMPRINTF_CALLED(dom->xch);

    for (i = 0; i < NR_MAGIC_PAGES; i++)
        p2m[i] = dom->rambase_pfn + dom->total_pages + i;

    rc = xc_domain_populate_physmap_exact(
            dom->xch, dom->guest_domid, NR_MAGIC_PAGES,
            0, 0, p2m);
    if ( rc < 0 )
        return rc;

    dom->console_pfn = dom->rambase_pfn + dom->total_pages + CONSOLE_PFN_OFFSET;
    dom->xenstore_pfn = dom->rambase_pfn + dom->total_pages + XENSTORE_PFN_OFFSET;

    xc_clear_domain_page(dom->xch, dom->guest_domid, dom->console_pfn);
    xc_clear_domain_page(dom->xch, dom->guest_domid, dom->xenstore_pfn);
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_CONSOLE_PFN,
            dom->console_pfn);
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_STORE_PFN,
            dom->xenstore_pfn);
    /* allocated by toolstack */
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_CONSOLE_EVTCHN,
            dom->console_evtchn);
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_STORE_EVTCHN,
            dom->xenstore_evtchn);

    return 0;
}

/* ------------------------------------------------------------------------ */

static int start_info_arm(struct xc_dom_image *dom)
{
    DOMPRINTF_CALLED(dom->xch);
    return 0;
}

static int shared_info_arm(struct xc_dom_image *dom, void *ptr)
{
    DOMPRINTF_CALLED(dom->xch);
    return 0;
}

/* ------------------------------------------------------------------------ */

static int vcpu_arm32(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_t *ctxt = ptr;

    DOMPRINTF_CALLED(dom->xch);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->user_regs.pc32 = dom->parms.virt_entry;

    /* Linux boot protocol. See linux.Documentation/arm/Booting. */
    ctxt->user_regs.r0_usr = 0; /* SBZ */
    /* Machine ID: We use DTB therefore no machine id */
    ctxt->user_regs.r1_usr = 0xffffffff;
    /* ATAGS/DTB: We currently require that the guest kernel to be
     * using CONFIG_ARM_APPENDED_DTB. Ensure that r2 does not look
     * like a valid pointer to a set of ATAGS or a DTB.
     */
    ctxt->user_regs.r2_usr = dom->devicetree_blob ?
        dom->devicetree_seg.vstart : 0xffffffff;

    ctxt->sctlr = SCTLR_GUEST_INIT;

    ctxt->ttbr0 = 0;
    ctxt->ttbr1 = 0;
    ctxt->ttbcr = 0; /* Defined Reset Value */

    ctxt->user_regs.cpsr = PSR_GUEST32_INIT;

    ctxt->flags = VGCF_online;

    DOMPRINTF("Initial state CPSR %#"PRIx32" PC %#"PRIx32,
           ctxt->user_regs.cpsr, ctxt->user_regs.pc32);

    return 0;
}

static int vcpu_arm64(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_t *ctxt = ptr;

    DOMPRINTF_CALLED(dom->xch);
    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->user_regs.pc64 = dom->parms.virt_entry;

    /* Linux boot protocol. See linux.Documentation/arm64/booting.txt. */
    ctxt->user_regs.x0 = dom->devicetree_blob ?
        dom->devicetree_seg.vstart : 0xffffffff;
    ctxt->user_regs.x1 = 0;
    ctxt->user_regs.x2 = 0;
    ctxt->user_regs.x3 = 0;

    DOMPRINTF("DTB %"PRIx64, ctxt->user_regs.x0);

    ctxt->sctlr = SCTLR_GUEST_INIT;

    ctxt->ttbr0 = 0;
    ctxt->ttbr1 = 0;
    ctxt->ttbcr = 0; /* Defined Reset Value */

    ctxt->user_regs.cpsr = PSR_GUEST64_INIT;

    ctxt->flags = VGCF_online;

    DOMPRINTF("Initial state CPSR %#"PRIx32" PC %#"PRIx64,
           ctxt->user_regs.cpsr, ctxt->user_regs.pc64);

    return 0;
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_32 = {
    .guest_type = "xen-3.0-armv7l",
    .native_protocol = XEN_IO_PROTO_ABI_ARM,
    .page_shift = PAGE_SHIFT_ARM,
    .sizeof_pfn = 8,
    .alloc_magic_pages = alloc_magic_pages,
    .count_pgtables = count_pgtables_arm,
    .setup_pgtables = setup_pgtables_arm,
    .start_info = start_info_arm,
    .shared_info = shared_info_arm,
    .vcpu = vcpu_arm32,
};

static struct xc_dom_arch xc_dom_64 = {
    .guest_type = "xen-3.0-aarch64",
    .native_protocol = XEN_IO_PROTO_ABI_ARM,
    .page_shift = PAGE_SHIFT_ARM,
    .sizeof_pfn = 8,
    .alloc_magic_pages = alloc_magic_pages,
    .count_pgtables = count_pgtables_arm,
    .setup_pgtables = setup_pgtables_arm,
    .start_info = start_info_arm,
    .shared_info = shared_info_arm,
    .vcpu = vcpu_arm64,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_32);
    xc_dom_register_arch_hooks(&xc_dom_64);
}

static int set_mode(xc_interface *xch, domid_t domid, char *guest_type)
{
    static const struct {
        char           *guest;
        uint32_t        size;
    } types[] = {
        { "xen-3.0-aarch64", 64 },
        { "xen-3.0-armv7l",  32 },
    };
    DECLARE_DOMCTL;
    int i,rc;

    domctl.domain = domid;
    domctl.cmd    = XEN_DOMCTL_set_address_size;
    for ( i = 0; i < sizeof(types)/sizeof(types[0]); i++ )
        if ( !strcmp(types[i].guest, guest_type) )
            domctl.u.address_size.size = types[i].size;
    if ( domctl.u.address_size.size == 0 )
    {
        xc_dom_printf(xch, "%s: warning: unknown guest type %s",
                      __FUNCTION__, guest_type);
        return -EINVAL;
    }

    xc_dom_printf(xch, "%s: guest %s, address size %" PRId32 "", __FUNCTION__,
                  guest_type, domctl.u.address_size.size);
    rc = do_domctl(xch, &domctl);
    if ( rc != 0 )
        xc_dom_printf(xch, "%s: warning: failed (rc=%d)",
                      __FUNCTION__, rc);
    return rc;
}

int arch_setup_meminit(struct xc_dom_image *dom)
{
    int rc;
    xen_pfn_t pfn, allocsz, i;
    uint64_t modbase;

    /* Convenient */
    const uint64_t rambase = dom->rambase_pfn << XC_PAGE_SHIFT;
    const uint64_t ramsize = dom->total_pages << XC_PAGE_SHIFT;
    const uint64_t ramend = rambase + ramsize;
    const uint64_t kernbase = dom->kernel_seg.vstart;
    const uint64_t kernend = ROUNDUP(dom->kernel_seg.vend, 21/*2MB*/);
    const uint64_t kernsize = kernend - kernbase;
    const uint64_t dtb_size = dom->devicetree_blob ?
        ROUNDUP(dom->devicetree_size, XC_PAGE_SHIFT) : 0;
    const uint64_t ramdisk_size = dom->ramdisk_blob ?
        ROUNDUP(dom->ramdisk_size, XC_PAGE_SHIFT) : 0;
    const uint64_t modsize = dtb_size + ramdisk_size;
    const uint64_t ram128mb = rambase + (128<<20);

    if ( modsize + kernsize > ramsize )
    {
        DOMPRINTF("%s: Not enough memory for the kernel+dtb+initrd",
                  __FUNCTION__);
        return -1;
    }

    rc = set_mode(dom->xch, dom->guest_domid, dom->guest_type);
    if ( rc )
        return rc;

    dom->shadow_enabled = 1;

    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) * dom->total_pages);
    if ( dom->p2m_host == NULL )
        return -EINVAL;

    /* setup initial p2m */
    for ( pfn = 0; pfn < dom->total_pages; pfn++ )
        dom->p2m_host[pfn] = pfn + dom->rambase_pfn;

    /* allocate guest memory */
    for ( i = rc = allocsz = 0;
          (i < dom->total_pages) && !rc;
          i += allocsz )
    {
        allocsz = dom->total_pages - i;
        if ( allocsz > 1024*1024 )
            allocsz = 1024*1024;

        rc = xc_domain_populate_physmap_exact(
            dom->xch, dom->guest_domid, allocsz,
            0, 0, &dom->p2m_host[i]);
    }

    /*
     * We try to place dtb+initrd at 128MB or if we have less RAM
     * as high as possible. If there is no space then fallback to
     * just before the kernel.
     *
     * If changing this then consider
     * xen/arch/arm/kernel.c:place_modules as well.
     */
    if ( ramend >= ram128mb + modsize && kernend < ram128mb )
        modbase = ram128mb;
    else if ( ramend - modsize > kernend )
        modbase = ramend - modsize;
    else if (kernbase - rambase > modsize )
        modbase = kernbase - modsize;
    else
        return -1;

    DOMPRINTF("%s: placing boot modules at 0x%" PRIx64, __FUNCTION__, modbase);

    /*
     * Must map DTB *after* initrd, to satisfy order of calls to
     * xc_dom_alloc_segment in xc_dom_build_image, which must map
     * things at monotonolically increasing addresses.
     */
    if ( ramdisk_size )
    {
        dom->ramdisk_seg.vstart = modbase;
        dom->ramdisk_seg.vend = modbase + ramdisk_size;

        DOMPRINTF("%s: ramdisk: 0x%" PRIx64 " -> 0x%" PRIx64 "",
                  __FUNCTION__,
                  dom->ramdisk_seg.vstart, dom->ramdisk_seg.vend);

        modbase += ramdisk_size;
    }

    if ( dtb_size )
    {
        dom->devicetree_seg.vstart = modbase;
        dom->devicetree_seg.vend = modbase + dtb_size;

        DOMPRINTF("%s: devicetree: 0x%" PRIx64 " -> 0x%" PRIx64 "",
                  __FUNCTION__,
                  dom->devicetree_seg.vstart, dom->devicetree_seg.vend);

        modbase += dtb_size;
    }

    return 0;
}

int arch_setup_bootearly(struct xc_dom_image *dom)
{
    DOMPRINTF("%s: doing nothing", __FUNCTION__);
    return 0;
}

int arch_setup_bootlate(struct xc_dom_image *dom)
{
    /* XXX
     *   map shared info
     *   map grant tables
     *   setup shared info
     */
    return 0;
}

int xc_dom_feature_translated(struct xc_dom_image *dom)
{
    return 1;
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
