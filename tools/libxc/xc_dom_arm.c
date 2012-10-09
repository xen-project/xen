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
    xen_pfn_t store_pfn, console_pfn, p2m[NR_MAGIC_PAGES];

    DOMPRINTF_CALLED(dom->xch);

    for (i = 0; i < NR_MAGIC_PAGES; i++)
        p2m[i] = dom->rambase_pfn + dom->total_pages + i;

    rc = xc_domain_populate_physmap_exact(
            dom->xch, dom->guest_domid, NR_MAGIC_PAGES,
            0, 0, p2m);
    if ( rc < 0 )
        return rc;

    console_pfn = dom->rambase_pfn + dom->total_pages + CONSOLE_PFN_OFFSET;
    store_pfn = dom->rambase_pfn + dom->total_pages + XENSTORE_PFN_OFFSET;

    xc_clear_domain_page(dom->xch, dom->guest_domid, console_pfn);
    xc_clear_domain_page(dom->xch, dom->guest_domid, store_pfn);
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_CONSOLE_PFN,
            console_pfn);
    xc_set_hvm_param(dom->xch, dom->guest_domid, HVM_PARAM_STORE_PFN,
            store_pfn);

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

static int vcpu_arm(struct xc_dom_image *dom, void *ptr)
{
    vcpu_guest_context_t *ctxt = ptr;

    DOMPRINTF_CALLED(dom->xch);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->user_regs.pc = dom->parms.virt_entry;

    /* Linux boot protocol. See linux.Documentation/arm/Booting. */
    ctxt->user_regs.r0 = 0; /* SBZ */
    /* Machine ID: We use DTB therefore no machine id */
    ctxt->user_regs.r1 = 0xffffffff;
    /* ATAGS/DTB: We currently require that the guest kernel to be
     * using CONFIG_ARM_APPENDED_DTB. Ensure that r2 does not look
     * like a valid pointer to a set of ATAGS or a DTB.
     */
    ctxt->user_regs.r2 = 0xffffffff;

    ctxt->sctlr = /* #define SCTLR_BASE */0x00c50078;

    ctxt->ttbr0 = 0;
    ctxt->ttbr1 = 0;
    ctxt->ttbcr = 0; /* Defined Reset Value */

    ctxt->user_regs.cpsr = PSR_ABT_MASK|PSR_FIQ_MASK|PSR_IRQ_MASK|PSR_MODE_SVC;

    ctxt->flags = VGCF_online;

    DOMPRINTF("Initial state CPSR %#"PRIx32" PC %#"PRIx32,
           ctxt->user_regs.cpsr, ctxt->user_regs.pc);

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
    .vcpu = vcpu_arm,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_32);
}

int arch_setup_meminit(struct xc_dom_image *dom)
{
    int rc;
    xen_pfn_t pfn, allocsz, i;

    dom->shadow_enabled = 1;

    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) * dom->total_pages);

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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
