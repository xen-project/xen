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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2011, Citrix Systems
 */
#include <inttypes.h>
#include <assert.h>

#include <xen/xen.h>
#include <xen/io/protocols.h>
#include <xen-tools/libs.h>

#include "xg_private.h"
#include "xc_dom.h"

#define NR_MAGIC_PAGES 4
#define CONSOLE_PFN_OFFSET 0
#define XENSTORE_PFN_OFFSET 1
#define MEMACCESS_PFN_OFFSET 2
#define VUART_PFN_OFFSET 3

#define LPAE_SHIFT 9

#define PFN_4K_SHIFT  (0)
#define PFN_2M_SHIFT  (PFN_4K_SHIFT+LPAE_SHIFT)
#define PFN_1G_SHIFT  (PFN_2M_SHIFT+LPAE_SHIFT)
#define PFN_512G_SHIFT (PFN_1G_SHIFT+LPAE_SHIFT)

/* get guest IO ABI protocol */
const char *xc_domain_get_native_protocol(xc_interface *xch,
                                          uint32_t domid)
{
    return XEN_IO_PROTO_ABI_ARM;
}

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    int rc, i;
    const xen_pfn_t base = GUEST_MAGIC_BASE >> XC_PAGE_SHIFT;
    xen_pfn_t p2m[NR_MAGIC_PAGES];

    BUILD_BUG_ON(NR_MAGIC_PAGES > GUEST_MAGIC_SIZE >> XC_PAGE_SHIFT);

    DOMPRINTF_CALLED(dom->xch);

    for (i = 0; i < NR_MAGIC_PAGES; i++)
        p2m[i] = base + i;

    rc = xc_domain_populate_physmap_exact(
            dom->xch, dom->guest_domid, NR_MAGIC_PAGES,
            0, 0, p2m);
    if ( rc < 0 )
        return rc;

    dom->console_pfn = base + CONSOLE_PFN_OFFSET;
    dom->xenstore_pfn = base + XENSTORE_PFN_OFFSET;
    dom->vuart_gfn = base + VUART_PFN_OFFSET;

    xc_clear_domain_page(dom->xch, dom->guest_domid, dom->console_pfn);
    xc_clear_domain_page(dom->xch, dom->guest_domid, dom->xenstore_pfn);
    xc_clear_domain_page(dom->xch, dom->guest_domid, base + MEMACCESS_PFN_OFFSET);
    xc_clear_domain_page(dom->xch, dom->guest_domid, dom->vuart_gfn);

    xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_CONSOLE_PFN,
            dom->console_pfn);
    xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_STORE_PFN,
            dom->xenstore_pfn);
    xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_MONITOR_RING_PFN,
            base + MEMACCESS_PFN_OFFSET);
    /* allocated by toolstack */
    xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_CONSOLE_EVTCHN,
            dom->console_evtchn);
    xc_hvm_param_set(dom->xch, dom->guest_domid, HVM_PARAM_STORE_EVTCHN,
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

static int vcpu_arm32(struct xc_dom_image *dom)
{
    vcpu_guest_context_any_t any_ctx;
    vcpu_guest_context_t *ctxt = &any_ctx.c;
    int rc;

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

    rc = xc_vcpu_setcontext(dom->xch, dom->guest_domid, 0, &any_ctx);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)", __func__, rc);

    return rc;
}

static int vcpu_arm64(struct xc_dom_image *dom)
{
    vcpu_guest_context_any_t any_ctx;
    vcpu_guest_context_t *ctxt = &any_ctx.c;
    int rc;

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

    rc = xc_vcpu_setcontext(dom->xch, dom->guest_domid, 0, &any_ctx);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)", __func__, rc);

    return rc;
}

/* ------------------------------------------------------------------------ */

static int set_mode(xc_interface *xch, uint32_t domid, char *guest_type)
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
    domctl.u.address_size.size = 0;

    for ( i = 0; i < ARRAY_SIZE(types); i++ )
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

/*  >0: success, *nr_pfns set to number actually populated
 *   0: didn't try with this pfn shift (e.g. misaligned base etc)
 *  <0: ERROR
 */
static int populate_one_size(struct xc_dom_image *dom, int pfn_shift,
                             xen_pfn_t base_pfn, xen_pfn_t *nr_pfns,
                             xen_pfn_t *extents)
{
    /* The mask for this level */
    const uint64_t mask = ((uint64_t)1<<(pfn_shift))-1;
    /* The shift, mask and next boundary for the level above this one */
    const int next_shift = pfn_shift + LPAE_SHIFT;
    const uint64_t next_mask = ((uint64_t)1<<next_shift)-1;
    const xen_pfn_t next_boundary
        = (base_pfn + ((uint64_t)1<<next_shift)) & ~next_mask;

    int nr, i, count;
    xen_pfn_t end_pfn = base_pfn + *nr_pfns;

    /* No level zero super pages with current hardware */
    if ( pfn_shift == PFN_512G_SHIFT )
        return 0;

    /* base is misaligned for this level */
    if ( mask & base_pfn )
        return 0;

    /*
     * If base is not aligned at the next level up then try and make
     * it so for next time around.
     */
    if ( (base_pfn & next_mask) && end_pfn > next_boundary )
        end_pfn = next_boundary;

    count = ( end_pfn - base_pfn ) >> pfn_shift;

    /* Nothing to allocate */
    if ( !count )
        return 0;

    for ( i = 0 ; i < count ; i ++ )
        extents[i] = base_pfn + (i<<pfn_shift);

    nr = xc_domain_populate_physmap(dom->xch, dom->guest_domid, count,
                                    pfn_shift, 0, extents);
    if ( nr <= 0 ) return nr;
    DOMPRINTF("%s: populated %#x/%#x entries with shift %d",
              __FUNCTION__, nr, count, pfn_shift);

    *nr_pfns = nr << pfn_shift;

    return 1;
}

static int populate_guest_memory(struct xc_dom_image *dom,
                                 xen_pfn_t base_pfn, xen_pfn_t nr_pfns)
{
    int rc = 0;
    xen_pfn_t allocsz, pfn, *extents;

    extents = calloc(1024*1024,sizeof(xen_pfn_t));
    if ( extents == NULL )
    {
        DOMPRINTF("%s: Unable to allocate extent array", __FUNCTION__);
        return -1;
    }

    DOMPRINTF("%s: populating RAM @ %016"PRIx64"-%016"PRIx64" (%"PRId64"MB)",
              __FUNCTION__,
              (uint64_t)base_pfn << XC_PAGE_SHIFT,
              (uint64_t)(base_pfn + nr_pfns) << XC_PAGE_SHIFT,
              (uint64_t)nr_pfns >> (20-XC_PAGE_SHIFT));

    for ( pfn = 0; pfn < nr_pfns; pfn += allocsz )
    {
        allocsz = min_t(int, 1024*1024, nr_pfns - pfn);
#if 0 /* Enable this to exercise/debug the code which tries to realign
       * to a superpage boundary, by misaligning at the start. */
        if ( pfn == 0 )
        {
            allocsz = 1;
            rc = populate_one_size(dom, PFN_4K_SHIFT,
                                   base_pfn + pfn, &allocsz, extents);
            if (rc < 0) break;
            if (rc > 0) continue;
            /* Failed to allocate a single page? */
            break;
        }
#endif

        rc = populate_one_size(dom, PFN_512G_SHIFT,
                               base_pfn + pfn, &allocsz, extents);
        if ( rc < 0 ) break;
        if ( rc > 0 ) continue;

        rc = populate_one_size(dom, PFN_1G_SHIFT,
                               base_pfn + pfn, &allocsz, extents);
        if ( rc < 0 ) break;
        if ( rc > 0 ) continue;

        rc = populate_one_size(dom, PFN_2M_SHIFT,
                               base_pfn + pfn, &allocsz, extents);
        if ( rc < 0 ) break;
        if ( rc > 0 ) continue;

        rc = populate_one_size(dom, PFN_4K_SHIFT,
                               base_pfn + pfn, &allocsz, extents);
        if ( rc < 0 ) break;
        if ( rc == 0 )
        {
            DOMPRINTF("%s: Not enough RAM", __FUNCTION__);
            errno = ENOMEM;
            rc = -1;
            goto out;
        }
    }

    for ( pfn = 0; pfn < nr_pfns; pfn++ )
        dom->p2m_host[pfn] = base_pfn + pfn;

out:
    free(extents);
    return rc < 0 ? rc : 0;
}

static int meminit(struct xc_dom_image *dom)
{
    int i, rc;
    xen_pfn_t pfn;
    uint64_t modbase;

    uint64_t ramsize = (uint64_t)dom->total_pages << XC_PAGE_SHIFT;

    const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
    const uint64_t bankmax[] = GUEST_RAM_BANK_SIZES;

    /* Convenient */
    const uint64_t kernbase = dom->kernel_seg.vstart;
    const uint64_t kernend = ROUNDUP(dom->kernel_seg.vend, 21/*2MB*/);
    const uint64_t kernsize = kernend - kernbase;
    const uint64_t dtb_size = dom->devicetree_blob ?
        ROUNDUP(dom->devicetree_size, XC_PAGE_SHIFT) : 0;
    const uint64_t ramdisk_size = dom->modules[0].blob ?
        ROUNDUP(dom->modules[0].size, XC_PAGE_SHIFT) : 0;
    const uint64_t modsize = dtb_size + ramdisk_size;
    const uint64_t ram128mb = bankbase[0] + (128<<20);

    xen_pfn_t p2m_size;
    uint64_t bank0end;

    assert(dom->rambase_pfn << XC_PAGE_SHIFT == bankbase[0]);

    if ( modsize + kernsize > bankmax[0] )
    {
        DOMPRINTF("%s: Not enough memory for the kernel+dtb+initrd",
                  __FUNCTION__);
        return -1;
    }

    if ( ramsize == 0 )
    {
        DOMPRINTF("%s: ram size is 0", __FUNCTION__);
        return -1;
    }

    if ( ramsize > GUEST_RAM_MAX )
    {
        DOMPRINTF("%s: ram size is too large for guest address space: "
                  "%"PRIx64" > %llx",
                  __FUNCTION__, ramsize, GUEST_RAM_MAX);
        return -1;
    }

    rc = set_mode(dom->xch, dom->guest_domid, dom->guest_type);
    if ( rc )
        return rc;

    for ( i = 0; ramsize && i < GUEST_RAM_BANKS; i++ )
    {
        uint64_t banksize = ramsize > bankmax[i] ? bankmax[i] : ramsize;

        ramsize -= banksize;

        p2m_size = ( bankbase[i] + banksize - bankbase[0] ) >> XC_PAGE_SHIFT;

        dom->rambank_size[i] = banksize >> XC_PAGE_SHIFT;
    }

    assert(dom->rambank_size[0] != 0);
    assert(ramsize == 0); /* Too much RAM is rejected above */

    dom->p2m_size = p2m_size;
    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) * p2m_size);
    if ( dom->p2m_host == NULL )
        return -EINVAL;
    for ( pfn = 0; pfn < p2m_size; pfn++ )
        dom->p2m_host[pfn] = INVALID_PFN;

    /* setup initial p2m and allocate guest memory */
    for ( i = 0; i < GUEST_RAM_BANKS && dom->rambank_size[i]; i++ )
    {
        if ((rc = populate_guest_memory(dom,
                                        bankbase[i] >> XC_PAGE_SHIFT,
                                        dom->rambank_size[i])))
            return rc;
    }

    /*
     * We try to place dtb+initrd at 128MB or if we have less RAM
     * as high as possible. If there is no space then fallback to
     * just before the kernel.
     *
     * If changing this then consider
     * xen/arch/arm/kernel.c:place_modules as well.
     */
    bank0end = bankbase[0] + ((uint64_t)dom->rambank_size[0] << XC_PAGE_SHIFT);

    if ( bank0end >= ram128mb + modsize && kernend < ram128mb )
        modbase = ram128mb;
    else if ( bank0end - modsize > kernend )
        modbase = bank0end - modsize;
    else if (kernbase - bankbase[0] > modsize )
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
        dom->modules[0].seg.vstart = modbase;
        dom->modules[0].seg.vend = modbase + ramdisk_size;

        DOMPRINTF("%s: ramdisk: 0x%" PRIx64 " -> 0x%" PRIx64 "",
                  __FUNCTION__,
                  dom->modules[0].seg.vstart, dom->modules[0].seg.vend);

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

bool xc_dom_translated(const struct xc_dom_image *dom)
{
    return true;
}

/* ------------------------------------------------------------------------ */

static int bootearly(struct xc_dom_image *dom)
{
    DOMPRINTF("%s: doing nothing", __FUNCTION__);
    return 0;
}

static int bootlate(struct xc_dom_image *dom)
{
    /* XXX
     *   map shared info
     *   map grant tables
     *   setup shared info
     */
    return 0;
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_32 = {
    .guest_type = "xen-3.0-armv7l",
    .native_protocol = XEN_IO_PROTO_ABI_ARM,
    .page_shift = PAGE_SHIFT_ARM,
    .sizeof_pfn = 8,
    .alloc_magic_pages = alloc_magic_pages,
    .start_info = start_info_arm,
    .shared_info = shared_info_arm,
    .vcpu = vcpu_arm32,
    .meminit = meminit,
    .bootearly = bootearly,
    .bootlate = bootlate,
};

static struct xc_dom_arch xc_dom_64 = {
    .guest_type = "xen-3.0-aarch64",
    .native_protocol = XEN_IO_PROTO_ABI_ARM,
    .page_shift = PAGE_SHIFT_ARM,
    .sizeof_pfn = 8,
    .alloc_magic_pages = alloc_magic_pages,
    .start_info = start_info_arm,
    .shared_info = shared_info_arm,
    .vcpu = vcpu_arm64,
    .meminit = meminit,
    .bootearly = bootearly,
    .bootlate = bootlate,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_32);
    xc_dom_register_arch_hooks(&xc_dom_64);
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
