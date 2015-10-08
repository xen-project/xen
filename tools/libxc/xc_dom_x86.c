/*
 * Xen domain builder -- i386 and x86_64 bits.
 *
 * Most architecture-specific code for x86 goes here.
 *   - prepare page tables.
 *   - fill architecture-specific structs.
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

#include <xen/xen.h>
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/hvm_info_table.h>
#include <xen/io/protocols.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "xenctrl.h"

/* ------------------------------------------------------------------------ */

#define SUPERPAGE_BATCH_SIZE 512

#define SUPERPAGE_2MB_SHIFT   9
#define SUPERPAGE_2MB_NR_PFNS (1UL << SUPERPAGE_2MB_SHIFT)
#define SUPERPAGE_1GB_SHIFT   18
#define SUPERPAGE_1GB_NR_PFNS (1UL << SUPERPAGE_1GB_SHIFT)

#define X86_CR0_PE 0x01
#define X86_CR0_ET 0x10

#define VGA_HOLE_SIZE (0x20)

#define SPECIALPAGE_PAGING   0
#define SPECIALPAGE_ACCESS   1
#define SPECIALPAGE_SHARING  2
#define SPECIALPAGE_BUFIOREQ 3
#define SPECIALPAGE_XENSTORE 4
#define SPECIALPAGE_IOREQ    5
#define SPECIALPAGE_IDENT_PT 6
#define SPECIALPAGE_CONSOLE  7
#define NR_SPECIAL_PAGES     8
#define special_pfn(x) (0xff000u - NR_SPECIAL_PAGES + (x))

#define NR_IOREQ_SERVER_PAGES 8
#define ioreq_server_pfn(x) (special_pfn(0) - NR_IOREQ_SERVER_PAGES + (x))

#define bits_to_mask(bits)       (((xen_vaddr_t)1 << (bits))-1)
#define round_down(addr, mask)   ((addr) & ~(mask))
#define round_up(addr, mask)     ((addr) | (mask))

/* get guest IO ABI protocol */
const char *xc_domain_get_native_protocol(xc_interface *xch,
                                          uint32_t domid)
{
    int ret;
    uint32_t guest_width;
    const char *protocol;

    ret = xc_domain_get_guest_width(xch, domid, &guest_width);

    if ( ret )
        return NULL;

    switch (guest_width) {
    case 4: /* 32 bit guest */
        protocol = XEN_IO_PROTO_ABI_X86_32;
        break;
    case 8: /* 64 bit guest */
        protocol = XEN_IO_PROTO_ABI_X86_64;
        break;
    default:
        protocol = NULL;
    }

    return protocol;
}

static unsigned long
nr_page_tables(struct xc_dom_image *dom,
               xen_vaddr_t start, xen_vaddr_t end, unsigned long bits)
{
    xen_vaddr_t mask = bits_to_mask(bits);
    int tables;

    if ( bits == 0 )
        return 0;  /* unused */

    if ( bits == (8 * sizeof(unsigned long)) )
    {
        /* must be pgd, need one */
        start = 0;
        end = -1;
        tables = 1;
    }
    else
    {
        start = round_down(start, mask);
        end = round_up(end, mask);
        tables = ((end - start) >> bits) + 1;
    }

    DOMPRINTF("%s: 0x%016" PRIx64 "/%ld: 0x%016" PRIx64
              " -> 0x%016" PRIx64 ", %d table(s)",
              __FUNCTION__, mask, bits, start, end, tables);
    return tables;
}

static int count_pgtables(struct xc_dom_image *dom, int pae,
                          int l4_bits, int l3_bits, int l2_bits, int l1_bits)
{
    int pages, extra_pages;
    xen_vaddr_t try_virt_end;
    xen_pfn_t try_pfn_end;

    extra_pages = dom->alloc_bootstack ? 1 : 0;
    extra_pages += dom->extra_pages;
    extra_pages += 128; /* 512kB padding */
    pages = extra_pages;
    for ( ; ; )
    {
        try_virt_end = round_up(dom->virt_alloc_end + pages * PAGE_SIZE_X86,
                                bits_to_mask(22)); /* 4MB alignment */

        try_pfn_end = (try_virt_end - dom->parms.virt_base) >> PAGE_SHIFT_X86;

        if ( try_pfn_end > dom->p2m_size )
        {
            xc_dom_panic(dom->xch, XC_OUT_OF_MEMORY,
                         "%s: not enough memory for initial mapping (%#"PRIpfn" > %#"PRIpfn")",
                         __FUNCTION__, try_pfn_end, dom->p2m_size);
            return -ENOMEM;
        }

        dom->pg_l4 =
            nr_page_tables(dom, dom->parms.virt_base, try_virt_end, l4_bits);
        dom->pg_l3 =
            nr_page_tables(dom, dom->parms.virt_base, try_virt_end, l3_bits);
        dom->pg_l2 =
            nr_page_tables(dom, dom->parms.virt_base, try_virt_end, l2_bits);
        dom->pg_l1 =
            nr_page_tables(dom, dom->parms.virt_base, try_virt_end, l1_bits);
        if (pae && try_virt_end < 0xc0000000)
        {
            DOMPRINTF("%s: PAE: extra l2 page table for l3#3",
                      __FUNCTION__);
            dom->pg_l2++;
        }
        dom->pgtables = dom->pg_l4 + dom->pg_l3 + dom->pg_l2 + dom->pg_l1;
        pages = dom->pgtables + extra_pages;
        if ( dom->virt_alloc_end + pages * PAGE_SIZE_X86 <= try_virt_end + 1 )
            break;
    }
    dom->virt_pgtab_end = try_virt_end + 1;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* i386 pagetables                                                          */

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT)

static int count_pgtables_x86_32_pae(struct xc_dom_image *dom)
{
    return count_pgtables(dom, 1, 0, 32,
                          L3_PAGETABLE_SHIFT_PAE, L2_PAGETABLE_SHIFT_PAE);
}

#define pfn_to_paddr(pfn) ((xen_paddr_t)(pfn) << PAGE_SHIFT_X86)

/*
 * Move the l3 page table page below 4G for guests which do not
 * support the extended-cr3 format.  The l3 is currently empty so we
 * do not need to preserve the current contents.
 */
static xen_pfn_t move_l3_below_4G(struct xc_dom_image *dom,
                                  xen_pfn_t l3pfn,
                                  xen_pfn_t l3mfn)
{
    xen_pfn_t new_l3mfn;
    struct xc_mmu *mmu;
    void *l3tab;

    mmu = xc_alloc_mmu_updates(dom->xch, dom->guest_domid);
    if ( mmu == NULL )
    {
        DOMPRINTF("%s: failed at %d", __FUNCTION__, __LINE__);
        return l3mfn;
    }

    xc_dom_unmap_one(dom, l3pfn);

    new_l3mfn = xc_make_page_below_4G(dom->xch, dom->guest_domid, l3mfn);
    if ( !new_l3mfn )
        goto out;

    dom->p2m_host[l3pfn] = new_l3mfn;
    if ( xc_dom_update_guest_p2m(dom) != 0 )
        goto out;

    if ( xc_add_mmu_update(dom->xch, mmu,
                           (((unsigned long long)new_l3mfn)
                            << XC_DOM_PAGE_SHIFT(dom)) |
                           MMU_MACHPHYS_UPDATE, l3pfn) )
        goto out;

    if ( xc_flush_mmu_updates(dom->xch, mmu) )
        goto out;

    /*
     * This ensures that the entire pgtables_seg is mapped by a single
     * mmap region. arch_setup_bootlate() relies on this to be able to
     * unmap and pin the pagetables.
     */
    if ( xc_dom_seg_to_ptr(dom, &dom->pgtables_seg) == NULL )
        goto out;

    l3tab = xc_dom_pfn_to_ptr(dom, l3pfn, 1);
    if ( l3tab == NULL )
    {
        DOMPRINTF("%s: xc_dom_pfn_to_ptr(dom, l3pfn, 1) => NULL",
                  __FUNCTION__);
        goto out; /* our one call site will call xc_dom_panic and fail */
    }
    memset(l3tab, 0, XC_DOM_PAGE_SIZE(dom));

    DOMPRINTF("%s: successfully relocated L3 below 4G. "
              "(L3 PFN %#"PRIpfn" MFN %#"PRIpfn"=>%#"PRIpfn")",
              __FUNCTION__, l3pfn, l3mfn, new_l3mfn);

    l3mfn = new_l3mfn;

 out:
    free(mmu);

    return l3mfn;
}

static int setup_pgtables_x86_32_pae(struct xc_dom_image *dom)
{
    xen_pfn_t l3pfn = dom->pgtables_seg.pfn;
    xen_pfn_t l2pfn = l3pfn + dom->pg_l3;
    xen_pfn_t l1pfn = l2pfn + dom->pg_l2;
    l3_pgentry_64_t *l3tab;
    l2_pgentry_64_t *l2tab = NULL;
    l1_pgentry_64_t *l1tab = NULL;
    unsigned long l3off, l2off = 0, l1off;
    xen_vaddr_t addr;
    xen_pfn_t pgpfn;
    xen_pfn_t l3mfn = xc_dom_p2m(dom, l3pfn);

    if ( dom->parms.pae == XEN_PAE_YES )
    {
        if ( l3mfn >= 0x100000 )
            l3mfn = move_l3_below_4G(dom, l3pfn, l3mfn);

        if ( l3mfn >= 0x100000 )
        {
            xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,"%s: cannot move L3"
                         " below 4G. extended-cr3 not supported by guest. "
                         "(L3 PFN %#"PRIpfn" MFN %#"PRIpfn")",
                         __FUNCTION__, l3pfn, l3mfn);
            return -EINVAL;
        }
    }

    l3tab = xc_dom_pfn_to_ptr(dom, l3pfn, 1);
    if ( l3tab == NULL )
        goto pfn_error;

    for ( addr = dom->parms.virt_base; addr < dom->virt_pgtab_end;
          addr += PAGE_SIZE_X86 )
    {
        if ( l2tab == NULL )
        {
            /* get L2 tab, make L3 entry */
            l2tab = xc_dom_pfn_to_ptr(dom, l2pfn, 1);
            if ( l2tab == NULL )
                goto pfn_error;
            l3off = l3_table_offset_pae(addr);
            l3tab[l3off] =
                pfn_to_paddr(xc_dom_p2m(dom, l2pfn)) | L3_PROT;
            l2pfn++;
        }

        if ( l1tab == NULL )
        {
            /* get L1 tab, make L2 entry */
            l1tab = xc_dom_pfn_to_ptr(dom, l1pfn, 1);
            if ( l1tab == NULL )
                goto pfn_error;
            l2off = l2_table_offset_pae(addr);
            l2tab[l2off] =
                pfn_to_paddr(xc_dom_p2m(dom, l1pfn)) | L2_PROT;
            l1pfn++;
        }

        /* make L1 entry */
        l1off = l1_table_offset_pae(addr);
        pgpfn = (addr - dom->parms.virt_base) >> PAGE_SHIFT_X86;
        l1tab[l1off] =
            pfn_to_paddr(xc_dom_p2m(dom, pgpfn)) | L1_PROT;
        if ( (!dom->pvh_enabled)                &&
             (addr >= dom->pgtables_seg.vstart) &&
             (addr < dom->pgtables_seg.vend) )
            l1tab[l1off] &= ~_PAGE_RW; /* page tables are r/o */

        if ( l1off == (L1_PAGETABLE_ENTRIES_PAE - 1) )
        {
            l1tab = NULL;
            if ( l2off == (L2_PAGETABLE_ENTRIES_PAE - 1) )
                l2tab = NULL;
        }
    }

    if ( dom->virt_pgtab_end <= 0xc0000000 )
    {
        DOMPRINTF("%s: PAE: extra l2 page table for l3#3", __FUNCTION__);
        l3tab[3] = pfn_to_paddr(xc_dom_p2m(dom, l2pfn)) | L3_PROT;
    }
    return 0;

pfn_error:
    xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                 "%s: xc_dom_pfn_to_ptr failed", __FUNCTION__);
    return -EINVAL;
}

#undef L1_PROT
#undef L2_PROT
#undef L3_PROT

/* ------------------------------------------------------------------------ */
/* x86_64 pagetables                                                        */

static int count_pgtables_x86_64(struct xc_dom_image *dom)
{
    return count_pgtables(dom, 0,
                          L4_PAGETABLE_SHIFT_X86_64 + 9,
                          L4_PAGETABLE_SHIFT_X86_64,
                          L3_PAGETABLE_SHIFT_X86_64,
                          L2_PAGETABLE_SHIFT_X86_64);
}

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

static int setup_pgtables_x86_64(struct xc_dom_image *dom)
{
    xen_pfn_t l4pfn = dom->pgtables_seg.pfn;
    xen_pfn_t l3pfn = l4pfn + dom->pg_l4;
    xen_pfn_t l2pfn = l3pfn + dom->pg_l3;
    xen_pfn_t l1pfn = l2pfn + dom->pg_l2;
    l4_pgentry_64_t *l4tab = xc_dom_pfn_to_ptr(dom, l4pfn, 1);
    l3_pgentry_64_t *l3tab = NULL;
    l2_pgentry_64_t *l2tab = NULL;
    l1_pgentry_64_t *l1tab = NULL;
    uint64_t l4off, l3off = 0, l2off = 0, l1off;
    uint64_t addr;
    xen_pfn_t pgpfn;

    if ( l4tab == NULL )
        goto pfn_error;

    for ( addr = dom->parms.virt_base; addr < dom->virt_pgtab_end;
          addr += PAGE_SIZE_X86 )
    {
        if ( l3tab == NULL )
        {
            /* get L3 tab, make L4 entry */
            l3tab = xc_dom_pfn_to_ptr(dom, l3pfn, 1);
            if ( l3tab == NULL )
                goto pfn_error;
            l4off = l4_table_offset_x86_64(addr);
            l4tab[l4off] =
                pfn_to_paddr(xc_dom_p2m(dom, l3pfn)) | L4_PROT;
            l3pfn++;
        }

        if ( l2tab == NULL )
        {
            /* get L2 tab, make L3 entry */
            l2tab = xc_dom_pfn_to_ptr(dom, l2pfn, 1);
            if ( l2tab == NULL )
                goto pfn_error;
            l3off = l3_table_offset_x86_64(addr);
            l3tab[l3off] =
                pfn_to_paddr(xc_dom_p2m(dom, l2pfn)) | L3_PROT;
            l2pfn++;
        }

        if ( l1tab == NULL )
        {
            /* get L1 tab, make L2 entry */
            l1tab = xc_dom_pfn_to_ptr(dom, l1pfn, 1);
            if ( l1tab == NULL )
                goto pfn_error;
            l2off = l2_table_offset_x86_64(addr);
            l2tab[l2off] =
                pfn_to_paddr(xc_dom_p2m(dom, l1pfn)) | L2_PROT;
            l1pfn++;
        }

        /* make L1 entry */
        l1off = l1_table_offset_x86_64(addr);
        pgpfn = (addr - dom->parms.virt_base) >> PAGE_SHIFT_X86;
        l1tab[l1off] =
            pfn_to_paddr(xc_dom_p2m(dom, pgpfn)) | L1_PROT;
        if ( (!dom->pvh_enabled)                &&
             (addr >= dom->pgtables_seg.vstart) &&
             (addr < dom->pgtables_seg.vend) )
            l1tab[l1off] &= ~_PAGE_RW; /* page tables are r/o */

        if ( l1off == (L1_PAGETABLE_ENTRIES_X86_64 - 1) )
        {
            l1tab = NULL;
            if ( l2off == (L2_PAGETABLE_ENTRIES_X86_64 - 1) )
            {
                l2tab = NULL;
                if ( l3off == (L3_PAGETABLE_ENTRIES_X86_64 - 1) )
                    l3tab = NULL;
            }
        }
    }
    return 0;

pfn_error:
    xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                 "%s: xc_dom_pfn_to_ptr failed", __FUNCTION__);
    return -EINVAL;
}

#undef L1_PROT
#undef L2_PROT
#undef L3_PROT
#undef L4_PROT

/* ------------------------------------------------------------------------ */

static int alloc_magic_pages(struct xc_dom_image *dom)
{
    size_t p2m_alloc_size = dom->p2m_size * dom->arch_hooks->sizeof_pfn;

    /* allocate phys2mach table */
    if ( xc_dom_alloc_segment(dom, &dom->p2m_seg, "phys2mach",
                              0, p2m_alloc_size) )
        return -1;
    dom->p2m_guest = xc_dom_seg_to_ptr(dom, &dom->p2m_seg);
    if ( dom->p2m_guest == NULL )
        return -1;

    /* allocate special pages */
    dom->start_info_pfn = xc_dom_alloc_page(dom, "start info");
    dom->xenstore_pfn = xc_dom_alloc_page(dom, "xenstore");
    dom->console_pfn = xc_dom_alloc_page(dom, "console");
    if ( xc_dom_feature_translated(dom) )
        dom->shared_info_pfn = xc_dom_alloc_page(dom, "shared info");
    dom->alloc_bootstack = 1;

    return 0;
}

static void build_hvm_info(void *hvm_info_page, struct xc_dom_image *dom)
{
    struct hvm_info_table *hvm_info = (struct hvm_info_table *)
        (((unsigned char *)hvm_info_page) + HVM_INFO_OFFSET);
    uint8_t sum;
    int i;

    memset(hvm_info_page, 0, PAGE_SIZE);

    /* Fill in the header. */
    memcpy(hvm_info->signature, "HVM INFO", sizeof(hvm_info->signature));
    hvm_info->length = sizeof(struct hvm_info_table);

    /* Sensible defaults: these can be overridden by the caller. */
    hvm_info->apic_mode = 1;
    hvm_info->nr_vcpus = 1;
    memset(hvm_info->vcpu_online, 0xff, sizeof(hvm_info->vcpu_online));

    /* Memory parameters. */
    hvm_info->low_mem_pgend = dom->lowmem_end >> PAGE_SHIFT;
    hvm_info->high_mem_pgend = dom->highmem_end >> PAGE_SHIFT;
    hvm_info->reserved_mem_pgstart = ioreq_server_pfn(0);

    /* Finish with the checksum. */
    for ( i = 0, sum = 0; i < hvm_info->length; i++ )
        sum += ((uint8_t *)hvm_info)[i];
    hvm_info->checksum = -sum;
}

static int alloc_magic_pages_hvm(struct xc_dom_image *dom)
{
    unsigned long i;
    void *hvm_info_page;
    uint32_t *ident_pt, domid = dom->guest_domid;
    int rc;
    xen_pfn_t special_array[NR_SPECIAL_PAGES];
    xen_pfn_t ioreq_server_array[NR_IOREQ_SERVER_PAGES];
    xc_interface *xch = dom->xch;

    if ( (hvm_info_page = xc_map_foreign_range(
              xch, domid, PAGE_SIZE, PROT_READ | PROT_WRITE,
              HVM_INFO_PFN)) == NULL )
        goto error_out;
    build_hvm_info(hvm_info_page, dom);
    munmap(hvm_info_page, PAGE_SIZE);

    /* Allocate and clear special pages. */
    for ( i = 0; i < NR_SPECIAL_PAGES; i++ )
        special_array[i] = special_pfn(i);

    rc = xc_domain_populate_physmap_exact(xch, domid, NR_SPECIAL_PAGES, 0, 0,
                                          special_array);
    if ( rc != 0 )
    {
        DOMPRINTF("Could not allocate special pages.");
        goto error_out;
    }

    if ( xc_clear_domain_pages(xch, domid, special_pfn(0), NR_SPECIAL_PAGES) )
            goto error_out;

    xc_hvm_param_set(xch, domid, HVM_PARAM_STORE_PFN,
                     special_pfn(SPECIALPAGE_XENSTORE));
    xc_hvm_param_set(xch, domid, HVM_PARAM_BUFIOREQ_PFN,
                     special_pfn(SPECIALPAGE_BUFIOREQ));
    xc_hvm_param_set(xch, domid, HVM_PARAM_IOREQ_PFN,
                     special_pfn(SPECIALPAGE_IOREQ));
    xc_hvm_param_set(xch, domid, HVM_PARAM_CONSOLE_PFN,
                     special_pfn(SPECIALPAGE_CONSOLE));
    xc_hvm_param_set(xch, domid, HVM_PARAM_PAGING_RING_PFN,
                     special_pfn(SPECIALPAGE_PAGING));
    xc_hvm_param_set(xch, domid, HVM_PARAM_MONITOR_RING_PFN,
                     special_pfn(SPECIALPAGE_ACCESS));
    xc_hvm_param_set(xch, domid, HVM_PARAM_SHARING_RING_PFN,
                     special_pfn(SPECIALPAGE_SHARING));

    /*
     * Allocate and clear additional ioreq server pages. The default
     * server will use the IOREQ and BUFIOREQ special pages above.
     */
    for ( i = 0; i < NR_IOREQ_SERVER_PAGES; i++ )
        ioreq_server_array[i] = ioreq_server_pfn(i);

    rc = xc_domain_populate_physmap_exact(xch, domid, NR_IOREQ_SERVER_PAGES, 0,
                                          0, ioreq_server_array);
    if ( rc != 0 )
    {
        DOMPRINTF("Could not allocate ioreq server pages.");
        goto error_out;
    }

    if ( xc_clear_domain_pages(xch, domid, ioreq_server_pfn(0),
                               NR_IOREQ_SERVER_PAGES) )
            goto error_out;

    /* Tell the domain where the pages are and how many there are */
    xc_hvm_param_set(xch, domid, HVM_PARAM_IOREQ_SERVER_PFN,
                     ioreq_server_pfn(0));
    xc_hvm_param_set(xch, domid, HVM_PARAM_NR_IOREQ_SERVER_PAGES,
                     NR_IOREQ_SERVER_PAGES);

    /*
     * Identity-map page table is required for running with CR0.PG=0 when
     * using Intel EPT. Create a 32-bit non-PAE page directory of superpages.
     */
    if ( (ident_pt = xc_map_foreign_range(
              xch, domid, PAGE_SIZE, PROT_READ | PROT_WRITE,
              special_pfn(SPECIALPAGE_IDENT_PT))) == NULL )
        goto error_out;
    for ( i = 0; i < PAGE_SIZE / sizeof(*ident_pt); i++ )
        ident_pt[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
                       _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
    munmap(ident_pt, PAGE_SIZE);
    xc_hvm_param_set(xch, domid, HVM_PARAM_IDENT_PT,
                     special_pfn(SPECIALPAGE_IDENT_PT) << PAGE_SHIFT);

    dom->console_pfn = special_pfn(SPECIALPAGE_CONSOLE);
    dom->xenstore_pfn = special_pfn(SPECIALPAGE_XENSTORE);
    dom->parms.virt_hypercall = -1;

    rc = 0;
    goto out;
 error_out:
    rc = -1;
 out:

    return rc;
}

/* ------------------------------------------------------------------------ */

static int start_info_x86_32(struct xc_dom_image *dom)
{
    start_info_x86_32_t *start_info =
        xc_dom_pfn_to_ptr(dom, dom->start_info_pfn, 1);
    xen_pfn_t shinfo =
        xc_dom_feature_translated(dom) ? dom->shared_info_pfn : dom->
        shared_info_mfn;

    DOMPRINTF_CALLED(dom->xch);

    if ( start_info == NULL )
    {
        DOMPRINTF("%s: xc_dom_pfn_to_ptr failed on start_info", __FUNCTION__);
        return -1; /* our caller throws away our return value :-/ */
    }

    memset(start_info, 0, sizeof(*start_info));
    strncpy(start_info->magic, dom->guest_type, sizeof(start_info->magic));
    start_info->magic[sizeof(start_info->magic) - 1] = '\0';
    start_info->nr_pages = dom->total_pages;
    start_info->shared_info = shinfo << PAGE_SHIFT_X86;
    start_info->pt_base = dom->pgtables_seg.vstart;
    start_info->nr_pt_frames = dom->pgtables;
    start_info->mfn_list = dom->p2m_seg.vstart;

    start_info->flags = dom->flags;
    start_info->store_mfn = xc_dom_p2m(dom, dom->xenstore_pfn);
    start_info->store_evtchn = dom->xenstore_evtchn;
    start_info->console.domU.mfn = xc_dom_p2m(dom, dom->console_pfn);
    start_info->console.domU.evtchn = dom->console_evtchn;

    if ( dom->ramdisk_blob )
    {
        start_info->mod_start = dom->ramdisk_seg.vstart;
        start_info->mod_len = dom->ramdisk_seg.vend - dom->ramdisk_seg.vstart;
    }

    if ( dom->cmdline )
    {
        strncpy((char *)start_info->cmd_line, dom->cmdline, MAX_GUEST_CMDLINE);
        start_info->cmd_line[MAX_GUEST_CMDLINE - 1] = '\0';
    }

    return 0;
}

static int start_info_x86_64(struct xc_dom_image *dom)
{
    start_info_x86_64_t *start_info =
        xc_dom_pfn_to_ptr(dom, dom->start_info_pfn, 1);
    xen_pfn_t shinfo =
        xc_dom_feature_translated(dom) ? dom->shared_info_pfn : dom->
        shared_info_mfn;

    DOMPRINTF_CALLED(dom->xch);

    if ( start_info == NULL )
    {
        DOMPRINTF("%s: xc_dom_pfn_to_ptr failed on start_info", __FUNCTION__);
        return -1; /* our caller throws away our return value :-/ */
    }

    memset(start_info, 0, sizeof(*start_info));
    strncpy(start_info->magic, dom->guest_type, sizeof(start_info->magic));
    start_info->magic[sizeof(start_info->magic) - 1] = '\0';
    start_info->nr_pages = dom->total_pages;
    start_info->shared_info = shinfo << PAGE_SHIFT_X86;
    start_info->pt_base = dom->pgtables_seg.vstart;
    start_info->nr_pt_frames = dom->pgtables;
    start_info->mfn_list = dom->p2m_seg.vstart;

    start_info->flags = dom->flags;
    start_info->store_mfn = xc_dom_p2m(dom, dom->xenstore_pfn);
    start_info->store_evtchn = dom->xenstore_evtchn;
    start_info->console.domU.mfn = xc_dom_p2m(dom, dom->console_pfn);
    start_info->console.domU.evtchn = dom->console_evtchn;

    if ( dom->ramdisk_blob )
    {
        start_info->mod_start = dom->ramdisk_seg.vstart;
        start_info->mod_len = dom->ramdisk_seg.vend - dom->ramdisk_seg.vstart;
    }

    if ( dom->cmdline )
    {
        strncpy((char *)start_info->cmd_line, dom->cmdline, MAX_GUEST_CMDLINE);
        start_info->cmd_line[MAX_GUEST_CMDLINE - 1] = '\0';
    }

    return 0;
}

static int shared_info_x86_32(struct xc_dom_image *dom, void *ptr)
{
    shared_info_x86_32_t *shared_info = ptr;
    int i;

    DOMPRINTF_CALLED(dom->xch);

    memset(shared_info, 0, sizeof(*shared_info));
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        shared_info->vcpu_info[i].evtchn_upcall_mask = 1;
    return 0;
}

static int shared_info_x86_64(struct xc_dom_image *dom, void *ptr)
{
    shared_info_x86_64_t *shared_info = ptr;
    int i;

    DOMPRINTF_CALLED(dom->xch);

    memset(shared_info, 0, sizeof(*shared_info));
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        shared_info->vcpu_info[i].evtchn_upcall_mask = 1;
    return 0;
}

/* ------------------------------------------------------------------------ */

static int vcpu_x86_32(struct xc_dom_image *dom)
{
    vcpu_guest_context_any_t any_ctx;
    vcpu_guest_context_x86_32_t *ctxt = &any_ctx.x32;
    xen_pfn_t cr3_pfn;
    int rc;

    DOMPRINTF_CALLED(dom->xch);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->user_regs.eip = dom->parms.virt_entry;
    ctxt->user_regs.esp =
        dom->parms.virt_base + (dom->bootstack_pfn + 1) * PAGE_SIZE_X86;
    ctxt->user_regs.esi =
        dom->parms.virt_base + (dom->start_info_pfn) * PAGE_SIZE_X86;
    ctxt->user_regs.eflags = 1 << 9; /* Interrupt Enable */

    ctxt->flags = VGCF_in_kernel_X86_32 | VGCF_online_X86_32;
    if ( dom->parms.pae == XEN_PAE_EXTCR3 ||
         dom->parms.pae == XEN_PAE_BIMODAL )
        ctxt->vm_assist |= (1UL << VMASST_TYPE_pae_extended_cr3);

    cr3_pfn = xc_dom_p2m(dom, dom->pgtables_seg.pfn);
    ctxt->ctrlreg[3] = xen_pfn_to_cr3_x86_32(cr3_pfn);
    DOMPRINTF("%s: cr3: pfn 0x%" PRIpfn " mfn 0x%" PRIpfn "",
              __FUNCTION__, dom->pgtables_seg.pfn, cr3_pfn);

    if ( !dom->pvh_enabled )
    {
        ctxt->user_regs.ds = FLAT_KERNEL_DS_X86_32;
        ctxt->user_regs.es = FLAT_KERNEL_DS_X86_32;
        ctxt->user_regs.fs = FLAT_KERNEL_DS_X86_32;
        ctxt->user_regs.gs = FLAT_KERNEL_DS_X86_32;
        ctxt->user_regs.ss = FLAT_KERNEL_SS_X86_32;
        ctxt->user_regs.cs = FLAT_KERNEL_CS_X86_32;

        ctxt->kernel_ss = ctxt->user_regs.ss;
        ctxt->kernel_sp = ctxt->user_regs.esp;
    }

    rc = xc_vcpu_setcontext(dom->xch, dom->guest_domid, 0, &any_ctx);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)", __func__, rc);

    return rc;
}

static int vcpu_x86_64(struct xc_dom_image *dom)
{
    vcpu_guest_context_any_t any_ctx;
    vcpu_guest_context_x86_64_t *ctxt = &any_ctx.x64;
    xen_pfn_t cr3_pfn;
    int rc;

    DOMPRINTF_CALLED(dom->xch);

    /* clear everything */
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->user_regs.rip = dom->parms.virt_entry;
    ctxt->user_regs.rsp =
        dom->parms.virt_base + (dom->bootstack_pfn + 1) * PAGE_SIZE_X86;
    ctxt->user_regs.rsi =
        dom->parms.virt_base + (dom->start_info_pfn) * PAGE_SIZE_X86;
    ctxt->user_regs.rflags = 1 << 9; /* Interrupt Enable */

    ctxt->flags = VGCF_in_kernel_X86_64 | VGCF_online_X86_64;
    cr3_pfn = xc_dom_p2m(dom, dom->pgtables_seg.pfn);
    ctxt->ctrlreg[3] = xen_pfn_to_cr3_x86_64(cr3_pfn);
    DOMPRINTF("%s: cr3: pfn 0x%" PRIpfn " mfn 0x%" PRIpfn "",
              __FUNCTION__, dom->pgtables_seg.pfn, cr3_pfn);

    if ( !dom->pvh_enabled )
    {
        ctxt->user_regs.ds = FLAT_KERNEL_DS_X86_64;
        ctxt->user_regs.es = FLAT_KERNEL_DS_X86_64;
        ctxt->user_regs.fs = FLAT_KERNEL_DS_X86_64;
        ctxt->user_regs.gs = FLAT_KERNEL_DS_X86_64;
        ctxt->user_regs.ss = FLAT_KERNEL_SS_X86_64;
        ctxt->user_regs.cs = FLAT_KERNEL_CS_X86_64;

        ctxt->kernel_ss = ctxt->user_regs.ss;
        ctxt->kernel_sp = ctxt->user_regs.esp;
    }

    rc = xc_vcpu_setcontext(dom->xch, dom->guest_domid, 0, &any_ctx);
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: SETVCPUCONTEXT failed (rc=%d)", __func__, rc);

    return rc;
}

static int vcpu_hvm(struct xc_dom_image *dom)
{
    struct {
        struct hvm_save_descriptor header_d;
        HVM_SAVE_TYPE(HEADER) header;
        struct hvm_save_descriptor cpu_d;
        HVM_SAVE_TYPE(CPU) cpu;
        struct hvm_save_descriptor end_d;
        HVM_SAVE_TYPE(END) end;
    } bsp_ctx;
    /*
     * The layout of the fpu context structure is the same for
     * both 32 and 64 bits.
     */
    struct {
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t rsvd1;
        uint16_t fop;
        union {
            uint64_t addr;
            struct {
                uint32_t offs;
                uint16_t sel;
                uint16_t rsvd;
            };
        } fip, fdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
    } *fpu_ctxt;
    uint8_t *full_ctx = NULL;
    int rc;

    DOMPRINTF_CALLED(dom->xch);

    /*
     * Get the full HVM context in order to have the header, it is not
     * possible to get the header with getcontext_partial, and crafting one
     * from userspace is also not an option since cpuid is trapped and
     * modified by Xen.
     */

    rc = xc_domain_hvm_getcontext(dom->xch, dom->guest_domid, NULL, 0);
    if ( rc <= 0 )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: unable to fetch HVM context size (rc=%d)",
                     __func__, rc);
        goto out;
    }

    full_ctx = calloc(1, rc);
    if ( full_ctx == NULL )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: unable to allocate memory for HVM context (rc=%d)",
                     __func__, rc);
        rc = -ENOMEM;
        goto out;
    }

    rc = xc_domain_hvm_getcontext(dom->xch, dom->guest_domid, full_ctx, rc);
    if ( rc <= 0 )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: unable to fetch HVM context (rc=%d)",
                     __func__, rc);
        goto out;
    }

    /* Copy the header to our partial context. */
    memset(&bsp_ctx, 0, sizeof(bsp_ctx));
    memcpy(&bsp_ctx, full_ctx,
           sizeof(struct hvm_save_descriptor) + HVM_SAVE_LENGTH(HEADER));

    /* Set the CPU descriptor. */
    bsp_ctx.cpu_d.typecode = HVM_SAVE_CODE(CPU);
    bsp_ctx.cpu_d.instance = 0;
    bsp_ctx.cpu_d.length = HVM_SAVE_LENGTH(CPU);

    /* Set the cached part of the relevant segment registers. */
    bsp_ctx.cpu.cs_base = 0;
    bsp_ctx.cpu.ds_base = 0;
    bsp_ctx.cpu.ss_base = 0;
    bsp_ctx.cpu.tr_base = 0;
    bsp_ctx.cpu.cs_limit = ~0u;
    bsp_ctx.cpu.ds_limit = ~0u;
    bsp_ctx.cpu.ss_limit = ~0u;
    bsp_ctx.cpu.tr_limit = 0x67;
    bsp_ctx.cpu.cs_arbytes = 0xc9b;
    bsp_ctx.cpu.ds_arbytes = 0xc93;
    bsp_ctx.cpu.ss_arbytes = 0xc93;
    bsp_ctx.cpu.tr_arbytes = 0x8b;

    /* Set the control registers. */
    bsp_ctx.cpu.cr0 = X86_CR0_PE | X86_CR0_ET;

    /*
     * XXX: Set initial FPU state.
     *
     * This should be removed once Xen is able to know if the
     * FPU state saved is valid or not, now Xen always sets
     * fpu_initialised to true regardless of the FPU state.
     *
     * The code below mimics the FPU sate after executing
     * fninit
     * ldmxcsr 0x1f80
     */
    fpu_ctxt = (typeof(fpu_ctxt))bsp_ctx.cpu.fpu_regs;

    fpu_ctxt->fcw = 0x37f;
    fpu_ctxt->ftw = 0xff;
    fpu_ctxt->mxcsr = 0x1f80;

    /* Set the IP. */
    bsp_ctx.cpu.rip = dom->parms.phys_entry;

    /* Set the end descriptor. */
    bsp_ctx.end_d.typecode = HVM_SAVE_CODE(END);
    bsp_ctx.end_d.instance = 0;
    bsp_ctx.end_d.length = HVM_SAVE_LENGTH(END);

    rc = xc_domain_hvm_setcontext(dom->xch, dom->guest_domid,
                                  (uint8_t *)&bsp_ctx, sizeof(bsp_ctx));
    if ( rc != 0 )
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: SETHVMCONTEXT failed (rc=%d)", __func__, rc);

 out:
    free(full_ctx);
    return rc;
}

/* ------------------------------------------------------------------------ */

static int x86_compat(xc_interface *xch, domid_t domid, char *guest_type)
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
    for ( i = 0; i < ARRAY_SIZE(types); i++ )
        if ( !strcmp(types[i].guest, guest_type) )
            domctl.u.address_size.size = types[i].size;
    if ( domctl.u.address_size.size == 0 )
        /* nothing to do */
        return 0;

    xc_dom_printf(xch, "%s: guest %s, address size %" PRId32 "", __FUNCTION__,
                  guest_type, domctl.u.address_size.size);
    rc = do_domctl(xch, &domctl);
    if ( rc != 0 )
        xc_dom_printf(xch, "%s: warning: failed (rc=%d)",
                      __FUNCTION__, rc);
    return rc;
}

static int x86_shadow(xc_interface *xch, domid_t domid)
{
    int rc, mode;

    DOMPRINTF_CALLED(xch);

    mode = XEN_DOMCTL_SHADOW_ENABLE_REFCOUNT |
        XEN_DOMCTL_SHADOW_ENABLE_TRANSLATE;

    rc = xc_shadow_control(xch, domid,
                           XEN_DOMCTL_SHADOW_OP_ENABLE,
                           NULL, 0, NULL, mode, NULL);
    if ( rc != 0 )
    {
        xc_dom_panic(xch, XC_INTERNAL_ERROR,
                     "%s: SHADOW_OP_ENABLE (mode=0x%x) failed (rc=%d)",
                     __FUNCTION__, mode, rc);
        return rc;
    }
    xc_dom_printf(xch, "%s: shadow enabled (mode=0x%x)", __FUNCTION__, mode);
    return rc;
}

static int meminit_pv(struct xc_dom_image *dom)
{
    int rc;
    xen_pfn_t pfn, allocsz, mfn, total, pfn_base;
    int i, j, k;
    xen_vmemrange_t dummy_vmemrange[1];
    unsigned int dummy_vnode_to_pnode[1];
    xen_vmemrange_t *vmemranges;
    unsigned int *vnode_to_pnode;
    unsigned int nr_vmemranges, nr_vnodes;

    rc = x86_compat(dom->xch, dom->guest_domid, dom->guest_type);
    if ( rc )
        return rc;
    if ( xc_dom_feature_translated(dom) && !dom->pvh_enabled )
    {
        dom->shadow_enabled = 1;
        rc = x86_shadow(dom->xch, dom->guest_domid);
        if ( rc )
            return rc;
    }

    /* try to claim pages for early warning of insufficient memory avail */
    if ( dom->claim_enabled )
    {
        rc = xc_domain_claim_pages(dom->xch, dom->guest_domid,
                                   dom->total_pages);
        if ( rc )
            return rc;
    }

    /* Setup dummy vNUMA information if it's not provided. Note
     * that this is a valid state if libxl doesn't provide any
     * vNUMA information.
     *
     * The dummy values make libxc allocate all pages from
     * arbitrary physical nodes. This is the expected behaviour if
     * no vNUMA configuration is provided to libxc.
     *
     * Note that the following hunk is just for the convenience of
     * allocation code. No defaulting happens in libxc.
     */
    if ( dom->nr_vmemranges == 0 )
    {
        nr_vmemranges = 1;
        vmemranges = dummy_vmemrange;
        vmemranges[0].start = 0;
        vmemranges[0].end   = (uint64_t)dom->total_pages << PAGE_SHIFT;
        vmemranges[0].flags = 0;
        vmemranges[0].nid   = 0;

        nr_vnodes = 1;
        vnode_to_pnode = dummy_vnode_to_pnode;
        vnode_to_pnode[0] = XC_NUMA_NO_NODE;
    }
    else
    {
        nr_vmemranges = dom->nr_vmemranges;
        nr_vnodes = dom->nr_vnodes;
        vmemranges = dom->vmemranges;
        vnode_to_pnode = dom->vnode_to_pnode;
    }

    total = dom->p2m_size = 0;
    for ( i = 0; i < nr_vmemranges; i++ )
    {
        total += ((vmemranges[i].end - vmemranges[i].start) >> PAGE_SHIFT);
        dom->p2m_size = max(dom->p2m_size,
                            (xen_pfn_t)(vmemranges[i].end >> PAGE_SHIFT));
    }
    if ( total != dom->total_pages )
    {
        xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                     "%s: vNUMA page count mismatch (0x%"PRIpfn" != 0x%"PRIpfn")",
                     __func__, total, dom->total_pages);
        return -EINVAL;
    }

    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) * dom->p2m_size);
    if ( dom->p2m_host == NULL )
        return -EINVAL;
    for ( pfn = 0; pfn < dom->p2m_size; pfn++ )
        dom->p2m_host[pfn] = INVALID_P2M_ENTRY;

    /* allocate guest memory */
    for ( i = 0; i < nr_vmemranges; i++ )
    {
        unsigned int memflags;
        uint64_t pages, super_pages;
        unsigned int pnode = vnode_to_pnode[vmemranges[i].nid];
        xen_pfn_t extents[SUPERPAGE_BATCH_SIZE];
        xen_pfn_t pfn_base_idx;

        memflags = 0;
        if ( pnode != XC_NUMA_NO_NODE )
            memflags |= XENMEMF_exact_node(pnode);

        pages = (vmemranges[i].end - vmemranges[i].start) >> PAGE_SHIFT;
        super_pages = pages >> SUPERPAGE_2MB_SHIFT;
        pfn_base = vmemranges[i].start >> PAGE_SHIFT;

        for ( pfn = pfn_base; pfn < pfn_base+pages; pfn++ )
            dom->p2m_host[pfn] = pfn;

        pfn_base_idx = pfn_base;
        while ( super_pages ) {
            uint64_t count = min_t(uint64_t, super_pages, SUPERPAGE_BATCH_SIZE);
            super_pages -= count;

            for ( pfn = pfn_base_idx, j = 0;
                  pfn < pfn_base_idx + (count << SUPERPAGE_2MB_SHIFT);
                  pfn += SUPERPAGE_2MB_NR_PFNS, j++ )
                extents[j] = dom->p2m_host[pfn];
            rc = xc_domain_populate_physmap(dom->xch, dom->guest_domid, count,
                                            SUPERPAGE_2MB_SHIFT, memflags,
                                            extents);
            if ( rc < 0 )
                return rc;

            /* Expand the returned mfns into the p2m array. */
            pfn = pfn_base_idx;
            for ( j = 0; j < rc; j++ )
            {
                mfn = extents[j];
                for ( k = 0; k < SUPERPAGE_2MB_NR_PFNS; k++, pfn++ )
                    dom->p2m_host[pfn] = mfn + k;
            }
            pfn_base_idx = pfn;
        }

        for ( j = pfn_base_idx - pfn_base; j < pages; j += allocsz )
        {
            allocsz = min_t(uint64_t, 1024 * 1024, pages - j);
            rc = xc_domain_populate_physmap_exact(dom->xch, dom->guest_domid,
                     allocsz, 0, memflags, &dom->p2m_host[pfn_base + j]);

            if ( rc )
            {
                if ( pnode != XC_NUMA_NO_NODE )
                    xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                                 "%s: failed to allocate 0x%"PRIx64" pages (v=%d, p=%d)",
                                 __func__, pages, i, pnode);
                else
                    xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                                 "%s: failed to allocate 0x%"PRIx64" pages",
                                 __func__, pages);
                return rc;
            }
        }
        rc = 0;
    }

    /* Ensure no unclaimed pages are left unused.
     * OK to call if hadn't done the earlier claim call. */
    xc_domain_claim_pages(dom->xch, dom->guest_domid, 0 /* cancel claim */);

    return rc;
}

/*
 * Check whether there exists mmio hole in the specified memory range.
 * Returns 1 if exists, else returns 0.
 */
static int check_mmio_hole(uint64_t start, uint64_t memsize,
                           uint64_t mmio_start, uint64_t mmio_size)
{
    if ( start + memsize <= mmio_start || start >= mmio_start + mmio_size )
        return 0;
    else
        return 1;
}

static int meminit_hvm(struct xc_dom_image *dom)
{
    unsigned long i, vmemid, nr_pages = dom->total_pages;
    unsigned long p2m_size;
    unsigned long target_pages = dom->target_pages;
    unsigned long cur_pages, cur_pfn;
    int rc;
    xen_capabilities_info_t caps;
    unsigned long stat_normal_pages = 0, stat_2mb_pages = 0, 
        stat_1gb_pages = 0;
    unsigned int memflags = 0;
    int claim_enabled = dom->claim_enabled;
    uint64_t total_pages;
    xen_vmemrange_t dummy_vmemrange[2];
    unsigned int dummy_vnode_to_pnode[1];
    xen_vmemrange_t *vmemranges;
    unsigned int *vnode_to_pnode;
    unsigned int nr_vmemranges, nr_vnodes;
    xc_interface *xch = dom->xch;
    uint32_t domid = dom->guest_domid;

    if ( nr_pages > target_pages )
        memflags |= XENMEMF_populate_on_demand;

    if ( dom->nr_vmemranges == 0 )
    {
        /* Build dummy vnode information
         *
         * Guest physical address space layout:
         * [0, hole_start) [hole_start, 4G) [4G, highmem_end)
         *
         * Of course if there is no high memory, the second vmemrange
         * has no effect on the actual result.
         */

        dummy_vmemrange[0].start = 0;
        dummy_vmemrange[0].end   = dom->lowmem_end;
        dummy_vmemrange[0].flags = 0;
        dummy_vmemrange[0].nid   = 0;
        nr_vmemranges = 1;

        if ( dom->highmem_end > (1ULL << 32) )
        {
            dummy_vmemrange[1].start = 1ULL << 32;
            dummy_vmemrange[1].end   = dom->highmem_end;
            dummy_vmemrange[1].flags = 0;
            dummy_vmemrange[1].nid   = 0;

            nr_vmemranges++;
        }

        dummy_vnode_to_pnode[0] = XC_NUMA_NO_NODE;
        nr_vnodes = 1;
        vmemranges = dummy_vmemrange;
        vnode_to_pnode = dummy_vnode_to_pnode;
    }
    else
    {
        if ( nr_pages > target_pages )
        {
            DOMPRINTF("Cannot enable vNUMA and PoD at the same time");
            goto error_out;
        }

        nr_vmemranges = dom->nr_vmemranges;
        nr_vnodes = dom->nr_vnodes;
        vmemranges = dom->vmemranges;
        vnode_to_pnode = dom->vnode_to_pnode;
    }

    total_pages = 0;
    p2m_size = 0;
    for ( i = 0; i < nr_vmemranges; i++ )
    {
        total_pages += ((vmemranges[i].end - vmemranges[i].start)
                        >> PAGE_SHIFT);
        p2m_size = p2m_size > (vmemranges[i].end >> PAGE_SHIFT) ?
            p2m_size : (vmemranges[i].end >> PAGE_SHIFT);
    }

    if ( total_pages != nr_pages )
    {
        DOMPRINTF("vNUMA memory pages mismatch (0x%"PRIx64" != 0x%lx)",
               total_pages, nr_pages);
        goto error_out;
    }

    if ( xc_version(xch, XENVER_capabilities, &caps) != 0 )
    {
        DOMPRINTF("Could not get Xen capabilities");
        goto error_out;
    }

    dom->p2m_size = p2m_size;
    dom->p2m_host = xc_dom_malloc(dom, sizeof(xen_pfn_t) *
                                      dom->p2m_size);
    if ( dom->p2m_host == NULL )
    {
        DOMPRINTF("Could not allocate p2m");
        goto error_out;
    }

    for ( i = 0; i < p2m_size; i++ )
        dom->p2m_host[i] = ((xen_pfn_t)-1);
    for ( vmemid = 0; vmemid < nr_vmemranges; vmemid++ )
    {
        uint64_t pfn;

        for ( pfn = vmemranges[vmemid].start >> PAGE_SHIFT;
              pfn < vmemranges[vmemid].end >> PAGE_SHIFT;
              pfn++ )
            dom->p2m_host[pfn] = pfn;
    }

    /*
     * Try to claim pages for early warning of insufficient memory available.
     * This should go before xc_domain_set_pod_target, becuase that function
     * actually allocates memory for the guest. Claiming after memory has been
     * allocated is pointless.
     */
    if ( claim_enabled ) {
        rc = xc_domain_claim_pages(xch, domid, target_pages - VGA_HOLE_SIZE);
        if ( rc != 0 )
        {
            DOMPRINTF("Could not allocate memory for HVM guest as we cannot claim memory!");
            goto error_out;
        }
    }

    if ( memflags & XENMEMF_populate_on_demand )
    {
        /*
         * Subtract VGA_HOLE_SIZE from target_pages for the VGA
         * "hole".  Xen will adjust the PoD cache size so that domain
         * tot_pages will be target_pages - VGA_HOLE_SIZE after
         * this call.
         */
        rc = xc_domain_set_pod_target(xch, domid, target_pages - VGA_HOLE_SIZE,
                                      NULL, NULL, NULL);
        if ( rc != 0 )
        {
            DOMPRINTF("Could not set PoD target for HVM guest.\n");
            goto error_out;
        }
    }

    /*
     * Allocate memory for HVM guest, skipping VGA hole 0xA0000-0xC0000.
     *
     * We attempt to allocate 1GB pages if possible. It falls back on 2MB
     * pages if 1GB allocation fails. 4KB pages will be used eventually if
     * both fail.
     * 
     * Under 2MB mode, we allocate pages in batches of no more than 8MB to 
     * ensure that we can be preempted and hence dom0 remains responsive.
     */
    rc = xc_domain_populate_physmap_exact(
        xch, domid, 0xa0, 0, memflags, &dom->p2m_host[0x00]);

    stat_normal_pages = 0;
    for ( vmemid = 0; vmemid < nr_vmemranges; vmemid++ )
    {
        unsigned int new_memflags = memflags;
        uint64_t end_pages;
        unsigned int vnode = vmemranges[vmemid].nid;
        unsigned int pnode = vnode_to_pnode[vnode];

        if ( pnode != XC_NUMA_NO_NODE )
            new_memflags |= XENMEMF_exact_node(pnode);

        end_pages = vmemranges[vmemid].end >> PAGE_SHIFT;
        /*
         * Consider vga hole belongs to the vmemrange that covers
         * 0xA0000-0xC0000. Note that 0x00000-0xA0000 is populated just
         * before this loop.
         */
        if ( vmemranges[vmemid].start == 0 )
        {
            cur_pages = 0xc0;
            stat_normal_pages += 0xc0;
        }
        else
            cur_pages = vmemranges[vmemid].start >> PAGE_SHIFT;

        while ( (rc == 0) && (end_pages > cur_pages) )
        {
            /* Clip count to maximum 1GB extent. */
            unsigned long count = end_pages - cur_pages;
            unsigned long max_pages = SUPERPAGE_1GB_NR_PFNS;

            if ( count > max_pages )
                count = max_pages;

            cur_pfn = dom->p2m_host[cur_pages];

            /* Take care the corner cases of super page tails */
            if ( ((cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
                 (count > (-cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1))) )
                count = -cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1);
            else if ( ((count & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
                      (count > SUPERPAGE_1GB_NR_PFNS) )
                count &= ~(SUPERPAGE_1GB_NR_PFNS - 1);

            /* Attemp to allocate 1GB super page. Because in each pass
             * we only allocate at most 1GB, we don't have to clip
             * super page boundaries.
             */
            if ( ((count | cur_pfn) & (SUPERPAGE_1GB_NR_PFNS - 1)) == 0 &&
                 /* Check if there exists MMIO hole in the 1GB memory
                  * range */
                 !check_mmio_hole(cur_pfn << PAGE_SHIFT,
                                  SUPERPAGE_1GB_NR_PFNS << PAGE_SHIFT,
                                  dom->mmio_start, dom->mmio_size) )
            {
                long done;
                unsigned long nr_extents = count >> SUPERPAGE_1GB_SHIFT;
                xen_pfn_t sp_extents[nr_extents];

                for ( i = 0; i < nr_extents; i++ )
                    sp_extents[i] =
                        dom->p2m_host[cur_pages+(i<<SUPERPAGE_1GB_SHIFT)];

                done = xc_domain_populate_physmap(xch, domid, nr_extents,
                                                  SUPERPAGE_1GB_SHIFT,
                                                  new_memflags, sp_extents);

                if ( done > 0 )
                {
                    stat_1gb_pages += done;
                    done <<= SUPERPAGE_1GB_SHIFT;
                    cur_pages += done;
                    count -= done;
                }
            }

            if ( count != 0 )
            {
                /* Clip count to maximum 8MB extent. */
                max_pages = SUPERPAGE_2MB_NR_PFNS * 4;
                if ( count > max_pages )
                    count = max_pages;

                /* Clip partial superpage extents to superpage
                 * boundaries. */
                if ( ((cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                     (count > (-cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1))) )
                    count = -cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1);
                else if ( ((count & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                          (count > SUPERPAGE_2MB_NR_PFNS) )
                    count &= ~(SUPERPAGE_2MB_NR_PFNS - 1); /* clip non-s.p. tail */

                /* Attempt to allocate superpage extents. */
                if ( ((count | cur_pfn) & (SUPERPAGE_2MB_NR_PFNS - 1)) == 0 )
                {
                    long done;
                    unsigned long nr_extents = count >> SUPERPAGE_2MB_SHIFT;
                    xen_pfn_t sp_extents[nr_extents];

                    for ( i = 0; i < nr_extents; i++ )
                        sp_extents[i] =
                            dom->p2m_host[cur_pages+(i<<SUPERPAGE_2MB_SHIFT)];

                    done = xc_domain_populate_physmap(xch, domid, nr_extents,
                                                      SUPERPAGE_2MB_SHIFT,
                                                      new_memflags, sp_extents);

                    if ( done > 0 )
                    {
                        stat_2mb_pages += done;
                        done <<= SUPERPAGE_2MB_SHIFT;
                        cur_pages += done;
                        count -= done;
                    }
                }
            }

            /* Fall back to 4kB extents. */
            if ( count != 0 )
            {
                rc = xc_domain_populate_physmap_exact(
                    xch, domid, count, 0, new_memflags, &dom->p2m_host[cur_pages]);
                cur_pages += count;
                stat_normal_pages += count;
            }
        }

        if ( rc != 0 )
            break;
    }

    if ( rc != 0 )
    {
        DOMPRINTF("Could not allocate memory for HVM guest.");
        goto error_out;
    }

    DPRINTF("PHYSICAL MEMORY ALLOCATION:\n");
    DPRINTF("  4KB PAGES: 0x%016lx\n", stat_normal_pages);
    DPRINTF("  2MB PAGES: 0x%016lx\n", stat_2mb_pages);
    DPRINTF("  1GB PAGES: 0x%016lx\n", stat_1gb_pages);

    rc = 0;
    goto out;
 error_out:
    rc = -1;
 out:

    /* ensure no unclaimed pages are left unused */
    xc_domain_claim_pages(xch, domid, 0 /* cancels the claim */);

    return rc;
}

/* ------------------------------------------------------------------------ */

static int bootearly(struct xc_dom_image *dom)
{
    DOMPRINTF("%s: doing nothing", __FUNCTION__);
    return 0;
}

/*
 * Map grant table frames into guest physmap. PVH manages grant during boot
 * via HVM mechanisms.
 */
static int map_grant_table_frames(struct xc_dom_image *dom)
{
    int i, rc;

    if ( dom->pvh_enabled )
        return 0;

    for ( i = 0; ; i++ )
    {
        rc = xc_domain_add_to_physmap(dom->xch, dom->guest_domid,
                                      XENMAPSPACE_grant_table,
                                      i, dom->p2m_size + i);
        if ( rc != 0 )
        {
            if ( (i > 0) && (errno == EINVAL) )
            {
                DOMPRINTF("%s: %d grant tables mapped", __FUNCTION__, i);
                break;
            }
            xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                         "%s: mapping grant tables failed " "(pfn=0x%" PRIpfn
                         ", rc=%d, errno=%d)", __FUNCTION__, dom->p2m_size + i,
                         rc, errno);
            return rc;
        }
    }
    return 0;
}

static int bootlate_pv(struct xc_dom_image *dom)
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

    for ( i = 0; i < ARRAY_SIZE(types); i++ )
        if ( !strcmp(types[i].guest, dom->guest_type) )
            pgd_type = types[i].pgd_type;

    if ( !xc_dom_feature_translated(dom) )
    {
        /* paravirtualized guest */
        xc_dom_unmap_one(dom, dom->pgtables_seg.pfn);
        rc = pin_table(dom->xch, pgd_type,
                       xc_dom_p2m(dom, dom->pgtables_seg.pfn),
                       dom->guest_domid);
        if ( rc != 0 )
        {
            xc_dom_panic(dom->xch, XC_INTERNAL_ERROR,
                         "%s: pin_table failed (pfn 0x%" PRIpfn ", rc=%d)",
                         __FUNCTION__, dom->pgtables_seg.pfn, rc);
            return rc;
        }
        shinfo = dom->shared_info_mfn;
    }
    else
    {
        /* paravirtualized guest with auto-translation */

        /* Map shared info frame into guest physmap. */
        rc = xc_domain_add_to_physmap(dom->xch, dom->guest_domid,
                                      XENMAPSPACE_shared_info,
                                      0, dom->shared_info_pfn);
        if ( rc != 0 )
        {
            xc_dom_panic(dom->xch, XC_INTERNAL_ERROR, "%s: mapping"
                         " shared_info failed (pfn=0x%" PRIpfn ", rc=%d, errno: %d)",
                         __FUNCTION__, dom->shared_info_pfn, rc, errno);
            return rc;
        }

        rc = map_grant_table_frames(dom);
        if ( rc != 0 )
            return rc;

        shinfo = dom->shared_info_pfn;
    }

    /* setup shared_info page */
    DOMPRINTF("%s: shared_info: pfn 0x%" PRIpfn ", mfn 0x%" PRIpfn "",
              __FUNCTION__, dom->shared_info_pfn, dom->shared_info_mfn);
    shared_info = xc_map_foreign_range(dom->xch, dom->guest_domid,
                                       PAGE_SIZE_X86,
                                       PROT_READ | PROT_WRITE,
                                       shinfo);
    if ( shared_info == NULL )
        return -1;
    dom->arch_hooks->shared_info(dom, shared_info);
    munmap(shared_info, PAGE_SIZE_X86);

    return 0;
}

static int bootlate_hvm(struct xc_dom_image *dom)
{
    DOMPRINTF("%s: doing nothing", __func__);
    return 0;
}

int xc_dom_feature_translated(struct xc_dom_image *dom)
{
    /* Guests running inside HVM containers are always auto-translated. */
    if ( dom->container_type == XC_DOM_HVM_CONTAINER )
        return 1;

    return elf_xen_feature_get(XENFEAT_auto_translated_physmap, dom->f_active);
}

/* ------------------------------------------------------------------------ */

static struct xc_dom_arch xc_dom_32_pae = {
    .guest_type = "xen-3.0-x86_32p",
    .native_protocol = XEN_IO_PROTO_ABI_X86_32,
    .page_shift = PAGE_SHIFT_X86,
    .sizeof_pfn = 4,
    .alloc_magic_pages = alloc_magic_pages,
    .count_pgtables = count_pgtables_x86_32_pae,
    .setup_pgtables = setup_pgtables_x86_32_pae,
    .start_info = start_info_x86_32,
    .shared_info = shared_info_x86_32,
    .vcpu = vcpu_x86_32,
    .meminit = meminit_pv,
    .bootearly = bootearly,
    .bootlate = bootlate_pv,
};

static struct xc_dom_arch xc_dom_64 = {
    .guest_type = "xen-3.0-x86_64",
    .native_protocol = XEN_IO_PROTO_ABI_X86_64,
    .page_shift = PAGE_SHIFT_X86,
    .sizeof_pfn = 8,
    .alloc_magic_pages = alloc_magic_pages,
    .count_pgtables = count_pgtables_x86_64,
    .setup_pgtables = setup_pgtables_x86_64,
    .start_info = start_info_x86_64,
    .shared_info = shared_info_x86_64,
    .vcpu = vcpu_x86_64,
    .meminit = meminit_pv,
    .bootearly = bootearly,
    .bootlate = bootlate_pv,
};

static struct xc_dom_arch xc_hvm_32 = {
    .guest_type = "hvm-3.0-x86_32",
    .native_protocol = XEN_IO_PROTO_ABI_X86_32,
    .page_shift = PAGE_SHIFT_X86,
    .sizeof_pfn = 4,
    .alloc_magic_pages = alloc_magic_pages_hvm,
    .count_pgtables = NULL,
    .setup_pgtables = NULL,
    .start_info = NULL,
    .shared_info = NULL,
    .vcpu = vcpu_hvm,
    .meminit = meminit_hvm,
    .bootearly = bootearly,
    .bootlate = bootlate_hvm,
};

static void __init register_arch_hooks(void)
{
    xc_dom_register_arch_hooks(&xc_dom_32_pae);
    xc_dom_register_arch_hooks(&xc_dom_64);
    xc_dom_register_arch_hooks(&xc_hvm_32);
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
