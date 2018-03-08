/******************************************************************************
 * arch/x86/mm.c
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * A description of the x86 page table API:
 *
 * Domains trap to do_mmu_update with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val.
 *
 * Reference counting of pages:
 * ----------------------------
 * Each page has two refcounts: tot_count and type_count.
 *
 * TOT_COUNT is the obvious reference count. It counts all uses of a
 * physical page frame by a domain, including uses as a page directory,
 * a page table, or simple mappings via a PTE. This count prevents a
 * domain from releasing a frame back to the free pool when it still holds
 * a reference to it.
 *
 * TYPE_COUNT is more subtle. A frame can be put to one of three
 * mutually-exclusive uses: it might be used as a page directory, or a
 * page table, or it may be mapped writable by the domain [of course, a
 * frame may not be used in any of these three ways!].
 * So, type_count is a count of the number of times a frame is being
 * referred to in its current incarnation. Therefore, a page can only
 * change its type when its type count is zero.
 *
 * Pinning the page type:
 * ----------------------
 * The type of a page can be pinned/unpinned with the commands
 * MMUEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
 * pinning is not reference counted, so it can't be nested).
 * This is useful to prevent a page's type count falling to zero, at which
 * point safety checks would need to be carried out next time the count
 * is increased again.
 *
 * A further note on writable page mappings:
 * -----------------------------------------
 * For simplicity, the count of writable mappings for a page may not
 * correspond to reality. The 'writable count' is incremented for every
 * PTE which maps the page with the _PAGE_RW flag set. However, for
 * write access to be possible the page directory entry must also have
 * its _PAGE_RW bit set. We do not check this as it complicates the
 * reference counting considerably [consider the case of multiple
 * directory entries referencing a single page table, some with the RW
 * bit set, others not -- it starts getting a bit messy].
 * In normal use, this simplification shouldn't be a problem.
 * However, the logic can be added if required.
 *
 * One more note on read-only page mappings:
 * -----------------------------------------
 * We want domains to be able to map pages for read-only access. The
 * main reason is that page tables and directories should be readable
 * by a domain, but it would not be safe for them to be writable.
 * However, domains have free access to rings 1 & 2 of the Intel
 * privilege model. In terms of page protection, these are considered
 * to be part of 'supervisor mode'. The WP bit in CR0 controls whether
 * read-only restrictions are respected in supervisor mode -- if the
 * bit is clear then any mapped page is writable.
 *
 * We get round this by always setting the WP bit and disallowing
 * updates to it. This is very unlikely to cause a problem for guest
 * OS's, which will generally use the WP bit to simplify copy-on-write
 * implementation (in that case, OS wants a fault when it writes to
 * an application-supplied buffer).
 */

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/err.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/pfn.h>
#include <xen/vmap.h>
#include <xen/xmalloc.h>
#include <xen/efi.h>
#include <xen/grant_table.h>
#include <xen/hypercall.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/x86_emulate.h>
#include <asm/e820.h>
#include <asm/hypercall.h>
#include <asm/shared.h>
#include <asm/mem_sharing.h>
#include <public/memory.h>
#include <public/sched.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <asm/setup.h>
#include <asm/fixmap.h>
#include <asm/io_apic.h>
#include <asm/pci.h>
#include <asm/guest.h>

#include <asm/hvm/grant_table.h>
#include <asm/pv/grant_table.h>
#include <asm/pv/mm.h>

#include "pv/mm.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

/* Mapping of the fixmap space needed early. */
l1_pgentry_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    l1_fixmap[L1_PAGETABLE_ENTRIES];

paddr_t __read_mostly mem_hotplug;

/* Private domain structs for DOMID_XEN and DOMID_IO. */
struct domain *dom_xen, *dom_io, *dom_cow;

/* Frame table size in pages. */
unsigned long max_page;
unsigned long total_pages;

bool __read_mostly machine_to_phys_mapping_valid;

struct rangeset *__read_mostly mmio_ro_ranges;

static uint32_t base_disallow_mask;
/* Global bit is allowed to be set on L1 PTEs. Intended for user mappings. */
#define L1_DISALLOW_MASK ((base_disallow_mask | _PAGE_GNTTAB) & ~_PAGE_GLOBAL)

#define L2_DISALLOW_MASK base_disallow_mask

#define l3_disallow_mask(d) (!is_pv_32bit_domain(d) ? \
                             base_disallow_mask : 0xFFFFF198U)

#define L4_DISALLOW_MASK (base_disallow_mask)

#define l1_disallow_mask(d)                                     \
    ((d != dom_io) &&                                           \
     (rangeset_is_empty((d)->iomem_caps) &&                     \
      rangeset_is_empty((d)->arch.ioport_caps) &&               \
      !has_arch_pdevs(d) &&                                     \
      is_pv_domain(d)) ?                                        \
     L1_DISALLOW_MASK : (L1_DISALLOW_MASK & ~PAGE_CACHE_ATTRS))

static s8 __read_mostly opt_mmio_relax;

static int __init parse_mmio_relax(const char *s)
{
    if ( !*s )
        opt_mmio_relax = 1;
    else
        opt_mmio_relax = parse_bool(s, NULL);
    if ( opt_mmio_relax < 0 && strcmp(s, "all") )
    {
        opt_mmio_relax = 0;
        return -EINVAL;
    }

    return 0;
}
custom_param("mmio-relax", parse_mmio_relax);

static void __init init_frametable_chunk(void *start, void *end)
{
    unsigned long s = (unsigned long)start;
    unsigned long e = (unsigned long)end;
    unsigned long step;
    mfn_t mfn;

    ASSERT(!(s & ((1 << L2_PAGETABLE_SHIFT) - 1)));
    for ( ; s < e; s += step << PAGE_SHIFT )
    {
        step = 1UL << (cpu_has_page1gb &&
                       !(s & ((1UL << L3_PAGETABLE_SHIFT) - 1)) ?
                       L3_PAGETABLE_SHIFT - PAGE_SHIFT :
                       L2_PAGETABLE_SHIFT - PAGE_SHIFT);
        /*
         * The hardcoded 4 below is arbitrary - just pick whatever you think
         * is reasonable to waste as a trade-off for using a large page.
         */
        while ( step && s + (step << PAGE_SHIFT) > e + (4 << PAGE_SHIFT) )
            step >>= PAGETABLE_ORDER;
        mfn = alloc_boot_pages(step, step);
        map_pages_to_xen(s, mfn_x(mfn), step, PAGE_HYPERVISOR);
    }

    memset(start, 0, end - start);
    memset(end, -1, s - e);
}

void __init init_frametable(void)
{
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;
    struct page_info *end_pg, *top_pg;

    BUILD_BUG_ON(XEN_VIRT_END > FRAMETABLE_VIRT_START);
    BUILD_BUG_ON(FRAMETABLE_VIRT_START & ((1UL << L2_PAGETABLE_SHIFT) - 1));

    for ( sidx = 0; ; sidx = nidx )
    {
        eidx = find_next_zero_bit(pdx_group_valid, max_idx, sidx);
        nidx = find_next_bit(pdx_group_valid, max_idx, eidx);
        if ( nidx >= max_idx )
            break;
        init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT),
                              pdx_to_page(eidx * PDX_GROUP_COUNT));
    }

    end_pg = pdx_to_page(max_pdx - 1) + 1;
    top_pg = mem_hotplug ? pdx_to_page(max_idx * PDX_GROUP_COUNT - 1) + 1
                         : end_pg;
    init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT), top_pg);
    memset(end_pg, -1, (unsigned long)top_pg - (unsigned long)end_pg);
}

#ifndef NDEBUG
static unsigned int __read_mostly root_pgt_pv_xen_slots
    = ROOT_PAGETABLE_PV_XEN_SLOTS;
static l4_pgentry_t __read_mostly split_l4e;
#else
#define root_pgt_pv_xen_slots ROOT_PAGETABLE_PV_XEN_SLOTS
#endif

void __init arch_init_memory(void)
{
    unsigned long i, pfn, rstart_pfn, rend_pfn, iostart_pfn, ioend_pfn;

    /*
     * Basic guest-accessible flags:
     *   PRESENT, R/W, USER, A/D, AVAIL[0,1,2], AVAIL_HIGH, NX (if available).
     */
    base_disallow_mask =
        ~(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED |
          _PAGE_DIRTY | _PAGE_AVAIL | _PAGE_AVAIL_HIGH | _PAGE_NX);

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     * Hidden PCI devices will also be associated with this domain
     * (but be [partly] controlled by Dom0 nevertheless).
     */
    dom_xen = domain_create(DOMID_XEN, NULL);
    BUG_ON(IS_ERR(dom_xen));
    INIT_LIST_HEAD(&dom_xen->arch.pdev_list);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create(DOMID_IO, NULL);
    BUG_ON(IS_ERR(dom_io));

    /*
     * Initialise our COW domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create(DOMID_COW, NULL);
    BUG_ON(IS_ERR(dom_cow));

    /*
     * First 1MB of RAM is historically marked as I/O.  If we booted PVH,
     * reclaim the space.  Irrespective, leave MFN 0 as special for the sake
     * of 0 being a very common default value. Also reserve the RAM needed by
     * the trampoline on PVH starting at MFN 1.
     */
    BUG_ON(pvh_boot && trampoline_phys != 0x1000);
    for ( i = 0;
          i < (pvh_boot ? (1 + PFN_UP(trampoline_end - trampoline_start))
                        : 0x100);
          i++ )
        share_xen_page_with_guest(mfn_to_page(_mfn(i)), dom_io, SHARE_rw);

    /* Any areas not specified as RAM by the e820 map are considered I/O. */
    for ( i = 0, pfn = 0; pfn < max_page; i++ )
    {
        while ( (i < e820.nr_map) &&
                (e820.map[i].type != E820_RAM) &&
                (e820.map[i].type != E820_UNUSABLE) )
            i++;

        if ( i >= e820.nr_map )
        {
            /* No more RAM regions: mark as I/O right to end of memory map. */
            rstart_pfn = rend_pfn = max_page;
        }
        else
        {
            /* Mark as I/O just up as far as next RAM region. */
            rstart_pfn = min_t(unsigned long, max_page,
                               PFN_UP(e820.map[i].addr));
            rend_pfn   = max_t(unsigned long, rstart_pfn,
                               PFN_DOWN(e820.map[i].addr + e820.map[i].size));
        }

        /*
         * Make sure any Xen mappings of RAM holes above 1MB are blown away.
         * In particular this ensures that RAM holes are respected even in
         * the statically-initialised 1-16MB mapping area.
         */
        iostart_pfn = max_t(unsigned long, pfn, 1UL << (20 - PAGE_SHIFT));
        ioend_pfn = min(rstart_pfn, 16UL << (20 - PAGE_SHIFT));
        if ( iostart_pfn < ioend_pfn )
            destroy_xen_mappings((unsigned long)mfn_to_virt(iostart_pfn),
                                 (unsigned long)mfn_to_virt(ioend_pfn));

        /* Mark as I/O up to next RAM region. */
        for ( ; pfn < rstart_pfn; pfn++ )
        {
            if ( !mfn_valid(_mfn(pfn)) )
                continue;

            share_xen_page_with_guest(mfn_to_page(_mfn(pfn)), dom_io, SHARE_rw);
        }

        /* Skip the RAM region. */
        pfn = rend_pfn;
    }

    subarch_init_memory();

    efi_init_memory();

    mem_sharing_init();

#ifndef NDEBUG
    if ( highmem_start )
    {
        unsigned long split_va = (unsigned long)__va(highmem_start);

        if ( split_va < HYPERVISOR_VIRT_END &&
             split_va - 1 == (unsigned long)__va(highmem_start - 1) )
        {
            root_pgt_pv_xen_slots = l4_table_offset(split_va) -
                                    ROOT_PAGETABLE_FIRST_XEN_SLOT;
            ASSERT(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS);
            if ( l4_table_offset(split_va) == l4_table_offset(split_va - 1) )
            {
                l3_pgentry_t *l3tab = alloc_xen_pagetable();

                if ( l3tab )
                {
                    const l3_pgentry_t *l3idle =
                        l4e_to_l3e(idle_pg_table[l4_table_offset(split_va)]);

                    for ( i = 0; i < l3_table_offset(split_va); ++i )
                        l3tab[i] = l3idle[i];
                    for ( ; i < L3_PAGETABLE_ENTRIES; ++i )
                        l3tab[i] = l3e_empty();
                    split_l4e = l4e_from_pfn(virt_to_mfn(l3tab),
                                             __PAGE_HYPERVISOR_RW);
                }
                else
                    ++root_pgt_pv_xen_slots;
            }
        }
    }
#endif
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    uint64_t maddr = pfn_to_paddr(mfn);
    int i;

    for ( i = 0; i < e820.nr_map; i++ )
    {
        switch ( e820.map[i].type )
        {
        case E820_RAM:
            if ( mem_type & RAM_TYPE_CONVENTIONAL )
                break;
            continue;
        case E820_RESERVED:
            if ( mem_type & RAM_TYPE_RESERVED )
                break;
            continue;
        case E820_UNUSABLE:
            if ( mem_type & RAM_TYPE_UNUSABLE )
                break;
            continue;
        case E820_ACPI:
        case E820_NVS:
            if ( mem_type & RAM_TYPE_ACPI )
                break;
            continue;
        default:
            /* unknown */
            continue;
        }

        /* Test the range. */
        if ( (e820.map[i].addr <= maddr) &&
             ((e820.map[i].addr + e820.map[i].size) >= (maddr + PAGE_SIZE)) )
            return 1;
    }

    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    if ( is_hvm_domain(d) )
        return p2m_get_hostp2m(d)->max_mapped_pfn;
    /* NB. PV guests specify nr_pfns rather than max_pfn so we adjust here. */
    return (arch_get_max_pfn(d) ?: 1) - 1;
}

void share_xen_page_with_guest(struct page_info *page, struct domain *d,
                               enum XENSHARE_flags flags)
{
    if ( page_get_owner(page) == d )
        return;

    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), INVALID_M2P_ENTRY);

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info =
        (flags == SHARE_ro ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    smp_wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT((page->count_info & ~PGC_xen_heap) == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        page->count_info |= PGC_xen_heap | PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        page_list_add_tail(page, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

int __init unshare_xen_page_with_guest(struct page_info *page,
                                       struct domain *d)
{
    if ( page_get_owner(page) != d || !is_xen_heap_page(page) )
        return -EINVAL;

    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    /* Remove the owner and clear the flags. */
    page->u.inuse.type_info = 0;
    page_set_owner(page, NULL);

    return 0;
}

void free_shared_domheap_page(struct page_info *page)
{
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);
    if ( !test_and_clear_bit(_PGC_xen_heap, &page->count_info) )
        ASSERT_UNREACHABLE();
    page->u.inuse.type_info = 0;
    page_set_owner(page, NULL);
    free_domheap_page(page);
}

void make_cr3(struct vcpu *v, mfn_t mfn)
{
    v->arch.cr3 = mfn_x(mfn) << PAGE_SHIFT;
}

void write_ptbase(struct vcpu *v)
{
    write_cr3(v->arch.cr3);
}

/*
 * Should be called after CR3 is updated.
 *
 * Uses values found in vcpu->arch.(guest_table and guest_table_user), and
 * for HVM guests, arch.monitor_table and hvm's guest CR3.
 *
 * Update ref counts to shadow tables appropriately.
 */
void update_cr3(struct vcpu *v)
{
    mfn_t cr3_mfn;

    if ( paging_mode_enabled(v->domain) )
    {
        paging_update_cr3(v, false);
        return;
    }

    if ( !(v->arch.flags & TF_kernel_mode) )
        cr3_mfn = pagetable_get_mfn(v->arch.guest_table_user);
    else
        cr3_mfn = pagetable_get_mfn(v->arch.guest_table);

    make_cr3(v, cr3_mfn);
}

static inline void set_tlbflush_timestamp(struct page_info *page)
{
    /*
     * Record TLB information for flush later. We do not stamp page tables
     * when running in shadow mode:
     *  1. Pointless, since it's the shadow pt's which must be tracked.
     *  2. Shadow mode reuses this field for shadowed page tables to store
     *     flags info -- we don't want to conflict with that.
     */
    if ( !(page->count_info & PGC_page_table) ||
         !shadow_mode_enabled(page_get_owner(page)) )
        page_set_tlbflush_timestamp(page);
}

const char __section(".bss.page_aligned.const") __aligned(PAGE_SIZE)
    zero_page[PAGE_SIZE];


static int alloc_segdesc_page(struct page_info *page)
{
    const struct domain *owner = page_get_owner(page);
    struct desc_struct *descs = __map_domain_page(page);
    unsigned i;

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(owner, &descs[i])) )
            break;

    unmap_domain_page(descs);

    return i == 512 ? 0 : -EINVAL;
}

static int get_page_and_type_from_mfn(
    mfn_t mfn, unsigned long type, struct domain *d,
    int partial, int preemptible)
{
    struct page_info *page = mfn_to_page(mfn);
    int rc;

    if ( likely(partial >= 0) &&
         unlikely(!get_page_from_mfn(mfn, d)) )
        return -EINVAL;

    rc = (preemptible ?
          get_page_type_preemptible(page, type) :
          (get_page_type(page, type) ? 0 : -EINVAL));

    if ( unlikely(rc) && partial >= 0 &&
         (!preemptible || page != current->arch.old_guest_table) )
        put_page(page);

    return rc;
}

static void put_data_page(
    struct page_info *page, int writeable)
{
    if ( writeable )
        put_page_and_type(page);
    else
        put_page(page);
}

#ifdef CONFIG_PV_LINEAR_PT

static bool inc_linear_entries(struct page_info *pg)
{
    typeof(pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;

    do {
        /*
         * The check below checks for the "linear use" count being non-zero
         * as well as overflow.  Signed integer overflow is undefined behavior
         * according to the C spec.  However, as long as linear_pt_count is
         * smaller in size than 'int', the arithmetic operation of the
         * increment below won't overflow; rather the result will be truncated
         * when stored.  Ensure that this is always true.
         */
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc++;
        if ( nc <= 0 )
            return false;
        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while ( oc != nc );

    return true;
}

static void dec_linear_entries(struct page_info *pg)
{
    typeof(pg->linear_pt_count) oc;

    oc = arch_fetch_and_add(&pg->linear_pt_count, -1);
    ASSERT(oc > 0);
}

static bool inc_linear_uses(struct page_info *pg)
{
    typeof(pg->linear_pt_count) nc = read_atomic(&pg->linear_pt_count), oc;

    do {
        /* See the respective comment in inc_linear_entries(). */
        BUILD_BUG_ON(sizeof(nc) >= sizeof(int));
        oc = nc--;
        if ( nc >= 0 )
            return false;
        nc = cmpxchg(&pg->linear_pt_count, oc, nc);
    } while ( oc != nc );

    return true;
}

static void dec_linear_uses(struct page_info *pg)
{
    typeof(pg->linear_pt_count) oc;

    oc = arch_fetch_and_add(&pg->linear_pt_count, 1);
    ASSERT(oc < 0);
}

/*
 * We allow root tables to map each other (a.k.a. linear page tables). It
 * needs some special care with reference counts and access permissions:
 *  1. The mapping entry must be read-only, or the guest may get write access
 *     to its own PTEs.
 *  2. We must only bump the reference counts for an *already validated*
 *     L2 table, or we can end up in a deadlock in get_page_type() by waiting
 *     on a validation that is required to complete that validation.
 *  3. We only need to increment the reference counts for the mapped page
 *     frame if it is mapped by a different root table. This is sufficient and
 *     also necessary to allow validation of a root table mapping itself.
 */
static bool __read_mostly opt_pv_linear_pt = true;
boolean_param("pv-linear-pt", opt_pv_linear_pt);

#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    unsigned long pfn;                                                      \
                                                                            \
    if ( !opt_pv_linear_pt )                                                \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. (feature disabled)\n");     \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (level##e_get_flags(pde) & _PAGE_RW) )                             \
    {                                                                       \
        gdprintk(XENLOG_WARNING,                                            \
                 "Attempt to create linear p.t. with write perms\n");       \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (pfn = level##e_get_pfn(pde)) != pde_pfn )                         \
    {                                                                       \
        struct page_info *page, *ptpg = mfn_to_page(_mfn(pde_pfn));         \
                                                                            \
        /* Make sure the page table belongs to the correct domain. */       \
        if ( unlikely(page_get_owner(ptpg) != d) )                          \
            return 0;                                                       \
                                                                            \
        /* Make sure the mapped frame belongs to the correct domain. */     \
        page = get_page_from_mfn(_mfn(pfn), d);                             \
        if ( unlikely(!page) )                                              \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table  \
         * and is not itself having linear entries, as well as that the     \
         * containing page table is not iself in use as a linear page table \
         * elsewhere.                                                       \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        if ( !inc_linear_entries(ptpg) )                                    \
        {                                                                   \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        if ( !inc_linear_uses(page) )                                       \
        {                                                                   \
            dec_linear_entries(ptpg);                                       \
            put_page(page);                                                 \
            return 0;                                                       \
        }                                                                   \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                dec_linear_uses(page);                                      \
                dec_linear_entries(ptpg);                                   \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}

#else /* CONFIG_PV_LINEAR_PT */

#define define_get_linear_pagetable(level)                              \
static int                                                              \
get_##level##_linear_pagetable(                                         \
        level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d) \
{                                                                       \
        return 0;                                                       \
}

static void dec_linear_uses(struct page_info *pg)
{
    ASSERT(pg->linear_pt_count == 0);
}

static void dec_linear_entries(struct page_info *pg)
{
    ASSERT(pg->linear_pt_count == 0);
}

#endif /* CONFIG_PV_LINEAR_PT */

bool is_iomem_page(mfn_t mfn)
{
    struct page_info *page;

    if ( !mfn_valid(mfn) )
        return true;

    /* Caller must know that it is an iomem page, or a reference is held. */
    page = mfn_to_page(mfn);
    ASSERT((page->count_info & PGC_count_mask) != 0);

    return (page_get_owner(page) == dom_io);
}

static int update_xen_mappings(unsigned long mfn, unsigned int cacheattr)
{
    int err = 0;
    bool alias = mfn >= PFN_DOWN(xen_phys_start) &&
         mfn < PFN_UP(xen_phys_start + xen_virt_end - XEN_VIRT_START);
    unsigned long xen_va =
        XEN_VIRT_START + ((mfn - PFN_DOWN(xen_phys_start)) << PAGE_SHIFT);

    if ( unlikely(alias) && cacheattr )
        err = map_pages_to_xen(xen_va, mfn, 1, 0);
    if ( !err )
        err = map_pages_to_xen((unsigned long)mfn_to_virt(mfn), mfn, 1,
                     PAGE_HYPERVISOR | cacheattr_to_pte_flags(cacheattr));
    if ( unlikely(alias) && !cacheattr && !err )
        err = map_pages_to_xen(xen_va, mfn, 1, PAGE_HYPERVISOR);
    return err;
}

#ifndef NDEBUG
struct mmio_emul_range_ctxt {
    const struct domain *d;
    unsigned long mfn;
};

static int print_mmio_emul_range(unsigned long s, unsigned long e, void *arg)
{
    const struct mmio_emul_range_ctxt *ctxt = arg;

    if ( ctxt->mfn > e )
        return 0;

    if ( ctxt->mfn >= s )
    {
        static DEFINE_SPINLOCK(last_lock);
        static const struct domain *last_d;
        static unsigned long last_s = ~0UL, last_e;
        bool print = false;

        spin_lock(&last_lock);
        if ( last_d != ctxt->d || last_s != s || last_e != e )
        {
            last_d = ctxt->d;
            last_s = s;
            last_e = e;
            print = true;
        }
        spin_unlock(&last_lock);

        if ( print )
            printk(XENLOG_G_INFO
                   "d%d: Forcing write emulation on MFNs %lx-%lx\n",
                   ctxt->d->domain_id, s, e);
    }

    return 1;
}
#endif

/*
 * get_page_from_l1e returns:
 *   0  => success (page not present also counts as such)
 *  <0  => error code
 *  >0  => the page flags to be flipped
 */
int
get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *l1e_owner, struct domain *pg_owner)
{
    unsigned long mfn = l1e_get_pfn(l1e);
    struct page_info *page = mfn_to_page(_mfn(mfn));
    uint32_t l1f = l1e_get_flags(l1e);
    struct vcpu *curr = current;
    struct domain *real_pg_owner;
    bool write;

    if ( !(l1f & _PAGE_PRESENT) )
        return 0;

    if ( unlikely(l1f & l1_disallow_mask(l1e_owner)) )
    {
        gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n",
                 l1f & l1_disallow_mask(l1e_owner));
        return -EINVAL;
    }

    if ( !mfn_valid(_mfn(mfn)) ||
         (real_pg_owner = page_get_owner_and_reference(page)) == dom_io )
    {
        int flip = 0;

        /* Only needed the reference to confirm dom_io ownership. */
        if ( mfn_valid(_mfn(mfn)) )
            put_page(page);

        /* DOMID_IO reverts to caller for privilege checks. */
        if ( pg_owner == dom_io )
            pg_owner = curr->domain;

        if ( !iomem_access_permitted(pg_owner, mfn, mfn) )
        {
            if ( mfn != (PADDR_MASK >> PAGE_SHIFT) ) /* INVALID_MFN? */
            {
                gdprintk(XENLOG_WARNING,
                         "d%d non-privileged attempt to map MMIO space %"PRI_mfn"\n",
                         pg_owner->domain_id, mfn);
                return -EPERM;
            }
            return -EINVAL;
        }

        if ( pg_owner != l1e_owner &&
             !iomem_access_permitted(l1e_owner, mfn, mfn) )
        {
            if ( mfn != (PADDR_MASK >> PAGE_SHIFT) ) /* INVALID_MFN? */
            {
                gdprintk(XENLOG_WARNING,
                         "d%d attempted to map MMIO space %"PRI_mfn" in d%d to d%d\n",
                         curr->domain->domain_id, mfn, pg_owner->domain_id,
                         l1e_owner->domain_id);
                return -EPERM;
            }
            return -EINVAL;
        }

        if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
        {
            /* MMIO pages must not be mapped cachable unless requested so. */
            switch ( opt_mmio_relax )
            {
            case 0:
                break;
            case 1:
                if ( !is_hardware_domain(l1e_owner) )
                    break;
                /* fallthrough */
            case -1:
                return 0;
            default:
                ASSERT_UNREACHABLE();
            }
        }
        else if ( l1f & _PAGE_RW )
        {
#ifndef NDEBUG
            const unsigned long *ro_map;
            unsigned int seg, bdf;

            if ( !pci_mmcfg_decode(mfn, &seg, &bdf) ||
                 ((ro_map = pci_get_ro_map(seg)) != NULL &&
                  test_bit(bdf, ro_map)) )
                printk(XENLOG_G_WARNING
                       "d%d: Forcing read-only access to MFN %lx\n",
                       l1e_owner->domain_id, mfn);
            else
                rangeset_report_ranges(mmio_ro_ranges, 0, ~0UL,
                                       print_mmio_emul_range,
                                       &(struct mmio_emul_range_ctxt){
                                           .d = l1e_owner,
                                           .mfn = mfn });
#endif
            flip = _PAGE_RW;
        }

        switch ( l1f & PAGE_CACHE_ATTRS )
        {
        case 0: /* WB */
            flip |= _PAGE_PWT | _PAGE_PCD;
            break;
        case _PAGE_PWT: /* WT */
        case _PAGE_PWT | _PAGE_PAT: /* WP */
            flip |= _PAGE_PCD | (l1f & _PAGE_PAT);
            break;
        }

        return flip;
    }

    if ( unlikely( (real_pg_owner != pg_owner) &&
                   (real_pg_owner != dom_cow) ) )
    {
        /*
         * Let privileged domains transfer the right to map their target
         * domain's pages. This is used to allow stub-domain pvfb export to
         * dom0, until pvfb supports granted mappings. At that time this
         * minor hack can go away.
         */
        if ( (real_pg_owner == NULL) || (pg_owner == l1e_owner) ||
             xsm_priv_mapping(XSM_TARGET, pg_owner, real_pg_owner) )
        {
            gdprintk(XENLOG_WARNING,
                     "pg_owner d%d l1e_owner d%d, but real_pg_owner d%d\n",
                     pg_owner->domain_id, l1e_owner->domain_id,
                     real_pg_owner ? real_pg_owner->domain_id : -1);
            goto could_not_pin;
        }
        pg_owner = real_pg_owner;
    }

    /*
     * Extra paranoid check for shared memory. Writable mappings
     * disallowed (unshare first!)
     */
    if ( (l1f & _PAGE_RW) && (real_pg_owner == dom_cow) )
        goto could_not_pin;

    /*
     * Foreign mappings into guests in shadow external mode don't
     * contribute to writeable mapping refcounts.  (This allows the
     * qemu-dm helper process in dom0 to map the domain's memory without
     * messing up the count of "real" writable mappings.)
     */
    write = (l1f & _PAGE_RW) &&
            ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner));
    if ( write && !get_page_type(page, PGT_writable_page) )
    {
        gdprintk(XENLOG_WARNING, "Could not get page type PGT_writable_page\n");
        goto could_not_pin;
    }

    if ( pte_flags_to_cacheattr(l1f) !=
         ((page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base) )
    {
        unsigned long x, nx, y = page->count_info;
        unsigned long cacheattr = pte_flags_to_cacheattr(l1f);
        int err;

        if ( is_xen_heap_page(page) )
        {
            if ( write )
                put_page_type(page);
            put_page(page);
            gdprintk(XENLOG_WARNING,
                     "Attempt to change cache attributes of Xen heap page\n");
            return -EACCES;
        }

        do {
            x  = y;
            nx = (x & ~PGC_cacheattr_mask) | (cacheattr << PGC_cacheattr_base);
        } while ( (y = cmpxchg(&page->count_info, x, nx)) != x );

        err = update_xen_mappings(mfn, cacheattr);
        if ( unlikely(err) )
        {
            cacheattr = y & PGC_cacheattr_mask;
            do {
                x  = y;
                nx = (x & ~PGC_cacheattr_mask) | cacheattr;
            } while ( (y = cmpxchg(&page->count_info, x, nx)) != x );

            if ( write )
                put_page_type(page);
            put_page(page);

            gdprintk(XENLOG_WARNING, "Error updating mappings for mfn %" PRI_mfn
                     " (pfn %" PRI_pfn ", from L1 entry %" PRIpte ") for d%d\n",
                     mfn, get_gpfn_from_mfn(mfn),
                     l1e_get_intpte(l1e), l1e_owner->domain_id);
            return err;
        }
    }

    return 0;

 could_not_pin:
    gdprintk(XENLOG_WARNING, "Error getting mfn %" PRI_mfn " (pfn %" PRI_pfn
             ") from L1 entry %" PRIpte " for l1e_owner d%d, pg_owner d%d\n",
             mfn, get_gpfn_from_mfn(mfn),
             l1e_get_intpte(l1e), l1e_owner->domain_id, pg_owner->domain_id);
    if ( real_pg_owner != NULL )
        put_page(page);
    return -EBUSY;
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
/*
 * get_page_from_l2e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l2);
static int
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn, struct domain *d)
{
    unsigned long mfn = l2e_get_pfn(l2e);
    int rc;

    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK)) )
    {
        gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n",
                 l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(_mfn(mfn), PGT_l1_page_table, d, 0, 0);
    if ( unlikely(rc == -EINVAL) && get_l2_linear_pagetable(l2e, pfn, d) )
        rc = 0;

    return rc;
}


/*
 * get_page_from_l3e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l3);
static int
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn, struct domain *d, int partial)
{
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3e_get_flags(l3e) & l3_disallow_mask(d))) )
    {
        gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n",
                 l3e_get_flags(l3e) & l3_disallow_mask(d));
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(
        l3e_get_mfn(l3e), PGT_l2_page_table, d, partial, 1);
    if ( unlikely(rc == -EINVAL) &&
         !is_pv_32bit_domain(d) &&
         get_l3_linear_pagetable(l3e, pfn, d) )
        rc = 0;

    return rc;
}

/*
 * get_page_from_l4e returns:
 *   1 => page not present
 *   0 => success
 *  <0 => error code
 */
define_get_linear_pagetable(l4);
static int
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, struct domain *d, int partial)
{
    int rc;

    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK)) )
    {
        gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n",
                 l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return -EINVAL;
    }

    rc = get_page_and_type_from_mfn(
        l4e_get_mfn(l4e), PGT_l3_page_table, d, partial, 1);
    if ( unlikely(rc == -EINVAL) && get_l4_linear_pagetable(l4e, pfn, d) )
        rc = 0;

    return rc;
}

static int _put_page_type(struct page_info *page, bool preemptible,
                          struct page_info *ptpg);

void put_page_from_l1e(l1_pgentry_t l1e, struct domain *l1e_owner)
{
    unsigned long     pfn = l1e_get_pfn(l1e);
    struct page_info *page;
    struct domain    *pg_owner;
    struct vcpu      *v;

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) || is_iomem_page(_mfn(pfn)) )
        return;

    page = mfn_to_page(_mfn(pfn));
    pg_owner = page_get_owner(page);

    /*
     * Check if this is a mapping that was established via a grant reference.
     * If it was then we should not be here: we require that such mappings are
     * explicitly destroyed via the grant-table interface.
     *
     * The upshot of this is that the guest can end up with active grants that
     * it cannot destroy (because it no longer has a PTE to present to the
     * grant-table interface). This can lead to subtle hard-to-catch bugs,
     * hence a special grant PTE flag can be enabled to catch the bug early.
     *
     * (Note that the undestroyable active grants are not a security hole in
     * Xen. All active grants can safely be cleaned up when the domain dies.)
     */
    if ( (l1e_get_flags(l1e) & _PAGE_GNTTAB) &&
         !l1e_owner->is_shutting_down && !l1e_owner->is_dying )
    {
        gdprintk(XENLOG_WARNING,
                 "Attempt to implicitly unmap a granted PTE %" PRIpte "\n",
                 l1e_get_intpte(l1e));
        domain_crash(l1e_owner);
    }

    /*
     * Remember we didn't take a type-count of foreign writable mappings
     * to paging-external domains.
     */
    if ( (l1e_get_flags(l1e) & _PAGE_RW) &&
         ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner)) )
    {
        put_page_and_type(page);
    }
    else
    {
        /* We expect this is rare so we blow the entire shadow LDT. */
        if ( unlikely(((page->u.inuse.type_info & PGT_type_mask) ==
                       PGT_seg_desc_page)) &&
             unlikely(((page->u.inuse.type_info & PGT_count_mask) != 0)) &&
             (l1e_owner == pg_owner) )
        {
            for_each_vcpu ( pg_owner, v )
            {
                if ( pv_destroy_ldt(v) )
                    flush_tlb_mask(cpumask_of(v->dirty_cpu));
            }
        }
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static int put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) || (l2e_get_pfn(l2e) == pfn) )
        return 1;

    if ( l2e_get_flags(l2e) & _PAGE_PSE )
    {
        struct page_info *page = l2e_get_page(l2e);
        unsigned int i;

        for ( i = 0; i < (1u << PAGETABLE_ORDER); i++, page++ )
            put_page_and_type(page);
    }
    else
    {
        struct page_info *pg = l2e_get_page(l2e);
        int rc = _put_page_type(pg, false, mfn_to_page(_mfn(pfn)));

        ASSERT(!rc);
        put_page(pg);
    }

    return 0;
}

static int put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn,
                             int partial, bool defer)
{
    struct page_info *pg;
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_pfn(l3e) == pfn) )
        return 1;

    if ( unlikely(l3e_get_flags(l3e) & _PAGE_PSE) )
    {
        unsigned long mfn = l3e_get_pfn(l3e);
        int writeable = l3e_get_flags(l3e) & _PAGE_RW;

        ASSERT(!(mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)));
        do {
            put_data_page(mfn_to_page(_mfn(mfn)), writeable);
        } while ( ++mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1) );

        return 0;
    }

    pg = l3e_get_page(l3e);

    if ( unlikely(partial > 0) )
    {
        ASSERT(!defer);
        return _put_page_type(pg, true, mfn_to_page(_mfn(pfn)));
    }

    if ( defer )
    {
        current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
        current->arch.old_guest_table = pg;
        return 0;
    }

    rc = _put_page_type(pg, true, mfn_to_page(_mfn(pfn)));
    if ( likely(!rc) )
        put_page(pg);

    return rc;
}

static int put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn,
                             int partial, bool defer)
{
    int rc = 1;

    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) &&
         (l4e_get_pfn(l4e) != pfn) )
    {
        struct page_info *pg = l4e_get_page(l4e);

        if ( unlikely(partial > 0) )
        {
            ASSERT(!defer);
            return _put_page_type(pg, true, mfn_to_page(_mfn(pfn)));
        }

        if ( defer )
        {
            current->arch.old_guest_ptpg = mfn_to_page(_mfn(pfn));
            current->arch.old_guest_table = pg;
            return 0;
        }

        rc = _put_page_type(pg, true, mfn_to_page(_mfn(pfn)));
        if ( likely(!rc) )
            put_page(pg);
    }

    return rc;
}

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    l1_pgentry_t  *pl1e;
    unsigned int   i;
    int            ret = 0;

    pl1e = __map_domain_page(page);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        switch ( ret = get_page_from_l1e(pl1e[i], d, d) )
        {
        default:
            goto fail;
        case 0:
            break;
        case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
            ASSERT(!(ret & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
            l1e_flip_flags(pl1e[i], ret);
            break;
        }

        pl1e[i] = adjust_guest_l1e(pl1e[i], d);
    }

    unmap_domain_page(pl1e);
    return 0;

 fail:
    gdprintk(XENLOG_WARNING, "Failure in alloc_l1_table: slot %#x\n", i);
    while ( i-- > 0 )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
    return ret;
}

static int create_pae_xen_mappings(struct domain *d, l3_pgentry_t *pl3e)
{
    struct page_info *page;
    l3_pgentry_t     l3e3;

    if ( !is_pv_32bit_domain(d) )
        return 1;

    pl3e = (l3_pgentry_t *)((unsigned long)pl3e & PAGE_MASK);

    /* 3rd L3 slot contains L2 with Xen-private mappings. It *must* exist. */
    l3e3 = pl3e[3];
    if ( !(l3e_get_flags(l3e3) & _PAGE_PRESENT) )
    {
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is empty\n");
        return 0;
    }

    /*
     * The Xen-private mappings include linear mappings. The L2 thus cannot
     * be shared by multiple L3 tables. The test here is adequate because:
     *  1. Cannot appear in slots != 3 because get_page_type() checks the
     *     PGT_pae_xen_l2 flag, which is asserted iff the L2 appears in slot 3
     *  2. Cannot appear in another page table's L3:
     *     a. alloc_l3_table() calls this function and this check will fail
     *     b. mod_l3_entry() disallows updates to slot 3 in an existing table
     */
    page = l3e_get_page(l3e3);
    BUG_ON(page->u.inuse.type_info & PGT_pinned);
    BUG_ON((page->u.inuse.type_info & PGT_count_mask) == 0);
    BUG_ON(!(page->u.inuse.type_info & PGT_pae_xen_l2));
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        gdprintk(XENLOG_WARNING, "PAE L3 3rd slot is shared\n");
        return 0;
    }

    return 1;
}

static int alloc_l2_table(struct page_info *page, unsigned long type,
                          int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t  *pl2e;
    unsigned int   i;
    int            rc = 0;

    pl2e = map_domain_page(_mfn(pfn));

    for ( i = page->nr_validated_ptes; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( preemptible && i > page->nr_validated_ptes
             && hypercall_preempt_check() )
        {
            page->nr_validated_ptes = i;
            rc = -ERESTART;
            break;
        }

        if ( !is_guest_l2_slot(d, type, i) ||
             (rc = get_page_from_l2e(pl2e[i], pfn, d)) > 0 )
            continue;

        if ( rc < 0 )
        {
            gdprintk(XENLOG_WARNING, "Failure in alloc_l2_table: slot %#x\n", i);
            while ( i-- > 0 )
                if ( is_guest_l2_slot(d, type, i) )
                    put_page_from_l2e(pl2e[i], pfn);
            break;
        }

        pl2e[i] = adjust_guest_l2e(pl2e[i], d);
    }

    if ( rc >= 0 && (type & PGT_pae_xen_l2) )
        init_xen_pae_l2_slots(pl2e, d);

    unmap_domain_page(pl2e);
    return rc > 0 ? 0 : rc;
}

static int alloc_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t  *pl3e;
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

    pl3e = map_domain_page(_mfn(pfn));

    /*
     * PAE guests allocate full pages, but aren't required to initialize
     * more than the first four entries; when running in compatibility
     * mode, however, the full page is visible to the MMU, and hence all
     * 512 entries must be valid/verified, which is most easily achieved
     * by clearing them out.
     */
    if ( is_pv_32bit_domain(d) )
        memset(pl3e + 4, 0, (L3_PAGETABLE_ENTRIES - 4) * sizeof(*pl3e));

    for ( i = page->nr_validated_ptes; i < L3_PAGETABLE_ENTRIES;
          i++, partial = 0 )
    {
        if ( is_pv_32bit_domain(d) && (i == 3) )
        {
            if ( !(l3e_get_flags(pl3e[i]) & _PAGE_PRESENT) ||
                 (l3e_get_flags(pl3e[i]) & l3_disallow_mask(d)) )
                rc = -EINVAL;
            else
                rc = get_page_and_type_from_mfn(
                    l3e_get_mfn(pl3e[i]),
                    PGT_l2_page_table | PGT_pae_xen_l2, d, partial, 1);
        }
        else if ( (rc = get_page_from_l3e(pl3e[i], pfn, d, partial)) > 0 )
            continue;

        if ( rc == -ERESTART )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc == -EINTR && i )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = 0;
            rc = -ERESTART;
        }
        if ( rc < 0 )
            break;

        pl3e[i] = adjust_guest_l3e(pl3e[i], d);
    }

    if ( rc >= 0 && !create_pae_xen_mappings(d, pl3e) )
        rc = -EINVAL;
    if ( rc < 0 && rc != -ERESTART && rc != -EINTR )
    {
        gdprintk(XENLOG_WARNING, "Failure in alloc_l3_table: slot %#x\n", i);
        if ( i )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = 0;
            current->arch.old_guest_ptpg = NULL;
            current->arch.old_guest_table = page;
        }
        while ( i-- > 0 )
            pl3e[i] = unadjust_guest_l3e(pl3e[i], d);
    }

    unmap_domain_page(pl3e);
    return rc > 0 ? 0 : rc;
}

void init_xen_pae_l2_slots(l2_pgentry_t *l2t, const struct domain *d)
{
    memcpy(&l2t[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
           &compat_idle_pg_table_l2[
               l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
           COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*l2t));
}

/*
 * Fill an L4 with Xen entries.
 *
 * This function must write all ROOT_PAGETABLE_PV_XEN_SLOTS, to clobber any
 * values a guest may have left there from alloc_l4_table().
 *
 * l4t and l4mfn are mandatory, but l4mfn doesn't need to be the mfn under
 * *l4t.  All other parameters are optional and will either fill or zero the
 * appropriate slots.  Pagetables not shared with guests will gain the
 * extended directmap.
 */
void init_xen_l4_slots(l4_pgentry_t *l4t, mfn_t l4mfn,
                       const struct domain *d, mfn_t sl4mfn, bool ro_mpt)
{
    /*
     * PV vcpus need a shortened directmap.  HVM and Idle vcpus get the full
     * directmap.
     */
    bool short_directmap = d && !paging_mode_external(d);

    /* Slot 256: RO M2P (if applicable). */
    l4t[l4_table_offset(RO_MPT_VIRT_START)] =
        ro_mpt ? idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)]
               : l4e_empty();

    /* Slot 257: PCI MMCFG. */
    l4t[l4_table_offset(PCI_MCFG_VIRT_START)] =
        idle_pg_table[l4_table_offset(PCI_MCFG_VIRT_START)];

    /* Slot 258: Self linear mappings. */
    ASSERT(!mfn_eq(l4mfn, INVALID_MFN));
    l4t[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_mfn(l4mfn, __PAGE_HYPERVISOR_RW);

    /* Slot 259: Shadow linear mappings (if applicable) .*/
    l4t[l4_table_offset(SH_LINEAR_PT_VIRT_START)] =
        mfn_eq(sl4mfn, INVALID_MFN) ? l4e_empty() :
        l4e_from_mfn(sl4mfn, __PAGE_HYPERVISOR_RW);

    /* Slot 260: Per-domain mappings (if applicable). */
    l4t[l4_table_offset(PERDOMAIN_VIRT_START)] =
        d ? l4e_from_page(d->arch.perdomain_l3_pg, __PAGE_HYPERVISOR_RW)
          : l4e_empty();

    /* Slot 261-: text/data/bss, RW M2P, vmap, frametable, directmap. */
#ifndef NDEBUG
    if ( short_directmap &&
         unlikely(root_pgt_pv_xen_slots < ROOT_PAGETABLE_PV_XEN_SLOTS) )
    {
        /*
         * If using highmem-start=, artificially shorten the directmap to
         * simulate very large machines.
         */
        l4_pgentry_t *next;

        memcpy(&l4t[l4_table_offset(XEN_VIRT_START)],
               &idle_pg_table[l4_table_offset(XEN_VIRT_START)],
               (ROOT_PAGETABLE_FIRST_XEN_SLOT + root_pgt_pv_xen_slots -
                l4_table_offset(XEN_VIRT_START)) * sizeof(*l4t));

        next = &l4t[ROOT_PAGETABLE_FIRST_XEN_SLOT + root_pgt_pv_xen_slots];

        if ( l4e_get_intpte(split_l4e) )
            *next++ = split_l4e;

        memset(next, 0,
               _p(&l4t[ROOT_PAGETABLE_LAST_XEN_SLOT + 1]) - _p(next));
    }
    else
#endif
    {
        unsigned int slots = (short_directmap
                              ? ROOT_PAGETABLE_PV_XEN_SLOTS
                              : ROOT_PAGETABLE_XEN_SLOTS);

        memcpy(&l4t[l4_table_offset(XEN_VIRT_START)],
               &idle_pg_table[l4_table_offset(XEN_VIRT_START)],
               (ROOT_PAGETABLE_FIRST_XEN_SLOT + slots -
                l4_table_offset(XEN_VIRT_START)) * sizeof(*l4t));
    }
}

bool fill_ro_mpt(mfn_t mfn)
{
    l4_pgentry_t *l4tab = map_domain_page(mfn);
    bool ret = false;

    if ( !l4e_get_intpte(l4tab[l4_table_offset(RO_MPT_VIRT_START)]) )
    {
        l4tab[l4_table_offset(RO_MPT_VIRT_START)] =
            idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)];
        ret = true;
    }
    unmap_domain_page(l4tab);

    return ret;
}

void zap_ro_mpt(mfn_t mfn)
{
    l4_pgentry_t *l4tab = map_domain_page(mfn);

    l4tab[l4_table_offset(RO_MPT_VIRT_START)] = l4e_empty();
    unmap_domain_page(l4tab);
}

static int alloc_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t  *pl4e = map_domain_page(_mfn(pfn));
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

    for ( i = page->nr_validated_ptes; i < L4_PAGETABLE_ENTRIES;
          i++, partial = 0 )
    {
        if ( !is_guest_l4_slot(d, i) ||
             (rc = get_page_from_l4e(pl4e[i], pfn, d, partial)) > 0 )
            continue;

        if ( rc == -ERESTART )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc < 0 )
        {
            if ( rc != -EINTR )
                gdprintk(XENLOG_WARNING,
                         "Failure in alloc_l4_table: slot %#x\n", i);
            if ( i )
            {
                page->nr_validated_ptes = i;
                page->partial_pte = 0;
                if ( rc == -EINTR )
                    rc = -ERESTART;
                else
                {
                    if ( current->arch.old_guest_table )
                        page->nr_validated_ptes++;
                    current->arch.old_guest_ptpg = NULL;
                    current->arch.old_guest_table = page;
                }
            }
        }
        if ( rc < 0 )
        {
            unmap_domain_page(pl4e);
            return rc;
        }

        pl4e[i] = adjust_guest_l4e(pl4e[i], d);
    }

    if ( rc >= 0 )
    {
        init_xen_l4_slots(pl4e, _mfn(pfn),
                          d, INVALID_MFN, VM_ASSIST(d, m2p_strict));
        atomic_inc(&d->arch.pv_domain.nr_l4_pages);
        rc = 0;
    }
    unmap_domain_page(pl4e);

    return rc;
}

static void free_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    l1_pgentry_t *pl1e;
    unsigned int  i;

    pl1e = __map_domain_page(page);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
}


static int free_l2_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l2_pgentry_t *pl2e;
    unsigned int  i = page->nr_validated_ptes - 1;
    int err = 0;

    pl2e = map_domain_page(_mfn(pfn));

    ASSERT(page->nr_validated_ptes);
    do {
        if ( is_guest_l2_slot(d, page->u.inuse.type_info, i) &&
             put_page_from_l2e(pl2e[i], pfn) == 0 &&
             preemptible && i && hypercall_preempt_check() )
        {
           page->nr_validated_ptes = i;
           err = -ERESTART;
        }
    } while ( !err && i-- );

    unmap_domain_page(pl2e);

    if ( !err )
        page->u.inuse.type_info &= ~PGT_pae_xen_l2;

    return err;
}

static int free_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l3_pgentry_t *pl3e;
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    pl3e = map_domain_page(_mfn(pfn));

    do {
        rc = put_page_from_l3e(pl3e[i], pfn, partial, 0);
        if ( rc < 0 )
            break;
        partial = 0;
        if ( rc > 0 )
            continue;
        pl3e[i] = unadjust_guest_l3e(pl3e[i], d);
    } while ( i-- );

    unmap_domain_page(pl3e);

    if ( rc == -ERESTART )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L3_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -ERESTART;
    }
    return rc > 0 ? 0 : rc;
}

static int free_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = mfn_x(page_to_mfn(page));
    l4_pgentry_t *pl4e = map_domain_page(_mfn(pfn));
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    do {
        if ( is_guest_l4_slot(d, i) )
            rc = put_page_from_l4e(pl4e[i], pfn, partial, 0);
        if ( rc < 0 )
            break;
        partial = 0;
    } while ( i-- );

    if ( rc == -ERESTART )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L4_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -ERESTART;
    }

    unmap_domain_page(pl4e);

    if ( rc >= 0 )
    {
        atomic_dec(&d->arch.pv_domain.nr_l4_pages);
        rc = 0;
    }

    return rc;
}

#ifndef NDEBUG
/*
 * We must never call _put_page_type() while holding a page_lock() for
 * that page; doing so may cause a deadlock under the right
 * conditions.
 *
 * Furthermore, there is no discipline for the order in which page locks
 * are grabbed; if there are any paths that grab the locks for two
 * different pages at once, we risk creating the conditions for a deadlock
 * to occur.
 *
 * These are believed to be safe, because it is believed that:
 * 1. No hypervisor paths ever lock two pages at once, and
 * 2. We never call _put_page_type() on a page while holding its page lock.
 *
 * Add a check to debug builds to catch any violations of these
 * assumpitons.
 *
 * NB that if we find valid, safe reasons to hold two page locks at
 * once, these checks will need to be adjusted.
 */
static DEFINE_PER_CPU(struct page_info *, current_locked_page);

static inline void current_locked_page_set(struct page_info *page) {
    this_cpu(current_locked_page) = page;
}

static inline bool current_locked_page_check(struct page_info *page) {
    return this_cpu(current_locked_page) == page;
}

/*
 * We need a separate "not-equal" check so the non-debug stubs can
 * always return true.
 */
static inline bool current_locked_page_ne_check(struct page_info *page) {
    return this_cpu(current_locked_page) != page;
}
#else
#define current_locked_page_set(x)
#define current_locked_page_check(x) true
#define current_locked_page_ne_check(x) true
#endif

int page_lock(struct page_info *page)
{
    unsigned long x, nx;

    ASSERT(current_locked_page_check(NULL));

    do {
        while ( (x = page->u.inuse.type_info) & PGT_locked )
            cpu_relax();
        nx = x + (1 | PGT_locked);
        if ( !(x & PGT_validated) ||
             !(x & PGT_count_mask) ||
             !(nx & PGT_count_mask) )
            return 0;
    } while ( cmpxchg(&page->u.inuse.type_info, x, nx) != x );

    current_locked_page_set(page);

    return 1;
}

void page_unlock(struct page_info *page)
{
    unsigned long x, nx, y = page->u.inuse.type_info;

    ASSERT(current_locked_page_check(page));

    do {
        x = y;
        ASSERT((x & PGT_count_mask) && (x & PGT_locked));

        nx = x - (1 | PGT_locked);
        /* We must not drop the last reference here. */
        ASSERT(nx & PGT_count_mask);
    } while ( (y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x );

    current_locked_page_set(NULL);
}

/*
 * PTE flags that a guest may change without re-validating the PTE.
 * All other bits affect translation, caching, or Xen's safety.
 */
#define FASTPATH_FLAG_WHITELIST                                     \
    (_PAGE_NX_BIT | _PAGE_AVAIL_HIGH | _PAGE_AVAIL | _PAGE_GLOBAL | \
     _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_USER)

/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e,
                        unsigned long gl1mfn, int preserve_ad,
                        struct vcpu *pt_vcpu, struct domain *pg_dom)
{
    l1_pgentry_t ol1e;
    struct domain *pt_dom = pt_vcpu->domain;
    int rc = 0;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return -EFAULT;

    ASSERT(!paging_mode_refcounts(pt_dom));

    if ( l1e_get_flags(nl1e) & _PAGE_PRESENT )
    {
        struct page_info *page = NULL;

        if ( unlikely(l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom)) )
        {
            gdprintk(XENLOG_WARNING, "Bad L1 flags %x\n",
                    l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom));
            return -EINVAL;
        }

        /* Translate foreign guest address. */
        if ( paging_mode_translate(pg_dom) )
        {
            p2m_type_t p2mt;
            p2m_query_t q = l1e_get_flags(nl1e) & _PAGE_RW ?
                            P2M_ALLOC | P2M_UNSHARE : P2M_ALLOC;

            page = get_page_from_gfn(pg_dom, l1e_get_pfn(nl1e), &p2mt, q);

            if ( p2m_is_paged(p2mt) )
            {
                if ( page )
                    put_page(page);
                p2m_mem_paging_populate(pg_dom, l1e_get_pfn(nl1e));
                return -ENOENT;
            }

            if ( p2mt == p2m_ram_paging_in && !page )
                return -ENOENT;

            /* Did our attempt to unshare fail? */
            if ( (q & P2M_UNSHARE) && p2m_is_shared(p2mt) )
            {
                /* We could not have obtained a page ref. */
                ASSERT(!page);
                /* And mem_sharing_notify has already been called. */
                return -ENOMEM;
            }

            if ( !page )
                return -EINVAL;
            nl1e = l1e_from_page(page, l1e_get_flags(nl1e));
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l1e_has_changed(ol1e, nl1e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl1e = adjust_guest_l1e(nl1e, pt_dom);
            rc = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                              preserve_ad);
            if ( page )
                put_page(page);
            return rc ? 0 : -EBUSY;
        }

        switch ( rc = get_page_from_l1e(nl1e, pt_dom, pg_dom) )
        {
        default:
            if ( page )
                put_page(page);
            return rc;
        case 0:
            break;
        case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
            ASSERT(!(rc & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
            l1e_flip_flags(nl1e, rc);
            rc = 0;
            break;
        }
        if ( page )
            put_page(page);

        nl1e = adjust_guest_l1e(nl1e, pt_dom);
        if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                    preserve_ad)) )
        {
            ol1e = nl1e;
            rc = -EBUSY;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                     preserve_ad)) )
    {
        return -EBUSY;
    }

    put_page_from_l1e(ol1e, pt_dom);
    return rc;
}


/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e,
                        l2_pgentry_t nl2e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
{
    l2_pgentry_t ol2e;
    struct domain *d = vcpu->domain;
    struct page_info *l2pg = mfn_to_page(_mfn(pfn));
    unsigned long type = l2pg->u.inuse.type_info;
    int rc = 0;

    if ( unlikely(!is_guest_l2_slot(d, type, pgentry_ptr_to_slot(pl2e))) )
    {
        gdprintk(XENLOG_WARNING, "L2 update in Xen-private area, slot %#lx\n",
                 pgentry_ptr_to_slot(pl2e));
        return -EPERM;
    }

    if ( unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0) )
        return -EFAULT;

    if ( l2e_get_flags(nl2e) & _PAGE_PRESENT )
    {
        if ( unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK) )
        {
            gdprintk(XENLOG_WARNING, "Bad L2 flags %x\n",
                    l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l2e_has_changed(ol2e, nl2e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl2e = adjust_guest_l2e(nl2e, d);
            if ( UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad) )
                return 0;
            return -EBUSY;
        }

        if ( unlikely((rc = get_page_from_l2e(nl2e, pfn, d)) < 0) )
            return rc;

        nl2e = adjust_guest_l2e(nl2e, d);
        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol2e = nl2e;
            rc = -EBUSY;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EBUSY;
    }

    put_page_from_l2e(ol2e, pfn);
    return rc;
}

/* Update the L3 entry at pl3e to new value nl3e. pl3e is within frame pfn. */
static int mod_l3_entry(l3_pgentry_t *pl3e,
                        l3_pgentry_t nl3e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
{
    l3_pgentry_t ol3e;
    struct domain *d = vcpu->domain;
    int rc = 0;

    /*
     * Disallow updates to final L3 slot. It contains Xen mappings, and it
     * would be a pain to ensure they remain continuously valid throughout.
     */
    if ( is_pv_32bit_domain(d) && (pgentry_ptr_to_slot(pl3e) >= 3) )
        return -EINVAL;

    if ( unlikely(__copy_from_user(&ol3e, pl3e, sizeof(ol3e)) != 0) )
        return -EFAULT;

    if ( l3e_get_flags(nl3e) & _PAGE_PRESENT )
    {
        if ( unlikely(l3e_get_flags(nl3e) & l3_disallow_mask(d)) )
        {
            gdprintk(XENLOG_WARNING, "Bad L3 flags %x\n",
                    l3e_get_flags(nl3e) & l3_disallow_mask(d));
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l3e_has_changed(ol3e, nl3e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl3e = adjust_guest_l3e(nl3e, d);
            rc = UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l3e(nl3e, pfn, d, 0);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        nl3e = adjust_guest_l3e(nl3e, d);
        if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol3e = nl3e;
            rc = -EFAULT;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EFAULT;
    }

    if ( likely(rc == 0) )
        if ( !create_pae_xen_mappings(d, pl3e) )
            BUG();

    put_page_from_l3e(ol3e, pfn, 0, 1);
    return rc;
}

/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e,
                        l4_pgentry_t nl4e,
                        unsigned long pfn,
                        int preserve_ad,
                        struct vcpu *vcpu)
{
    struct domain *d = vcpu->domain;
    l4_pgentry_t ol4e;
    int rc = 0;

    if ( unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e))) )
    {
        gdprintk(XENLOG_WARNING, "L4 update in Xen-private area, slot %#lx\n",
                 pgentry_ptr_to_slot(pl4e));
        return -EINVAL;
    }

    if ( unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0) )
        return -EFAULT;

    if ( l4e_get_flags(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK) )
        {
            gdprintk(XENLOG_WARNING, "Bad L4 flags %x\n",
                    l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for sufficiently-similar mappings. */
        if ( !l4e_has_changed(ol4e, nl4e, ~FASTPATH_FLAG_WHITELIST) )
        {
            nl4e = adjust_guest_l4e(nl4e, d);
            rc = UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l4e(nl4e, pfn, d, 0);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        nl4e = adjust_guest_l4e(nl4e, d);
        if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol4e = nl4e;
            rc = -EFAULT;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return -EFAULT;
    }

    put_page_from_l4e(ol4e, pfn, 0, 1);
    return rc;
}

static int cleanup_page_cacheattr(struct page_info *page)
{
    unsigned int cacheattr =
        (page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base;

    if ( likely(cacheattr == 0) )
        return 0;

    page->count_info &= ~PGC_cacheattr_mask;

    BUG_ON(is_xen_heap_page(page));

    return update_xen_mappings(mfn_x(page_to_mfn(page)), 0);
}

void put_page(struct page_info *page)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) != 0);
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        if ( cleanup_page_cacheattr(page) == 0 )
            free_domheap_page(page);
        else
            gdprintk(XENLOG_WARNING,
                     "Leaking mfn %" PRI_mfn "\n", mfn_x(page_to_mfn(page)));
    }
}


struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         * Count == -2: Remaining unused ref is reserved for get_page_light().
         */
        if ( unlikely(((x + 2) & PGC_count_mask) <= 2) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}


int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( !paging_mode_refcounts(domain) && !domain->is_dying )
        gprintk(XENLOG_INFO,
                "Error mfn %"PRI_mfn": rd=%d od=%d caf=%08lx taf=%" PRtype_info "\n",
                mfn_x(page_to_mfn(page)), domain->domain_id,
                owner ? owner->domain_id : DOMID_INVALID,
                page->count_info - !!owner, page->u.inuse.type_info);

    if ( owner )
        put_page(page);

    return 0;
}

/*
 * Special version of get_page() to be used exclusively when
 * - a page is known to already have a non-zero reference count
 * - the page does not need its owner to be checked
 * - it will not be called more than once without dropping the thus
 *   acquired reference again.
 * Due to get_page() reserving one reference, this call cannot fail.
 */
static void get_page_light(struct page_info *page)
{
    unsigned long x, nx, y = page->count_info;

    do {
        x  = y;
        nx = x + 1;
        BUG_ON(!(x & PGC_count_mask)); /* Not allocated? */
        BUG_ON(!(nx & PGC_count_mask)); /* Overflow? */
        y = cmpxchg(&page->count_info, x, nx);
    }
    while ( unlikely(y != x) );
}

static int alloc_page_type(struct page_info *page, unsigned long type,
                           int preemptible)
{
    struct domain *owner = page_get_owner(page);
    int rc;

    /* A page table is dirtied when its type count becomes non-zero. */
    if ( likely(owner != NULL) )
        paging_mark_dirty(owner, page_to_mfn(page));

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        rc = alloc_l1_table(page);
        break;
    case PGT_l2_page_table:
        rc = alloc_l2_table(page, type, preemptible);
        break;
    case PGT_l3_page_table:
        ASSERT(preemptible);
        rc = alloc_l3_table(page);
        break;
    case PGT_l4_page_table:
        ASSERT(preemptible);
        rc = alloc_l4_table(page);
        break;
    case PGT_seg_desc_page:
        rc = alloc_segdesc_page(page);
        break;
    default:
        printk("Bad type in alloc_page_type %lx t=%" PRtype_info " c=%lx\n",
               type, page->u.inuse.type_info,
               page->count_info);
        rc = -EINVAL;
        BUG();
    }

    /* No need for atomic update of type_info here: noone else updates it. */
    smp_wmb();
    switch ( rc )
    {
    case 0:
        page->u.inuse.type_info |= PGT_validated;
        break;
    case -EINTR:
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        page->u.inuse.type_info &= ~PGT_count_mask;
        break;
    default:
        ASSERT(rc < 0);
        gdprintk(XENLOG_WARNING, "Error while validating mfn %" PRI_mfn
                 " (pfn %" PRI_pfn ") for type %" PRtype_info
                 ": caf=%08lx taf=%" PRtype_info "\n",
                 mfn_x(page_to_mfn(page)),
                 get_gpfn_from_mfn(mfn_x(page_to_mfn(page))),
                 type, page->count_info, page->u.inuse.type_info);
        if ( page != current->arch.old_guest_table )
            page->u.inuse.type_info = 0;
        else
        {
            ASSERT((page->u.inuse.type_info &
                    (PGT_count_mask | PGT_validated)) == 1);
    case -ERESTART:
            get_page_light(page);
            page->u.inuse.type_info |= PGT_partial;
        }
        break;
    }

    return rc;
}


int free_page_type(struct page_info *page, unsigned long type,
                   int preemptible)
{
    struct domain *owner = page_get_owner(page);
    unsigned long gmfn;
    int rc;

    if ( likely(owner != NULL) && unlikely(paging_mode_enabled(owner)) )
    {
        /* A page table is dirtied when its type count becomes zero. */
        paging_mark_dirty(owner, page_to_mfn(page));

        ASSERT(!shadow_mode_refcounts(owner));

        gmfn = mfn_to_gmfn(owner, mfn_x(page_to_mfn(page)));
        if ( VALID_M2P(gmfn) )
            shadow_remove_all_shadows(owner, _mfn(gmfn));
    }

    if ( !(type & PGT_partial) )
    {
        page->nr_validated_ptes = 1U << PAGETABLE_ORDER;
        page->partial_pte = 0;
    }

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        rc = 0;
        break;
    case PGT_l2_page_table:
        rc = free_l2_table(page, preemptible);
        break;
    case PGT_l3_page_table:
        ASSERT(preemptible);
        rc = free_l3_table(page);
        break;
    case PGT_l4_page_table:
        ASSERT(preemptible);
        rc = free_l4_table(page);
        break;
    default:
        gdprintk(XENLOG_WARNING, "type %" PRtype_info " mfn %" PRI_mfn "\n",
                 type, mfn_x(page_to_mfn(page)));
        rc = -EINVAL;
        BUG();
    }

    return rc;
}


static int _put_final_page_type(struct page_info *page, unsigned long type,
                                bool preemptible, struct page_info *ptpg)
{
    int rc = free_page_type(page, type, preemptible);

    /* No need for atomic update of type_info here: noone else updates it. */
    if ( rc == 0 )
    {
        if ( ptpg && PGT_type_equal(type, ptpg->u.inuse.type_info) )
        {
            dec_linear_uses(page);
            dec_linear_entries(ptpg);
        }
        ASSERT(!page->linear_pt_count || page_get_owner(page)->is_dying);
        set_tlbflush_timestamp(page);
        smp_wmb();
        page->u.inuse.type_info--;
    }
    else if ( rc == -EINTR )
    {
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        smp_wmb();
        page->u.inuse.type_info |= PGT_validated;
    }
    else
    {
        BUG_ON(rc != -ERESTART);
        smp_wmb();
        get_page_light(page);
        page->u.inuse.type_info |= PGT_partial;
    }

    return rc;
}


static int _put_page_type(struct page_info *page, bool preemptible,
                          struct page_info *ptpg)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

    ASSERT(current_locked_page_ne_check(page));

    for ( ; ; )
    {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        switch ( nx & (PGT_locked | PGT_count_mask) )
        {
        case 0:
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & (PGT_validated|PGT_partial)) )
            {
                int rc;

                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                nx = x & ~(PGT_validated|PGT_partial);
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info,
                                           x, nx)) != x) )
                    continue;
                /* We cleared the 'valid bit' so we do the clean up. */
                rc = _put_final_page_type(page, x, preemptible, ptpg);
                if ( x & PGT_partial )
                    put_page(page);

                return rc;
            }

            if ( !ptpg || !PGT_type_equal(x, ptpg->u.inuse.type_info) )
            {
                /*
                 * set_tlbflush_timestamp() accesses the same union
                 * linear_pt_count lives in. Pages (including page table ones),
                 * however, don't need their flush time stamp set except when
                 * the last reference is being dropped. For page table pages
                 * this happens in _put_final_page_type().
                 */
                set_tlbflush_timestamp(page);
            }
            else
                BUG_ON(!IS_ENABLED(CONFIG_PV_LINEAR_PT));

            break;

        case PGT_locked:
            ASSERT_UNREACHABLE();
            return -EILSEQ;

        case PGT_locked | 1:
            /*
             * We must not drop the second to last reference when the page is
             * locked, as page_unlock() doesn't do any cleanup of the type.
             */
            cpu_relax();
            y = page->u.inuse.type_info;
            continue;
        }

        if ( likely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) == x) )
            break;

        if ( preemptible && hypercall_preempt_check() )
            return -EINTR;
    }

    if ( ptpg && PGT_type_equal(x, ptpg->u.inuse.type_info) )
    {
        dec_linear_uses(page);
        dec_linear_entries(ptpg);
    }

    return 0;
}


static int _get_page_type(struct page_info *page, unsigned long type,
                          bool preemptible)
{
    unsigned long nx, x, y = page->u.inuse.type_info;
    int rc = 0, iommu_ret = 0;

    ASSERT(!(type & ~(PGT_type_mask | PGT_pae_xen_l2)));
    ASSERT(!in_irq());

    for ( ; ; )
    {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            gdprintk(XENLOG_WARNING,
                     "Type count overflow on mfn %"PRI_mfn"\n",
                     mfn_x(page_to_mfn(page)));
            return -EINVAL;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            struct domain *d = page_get_owner(page);

            /*
             * Normally we should never let a page go from type count 0
             * to type count 1 when it is shadowed. One exception:
             * out-of-sync shadowed pages are allowed to become
             * writeable.
             */
            if ( d && shadow_mode_enabled(d)
                 && (page->count_info & PGC_page_table)
                 && !((page->shadow_flags & (1u<<29))
                      && type == PGT_writable_page) )
               shadow_remove_all_shadows(d, page_to_mfn(page));

            ASSERT(!(x & PGT_pae_xen_l2));
            if ( (x & PGT_type_mask) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. It is
                 * vital that no other CPUs are left with mappings of a frame
                 * which is about to become writeable to the guest.
                 */
                cpumask_t *mask = this_cpu(scratch_cpumask);

                BUG_ON(in_irq());
                cpumask_copy(mask, d->dirty_cpumask);

                /* Don't flush if the timestamp is old enough */
                tlbflush_filter(mask, page->tlbflush_timestamp);

                if ( unlikely(!cpumask_empty(mask)) &&
                     /* Shadow mode: track only writable pages. */
                     (!shadow_mode_enabled(page_get_owner(page)) ||
                      ((nx & PGT_type_mask) == PGT_writable_page)) )
                {
                    perfc_incr(need_flush_tlb_flush);
                    flush_tlb_mask(mask);
                }

                /* We lose existing type and validity. */
                nx &= ~(PGT_type_mask | PGT_validated);
                nx |= type;

                /*
                 * No special validation needed for writable pages.
                 * Page tables and GDT/LDT need to be scanned for validity.
                 */
                if ( type == PGT_writable_page || type == PGT_shared_page )
                    nx |= PGT_validated;
            }
        }
        else if ( unlikely((x & (PGT_type_mask|PGT_pae_xen_l2)) != type) )
        {
            /* Don't log failure if it could be a recursive-mapping attempt. */
            if ( ((x & PGT_type_mask) == PGT_l2_page_table) &&
                 (type == PGT_l1_page_table) )
                return -EINVAL;
            if ( ((x & PGT_type_mask) == PGT_l3_page_table) &&
                 (type == PGT_l2_page_table) )
                return -EINVAL;
            if ( ((x & PGT_type_mask) == PGT_l4_page_table) &&
                 (type == PGT_l3_page_table) )
                return -EINVAL;
            gdprintk(XENLOG_WARNING,
                     "Bad type (saw %" PRtype_info " != exp %" PRtype_info ") "
                     "for mfn %" PRI_mfn " (pfn %" PRI_pfn ")\n",
                     x, type, mfn_x(page_to_mfn(page)),
                     get_gpfn_from_mfn(mfn_x(page_to_mfn(page))));
            return -EINVAL;
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            if ( !(x & PGT_partial) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                {
                    if ( preemptible && hypercall_preempt_check() )
                        return -EINTR;
                    cpu_relax();
                }
                continue;
            }
            /* Type ref count was left at 1 when PGT_partial got set. */
            ASSERT((x & PGT_count_mask) == 1);
            nx = x & ~PGT_partial;
        }

        if ( likely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) == x) )
            break;

        if ( preemptible && hypercall_preempt_check() )
            return -EINTR;
    }

    if ( unlikely((x & PGT_type_mask) != type) )
    {
        /* Special pages should not be accessible from devices. */
        struct domain *d = page_get_owner(page);
        if ( d && is_pv_domain(d) && unlikely(need_iommu(d)) )
        {
            gfn_t gfn = _gfn(mfn_to_gmfn(d, mfn_x(page_to_mfn(page))));

            if ( (x & PGT_type_mask) == PGT_writable_page )
                iommu_ret = iommu_unmap_page(d, gfn_x(gfn));
            else if ( type == PGT_writable_page )
                iommu_ret = iommu_map_page(d, gfn_x(gfn),
                                           mfn_x(page_to_mfn(page)),
                                           IOMMUF_readable|IOMMUF_writable);
        }
    }

    if ( unlikely(!(nx & PGT_validated)) )
    {
        if ( !(x & PGT_partial) )
        {
            page->nr_validated_ptes = 0;
            page->partial_pte = 0;
        }
        page->linear_pt_count = 0;
        rc = alloc_page_type(page, type, preemptible);
    }

    if ( (x & PGT_partial) && !(nx & PGT_partial) )
        put_page(page);

    if ( !rc )
        rc = iommu_ret;

    return rc;
}

void put_page_type(struct page_info *page)
{
    int rc = _put_page_type(page, false, NULL);
    ASSERT(rc == 0);
    (void)rc;
}

int get_page_type(struct page_info *page, unsigned long type)
{
    int rc = _get_page_type(page, type, false);

    if ( likely(rc == 0) )
        return 1;
    ASSERT(rc != -EINTR && rc != -ERESTART);
    return 0;
}

int put_page_type_preemptible(struct page_info *page)
{
    return _put_page_type(page, true, NULL);
}

int get_page_type_preemptible(struct page_info *page, unsigned long type)
{
    ASSERT(!current->arch.old_guest_table);

    return _get_page_type(page, type, true);
}

int put_old_guest_table(struct vcpu *v)
{
    int rc;

    if ( !v->arch.old_guest_table )
        return 0;

    switch ( rc = _put_page_type(v->arch.old_guest_table, true,
                                 v->arch.old_guest_ptpg) )
    {
    case -EINTR:
    case -ERESTART:
        return -ERESTART;
    case 0:
        put_page(v->arch.old_guest_table);
    }

    v->arch.old_guest_table = NULL;

    return rc;
}

int vcpu_destroy_pagetables(struct vcpu *v)
{
    unsigned long mfn = pagetable_get_pfn(v->arch.guest_table);
    struct page_info *page;
    l4_pgentry_t *l4tab = NULL;
    int rc = put_old_guest_table(v);

    if ( rc )
        return rc;

    if ( is_pv_32bit_vcpu(v) )
    {
        l4tab = map_domain_page(_mfn(mfn));
        mfn = l4e_get_pfn(*l4tab);
    }

    if ( mfn )
    {
        page = mfn_to_page(_mfn(mfn));
        if ( paging_mode_refcounts(v->domain) )
            put_page(page);
        else
            rc = put_page_and_type_preemptible(page);
    }

    if ( l4tab )
    {
        if ( !rc )
            l4e_write(l4tab, l4e_empty());
        unmap_domain_page(l4tab);
    }
    else if ( !rc )
    {
        v->arch.guest_table = pagetable_null();

        /* Drop ref to guest_table_user (from MMUEXT_NEW_USER_BASEPTR) */
        mfn = pagetable_get_pfn(v->arch.guest_table_user);
        if ( mfn )
        {
            page = mfn_to_page(_mfn(mfn));
            if ( paging_mode_refcounts(v->domain) )
                put_page(page);
            else
                rc = put_page_and_type_preemptible(page);
        }
        if ( !rc )
            v->arch.guest_table_user = pagetable_null();
    }

    v->arch.cr3 = 0;

    /*
     * put_page_and_type_preemptible() is liable to return -EINTR. The
     * callers of us expect -ERESTART so convert it over.
     */
    return rc != -EINTR ? rc : -ERESTART;
}

int new_guest_cr3(mfn_t mfn)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    int rc;
    mfn_t old_base_mfn;

    if ( is_pv_32bit_domain(d) )
    {
        mfn_t gt_mfn = pagetable_get_mfn(curr->arch.guest_table);
        l4_pgentry_t *pl4e = map_domain_page(gt_mfn);

        rc = mod_l4_entry(pl4e,
                          l4e_from_mfn(mfn,
                                       (_PAGE_PRESENT | _PAGE_RW |
                                        _PAGE_USER | _PAGE_ACCESSED)),
                          mfn_x(gt_mfn), 0, curr);
        unmap_domain_page(pl4e);
        switch ( rc )
        {
        case 0:
            break;
        case -EINTR:
        case -ERESTART:
            return -ERESTART;
        default:
            gdprintk(XENLOG_WARNING,
                     "Error while installing new compat baseptr %" PRI_mfn "\n",
                     mfn_x(mfn));
            return rc;
        }

        pv_destroy_ldt(curr); /* Unconditional TLB flush later. */
        write_ptbase(curr);

        return 0;
    }

    rc = put_old_guest_table(curr);
    if ( unlikely(rc) )
        return rc;

    old_base_mfn = pagetable_get_mfn(curr->arch.guest_table);
    /*
     * This is particularly important when getting restarted after the
     * previous attempt got preempted in the put-old-MFN phase.
     */
    if ( mfn_eq(old_base_mfn, mfn) )
    {
        write_ptbase(curr);
        return 0;
    }

    rc = get_page_and_type_from_mfn(mfn, PGT_root_page_table, d, 0, 1);
    switch ( rc )
    {
    case 0:
        break;
    case -EINTR:
    case -ERESTART:
        return -ERESTART;
    default:
        gdprintk(XENLOG_WARNING,
                 "Error while installing new baseptr %" PRI_mfn "\n",
                 mfn_x(mfn));
        return rc;
    }

    pv_destroy_ldt(curr); /* Unconditional TLB flush later. */

    if ( !VM_ASSIST(d, m2p_strict) && !paging_mode_refcounts(d) )
        fill_ro_mpt(mfn);
    curr->arch.guest_table = pagetable_from_mfn(mfn);
    update_cr3(curr);

    write_ptbase(curr);

    if ( likely(mfn_x(old_base_mfn) != 0) )
    {
        struct page_info *page = mfn_to_page(old_base_mfn);

        if ( paging_mode_refcounts(d) )
            put_page(page);
        else
            switch ( rc = put_page_and_type_preemptible(page) )
            {
            case -EINTR:
                rc = -ERESTART;
                /* fallthrough */
            case -ERESTART:
                curr->arch.old_guest_ptpg = NULL;
                curr->arch.old_guest_table = page;
                break;
            default:
                BUG_ON(rc);
                break;
            }
    }

    return rc;
}

static struct domain *get_pg_owner(domid_t domid)
{
    struct domain *pg_owner = NULL, *curr = current->domain;

    if ( likely(domid == DOMID_SELF) )
    {
        pg_owner = rcu_lock_current_domain();
        goto out;
    }

    if ( unlikely(domid == curr->domain_id) )
    {
        gdprintk(XENLOG_WARNING, "Cannot specify itself as foreign domain\n");
        goto out;
    }

    switch ( domid )
    {
    case DOMID_IO:
        pg_owner = rcu_lock_domain(dom_io);
        break;
    case DOMID_XEN:
        pg_owner = rcu_lock_domain(dom_xen);
        break;
    default:
        if ( (pg_owner = rcu_lock_domain_by_id(domid)) == NULL )
        {
            gdprintk(XENLOG_WARNING, "Unknown domain d%d\n", domid);
            break;
        }
        break;
    }

 out:
    return pg_owner;
}

static void put_pg_owner(struct domain *pg_owner)
{
    rcu_unlock_domain(pg_owner);
}

static inline int vcpumask_to_pcpumask(
    struct domain *d, XEN_GUEST_HANDLE_PARAM(const_void) bmap, cpumask_t *pmask)
{
    unsigned int vcpu_id, vcpu_bias, offs;
    unsigned long vmask;
    struct vcpu *v;
    bool is_native = !is_pv_32bit_domain(d);

    cpumask_clear(pmask);
    for ( vmask = 0, offs = 0; ; ++offs )
    {
        vcpu_bias = offs * (is_native ? BITS_PER_LONG : 32);
        if ( vcpu_bias >= d->max_vcpus )
            return 0;

        if ( unlikely(is_native ?
                      copy_from_guest_offset(&vmask, bmap, offs, 1) :
                      copy_from_guest_offset((unsigned int *)&vmask, bmap,
                                             offs, 1)) )
        {
            cpumask_clear(pmask);
            return -EFAULT;
        }

        while ( vmask )
        {
            vcpu_id = find_first_set_bit(vmask);
            vmask &= ~(1UL << vcpu_id);
            vcpu_id += vcpu_bias;
            if ( (vcpu_id >= d->max_vcpus) )
                return 0;
            if ( ((v = d->vcpu[vcpu_id]) != NULL) && vcpu_cpu_dirty(v) )
                __cpumask_set_cpu(v->dirty_cpu, pmask);
        }
    }
}

long do_mmuext_op(
    XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom)
{
    struct mmuext_op op;
    unsigned long type;
    unsigned int i, done = 0;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct domain *pg_owner;
    int rc = put_old_guest_table(curr);

    if ( unlikely(rc) )
    {
        if ( likely(rc == -ERESTART) )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_mmuext_op, "hihi", uops, count, pdone,
                     foreigndom);
        return rc;
    }

    if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(uops)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmuext_op);

    if ( unlikely(!guest_handle_okay(uops, count)) )
        return -EFAULT;

    if ( (pg_owner = get_pg_owner(foreigndom)) == NULL )
        return -ESRCH;

    if ( !is_pv_domain(pg_owner) )
    {
        put_pg_owner(pg_owner);
        return -EINVAL;
    }

    rc = xsm_mmuext_op(XSM_TARGET, currd, pg_owner);
    if ( rc )
    {
        put_pg_owner(pg_owner);
        return rc;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( curr->arch.old_guest_table || (i && hypercall_preempt_check()) )
        {
            rc = -ERESTART;
            break;
        }

        if ( unlikely(__copy_from_guest(&op, uops, 1) != 0) )
        {
            rc = -EFAULT;
            break;
        }

        if ( is_hvm_domain(currd) )
        {
            switch ( op.cmd )
            {
            case MMUEXT_PIN_L1_TABLE:
            case MMUEXT_PIN_L2_TABLE:
            case MMUEXT_PIN_L3_TABLE:
            case MMUEXT_PIN_L4_TABLE:
            case MMUEXT_UNPIN_TABLE:
                break;
            default:
                rc = -EOPNOTSUPP;
                goto done;
            }
        }

        rc = 0;

        switch ( op.cmd )
        {
            struct page_info *page;
            p2m_type_t p2mt;

        case MMUEXT_PIN_L1_TABLE:
            type = PGT_l1_page_table;
            goto pin_page;

        case MMUEXT_PIN_L2_TABLE:
            type = PGT_l2_page_table;
            goto pin_page;

        case MMUEXT_PIN_L3_TABLE:
            type = PGT_l3_page_table;
            goto pin_page;

        case MMUEXT_PIN_L4_TABLE:
            if ( is_pv_32bit_domain(pg_owner) )
                break;
            type = PGT_l4_page_table;

        pin_page:
            /* Ignore pinning of invalid paging levels. */
            if ( (op.cmd - MMUEXT_PIN_L1_TABLE) > (CONFIG_PAGING_LEVELS - 1) )
                break;

            if ( paging_mode_refcounts(pg_owner) )
                break;

            page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
            if ( unlikely(!page) )
            {
                rc = -EINVAL;
                break;
            }

            rc = get_page_type_preemptible(page, type);
            if ( unlikely(rc) )
            {
                if ( rc == -EINTR )
                    rc = -ERESTART;
                else if ( rc != -ERESTART )
                    gdprintk(XENLOG_WARNING,
                             "Error %d while pinning mfn %" PRI_mfn "\n",
                             rc, mfn_x(page_to_mfn(page)));
                if ( page != curr->arch.old_guest_table )
                    put_page(page);
                break;
            }

            rc = xsm_memory_pin_page(XSM_HOOK, currd, pg_owner, page);
            if ( !rc && unlikely(test_and_set_bit(_PGT_pinned,
                                                  &page->u.inuse.type_info)) )
            {
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " already pinned\n",
                         mfn_x(page_to_mfn(page)));
                rc = -EINVAL;
            }

            if ( unlikely(rc) )
                goto pin_drop;

            /* A page is dirtied when its pin status is set. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));

            /* We can race domain destruction (domain_relinquish_resources). */
            if ( unlikely(pg_owner != currd) )
            {
                bool drop_ref;

                spin_lock(&pg_owner->page_alloc_lock);
                drop_ref = (pg_owner->is_dying &&
                            test_and_clear_bit(_PGT_pinned,
                                               &page->u.inuse.type_info));
                spin_unlock(&pg_owner->page_alloc_lock);
                if ( drop_ref )
                {
        pin_drop:
                    if ( type == PGT_l1_page_table )
                        put_page_and_type(page);
                    else
                    {
                        curr->arch.old_guest_ptpg = NULL;
                        curr->arch.old_guest_table = page;
                    }
                }
            }
            break;

        case MMUEXT_UNPIN_TABLE:
            if ( paging_mode_refcounts(pg_owner) )
                break;

            page = get_page_from_gfn(pg_owner, op.arg1.mfn, NULL, P2M_ALLOC);
            if ( unlikely(!page) )
            {
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " bad, or bad owner d%d\n",
                         op.arg1.mfn, pg_owner->domain_id);
                rc = -EINVAL;
                break;
            }

            if ( !test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            {
                put_page(page);
                gdprintk(XENLOG_WARNING,
                         "mfn %" PRI_mfn " not pinned\n", op.arg1.mfn);
                rc = -EINVAL;
                break;
            }

            switch ( rc = put_page_and_type_preemptible(page) )
            {
            case -EINTR:
            case -ERESTART:
                curr->arch.old_guest_ptpg = NULL;
                curr->arch.old_guest_table = page;
                rc = 0;
                break;
            default:
                BUG_ON(rc);
                break;
            }
            put_page(page);

            /* A page is dirtied when its pin status is cleared. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));
            break;

        case MMUEXT_NEW_BASEPTR:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(paging_mode_translate(currd)) )
                rc = -EINVAL;
            else
                rc = new_guest_cr3(_mfn(op.arg1.mfn));
            break;

        case MMUEXT_NEW_USER_BASEPTR: {
            unsigned long old_mfn;

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(paging_mode_translate(currd)) )
                rc = -EINVAL;
            if ( unlikely(rc) )
                break;

            old_mfn = pagetable_get_pfn(curr->arch.guest_table_user);
            /*
             * This is particularly important when getting restarted after the
             * previous attempt got preempted in the put-old-MFN phase.
             */
            if ( old_mfn == op.arg1.mfn )
                break;

            if ( op.arg1.mfn != 0 )
            {
                rc = get_page_and_type_from_mfn(
                    _mfn(op.arg1.mfn), PGT_root_page_table, currd, 0, 1);

                if ( unlikely(rc) )
                {
                    if ( rc == -EINTR )
                        rc = -ERESTART;
                    else if ( rc != -ERESTART )
                        gdprintk(XENLOG_WARNING,
                                 "Error %d installing new mfn %" PRI_mfn "\n",
                                 rc, op.arg1.mfn);
                    break;
                }

                if ( VM_ASSIST(currd, m2p_strict) )
                    zap_ro_mpt(_mfn(op.arg1.mfn));
            }

            curr->arch.guest_table_user = pagetable_from_pfn(op.arg1.mfn);

            if ( old_mfn != 0 )
            {
                page = mfn_to_page(_mfn(old_mfn));

                switch ( rc = put_page_and_type_preemptible(page) )
                {
                case -EINTR:
                    rc = -ERESTART;
                    /* fallthrough */
                case -ERESTART:
                    curr->arch.old_guest_ptpg = NULL;
                    curr->arch.old_guest_table = page;
                    break;
                default:
                    BUG_ON(rc);
                    break;
                }
            }

            break;
        }

        case MMUEXT_TLB_FLUSH_LOCAL:
            if ( likely(currd == pg_owner) )
                flush_tlb_local();
            else
                rc = -EPERM;
            break;

        case MMUEXT_INVLPG_LOCAL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else
                paging_invlpg(curr, op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            cpumask_t *mask = this_cpu(scratch_cpumask);

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(vcpumask_to_pcpumask(currd,
                                   guest_handle_to_param(op.arg2.vcpumask,
                                                         const_void),
                                   mask)) )
                rc = -EINVAL;
            if ( unlikely(rc) )
                break;

            if ( op.cmd == MMUEXT_TLB_FLUSH_MULTI )
                flush_tlb_mask(mask);
            else if ( __addr_ok(op.arg1.linear_addr) )
                flush_tlb_one_mask(mask, op.arg1.linear_addr);
            break;
        }

        case MMUEXT_TLB_FLUSH_ALL:
            if ( likely(currd == pg_owner) )
                flush_tlb_mask(currd->dirty_cpumask);
            else
                rc = -EPERM;
            break;

        case MMUEXT_INVLPG_ALL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( __addr_ok(op.arg1.linear_addr) )
                flush_tlb_one_mask(currd->dirty_cpumask, op.arg1.linear_addr);
            break;

        case MMUEXT_FLUSH_CACHE:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( unlikely(!cache_flush_permitted(currd)) )
                rc = -EACCES;
            else
                wbinvd();
            break;

        case MMUEXT_FLUSH_CACHE_GLOBAL:
            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( likely(cache_flush_permitted(currd)) )
            {
                unsigned int cpu;
                cpumask_t *mask = this_cpu(scratch_cpumask);

                cpumask_clear(mask);
                for_each_online_cpu(cpu)
                    if ( !cpumask_intersects(mask,
                                             per_cpu(cpu_sibling_mask, cpu)) )
                        __cpumask_set_cpu(cpu, mask);
                flush_mask(mask, FLUSH_CACHE);
            }
            else
                rc = -EINVAL;
            break;

        case MMUEXT_SET_LDT:
        {
            unsigned int ents = op.arg2.nr_ents;
            unsigned long ptr = ents ? op.arg1.linear_addr : 0;

            if ( unlikely(currd != pg_owner) )
                rc = -EPERM;
            else if ( paging_mode_external(currd) )
                rc = -EINVAL;
            else if ( ((ptr & (PAGE_SIZE - 1)) != 0) || !__addr_ok(ptr) ||
                      (ents > 8192) )
            {
                gdprintk(XENLOG_WARNING,
                         "Bad args to SET_LDT: ptr=%lx, ents=%x\n", ptr, ents);
                rc = -EINVAL;
            }
            else if ( (curr->arch.pv_vcpu.ldt_ents != ents) ||
                      (curr->arch.pv_vcpu.ldt_base != ptr) )
            {
                if ( pv_destroy_ldt(curr) )
                    flush_tlb_local();

                curr->arch.pv_vcpu.ldt_base = ptr;
                curr->arch.pv_vcpu.ldt_ents = ents;
                load_LDT(curr);
            }
            break;
        }

        case MMUEXT_CLEAR_PAGE:
            page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt, P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && page )
            {
                put_page(page);
                page = NULL;
            }
            if ( !page || !get_page_type(page, PGT_writable_page) )
            {
                if ( page )
                    put_page(page);
                gdprintk(XENLOG_WARNING,
                         "Error clearing mfn %" PRI_mfn "\n", op.arg1.mfn);
                rc = -EINVAL;
                break;
            }

            /* A page is dirtied when it's being cleared. */
            paging_mark_dirty(pg_owner, page_to_mfn(page));

            clear_domain_page(page_to_mfn(page));

            put_page_and_type(page);
            break;

        case MMUEXT_COPY_PAGE:
        {
            struct page_info *src_page, *dst_page;

            src_page = get_page_from_gfn(pg_owner, op.arg2.src_mfn, &p2mt,
                                         P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && src_page )
            {
                put_page(src_page);
                src_page = NULL;
            }
            if ( unlikely(!src_page) )
            {
                gdprintk(XENLOG_WARNING,
                         "Error copying from mfn %" PRI_mfn "\n",
                         op.arg2.src_mfn);
                rc = -EINVAL;
                break;
            }

            dst_page = get_page_from_gfn(pg_owner, op.arg1.mfn, &p2mt,
                                         P2M_ALLOC);
            if ( unlikely(p2mt != p2m_ram_rw) && dst_page )
            {
                put_page(dst_page);
                dst_page = NULL;
            }
            rc = (dst_page &&
                  get_page_type(dst_page, PGT_writable_page)) ? 0 : -EINVAL;
            if ( unlikely(rc) )
            {
                put_page(src_page);
                if ( dst_page )
                    put_page(dst_page);
                gdprintk(XENLOG_WARNING,
                         "Error copying to mfn %" PRI_mfn "\n", op.arg1.mfn);
                break;
            }

            /* A page is dirtied when it's being copied to. */
            paging_mark_dirty(pg_owner, page_to_mfn(dst_page));

            copy_domain_page(page_to_mfn(dst_page), page_to_mfn(src_page));

            put_page_and_type(dst_page);
            put_page(src_page);
            break;
        }

        case MMUEXT_MARK_SUPER:
        case MMUEXT_UNMARK_SUPER:
            rc = -EOPNOTSUPP;
            break;

        default:
            rc = -ENOSYS;
            break;
        }

 done:
        if ( unlikely(rc) )
            break;

        guest_handle_add_offset(uops, 1);
    }

    if ( rc == -ERESTART )
    {
        ASSERT(i < count);
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmuext_op, "hihi",
            uops, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
    }
    else if ( curr->arch.old_guest_table )
    {
        XEN_GUEST_HANDLE_PARAM(void) null;

        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        /*
         * In order to have a way to communicate the final return value to
         * our continuation, we pass this in place of "foreigndom", building
         * on the fact that this argument isn't needed anymore.
         */
        rc = hypercall_create_continuation(
                __HYPERVISOR_mmuext_op, "hihi", null,
                MMU_UPDATE_PREEMPTED, null, rc);
    }

    put_pg_owner(pg_owner);

    perfc_add(num_mmuext_ops, i);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}

long do_mmu_update(
    XEN_GUEST_HANDLE_PARAM(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE_PARAM(uint) pdone,
    unsigned int foreigndom)
{
    struct mmu_update req;
    void *va = NULL;
    unsigned long gpfn, gmfn, mfn;
    struct page_info *page;
    unsigned int cmd, i = 0, done = 0, pt_dom;
    struct vcpu *curr = current, *v = curr;
    struct domain *d = v->domain, *pt_owner = d, *pg_owner;
    mfn_t map_mfn = INVALID_MFN;
    bool sync_guest = false;
    uint32_t xsm_needed = 0;
    uint32_t xsm_checked = 0;
    int rc = put_old_guest_table(curr);

    if ( unlikely(rc) )
    {
        if ( likely(rc == -ERESTART) )
            rc = hypercall_create_continuation(
                     __HYPERVISOR_mmu_update, "hihi", ureqs, count, pdone,
                     foreigndom);
        return rc;
    }

    if ( unlikely(count == MMU_UPDATE_PREEMPTED) &&
         likely(guest_handle_is_null(ureqs)) )
    {
        /*
         * See the curr->arch.old_guest_table related
         * hypercall_create_continuation() below.
         */
        return (int)foreigndom;
    }

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmu_update);

    if ( unlikely(!guest_handle_okay(ureqs, count)) )
        return -EFAULT;

    if ( (pt_dom = foreigndom >> 16) != 0 )
    {
        /* Pagetables belong to a foreign domain (PFD). */
        if ( (pt_owner = rcu_lock_domain_by_id(pt_dom - 1)) == NULL )
            return -ESRCH;

        if ( pt_owner == d )
            rcu_unlock_domain(pt_owner);
        else if ( !pt_owner->vcpu || (v = pt_owner->vcpu[0]) == NULL )
        {
            rc = -EINVAL;
            goto out;
        }
    }

    if ( (pg_owner = get_pg_owner((uint16_t)foreigndom)) == NULL )
    {
        rc = -ESRCH;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( curr->arch.old_guest_table || (i && hypercall_preempt_check()) )
        {
            rc = -ERESTART;
            break;
        }

        if ( unlikely(__copy_from_guest(&req, ureqs, 1) != 0) )
        {
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             * MMU_UPDATE_PT_PRESERVE_AD: As above but also preserve (OR)
             * current A/D bits.
             */
        case MMU_NORMAL_PT_UPDATE:
        case MMU_PT_UPDATE_PRESERVE_AD:
        {
            p2m_type_t p2mt;

            rc = -EOPNOTSUPP;
            if ( unlikely(paging_mode_refcounts(pt_owner)) )
                break;

            xsm_needed |= XSM_MMU_NORMAL_UPDATE;
            if ( get_pte_flags(req.val) & _PAGE_PRESENT )
            {
                xsm_needed |= XSM_MMU_UPDATE_READ;
                if ( get_pte_flags(req.val) & _PAGE_RW )
                    xsm_needed |= XSM_MMU_UPDATE_WRITE;
            }
            if ( xsm_needed != xsm_checked )
            {
                rc = xsm_mmu_update(XSM_TARGET, d, pt_owner, pg_owner, xsm_needed);
                if ( rc )
                    break;
                xsm_checked = xsm_needed;
            }
            rc = -EINVAL;

            req.ptr -= cmd;
            gmfn = req.ptr >> PAGE_SHIFT;
            page = get_page_from_gfn(pt_owner, gmfn, &p2mt, P2M_ALLOC);

            if ( unlikely(!page) || p2mt != p2m_ram_rw )
            {
                if ( page )
                    put_page(page);
                if ( p2m_is_paged(p2mt) )
                {
                    p2m_mem_paging_populate(pt_owner, gmfn);
                    rc = -ENOENT;
                }
                else
                    gdprintk(XENLOG_WARNING,
                             "Could not get page for normal update\n");
                break;
            }

            mfn = mfn_x(page_to_mfn(page));

            if ( !mfn_eq(_mfn(mfn), map_mfn) )
            {
                if ( va )
                    unmap_domain_page(va);
                va = map_domain_page(_mfn(mfn));
                map_mfn = _mfn(mfn);
            }
            va = _p(((unsigned long)va & PAGE_MASK) + (req.ptr & ~PAGE_MASK));

            if ( page_lock(page) )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    rc = mod_l1_entry(va, l1e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v,
                                      pg_owner);
                    break;

                case PGT_l2_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l2_entry(va, l2e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;

                case PGT_l3_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l3_entry(va, l3e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    break;

                case PGT_l4_page_table:
                    if ( unlikely(pg_owner != pt_owner) )
                        break;
                    rc = mod_l4_entry(va, l4e_from_intpte(req.val), mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                    /*
                     * No need to sync if all uses of the page can be accounted
                     * to the page lock we hold, its pinned status, and uses on
                     * this (v)CPU.
                     */
                    if ( !rc && this_cpu(root_pgt) &&
                         ((page->u.inuse.type_info & PGT_count_mask) >
                          (1 + !!(page->u.inuse.type_info & PGT_pinned) +
                           (pagetable_get_pfn(curr->arch.guest_table) == mfn) +
                           (pagetable_get_pfn(curr->arch.guest_table_user) ==
                            mfn))) )
                        sync_guest = true;
                    break;

                case PGT_writable_page:
                    perfc_incr(writable_mmu_updates);
                    if ( paging_write_guest_entry(v, va, req.val, _mfn(mfn)) )
                        rc = 0;
                    break;
                }
                page_unlock(page);
                if ( rc == -EINTR )
                    rc = -ERESTART;
            }
            else if ( get_page_type(page, PGT_writable_page) )
            {
                perfc_incr(writable_mmu_updates);
                if ( paging_write_guest_entry(v, va, req.val, _mfn(mfn)) )
                    rc = 0;
                put_page_type(page);
            }

            put_page(page);
        }
        break;

        case MMU_MACHPHYS_UPDATE:
            if ( unlikely(d != pt_owner) )
            {
                rc = -EPERM;
                break;
            }

            if ( unlikely(paging_mode_translate(pg_owner)) )
            {
                rc = -EINVAL;
                break;
            }

            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            xsm_needed |= XSM_MMU_MACHPHYS_UPDATE;
            if ( xsm_needed != xsm_checked )
            {
                rc = xsm_mmu_update(XSM_TARGET, d, NULL, pg_owner, xsm_needed);
                if ( rc )
                    break;
                xsm_checked = xsm_needed;
            }

            page = get_page_from_mfn(_mfn(mfn), pg_owner);
            if ( unlikely(!page) )
            {
                gdprintk(XENLOG_WARNING,
                         "Could not get page for mach->phys update\n");
                rc = -EINVAL;
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);
            paging_mark_pfn_dirty(pg_owner, _pfn(gpfn));

            put_page(page);
            break;

        default:
            rc = -ENOSYS;
            break;
        }

        if ( unlikely(rc) )
            break;

        guest_handle_add_offset(ureqs, 1);
    }

    if ( rc == -ERESTART )
    {
        ASSERT(i < count);
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmu_update, "hihi",
            ureqs, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
    }
    else if ( curr->arch.old_guest_table )
    {
        XEN_GUEST_HANDLE_PARAM(void) null;

        ASSERT(rc || i == count);
        set_xen_guest_handle(null, NULL);
        /*
         * In order to have a way to communicate the final return value to
         * our continuation, we pass this in place of "foreigndom", building
         * on the fact that this argument isn't needed anymore.
         */
        rc = hypercall_create_continuation(
                __HYPERVISOR_mmu_update, "hihi", null,
                MMU_UPDATE_PREEMPTED, null, rc);
    }

    put_pg_owner(pg_owner);

    if ( va )
        unmap_domain_page(va);

    if ( sync_guest )
    {
        /*
         * Force other vCPU-s of the affected guest to pick up L4 entry
         * changes (if any).
         */
        unsigned int cpu = smp_processor_id();
        cpumask_t *mask = per_cpu(scratch_cpumask, cpu);

        cpumask_andnot(mask, pt_owner->dirty_cpumask, cpumask_of(cpu));
        if ( !cpumask_empty(mask) )
            flush_mask(mask, FLUSH_TLB_GLOBAL);
    }

    perfc_add(num_page_updates, i);

 out:
    if ( pt_owner != d )
        rcu_unlock_domain(pt_owner);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}

int donate_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    const struct domain *owner = dom_xen;

    spin_lock(&d->page_alloc_lock);

    if ( is_xen_heap_page(page) || ((owner = page_get_owner(page)) != NULL) )
        goto fail;

    if ( d->is_dying )
        goto fail;

    if ( page->count_info & ~(PGC_allocated | 1) )
        goto fail;

    if ( !(memflags & MEMF_no_refcount) )
    {
        if ( d->tot_pages >= d->max_pages )
            goto fail;
        domain_adjust_tot_pages(d, 1);
    }

    page->count_info = PGC_allocated | 1;
    page_set_owner(page, d);
    page_list_add_tail(page,&d->page_list);

    spin_unlock(&d->page_alloc_lock);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    gdprintk(XENLOG_WARNING, "Bad donate mfn %" PRI_mfn
             " to d%d (owner d%d) caf=%08lx taf=%" PRtype_info "\n",
             mfn_x(page_to_mfn(page)), d->domain_id,
             owner ? owner->domain_id : DOMID_INVALID,
             page->count_info, page->u.inuse.type_info);
    return -EINVAL;
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    unsigned long x, y;
    bool drop_dom_ref = false;
    const struct domain *owner = dom_xen;

    if ( paging_mode_external(d) )
        return -EOPNOTSUPP;

    spin_lock(&d->page_alloc_lock);

    if ( is_xen_heap_page(page) || ((owner = page_get_owner(page)) != d) )
        goto fail;

    /*
     * We require there is just one reference (PGC_allocated). We temporarily
     * drop this reference now so that we can safely swizzle the owner.
     */
    y = page->count_info;
    do {
        x = y;
        if ( (x & (PGC_count_mask|PGC_allocated)) != (1 | PGC_allocated) )
            goto fail;
        y = cmpxchg(&page->count_info, x, x & ~PGC_count_mask);
    } while ( y != x );

    /*
     * With the sole reference dropped temporarily, no-one can update type
     * information. Type count also needs to be zero in this case, but e.g.
     * PGT_seg_desc_page may still have PGT_validated set, which we need to
     * clear before transferring ownership (as validation criteria vary
     * depending on domain type).
     */
    BUG_ON(page->u.inuse.type_info & (PGT_count_mask | PGT_locked |
                                      PGT_pinned));
    page->u.inuse.type_info = 0;

    /* Swizzle the owner then reinstate the PGC_allocated reference. */
    page_set_owner(page, NULL);
    y = page->count_info;
    do {
        x = y;
        BUG_ON((x & (PGC_count_mask|PGC_allocated)) != PGC_allocated);
    } while ( (y = cmpxchg(&page->count_info, x, x | 1)) != x );

    /* Unlink from original owner. */
    if ( !(memflags & MEMF_no_refcount) && !domain_adjust_tot_pages(d, -1) )
        drop_dom_ref = true;
    page_list_del(page, &d->page_list);

    spin_unlock(&d->page_alloc_lock);
    if ( unlikely(drop_dom_ref) )
        put_domain(d);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    gdprintk(XENLOG_WARNING, "Bad steal mfn %" PRI_mfn
             " from d%d (owner d%d) caf=%08lx taf=%" PRtype_info "\n",
             mfn_x(page_to_mfn(page)), d->domain_id,
             owner ? owner->domain_id : DOMID_INVALID,
             page->count_info, page->u.inuse.type_info);
    return -EINVAL;
}

static int __do_update_va_mapping(
    unsigned long va, u64 val64, unsigned long flags, struct domain *pg_owner)
{
    l1_pgentry_t   val = l1e_from_intpte(val64);
    struct vcpu   *v   = current;
    struct domain *d   = v->domain;
    struct page_info *gl1pg;
    l1_pgentry_t  *pl1e;
    unsigned long  bmap_ptr;
    mfn_t          gl1mfn;
    cpumask_t     *mask = NULL;
    int            rc;

    perfc_incr(calls_to_update_va);

    rc = xsm_update_va_mapping(XSM_TARGET, d, pg_owner, val);
    if ( rc )
        return rc;

    rc = -EINVAL;
    pl1e = map_guest_l1e(va, &gl1mfn);
    gl1pg = pl1e ? get_page_from_mfn(gl1mfn, d) : NULL;
    if ( unlikely(!gl1pg) )
        goto out;

    if ( !page_lock(gl1pg) )
    {
        put_page(gl1pg);
        goto out;
    }

    if ( (gl1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(gl1pg);
        put_page(gl1pg);
        goto out;
    }

    rc = mod_l1_entry(pl1e, val, mfn_x(gl1mfn), 0, v, pg_owner);

    page_unlock(gl1pg);
    put_page(gl1pg);

 out:
    if ( pl1e )
        unmap_domain_page(pl1e);

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            flush_tlb_local();
            break;
        case UVMF_ALL:
            mask = d->dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
                                      mask);
            break;
        }
        if ( mask )
            flush_tlb_mask(mask);
        break;

    case UVMF_INVLPG:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            paging_invlpg(v, va);
            break;
        case UVMF_ALL:
            mask = d->dirty_cpumask;
            break;
        default:
            mask = this_cpu(scratch_cpumask);
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
                                      mask);
            break;
        }
        if ( mask )
            flush_tlb_one_mask(mask, va);
        break;
    }

    return rc;
}

long do_update_va_mapping(unsigned long va, u64 val64,
                          unsigned long flags)
{
    return __do_update_va_mapping(va, val64, flags, current->domain);
}

long do_update_va_mapping_otherdomain(unsigned long va, u64 val64,
                                      unsigned long flags,
                                      domid_t domid)
{
    struct domain *pg_owner;
    int rc;

    if ( (pg_owner = get_pg_owner(domid)) == NULL )
        return -ESRCH;

    rc = __do_update_va_mapping(va, val64, flags, pg_owner);

    put_pg_owner(pg_owner);

    return rc;
}

typedef struct e820entry e820entry_t;
DEFINE_XEN_GUEST_HANDLE(e820entry_t);

struct memory_map_context
{
    unsigned int n;
    unsigned long s;
    struct xen_memory_map map;
};

static int _handle_iomem_range(unsigned long s, unsigned long e,
                               struct memory_map_context *ctxt)
{
    if ( s > ctxt->s && !(s >> (paddr_bits - PAGE_SHIFT)) )
    {
        e820entry_t ent;
        XEN_GUEST_HANDLE_PARAM(e820entry_t) buffer_param;
        XEN_GUEST_HANDLE(e820entry_t) buffer;

        if ( !guest_handle_is_null(ctxt->map.buffer) )
        {
            if ( ctxt->n + 1 >= ctxt->map.nr_entries )
                return -EINVAL;
            ent.addr = (uint64_t)ctxt->s << PAGE_SHIFT;
            ent.size = (uint64_t)(s - ctxt->s) << PAGE_SHIFT;
            ent.type = E820_RESERVED;
            buffer_param = guest_handle_cast(ctxt->map.buffer, e820entry_t);
            buffer = guest_handle_from_param(buffer_param, e820entry_t);
            if ( __copy_to_guest_offset(buffer, ctxt->n, &ent, 1) )
                return -EFAULT;
        }
        ctxt->n++;
    }
    ctxt->s = e + 1;

    return 0;
}

static int handle_iomem_range(unsigned long s, unsigned long e, void *p)
{
    int err = 0;

    do {
        unsigned long low = -1UL;
        unsigned int i;

        for ( i = 0; i < nr_ioapics; ++i )
        {
            unsigned long mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);

            if ( mfn >= s && mfn <= e && mfn < low )
                low = mfn;
        }
        if ( !(low + 1) )
            break;
        if ( s < low )
            err = _handle_iomem_range(s, low - 1, p);
        s = low + 1;
    } while ( !err );

    return err || s > e ? err : _handle_iomem_range(s, e, p);
}

int xenmem_add_to_physmap_one(
    struct domain *d,
    unsigned int space,
    union xen_add_to_physmap_batch_extra extra,
    unsigned long idx,
    gfn_t gpfn)
{
    struct page_info *page = NULL;
    unsigned long gfn = 0; /* gcc ... */
    unsigned long prev_mfn, old_gpfn;
    int rc = 0;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t p2mt;

    if ( !paging_mode_translate(d) )
        return -EACCES;

    switch ( space )
    {
        case XENMAPSPACE_shared_info:
            if ( idx == 0 )
                mfn = _mfn(virt_to_mfn(d->shared_info));
            break;
        case XENMAPSPACE_grant_table:
            rc = gnttab_map_frame(d, idx, gpfn, &mfn);
            if ( rc )
                return rc;
            break;
        case XENMAPSPACE_gmfn:
        {
            p2m_type_t p2mt;

            gfn = idx;
            mfn = get_gfn_unshare(d, gfn, &p2mt);
            /* If the page is still shared, exit early */
            if ( p2m_is_shared(p2mt) )
            {
                put_gfn(d, gfn);
                return -ENOMEM;
            }
            page = get_page_from_mfn(mfn, d);
            if ( unlikely(!page) )
                mfn = INVALID_MFN;
            break;
        }
        case XENMAPSPACE_gmfn_foreign:
            return p2m_add_foreign(d, idx, gfn_x(gpfn), extra.foreign_domid);
        default:
            break;
    }

    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        rc = -EINVAL;
        goto put_both;
    }

    /* Remove previously mapped page if it was present. */
    prev_mfn = mfn_x(get_gfn(d, gfn_x(gpfn), &p2mt));
    if ( mfn_valid(_mfn(prev_mfn)) )
    {
        if ( is_xen_heap_mfn(prev_mfn) )
            /* Xen heap frames are simply unhooked from this phys slot. */
            rc = guest_physmap_remove_page(d, gpfn, _mfn(prev_mfn), PAGE_ORDER_4K);
        else
            /* Normal domain memory is freed, to avoid leaking memory. */
            rc = guest_remove_page(d, gfn_x(gpfn));
    }
    /* In the XENMAPSPACE_gmfn case we still hold a ref on the old page. */
    put_gfn(d, gfn_x(gpfn));

    if ( rc )
        goto put_both;

    /* Unmap from old location, if any. */
    old_gpfn = get_gpfn_from_mfn(mfn_x(mfn));
    ASSERT(!SHARED_M2P(old_gpfn));
    if ( space == XENMAPSPACE_gmfn && old_gpfn != gfn )
    {
        rc = -EXDEV;
        goto put_both;
    }
    if ( old_gpfn != INVALID_M2P_ENTRY )
        rc = guest_physmap_remove_page(d, _gfn(old_gpfn), mfn, PAGE_ORDER_4K);

    /* Map at new location. */
    if ( !rc )
        rc = guest_physmap_add_page(d, gpfn, mfn, PAGE_ORDER_4K);

 put_both:
    /* In the XENMAPSPACE_gmfn case, we took a ref of the gfn at the top. */
    if ( space == XENMAPSPACE_gmfn )
        put_gfn(d, gfn);

    if ( page )
        put_page(page);

    return rc;
}

long arch_memory_op(unsigned long cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc;

    switch ( cmd )
    {
    case XENMEM_set_memory_map:
    {
        struct xen_foreign_memory_map fmap;
        struct domain *d;
        struct e820entry *e820;

        if ( copy_from_guest(&fmap, arg, 1) )
            return -EFAULT;

        if ( fmap.map.nr_entries > E820MAX )
            return -EINVAL;

        d = rcu_lock_domain_by_any_id(fmap.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_domain_memory_map(XSM_TARGET, d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        e820 = xmalloc_array(e820entry_t, fmap.map.nr_entries);
        if ( e820 == NULL )
        {
            rcu_unlock_domain(d);
            return -ENOMEM;
        }

        if ( copy_from_guest(e820, fmap.map.buffer, fmap.map.nr_entries) )
        {
            xfree(e820);
            rcu_unlock_domain(d);
            return -EFAULT;
        }

        spin_lock(&d->arch.e820_lock);
        xfree(d->arch.e820);
        d->arch.e820 = e820;
        d->arch.nr_e820 = fmap.map.nr_entries;
        spin_unlock(&d->arch.e820_lock);

        rcu_unlock_domain(d);
        return rc;
    }

    case XENMEM_memory_map:
    {
        struct xen_memory_map map;
        struct domain *d = current->domain;

        if ( copy_from_guest(&map, arg, 1) )
            return -EFAULT;

        spin_lock(&d->arch.e820_lock);

        /* Backwards compatibility. */
        if ( (d->arch.nr_e820 == 0) || (d->arch.e820 == NULL) )
        {
            spin_unlock(&d->arch.e820_lock);
            return -ENOSYS;
        }

        map.nr_entries = min(map.nr_entries, d->arch.nr_e820);
        if ( copy_to_guest(map.buffer, d->arch.e820, map.nr_entries) ||
             __copy_to_guest(arg, &map, 1) )
        {
            spin_unlock(&d->arch.e820_lock);
            return -EFAULT;
        }

        spin_unlock(&d->arch.e820_lock);
        return 0;
    }

    case XENMEM_machine_memory_map:
    {
        struct memory_map_context ctxt;
        XEN_GUEST_HANDLE(e820entry_t) buffer;
        XEN_GUEST_HANDLE_PARAM(e820entry_t) buffer_param;
        unsigned int i;
        bool store;

        rc = xsm_machine_memory_map(XSM_PRIV);
        if ( rc )
            return rc;

        if ( copy_from_guest(&ctxt.map, arg, 1) )
            return -EFAULT;

        store = !guest_handle_is_null(ctxt.map.buffer);

        if ( store && ctxt.map.nr_entries < e820.nr_map + 1 )
            return -EINVAL;

        buffer_param = guest_handle_cast(ctxt.map.buffer, e820entry_t);
        buffer = guest_handle_from_param(buffer_param, e820entry_t);
        if ( store && !guest_handle_okay(buffer, ctxt.map.nr_entries) )
            return -EFAULT;

        for ( i = 0, ctxt.n = 0, ctxt.s = 0; i < e820.nr_map; ++i, ++ctxt.n )
        {
            unsigned long s = PFN_DOWN(e820.map[i].addr);

            if ( s > ctxt.s )
            {
                rc = rangeset_report_ranges(current->domain->iomem_caps,
                                            ctxt.s, s - 1,
                                            handle_iomem_range, &ctxt);
                if ( !rc )
                    rc = handle_iomem_range(s, s, &ctxt);
                if ( rc )
                    return rc;
            }
            if ( store )
            {
                if ( ctxt.map.nr_entries <= ctxt.n + (e820.nr_map - i) )
                    return -EINVAL;
                if ( __copy_to_guest_offset(buffer, ctxt.n, e820.map + i, 1) )
                    return -EFAULT;
            }
            ctxt.s = PFN_UP(e820.map[i].addr + e820.map[i].size);
        }

        if ( ctxt.s )
        {
            rc = rangeset_report_ranges(current->domain->iomem_caps, ctxt.s,
                                        ~0UL, handle_iomem_range, &ctxt);
            if ( !rc && ctxt.s )
                rc = handle_iomem_range(~0UL, ~0UL, &ctxt);
            if ( rc )
                return rc;
        }

        ctxt.map.nr_entries = ctxt.n;

        if ( __copy_to_guest(arg, &ctxt.map, 1) )
            return -EFAULT;

        return 0;
    }

    case XENMEM_machphys_mapping:
    {
        struct xen_machphys_mapping mapping = {
            .v_start = MACH2PHYS_VIRT_START,
            .v_end   = MACH2PHYS_VIRT_END,
            .max_mfn = MACH2PHYS_NR_ENTRIES - 1
        };

        if ( !mem_hotplug && is_hardware_domain(current->domain) )
            mapping.max_mfn = max_page - 1;
        if ( copy_to_guest(arg, &mapping, 1) )
            return -EFAULT;

        return 0;
    }

    case XENMEM_set_pod_target:
    case XENMEM_get_pod_target:
    {
        xen_pod_target_t target;
        struct domain *d;
        struct p2m_domain *p2m;

        if ( copy_from_guest(&target, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(target.domid);
        if ( d == NULL )
            return -ESRCH;

        if ( cmd == XENMEM_set_pod_target )
            rc = xsm_set_pod_target(XSM_PRIV, d);
        else
            rc = xsm_get_pod_target(XSM_PRIV, d);

        if ( rc != 0 )
            goto pod_target_out_unlock;

        if ( cmd == XENMEM_set_pod_target )
        {
            if ( target.target_pages > d->max_pages )
            {
                rc = -EINVAL;
                goto pod_target_out_unlock;
            }

            rc = p2m_pod_set_mem_target(d, target.target_pages);
        }

        if ( rc == -ERESTART )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_memory_op, "lh", cmd, arg);
        }
        else if ( rc >= 0 )
        {
            p2m = p2m_get_hostp2m(d);
            target.tot_pages       = d->tot_pages;
            target.pod_cache_pages = p2m->pod.count;
            target.pod_entries     = p2m->pod.entry_count;

            if ( __copy_to_guest(arg, &target, 1) )
            {
                rc= -EFAULT;
                goto pod_target_out_unlock;
            }
        }

    pod_target_out_unlock:
        rcu_unlock_domain(d);
        return rc;
    }

    default:
        return subarch_memory_op(cmd, arg);
    }

    return 0;
}

int mmio_ro_emulated_write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct mmio_ro_emulate_ctxt *mmio_ro_ctxt = ctxt->data;

    /* Only allow naturally-aligned stores at the original %cr2 address. */
    if ( ((bytes | offset) & (bytes - 1)) || !bytes ||
         offset != mmio_ro_ctxt->cr2 )
    {
        gdprintk(XENLOG_WARNING, "bad access (cr2=%lx, addr=%lx, bytes=%u)\n",
                mmio_ro_ctxt->cr2, offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

int mmcfg_intercept_write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct mmio_ro_emulate_ctxt *mmio_ctxt = ctxt->data;

    /*
     * Only allow naturally-aligned stores no wider than 4 bytes to the
     * original %cr2 address.
     */
    if ( ((bytes | offset) & (bytes - 1)) || bytes > 4 || !bytes ||
         offset != mmio_ctxt->cr2 )
    {
        gdprintk(XENLOG_WARNING, "bad write (cr2=%lx, addr=%lx, bytes=%u)\n",
                mmio_ctxt->cr2, offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    offset &= 0xfff;
    if ( pci_conf_write_intercept(mmio_ctxt->seg, mmio_ctxt->bdf,
                                  offset, bytes, p_data) >= 0 )
        pci_mmcfg_write(mmio_ctxt->seg, PCI_BUS(mmio_ctxt->bdf),
                        PCI_DEVFN2(mmio_ctxt->bdf), offset, bytes,
                        *(uint32_t *)p_data);

    return X86EMUL_OKAY;
}

void *alloc_xen_pagetable(void)
{
    if ( system_state != SYS_STATE_early_boot )
    {
        void *ptr = alloc_xenheap_page();

        BUG_ON(!hardware_domain && !ptr);
        return ptr;
    }

    return mfn_to_virt(mfn_x(alloc_boot_pages(1, 1)));
}

void free_xen_pagetable(void *v)
{
    if ( system_state != SYS_STATE_early_boot )
        free_xenheap_page(v);
}

static DEFINE_SPINLOCK(map_pgdir_lock);

static l3_pgentry_t *virt_to_xen_l3e(unsigned long v)
{
    l4_pgentry_t *pl4e;

    pl4e = &idle_pg_table[l4_table_offset(v)];
    if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
    {
        bool locking = system_state > SYS_STATE_boot;
        l3_pgentry_t *pl3e = alloc_xen_pagetable();

        if ( !pl3e )
            return NULL;
        clear_page(pl3e);
        if ( locking )
            spin_lock(&map_pgdir_lock);
        if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
        {
            l4_pgentry_t l4e = l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR);

            l4e_write(pl4e, l4e);
            efi_update_l4_pgtable(l4_table_offset(v), l4e);
            pl3e = NULL;
        }
        if ( locking )
            spin_unlock(&map_pgdir_lock);
        if ( pl3e )
            free_xen_pagetable(pl3e);
    }

    return l4e_to_l3e(*pl4e) + l3_table_offset(v);
}

static l2_pgentry_t *virt_to_xen_l2e(unsigned long v)
{
    l3_pgentry_t *pl3e;

    pl3e = virt_to_xen_l3e(v);
    if ( !pl3e )
        return NULL;

    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
    {
        bool locking = system_state > SYS_STATE_boot;
        l2_pgentry_t *pl2e = alloc_xen_pagetable();

        if ( !pl2e )
            return NULL;
        clear_page(pl2e);
        if ( locking )
            spin_lock(&map_pgdir_lock);
        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
            l3e_write(pl3e, l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR));
            pl2e = NULL;
        }
        if ( locking )
            spin_unlock(&map_pgdir_lock);
        if ( pl2e )
            free_xen_pagetable(pl2e);
    }

    BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
    return l3e_to_l2e(*pl3e) + l2_table_offset(v);
}

l1_pgentry_t *virt_to_xen_l1e(unsigned long v)
{
    l2_pgentry_t *pl2e;

    pl2e = virt_to_xen_l2e(v);
    if ( !pl2e )
        return NULL;

    if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
    {
        bool locking = system_state > SYS_STATE_boot;
        l1_pgentry_t *pl1e = alloc_xen_pagetable();

        if ( !pl1e )
            return NULL;
        clear_page(pl1e);
        if ( locking )
            spin_lock(&map_pgdir_lock);
        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            l2e_write(pl2e, l2e_from_paddr(__pa(pl1e), __PAGE_HYPERVISOR));
            pl1e = NULL;
        }
        if ( locking )
            spin_unlock(&map_pgdir_lock);
        if ( pl1e )
            free_xen_pagetable(pl1e);
    }

    BUG_ON(l2e_get_flags(*pl2e) & _PAGE_PSE);
    return l2e_to_l1e(*pl2e) + l1_table_offset(v);
}

/* Convert to from superpage-mapping flags for map_pages_to_xen(). */
#define l1f_to_lNf(f) (((f) & _PAGE_PRESENT) ? ((f) |  _PAGE_PSE) : (f))
#define lNf_to_l1f(f) (((f) & _PAGE_PRESENT) ? ((f) & ~_PAGE_PSE) : (f))

/*
 * map_pages_to_xen() can be called with interrupts disabled during
 * early bootstrap. In this case it is safe to use flush_area_local()
 * and avoid locking because only the local CPU is online.
 */
#define flush_area(v,f) (!local_irq_is_enabled() ?              \
                         flush_area_local((const void *)v, f) : \
                         flush_area_all((const void *)v, f))

int map_pages_to_xen(
    unsigned long virt,
    unsigned long mfn,
    unsigned long nr_mfns,
    unsigned int flags)
{
    bool locking = system_state > SYS_STATE_boot;
    l2_pgentry_t *pl2e, ol2e;
    l1_pgentry_t *pl1e, ol1e;
    unsigned int  i;

#define flush_flags(oldf) do {                 \
    unsigned int o_ = (oldf);                  \
    if ( (o_) & _PAGE_GLOBAL )                 \
        flush_flags |= FLUSH_TLB_GLOBAL;       \
    if ( (flags & _PAGE_PRESENT) &&            \
         (((o_) ^ flags) & PAGE_CACHE_ATTRS) ) \
    {                                          \
        flush_flags |= FLUSH_CACHE;            \
        if ( virt >= DIRECTMAP_VIRT_START &&   \
             virt < HYPERVISOR_VIRT_END )      \
            flush_flags |= FLUSH_VA_VALID;     \
    }                                          \
} while (0)

    while ( nr_mfns != 0 )
    {
        l3_pgentry_t ol3e, *pl3e = virt_to_xen_l3e(virt);

        if ( !pl3e )
            return -ENOMEM;
        ol3e = *pl3e;

        if ( cpu_has_page1gb &&
             !(((virt >> PAGE_SHIFT) | mfn) &
               ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)) &&
             nr_mfns >= (1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) &&
             !(flags & (_PAGE_PAT | MAP_SMALL_PAGES)) )
        {
            /* 1GB-page mapping. */
            l3e_write_atomic(pl3e, l3e_from_pfn(mfn, l1f_to_lNf(flags)));

            if ( (l3e_get_flags(ol3e) & _PAGE_PRESENT) )
            {
                unsigned int flush_flags =
                    FLUSH_TLB | FLUSH_ORDER(2 * PAGETABLE_ORDER);

                if ( l3e_get_flags(ol3e) & _PAGE_PSE )
                {
                    flush_flags(lNf_to_l1f(l3e_get_flags(ol3e)));
                    flush_area(virt, flush_flags);
                }
                else
                {
                    pl2e = l3e_to_l2e(ol3e);
                    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
                    {
                        ol2e = pl2e[i];
                        if ( !(l2e_get_flags(ol2e) & _PAGE_PRESENT) )
                            continue;
                        if ( l2e_get_flags(ol2e) & _PAGE_PSE )
                            flush_flags(lNf_to_l1f(l2e_get_flags(ol2e)));
                        else
                        {
                            unsigned int j;

                            pl1e = l2e_to_l1e(ol2e);
                            for ( j = 0; j < L1_PAGETABLE_ENTRIES; j++ )
                                flush_flags(l1e_get_flags(pl1e[j]));
                        }
                    }
                    flush_area(virt, flush_flags);
                    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
                    {
                        ol2e = pl2e[i];
                        if ( (l2e_get_flags(ol2e) & _PAGE_PRESENT) &&
                             !(l2e_get_flags(ol2e) & _PAGE_PSE) )
                            free_xen_pagetable(l2e_to_l1e(ol2e));
                    }
                    free_xen_pagetable(pl2e);
                }
            }

            virt    += 1UL << L3_PAGETABLE_SHIFT;
            mfn     += 1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
            nr_mfns -= 1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
            continue;
        }

        if ( (l3e_get_flags(ol3e) & _PAGE_PRESENT) &&
             (l3e_get_flags(ol3e) & _PAGE_PSE) )
        {
            unsigned int flush_flags =
                FLUSH_TLB | FLUSH_ORDER(2 * PAGETABLE_ORDER);

            /* Skip this PTE if there is no change. */
            if ( ((l3e_get_pfn(ol3e) & ~(L2_PAGETABLE_ENTRIES *
                                         L1_PAGETABLE_ENTRIES - 1)) +
                  (l2_table_offset(virt) << PAGETABLE_ORDER) +
                  l1_table_offset(virt) == mfn) &&
                 ((lNf_to_l1f(l3e_get_flags(ol3e)) ^ flags) &
                  ~(_PAGE_ACCESSED|_PAGE_DIRTY)) == 0 )
            {
                /* We can skip to end of L3 superpage if we got a match. */
                i = (1u << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) -
                    (mfn & ((1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
                if ( i > nr_mfns )
                    i = nr_mfns;
                virt    += i << PAGE_SHIFT;
                mfn     += i;
                nr_mfns -= i;
                continue;
            }

            pl2e = alloc_xen_pagetable();
            if ( pl2e == NULL )
                return -ENOMEM;

            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
                l2e_write(pl2e + i,
                          l2e_from_pfn(l3e_get_pfn(ol3e) +
                                       (i << PAGETABLE_ORDER),
                                       l3e_get_flags(ol3e)));

            if ( l3e_get_flags(ol3e) & _PAGE_GLOBAL )
                flush_flags |= FLUSH_TLB_GLOBAL;

            if ( locking )
                spin_lock(&map_pgdir_lock);
            if ( (l3e_get_flags(*pl3e) & _PAGE_PRESENT) &&
                 (l3e_get_flags(*pl3e) & _PAGE_PSE) )
            {
                l3e_write_atomic(pl3e, l3e_from_pfn(virt_to_mfn(pl2e),
                                                    __PAGE_HYPERVISOR));
                pl2e = NULL;
            }
            if ( locking )
                spin_unlock(&map_pgdir_lock);
            flush_area(virt, flush_flags);
            if ( pl2e )
                free_xen_pagetable(pl2e);
        }

        pl2e = virt_to_xen_l2e(virt);
        if ( !pl2e )
            return -ENOMEM;

        if ( ((((virt >> PAGE_SHIFT) | mfn) &
               ((1u << PAGETABLE_ORDER) - 1)) == 0) &&
             (nr_mfns >= (1u << PAGETABLE_ORDER)) &&
             !(flags & (_PAGE_PAT|MAP_SMALL_PAGES)) )
        {
            /* Super-page mapping. */
            ol2e = *pl2e;
            l2e_write_atomic(pl2e, l2e_from_pfn(mfn, l1f_to_lNf(flags)));

            if ( (l2e_get_flags(ol2e) & _PAGE_PRESENT) )
            {
                unsigned int flush_flags =
                    FLUSH_TLB | FLUSH_ORDER(PAGETABLE_ORDER);

                if ( l2e_get_flags(ol2e) & _PAGE_PSE )
                {
                    flush_flags(lNf_to_l1f(l2e_get_flags(ol2e)));
                    flush_area(virt, flush_flags);
                }
                else
                {
                    pl1e = l2e_to_l1e(ol2e);
                    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                        flush_flags(l1e_get_flags(pl1e[i]));
                    flush_area(virt, flush_flags);
                    free_xen_pagetable(pl1e);
                }
            }

            virt    += 1UL << L2_PAGETABLE_SHIFT;
            mfn     += 1UL << PAGETABLE_ORDER;
            nr_mfns -= 1UL << PAGETABLE_ORDER;
        }
        else
        {
            /* Normal page mapping. */
            if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
            {
                pl1e = virt_to_xen_l1e(virt);
                if ( pl1e == NULL )
                    return -ENOMEM;
            }
            else if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
            {
                unsigned int flush_flags =
                    FLUSH_TLB | FLUSH_ORDER(PAGETABLE_ORDER);

                /* Skip this PTE if there is no change. */
                if ( (((l2e_get_pfn(*pl2e) & ~(L1_PAGETABLE_ENTRIES - 1)) +
                       l1_table_offset(virt)) == mfn) &&
                     (((lNf_to_l1f(l2e_get_flags(*pl2e)) ^ flags) &
                       ~(_PAGE_ACCESSED|_PAGE_DIRTY)) == 0) )
                {
                    /* We can skip to end of L2 superpage if we got a match. */
                    i = (1u << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) -
                        (mfn & ((1u << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
                    if ( i > nr_mfns )
                        i = nr_mfns;
                    virt    += i << L1_PAGETABLE_SHIFT;
                    mfn     += i;
                    nr_mfns -= i;
                    goto check_l3;
                }

                pl1e = alloc_xen_pagetable();
                if ( pl1e == NULL )
                    return -ENOMEM;

                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           lNf_to_l1f(l2e_get_flags(*pl2e))));

                if ( l2e_get_flags(*pl2e) & _PAGE_GLOBAL )
                    flush_flags |= FLUSH_TLB_GLOBAL;

                if ( locking )
                    spin_lock(&map_pgdir_lock);
                if ( (l2e_get_flags(*pl2e) & _PAGE_PRESENT) &&
                     (l2e_get_flags(*pl2e) & _PAGE_PSE) )
                {
                    l2e_write_atomic(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                                        __PAGE_HYPERVISOR));
                    pl1e = NULL;
                }
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                flush_area(virt, flush_flags);
                if ( pl1e )
                    free_xen_pagetable(pl1e);
            }

            pl1e  = l2e_to_l1e(*pl2e) + l1_table_offset(virt);
            ol1e  = *pl1e;
            l1e_write_atomic(pl1e, l1e_from_pfn(mfn, flags));
            if ( (l1e_get_flags(ol1e) & _PAGE_PRESENT) )
            {
                unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(0);

                flush_flags(l1e_get_flags(ol1e));
                flush_area(virt, flush_flags);
            }

            virt    += 1UL << L1_PAGETABLE_SHIFT;
            mfn     += 1UL;
            nr_mfns -= 1UL;

            if ( (flags == PAGE_HYPERVISOR) &&
                 ((nr_mfns == 0) ||
                  ((((virt >> PAGE_SHIFT) | mfn) &
                    ((1u << PAGETABLE_ORDER) - 1)) == 0)) )
            {
                unsigned long base_mfn;

                if ( locking )
                    spin_lock(&map_pgdir_lock);

                ol2e = *pl2e;
                /*
                 * L2E may be already cleared, or set to a superpage, by
                 * concurrent paging structure modifications on other CPUs.
                 */
                if ( !(l2e_get_flags(ol2e) & _PAGE_PRESENT) )
                {
                    if ( locking )
                        spin_unlock(&map_pgdir_lock);
                    continue;
                }

                if ( l2e_get_flags(ol2e) & _PAGE_PSE )
                {
                    if ( locking )
                        spin_unlock(&map_pgdir_lock);
                    goto check_l3;
                }

                pl1e = l2e_to_l1e(ol2e);
                base_mfn = l1e_get_pfn(*pl1e) & ~(L1_PAGETABLE_ENTRIES - 1);
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++, pl1e++ )
                    if ( (l1e_get_pfn(*pl1e) != (base_mfn + i)) ||
                         (l1e_get_flags(*pl1e) != flags) )
                        break;
                if ( i == L1_PAGETABLE_ENTRIES )
                {
                    l2e_write_atomic(pl2e, l2e_from_pfn(base_mfn,
                                                        l1f_to_lNf(flags)));
                    if ( locking )
                        spin_unlock(&map_pgdir_lock);
                    flush_area(virt - PAGE_SIZE,
                               FLUSH_TLB_GLOBAL |
                               FLUSH_ORDER(PAGETABLE_ORDER));
                    free_xen_pagetable(l2e_to_l1e(ol2e));
                }
                else if ( locking )
                    spin_unlock(&map_pgdir_lock);
            }
        }

 check_l3:
        if ( cpu_has_page1gb &&
             (flags == PAGE_HYPERVISOR) &&
             ((nr_mfns == 0) ||
              !(((virt >> PAGE_SHIFT) | mfn) &
                ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1))) )
        {
            unsigned long base_mfn;

            if ( locking )
                spin_lock(&map_pgdir_lock);

            ol3e = *pl3e;
            /*
             * L3E may be already cleared, or set to a superpage, by
             * concurrent paging structure modifications on other CPUs.
             */
            if ( !(l3e_get_flags(ol3e) & _PAGE_PRESENT) ||
                (l3e_get_flags(ol3e) & _PAGE_PSE) )
            {
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                continue;
            }

            pl2e = l3e_to_l2e(ol3e);
            base_mfn = l2e_get_pfn(*pl2e) & ~(L2_PAGETABLE_ENTRIES *
                                              L1_PAGETABLE_ENTRIES - 1);
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++, pl2e++ )
                if ( (l2e_get_pfn(*pl2e) !=
                      (base_mfn + (i << PAGETABLE_ORDER))) ||
                     (l2e_get_flags(*pl2e) != l1f_to_lNf(flags)) )
                    break;
            if ( i == L2_PAGETABLE_ENTRIES )
            {
                l3e_write_atomic(pl3e, l3e_from_pfn(base_mfn,
                                                    l1f_to_lNf(flags)));
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                flush_area(virt - PAGE_SIZE,
                           FLUSH_TLB_GLOBAL |
                           FLUSH_ORDER(2*PAGETABLE_ORDER));
                free_xen_pagetable(l3e_to_l2e(ol3e));
            }
            else if ( locking )
                spin_unlock(&map_pgdir_lock);
        }
    }

#undef flush_flags

    return 0;
}

int populate_pt_range(unsigned long virt, unsigned long mfn,
                      unsigned long nr_mfns)
{
    return map_pages_to_xen(virt, mfn, nr_mfns, MAP_SMALL_PAGES);
}

/*
 * Alter the permissions of a range of Xen virtual address space.
 *
 * Does not create new mappings, and does not modify the mfn in existing
 * mappings, but will shatter superpages if necessary, and will destroy
 * mappings if not passed _PAGE_PRESENT.
 *
 * The only flags considered are NX, RW and PRESENT.  All other input flags
 * are ignored.
 *
 * It is an error to call with present flags over an unpopulated range.
 */
int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int nf)
{
    bool locking = system_state > SYS_STATE_boot;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int  i;
    unsigned long v = s;

    /* Set of valid PTE bits which may be altered. */
#define FLAGS_MASK (_PAGE_NX|_PAGE_RW|_PAGE_PRESENT)
    nf &= FLAGS_MASK;

    ASSERT(IS_ALIGNED(s, PAGE_SIZE));
    ASSERT(IS_ALIGNED(e, PAGE_SIZE));

    while ( v < e )
    {
        l3_pgentry_t *pl3e = virt_to_xen_l3e(v);

        if ( !pl3e || !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
            /* Confirm the caller isn't trying to create new mappings. */
            ASSERT(!(nf & _PAGE_PRESENT));

            v += 1UL << L3_PAGETABLE_SHIFT;
            v &= ~((1UL << L3_PAGETABLE_SHIFT) - 1);
            continue;
        }

        if ( l3e_get_flags(*pl3e) & _PAGE_PSE )
        {
            if ( l2_table_offset(v) == 0 &&
                 l1_table_offset(v) == 0 &&
                 ((e - v) >= (1UL << L3_PAGETABLE_SHIFT)) )
            {
                /* PAGE1GB: whole superpage is modified. */
                l3_pgentry_t nl3e = !(nf & _PAGE_PRESENT) ? l3e_empty()
                    : l3e_from_pfn(l3e_get_pfn(*pl3e),
                                   (l3e_get_flags(*pl3e) & ~FLAGS_MASK) | nf);

                l3e_write_atomic(pl3e, nl3e);
                v += 1UL << L3_PAGETABLE_SHIFT;
                continue;
            }

            /* PAGE1GB: shatter the superpage and fall through. */
            pl2e = alloc_xen_pagetable();
            if ( !pl2e )
                return -ENOMEM;
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
                l2e_write(pl2e + i,
                          l2e_from_pfn(l3e_get_pfn(*pl3e) +
                                       (i << PAGETABLE_ORDER),
                                       l3e_get_flags(*pl3e)));
            if ( locking )
                spin_lock(&map_pgdir_lock);
            if ( (l3e_get_flags(*pl3e) & _PAGE_PRESENT) &&
                 (l3e_get_flags(*pl3e) & _PAGE_PSE) )
            {
                l3e_write_atomic(pl3e, l3e_from_pfn(virt_to_mfn(pl2e),
                                                    __PAGE_HYPERVISOR));
                pl2e = NULL;
            }
            if ( locking )
                spin_unlock(&map_pgdir_lock);
            if ( pl2e )
                free_xen_pagetable(pl2e);
        }

        /*
         * The L3 entry has been verified to be present, and we've dealt with
         * 1G pages as well, so the L2 table cannot require allocation.
         */
        pl2e = l3e_to_l2e(*pl3e) + l2_table_offset(v);

        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            /* Confirm the caller isn't trying to create new mappings. */
            ASSERT(!(nf & _PAGE_PRESENT));

            v += 1UL << L2_PAGETABLE_SHIFT;
            v &= ~((1UL << L2_PAGETABLE_SHIFT) - 1);
            continue;
        }

        if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
        {
            if ( (l1_table_offset(v) == 0) &&
                 ((e-v) >= (1UL << L2_PAGETABLE_SHIFT)) )
            {
                /* PSE: whole superpage is modified. */
                l2_pgentry_t nl2e = !(nf & _PAGE_PRESENT) ? l2e_empty()
                    : l2e_from_pfn(l2e_get_pfn(*pl2e),
                                   (l2e_get_flags(*pl2e) & ~FLAGS_MASK) | nf);

                l2e_write_atomic(pl2e, nl2e);
                v += 1UL << L2_PAGETABLE_SHIFT;
            }
            else
            {
                /* PSE: shatter the superpage and try again. */
                pl1e = alloc_xen_pagetable();
                if ( !pl1e )
                    return -ENOMEM;
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           l2e_get_flags(*pl2e) & ~_PAGE_PSE));
                if ( locking )
                    spin_lock(&map_pgdir_lock);
                if ( (l2e_get_flags(*pl2e) & _PAGE_PRESENT) &&
                     (l2e_get_flags(*pl2e) & _PAGE_PSE) )
                {
                    l2e_write_atomic(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                                        __PAGE_HYPERVISOR));
                    pl1e = NULL;
                }
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                if ( pl1e )
                    free_xen_pagetable(pl1e);
            }
        }
        else
        {
            l1_pgentry_t nl1e;

            /*
             * Ordinary 4kB mapping: The L2 entry has been verified to be
             * present, and we've dealt with 2M pages as well, so the L1 table
             * cannot require allocation.
             */
            pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(v);

            /* Confirm the caller isn't trying to create new mappings. */
            if ( !(l1e_get_flags(*pl1e) & _PAGE_PRESENT) )
                ASSERT(!(nf & _PAGE_PRESENT));

            nl1e = !(nf & _PAGE_PRESENT) ? l1e_empty()
                : l1e_from_pfn(l1e_get_pfn(*pl1e),
                               (l1e_get_flags(*pl1e) & ~FLAGS_MASK) | nf);

            l1e_write_atomic(pl1e, nl1e);
            v += PAGE_SIZE;

            /*
             * If we are not destroying mappings, or not done with the L2E,
             * skip the empty&free check.
             */
            if ( (nf & _PAGE_PRESENT) || ((v != e) && (l1_table_offset(v) != 0)) )
                continue;
            if ( locking )
                spin_lock(&map_pgdir_lock);

            /*
             * L2E may be already cleared, or set to a superpage, by
             * concurrent paging structure modifications on other CPUs.
             */
            if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
            {
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                goto check_l3;
            }

            if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
            {
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                continue;
            }

            pl1e = l2e_to_l1e(*pl2e);
            for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                if ( l1e_get_intpte(pl1e[i]) != 0 )
                    break;
            if ( i == L1_PAGETABLE_ENTRIES )
            {
                /* Empty: zap the L2E and free the L1 page. */
                l2e_write_atomic(pl2e, l2e_empty());
                if ( locking )
                    spin_unlock(&map_pgdir_lock);
                flush_area(NULL, FLUSH_TLB_GLOBAL); /* flush before free */
                free_xen_pagetable(pl1e);
            }
            else if ( locking )
                spin_unlock(&map_pgdir_lock);
        }

 check_l3:
        /*
         * If we are not destroying mappings, or not done with the L3E,
         * skip the empty&free check.
         */
        if ( (nf & _PAGE_PRESENT) ||
             ((v != e) && (l2_table_offset(v) + l1_table_offset(v) != 0)) )
            continue;
        if ( locking )
            spin_lock(&map_pgdir_lock);

        /*
         * L3E may be already cleared, or set to a superpage, by
         * concurrent paging structure modifications on other CPUs.
         */
        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) ||
              (l3e_get_flags(*pl3e) & _PAGE_PSE) )
        {
            if ( locking )
                spin_unlock(&map_pgdir_lock);
            continue;
        }

        pl2e = l3e_to_l2e(*pl3e);
        for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            if ( l2e_get_intpte(pl2e[i]) != 0 )
                break;
        if ( i == L2_PAGETABLE_ENTRIES )
        {
            /* Empty: zap the L3E and free the L2 page. */
            l3e_write_atomic(pl3e, l3e_empty());
            if ( locking )
                spin_unlock(&map_pgdir_lock);
            flush_area(NULL, FLUSH_TLB_GLOBAL); /* flush before free */
            free_xen_pagetable(pl2e);
        }
        else if ( locking )
            spin_unlock(&map_pgdir_lock);
    }

    flush_area(NULL, FLUSH_TLB_GLOBAL);

#undef FLAGS_MASK
    return 0;
}

#undef flush_area

int destroy_xen_mappings(unsigned long s, unsigned long e)
{
    return modify_xen_mappings(s, e, _PAGE_NONE);
}

void __set_fixmap(
    enum fixed_addresses idx, unsigned long mfn, unsigned long flags)
{
    BUG_ON(idx >= __end_of_fixed_addresses);
    map_pages_to_xen(__fix_to_virt(idx), mfn, 1, flags);
}

void *__init arch_vmap_virt_end(void)
{
    return fix_to_virt(__end_of_fixed_addresses);
}

void __iomem *ioremap(paddr_t pa, size_t len)
{
    mfn_t mfn = _mfn(PFN_DOWN(pa));
    void *va;

    WARN_ON(page_is_ram_type(mfn_x(mfn), RAM_TYPE_CONVENTIONAL));

    /* The low first Mb is always mapped. */
    if ( !((pa + len - 1) >> 20) )
        va = __va(pa);
    else
    {
        unsigned int offs = pa & (PAGE_SIZE - 1);
        unsigned int nr = PFN_UP(offs + len);

        va = __vmap(&mfn, nr, 1, 1, PAGE_HYPERVISOR_UCMINUS, VMAP_DEFAULT) + offs;
    }

    return (void __force __iomem *)va;
}

int create_perdomain_mapping(struct domain *d, unsigned long va,
                             unsigned int nr, l1_pgentry_t **pl1tab,
                             struct page_info **ppg)
{
    struct page_info *pg;
    l3_pgentry_t *l3tab;
    l2_pgentry_t *l2tab;
    l1_pgentry_t *l1tab;
    int rc = 0;

    ASSERT(va >= PERDOMAIN_VIRT_START &&
           va < PERDOMAIN_VIRT_SLOT(PERDOMAIN_SLOTS));

    if ( !d->arch.perdomain_l3_pg )
    {
        pg = alloc_domheap_page(d, MEMF_no_owner);
        if ( !pg )
            return -ENOMEM;
        l3tab = __map_domain_page(pg);
        clear_page(l3tab);
        d->arch.perdomain_l3_pg = pg;
        if ( !nr )
        {
            unmap_domain_page(l3tab);
            return 0;
        }
    }
    else if ( !nr )
        return 0;
    else
        l3tab = __map_domain_page(d->arch.perdomain_l3_pg);

    ASSERT(!l3_table_offset(va ^ (va + nr * PAGE_SIZE - 1)));

    if ( !(l3e_get_flags(l3tab[l3_table_offset(va)]) & _PAGE_PRESENT) )
    {
        pg = alloc_domheap_page(d, MEMF_no_owner);
        if ( !pg )
        {
            unmap_domain_page(l3tab);
            return -ENOMEM;
        }
        l2tab = __map_domain_page(pg);
        clear_page(l2tab);
        l3tab[l3_table_offset(va)] = l3e_from_page(pg, __PAGE_HYPERVISOR_RW);
    }
    else
        l2tab = map_l2t_from_l3e(l3tab[l3_table_offset(va)]);

    unmap_domain_page(l3tab);

    if ( !pl1tab && !ppg )
    {
        unmap_domain_page(l2tab);
        return 0;
    }

    for ( l1tab = NULL; !rc && nr--; )
    {
        l2_pgentry_t *pl2e = l2tab + l2_table_offset(va);

        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            if ( pl1tab && !IS_NIL(pl1tab) )
            {
                l1tab = alloc_xenheap_pages(0, MEMF_node(domain_to_node(d)));
                if ( !l1tab )
                {
                    rc = -ENOMEM;
                    break;
                }
                ASSERT(!pl1tab[l2_table_offset(va)]);
                pl1tab[l2_table_offset(va)] = l1tab;
                pg = virt_to_page(l1tab);
            }
            else
            {
                pg = alloc_domheap_page(d, MEMF_no_owner);
                if ( !pg )
                {
                    rc = -ENOMEM;
                    break;
                }
                l1tab = __map_domain_page(pg);
            }
            clear_page(l1tab);
            *pl2e = l2e_from_page(pg, __PAGE_HYPERVISOR_RW);
        }
        else if ( !l1tab )
            l1tab = map_l1t_from_l2e(*pl2e);

        if ( ppg &&
             !(l1e_get_flags(l1tab[l1_table_offset(va)]) & _PAGE_PRESENT) )
        {
            pg = alloc_domheap_page(d, MEMF_no_owner);
            if ( pg )
            {
                clear_domain_page(page_to_mfn(pg));
                if ( !IS_NIL(ppg) )
                    *ppg++ = pg;
                l1tab[l1_table_offset(va)] =
                    l1e_from_page(pg, __PAGE_HYPERVISOR_RW | _PAGE_AVAIL0);
                l2e_add_flags(*pl2e, _PAGE_AVAIL0);
            }
            else
                rc = -ENOMEM;
        }

        va += PAGE_SIZE;
        if ( rc || !nr || !l1_table_offset(va) )
        {
            /* Note that this is a no-op for the alloc_xenheap_page() case. */
            unmap_domain_page(l1tab);
            l1tab = NULL;
        }
    }

    ASSERT(!l1tab);
    unmap_domain_page(l2tab);

    return rc;
}

void destroy_perdomain_mapping(struct domain *d, unsigned long va,
                               unsigned int nr)
{
    const l3_pgentry_t *l3tab, *pl3e;

    ASSERT(va >= PERDOMAIN_VIRT_START &&
           va < PERDOMAIN_VIRT_SLOT(PERDOMAIN_SLOTS));
    ASSERT(!l3_table_offset(va ^ (va + nr * PAGE_SIZE - 1)));

    if ( !d->arch.perdomain_l3_pg )
        return;

    l3tab = __map_domain_page(d->arch.perdomain_l3_pg);
    pl3e = l3tab + l3_table_offset(va);

    if ( l3e_get_flags(*pl3e) & _PAGE_PRESENT )
    {
        const l2_pgentry_t *l2tab = map_l2t_from_l3e(*pl3e);
        const l2_pgentry_t *pl2e = l2tab + l2_table_offset(va);
        unsigned int i = l1_table_offset(va);

        while ( nr )
        {
            if ( l2e_get_flags(*pl2e) & _PAGE_PRESENT )
            {
                l1_pgentry_t *l1tab = map_l1t_from_l2e(*pl2e);

                for ( ; nr && i < L1_PAGETABLE_ENTRIES; --nr, ++i )
                {
                    if ( (l1e_get_flags(l1tab[i]) &
                          (_PAGE_PRESENT | _PAGE_AVAIL0)) ==
                         (_PAGE_PRESENT | _PAGE_AVAIL0) )
                        free_domheap_page(l1e_get_page(l1tab[i]));
                    l1tab[i] = l1e_empty();
                }

                unmap_domain_page(l1tab);
            }
            else if ( nr + i < L1_PAGETABLE_ENTRIES )
                break;
            else
                nr -= L1_PAGETABLE_ENTRIES - i;

            ++pl2e;
            i = 0;
        }

        unmap_domain_page(l2tab);
    }

    unmap_domain_page(l3tab);
}

void free_perdomain_mappings(struct domain *d)
{
    l3_pgentry_t *l3tab;
    unsigned int i;

    if ( !d->arch.perdomain_l3_pg )
        return;

    l3tab = __map_domain_page(d->arch.perdomain_l3_pg);

    for ( i = 0; i < PERDOMAIN_SLOTS; ++i)
        if ( l3e_get_flags(l3tab[i]) & _PAGE_PRESENT )
        {
            struct page_info *l2pg = l3e_get_page(l3tab[i]);
            l2_pgentry_t *l2tab = __map_domain_page(l2pg);
            unsigned int j;

            for ( j = 0; j < L2_PAGETABLE_ENTRIES; ++j )
                if ( l2e_get_flags(l2tab[j]) & _PAGE_PRESENT )
                {
                    struct page_info *l1pg = l2e_get_page(l2tab[j]);

                    if ( l2e_get_flags(l2tab[j]) & _PAGE_AVAIL0 )
                    {
                        l1_pgentry_t *l1tab = __map_domain_page(l1pg);
                        unsigned int k;

                        for ( k = 0; k < L1_PAGETABLE_ENTRIES; ++k )
                            if ( (l1e_get_flags(l1tab[k]) &
                                  (_PAGE_PRESENT | _PAGE_AVAIL0)) ==
                                 (_PAGE_PRESENT | _PAGE_AVAIL0) )
                                free_domheap_page(l1e_get_page(l1tab[k]));

                        unmap_domain_page(l1tab);
                    }

                    if ( is_xen_heap_page(l1pg) )
                        free_xenheap_page(page_to_virt(l1pg));
                    else
                        free_domheap_page(l1pg);
                }

            unmap_domain_page(l2tab);
            free_domheap_page(l2pg);
        }

    unmap_domain_page(l3tab);
    free_domheap_page(d->arch.perdomain_l3_pg);
    d->arch.perdomain_l3_pg = NULL;
}

#ifdef MEMORY_GUARD

static void __memguard_change_range(void *p, unsigned long l, int guard)
{
    unsigned long _p = (unsigned long)p;
    unsigned long _l = (unsigned long)l;
    unsigned int flags = __PAGE_HYPERVISOR_RW | MAP_SMALL_PAGES;

    /* Ensure we are dealing with a page-aligned whole number of pages. */
    ASSERT(IS_ALIGNED(_p, PAGE_SIZE));
    ASSERT(IS_ALIGNED(_l, PAGE_SIZE));

    if ( guard )
        flags &= ~_PAGE_PRESENT;

    map_pages_to_xen(
        _p, virt_to_maddr(p) >> PAGE_SHIFT, _l >> PAGE_SHIFT, flags);
}

void memguard_guard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 1);
}

void memguard_unguard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 0);
}

#endif

void memguard_guard_stack(void *p)
{
    /* IST_MAX IST pages + at least 1 guard page + primary stack. */
    BUILD_BUG_ON((IST_MAX + 1) * PAGE_SIZE + PRIMARY_STACK_SIZE > STACK_SIZE);

    memguard_guard_range(p + IST_MAX * PAGE_SIZE,
                         STACK_SIZE - PRIMARY_STACK_SIZE - IST_MAX * PAGE_SIZE);
}

void memguard_unguard_stack(void *p)
{
    memguard_unguard_range(p + IST_MAX * PAGE_SIZE,
                           STACK_SIZE - PRIMARY_STACK_SIZE - IST_MAX * PAGE_SIZE);
}

bool memguard_is_stack_guard_page(unsigned long addr)
{
    addr &= STACK_SIZE - 1;

    return addr >= IST_MAX * PAGE_SIZE &&
           addr < STACK_SIZE - PRIMARY_STACK_SIZE;
}

void arch_dump_shared_mem_info(void)
{
    printk("Shared frames %u -- Saved frames %u\n",
            mem_sharing_get_nr_shared_mfns(),
            mem_sharing_get_nr_saved_mfns());
}

const unsigned long *__init get_platform_badpages(unsigned int *array_size)
{
    u32 igd_id;
    static unsigned long __initdata bad_pages[] = {
        0x20050000,
        0x20110000,
        0x20130000,
        0x20138000,
        0x40004000,
    };

    *array_size = ARRAY_SIZE(bad_pages);
    igd_id = pci_conf_read32(0, 0, 2, 0, 0);
    if ( !IS_SNB_GFX(igd_id) )
        return NULL;

    return bad_pages;
}

void paging_invlpg(struct vcpu *v, unsigned long va)
{
    if ( !is_canonical_address(va) )
        return;

    if ( paging_mode_enabled(v->domain) &&
         !paging_get_hostmode(v)->invlpg(v, va) )
        return;

    if ( is_pv_vcpu(v) )
        flush_tlb_one_local(va);
    else
        hvm_funcs.invlpg(v, va);
}

/* Build a 32bit PSE page table using 4MB pages. */
void write_32bit_pse_identmap(uint32_t *l2)
{
    unsigned int i;

    for ( i = 0; i < PAGE_SIZE / sizeof(*l2); i++ )
        l2[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
                 _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
}

unsigned long get_upper_mfn_bound(void)
{
    unsigned long max_mfn;

    max_mfn = mem_hotplug ? PFN_DOWN(mem_hotplug) : max_page;
#ifndef CONFIG_BIGMEM
    max_mfn = min(max_mfn, 1UL << 32);
#endif
    return min(max_mfn, 1UL << (paddr_bits - PAGE_SHIFT)) - 1;
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
