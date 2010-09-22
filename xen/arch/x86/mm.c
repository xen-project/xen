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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
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
#include <public/memory.h>
#include <public/sched.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <asm/setup.h>
#include <asm/fixmap.h>
#include <asm/mem_sharing.h>

/*
 * Mapping of first 2 or 4 megabytes of memory. This is mapped with 4kB
 * mappings to avoid type conflicts with fixed-range MTRRs covering the
 * lowest megabyte of physical memory. In any case the VGA hole should be
 * mapped with type UC.
 */
l1_pgentry_t __attribute__ ((__section__ (".bss.page_aligned")))
    l1_identmap[L1_PAGETABLE_ENTRIES];

#define MEM_LOG(_f, _a...) gdprintk(XENLOG_WARNING , _f "\n" , ## _a)

/*
 * PTE updates can be done with ordinary writes except:
 *  1. Debug builds get extra checking by using CMPXCHG[8B].
 *  2. PAE builds perform an atomic 8-byte store with CMPXCHG8B.
 */
#if !defined(NDEBUG) || defined(__i386__)
#define PTE_UPDATE_WITH_CMPXCHG
#endif

int mem_hotplug = 0;

/* Private domain structs for DOMID_XEN and DOMID_IO. */
struct domain *dom_xen, *dom_io, *dom_cow;

/* Frame table size in pages. */
unsigned long max_page;
unsigned long total_pages;

unsigned long __read_mostly pdx_group_valid[BITS_TO_LONGS(
    (FRAMETABLE_SIZE / sizeof(*frame_table) + PDX_GROUP_COUNT - 1)
    / PDX_GROUP_COUNT)] = { [0] = 1 };

#define PAGE_CACHE_ATTRS (_PAGE_PAT|_PAGE_PCD|_PAGE_PWT)

int opt_allow_superpage;
boolean_param("allowsuperpage", opt_allow_superpage);

#ifdef __i386__
static int get_superpage(unsigned long mfn, struct domain *d);
#endif
static void put_superpage(unsigned long mfn);

#define l1_disallow_mask(d)                                     \
    ((d != dom_io) &&                                           \
     (rangeset_is_empty((d)->iomem_caps) &&                     \
      rangeset_is_empty((d)->arch.ioport_caps) &&               \
      !has_arch_pdevs(d) &&                                     \
      !is_hvm_domain(d)) ?                                      \
     L1_DISALLOW_MASK : (L1_DISALLOW_MASK & ~PAGE_CACHE_ATTRS))

#ifdef __x86_64__
l2_pgentry_t *compat_idle_pg_table_l2 = NULL;
#define l3_disallow_mask(d) (!is_pv_32on64_domain(d) ?  \
                             L3_DISALLOW_MASK :         \
                             COMPAT_L3_DISALLOW_MASK)
#else
#define l3_disallow_mask(d) L3_DISALLOW_MASK
#endif

#ifdef __x86_64__
static void __init init_spagetable(void)
{
    unsigned long s, start = SPAGETABLE_VIRT_START;
    unsigned long end = SPAGETABLE_VIRT_END;
    unsigned long step, mfn;
    unsigned int max_entries;

    step = 1UL << PAGETABLE_ORDER;
    max_entries = (max_pdx + ((1UL<<SUPERPAGE_ORDER)-1)) >> SUPERPAGE_ORDER;
    end = start + (((max_entries * sizeof(*spage_table)) +
                    ((1UL<<SUPERPAGE_SHIFT)-1)) & (~((1UL<<SUPERPAGE_SHIFT)-1)));

    for (s = start; s < end; s += step << PAGE_SHIFT)
    {
        mfn = alloc_boot_pages(step, step);
        if ( !mfn )
            panic("Not enough memory for spage table");
        map_pages_to_xen(s, mfn, step, PAGE_HYPERVISOR);
    }
    memset((void *)start, 0, end - start);
}
#endif

static void __init init_frametable_chunk(void *start, void *end)
{
    unsigned long s = (unsigned long)start;
    unsigned long e = (unsigned long)end;
    unsigned long step, mfn;

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
        do {
            mfn = alloc_boot_pages(step, step);
        } while ( !mfn && (step >>= PAGETABLE_ORDER) );
        if ( !mfn )
            panic("Not enough memory for frame table");
        map_pages_to_xen(s, mfn, step, PAGE_HYPERVISOR);
    }

    memset(start, 0, end - start);
    memset(end, -1, s - (unsigned long)end);
}

void __init init_frametable(void)
{
    unsigned int sidx, eidx, nidx;
    unsigned int max_idx = (max_pdx + PDX_GROUP_COUNT - 1) / PDX_GROUP_COUNT;

#ifdef __x86_64__
    BUILD_BUG_ON(XEN_VIRT_END > FRAMETABLE_VIRT_END);
#endif
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
    if ( !mem_hotplug )
        init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT),
                              pdx_to_page(max_pdx - 1) + 1);
    else
    {
        init_frametable_chunk(pdx_to_page(sidx * PDX_GROUP_COUNT),
                              pdx_to_page(max_idx * PDX_GROUP_COUNT - 1) + 1);
        memset(pdx_to_page(max_pdx), -1,
               (unsigned long)pdx_to_page(max_idx * PDX_GROUP_COUNT) -
               (unsigned long)pdx_to_page(max_pdx));
    }
#ifdef __x86_64__
    if (opt_allow_superpage)
        init_spagetable();
#endif
}

void __init arch_init_memory(void)
{
    unsigned long i, pfn, rstart_pfn, rend_pfn, iostart_pfn, ioend_pfn;

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = domain_create(DOMID_XEN, DOMCRF_dummy, 0);
    BUG_ON(dom_xen == NULL);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create(DOMID_IO, DOMCRF_dummy, 0);
    BUG_ON(dom_io == NULL);
    
    /*
     * Initialise our DOMID_IO domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create(DOMID_COW, DOMCRF_dummy, 0);
    BUG_ON(dom_cow == NULL);

    /* First 1MB of RAM is historically marked as I/O. */
    for ( i = 0; i < 0x100; i++ )
        share_xen_page_with_guest(mfn_to_page(i), dom_io, XENSHARE_writable);
 
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
#if defined(CONFIG_X86_32)
        ioend_pfn = min_t(unsigned long, rstart_pfn,
                          DIRECTMAP_MBYTES << (20 - PAGE_SHIFT));
#else
        ioend_pfn = min(rstart_pfn, 16UL << (20 - PAGE_SHIFT));
#endif
        if ( iostart_pfn < ioend_pfn )            
            destroy_xen_mappings((unsigned long)mfn_to_virt(iostart_pfn),
                                 (unsigned long)mfn_to_virt(ioend_pfn));

        /* Mark as I/O up to next RAM region. */
        for ( ; pfn < rstart_pfn; pfn++ )
        {
            if ( !mfn_valid(pfn) )
                continue;
            share_xen_page_with_guest(
                mfn_to_page(pfn), dom_io, XENSHARE_writable);
        }

        /* Skip the RAM region. */
        pfn = rend_pfn;
    }

    subarch_init_memory();

    mem_sharing_init();
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
    return arch_get_max_pfn(d) - 1;
}

void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

    set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT((page->count_info & ~PGC_xen_heap) == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        page_list_add_tail(page, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

#if defined(__i386__)

#ifdef NDEBUG
/* Only PDPTs above 4GB boundary need to be shadowed in low memory. */
#define l3tab_needs_shadow(mfn) ((mfn) >= 0x100000)
#else
/*
 * In debug builds we shadow a selection of <4GB PDPTs to exercise code paths.
 * We cannot safely shadow the idle page table, nor shadow page tables
 * (detected by zero reference count). As required for correctness, we
 * always shadow PDPTs above 4GB.
 */
#define l3tab_needs_shadow(mfn)                          \
    (((((mfn) << PAGE_SHIFT) != __pa(idle_pg_table)) &&  \
      (mfn_to_page(mfn)->count_info & PGC_count_mask) && \
      ((mfn) & 1)) || /* odd MFNs are shadowed */        \
     ((mfn) >= 0x100000))
#endif

static l1_pgentry_t *fix_pae_highmem_pl1e;

/* Cache the address of PAE high-memory fixmap page tables. */
static int __init cache_pae_fixmap_address(void)
{
    unsigned long fixmap_base = fix_to_virt(FIX_PAE_HIGHMEM_0);
    l2_pgentry_t *pl2e = virt_to_xen_l2e(fixmap_base);
    fix_pae_highmem_pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(fixmap_base);
    return 0;
}
__initcall(cache_pae_fixmap_address);

static DEFINE_PER_CPU(u32, make_cr3_timestamp);

void make_cr3(struct vcpu *v, unsigned long mfn)
/* Takes the MFN of a PAE l3 table, copies the contents to below 4GB if
 * necessary, and sets v->arch.cr3 to the value to load in CR3. */
{
    l3_pgentry_t *highmem_l3tab, *lowmem_l3tab;
    struct pae_l3_cache *cache = &v->arch.pae_l3_cache;
    unsigned int cpu = smp_processor_id();

    /* Fast path: does this mfn need a shadow at all? */
    if ( !l3tab_needs_shadow(mfn) )
    {
        v->arch.cr3 = mfn << PAGE_SHIFT;
        /* Cache is no longer in use or valid */
        cache->high_mfn = 0;
        return;
    }

    /* Caching logic is not interrupt safe. */
    ASSERT(!in_irq());

    /* Protects against pae_flush_pgd(). */
    spin_lock(&cache->lock);

    cache->inuse_idx ^= 1;
    cache->high_mfn   = mfn;

    /* Map the guest L3 table and copy to the chosen low-memory cache. */
    l1e_write(fix_pae_highmem_pl1e-cpu, l1e_from_pfn(mfn, __PAGE_HYPERVISOR));
    /* First check the previous high mapping can't be in the TLB. 
     * (i.e. have we loaded CR3 since we last did this?) */
    if ( unlikely(this_cpu(make_cr3_timestamp) == this_cpu(tlbflush_time)) )
        flush_tlb_one_local(fix_to_virt(FIX_PAE_HIGHMEM_0 + cpu));
    highmem_l3tab = (l3_pgentry_t *)fix_to_virt(FIX_PAE_HIGHMEM_0 + cpu);
    lowmem_l3tab  = cache->table[cache->inuse_idx];
    memcpy(lowmem_l3tab, highmem_l3tab, sizeof(cache->table[0]));
    l1e_write(fix_pae_highmem_pl1e-cpu, l1e_empty());
    this_cpu(make_cr3_timestamp) = this_cpu(tlbflush_time);

    v->arch.cr3 = __pa(lowmem_l3tab);

    spin_unlock(&cache->lock);
}

#else /* !defined(__i386__) */

void make_cr3(struct vcpu *v, unsigned long mfn)
{
    v->arch.cr3 = mfn << PAGE_SHIFT;
}

#endif /* !defined(__i386__) */

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
    unsigned long cr3_mfn=0;

    if ( paging_mode_enabled(v->domain) )
    {
        paging_update_cr3(v);
        return;
    }

#if CONFIG_PAGING_LEVELS == 4
    if ( !(v->arch.flags & TF_kernel_mode) )
        cr3_mfn = pagetable_get_pfn(v->arch.guest_table_user);
    else
#endif
        cr3_mfn = pagetable_get_pfn(v->arch.guest_table);

    make_cr3(v, cr3_mfn);
}


static void invalidate_shadow_ldt(struct vcpu *v, int flush)
{
    int i;
    unsigned long pfn;
    struct page_info *page;

    BUG_ON(unlikely(in_irq()));

    spin_lock(&v->arch.shadow_ldt_lock);

    if ( v->arch.shadow_ldt_mapcnt == 0 )
        goto out;

    v->arch.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1e_get_pfn(v->arch.perdomain_ptes[i]);
        if ( pfn == 0 ) continue;
        l1e_write(&v->arch.perdomain_ptes[i], l1e_empty());
        page = mfn_to_page(pfn);
        ASSERT_PAGE_IS_TYPE(page, PGT_seg_desc_page);
        ASSERT_PAGE_IS_DOMAIN(page, v->domain);
        put_page_and_type(page);
    }

    /* Rid TLBs of stale mappings (guest mappings and shadow mappings). */
    if ( flush )
        flush_tlb_mask(&v->vcpu_dirty_cpumask);

 out:
    spin_unlock(&v->arch.shadow_ldt_lock);
}


static int alloc_segdesc_page(struct page_info *page)
{
    struct desc_struct *descs;
    int i;

    descs = __map_domain_page(page);

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(page_get_owner(page), &descs[i])) )
            goto fail;

    unmap_domain_page(descs);
    return 0;

 fail:
    unmap_domain_page(descs);
    return -EINVAL;
}


/* Map shadow page at offset @off. */
int map_ldt_shadow_page(unsigned int off)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long gmfn, mfn;
    l1_pgentry_t l1e, nl1e;
    unsigned long gva = v->arch.guest_context.ldt_base + (off << PAGE_SHIFT);
    int okay;

    BUG_ON(unlikely(in_irq()));

    guest_get_eff_kern_l1e(v, gva, &l1e);
    if ( unlikely(!(l1e_get_flags(l1e) & _PAGE_PRESENT)) )
        return 0;

    gmfn = l1e_get_pfn(l1e);
    mfn = gmfn_to_mfn(d, gmfn);
    if ( unlikely(!mfn_valid(mfn)) )
        return 0;

    okay = get_page_and_type(mfn_to_page(mfn), d, PGT_seg_desc_page);
    if ( unlikely(!okay) )
        return 0;

    nl1e = l1e_from_pfn(mfn, l1e_get_flags(l1e) | _PAGE_RW);

    spin_lock(&v->arch.shadow_ldt_lock);
    l1e_write(&v->arch.perdomain_ptes[off + 16], nl1e);
    v->arch.shadow_ldt_mapcnt++;
    spin_unlock(&v->arch.shadow_ldt_lock);

    return 1;
}


static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct page_info *page = mfn_to_page(page_nr);

    if ( unlikely(!mfn_valid(page_nr)) || unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %lx", page_nr);
        return 0;
    }

    return 1;
}


static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         unsigned long type,
                                         struct domain *d,
                                         int partial,
                                         int preemptible)
{
    struct page_info *page = mfn_to_page(page_nr);
    int rc;

    if ( likely(partial >= 0) &&
         unlikely(!get_page_from_pagenr(page_nr, d)) )
        return -EINVAL;

    rc = (preemptible ?
          get_page_type_preemptible(page, type) :
          (get_page_type(page, type) ? 0 : -EINVAL));

    if ( unlikely(rc) && partial >= 0 )
        put_page(page);

    return rc;
}

#ifdef __x86_64__
static void put_data_page(
    struct page_info *page, int writeable)
{
    if ( writeable )
        put_page_and_type(page);
    else
        put_page(page);
}
#endif

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
#define define_get_linear_pagetable(level)                                  \
static int                                                                  \
get_##level##_linear_pagetable(                                             \
    level##_pgentry_t pde, unsigned long pde_pfn, struct domain *d)         \
{                                                                           \
    unsigned long x, y;                                                     \
    struct page_info *page;                                                 \
    unsigned long pfn;                                                      \
                                                                            \
    if ( (level##e_get_flags(pde) & _PAGE_RW) )                             \
    {                                                                       \
        MEM_LOG("Attempt to create linear p.t. with write perms");          \
        return 0;                                                           \
    }                                                                       \
                                                                            \
    if ( (pfn = level##e_get_pfn(pde)) != pde_pfn )                         \
    {                                                                       \
        /* Make sure the mapped frame belongs to the correct domain. */     \
        if ( unlikely(!get_page_from_pagenr(pfn, d)) )                      \
            return 0;                                                       \
                                                                            \
        /*                                                                  \
         * Ensure that the mapped frame is an already-validated page table. \
         * If so, atomically increment the count (checking for overflow).   \
         */                                                                 \
        page = mfn_to_page(pfn);                                            \
        y = page->u.inuse.type_info;                                        \
        do {                                                                \
            x = y;                                                          \
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||        \
                 unlikely((x & (PGT_type_mask|PGT_validated)) !=            \
                          (PGT_##level##_page_table|PGT_validated)) )       \
            {                                                               \
                put_page(page);                                             \
                return 0;                                                   \
            }                                                               \
        }                                                                   \
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );   \
    }                                                                       \
                                                                            \
    return 1;                                                               \
}


int is_iomem_page(unsigned long mfn)
{
    struct page_info *page;

    if ( !mfn_valid(mfn) )
        return 1;

    /* Caller must know that it is an iomem page, or a reference is held. */
    page = mfn_to_page(mfn);
    ASSERT((page->count_info & PGC_count_mask) != 0);

    return (page_get_owner(page) == dom_io);
}

static void update_xen_mappings(unsigned long mfn, unsigned long cacheattr)
{
#ifdef __x86_64__
    bool_t alias = mfn >= PFN_DOWN(xen_phys_start) &&
         mfn < PFN_UP(xen_phys_start + (unsigned long)_end - XEN_VIRT_START);
    unsigned long xen_va =
        XEN_VIRT_START + ((mfn - PFN_DOWN(xen_phys_start)) << PAGE_SHIFT);

    if ( unlikely(alias) && cacheattr )
        map_pages_to_xen(xen_va, mfn, 1, 0);
    map_pages_to_xen((unsigned long)mfn_to_virt(mfn), mfn, 1,
                     PAGE_HYPERVISOR | cacheattr_to_pte_flags(cacheattr));
    if ( unlikely(alias) && !cacheattr )
        map_pages_to_xen(xen_va, mfn, 1, PAGE_HYPERVISOR);
#endif
}

int
get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *l1e_owner, struct domain *pg_owner)
{
    unsigned long mfn = l1e_get_pfn(l1e);
    struct page_info *page = mfn_to_page(mfn);
    uint32_t l1f = l1e_get_flags(l1e);
    struct vcpu *curr = current;
    struct domain *real_pg_owner;

    if ( !(l1f & _PAGE_PRESENT) )
        return 1;

    if ( unlikely(l1f & l1_disallow_mask(l1e_owner)) )
    {
        MEM_LOG("Bad L1 flags %x", l1f & l1_disallow_mask(l1e_owner));
        return 0;
    }

    if ( !mfn_valid(mfn) ||
         (real_pg_owner = page_get_owner_and_reference(page)) == dom_io )
    {
        /* Only needed the reference to confirm dom_io ownership. */
        if ( mfn_valid(mfn) )
            put_page(page);

        /* DOMID_IO reverts to caller for privilege checks. */
        if ( pg_owner == dom_io )
            pg_owner = curr->domain;

        if ( !iomem_access_permitted(pg_owner, mfn, mfn) )
        {
            if ( mfn != (PADDR_MASK >> PAGE_SHIFT) ) /* INVALID_MFN? */
                MEM_LOG("Non-privileged (%u) attempt to map I/O space %08lx", 
                        pg_owner->domain_id, mfn);
            return 0;
        }

        if ( !(l1f & _PAGE_RW) || IS_PRIV(pg_owner) ||
             !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
            return 1;
        dprintk(XENLOG_G_WARNING,
                "d%d: Forcing read-only access to MFN %lx\n",
                l1e_owner->domain_id, mfn);
        return -1;
    }

    if ( unlikely(real_pg_owner != pg_owner) )
    {
        /*
         * Let privileged domains transfer the right to map their target
         * domain's pages. This is used to allow stub-domain pvfb export to
         * dom0, until pvfb supports granted mappings. At that time this
         * minor hack can go away.
         */
        if ( (real_pg_owner == NULL) || (pg_owner == l1e_owner) ||
             !IS_PRIV_FOR(pg_owner, real_pg_owner) )
            goto could_not_pin;
        pg_owner = real_pg_owner;
    }

    /* Foreign mappings into guests in shadow external mode don't
     * contribute to writeable mapping refcounts.  (This allows the
     * qemu-dm helper process in dom0 to map the domain's memory without
     * messing up the count of "real" writable mappings.) */
    if ( (l1f & _PAGE_RW) &&
         ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner)) &&
         !get_page_type(page, PGT_writable_page) )
        goto could_not_pin;

    if ( pte_flags_to_cacheattr(l1f) !=
         ((page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base) )
    {
        unsigned long x, nx, y = page->count_info;
        unsigned long cacheattr = pte_flags_to_cacheattr(l1f);

        if ( is_xen_heap_page(page) )
        {
            if ( (l1f & _PAGE_RW) &&
                 ((l1e_owner == pg_owner) || !paging_mode_external(pg_owner)) )
                put_page_type(page);
            put_page(page);
            MEM_LOG("Attempt to change cache attributes of Xen heap page");
            return 0;
        }

        while ( ((y & PGC_cacheattr_mask) >> PGC_cacheattr_base) != cacheattr )
        {
            x  = y;
            nx = (x & ~PGC_cacheattr_mask) | (cacheattr << PGC_cacheattr_base);
            y  = cmpxchg(&page->count_info, x, nx);
        }

        update_xen_mappings(mfn, cacheattr);
    }

    return 1;

 could_not_pin:
    MEM_LOG("Error getting mfn %lx (pfn %lx) from L1 entry %" PRIpte
            " for l1e_owner=%d, pg_owner=%d",
            mfn, get_gpfn_from_mfn(mfn),
            l1e_get_intpte(l1e), l1e_owner->domain_id, pg_owner->domain_id);
    if ( real_pg_owner != NULL )
        put_page(page);
    return 0;
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
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
        MEM_LOG("Bad L2 flags %x", l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return -EINVAL;
    }

    if ( !(l2e_get_flags(l2e) & _PAGE_PSE) )
    {
        rc = get_page_and_type_from_pagenr(mfn, PGT_l1_page_table, d, 0, 0);
        if ( unlikely(rc == -EINVAL) && get_l2_linear_pagetable(l2e, pfn, d) )
            rc = 0;
        return rc;
    }

    if ( !opt_allow_superpage )
    {
        MEM_LOG("Attempt to map superpage without allowsuperpage "
                "flag in hypervisor");
        return -EINVAL;
    }

    if ( mfn & (L1_PAGETABLE_ENTRIES-1) )
    {
        MEM_LOG("Unaligned superpage map attempt mfn %lx", mfn);
        return -EINVAL;
    }

    return get_superpage(mfn, d);
}


define_get_linear_pagetable(l3);
static int
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn, struct domain *d, int partial, int preemptible)
{
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3e_get_flags(l3e) & l3_disallow_mask(d))) )
    {
        MEM_LOG("Bad L3 flags %x", l3e_get_flags(l3e) & l3_disallow_mask(d));
        return -EINVAL;
    }

    rc = get_page_and_type_from_pagenr(
        l3e_get_pfn(l3e), PGT_l2_page_table, d, partial, preemptible);
    if ( unlikely(rc == -EINVAL) && get_l3_linear_pagetable(l3e, pfn, d) )
        rc = 0;

    return rc;
}

#if CONFIG_PAGING_LEVELS >= 4
define_get_linear_pagetable(l4);
static int
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, struct domain *d, int partial, int preemptible)
{
    int rc;

    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L4 flags %x", l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return -EINVAL;
    }

    rc = get_page_and_type_from_pagenr(
        l4e_get_pfn(l4e), PGT_l3_page_table, d, partial, preemptible);
    if ( unlikely(rc == -EINVAL) && get_l4_linear_pagetable(l4e, pfn, d) )
        rc = 0;

    return rc;
}
#endif /* 4 level */

#ifdef __x86_64__

#ifdef USER_MAPPINGS_ARE_GLOBAL
#define adjust_guest_l1e(pl1e, d)                                            \
    do {                                                                     \
        if ( likely(l1e_get_flags((pl1e)) & _PAGE_PRESENT) &&                \
             likely(!is_pv_32on64_domain(d)) )                               \
        {                                                                    \
            /* _PAGE_GUEST_KERNEL page cannot have the Global bit set. */    \
            if ( (l1e_get_flags((pl1e)) & (_PAGE_GUEST_KERNEL|_PAGE_GLOBAL)) \
                 == (_PAGE_GUEST_KERNEL|_PAGE_GLOBAL) )                      \
                MEM_LOG("Global bit is set to kernel page %lx",              \
                        l1e_get_pfn((pl1e)));                                \
            if ( !(l1e_get_flags((pl1e)) & _PAGE_USER) )                     \
                l1e_add_flags((pl1e), (_PAGE_GUEST_KERNEL|_PAGE_USER));      \
            if ( !(l1e_get_flags((pl1e)) & _PAGE_GUEST_KERNEL) )             \
                l1e_add_flags((pl1e), (_PAGE_GLOBAL|_PAGE_USER));            \
        }                                                                    \
    } while ( 0 )
#else
#define adjust_guest_l1e(pl1e, d)                               \
    do {                                                        \
        if ( likely(l1e_get_flags((pl1e)) & _PAGE_PRESENT) &&   \
             likely(!is_pv_32on64_domain(d)) )                  \
            l1e_add_flags((pl1e), _PAGE_USER);                  \
    } while ( 0 )
#endif

#define adjust_guest_l2e(pl2e, d)                               \
    do {                                                        \
        if ( likely(l2e_get_flags((pl2e)) & _PAGE_PRESENT) &&   \
             likely(!is_pv_32on64_domain(d)) )                  \
            l2e_add_flags((pl2e), _PAGE_USER);                  \
    } while ( 0 )

#define adjust_guest_l3e(pl3e, d)                                   \
    do {                                                            \
        if ( likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )        \
            l3e_add_flags((pl3e), likely(!is_pv_32on64_domain(d)) ? \
                                         _PAGE_USER :               \
                                         _PAGE_USER|_PAGE_RW);      \
    } while ( 0 )

#define adjust_guest_l4e(pl4e, d)                               \
    do {                                                        \
        if ( likely(l4e_get_flags((pl4e)) & _PAGE_PRESENT) &&   \
             likely(!is_pv_32on64_domain(d)) )                  \
            l4e_add_flags((pl4e), _PAGE_USER);                  \
    } while ( 0 )

#else /* !defined(__x86_64__) */

#define adjust_guest_l1e(_p, _d) ((void)(_d))
#define adjust_guest_l2e(_p, _d) ((void)(_d))
#define adjust_guest_l3e(_p, _d) ((void)(_d))

#endif

#ifdef __x86_64__
#define unadjust_guest_l3e(pl3e, d)                                         \
    do {                                                                    \
        if ( unlikely(is_pv_32on64_domain(d)) &&                            \
             likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )                \
            l3e_remove_flags((pl3e), _PAGE_USER|_PAGE_RW|_PAGE_ACCESSED);   \
    } while ( 0 )
#else
#define unadjust_guest_l3e(_p, _d) ((void)(_d))
#endif

void put_page_from_l1e(l1_pgentry_t l1e, struct domain *l1e_owner)
{
    unsigned long     pfn = l1e_get_pfn(l1e);
    struct page_info *page;
    struct domain    *pg_owner;
    struct vcpu      *v;

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) || is_iomem_page(pfn) )
        return;

    page = mfn_to_page(pfn);
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
        MEM_LOG("Attempt to implicitly unmap a granted PTE %" PRIpte,
                l1e_get_intpte(l1e));
        domain_crash(l1e_owner);
    }

    /* Remember we didn't take a type-count of foreign writable mappings
     * to paging-external domains */
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
                invalidate_shadow_ldt(v, 1);
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
        put_superpage(l2e_get_pfn(l2e));
    else
        put_page_and_type(l2e_get_page(l2e));

    return 0;
}

static int __put_page_type(struct page_info *, int preemptible);

static int put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn,
                             int partial, int preemptible)
{
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) || (l3e_get_pfn(l3e) == pfn) )
        return 1;

#ifdef __x86_64__
    if ( unlikely(l3e_get_flags(l3e) & _PAGE_PSE) )
    {
        unsigned long mfn = l3e_get_pfn(l3e);
        int writeable = l3e_get_flags(l3e) & _PAGE_RW;

        ASSERT(!(mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)));
        do {
            put_data_page(mfn_to_page(mfn), writeable);
        } while ( ++mfn & ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1) );

        return 0;
    }
#endif

    if ( unlikely(partial > 0) )
        return __put_page_type(l3e_get_page(l3e), preemptible);

    return put_page_and_type_preemptible(l3e_get_page(l3e), preemptible);
}

#if CONFIG_PAGING_LEVELS >= 4
static int put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn,
                             int partial, int preemptible)
{
    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) && 
         (l4e_get_pfn(l4e) != pfn) )
    {
        if ( unlikely(partial > 0) )
            return __put_page_type(l4e_get_page(l4e), preemptible);
        return put_page_and_type_preemptible(l4e_get_page(l4e), preemptible);
    }
    return 1;
}
#endif

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l1_pgentry_t  *pl1e;
    unsigned int   i;

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        if ( is_guest_l1_slot(i) )
            switch ( get_page_from_l1e(pl1e[i], d, d) )
            {
            case 0:
                goto fail;
            case -1:
                l1e_remove_flags(pl1e[i], _PAGE_RW);
                break;
            }

        adjust_guest_l1e(pl1e[i], d);
    }

    unmap_domain_page(pl1e);
    return 0;

 fail:
    MEM_LOG("Failure in alloc_l1_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
    return -EINVAL;
}

static int create_pae_xen_mappings(struct domain *d, l3_pgentry_t *pl3e)
{
    struct page_info *page;
    l3_pgentry_t     l3e3;
#ifdef __i386__
    l2_pgentry_t     *pl2e, l2e;
    int              i;
#endif

    if ( !is_pv_32bit_domain(d) )
        return 1;

    pl3e = (l3_pgentry_t *)((unsigned long)pl3e & PAGE_MASK);

    /* 3rd L3 slot contains L2 with Xen-private mappings. It *must* exist. */
    l3e3 = pl3e[3];
    if ( !(l3e_get_flags(l3e3) & _PAGE_PRESENT) )
    {
        MEM_LOG("PAE L3 3rd slot is empty");
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
        MEM_LOG("PAE L3 3rd slot is shared");
        return 0;
    }

#ifdef __i386__
    /* Xen linear pagetable mappings. */
    pl2e = map_domain_page(l3e_get_pfn(l3e3));
    for ( i = 0; i < (LINEARPT_MBYTES >> (L2_PAGETABLE_SHIFT - 20)); i++ )
    {
        l2e = l2e_empty();
        if ( l3e_get_flags(pl3e[i]) & _PAGE_PRESENT )
            l2e = l2e_from_pfn(l3e_get_pfn(pl3e[i]), __PAGE_HYPERVISOR);
        l2e_write(&pl2e[l2_table_offset(LINEAR_PT_VIRT_START) + i], l2e);
    }
    unmap_domain_page(pl2e);
#endif

    return 1;
}

#ifdef __i386__
/* Flush a pgdir update into low-memory caches. */
static void pae_flush_pgd(
    unsigned long mfn, unsigned int idx, l3_pgentry_t nl3e)
{
    struct domain *d = page_get_owner(mfn_to_page(mfn));
    struct vcpu   *v;
    intpte_t       _ol3e, _nl3e, _pl3e;
    l3_pgentry_t  *l3tab_ptr;
    struct pae_l3_cache *cache;

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        cpumask_t m = CPU_MASK_NONE;
        /* Re-shadow this l3 table on any vcpus that are using it */
        for_each_vcpu ( d, v )
            if ( pagetable_get_pfn(v->arch.guest_table) == mfn )
            {
                paging_update_cr3(v);
                cpus_or(m, m, v->vcpu_dirty_cpumask);
            }
        flush_tlb_mask(&m);
    }

    /* If below 4GB then the pgdir is not shadowed in low memory. */
    if ( !l3tab_needs_shadow(mfn) )
        return;

    for_each_vcpu ( d, v )
    {
        cache = &v->arch.pae_l3_cache;

        spin_lock(&cache->lock);

        if ( cache->high_mfn == mfn )
        {
            l3tab_ptr = &cache->table[cache->inuse_idx][idx];
            _ol3e = l3e_get_intpte(*l3tab_ptr);
            _nl3e = l3e_get_intpte(nl3e);
            _pl3e = cmpxchg(&l3e_get_intpte(*l3tab_ptr), _ol3e, _nl3e);
            BUG_ON(_pl3e != _ol3e);
        }

        spin_unlock(&cache->lock);
    }

    flush_tlb_mask(&d->domain_dirty_cpumask);
}
#else
# define pae_flush_pgd(mfn, idx, nl3e) ((void)0)
#endif

static int alloc_l2_table(struct page_info *page, unsigned long type,
                          int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l2_pgentry_t  *pl2e;
    unsigned int   i;
    int            rc = 0;

    pl2e = map_domain_page(pfn);

    for ( i = page->nr_validated_ptes; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( preemptible && i && hypercall_preempt_check() )
        {
            page->nr_validated_ptes = i;
            rc = -EAGAIN;
            break;
        }

        if ( !is_guest_l2_slot(d, type, i) ||
             (rc = get_page_from_l2e(pl2e[i], pfn, d)) > 0 )
            continue;

        if ( rc < 0 )
        {
            MEM_LOG("Failure in alloc_l2_table: entry %d", i);
            while ( i-- > 0 )
                if ( is_guest_l2_slot(d, type, i) )
                    put_page_from_l2e(pl2e[i], pfn);
            break;
        }

        adjust_guest_l2e(pl2e[i], d);
    }

    if ( rc >= 0 && (type & PGT_pae_xen_l2) )
    {
        /* Xen private mappings. */
#if defined(__i386__)
        memcpy(&pl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
               &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
               L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));
        for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
            l2e_write(&pl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i],
                      l2e_from_page(perdomain_pt_page(d, i),
                                    __PAGE_HYPERVISOR));
        pl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
            l2e_from_pfn(pfn, __PAGE_HYPERVISOR);
#else
        memcpy(&pl2e[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
               &compat_idle_pg_table_l2[
                   l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
               COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*pl2e));
#endif
    }

    unmap_domain_page(pl2e);
    return rc > 0 ? 0 : rc;
}

static int alloc_l3_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l3_pgentry_t  *pl3e;
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

#if CONFIG_PAGING_LEVELS == 3
    /*
     * PAE pgdirs above 4GB are unacceptable if the guest does not understand
     * the weird 'extended cr3' format for dealing with high-order address
     * bits. We cut some slack for control tools (before vcpu0 is initialised).
     */
    if ( (pfn >= 0x100000) &&
         unlikely(!VM_ASSIST(d, VMASST_TYPE_pae_extended_cr3)) &&
         d->vcpu && d->vcpu[0] && d->vcpu[0]->is_initialised )
    {
        MEM_LOG("PAE pgd must be below 4GB (0x%lx >= 0x100000)", pfn);
        return -EINVAL;
    }
#endif

    pl3e = map_domain_page(pfn);

    /*
     * PAE guests allocate full pages, but aren't required to initialize
     * more than the first four entries; when running in compatibility
     * mode, however, the full page is visible to the MMU, and hence all
     * 512 entries must be valid/verified, which is most easily achieved
     * by clearing them out.
     */
    if ( is_pv_32on64_domain(d) )
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
                rc = get_page_and_type_from_pagenr(l3e_get_pfn(pl3e[i]),
                                                   PGT_l2_page_table |
                                                   PGT_pae_xen_l2,
                                                   d, partial, preemptible);
        }
        else if ( !is_guest_l3_slot(i) ||
                  (rc = get_page_from_l3e(pl3e[i], pfn, d,
                                          partial, preemptible)) > 0 )
            continue;

        if ( rc == -EAGAIN )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc == -EINTR && i )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = 0;
            rc = -EAGAIN;
        }
        if ( rc < 0 )
            break;

        adjust_guest_l3e(pl3e[i], d);
    }

    if ( rc >= 0 && !create_pae_xen_mappings(d, pl3e) )
        rc = -EINVAL;
    if ( rc < 0 && rc != -EAGAIN && rc != -EINTR )
    {
        MEM_LOG("Failure in alloc_l3_table: entry %d", i);
        while ( i-- > 0 )
        {
            if ( !is_guest_l3_slot(i) )
                continue;
            unadjust_guest_l3e(pl3e[i], d);
            put_page_from_l3e(pl3e[i], pfn, 0, 0);
        }
    }

    unmap_domain_page(pl3e);
    return rc > 0 ? 0 : rc;
}

#if CONFIG_PAGING_LEVELS >= 4
static int alloc_l4_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l4_pgentry_t  *pl4e = page_to_virt(page);
    unsigned int   i;
    int            rc = 0, partial = page->partial_pte;

    for ( i = page->nr_validated_ptes; i < L4_PAGETABLE_ENTRIES;
          i++, partial = 0 )
    {
        if ( !is_guest_l4_slot(d, i) ||
             (rc = get_page_from_l4e(pl4e[i], pfn, d,
                                     partial, preemptible)) > 0 )
            continue;

        if ( rc == -EAGAIN )
        {
            page->nr_validated_ptes = i;
            page->partial_pte = partial ?: 1;
        }
        else if ( rc == -EINTR )
        {
            if ( i )
            {
                page->nr_validated_ptes = i;
                page->partial_pte = 0;
                rc = -EAGAIN;
            }
        }
        else if ( rc < 0 )
        {
            MEM_LOG("Failure in alloc_l4_table: entry %d", i);
            while ( i-- > 0 )
                if ( is_guest_l4_slot(d, i) )
                    put_page_from_l4e(pl4e[i], pfn, 0, 0);
        }
        if ( rc < 0 )
            return rc;

        adjust_guest_l4e(pl4e[i], d);
    }

    /* Xen private mappings. */
    memcpy(&pl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));
    pl4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(pfn, __PAGE_HYPERVISOR);
    pl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_page(virt_to_page(d->arch.mm_perdomain_l3),
                      __PAGE_HYPERVISOR);

    return rc > 0 ? 0 : rc;
}
#else
#define alloc_l4_table(page, preemptible) (-EINVAL)
#endif


static void free_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l1_pgentry_t *pl1e;
    unsigned int  i;

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
}


static int free_l2_table(struct page_info *page, int preemptible)
{
#ifdef __x86_64__
    struct domain *d = page_get_owner(page);
#endif
    unsigned long pfn = page_to_mfn(page);
    l2_pgentry_t *pl2e;
    unsigned int  i = page->nr_validated_ptes - 1;
    int err = 0;

    pl2e = map_domain_page(pfn);

    ASSERT(page->nr_validated_ptes);
    do {
        if ( is_guest_l2_slot(d, page->u.inuse.type_info, i) &&
             put_page_from_l2e(pl2e[i], pfn) == 0 &&
             preemptible && i && hypercall_preempt_check() )
        {
           page->nr_validated_ptes = i;
           err = -EAGAIN;
        }
    } while ( !err && i-- );

    unmap_domain_page(pl2e);

    if ( !err )
        page->u.inuse.type_info &= ~PGT_pae_xen_l2;

    return err;
}

static int free_l3_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l3_pgentry_t *pl3e;
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    pl3e = map_domain_page(pfn);

    do {
        if ( is_guest_l3_slot(i) )
        {
            rc = put_page_from_l3e(pl3e[i], pfn, partial, preemptible);
            if ( rc < 0 )
                break;
            partial = 0;
            if ( rc > 0 )
                continue;
            unadjust_guest_l3e(pl3e[i], d);
        }
    } while ( i-- );

    unmap_domain_page(pl3e);

    if ( rc == -EAGAIN )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L3_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -EAGAIN;
    }
    return rc > 0 ? 0 : rc;
}

#if CONFIG_PAGING_LEVELS >= 4
static int free_l4_table(struct page_info *page, int preemptible)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l4_pgentry_t *pl4e = page_to_virt(page);
    int rc = 0, partial = page->partial_pte;
    unsigned int  i = page->nr_validated_ptes - !partial;

    do {
        if ( is_guest_l4_slot(d, i) )
            rc = put_page_from_l4e(pl4e[i], pfn, partial, preemptible);
        if ( rc < 0 )
            break;
        partial = 0;
    } while ( i-- );

    if ( rc == -EAGAIN )
    {
        page->nr_validated_ptes = i;
        page->partial_pte = partial ?: -1;
    }
    else if ( rc == -EINTR && i < L4_PAGETABLE_ENTRIES - 1 )
    {
        page->nr_validated_ptes = i + 1;
        page->partial_pte = 0;
        rc = -EAGAIN;
    }
    return rc > 0 ? 0 : rc;
}
#else
#define free_l4_table(page, preemptible) (-EINVAL)
#endif

static int page_lock(struct page_info *page)
{
    unsigned long x, nx;

    do {
        while ( (x = page->u.inuse.type_info) & PGT_locked )
            cpu_relax();
        nx = x + (1 | PGT_locked);
        if ( !(x & PGT_validated) ||
             !(x & PGT_count_mask) ||
             !(nx & PGT_count_mask) )
            return 0;
    } while ( cmpxchg(&page->u.inuse.type_info, x, nx) != x );

    return 1;
}

static void page_unlock(struct page_info *page)
{
    unsigned long x, nx, y = page->u.inuse.type_info;

    do {
        x = y;
        nx = x - (1 | PGT_locked);
    } while ( (y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x );
}

/* How to write an entry to the guest pagetables.
 * Returns 0 for failure (pointer not valid), 1 for success. */
static inline int update_intpte(intpte_t *p, 
                                intpte_t old, 
                                intpte_t new,
                                unsigned long mfn,
                                struct vcpu *v,
                                int preserve_ad)
{
    int rv = 1;
#ifndef PTE_UPDATE_WITH_CMPXCHG
    if ( !preserve_ad )
    {
        rv = paging_write_guest_entry(v, p, new, _mfn(mfn));
    }
    else
#endif
    {
        intpte_t t = old;
        for ( ; ; )
        {
            intpte_t _new = new;
            if ( preserve_ad )
                _new |= old & (_PAGE_ACCESSED | _PAGE_DIRTY);

            rv = paging_cmpxchg_guest_entry(v, p, &t, _new, _mfn(mfn));
            if ( unlikely(rv == 0) )
            {
                MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte
                        ": saw %" PRIpte, old, _new, t);
                break;
            }

            if ( t == old )
                break;

            /* Allowed to change in Accessed/Dirty flags only. */
            BUG_ON((t ^ old) & ~(intpte_t)(_PAGE_ACCESSED|_PAGE_DIRTY));

            old = t;
        }
    }
    return rv;
}

/* Macro that wraps the appropriate type-changes around update_intpte().
 * Arguments are: type, ptr, old, new, mfn, vcpu */
#define UPDATE_ENTRY(_t,_p,_o,_n,_m,_v,_ad)                         \
    update_intpte(&_t ## e_get_intpte(*(_p)),                       \
                  _t ## e_get_intpte(_o), _t ## e_get_intpte(_n),   \
                  (_m), (_v), (_ad))

/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e,
                        unsigned long gl1mfn, int preserve_ad,
                        struct vcpu *pt_vcpu, struct domain *pg_dom)
{
    l1_pgentry_t ol1e;
    struct domain *pt_dom = pt_vcpu->domain;
    unsigned long mfn;
    p2m_type_t p2mt;
    int rc = 1;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return 0;

    if ( unlikely(paging_mode_refcounts(pt_dom)) )
    {
        rc = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu, preserve_ad);
        return rc;
    }

    if ( l1e_get_flags(nl1e) & _PAGE_PRESENT )
    {
        /* Translate foreign guest addresses. */
        mfn = mfn_x(gfn_to_mfn(p2m_get_hostp2m(pg_dom),
            l1e_get_pfn(nl1e), &p2mt));
        if ( !p2m_is_ram(p2mt) || unlikely(mfn == INVALID_MFN) )
            return 0;
        ASSERT((mfn & ~(PADDR_MASK >> PAGE_SHIFT)) == 0);
        nl1e = l1e_from_pfn(mfn, l1e_get_flags(nl1e));

        if ( unlikely(l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom)) )
        {
            MEM_LOG("Bad L1 flags %x",
                    l1e_get_flags(nl1e) & l1_disallow_mask(pt_dom));
            return 0;
        }

        /* Fast path for identical mapping, r/w and presence. */
        if ( !l1e_has_changed(ol1e, nl1e, _PAGE_RW | _PAGE_PRESENT) )
        {
            adjust_guest_l1e(nl1e, pt_dom);
            rc = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                              preserve_ad);
            return rc;
        }

        switch ( get_page_from_l1e(nl1e, pt_dom, pg_dom) )
        {
        case 0:
            return 0;
        case -1:
            l1e_remove_flags(nl1e, _PAGE_RW);
            break;
        }
        
        adjust_guest_l1e(nl1e, pt_dom);
        if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                    preserve_ad)) )
        {
            ol1e = nl1e;
            rc = 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, pt_vcpu,
                                     preserve_ad)) )
    {
        return 0;
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
    struct page_info *l2pg = mfn_to_page(pfn);
    unsigned long type = l2pg->u.inuse.type_info;
    int rc = 1;

    if ( unlikely(!is_guest_l2_slot(d, type, pgentry_ptr_to_slot(pl2e))) )
    {
        MEM_LOG("Illegal L2 update attempt in Xen-private area %p", pl2e);
        return 0;
    }

    if ( unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0) )
        return 0;

    if ( l2e_get_flags(nl2e) & _PAGE_PRESENT )
    {
        if ( unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L2 flags %x",
                    l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l2e_has_changed(ol2e, nl2e, _PAGE_PRESENT) )
        {
            adjust_guest_l2e(nl2e, d);
            rc = UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu, preserve_ad);
            return rc;
        }

        if ( unlikely(get_page_from_l2e(nl2e, pfn, d) < 0) )
            return 0;

        adjust_guest_l2e(nl2e, d);
        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                    preserve_ad)) )
        {
            ol2e = nl2e;
            rc = 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, vcpu,
                                     preserve_ad)) )
    {
        return 0;
    }

    put_page_from_l2e(ol2e, pfn);
    return rc;
}

/* Update the L3 entry at pl3e to new value nl3e. pl3e is within frame pfn. */
static int mod_l3_entry(l3_pgentry_t *pl3e, 
                        l3_pgentry_t nl3e, 
                        unsigned long pfn,
                        int preserve_ad,
                        int preemptible,
                        struct vcpu *vcpu)
{
    l3_pgentry_t ol3e;
    struct domain *d = vcpu->domain;
    int rc = 0;

    if ( unlikely(!is_guest_l3_slot(pgentry_ptr_to_slot(pl3e))) )
    {
        MEM_LOG("Illegal L3 update attempt in Xen-private area %p", pl3e);
        return -EINVAL;
    }

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
            MEM_LOG("Bad L3 flags %x",
                    l3e_get_flags(nl3e) & l3_disallow_mask(d));
            return -EINVAL;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l3e_has_changed(ol3e, nl3e, _PAGE_PRESENT) )
        {
            adjust_guest_l3e(nl3e, d);
            rc = UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l3e(nl3e, pfn, d, 0, preemptible);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        adjust_guest_l3e(nl3e, d);
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
    {
        if ( !create_pae_xen_mappings(d, pl3e) )
            BUG();

        pae_flush_pgd(pfn, pgentry_ptr_to_slot(pl3e), nl3e);
    }

    put_page_from_l3e(ol3e, pfn, 0, 0);
    return rc;
}

#if CONFIG_PAGING_LEVELS >= 4

/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e, 
                        l4_pgentry_t nl4e, 
                        unsigned long pfn,
                        int preserve_ad,
                        int preemptible,
                        struct vcpu *vcpu)
{
    struct domain *d = vcpu->domain;
    l4_pgentry_t ol4e;
    int rc = 0;

    if ( unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e))) )
    {
        MEM_LOG("Illegal L4 update attempt in Xen-private area %p", pl4e);
        return -EINVAL;
    }

    if ( unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0) )
        return -EFAULT;

    if ( l4e_get_flags(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L4 flags %x",
                    l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return -EINVAL;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l4e_has_changed(ol4e, nl4e, _PAGE_PRESENT) )
        {
            adjust_guest_l4e(nl4e, d);
            rc = UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, vcpu, preserve_ad);
            return rc ? 0 : -EFAULT;
        }

        rc = get_page_from_l4e(nl4e, pfn, d, 0, preemptible);
        if ( unlikely(rc < 0) )
            return rc;
        rc = 0;

        adjust_guest_l4e(nl4e, d);
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

    put_page_from_l4e(ol4e, pfn, 0, 0);
    return rc;
}

#endif

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
        cleanup_page_cacheattr(page);
        free_domheap_page(page);
    }
}


struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;

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

    return page_get_owner(page);
}


int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( owner != NULL )
        put_page(page);

    if ( !_shadow_mode_refcounts(domain) && !domain->is_dying )
        gdprintk(XENLOG_INFO,
                 "Error pfn %lx: rd=%p, od=%p, caf=%08lx, taf=%"
                 PRtype_info "\n",
                 page_to_mfn(page), domain, owner,
                 page->count_info, page->u.inuse.type_info);
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
        rc = alloc_l3_table(page, preemptible);
        break;
    case PGT_l4_page_table:
        rc = alloc_l4_table(page, preemptible);
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
    wmb();
    if ( rc == -EAGAIN )
    {
        get_page_light(page);
        page->u.inuse.type_info |= PGT_partial;
    }
    else if ( rc == -EINTR )
    {
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        page->u.inuse.type_info &= ~PGT_count_mask;
    }
    else if ( rc )
    {
        ASSERT(rc < 0);
        MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %"
                PRtype_info ": caf=%08lx taf=%" PRtype_info,
                page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)),
                type, page->count_info, page->u.inuse.type_info);
        page->u.inuse.type_info = 0;
    }
    else
    {
        page->u.inuse.type_info |= PGT_validated;
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

        if ( shadow_mode_refcounts(owner) )
            return 0;

        gmfn = mfn_to_gmfn(owner, page_to_mfn(page));
        ASSERT(VALID_M2P(gmfn));
        /* Page sharing not supported for shadowed domains */
        if(!SHARED_M2P(gmfn))
            shadow_remove_all_shadows(owner->vcpu[0], _mfn(gmfn));
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
#if CONFIG_PAGING_LEVELS == 3
        if ( !(type & PGT_partial) )
            page->nr_validated_ptes = L3_PAGETABLE_ENTRIES;
#endif
        rc = free_l3_table(page, preemptible);
        break;
    case PGT_l4_page_table:
        rc = free_l4_table(page, preemptible);
        break;
    default:
        MEM_LOG("type %lx pfn %lx\n", type, page_to_mfn(page));
        rc = -EINVAL;
        BUG();
    }

    return rc;
}


static int __put_final_page_type(
    struct page_info *page, unsigned long type, int preemptible)
{
    int rc = free_page_type(page, type, preemptible);

    /* No need for atomic update of type_info here: noone else updates it. */
    if ( rc == 0 )
    {
        /*
         * Record TLB information for flush later. We do not stamp page tables
         * when running in shadow mode:
         *  1. Pointless, since it's the shadow pt's which must be tracked.
         *  2. Shadow mode reuses this field for shadowed page tables to
         *     store flags info -- we don't want to conflict with that.
         */
        if ( !(shadow_mode_enabled(page_get_owner(page)) &&
               (page->count_info & PGC_page_table)) )
            page->tlbflush_timestamp = tlbflush_current_time();
        wmb();
        page->u.inuse.type_info--;
    }
    else if ( rc == -EINTR )
    {
        ASSERT((page->u.inuse.type_info &
                (PGT_count_mask|PGT_validated|PGT_partial)) == 1);
        if ( !(shadow_mode_enabled(page_get_owner(page)) &&
               (page->count_info & PGC_page_table)) )
            page->tlbflush_timestamp = tlbflush_current_time();
        wmb();
        page->u.inuse.type_info |= PGT_validated;
    }
    else
    {
        BUG_ON(rc != -EAGAIN);
        wmb();
        get_page_light(page);
        page->u.inuse.type_info |= PGT_partial;
    }

    return rc;
}


static int __put_page_type(struct page_info *page,
                           int preemptible)
{
    unsigned long nx, x, y = page->u.inuse.type_info;
    int rc = 0;

    for ( ; ; )
    {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & (PGT_validated|PGT_partial)) )
            {
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
                rc = __put_final_page_type(page, x, preemptible);
                if ( x & PGT_partial )
                    put_page(page);
                break;
            }

            /*
             * Record TLB information for flush later. We do not stamp page
             * tables when running in shadow mode:
             *  1. Pointless, since it's the shadow pt's which must be tracked.
             *  2. Shadow mode reuses this field for shadowed page tables to
             *     store flags info -- we don't want to conflict with that.
             */
            if ( !(shadow_mode_enabled(page_get_owner(page)) &&
                   (page->count_info & PGC_page_table)) )
                page->tlbflush_timestamp = tlbflush_current_time();
        }

        if ( likely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) == x) )
            break;

        if ( preemptible && hypercall_preempt_check() )
            return -EINTR;
    }

    return rc;
}


static int __get_page_type(struct page_info *page, unsigned long type,
                           int preemptible)
{
    unsigned long nx, x, y = page->u.inuse.type_info;
    int rc = 0;

    ASSERT(!(type & ~(PGT_type_mask | PGT_pae_xen_l2)));

    for ( ; ; )
    {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_mfn(page));
            return -EINVAL;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            struct domain *d = page_get_owner(page);

            /* Normally we should never let a page go from type count 0
             * to type count 1 when it is shadowed. One exception:
             * out-of-sync shadowed pages are allowed to become
             * writeable. */
            if ( d && shadow_mode_enabled(d)
                 && (page->count_info & PGC_page_table)
                 && !((page->shadow_flags & (1u<<29))
                      && type == PGT_writable_page) )
               shadow_remove_all_shadows(d->vcpu[0], _mfn(page_to_mfn(page)));

            ASSERT(!(x & PGT_pae_xen_l2));
            if ( (x & PGT_type_mask) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. This 
                 * may be unnecessary (e.g., page was GDT/LDT) but those 
                 * circumstances should be very rare.
                 */
                cpumask_t mask = d->domain_dirty_cpumask;

                /* Don't flush if the timestamp is old enough */
                tlbflush_filter(mask, page->tlbflush_timestamp);

                if ( unlikely(!cpus_empty(mask)) &&
                     /* Shadow mode: track only writable pages. */
                     (!shadow_mode_enabled(page_get_owner(page)) ||
                      ((nx & PGT_type_mask) == PGT_writable_page)) )
                {
                    perfc_incr(need_flush_tlb_flush);
                    flush_tlb_mask(&mask);
                }

                /* We lose existing type and validity. */
                nx &= ~(PGT_type_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
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
            MEM_LOG("Bad type (saw %" PRtype_info " != exp %" PRtype_info ") "
                    "for mfn %lx (pfn %lx)",
                    x, type, page_to_mfn(page),
                    get_gpfn_from_mfn(page_to_mfn(page)));
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
        if ( d && !is_hvm_domain(d) && unlikely(need_iommu(d)) )
        {
            if ( (x & PGT_type_mask) == PGT_writable_page )
                iommu_unmap_page(d, mfn_to_gmfn(d, page_to_mfn(page)));
            else if ( type == PGT_writable_page )
                iommu_map_page(d, mfn_to_gmfn(d, page_to_mfn(page)),
                               page_to_mfn(page),
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
        rc = alloc_page_type(page, type, preemptible);
    }

    if ( (x & PGT_partial) && !(nx & PGT_partial) )
        put_page(page);

    return rc;
}

void put_page_type(struct page_info *page)
{
    int rc = __put_page_type(page, 0);
    ASSERT(rc == 0);
    (void)rc;
}

int get_page_type(struct page_info *page, unsigned long type)
{
    int rc = __get_page_type(page, type, 0);
    if ( likely(rc == 0) )
        return 1;
    ASSERT(rc == -EINVAL);
    return 0;
}

int put_page_type_preemptible(struct page_info *page)
{
    return __put_page_type(page, 1);
}

int get_page_type_preemptible(struct page_info *page, unsigned long type)
{
    return __get_page_type(page, type, 1);
}

static int get_spage_pages(struct page_info *page, struct domain *d)
{
    int i;

    for (i = 0; i < (1<<PAGETABLE_ORDER); i++, page++)
    {
        if (!get_page_and_type(page, d, PGT_writable_page))
        {
            while (--i >= 0)
                put_page_and_type(--page);
            return 0;
        }
    }
    return 1;
}

static void put_spage_pages(struct page_info *page)
{
    int i;

    for (i = 0; i < (1<<PAGETABLE_ORDER); i++, page++)
    {
        put_page_and_type(page);
    }
    return;
}

#ifdef __x86_64__

static int mark_superpage(struct spage_info *spage, struct domain *d)
{
    unsigned long x, nx, y = spage->type_info;
    int pages_done = 0;

    ASSERT(opt_allow_superpage);

    do {
        x = y;
        nx = x + 1;
        if ( (x & SGT_type_mask) == SGT_mark )
        {
            MEM_LOG("Duplicate superpage mark attempt mfn %lx",
                    spage_to_mfn(spage));
            if ( pages_done )
                put_spage_pages(spage_to_page(spage));
            return -EINVAL;
        }
        if ( (x & SGT_type_mask) == SGT_dynamic )
        {
            if ( pages_done )
            {
                put_spage_pages(spage_to_page(spage));
                pages_done = 0;
            }
        }
        else if ( !pages_done )
        {
            if ( !get_spage_pages(spage_to_page(spage), d) )
            {
                MEM_LOG("Superpage type conflict in mark attempt mfn %lx",
                        spage_to_mfn(spage));
                return -EINVAL;
            }
            pages_done = 1;
        }
        nx = (nx & ~SGT_type_mask) | SGT_mark;

    } while ( (y = cmpxchg(&spage->type_info, x, nx)) != x );

    return 0;
}

static int unmark_superpage(struct spage_info *spage)
{
    unsigned long x, nx, y = spage->type_info;
    unsigned long do_pages = 0;

    ASSERT(opt_allow_superpage);

    do {
        x = y;
        nx = x - 1;
        if ( (x & SGT_type_mask) != SGT_mark )
        {
            MEM_LOG("Attempt to unmark unmarked superpage mfn %lx",
                    spage_to_mfn(spage));
            return -EINVAL;
        }
        if ( (nx & SGT_count_mask) == 0 )
        {
            nx = (nx & ~SGT_type_mask) | SGT_none;
            do_pages = 1;
        }
        else
        {
            nx = (nx & ~SGT_type_mask) | SGT_dynamic;
        }
    } while ( (y = cmpxchg(&spage->type_info, x, nx)) != x );

    if ( do_pages )
        put_spage_pages(spage_to_page(spage));

    return 0;
}

void clear_superpage_mark(struct page_info *page)
{
    struct spage_info *spage;

    if ( !opt_allow_superpage )
        return;

    spage = page_to_spage(page);
    if ((spage->type_info & SGT_type_mask) == SGT_mark)
        unmark_superpage(spage);

}

int get_superpage(unsigned long mfn, struct domain *d)
{
    struct spage_info *spage;
    unsigned long x, nx, y;
    int pages_done = 0;

    ASSERT(opt_allow_superpage);

    spage = mfn_to_spage(mfn);
    y = spage->type_info;
    do {
        x = y;
        nx = x + 1;
        if ( (x & SGT_type_mask) != SGT_none )
        {
            if ( pages_done )
            {
                put_spage_pages(spage_to_page(spage));
                pages_done = 0;
            }
        }
        else
        {
            if ( !get_spage_pages(spage_to_page(spage), d) )
            {
                MEM_LOG("Type conflict on superpage mapping mfn %lx",
                        spage_to_mfn(spage));
                return -EINVAL;
            }
            pages_done = 1;
            nx = (nx & ~SGT_type_mask) | SGT_dynamic;
        }
    } while ( (y = cmpxchg(&spage->type_info, x, nx)) != x );

    return 0;
}

static void put_superpage(unsigned long mfn)
{
    struct spage_info *spage;
    unsigned long x, nx, y;
    unsigned long do_pages = 0;

    if ( !opt_allow_superpage )
    {
        put_spage_pages(mfn_to_page(mfn));
        return;
    }

    spage = mfn_to_spage(mfn);
    y = spage->type_info;
    do {
        x = y;
        nx = x - 1;
        if ((x & SGT_type_mask) == SGT_dynamic)
        {
            if ((nx & SGT_count_mask) == 0)
            {
                nx = (nx & ~SGT_type_mask) | SGT_none;
                do_pages = 1;
            }
        }

    } while ((y = cmpxchg(&spage->type_info, x, nx)) != x);

    if (do_pages)
        put_spage_pages(spage_to_page(spage));

    return;
}

#else /* __i386__ */

void clear_superpage_mark(struct page_info *page)
{
}

static int get_superpage(unsigned long mfn, struct domain *d)
{
    return get_spage_pages(mfn_to_page(mfn), d);
}

static void put_superpage(unsigned long mfn)
{
    put_spage_pages(mfn_to_page(mfn));
}

#endif

void cleanup_page_cacheattr(struct page_info *page)
{
    uint32_t cacheattr =
        (page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base;

    if ( likely(cacheattr == 0) )
        return;

    page->count_info &= ~PGC_cacheattr_mask;

    BUG_ON(is_xen_heap_page(page));

    update_xen_mappings(page_to_mfn(page), 0);
}


int new_guest_cr3(unsigned long mfn)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    int okay;
    unsigned long old_base_mfn;

#ifdef __x86_64__
    if ( is_pv_32on64_domain(d) )
    {
        okay = paging_mode_refcounts(d)
            ? 0 /* Old code was broken, but what should it be? */
            : mod_l4_entry(
                    __va(pagetable_get_paddr(curr->arch.guest_table)),
                    l4e_from_pfn(
                        mfn,
                        (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED)),
                    pagetable_get_pfn(curr->arch.guest_table), 0, 0, curr) == 0;
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while installing new compat baseptr %lx", mfn);
            return 0;
        }

        invalidate_shadow_ldt(curr, 0);
        write_ptbase(curr);

        return 1;
    }
#endif
    okay = paging_mode_refcounts(d)
        ? get_page_from_pagenr(mfn, d)
        : !get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d, 0, 0);
    if ( unlikely(!okay) )
    {
        MEM_LOG("Error while installing new baseptr %lx", mfn);
        return 0;
    }

    invalidate_shadow_ldt(curr, 0);

    old_base_mfn = pagetable_get_pfn(curr->arch.guest_table);

    curr->arch.guest_table = pagetable_from_pfn(mfn);
    update_cr3(curr);

    write_ptbase(curr);

    if ( likely(old_base_mfn != 0) )
    {
        if ( paging_mode_refcounts(d) )
            put_page(mfn_to_page(old_base_mfn));
        else
            put_page_and_type(mfn_to_page(old_base_mfn));
    }

    return 1;
}

static struct domain *get_pg_owner(domid_t domid)
{
    struct domain *pg_owner = NULL, *curr = current->domain;

    if ( likely(domid == DOMID_SELF) )
    {
        pg_owner = rcu_lock_domain(curr);
        goto out;
    }

    if ( unlikely(domid == curr->domain_id) )
    {
        MEM_LOG("Cannot specify itself as foreign domain");
        goto out;
    }

    if ( unlikely(paging_mode_translate(curr)) )
    {
        MEM_LOG("Cannot mix foreign mappings with translated domains");
        goto out;
    }

    switch ( domid )
    {
    case DOMID_IO:
        pg_owner = rcu_lock_domain(dom_io);
        break;
    case DOMID_XEN:
        if ( !IS_PRIV(curr) )
        {
            MEM_LOG("Cannot set foreign dom");
            break;
        }
        pg_owner = rcu_lock_domain(dom_xen);
        break;
    default:
        if ( (pg_owner = rcu_lock_domain_by_id(domid)) == NULL )
        {
            MEM_LOG("Unknown domain '%u'", domid);
            break;
        }
        if ( !IS_PRIV_FOR(curr, pg_owner) )
        {
            MEM_LOG("Cannot set foreign dom");
            rcu_unlock_domain(pg_owner);
            pg_owner = NULL;
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
    struct domain *d, XEN_GUEST_HANDLE(const_void) bmap, cpumask_t *pmask)
{
    unsigned int vcpu_id, vcpu_bias, offs;
    unsigned long vmask;
    struct vcpu *v;
    bool_t is_native = !is_pv_32on64_domain(d);

    cpus_clear(*pmask);
    for ( vmask = 0, offs = 0; ; ++offs)
    {
        vcpu_bias = offs * (is_native ? BITS_PER_LONG : 32);
        if ( vcpu_bias >= d->max_vcpus )
            return 0;

        if ( unlikely(is_native ?
                      copy_from_guest_offset(&vmask, bmap, offs, 1) :
                      copy_from_guest_offset((unsigned int *)&vmask, bmap,
                                             offs, 1)) )
        {
            cpus_clear(*pmask);
            return -EFAULT;
        }

        while ( vmask )
        {
            vcpu_id = find_first_set_bit(vmask);
            vmask &= ~(1UL << vcpu_id);
            vcpu_id += vcpu_bias;
            if ( (vcpu_id >= d->max_vcpus) )
                return 0;
            if ( ((v = d->vcpu[vcpu_id]) != NULL) )
                cpus_or(*pmask, *pmask, v->vcpu_dirty_cpumask);
        }
    }
}

#ifdef __i386__
static inline void *fixmap_domain_page(unsigned long mfn)
{
    unsigned int cpu = smp_processor_id();
    void *ptr = (void *)fix_to_virt(FIX_PAE_HIGHMEM_0 + cpu);

    l1e_write(fix_pae_highmem_pl1e - cpu,
              l1e_from_pfn(mfn, __PAGE_HYPERVISOR));
    flush_tlb_one_local(ptr);
    return ptr;
}
static inline void fixunmap_domain_page(const void *ptr)
{
    unsigned int cpu = virt_to_fix((unsigned long)ptr) - FIX_PAE_HIGHMEM_0;

    l1e_write(fix_pae_highmem_pl1e - cpu, l1e_empty());
    this_cpu(make_cr3_timestamp) = this_cpu(tlbflush_time);
}
#else
#define fixmap_domain_page(mfn) mfn_to_virt(mfn)
#define fixunmap_domain_page(ptr) ((void)(ptr))
#endif

int do_mmuext_op(
    XEN_GUEST_HANDLE(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom)
{
    struct mmuext_op op;
    int rc = 0, i = 0, okay;
    unsigned long type;
    unsigned int done = 0;
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    struct domain *pg_owner;

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmuext_op);

    if ( unlikely(!guest_handle_okay(uops, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

    if ( (pg_owner = get_pg_owner(foreigndom)) == NULL )
    {
        rc = -ESRCH;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = -EAGAIN;
            break;
        }

        if ( unlikely(__copy_from_guest(&op, uops, 1) != 0) )
        {
            MEM_LOG("Bad __copy_from_guest");
            rc = -EFAULT;
            break;
        }

        okay = 1;

        switch ( op.cmd )
        {
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

        pin_page: {
            unsigned long mfn;
            struct page_info *page;

            /* Ignore pinning of invalid paging levels. */
            if ( (op.cmd - MMUEXT_PIN_L1_TABLE) > (CONFIG_PAGING_LEVELS - 1) )
                break;

            if ( paging_mode_refcounts(pg_owner) )
                break;

            mfn = gmfn_to_mfn(pg_owner, op.arg1.mfn);
            rc = get_page_and_type_from_pagenr(mfn, type, pg_owner, 0, 1);
            okay = !rc;
            if ( unlikely(!okay) )
            {
                if ( rc == -EINTR )
                    rc = -EAGAIN;
                else if ( rc != -EAGAIN )
                    MEM_LOG("Error while pinning mfn %lx", mfn);
                break;
            }

            page = mfn_to_page(mfn);

            if ( (rc = xsm_memory_pin_page(d, page)) != 0 )
            {
                put_page_and_type(page);
                okay = 0;
                break;
            }

            if ( unlikely(test_and_set_bit(_PGT_pinned,
                                           &page->u.inuse.type_info)) )
            {
                MEM_LOG("Mfn %lx already pinned", mfn);
                put_page_and_type(page);
                okay = 0;
                break;
            }

            /* A page is dirtied when its pin status is set. */
            paging_mark_dirty(pg_owner, mfn);
           
            /* We can race domain destruction (domain_relinquish_resources). */
            if ( unlikely(pg_owner != d) )
            {
                int drop_ref;
                spin_lock(&pg_owner->page_alloc_lock);
                drop_ref = (pg_owner->is_dying &&
                            test_and_clear_bit(_PGT_pinned,
                                               &page->u.inuse.type_info));
                spin_unlock(&pg_owner->page_alloc_lock);
                if ( drop_ref )
                    put_page_and_type(page);
            }

            break;
        }

        case MMUEXT_UNPIN_TABLE: {
            unsigned long mfn;
            struct page_info *page;

            if ( paging_mode_refcounts(pg_owner) )
                break;

            mfn = gmfn_to_mfn(pg_owner, op.arg1.mfn);
            if ( unlikely(!(okay = get_page_from_pagenr(mfn, pg_owner))) )
            {
                MEM_LOG("Mfn %lx bad domain", mfn);
                break;
            }

            page = mfn_to_page(mfn);

            if ( !test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            {
                okay = 0;
                put_page(page);
                MEM_LOG("Mfn %lx not pinned", mfn);
                break;
            }

            put_page_and_type(page);
            put_page(page);

            /* A page is dirtied when its pin status is cleared. */
            paging_mark_dirty(pg_owner, mfn);

            break;
        }

        case MMUEXT_NEW_BASEPTR:
            okay = new_guest_cr3(gmfn_to_mfn(d, op.arg1.mfn));
            break;
        
#ifdef __x86_64__
        case MMUEXT_NEW_USER_BASEPTR: {
            unsigned long old_mfn, mfn;

            mfn = gmfn_to_mfn(d, op.arg1.mfn);
            if ( mfn != 0 )
            {
                if ( paging_mode_refcounts(d) )
                    okay = get_page_from_pagenr(mfn, d);
                else
                    okay = !get_page_and_type_from_pagenr(
                        mfn, PGT_root_page_table, d, 0, 0);
                if ( unlikely(!okay) )
                {
                    MEM_LOG("Error while installing new mfn %lx", mfn);
                    break;
                }
            }

            old_mfn = pagetable_get_pfn(curr->arch.guest_table_user);
            curr->arch.guest_table_user = pagetable_from_pfn(mfn);

            if ( old_mfn != 0 )
            {
                if ( paging_mode_refcounts(d) )
                    put_page(mfn_to_page(old_mfn));
                else
                    put_page_and_type(mfn_to_page(old_mfn));
            }

            break;
        }
#endif
        
        case MMUEXT_TLB_FLUSH_LOCAL:
            flush_tlb_local();
            break;
    
        case MMUEXT_INVLPG_LOCAL:
            if ( !paging_mode_enabled(d) 
                 || paging_invlpg(curr, op.arg1.linear_addr) != 0 )
                flush_tlb_one_local(op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            cpumask_t pmask;

            if ( unlikely(vcpumask_to_pcpumask(d, op.arg2.vcpumask, &pmask)) )
            {
                okay = 0;
                break;
            }
            if ( op.cmd == MMUEXT_TLB_FLUSH_MULTI )
                flush_tlb_mask(&pmask);
            else
                flush_tlb_one_mask(&pmask, op.arg1.linear_addr);
            break;
        }

        case MMUEXT_TLB_FLUSH_ALL:
            flush_tlb_mask(&d->domain_dirty_cpumask);
            break;
    
        case MMUEXT_INVLPG_ALL:
            flush_tlb_one_mask(&d->domain_dirty_cpumask, op.arg1.linear_addr);
            break;

        case MMUEXT_FLUSH_CACHE:
            if ( unlikely(!cache_flush_permitted(d)) )
            {
                MEM_LOG("Non-physdev domain tried to FLUSH_CACHE.");
                okay = 0;
            }
            else
            {
                wbinvd();
            }
            break;

        case MMUEXT_FLUSH_CACHE_GLOBAL:
            if ( unlikely(foreigndom != DOMID_SELF) )
                okay = 0;
            else if ( likely(cache_flush_permitted(d)) )
            {
                unsigned int cpu;
                cpumask_t mask = CPU_MASK_NONE;

                for_each_online_cpu(cpu)
                    if ( !cpus_intersects(mask,
                                          per_cpu(cpu_sibling_map, cpu)) )
                        cpu_set(cpu, mask);
                flush_mask(&mask, FLUSH_CACHE);
            }
            else
            {
                MEM_LOG("Non-physdev domain tried to FLUSH_CACHE_GLOBAL");
                okay = 0;
            }
            break;

        case MMUEXT_SET_LDT:
        {
            unsigned long ptr  = op.arg1.linear_addr;
            unsigned long ents = op.arg2.nr_ents;

            if ( paging_mode_external(d) )
            {
                MEM_LOG("ignoring SET_LDT hypercall from external domain");
                okay = 0;
            }
            else if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
                      (ents > 8192) ||
                      !array_access_ok(ptr, ents, LDT_ENTRY_SIZE) )
            {
                okay = 0;
                MEM_LOG("Bad args to SET_LDT: ptr=%lx, ents=%lx", ptr, ents);
            }
            else if ( (curr->arch.guest_context.ldt_ents != ents) || 
                      (curr->arch.guest_context.ldt_base != ptr) )
            {
                invalidate_shadow_ldt(curr, 0);
                flush_tlb_local();
                curr->arch.guest_context.ldt_base = ptr;
                curr->arch.guest_context.ldt_ents = ents;
                load_LDT(curr);
                if ( ents != 0 )
                    (void)map_ldt_shadow_page(0);
            }
            break;
        }

        case MMUEXT_CLEAR_PAGE: {
            unsigned long mfn;
            unsigned char *ptr;

            mfn = gmfn_to_mfn(d, op.arg1.mfn);
            okay = !get_page_and_type_from_pagenr(
                mfn, PGT_writable_page, d, 0, 0);
            if ( unlikely(!okay) )
            {
                MEM_LOG("Error while clearing mfn %lx", mfn);
                break;
            }

            /* A page is dirtied when it's being cleared. */
            paging_mark_dirty(d, mfn);

            ptr = fixmap_domain_page(mfn);
            clear_page(ptr);
            fixunmap_domain_page(ptr);

            put_page_and_type(mfn_to_page(mfn));
            break;
        }

        case MMUEXT_COPY_PAGE:
        {
            const unsigned char *src;
            unsigned char *dst;
            unsigned long src_mfn, mfn;

            src_mfn = gmfn_to_mfn(d, op.arg2.src_mfn);
            okay = get_page_from_pagenr(src_mfn, d);
            if ( unlikely(!okay) )
            {
                MEM_LOG("Error while copying from mfn %lx", src_mfn);
                break;
            }

            mfn = gmfn_to_mfn(d, op.arg1.mfn);
            okay = !get_page_and_type_from_pagenr(
                mfn, PGT_writable_page, d, 0, 0);
            if ( unlikely(!okay) )
            {
                put_page(mfn_to_page(src_mfn));
                MEM_LOG("Error while copying to mfn %lx", mfn);
                break;
            }

            /* A page is dirtied when it's being copied to. */
            paging_mark_dirty(d, mfn);

            src = map_domain_page(src_mfn);
            dst = fixmap_domain_page(mfn);
            copy_page(dst, src);
            fixunmap_domain_page(dst);
            unmap_domain_page(src);

            put_page_and_type(mfn_to_page(mfn));
            put_page(mfn_to_page(src_mfn));
            break;
        }

#ifdef __x86_64__
        case MMUEXT_MARK_SUPER:
        {
            unsigned long mfn;
            struct spage_info *spage;

            mfn = op.arg1.mfn;
            if ( mfn & (L1_PAGETABLE_ENTRIES-1) )
            {
                MEM_LOG("Unaligned superpage reference mfn %lx", mfn);
                okay = 0;
                break;
            }

            if ( !opt_allow_superpage )
            {
                MEM_LOG("Superpages disallowed");
                okay = 0;
                rc = -ENOSYS;
                break;
            }

            spage = mfn_to_spage(mfn);
            okay = (mark_superpage(spage, d) >= 0);
            break;
        }

        case MMUEXT_UNMARK_SUPER:
        {
            unsigned long mfn;
            struct spage_info *spage;

            mfn = op.arg1.mfn;
            if ( mfn & (L1_PAGETABLE_ENTRIES-1) )
            {
                MEM_LOG("Unaligned superpage reference mfn %lx", mfn);
                okay = 0;
                break;
            }

            if ( !opt_allow_superpage )
            {
                MEM_LOG("Superpages disallowed");
                okay = 0;
                rc = -ENOSYS;
                break;
            }

            spage = mfn_to_spage(mfn);
            okay = (unmark_superpage(spage) >= 0);
            break;
        }
#endif

        default:
            MEM_LOG("Invalid extended pt command 0x%x", op.cmd);
            rc = -ENOSYS;
            okay = 0;
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = rc ? rc : -EINVAL;
            break;
        }

        guest_handle_add_offset(uops, 1);
    }

    if ( rc == -EAGAIN )
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmuext_op, "hihi",
            uops, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);

    put_pg_owner(pg_owner);

    perfc_add(num_mmuext_ops, i);

 out:
    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}

int do_mmu_update(
    XEN_GUEST_HANDLE(mmu_update_t) ureqs,
    unsigned int count,
    XEN_GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom)
{
    struct mmu_update req;
    void *va;
    unsigned long gpfn, gmfn, mfn;
    struct page_info *page;
    int rc = 0, okay = 1, i = 0;
    unsigned int cmd, done = 0, pt_dom;
    struct vcpu *v = current;
    struct domain *d = v->domain, *pt_owner = d, *pg_owner;
    struct domain_mmap_cache mapcache;

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }
    else
        perfc_incr(calls_to_mmu_update);

    if ( unlikely(!guest_handle_okay(ureqs, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

    if ( (pt_dom = foreigndom >> 16) != 0 )
    {
        /* Pagetables belong to a foreign domain (PFD). */
        if ( (pt_owner = rcu_lock_domain_by_id(pt_dom - 1)) == NULL )
        {
            rc = -EINVAL;
            goto out;
        }
        if ( pt_owner == d )
            rcu_unlock_domain(pt_owner);
        if ( (v = pt_owner->vcpu ? pt_owner->vcpu[0] : NULL) == NULL )
        {
            rc = -EINVAL;
            goto out;
        }
        if ( !IS_PRIV_FOR(d, pt_owner) )
        {
            rc = -ESRCH;
            goto out;
        }
    }

    if ( (pg_owner = get_pg_owner((uint16_t)foreigndom)) == NULL )
    {
        rc = -ESRCH;
        goto out;
    }

    domain_mmap_cache_init(&mapcache);

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = -EAGAIN;
            break;
        }

        if ( unlikely(__copy_from_guest(&req, ureqs, 1) != 0) )
        {
            MEM_LOG("Bad __copy_from_guest");
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);
        okay = 0;

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

            rc = xsm_mmu_normal_update(d, pg_owner, req.val);
            if ( rc )
                break;

            req.ptr -= cmd;
            gmfn = req.ptr >> PAGE_SHIFT;
            mfn = mfn_x(gfn_to_mfn(p2m_get_hostp2m(pt_owner), gmfn, &p2mt));
            if ( !p2m_is_valid(p2mt) )
              mfn = INVALID_MFN;

            if ( p2m_is_paged(p2mt) )
            {
                p2m_mem_paging_populate(p2m_get_hostp2m(pg_owner), gmfn);

                rc = -ENOENT;
                break;
            }

            if ( unlikely(!get_page_from_pagenr(mfn, pt_owner)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            va = map_domain_page_with_cache(mfn, &mapcache);
            va = (void *)((unsigned long)va +
                          (unsigned long)(req.ptr & ~PAGE_MASK));
            page = mfn_to_page(mfn);

            if ( page_lock(page) )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                {
                    l1_pgentry_t l1e = l1e_from_intpte(req.val);
                    p2m_type_t l1e_p2mt;
                    gfn_to_mfn(p2m_get_hostp2m(pg_owner),
                        l1e_get_pfn(l1e), &l1e_p2mt);

                    if ( p2m_is_paged(l1e_p2mt) )
                    {
                        p2m_mem_paging_populate(p2m_get_hostp2m(pg_owner),
                            l1e_get_pfn(l1e));
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_paging_in_start == l1e_p2mt )
                    {
                        rc = -ENOENT;
                        break;
                    }
#ifdef __x86_64__
                    /* XXX: Ugly: pull all the checks into a separate function. 
                     * Don't want to do it now, not to interfere with mem_paging
                     * patches */
                    else if ( p2m_ram_shared == l1e_p2mt )
                    {
                        /* Unshare the page for RW foreign mappings */
                        if ( l1e_get_flags(l1e) & _PAGE_RW )
                        {
                            rc = mem_sharing_unshare_page(p2m_get_hostp2m(pg_owner), 
                                                          l1e_get_pfn(l1e), 
                                                          0);
                            if ( rc )
                                break; 
                        }
                    } 
#endif

                    okay = mod_l1_entry(va, l1e, mfn,
                                        cmd == MMU_PT_UPDATE_PRESERVE_AD, v,
                                        pg_owner);
                }
                break;
                case PGT_l2_page_table:
                {
                    l2_pgentry_t l2e = l2e_from_intpte(req.val);
                    p2m_type_t l2e_p2mt;
                    gfn_to_mfn(p2m_get_hostp2m(pg_owner), l2e_get_pfn(l2e), &l2e_p2mt);

                    if ( p2m_is_paged(l2e_p2mt) )
                    {
                        p2m_mem_paging_populate(p2m_get_hostp2m(pg_owner),
                            l2e_get_pfn(l2e));
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_paging_in_start == l2e_p2mt )
                    {
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_shared == l2e_p2mt )
                    {
                        MEM_LOG("Unexpected attempt to map shared page.\n");
                        rc = -EINVAL;
                        break;
                    }


                    okay = mod_l2_entry(va, l2e, mfn,
                                        cmd == MMU_PT_UPDATE_PRESERVE_AD, v);
                }
                break;
                case PGT_l3_page_table:
                {
                    l3_pgentry_t l3e = l3e_from_intpte(req.val);
                    p2m_type_t l3e_p2mt;
                    gfn_to_mfn(p2m_get_hostp2m(pg_owner), l3e_get_pfn(l3e), &l3e_p2mt);

                    if ( p2m_is_paged(l3e_p2mt) )
                    {
                        p2m_mem_paging_populate(p2m_get_hostp2m(pg_owner),
                            l3e_get_pfn(l3e));
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_paging_in_start == l3e_p2mt )
                    {
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_shared == l3e_p2mt )
                    {
                        MEM_LOG("Unexpected attempt to map shared page.\n");
                        rc = -EINVAL;
                        break;
                    }

                    rc = mod_l3_entry(va, l3e, mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, 1, v);
                    okay = !rc;
                }
                break;
#if CONFIG_PAGING_LEVELS >= 4
                case PGT_l4_page_table:
                {
                    l4_pgentry_t l4e = l4e_from_intpte(req.val);
                    p2m_type_t l4e_p2mt;
                    gfn_to_mfn(p2m_get_hostp2m(pg_owner),
                        l4e_get_pfn(l4e), &l4e_p2mt);

                    if ( p2m_is_paged(l4e_p2mt) )
                    {
                        p2m_mem_paging_populate(p2m_get_hostp2m(pg_owner),
                            l4e_get_pfn(l4e));
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_paging_in_start == l4e_p2mt )
                    {
                        rc = -ENOENT;
                        break;
                    }
                    else if ( p2m_ram_shared == l4e_p2mt )
                    {
                        MEM_LOG("Unexpected attempt to map shared page.\n");
                        rc = -EINVAL;
                        break;
                    }

                    rc = mod_l4_entry(va, l4e, mfn,
                                      cmd == MMU_PT_UPDATE_PRESERVE_AD, 1, v);
                    okay = !rc;
                }
                break;
#endif
                case PGT_writable_page:
                    perfc_incr(writable_mmu_updates);
                    okay = paging_write_guest_entry(
                        v, va, req.val, _mfn(mfn));
                    break;
                }
                page_unlock(page);
                if ( rc == -EINTR )
                    rc = -EAGAIN;
            }
            else if ( get_page_type(page, PGT_writable_page) )
            {
                perfc_incr(writable_mmu_updates);
                okay = paging_write_guest_entry(
                    v, va, req.val, _mfn(mfn));
                put_page_type(page);
            }

            unmap_domain_page_with_cache(va, &mapcache);
            put_page(page);
        }
        break;

        case MMU_MACHPHYS_UPDATE:

            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            rc = xsm_mmu_machphys_update(d, mfn);
            if ( rc )
                break;

            if ( unlikely(!get_page_from_pagenr(mfn, pg_owner)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            if ( unlikely(paging_mode_translate(pg_owner)) )
            {
                MEM_LOG("Mach-phys update on auto-translate guest");
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);
            okay = 1;

            paging_mark_dirty(pg_owner, mfn);

            put_page(mfn_to_page(mfn));
            break;

        default:
            MEM_LOG("Invalid page update command %x", cmd);
            rc = -ENOSYS;
            okay = 0;
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = rc ? rc : -EINVAL;
            break;
        }

        guest_handle_add_offset(ureqs, 1);
    }

    if ( rc == -EAGAIN )
        rc = hypercall_create_continuation(
            __HYPERVISOR_mmu_update, "hihi",
            ureqs, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);

    put_pg_owner(pg_owner);

    domain_mmap_cache_destroy(&mapcache);

    perfc_add(num_page_updates, i);

 out:
    if ( pt_owner && (pt_owner != d) )
        rcu_unlock_domain(pt_owner);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(!guest_handle_is_null(pdone)) )
    {
        done += i;
        copy_to_guest(pdone, &done, 1);
    }

    return rc;
}


static int create_grant_pte_mapping(
    uint64_t pte_addr, l1_pgentry_t nl1e, struct vcpu *v)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    l1_pgentry_t ol1e;
    struct domain *d = v->domain;

    ASSERT(domain_is_locked(d));

    adjust_guest_l1e(nl1e, d);

    gmfn = pte_addr >> PAGE_SHIFT;
    mfn = gmfn_to_mfn(d, gmfn);

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + ((unsigned long)pte_addr & ~PAGE_MASK));
    page = mfn_to_page(mfn);

    if ( !page_lock(page) )
    {
        rc = GNTST_general_error;
        goto failed;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    }

    ol1e = *(l1_pgentry_t *)va;
    if ( !UPDATE_ENTRY(l1, (l1_pgentry_t *)va, ol1e, nl1e, mfn, v, 0) )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    } 

    page_unlock(page);

    if ( !paging_mode_refcounts(d) )
        put_page_from_l1e(ol1e, d);

 failed:
    unmap_domain_page(va);
    put_page(page);

    return rc;
}

static int destroy_grant_pte_mapping(
    uint64_t addr, unsigned long frame, struct domain *d)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    l1_pgentry_t ol1e;

    gmfn = addr >> PAGE_SHIFT;
    mfn = gmfn_to_mfn(d, gmfn);

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + ((unsigned long)addr & ~PAGE_MASK));
    page = mfn_to_page(mfn);

    if ( !page_lock(page) )
    {
        rc = GNTST_general_error;
        goto failed;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        rc = GNTST_general_error;
        goto failed;
    }

    ol1e = *(l1_pgentry_t *)va;
    
    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        page_unlock(page);
        MEM_LOG("PTE entry %lx for address %"PRIx64" doesn't match frame %lx",
                (unsigned long)l1e_get_intpte(ol1e), addr, frame);
        rc = GNTST_general_error;
        goto failed;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY
                  (l1, 
                   (l1_pgentry_t *)va, ol1e, l1e_empty(), mfn, 
                   d->vcpu[0] /* Change if we go to per-vcpu shadows. */,
                   0)) )
    {
        page_unlock(page);
        MEM_LOG("Cannot delete PTE entry at %p", va);
        rc = GNTST_general_error;
        goto failed;
    }

    page_unlock(page);

 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}


static int create_grant_va_mapping(
    unsigned long va, l1_pgentry_t nl1e, struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    struct domain *d = v->domain;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int okay;
    
    ASSERT(domain_is_locked(d));

    adjust_guest_l1e(nl1e, d);

    pl1e = guest_map_l1e(v, va, &gl1mfn);
    if ( !pl1e )
    {
        MEM_LOG("Could not find L1 PTE for address %lx", va);
        return GNTST_general_error;
    }

    if ( !get_page_from_pagenr(gl1mfn, current->domain) )
    {
        guest_unmap_l1e(v, pl1e);
        return GNTST_general_error;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        put_page(l1pg);
        guest_unmap_l1e(v, pl1e);
        return GNTST_general_error;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        guest_unmap_l1e(v, pl1e);
        return GNTST_general_error;
    }

    ol1e = *pl1e;
    okay = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, v, 0);

    page_unlock(l1pg);
    put_page(l1pg);
    guest_unmap_l1e(v, pl1e);

    if ( okay && !paging_mode_refcounts(d) )
        put_page_from_l1e(ol1e, d);

    return okay ? GNTST_okay : GNTST_general_error;
}

static int replace_grant_va_mapping(
    unsigned long addr, unsigned long frame, l1_pgentry_t nl1e, struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int rc = 0;
    
    pl1e = guest_map_l1e(v, addr, &gl1mfn);
    if ( !pl1e )
    {
        MEM_LOG("Could not find L1 PTE for address %lx", addr);
        return GNTST_general_error;
    }

    if ( !get_page_from_pagenr(gl1mfn, current->domain) )
    {
        rc = GNTST_general_error;
        goto out;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        rc = GNTST_general_error;
        put_page(l1pg);
        goto out;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

    ol1e = *pl1e;

    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                l1e_get_pfn(ol1e), addr, frame);
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, v, 0)) )
    {
        MEM_LOG("Cannot delete PTE entry at %p", (unsigned long *)pl1e);
        rc = GNTST_general_error;
        goto unlock_and_out;
    }

 unlock_and_out:
    page_unlock(l1pg);
    put_page(l1pg);
 out:
    guest_unmap_l1e(v, pl1e);
    return rc;
}

static int destroy_grant_va_mapping(
    unsigned long addr, unsigned long frame, struct vcpu *v)
{
    return replace_grant_va_mapping(addr, frame, l1e_empty(), v);
}

static int create_grant_p2m_mapping(uint64_t addr, unsigned long frame,
                                    unsigned int flags,
                                    unsigned int cache_flags)
{
    p2m_type_t p2mt;
    int rc;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        p2mt = p2m_grant_map_ro;
    else
        p2mt = p2m_grant_map_rw;
    rc = guest_physmap_add_entry(p2m_get_hostp2m(current->domain),
                                 addr >> PAGE_SHIFT, frame, 0, p2mt);
    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int create_grant_host_mapping(uint64_t addr, unsigned long frame, 
                              unsigned int flags, unsigned int cache_flags)
{
    l1_pgentry_t pte;

    if ( paging_mode_external(current->domain) )
        return create_grant_p2m_mapping(addr, frame, flags, cache_flags);

    pte = l1e_from_pfn(frame, GRANT_PTE_FLAGS);
    if ( (flags & GNTMAP_application_map) )
        l1e_add_flags(pte,_PAGE_USER);
    if ( !(flags & GNTMAP_readonly) )
        l1e_add_flags(pte,_PAGE_RW);

    l1e_add_flags(pte,
                  ((flags >> _GNTMAP_guest_avail0) * _PAGE_AVAIL0)
                   & _PAGE_AVAIL);

    l1e_add_flags(pte, cacheattr_to_pte_flags(cache_flags >> 5));

    if ( flags & GNTMAP_contains_pte )
        return create_grant_pte_mapping(addr, pte, current);
    return create_grant_va_mapping(addr, pte, current);
}

static int replace_grant_p2m_mapping(
    uint64_t addr, unsigned long frame, uint64_t new_addr, unsigned int flags)
{
    unsigned long gfn = (unsigned long)(addr >> PAGE_SHIFT);
    p2m_type_t type;
    mfn_t old_mfn;
    struct domain *d = current->domain;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    old_mfn = gfn_to_mfn(p2m_get_hostp2m(d), gfn, &type);
    if ( !p2m_is_grant(type) || mfn_x(old_mfn) != frame )
    {
        gdprintk(XENLOG_WARNING,
                 "replace_grant_p2m_mapping: old mapping invalid (type %d, mfn %lx, frame %lx)\n",
                 type, mfn_x(old_mfn), frame);
        return GNTST_general_error;
    }
    guest_physmap_remove_page(d, gfn, frame, 0);

    return GNTST_okay;
}

int replace_grant_host_mapping(
    uint64_t addr, unsigned long frame, uint64_t new_addr, unsigned int flags)
{
    struct vcpu *curr = current;
    l1_pgentry_t *pl1e, ol1e;
    unsigned long gl1mfn;
    struct page_info *l1pg;
    int rc;
    
    if ( paging_mode_external(current->domain) )
        return replace_grant_p2m_mapping(addr, frame, new_addr, flags);

    if ( flags & GNTMAP_contains_pte )
    {
        if ( !new_addr )
            return destroy_grant_pte_mapping(addr, frame, curr->domain);
        
        MEM_LOG("Unsupported grant table operation");
        return GNTST_general_error;
    }

    if ( !new_addr )
        return destroy_grant_va_mapping(addr, frame, curr);

    pl1e = guest_map_l1e(curr, new_addr, &gl1mfn);
    if ( !pl1e )
    {
        MEM_LOG("Could not find L1 PTE for address %lx",
                (unsigned long)new_addr);
        return GNTST_general_error;
    }

    if ( !get_page_from_pagenr(gl1mfn, current->domain) )
    {
        guest_unmap_l1e(curr, pl1e);
        return GNTST_general_error;
    }

    l1pg = mfn_to_page(gl1mfn);
    if ( !page_lock(l1pg) )
    {
        put_page(l1pg);
        guest_unmap_l1e(curr, pl1e);
        return GNTST_general_error;
    }

    if ( (l1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        guest_unmap_l1e(curr, pl1e);
        return GNTST_general_error;
    }

    ol1e = *pl1e;

    if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, l1e_empty(),
                                gl1mfn, curr, 0)) )
    {
        page_unlock(l1pg);
        put_page(l1pg);
        MEM_LOG("Cannot delete PTE entry at %p", (unsigned long *)pl1e);
        guest_unmap_l1e(curr, pl1e);
        return GNTST_general_error;
    }

    page_unlock(l1pg);
    put_page(l1pg);
    guest_unmap_l1e(curr, pl1e);

    rc = replace_grant_va_mapping(addr, frame, ol1e, curr);
    if ( rc && !paging_mode_refcounts(curr->domain) )
        put_page_from_l1e(ol1e, curr->domain);

    return rc;
}

int donate_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    spin_lock(&d->page_alloc_lock);

    if ( is_xen_heap_page(page) || (page_get_owner(page) != NULL) )
        goto fail;

    if ( d->is_dying )
        goto fail;

    if ( page->count_info & ~(PGC_allocated | 1) )
        goto fail;

    if ( !(memflags & MEMF_no_refcount) )
    {
        if ( d->tot_pages >= d->max_pages )
            goto fail;
        d->tot_pages++;
    }

    page->count_info = PGC_allocated | 1;
    page_set_owner(page, d);
    page_list_add_tail(page,&d->page_list);

    spin_unlock(&d->page_alloc_lock);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    MEM_LOG("Bad donate %p: ed=%p(%u), sd=%p, caf=%08lx, taf=%" PRtype_info,
            (void *)page_to_mfn(page), d, d->domain_id,
            page_get_owner(page), page->count_info, page->u.inuse.type_info);
    return -1;
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    unsigned long x, y;
    bool_t drop_dom_ref = 0;

    spin_lock(&d->page_alloc_lock);

    if ( is_xen_heap_page(page) || (page_get_owner(page) != d) )
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

    /* Swizzle the owner then reinstate the PGC_allocated reference. */
    page_set_owner(page, NULL);
    y = page->count_info;
    do {
        x = y;
        BUG_ON((x & (PGC_count_mask|PGC_allocated)) != PGC_allocated);
    } while ( (y = cmpxchg(&page->count_info, x, x | 1)) != x );

    /* Unlink from original owner. */
    if ( !(memflags & MEMF_no_refcount) && !--d->tot_pages )
        drop_dom_ref = 1;
    page_list_del(page, &d->page_list);

    spin_unlock(&d->page_alloc_lock);
    if ( unlikely(drop_dom_ref) )
        put_domain(d);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    MEM_LOG("Bad page %p: ed=%p(%u), sd=%p, caf=%08lx, taf=%" PRtype_info,
            (void *)page_to_mfn(page), d, d->domain_id,
            page_get_owner(page), page->count_info, page->u.inuse.type_info);
    return -1;
}

int page_make_sharable(struct domain *d, 
                       struct page_info *page, 
                       int expected_refcnt)
{
    unsigned long x, nx, y;

    /* Acquire ref first, so that the page doesn't dissapear from us */
    if(!get_page(page, d))
        return -EINVAL;

    spin_lock(&d->page_alloc_lock);

    /* Change page type and count atomically */
    y = page->u.inuse.type_info;
    nx = PGT_shared_page | PGT_validated | 1; 
    do {
        x = y;
        /* We can only change the type if count is zero, and 
           type is PGT_none */
        if((x & (PGT_type_mask | PGT_count_mask)) != PGT_none)
        {
            put_page(page);
            spin_unlock(&d->page_alloc_lock);
            return -EEXIST;
        }
        y = cmpxchg(&page->u.inuse.type_info, x, nx);
    } while(x != y);

    /* Check if the ref count is 2. The first from PGT_allocated, and the second
     * from get_page at the top of this function */
    if(page->count_info != (PGC_allocated | (2 + expected_refcnt)))
    {
        /* Return type count back to zero */
        put_page_and_type(page);
        spin_unlock(&d->page_alloc_lock);
        return -E2BIG;
    }

    page_set_owner(page, dom_cow);
    d->tot_pages--;
    page_list_del(page, &d->page_list);
    spin_unlock(&d->page_alloc_lock);

    /* NOTE: We are not putting the page back. In effect this function acquires
     * one ref and type ref for the caller */

    return 0;
}

int page_make_private(struct domain *d, struct page_info *page)
{
    unsigned long x, y;

    if(!get_page(page, dom_cow))
        return -EINVAL;
    
    spin_lock(&d->page_alloc_lock);

    /* Change page type and count atomically */
    y = page->u.inuse.type_info;
    do {
        x = y;
        /* We can only change the type if count is one */
        if((x & (PGT_type_mask | PGT_count_mask)) != 
                (PGT_shared_page | 1))
        {
            put_page(page);
            spin_unlock(&d->page_alloc_lock);
            return -EEXIST;
        }
        y = cmpxchg(&page->u.inuse.type_info, x, PGT_none);
    } while(x != y);

    /* We dropped type ref above, drop one ref count too */
    put_page(page);

    /* Change the owner */
    ASSERT(page_get_owner(page) == dom_cow);
    page_set_owner(page, d);

    d->tot_pages++;
    page_list_add_tail(page, &d->page_list);
    spin_unlock(&d->page_alloc_lock);

    put_page(page);

    return 0;
}

static int __do_update_va_mapping(
    unsigned long va, u64 val64, unsigned long flags, struct domain *pg_owner)
{
    l1_pgentry_t   val = l1e_from_intpte(val64);
    struct vcpu   *v   = current;
    struct domain *d   = v->domain;
    struct page_info *gl1pg;
    l1_pgentry_t  *pl1e;
    unsigned long  bmap_ptr, gl1mfn;
    cpumask_t      pmask;
    int            rc;

    perfc_incr(calls_to_update_va);

    rc = xsm_update_va_mapping(d, pg_owner, val);
    if ( rc )
        return rc;

    rc = -EINVAL;
    pl1e = guest_map_l1e(v, va, &gl1mfn);
    if ( unlikely(!pl1e || !get_page_from_pagenr(gl1mfn, d)) )
        goto out;

    gl1pg = mfn_to_page(gl1mfn);
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

    rc = mod_l1_entry(pl1e, val, gl1mfn, 0, v, pg_owner) ? 0 : -EINVAL;

    page_unlock(gl1pg);
    put_page(gl1pg);

 out:
    if ( pl1e )
        guest_unmap_l1e(v, pl1e);

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            flush_tlb_local();
            break;
        case UVMF_ALL:
            flush_tlb_mask(&d->domain_dirty_cpumask);
            break;
        default:
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
                                      &pmask);
            flush_tlb_mask(&pmask);
            break;
        }
        break;

    case UVMF_INVLPG:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            if ( !paging_mode_enabled(d) ||
                 (paging_invlpg(v, va) != 0) ) 
                flush_tlb_one_local(va);
            break;
        case UVMF_ALL:
            flush_tlb_one_mask(&d->domain_dirty_cpumask, va);
            break;
        default:
            rc = vcpumask_to_pcpumask(d, const_guest_handle_from_ptr(bmap_ptr,
                                                                     void),
                                      &pmask);
            flush_tlb_one_mask(&pmask, va);
            break;
        }
        break;
    }

    return rc;
}

int do_update_va_mapping(unsigned long va, u64 val64,
                         unsigned long flags)
{
    return __do_update_va_mapping(va, val64, flags, current->domain);
}

int do_update_va_mapping_otherdomain(unsigned long va, u64 val64,
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



/*************************
 * Descriptor Tables
 */

void destroy_gdt(struct vcpu *v)
{
    int i;
    unsigned long pfn;

    v->arch.guest_context.gdt_ents = 0;
    for ( i = 0; i < FIRST_RESERVED_GDT_PAGE; i++ )
    {
        if ( (pfn = l1e_get_pfn(v->arch.perdomain_ptes[i])) != 0 )
            put_page_and_type(mfn_to_page(pfn));
        l1e_write(&v->arch.perdomain_ptes[i], l1e_empty());
        v->arch.guest_context.gdt_frames[i] = 0;
    }
}


long set_gdt(struct vcpu *v, 
             unsigned long *frames,
             unsigned int entries)
{
    struct domain *d = v->domain;
    /* NB. There are 512 8-byte entries per GDT page. */
    int i, nr_pages = (entries + 511) / 512;
    unsigned long mfn;

    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;

    /* Check the pages in the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        mfn = frames[i] = gmfn_to_mfn(d, frames[i]);
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_seg_desc_page) )
            goto fail;
    }

    /* Tear down the old GDT. */
    destroy_gdt(v);

    /* Install the new GDT. */
    v->arch.guest_context.gdt_ents = entries;
    for ( i = 0; i < nr_pages; i++ )
    {
        v->arch.guest_context.gdt_frames[i] = frames[i];
        l1e_write(&v->arch.perdomain_ptes[i],
                  l1e_from_pfn(frames[i], __PAGE_HYPERVISOR));
    }

    return 0;

 fail:
    while ( i-- > 0 )
        put_page_and_type(mfn_to_page(frames[i]));
    return -EINVAL;
}


long do_set_gdt(XEN_GUEST_HANDLE(ulong) frame_list, unsigned int entries)
{
    int nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    struct vcpu *curr = current;
    long ret;

    /* Rechecked in set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;
    
    if ( copy_from_guest(frames, frame_list, nr_pages) )
        return -EFAULT;

    domain_lock(curr->domain);

    if ( (ret = set_gdt(curr, frames, entries)) == 0 )
        flush_tlb_local();

    domain_unlock(curr->domain);

    return ret;
}


long do_update_descriptor(u64 pa, u64 desc)
{
    struct domain *dom = current->domain;
    unsigned long gmfn = pa >> PAGE_SHIFT;
    unsigned long mfn;
    unsigned int  offset;
    struct desc_struct *gdt_pent, d;
    struct page_info *page;
    long ret = -EINVAL;

    offset = ((unsigned int)pa & ~PAGE_MASK) / sizeof(struct desc_struct);

    *(u64 *)&d = desc;

    mfn = gmfn_to_mfn(dom, gmfn);
    if ( (((unsigned int)pa % sizeof(struct desc_struct)) != 0) ||
         !mfn_valid(mfn) ||
         !check_descriptor(dom, &d) )
        return -EINVAL;

    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, dom)) )
        return -EINVAL;

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_seg_desc_page:
        if ( unlikely(!get_page_type(page, PGT_seg_desc_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    paging_mark_dirty(dom, mfn);

    /* All is good so make the update. */
    gdt_pent = map_domain_page(mfn);
    atomic_write64((uint64_t *)&gdt_pent[offset], *(uint64_t *)&d);
    unmap_domain_page(gdt_pent);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    return ret;
}

typedef struct e820entry e820entry_t;
DEFINE_XEN_GUEST_HANDLE(e820entry_t);

struct memory_map_context
{
    unsigned int n;
    unsigned long s;
    struct xen_memory_map map;
};

static int handle_iomem_range(unsigned long s, unsigned long e, void *p)
{
    struct memory_map_context *ctxt = p;

    if ( s > ctxt->s )
    {
        e820entry_t ent;
        XEN_GUEST_HANDLE(e820entry_t) buffer;

        if ( ctxt->n + 1 >= ctxt->map.nr_entries )
            return -EINVAL;
        ent.addr = (uint64_t)ctxt->s << PAGE_SHIFT;
        ent.size = (uint64_t)(s - ctxt->s) << PAGE_SHIFT;
        ent.type = E820_RESERVED;
        buffer = guest_handle_cast(ctxt->map.buffer, e820entry_t);
        if ( __copy_to_guest_offset(buffer, ctxt->n, &ent, 1) < 0 )
            return -EFAULT;
        ctxt->n++;
    }
    ctxt->s = e + 1;

    return 0;
}

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct page_info *page = NULL;
    int rc;

    switch ( op )
    {
    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;
        unsigned long prev_mfn, mfn = 0, gpfn;
        struct domain *d;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(xatp.domid, &d);
        if ( rc != 0 )
            return rc;

        if ( xsm_add_to_physmap(current->domain, d) )
        {
            rcu_unlock_domain(d);
            return -EPERM;
        }

        switch ( xatp.space )
        {
        case XENMAPSPACE_shared_info:
            if ( xatp.idx == 0 )
                mfn = virt_to_mfn(d->shared_info);
            break;
        case XENMAPSPACE_grant_table:
            spin_lock(&d->grant_table->lock);

            if ( d->grant_table->gt_version == 0 )
                d->grant_table->gt_version = 1;

            if ( d->grant_table->gt_version == 2 &&
                 (xatp.idx & XENMAPIDX_grant_table_status) )
            {
                xatp.idx &= ~XENMAPIDX_grant_table_status;
                if ( xatp.idx < nr_status_frames(d->grant_table) )
                    mfn = virt_to_mfn(d->grant_table->status[xatp.idx]);
            }
            else
            {
                if ( (xatp.idx >= nr_grant_frames(d->grant_table)) &&
                     (xatp.idx < max_nr_grant_frames) )
                    gnttab_grow_table(d, xatp.idx + 1);

                if ( xatp.idx < nr_grant_frames(d->grant_table) )
                    mfn = virt_to_mfn(d->grant_table->shared_raw[xatp.idx]);
            }

            spin_unlock(&d->grant_table->lock);
            break;
        case XENMAPSPACE_gmfn:
        {
            p2m_type_t p2mt;

            xatp.idx = mfn_x(gfn_to_mfn_unshare(p2m_get_hostp2m(d),
                                                xatp.idx, &p2mt, 0));
            /* If the page is still shared, exit early */
            if ( p2m_is_shared(p2mt) )
            {
                rcu_unlock_domain(d);
                return -ENOMEM;
            }
            if ( !get_page_from_pagenr(xatp.idx, d) )
                break;
            mfn = xatp.idx;
            page = mfn_to_page(mfn);
            break;
        }
        default:
            break;
        }

        if ( !paging_mode_translate(d) || (mfn == 0) )
        {
            if ( page )
                put_page(page);
            rcu_unlock_domain(d);
            return -EINVAL;
        }

        domain_lock(d);

        if ( page )
            put_page(page);

        /* Remove previously mapped page if it was present. */
        prev_mfn = gmfn_to_mfn(d, xatp.gpfn);
        if ( mfn_valid(prev_mfn) )
        {
            if ( is_xen_heap_mfn(prev_mfn) )
                /* Xen heap frames are simply unhooked from this phys slot. */
                guest_physmap_remove_page(d, xatp.gpfn, prev_mfn, 0);
            else
                /* Normal domain memory is freed, to avoid leaking memory. */
                guest_remove_page(d, xatp.gpfn);
        }

        /* Unmap from old location, if any. */
        gpfn = get_gpfn_from_mfn(mfn);
        ASSERT( gpfn != SHARED_M2P_ENTRY );
        if ( gpfn != INVALID_M2P_ENTRY )
            guest_physmap_remove_page(d, gpfn, mfn, 0);

        /* Map at new location. */
        rc = guest_physmap_add_page(d, xatp.gpfn, mfn, 0);

        domain_unlock(d);

        rcu_unlock_domain(d);

        return rc;
    }

    case XENMEM_set_memory_map:
    {
        struct xen_foreign_memory_map fmap;
        struct domain *d;

        if ( copy_from_guest(&fmap, arg, 1) )
            return -EFAULT;

        if ( fmap.map.nr_entries > ARRAY_SIZE(d->arch.e820) )
            return -EINVAL;

        rc = rcu_lock_target_domain_by_id(fmap.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = xsm_domain_memory_map(d);
        if ( rc )
        {
            rcu_unlock_domain(d);
            return rc;
        }

        rc = copy_from_guest(d->arch.e820, fmap.map.buffer,
                             fmap.map.nr_entries) ? -EFAULT : 0;
        d->arch.nr_e820 = fmap.map.nr_entries;

        rcu_unlock_domain(d);
        return rc;
    }

    case XENMEM_memory_map:
    {
        struct xen_memory_map map;
        struct domain *d = current->domain;

        /* Backwards compatibility. */
        if ( d->arch.nr_e820 == 0 )
            return -ENOSYS;

        if ( copy_from_guest(&map, arg, 1) )
            return -EFAULT;

        map.nr_entries = min(map.nr_entries, d->arch.nr_e820);
        if ( copy_to_guest(map.buffer, d->arch.e820, map.nr_entries) ||
             copy_to_guest(arg, &map, 1) )
            return -EFAULT;

        return 0;
    }

    case XENMEM_machine_memory_map:
    {
        struct memory_map_context ctxt;
        XEN_GUEST_HANDLE(e820entry_t) buffer;
        unsigned int i;

        if ( !IS_PRIV(current->domain) )
            return -EINVAL;

        rc = xsm_machine_memory_map();
        if ( rc )
            return rc;

        if ( copy_from_guest(&ctxt.map, arg, 1) )
            return -EFAULT;
        if ( ctxt.map.nr_entries < e820.nr_map + 1 )
            return -EINVAL;

        buffer = guest_handle_cast(ctxt.map.buffer, e820entry_t);
        if ( !guest_handle_okay(buffer, ctxt.map.nr_entries) )
            return -EFAULT;

        for ( i = 0, ctxt.n = 0, ctxt.s = 0; i < e820.nr_map; ++i, ++ctxt.n )
        {
            unsigned long s = PFN_DOWN(e820.map[i].addr);

            if ( s )
            {
                rc = rangeset_report_ranges(current->domain->iomem_caps,
                                            ctxt.s, s - 1,
                                            handle_iomem_range, &ctxt);
                if ( !rc )
                    rc = handle_iomem_range(s, s, &ctxt);
                if ( rc )
                    return rc;
            }
            if ( ctxt.map.nr_entries <= ctxt.n + (e820.nr_map - i) )
                return -EINVAL;
            if ( __copy_to_guest_offset(buffer, ctxt.n, e820.map + i, 1) < 0 )
                return -EFAULT;
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

        if ( copy_to_guest(arg, &ctxt.map, 1) )
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

        if ( !mem_hotplug )
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

        /* Support DOMID_SELF? */
        if ( !IS_PRIV(current->domain) )
            return -EINVAL;

        if ( copy_from_guest(&target, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(target.domid, &d);
        if ( rc != 0 )
            return rc;

        if ( op == XENMEM_set_pod_target )
        {
            if ( target.target_pages > d->max_pages )
            {
                rc = -EINVAL;
                goto pod_target_out_unlock;
            }
            
            rc = p2m_pod_set_mem_target(d, target.target_pages);
        }

        p2m = p2m_get_hostp2m(d);
        target.tot_pages       = d->tot_pages;
        target.pod_cache_pages = p2m->pod.count;
        target.pod_entries     = p2m->pod.entry_count;

        if ( copy_to_guest(arg, &target, 1) )
        {
            rc= -EFAULT;
            goto pod_target_out_unlock;
        }
        
    pod_target_out_unlock:
        rcu_unlock_domain(d);
        return rc;
    }

#ifdef __x86_64__
    case XENMEM_get_sharing_freed_pages:
        return mem_sharing_get_nr_saved_mfns();
#endif

    default:
        return subarch_memory_op(op, arg);
    }

    return 0;
}


/*************************
 * Writable Pagetables
 */

struct ptwr_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;
    unsigned long cr2;
    l1_pgentry_t  pte;
};

static int ptwr_emulated_read(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned int rc;
    unsigned long addr = offset;

    if ( (rc = copy_from_user(p_data, (void *)addr, bytes)) != 0 )
    {
        propagate_page_fault(addr + bytes - rc, 0); /* read fault */
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

static int ptwr_emulated_update(
    unsigned long addr,
    paddr_t old,
    paddr_t val,
    unsigned int bytes,
    unsigned int do_cmpxchg,
    struct ptwr_emulate_ctxt *ptwr_ctxt)
{
    unsigned long mfn;
    unsigned long unaligned_addr = addr;
    struct page_info *page;
    l1_pgentry_t pte, ol1e, nl1e, *pl1e;
    struct vcpu *v = current;
    struct domain *d = v->domain;

    /* Only allow naturally-aligned stores within the original %cr2 page. */
    if ( unlikely(((addr^ptwr_ctxt->cr2) & PAGE_MASK) || (addr & (bytes-1))) )
    {
        MEM_LOG("ptwr_emulate: bad access (cr2=%lx, addr=%lx, bytes=%u)",
                ptwr_ctxt->cr2, addr, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    /* Turn a sub-word access into a full-word access. */
    if ( bytes != sizeof(paddr_t) )
    {
        paddr_t      full;
        unsigned int rc, offset = addr & (sizeof(paddr_t)-1);

        /* Align address; read full word. */
        addr &= ~(sizeof(paddr_t)-1);
        if ( (rc = copy_from_user(&full, (void *)addr, sizeof(paddr_t))) != 0 )
        {
            propagate_page_fault(addr+sizeof(paddr_t)-rc, 0); /* read fault */
            return X86EMUL_EXCEPTION;
        }
        /* Mask out bits provided by caller. */
        full &= ~((((paddr_t)1 << (bytes*8)) - 1) << (offset*8));
        /* Shift the caller value and OR in the missing bits. */
        val  &= (((paddr_t)1 << (bytes*8)) - 1);
        val <<= (offset)*8;
        val  |= full;
        /* Also fill in missing parts of the cmpxchg old value. */
        old  &= (((paddr_t)1 << (bytes*8)) - 1);
        old <<= (offset)*8;
        old  |= full;
    }

    pte  = ptwr_ctxt->pte;
    mfn  = l1e_get_pfn(pte);
    page = mfn_to_page(mfn);

    /* We are looking only for read-only mappings of p.t. pages. */
    ASSERT((l1e_get_flags(pte) & (_PAGE_RW|_PAGE_PRESENT)) == _PAGE_PRESENT);
    ASSERT(mfn_valid(mfn));
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_l1_page_table);
    ASSERT((page->u.inuse.type_info & PGT_count_mask) != 0);
    ASSERT(page_get_owner(page) == d);

    /* Check the new PTE. */
    nl1e = l1e_from_intpte(val);
    switch ( get_page_from_l1e(nl1e, d, d) )
    {
    case 0:
        if ( is_pv_32bit_domain(d) && (bytes == 4) && (unaligned_addr & 4) &&
             !do_cmpxchg && (l1e_get_flags(nl1e) & _PAGE_PRESENT) )
        {
            /*
             * If this is an upper-half write to a PAE PTE then we assume that
             * the guest has simply got the two writes the wrong way round. We
             * zap the PRESENT bit on the assumption that the bottom half will
             * be written immediately after we return to the guest.
             */
            gdprintk(XENLOG_DEBUG, "ptwr_emulate: fixing up invalid PAE PTE %"
                     PRIpte"\n", l1e_get_intpte(nl1e));
            l1e_remove_flags(nl1e, _PAGE_PRESENT);
        }
        else
        {
            MEM_LOG("ptwr_emulate: could not get_page_from_l1e()");
            return X86EMUL_UNHANDLEABLE;
        }
        break;
    case -1:
        l1e_remove_flags(nl1e, _PAGE_RW);
        break;
    }

    adjust_guest_l1e(nl1e, d);

    /* Checked successfully: do the update (write or cmpxchg). */
    pl1e = map_domain_page(mfn);
    pl1e = (l1_pgentry_t *)((unsigned long)pl1e + (addr & ~PAGE_MASK));
    if ( do_cmpxchg )
    {
        int okay;
        intpte_t t = old;
        ol1e = l1e_from_intpte(old);

        okay = paging_cmpxchg_guest_entry(v, &l1e_get_intpte(*pl1e),
                                          &t, l1e_get_intpte(nl1e), _mfn(mfn));
        okay = (okay && t == old);

        if ( !okay )
        {
            unmap_domain_page(pl1e);
            put_page_from_l1e(nl1e, d);
            return X86EMUL_CMPXCHG_FAILED;
        }
    }
    else
    {
        ol1e = *pl1e;
        if ( !UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, mfn, v, 0) )
            BUG();
    }

    trace_ptwr_emulation(addr, nl1e);

    unmap_domain_page(pl1e);

    /* Finally, drop the old PTE. */
    put_page_from_l1e(ol1e, d);

    return X86EMUL_OKAY;
}

static int ptwr_emulated_write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    paddr_t val = 0;

    if ( (bytes > sizeof(paddr_t)) || (bytes & (bytes -1)) )
    {
        MEM_LOG("ptwr_emulate: bad write size (addr=%lx, bytes=%u)",
                offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&val, p_data, bytes);

    return ptwr_emulated_update(
        offset, 0, val, bytes, 0,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static int ptwr_emulated_cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    paddr_t old = 0, new = 0;

    if ( (bytes > sizeof(paddr_t)) || (bytes & (bytes -1)) )
    {
        MEM_LOG("ptwr_emulate: bad cmpxchg size (addr=%lx, bytes=%u)",
                offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&old, p_old, bytes);
    memcpy(&new, p_new, bytes);

    return ptwr_emulated_update(
        offset, old, new, bytes, 1,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static const struct x86_emulate_ops ptwr_emulate_ops = {
    .read       = ptwr_emulated_read,
    .insn_fetch = ptwr_emulated_read,
    .write      = ptwr_emulated_write,
    .cmpxchg    = ptwr_emulated_cmpxchg,
};

/* Write page fault handler: check if guest is trying to modify a PTE. */
int ptwr_do_page_fault(struct vcpu *v, unsigned long addr, 
                       struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;
    struct page_info *page;
    l1_pgentry_t      pte;
    struct ptwr_emulate_ctxt ptwr_ctxt;
    int rc;

    /* Attempt to read the PTE that maps the VA being accessed. */
    guest_get_eff_l1e(v, addr, &pte);

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((l1e_get_flags(pte) & (_PAGE_PRESENT|_PAGE_RW)) != _PAGE_PRESENT) ||
         !get_page_from_pagenr(l1e_get_pfn(pte), d) )
        goto bail;

    page = l1e_get_page(pte);
    if ( !page_lock(page) )
    {
        put_page(page);
        goto bail;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        put_page(page);
        goto bail;
    }

    ptwr_ctxt.ctxt.regs = regs;
    ptwr_ctxt.ctxt.force_writeback = 0;
    ptwr_ctxt.ctxt.addr_size = ptwr_ctxt.ctxt.sp_size =
        is_pv_32on64_domain(d) ? 32 : BITS_PER_LONG;
    ptwr_ctxt.cr2 = addr;
    ptwr_ctxt.pte = pte;

    rc = x86_emulate(&ptwr_ctxt.ctxt, &ptwr_emulate_ops);

    page_unlock(page);
    put_page(page);

    if ( rc == X86EMUL_UNHANDLEABLE )
        goto bail;

    perfc_incr(ptwr_emulations);
    return EXCRET_fault_fixed;

 bail:
    return 0;
}

void free_xen_pagetable(void *v)
{
    if ( early_boot )
        return;

    if ( is_xen_heap_page(virt_to_page(v)) )
        free_xenheap_page(v);
    else
        free_domheap_page(virt_to_page(v));
}

/* Convert to from superpage-mapping flags for map_pages_to_xen(). */
#define l1f_to_lNf(f) (((f) & _PAGE_PRESENT) ? ((f) |  _PAGE_PSE) : (f))
#define lNf_to_l1f(f) (((f) & _PAGE_PRESENT) ? ((f) & ~_PAGE_PSE) : (f))

/*
 * map_pages_to_xen() can be called with interrupts disabled:
 *  * During early bootstrap; or
 *  * alloc_xenheap_pages() via memguard_guard_range
 * In these cases it is safe to use flush_area_local():
 *  * Because only the local CPU is online; or
 *  * Because stale TLB entries do not matter for memguard_[un]guard_range().
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
    l2_pgentry_t *pl2e, ol2e;
    l1_pgentry_t *pl1e, ol1e;
    unsigned int  i;

    while ( nr_mfns != 0 )
    {
#ifdef __x86_64__
        l3_pgentry_t *pl3e = virt_to_xen_l3e(virt);
        l3_pgentry_t ol3e = *pl3e;

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
                    if ( l3e_get_flags(ol3e) & _PAGE_GLOBAL )
                        flush_flags |= FLUSH_TLB_GLOBAL;
                    if ( (lNf_to_l1f(l3e_get_flags(ol3e)) ^ flags) &
                         PAGE_CACHE_ATTRS )
                        flush_flags |= FLUSH_CACHE;
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
                        {
                            if ( l2e_get_flags(ol2e) & _PAGE_GLOBAL )
                                flush_flags |= FLUSH_TLB_GLOBAL;
                            if ( (lNf_to_l1f(l2e_get_flags(ol2e)) ^ flags) &
                                 PAGE_CACHE_ATTRS )
                                flush_flags |= FLUSH_CACHE;
                        }
                        else
                        {
                            unsigned int j;

                            pl1e = l2e_to_l1e(ol2e);
                            for ( j = 0; j < L1_PAGETABLE_ENTRIES; j++ )
                            {
                                ol1e = pl1e[j];
                                if ( l1e_get_flags(ol1e) & _PAGE_GLOBAL )
                                    flush_flags |= FLUSH_TLB_GLOBAL;
                                if ( (l1e_get_flags(ol1e) ^ flags) &
                                     PAGE_CACHE_ATTRS )
                                    flush_flags |= FLUSH_CACHE;
                            }
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
                i = (1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) -
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

            l3e_write_atomic(pl3e, l3e_from_pfn(virt_to_mfn(pl2e),
                                                __PAGE_HYPERVISOR));
            flush_area(virt, flush_flags);
        }
#endif

        pl2e = virt_to_xen_l2e(virt);

        if ( ((((virt>>PAGE_SHIFT) | mfn) & ((1<<PAGETABLE_ORDER)-1)) == 0) &&
             (nr_mfns >= (1<<PAGETABLE_ORDER)) &&
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
                    if ( l2e_get_flags(ol2e) & _PAGE_GLOBAL )
                        flush_flags |= FLUSH_TLB_GLOBAL;
                    if ( (lNf_to_l1f(l2e_get_flags(ol2e)) ^ flags) &
                         PAGE_CACHE_ATTRS )
                        flush_flags |= FLUSH_CACHE;
                    flush_area(virt, flush_flags);
                }
                else
                {
                    pl1e = l2e_to_l1e(ol2e);
                    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    {
                        if ( l1e_get_flags(pl1e[i]) & _PAGE_GLOBAL )
                            flush_flags |= FLUSH_TLB_GLOBAL;
                        if ( (l1e_get_flags(pl1e[i]) ^ flags) &
                             PAGE_CACHE_ATTRS )
                            flush_flags |= FLUSH_CACHE;
                    }
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
                pl1e = alloc_xen_pagetable();
                if ( pl1e == NULL )
                    return -ENOMEM;
                clear_page(pl1e);
                l2e_write(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                             __PAGE_HYPERVISOR));
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
                    i = (1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) -
                        (mfn & ((1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1));
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

                l2e_write_atomic(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                                    __PAGE_HYPERVISOR));
                flush_area(virt, flush_flags);
            }

            pl1e  = l2e_to_l1e(*pl2e) + l1_table_offset(virt);
            ol1e  = *pl1e;
            l1e_write_atomic(pl1e, l1e_from_pfn(mfn, flags));
            if ( (l1e_get_flags(ol1e) & _PAGE_PRESENT) )
            {
                unsigned int flush_flags = FLUSH_TLB | FLUSH_ORDER(0);
                if ( l1e_get_flags(ol1e) & _PAGE_GLOBAL )
                    flush_flags |= FLUSH_TLB_GLOBAL;
                if ( (l1e_get_flags(ol1e) ^ flags) & PAGE_CACHE_ATTRS )
                    flush_flags |= FLUSH_CACHE;
                flush_area(virt, flush_flags);
            }

            virt    += 1UL << L1_PAGETABLE_SHIFT;
            mfn     += 1UL;
            nr_mfns -= 1UL;

            if ( (flags == PAGE_HYPERVISOR) &&
                 ((nr_mfns == 0) ||
                  ((((virt >> PAGE_SHIFT) | mfn) &
                    ((1 << PAGETABLE_ORDER) - 1)) == 0)) )
            {
                unsigned long base_mfn;
                pl1e = l2e_to_l1e(*pl2e);
                base_mfn = l1e_get_pfn(*pl1e) & ~(L1_PAGETABLE_ENTRIES - 1);
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++, pl1e++ )
                    if ( (l1e_get_pfn(*pl1e) != (base_mfn + i)) ||
                         (l1e_get_flags(*pl1e) != flags) )
                        break;
                if ( i == L1_PAGETABLE_ENTRIES )
                {
                    ol2e = *pl2e;
                    l2e_write_atomic(pl2e, l2e_from_pfn(base_mfn,
                                                        l1f_to_lNf(flags)));
                    flush_area(virt - PAGE_SIZE,
                               FLUSH_TLB_GLOBAL |
                               FLUSH_ORDER(PAGETABLE_ORDER));
                    free_xen_pagetable(l2e_to_l1e(ol2e));
                }
            }
        }

 check_l3: ;
#ifdef __x86_64__
        if ( cpu_has_page1gb &&
             (flags == PAGE_HYPERVISOR) &&
             ((nr_mfns == 0) ||
              !(((virt >> PAGE_SHIFT) | mfn) &
                ((1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1))) )
        {
            unsigned long base_mfn;

            ol3e = *pl3e;
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
                flush_area(virt - PAGE_SIZE,
                           FLUSH_TLB_GLOBAL |
                           FLUSH_ORDER(2*PAGETABLE_ORDER));
                free_xen_pagetable(l3e_to_l2e(ol3e));
            }
        }
#endif
    }

    return 0;
}

void destroy_xen_mappings(unsigned long s, unsigned long e)
{
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned int  i;
    unsigned long v = s;

    ASSERT((s & ~PAGE_MASK) == 0);
    ASSERT((e & ~PAGE_MASK) == 0);

    while ( v < e )
    {
#ifdef __x86_64__
        l3_pgentry_t *pl3e = virt_to_xen_l3e(v);

        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
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
                /* PAGE1GB: whole superpage is destroyed. */
                l3e_write_atomic(pl3e, l3e_empty());
                v += 1UL << L3_PAGETABLE_SHIFT;
                continue;
            }

            /* PAGE1GB: shatter the superpage and fall through. */
            pl2e = alloc_xen_pagetable();
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
                l2e_write(pl2e + i,
                          l2e_from_pfn(l3e_get_pfn(*pl3e) +
                                       (i << PAGETABLE_ORDER),
                                       l3e_get_flags(*pl3e)));
            l3e_write_atomic(pl3e, l3e_from_pfn(virt_to_mfn(pl2e),
                                                __PAGE_HYPERVISOR));
        }
#endif

        pl2e = virt_to_xen_l2e(v);

        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            v += 1UL << L2_PAGETABLE_SHIFT;
            v &= ~((1UL << L2_PAGETABLE_SHIFT) - 1);
            continue;
        }

        if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
        {
            if ( (l1_table_offset(v) == 0) &&
                 ((e-v) >= (1UL << L2_PAGETABLE_SHIFT)) )
            {
                /* PSE: whole superpage is destroyed. */
                l2e_write_atomic(pl2e, l2e_empty());
                v += 1UL << L2_PAGETABLE_SHIFT;
            }
            else
            {
                /* PSE: shatter the superpage and try again. */
                pl1e = alloc_xen_pagetable();
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           l2e_get_flags(*pl2e) & ~_PAGE_PSE));
                l2e_write_atomic(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                                    __PAGE_HYPERVISOR));
            }
        }
        else
        {
            /* Ordinary 4kB mapping. */
            pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(v);
            l1e_write_atomic(pl1e, l1e_empty());
            v += PAGE_SIZE;

            /* If we are done with the L2E, check if it is now empty. */
            if ( (v != e) && (l1_table_offset(v) != 0) )
                continue;
            pl1e = l2e_to_l1e(*pl2e);
            for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                if ( l1e_get_intpte(pl1e[i]) != 0 )
                    break;
            if ( i == L1_PAGETABLE_ENTRIES )
            {
                /* Empty: zap the L2E and free the L1 page. */
                l2e_write_atomic(pl2e, l2e_empty());
                flush_area(NULL, FLUSH_TLB_GLOBAL); /* flush before free */
                free_xen_pagetable(pl1e);
            }
        }

#ifdef __x86_64__
        /* If we are done with the L3E, check if it is now empty. */
        if ( (v != e) && (l2_table_offset(v) + l1_table_offset(v) != 0) )
            continue;
        pl2e = l3e_to_l2e(*pl3e);
        for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
            if ( l2e_get_intpte(pl2e[i]) != 0 )
                break;
        if ( i == L2_PAGETABLE_ENTRIES )
        {
            /* Empty: zap the L3E and free the L2 page. */
            l3e_write_atomic(pl3e, l3e_empty());
            flush_area(NULL, FLUSH_TLB_GLOBAL); /* flush before free */
            free_xen_pagetable(pl2e);
        }
#endif
    }

    flush_area(NULL, FLUSH_TLB_GLOBAL);
}

void __set_fixmap(
    enum fixed_addresses idx, unsigned long mfn, unsigned long flags)
{
    BUG_ON(idx >= __end_of_fixed_addresses);
    map_pages_to_xen(fix_to_virt(idx), mfn, 1, flags);
}

#ifdef MEMORY_GUARD

void memguard_init(void)
{
    unsigned long start = max_t(unsigned long, xen_phys_start, 1UL << 20);
#ifdef __i386__
    map_pages_to_xen(
        (unsigned long)__va(start),
        start >> PAGE_SHIFT,
        (xenheap_phys_end - start) >> PAGE_SHIFT,
        __PAGE_HYPERVISOR|MAP_SMALL_PAGES);
#else
    map_pages_to_xen(
        (unsigned long)__va(start),
        start >> PAGE_SHIFT,
        (__pa(&_end) + PAGE_SIZE - 1 - start) >> PAGE_SHIFT,
        __PAGE_HYPERVISOR|MAP_SMALL_PAGES);
    BUG_ON(start != xen_phys_start);
    map_pages_to_xen(
        XEN_VIRT_START,
        start >> PAGE_SHIFT,
        (__pa(&_end) + PAGE_SIZE - 1 - start) >> PAGE_SHIFT,
        __PAGE_HYPERVISOR|MAP_SMALL_PAGES);
#endif
}

static void __memguard_change_range(void *p, unsigned long l, int guard)
{
    unsigned long _p = (unsigned long)p;
    unsigned long _l = (unsigned long)l;
    unsigned int flags = __PAGE_HYPERVISOR | MAP_SMALL_PAGES;

    /* Ensure we are dealing with a page-aligned whole number of pages. */
    ASSERT((_p&~PAGE_MASK) == 0);
    ASSERT((_l&~PAGE_MASK) == 0);

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
    BUILD_BUG_ON((PRIMARY_STACK_SIZE + PAGE_SIZE) > STACK_SIZE);
    p = (void *)((unsigned long)p + STACK_SIZE -
                 PRIMARY_STACK_SIZE - PAGE_SIZE);
    memguard_guard_range(p, PAGE_SIZE);
}

void memguard_unguard_stack(void *p)
{
    p = (void *)((unsigned long)p + STACK_SIZE -
                 PRIMARY_STACK_SIZE - PAGE_SIZE);
    memguard_unguard_range(p, PAGE_SIZE);
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
