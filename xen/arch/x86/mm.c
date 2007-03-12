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
#include <public/memory.h>

#define MEM_LOG(_f, _a...) gdprintk(XENLOG_WARNING , _f "\n" , ## _a)

/*
 * PTE updates can be done with ordinary writes except:
 *  1. Debug builds get extra checking by using CMPXCHG[8B].
 *  2. PAE builds perform an atomic 8-byte store with CMPXCHG8B.
 */
#if !defined(NDEBUG) || defined(CONFIG_X86_PAE)
#define PTE_UPDATE_WITH_CMPXCHG
#endif

/* Used to defer flushing of memory structures. */
struct percpu_mm_info {
#define DOP_FLUSH_TLB      (1<<0) /* Flush the local TLB.                    */
#define DOP_FLUSH_ALL_TLBS (1<<1) /* Flush TLBs of all VCPUs of current dom. */
#define DOP_RELOAD_LDT     (1<<2) /* Reload the LDT shadow mapping.          */
    unsigned int   deferred_ops;
    /* If non-NULL, specifies a foreign subject domain for some operations. */
    struct domain *foreign;
};
static DEFINE_PER_CPU(struct percpu_mm_info, percpu_mm_info);

/*
 * Returns the current foreign domain; defaults to the currently-executing
 * domain if a foreign override hasn't been specified.
 */
#define FOREIGNDOM (this_cpu(percpu_mm_info).foreign ?: current->domain)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
static struct domain *dom_xen, *dom_io;

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long max_page;
unsigned long total_pages;

#ifdef CONFIG_COMPAT
l2_pgentry_t *compat_idle_pg_table_l2 = NULL;
#define l3_disallow_mask(d) (!IS_COMPAT(d) ? \
                             L3_DISALLOW_MASK : \
                             COMPAT_L3_DISALLOW_MASK)
#else
#define l3_disallow_mask(d) L3_DISALLOW_MASK
#endif

static void queue_deferred_ops(struct domain *d, unsigned int ops)
{
    ASSERT(d == current->domain);
    this_cpu(percpu_mm_info).deferred_ops |= ops;
}

void __init init_frametable(void)
{
    unsigned long nr_pages, page_step, i, mfn;

    frame_table = (struct page_info *)FRAMETABLE_VIRT_START;

    nr_pages  = PFN_UP(max_page * sizeof(*frame_table));
    page_step = (1 << L2_PAGETABLE_SHIFT) >> PAGE_SHIFT;

    for ( i = 0; i < nr_pages; i += page_step )
    {
        mfn = alloc_boot_pages(min(nr_pages - i, page_step), page_step);
        if ( mfn == 0 )
            panic("Not enough memory for frame table\n");
        map_pages_to_xen(
            FRAMETABLE_VIRT_START + (i << PAGE_SHIFT),
            mfn, page_step, PAGE_HYPERVISOR);
    }

    memset(frame_table, 0, nr_pages << PAGE_SHIFT);
}

void arch_init_memory(void)
{
    extern void subarch_init_memory(void);

    unsigned long i, pfn, rstart_pfn, rend_pfn;

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain(DOMID_XEN);
    BUG_ON(dom_xen == NULL);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain(DOMID_IO);
    BUG_ON(dom_io == NULL);

    /* First 1MB of RAM is historically marked as I/O. */
    for ( i = 0; i < 0x100; i++ )
        share_xen_page_with_guest(mfn_to_page(i), dom_io, XENSHARE_writable);
 
    /* Any areas not specified as RAM by the e820 map are considered I/O. */
    for ( i = 0, pfn = 0; i < e820.nr_map; i++ )
    {
        if ( e820.map[i].type != E820_RAM )
            continue;
        /* Every page from cursor to start of next RAM region is I/O. */
        rstart_pfn = PFN_UP(e820.map[i].addr);
        rend_pfn   = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
        for ( ; pfn < rstart_pfn; pfn++ )
        {
            BUG_ON(!mfn_valid(pfn));
            share_xen_page_with_guest(
                mfn_to_page(pfn), dom_io, XENSHARE_writable);
        }
        /* Skip the RAM region. */
        pfn = rend_pfn;
    }
    BUG_ON(pfn != max_page);

    subarch_init_memory();
}

int memory_is_conventional_ram(paddr_t p)
{
    int i;

    for ( i = 0; i < e820.nr_map; i++ )
    {
        if ( (e820.map[i].type == E820_RAM) &&
             (e820.map[i].addr <= p) &&
             (e820.map[i].size > p) )
            return 1;
    }

    return 0;
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
    ASSERT(page->count_info == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !test_bit(_DOMF_dying, &d->domain_flags) )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        list_add_tail(&page->list, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

#if defined(CONFIG_X86_PAE)

#ifdef NDEBUG
/* Only PDPTs above 4GB boundary need to be shadowed in low memory. */
#define l3tab_needs_shadow(mfn) ((mfn) >= 0x100000)
#else
/*
 * In debug builds we shadow a selection of <4GB PDPTs to exercise code paths.
 * We cannot safely shadow the idle page table, nor shadow (v1) page tables
 * (detected by lack of an owning domain). As required for correctness, we
 * always shadow PDPTs above 4GB.
 */
#define l3tab_needs_shadow(mfn)                         \
    (((((mfn) << PAGE_SHIFT) != __pa(idle_pg_table)) && \
      (page_get_owner(mfn_to_page(mfn)) != NULL) &&     \
      ((mfn) & 1)) || /* odd MFNs are shadowed */       \
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
        local_flush_tlb_one(fix_to_virt(FIX_PAE_HIGHMEM_0 + cpu));
    highmem_l3tab = (l3_pgentry_t *)fix_to_virt(FIX_PAE_HIGHMEM_0 + cpu);
    lowmem_l3tab  = cache->table[cache->inuse_idx];
    memcpy(lowmem_l3tab, highmem_l3tab, sizeof(cache->table[0]));
    l1e_write(fix_pae_highmem_pl1e-cpu, l1e_empty());
    this_cpu(make_cr3_timestamp) = this_cpu(tlbflush_time);

    v->arch.cr3 = __pa(lowmem_l3tab);

    spin_unlock(&cache->lock);
}

#else /* !CONFIG_X86_PAE */

void make_cr3(struct vcpu *v, unsigned long mfn)
{
    v->arch.cr3 = mfn << PAGE_SHIFT;
}

#endif /* !CONFIG_X86_PAE */

void write_ptbase(struct vcpu *v)
{
    write_cr3(v->arch.cr3);
}

/* Should be called after CR3 is updated.
 * Updates vcpu->arch.cr3 and, for HVM guests, vcpu->arch.hvm_vcpu.cpu_cr3.
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


void invalidate_shadow_ldt(struct vcpu *v)
{
    int i;
    unsigned long pfn;
    struct page_info *page;
    
    if ( v->arch.shadow_ldt_mapcnt == 0 )
        return;

    v->arch.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1e_get_pfn(v->arch.perdomain_ptes[i]);
        if ( pfn == 0 ) continue;
        l1e_write(&v->arch.perdomain_ptes[i], l1e_empty());
        page = mfn_to_page(pfn);
        ASSERT_PAGE_IS_TYPE(page, PGT_ldt_page);
        ASSERT_PAGE_IS_DOMAIN(page, v->domain);
        put_page_and_type(page);
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    if ( v == current )
        queue_deferred_ops(v->domain, DOP_FLUSH_TLB | DOP_RELOAD_LDT);
    else
        flush_tlb_mask(v->domain->domain_dirty_cpumask);
}


static int alloc_segdesc_page(struct page_info *page)
{
    struct desc_struct *descs;
    int i;

    descs = map_domain_page(page_to_mfn(page));

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(page_get_owner(page), &descs[i])) )
            goto fail;

    unmap_domain_page(descs);
    return 1;

 fail:
    unmap_domain_page(descs);
    return 0;
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

    okay = get_page_and_type(mfn_to_page(mfn), d, PGT_ldt_page);
    if ( unlikely(!okay) )
        return 0;

    nl1e = l1e_from_pfn(mfn, l1e_get_flags(l1e) | _PAGE_RW);

    l1e_write(&v->arch.perdomain_ptes[off + 16], nl1e);
    v->arch.shadow_ldt_mapcnt++;

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
                                         struct domain *d)
{
    struct page_info *page = mfn_to_page(page_nr);

    if ( unlikely(!get_page_from_pagenr(page_nr, d)) )
        return 0;

    if ( unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        return 0;
    }

    return 1;
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

int
get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *d)
{
    unsigned long mfn = l1e_get_pfn(l1e);
    struct page_info *page = mfn_to_page(mfn);
    int okay;

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely(l1e_get_flags(l1e) & L1_DISALLOW_MASK) )
    {
        MEM_LOG("Bad L1 flags %x", l1e_get_flags(l1e) & L1_DISALLOW_MASK);
        return 0;
    }

    if ( unlikely(!mfn_valid(mfn)) ||
         unlikely(page_get_owner(page) == dom_io) )
    {
        /* DOMID_IO reverts to caller for privilege checks. */
        if ( d == dom_io )
            d = current->domain;

        if ( !iomem_access_permitted(d, mfn, mfn) )
        {
            if ( mfn != (PADDR_MASK >> PAGE_SHIFT) ) /* INVALID_MFN? */
                MEM_LOG("Non-privileged (%u) attempt to map I/O space %08lx", 
                        d->domain_id, mfn);
            return 0;
        }

        /* No reference counting for out-of-range I/O pages. */
        if ( !mfn_valid(mfn) )
            return 1;

        d = dom_io;
    }

    /* Foreign mappings into guests in shadow external mode don't
     * contribute to writeable mapping refcounts.  (This allows the
     * qemu-dm helper process in dom0 to map the domain's memory without
     * messing up the count of "real" writable mappings.) */
    okay = (((l1e_get_flags(l1e) & _PAGE_RW) && 
             !(unlikely(paging_mode_external(d) && (d != current->domain))))
            ? get_page_and_type(page, d, PGT_writable_page)
            : get_page(page, d));
    if ( !okay )
    {
        MEM_LOG("Error getting mfn %lx (pfn %lx) from L1 entry %" PRIpte
                " for dom%d",
                mfn, get_gpfn_from_mfn(mfn),
                l1e_get_intpte(l1e), d->domain_id);
    }

    return okay;
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
define_get_linear_pagetable(l2);
static int
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn, struct domain *d)
{
    int rc;

    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L2 flags %x", l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return 0;
    }

    rc = get_page_and_type_from_pagenr(l2e_get_pfn(l2e), PGT_l1_page_table, d);
    if ( unlikely(!rc) )
        rc = get_l2_linear_pagetable(l2e, pfn, d);

    return rc;
}


#if CONFIG_PAGING_LEVELS >= 3
define_get_linear_pagetable(l3);
static int
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn, struct domain *d)
{
    int rc;

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3e_get_flags(l3e) & l3_disallow_mask(d))) )
    {
        MEM_LOG("Bad L3 flags %x", l3e_get_flags(l3e) & l3_disallow_mask(d));
        return 0;
    }

    rc = get_page_and_type_from_pagenr(l3e_get_pfn(l3e), PGT_l2_page_table, d);
    if ( unlikely(!rc) )
        rc = get_l3_linear_pagetable(l3e, pfn, d);

    return rc;
}
#endif /* 3 level */

#if CONFIG_PAGING_LEVELS >= 4
define_get_linear_pagetable(l4);
static int
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, struct domain *d)
{
    int rc;

    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L4 flags %x", l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return 0;
    }

    rc = get_page_and_type_from_pagenr(l4e_get_pfn(l4e), PGT_l3_page_table, d);
    if ( unlikely(!rc) )
        rc = get_l4_linear_pagetable(l4e, pfn, d);

    return rc;
}
#endif /* 4 level */

#ifdef __x86_64__

#ifdef USER_MAPPINGS_ARE_GLOBAL
#define adjust_guest_l1e(pl1e, d)                                            \
    do {                                                                     \
        if ( likely(l1e_get_flags((pl1e)) & _PAGE_PRESENT) &&                \
             likely(!IS_COMPAT(d)) )                                         \
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
             likely(!IS_COMPAT(d)) )                            \
            l1e_add_flags((pl1e), _PAGE_USER);                  \
    } while ( 0 )
#endif

#define adjust_guest_l2e(pl2e, d)                               \
    do {                                                        \
        if ( likely(l2e_get_flags((pl2e)) & _PAGE_PRESENT) &&   \
             likely(!IS_COMPAT(d)) )                            \
            l2e_add_flags((pl2e), _PAGE_USER);                  \
    } while ( 0 )

#define adjust_guest_l3e(pl3e, d)                               \
    do {                                                        \
        if ( likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )    \
            l3e_add_flags((pl3e), likely(!IS_COMPAT(d)) ?       \
                                         _PAGE_USER :           \
                                         _PAGE_USER|_PAGE_RW);  \
    } while ( 0 )

#define adjust_guest_l4e(pl4e, d)                               \
    do {                                                        \
        if ( likely(l4e_get_flags((pl4e)) & _PAGE_PRESENT) &&   \
             likely(!IS_COMPAT(d)) )                            \
            l4e_add_flags((pl4e), _PAGE_USER);                  \
    } while ( 0 )

#else /* !defined(__x86_64__) */

#define adjust_guest_l1e(_p, _d) ((void)(_d))
#define adjust_guest_l2e(_p, _d) ((void)(_d))
#define adjust_guest_l3e(_p, _d) ((void)(_d))

#endif

#ifdef CONFIG_COMPAT
#define unadjust_guest_l3e(pl3e, d)                             \
    do {                                                        \
        if ( unlikely(IS_COMPAT(d)) &&                          \
             likely(l3e_get_flags((pl3e)) & _PAGE_PRESENT) )    \
            l3e_remove_flags((pl3e), _PAGE_USER|_PAGE_RW|_PAGE_ACCESSED); \
    } while ( 0 )
#else
#define unadjust_guest_l3e(_p, _d) ((void)(_d))
#endif

void put_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    unsigned long    pfn  = l1e_get_pfn(l1e);
    struct page_info *page = mfn_to_page(pfn);
    struct domain   *e;
    struct vcpu     *v;

    if ( !(l1e_get_flags(l1e) & _PAGE_PRESENT) || !mfn_valid(pfn) )
        return;

    e = page_get_owner(page);

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
         !(d->domain_flags & (DOMF_shutdown|DOMF_dying)) )
    {
        MEM_LOG("Attempt to implicitly unmap a granted PTE %" PRIpte,
                l1e_get_intpte(l1e));
        domain_crash(d);
    }

    /* Remember we didn't take a type-count of foreign writable mappings
     * to paging-external domains */
    if ( (l1e_get_flags(l1e) & _PAGE_RW) && 
         !(unlikely((e != d) && paging_mode_external(e))) )
    {
        put_page_and_type(page);
    }
    else
    {
        /* We expect this is rare so we blow the entire shadow LDT. */
        if ( unlikely(((page->u.inuse.type_info & PGT_type_mask) == 
                       PGT_ldt_page)) &&
             unlikely(((page->u.inuse.type_info & PGT_count_mask) != 0)) &&
             (d == e) )
        {
            for_each_vcpu ( d, v )
                invalidate_shadow_ldt(v);
        }
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static void put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( (l2e_get_flags(l2e) & _PAGE_PRESENT) && 
         (l2e_get_pfn(l2e) != pfn) )
        put_page_and_type(l2e_get_page(l2e));
}


#if CONFIG_PAGING_LEVELS >= 3
static void put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn)
{
    if ( (l3e_get_flags(l3e) & _PAGE_PRESENT) && 
         (l3e_get_pfn(l3e) != pfn) )
        put_page_and_type(l3e_get_page(l3e));
}
#endif

#if CONFIG_PAGING_LEVELS >= 4
static void put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn)
{
    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) && 
         (l4e_get_pfn(l4e) != pfn) )
        put_page_and_type(l4e_get_page(l4e));
}
#endif

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l1_pgentry_t  *pl1e;
    int            i;

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        if ( is_guest_l1_slot(i) &&
             unlikely(!get_page_from_l1e(pl1e[i], d)) )
            goto fail;

        adjust_guest_l1e(pl1e[i], d);
    }

    unmap_domain_page(pl1e);
    return 1;

 fail:
    MEM_LOG("Failure in alloc_l1_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
    return 0;
}

#if defined(CONFIG_X86_PAE) || defined(CONFIG_COMPAT)
static int create_pae_xen_mappings(struct domain *d, l3_pgentry_t *pl3e)
{
    struct page_info *page;
    l2_pgentry_t    *pl2e;
    l3_pgentry_t     l3e3;
#ifndef CONFIG_COMPAT
    l2_pgentry_t     l2e;
    int              i;
#else

    if ( !IS_COMPAT(d) )
        return 1;
#endif

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

    /* Xen private mappings. */
    pl2e = map_domain_page(l3e_get_pfn(l3e3));
#ifndef CONFIG_COMPAT
    memcpy(&pl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
    {
        l2e = l2e_from_page(
            virt_to_page(page_get_owner(page)->arch.mm_perdomain_pt) + i,
            __PAGE_HYPERVISOR);
        l2e_write(&pl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i], l2e);
    }
    for ( i = 0; i < (LINEARPT_MBYTES >> (L2_PAGETABLE_SHIFT - 20)); i++ )
    {
        l2e = l2e_empty();
        if ( l3e_get_flags(pl3e[i]) & _PAGE_PRESENT )
            l2e = l2e_from_pfn(l3e_get_pfn(pl3e[i]), __PAGE_HYPERVISOR);
        l2e_write(&pl2e[l2_table_offset(LINEAR_PT_VIRT_START) + i], l2e);
    }
#else
    memcpy(&pl2e[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
           &compat_idle_pg_table_l2[
               l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
           COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*pl2e));
#endif
    unmap_domain_page(pl2e);

    return 1;
}
#else
# define create_pae_xen_mappings(d, pl3e) (1)
#endif

#ifdef CONFIG_X86_PAE
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
        flush_tlb_mask(m);
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
            _pl3e = cmpxchg((intpte_t *)l3tab_ptr, _ol3e, _nl3e);
            BUG_ON(_pl3e != _ol3e);
        }

        spin_unlock(&cache->lock);
    }

    flush_tlb_mask(d->domain_dirty_cpumask);
}
#else
# define pae_flush_pgd(mfn, idx, nl3e) ((void)0)
#endif

static int alloc_l2_table(struct page_info *page, unsigned long type)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l2_pgentry_t  *pl2e;
    int            i;

    pl2e = map_domain_page(pfn);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( is_guest_l2_slot(d, type, i) &&
             unlikely(!get_page_from_l2e(pl2e[i], pfn, d)) )
            goto fail;
        
        adjust_guest_l2e(pl2e[i], d);
    }

#if CONFIG_PAGING_LEVELS == 2
    /* Xen private mappings. */
    memcpy(&pl2e[L2_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));
    pl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
        l2e_from_pfn(pfn, __PAGE_HYPERVISOR);
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        pl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_page(
                virt_to_page(page_get_owner(page)->arch.mm_perdomain_pt) + i,
                __PAGE_HYPERVISOR);
#endif

    unmap_domain_page(pl2e);
    return 1;

 fail:
    MEM_LOG("Failure in alloc_l2_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l2_slot(d, type, i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_page(pl2e);
    return 0;
}


#if CONFIG_PAGING_LEVELS >= 3
static int alloc_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l3_pgentry_t  *pl3e;
    int            i;

#ifdef CONFIG_X86_PAE
    /*
     * PAE pgdirs above 4GB are unacceptable if the guest does not understand
     * the weird 'extended cr3' format for dealing with high-order address
     * bits. We cut some slack for control tools (before vcpu0 is initialised).
     */
    if ( (pfn >= 0x100000) &&
         unlikely(!VM_ASSIST(d, VMASST_TYPE_pae_extended_cr3)) &&
         d->vcpu[0] && test_bit(_VCPUF_initialised, &d->vcpu[0]->vcpu_flags) )
    {
        MEM_LOG("PAE pgd must be below 4GB (0x%lx >= 0x100000)", pfn);
        return 0;
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
    if ( IS_COMPAT(d) )
        memset(pl3e + 4, 0, (L3_PAGETABLE_ENTRIES - 4) * sizeof(*pl3e));

    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
    {
#if defined(CONFIG_X86_PAE) || defined(CONFIG_COMPAT)
        if ( (CONFIG_PAGING_LEVELS < 4 || IS_COMPAT(d)) && i == 3 )
        {
            if ( !(l3e_get_flags(pl3e[i]) & _PAGE_PRESENT) ||
                 (l3e_get_flags(pl3e[i]) & l3_disallow_mask(d)) ||
                 !get_page_and_type_from_pagenr(l3e_get_pfn(pl3e[i]),
                                                PGT_l2_page_table |
                                                PGT_pae_xen_l2,
                                                d) )
                goto fail;
        }
        else
#endif
        if ( is_guest_l3_slot(i) &&
             unlikely(!get_page_from_l3e(pl3e[i], pfn, d)) )
            goto fail;
        
        adjust_guest_l3e(pl3e[i], d);
    }

    if ( !create_pae_xen_mappings(d, pl3e) )
        goto fail;

    unmap_domain_page(pl3e);
    return 1;

 fail:
    MEM_LOG("Failure in alloc_l3_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l3_slot(i) )
            put_page_from_l3e(pl3e[i], pfn);

    unmap_domain_page(pl3e);
    return 0;
}
#else
#define alloc_l3_table(page) (0)
#endif

#if CONFIG_PAGING_LEVELS >= 4
static int alloc_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l4_pgentry_t  *pl4e = page_to_virt(page);
    int            i;

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
    {
        if ( is_guest_l4_slot(d, i) &&
             unlikely(!get_page_from_l4e(pl4e[i], pfn, d)) )
            goto fail;

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
    if ( IS_COMPAT(d) )
        pl4e[l4_table_offset(COMPAT_ARG_XLAT_VIRT_BASE)] =
            l4e_from_page(virt_to_page(d->arch.mm_arg_xlat_l3),
                          __PAGE_HYPERVISOR);

    return 1;

 fail:
    MEM_LOG("Failure in alloc_l4_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l4_slot(d, i) )
            put_page_from_l4e(pl4e[i], pfn);

    return 0;
}
#else
#define alloc_l4_table(page) (0)
#endif


static void free_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l1_pgentry_t *pl1e;
    int i;

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
}


static void free_l2_table(struct page_info *page)
{
#ifdef CONFIG_COMPAT
    struct domain *d = page_get_owner(page);
#endif
    unsigned long pfn = page_to_mfn(page);
    l2_pgentry_t *pl2e;
    int i;

    pl2e = map_domain_page(pfn);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l2_slot(d, page->u.inuse.type_info, i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_page(pl2e);

    page->u.inuse.type_info &= ~PGT_pae_xen_l2;
}


#if CONFIG_PAGING_LEVELS >= 3

static void free_l3_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l3_pgentry_t *pl3e;
    int           i;

    pl3e = map_domain_page(pfn);

    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l3_slot(i) )
        {
            put_page_from_l3e(pl3e[i], pfn);
            unadjust_guest_l3e(pl3e[i], d);
        }

    unmap_domain_page(pl3e);
}

#endif

#if CONFIG_PAGING_LEVELS >= 4

static void free_l4_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_mfn(page);
    l4_pgentry_t *pl4e = page_to_virt(page);
    int           i;

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l4_slot(d, i) )
            put_page_from_l4e(pl4e[i], pfn);
}

#endif


/* How to write an entry to the guest pagetables.
 * Returns 0 for failure (pointer not valid), 1 for success. */
static inline int update_intpte(intpte_t *p, 
                                intpte_t old, 
                                intpte_t new,
                                unsigned long mfn,
                                struct vcpu *v)
{
    int rv = 1;
#ifndef PTE_UPDATE_WITH_CMPXCHG
    rv = paging_write_guest_entry(v, p, new, _mfn(mfn));
#else
    {
        intpte_t t = old;
        for ( ; ; )
        {
            rv = paging_cmpxchg_guest_entry(v, p, &t, new, _mfn(mfn));
            if ( unlikely(rv == 0) )
            {
                MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte
                        ": saw %" PRIpte, old, new, t);
                break;
            }

            if ( t == old )
                break;

            /* Allowed to change in Accessed/Dirty flags only. */
            BUG_ON((t ^ old) & ~(intpte_t)(_PAGE_ACCESSED|_PAGE_DIRTY));

            old = t;
        }
    }
#endif
    return rv;
}

/* Macro that wraps the appropriate type-changes around update_intpte().
 * Arguments are: type, ptr, old, new, mfn, vcpu */
#define UPDATE_ENTRY(_t,_p,_o,_n,_m,_v)                             \
    update_intpte((intpte_t *)(_p),                                 \
                  _t ## e_get_intpte(_o), _t ## e_get_intpte(_n),   \
                  (_m), (_v))

/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e, 
                        unsigned long gl1mfn)
{
    l1_pgentry_t ol1e;
    struct domain *d = current->domain;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return 0;

    if ( unlikely(paging_mode_refcounts(d)) )
        return UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, current);

    if ( l1e_get_flags(nl1e) & _PAGE_PRESENT )
    {
        /* Translate foreign guest addresses. */
        nl1e = l1e_from_pfn(gmfn_to_mfn(FOREIGNDOM, l1e_get_pfn(nl1e)),
                            l1e_get_flags(nl1e));

        if ( unlikely(l1e_get_flags(nl1e) & L1_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L1 flags %x",
                    l1e_get_flags(nl1e) & L1_DISALLOW_MASK);
            return 0;
        }

        adjust_guest_l1e(nl1e, d);

        /* Fast path for identical mapping, r/w and presence. */
        if ( !l1e_has_changed(ol1e, nl1e, _PAGE_RW | _PAGE_PRESENT) )
            return UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, current);

        if ( unlikely(!get_page_from_l1e(nl1e, FOREIGNDOM)) )
            return 0;
        
        if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, current)) )
        {
            put_page_from_l1e(nl1e, d);
            return 0;
        }
    }
    else
    {
        if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, current)) )
            return 0;
    }

    put_page_from_l1e(ol1e, d);
    return 1;
}


/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, 
                        l2_pgentry_t nl2e, 
                        unsigned long pfn,
                        unsigned long type)
{
    l2_pgentry_t ol2e;
    struct domain *d = current->domain;

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

        adjust_guest_l2e(nl2e, d);

        /* Fast path for identical mapping and presence. */
        if ( !l2e_has_changed(ol2e, nl2e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, current);

        if ( unlikely(!get_page_from_l2e(nl2e, pfn, d)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, current)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e, pfn, current)) )
    {
        return 0;
    }

    put_page_from_l2e(ol2e, pfn);
    return 1;
}

#if CONFIG_PAGING_LEVELS >= 3

/* Update the L3 entry at pl3e to new value nl3e. pl3e is within frame pfn. */
static int mod_l3_entry(l3_pgentry_t *pl3e, 
                        l3_pgentry_t nl3e, 
                        unsigned long pfn)
{
    l3_pgentry_t ol3e;
    struct domain *d = current->domain;
    int okay;

    if ( unlikely(!is_guest_l3_slot(pgentry_ptr_to_slot(pl3e))) )
    {
        MEM_LOG("Illegal L3 update attempt in Xen-private area %p", pl3e);
        return 0;
    }

#if defined(CONFIG_X86_PAE) || defined(CONFIG_COMPAT)
    /*
     * Disallow updates to final L3 slot. It contains Xen mappings, and it
     * would be a pain to ensure they remain continuously valid throughout.
     */
    if ( (CONFIG_PAGING_LEVELS < 4 || IS_COMPAT(d)) &&
         pgentry_ptr_to_slot(pl3e) >= 3 )
        return 0;
#endif 

    if ( unlikely(__copy_from_user(&ol3e, pl3e, sizeof(ol3e)) != 0) )
        return 0;

    if ( l3e_get_flags(nl3e) & _PAGE_PRESENT )
    {
        if ( unlikely(l3e_get_flags(nl3e) & l3_disallow_mask(d)) )
        {
            MEM_LOG("Bad L3 flags %x",
                    l3e_get_flags(nl3e) & l3_disallow_mask(d));
            return 0;
        }

        adjust_guest_l3e(nl3e, d);

        /* Fast path for identical mapping and presence. */
        if (!l3e_has_changed(ol3e, nl3e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, current);

        if ( unlikely(!get_page_from_l3e(nl3e, pfn, d)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, current)) )
        {
            put_page_from_l3e(nl3e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e, pfn, current)) )
    {
        return 0;
    }

    okay = create_pae_xen_mappings(d, pl3e);
    BUG_ON(!okay);

    pae_flush_pgd(pfn, pgentry_ptr_to_slot(pl3e), nl3e);

    put_page_from_l3e(ol3e, pfn);
    return 1;
}

#endif

#if CONFIG_PAGING_LEVELS >= 4

/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(struct domain *d,
                        l4_pgentry_t *pl4e, 
                        l4_pgentry_t nl4e, 
                        unsigned long pfn)
{
    l4_pgentry_t ol4e;

    if ( unlikely(!is_guest_l4_slot(d, pgentry_ptr_to_slot(pl4e))) )
    {
        MEM_LOG("Illegal L4 update attempt in Xen-private area %p", pl4e);
        return 0;
    }

    if ( unlikely(__copy_from_user(&ol4e, pl4e, sizeof(ol4e)) != 0) )
        return 0;

    if ( l4e_get_flags(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4e_get_flags(nl4e) & L4_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L4 flags %x",
                    l4e_get_flags(nl4e) & L4_DISALLOW_MASK);
            return 0;
        }

        adjust_guest_l4e(nl4e, current->domain);

        /* Fast path for identical mapping and presence. */
        if (!l4e_has_changed(ol4e, nl4e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, current);

        if ( unlikely(!get_page_from_l4e(nl4e, pfn, current->domain)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, current)) )
        {
            put_page_from_l4e(nl4e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e, pfn, current)) )
    {
        return 0;
    }

    put_page_from_l4e(ol4e, pfn);
    return 1;
}

#endif

int alloc_page_type(struct page_info *page, unsigned long type)
{
    struct domain *owner = page_get_owner(page);

    /* A page table is dirtied when its type count becomes non-zero. */
    if ( likely(owner != NULL) )
        mark_dirty(owner, page_to_mfn(page));

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        return alloc_l1_table(page);
    case PGT_l2_page_table:
        return alloc_l2_table(page, type);
    case PGT_l3_page_table:
        return alloc_l3_table(page);
    case PGT_l4_page_table:
        return alloc_l4_table(page);
    case PGT_gdt_page:
    case PGT_ldt_page:
        return alloc_segdesc_page(page);
    default:
        printk("Bad type in alloc_page_type %lx t=%" PRtype_info " c=%x\n", 
               type, page->u.inuse.type_info,
               page->count_info);
        BUG();
    }

    return 0;
}


void free_page_type(struct page_info *page, unsigned long type)
{
    struct domain *owner = page_get_owner(page);
    unsigned long gmfn;

    if ( likely(owner != NULL) )
    {
        /*
         * We have to flush before the next use of the linear mapping
         * (e.g., update_va_mapping()) or we could end up modifying a page
         * that is no longer a page table (and hence screw up ref counts).
         */
        if ( current->domain == owner )
            queue_deferred_ops(owner, DOP_FLUSH_ALL_TLBS);
        else
            flush_tlb_mask(owner->domain_dirty_cpumask);

        if ( unlikely(paging_mode_enabled(owner)) )
        {
            /* A page table is dirtied when its type count becomes zero. */
            mark_dirty(owner, page_to_mfn(page));

            if ( shadow_mode_refcounts(owner) )
                return;

            gmfn = mfn_to_gmfn(owner, page_to_mfn(page));
            ASSERT(VALID_M2P(gmfn));
            shadow_remove_all_shadows(owner->vcpu[0], _mfn(gmfn));
        }
    }

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        break;

    case PGT_l2_page_table:
        free_l2_table(page);
        break;

#if CONFIG_PAGING_LEVELS >= 3
    case PGT_l3_page_table:
        free_l3_table(page);
        break;
#endif

#if CONFIG_PAGING_LEVELS >= 4
    case PGT_l4_page_table:
        free_l4_table(page);
        break;
#endif

    default:
        printk("%s: type %lx pfn %lx\n",__FUNCTION__,
               type, page_to_mfn(page));
        BUG();
    }
}


void put_page_type(struct page_info *page)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, 
                                           x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we do the clean up. */
                free_page_type(page, x);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
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
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, unsigned long type)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

    ASSERT(!(type & ~(PGT_type_mask | PGT_pae_xen_l2)));

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_mfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            struct domain *d = page_get_owner(page);

            /* Never allow a shadowed frame to go from type count 0 to 1 */
            if ( d && shadow_mode_enabled(d) )
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
                    perfc_incrc(need_flush_tlb_flush);
                    flush_tlb_mask(mask);
                }

                /* We lose existing type, back pointer, and validity. */
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
            if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                 (type != PGT_l1_page_table) )
                MEM_LOG("Bad type (saw %" PRtype_info
                        " != exp %" PRtype_info ") "
                        "for mfn %lx (pfn %lx)",
                        x, type, page_to_mfn(page),
                        get_gpfn_from_mfn(page_to_mfn(page)));
            return 0;
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) == x )
                cpu_relax();
            goto again;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %"
                    PRtype_info ": caf=%08x taf=%" PRtype_info,
                    page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)),
                    type, page->count_info, page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}


int new_guest_cr3(unsigned long mfn)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    int okay;
    unsigned long old_base_mfn;

#ifdef CONFIG_COMPAT
    if ( IS_COMPAT(d) )
    {
        okay = paging_mode_refcounts(d)
            ? 0 /* Old code was broken, but what should it be? */
            : mod_l4_entry(
                    d,
                    __va(pagetable_get_paddr(v->arch.guest_table)),
                    l4e_from_pfn(
                        mfn,
                        (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED)),
                    pagetable_get_pfn(v->arch.guest_table));
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while installing new compat baseptr %lx", mfn);
            return 0;
        }

        invalidate_shadow_ldt(v);
        write_ptbase(v);

        return 1;
    }
#endif
    okay = paging_mode_refcounts(d)
        ? get_page_from_pagenr(mfn, d)
        : get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d);
    if ( unlikely(!okay) )
    {
        MEM_LOG("Error while installing new baseptr %lx", mfn);
        return 0;
    }

    invalidate_shadow_ldt(v);

    old_base_mfn = pagetable_get_pfn(v->arch.guest_table);

    v->arch.guest_table = pagetable_from_pfn(mfn);
    update_cr3(v);

    write_ptbase(v);

    if ( likely(old_base_mfn != 0) )
    {
        if ( paging_mode_refcounts(d) )
            put_page(mfn_to_page(old_base_mfn));
        else
            put_page_and_type(mfn_to_page(old_base_mfn));
    }

    return 1;
}

static void process_deferred_ops(void)
{
    unsigned int deferred_ops;
    struct domain *d = current->domain;
    struct percpu_mm_info *info = &this_cpu(percpu_mm_info);

    deferred_ops = info->deferred_ops;
    info->deferred_ops = 0;

    if ( deferred_ops & (DOP_FLUSH_ALL_TLBS|DOP_FLUSH_TLB) )
    {
        if ( deferred_ops & DOP_FLUSH_ALL_TLBS )
            flush_tlb_mask(d->domain_dirty_cpumask);
        else
            local_flush_tlb();
    }

    if ( deferred_ops & DOP_RELOAD_LDT )
        (void)map_ldt_shadow_page(0);

    if ( unlikely(info->foreign != NULL) )
    {
        rcu_unlock_domain(info->foreign);
        info->foreign = NULL;
    }
}

static int set_foreigndom(domid_t domid)
{
    struct domain *e, *d = current->domain;
    struct percpu_mm_info *info = &this_cpu(percpu_mm_info);
    int okay = 1;

    ASSERT(info->foreign == NULL);

    if ( likely(domid == DOMID_SELF) )
        goto out;

    if ( unlikely(domid == d->domain_id) )
    {
        MEM_LOG("Dom %u tried to specify itself as foreign domain",
                d->domain_id);
        okay = 0;
    }
    else if ( unlikely(paging_mode_translate(d)) )
    {
        MEM_LOG("Cannot mix foreign mappings with translated domains");
        okay = 0;
    }
    else if ( !IS_PRIV(d) )
    {
        switch ( domid )
        {
        case DOMID_IO:
            info->foreign = rcu_lock_domain(dom_io);
            break;
        default:
            MEM_LOG("Dom %u cannot set foreign dom", d->domain_id);
            okay = 0;
            break;
        }
    }
    else
    {
        info->foreign = e = rcu_lock_domain_by_id(domid);
        if ( e == NULL )
        {
            switch ( domid )
            {
            case DOMID_XEN:
                info->foreign = rcu_lock_domain(dom_xen);
                break;
            case DOMID_IO:
                info->foreign = rcu_lock_domain(dom_io);
                break;
            default:
                MEM_LOG("Unknown domain '%u'", domid);
                okay = 0;
                break;
            }
        }
    }

 out:
    return okay;
}

static inline cpumask_t vcpumask_to_pcpumask(
    struct domain *d, unsigned long vmask)
{
    unsigned int vcpu_id;
    cpumask_t    pmask = CPU_MASK_NONE;
    struct vcpu *v;

    while ( vmask != 0 )
    {
        vcpu_id = find_first_set_bit(vmask);
        vmask &= ~(1UL << vcpu_id);
        if ( (vcpu_id < MAX_VIRT_CPUS) &&
             ((v = d->vcpu[vcpu_id]) != NULL) )
            cpus_or(pmask, pmask, v->vcpu_dirty_cpumask);
    }

    return pmask;
}

int do_mmuext_op(
    XEN_GUEST_HANDLE(mmuext_op_t) uops,
    unsigned int count,
    XEN_GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom)
{
    struct mmuext_op op;
    int rc = 0, i = 0, okay;
    unsigned long mfn = 0, gmfn = 0, type;
    unsigned int done = 0;
    struct page_info *page;
    struct vcpu *v = current;
    struct domain *d = v->domain;

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }

    if ( unlikely(!guest_handle_okay(uops, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

    if ( !set_foreigndom(foreigndom) )
    {
        rc = -ESRCH;
        goto out;
    }

    LOCK_BIGLOCK(d);

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_mmuext_op, "hihi",
                uops, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
            break;
        }

        if ( unlikely(__copy_from_guest(&op, uops, 1) != 0) )
        {
            MEM_LOG("Bad __copy_from_guest");
            rc = -EFAULT;
            break;
        }

        okay = 1;
        gmfn  = op.arg1.mfn;
        mfn = gmfn_to_mfn(FOREIGNDOM, gmfn);
        page = mfn_to_page(mfn);

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
            if ( IS_COMPAT(FOREIGNDOM) )
                break;
            type = PGT_l4_page_table;

        pin_page:
            /* Ignore pinning of invalid paging levels. */
            if ( (op.cmd - MMUEXT_PIN_L1_TABLE) > (CONFIG_PAGING_LEVELS - 1) )
                break;

            if ( paging_mode_refcounts(FOREIGNDOM) )
                break;

            okay = get_page_and_type_from_pagenr(mfn, type, FOREIGNDOM);
            if ( unlikely(!okay) )
            {
                MEM_LOG("Error while pinning mfn %lx", mfn);
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
            mark_dirty(d, mfn);
           
            /* We can race domain destruction (domain_relinquish_resources). */
            if ( unlikely(this_cpu(percpu_mm_info).foreign != NULL) &&
                 test_bit(_DOMF_dying, &FOREIGNDOM->domain_flags) &&
                 test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
                put_page_and_type(page);

            break;

        case MMUEXT_UNPIN_TABLE:
            if ( paging_mode_refcounts(d) )
                break;

            if ( unlikely(!(okay = get_page_from_pagenr(mfn, d))) )
            {
                MEM_LOG("Mfn %lx bad domain (dom=%p)",
                        mfn, page_get_owner(page));
            }
            else if ( likely(test_and_clear_bit(_PGT_pinned, 
                                                &page->u.inuse.type_info)) )
            {
                put_page_and_type(page);
                put_page(page);
                /* A page is dirtied when its pin status is cleared. */
                mark_dirty(d, mfn);
            }
            else
            {
                okay = 0;
                put_page(page);
                MEM_LOG("Mfn %lx not pinned", mfn);
            }
            break;

        case MMUEXT_NEW_BASEPTR:
            okay = new_guest_cr3(mfn);
            this_cpu(percpu_mm_info).deferred_ops &= ~DOP_FLUSH_TLB;
            break;
        
#ifdef __x86_64__
        case MMUEXT_NEW_USER_BASEPTR: {
            unsigned long old_mfn;

            if ( mfn != 0 )
            {
                if ( paging_mode_refcounts(d) )
                    okay = get_page_from_pagenr(mfn, d);
                else
                    okay = get_page_and_type_from_pagenr(
                        mfn, PGT_root_page_table, d);
                if ( unlikely(!okay) )
                {
                    MEM_LOG("Error while installing new mfn %lx", mfn);
                    break;
                }
            }

            old_mfn = pagetable_get_pfn(v->arch.guest_table_user);
            v->arch.guest_table_user = pagetable_from_pfn(mfn);

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
            this_cpu(percpu_mm_info).deferred_ops |= DOP_FLUSH_TLB;
            break;
    
        case MMUEXT_INVLPG_LOCAL:
            if ( !paging_mode_enabled(d) 
                 || paging_invlpg(v, op.arg1.linear_addr) != 0 )
                local_flush_tlb_one(op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            unsigned long vmask;
            cpumask_t     pmask;
            if ( unlikely(copy_from_guest(&vmask, op.arg2.vcpumask, 1)) )
            {
                okay = 0;
                break;
            }
            pmask = vcpumask_to_pcpumask(d, vmask);
            if ( op.cmd == MMUEXT_TLB_FLUSH_MULTI )
                flush_tlb_mask(pmask);
            else
                flush_tlb_one_mask(pmask, op.arg1.linear_addr);
            break;
        }

        case MMUEXT_TLB_FLUSH_ALL:
            flush_tlb_mask(d->domain_dirty_cpumask);
            break;
    
        case MMUEXT_INVLPG_ALL:
            flush_tlb_one_mask(d->domain_dirty_cpumask, op.arg1.linear_addr);
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

        case MMUEXT_SET_LDT:
        {
            unsigned long ptr  = op.arg1.linear_addr;
            unsigned long ents = op.arg2.nr_ents;

            if ( paging_mode_external(d) )
            {
                MEM_LOG("ignoring SET_LDT hypercall from external "
                        "domain %u", d->domain_id);
                okay = 0;
            }
            else if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
                      (ents > 8192) ||
                      !array_access_ok(ptr, ents, LDT_ENTRY_SIZE) )
            {
                okay = 0;
                MEM_LOG("Bad args to SET_LDT: ptr=%lx, ents=%lx", ptr, ents);
            }
            else if ( (v->arch.guest_context.ldt_ents != ents) || 
                      (v->arch.guest_context.ldt_base != ptr) )
            {
                invalidate_shadow_ldt(v);
                v->arch.guest_context.ldt_base = ptr;
                v->arch.guest_context.ldt_ents = ents;
                load_LDT(v);
                this_cpu(percpu_mm_info).deferred_ops &= ~DOP_RELOAD_LDT;
                if ( ents != 0 )
                    this_cpu(percpu_mm_info).deferred_ops |= DOP_RELOAD_LDT;
            }
            break;
        }

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

    process_deferred_ops();

    UNLOCK_BIGLOCK(d);

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
    unsigned int cmd, done = 0;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long type_info;
    struct domain_mmap_cache mapcache, sh_mapcache;

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }

    if ( unlikely(!guest_handle_okay(ureqs, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

    if ( !set_foreigndom(foreigndom) )
    {
        rc = -ESRCH;
        goto out;
    }

    domain_mmap_cache_init(&mapcache);
    domain_mmap_cache_init(&sh_mapcache);

    perfc_incrc(calls_to_mmu_update);
    perfc_addc(num_page_updates, count);

    LOCK_BIGLOCK(d);

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_mmu_update, "hihi",
                ureqs, (count - i) | MMU_UPDATE_PREEMPTED, pdone, foreigndom);
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
             */
        case MMU_NORMAL_PT_UPDATE:

            gmfn = req.ptr >> PAGE_SHIFT;
            mfn = gmfn_to_mfn(d, gmfn);

            if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            va = map_domain_page_with_cache(mfn, &mapcache);
            va = (void *)((unsigned long)va +
                          (unsigned long)(req.ptr & ~PAGE_MASK));
            page = mfn_to_page(mfn);

            switch ( (type_info = page->u.inuse.type_info) & PGT_type_mask )
            {
            case PGT_l1_page_table:
            case PGT_l2_page_table:
            case PGT_l3_page_table:
            case PGT_l4_page_table:
            {
                if ( paging_mode_refcounts(d) )
                {
                    MEM_LOG("mmu update on auto-refcounted domain!");
                    break;
                }

                if ( unlikely(!get_page_type(
                    page, type_info & (PGT_type_mask|PGT_pae_xen_l2))) )
                    goto not_a_pt;

                switch ( type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                {
                    l1_pgentry_t l1e = l1e_from_intpte(req.val);
                    okay = mod_l1_entry(va, l1e, mfn);
                }
                break;
                case PGT_l2_page_table:
                {
                    l2_pgentry_t l2e = l2e_from_intpte(req.val);
                    okay = mod_l2_entry(va, l2e, mfn, type_info);
                }
                break;
#if CONFIG_PAGING_LEVELS >= 3
                case PGT_l3_page_table:
                {
                    l3_pgentry_t l3e = l3e_from_intpte(req.val);
                    okay = mod_l3_entry(va, l3e, mfn);
                }
                break;
#endif
#if CONFIG_PAGING_LEVELS >= 4
                case PGT_l4_page_table:
                {
                    l4_pgentry_t l4e = l4e_from_intpte(req.val);
                    okay = mod_l4_entry(d, va, l4e, mfn);
                }
                break;
#endif
                }

                put_page_type(page);
            }
            break;

            default:
            not_a_pt:
            {
                if ( unlikely(!get_page_type(page, PGT_writable_page)) )
                    break;

                okay = paging_write_guest_entry(v, va, req.val, _mfn(mfn));

                put_page_type(page);
            }
            break;
            }

            unmap_domain_page_with_cache(va, &mapcache);

            put_page(page);
            break;

        case MMU_MACHPHYS_UPDATE:

            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            if ( unlikely(!get_page_from_pagenr(mfn, FOREIGNDOM)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            if ( unlikely(paging_mode_translate(FOREIGNDOM)) )
            {
                MEM_LOG("Mach-phys update on auto-translate guest");
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);
            okay = 1;

            mark_dirty(FOREIGNDOM, mfn);

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

    domain_mmap_cache_destroy(&mapcache);
    domain_mmap_cache_destroy(&sh_mapcache);

    process_deferred_ops();

    UNLOCK_BIGLOCK(d);

 out:
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
    u32 type;
    l1_pgentry_t ol1e;
    struct domain *d = v->domain;

    ASSERT(spin_is_locked(&d->big_lock));

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

    type = page->u.inuse.type_info & PGT_type_mask;
    if ( (type != PGT_l1_page_table) || !get_page_type(page, type) )
    {
        MEM_LOG("Grant map attempted to update a non-L1 page");
        rc = GNTST_general_error;
        goto failed;
    }

    ol1e = *(l1_pgentry_t *)va;
    if ( !UPDATE_ENTRY(l1, va, ol1e, nl1e, mfn, v) )
    {
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    } 

    if ( !paging_mode_refcounts(d) )
        put_page_from_l1e(ol1e, d);

    put_page_type(page);
 
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
    u32 type;
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

    type = page->u.inuse.type_info & PGT_type_mask;
    if ( (type != PGT_l1_page_table) || !get_page_type(page, type) )
    {
        MEM_LOG("Grant map attempted to update a non-L1 page");
        rc = GNTST_general_error;
        goto failed;
    }

    if ( __copy_from_user(&ol1e, (l1_pgentry_t *)va, sizeof(ol1e)) )
    {
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }
    
    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely((l1e_get_intpte(ol1e) >> PAGE_SHIFT) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %"PRIx64" doesn't match frame %lx",
                (unsigned long)l1e_get_intpte(ol1e), addr, frame);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY(l1, 
                      (l1_pgentry_t *)va, ol1e, l1e_empty(), mfn, 
                      d->vcpu[0] /* Change if we go to per-vcpu shadows. */)) )
    {
        MEM_LOG("Cannot delete PTE entry at %p", va);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    put_page_type(page);

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
    int okay;
    
    ASSERT(spin_is_locked(&d->big_lock));

    adjust_guest_l1e(nl1e, d);

    pl1e = guest_map_l1e(v, va, &gl1mfn);
    if ( !pl1e )
    {
        MEM_LOG("Could not find L1 PTE for address %lx", va);
        return GNTST_general_error;
    }
    ol1e = *pl1e;
    okay = UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, gl1mfn, v);
    guest_unmap_l1e(v, pl1e);
    pl1e = NULL;

    if ( !okay )
            return GNTST_general_error;

    if ( !paging_mode_refcounts(d) )
        put_page_from_l1e(ol1e, d);

    return GNTST_okay;
}

static int destroy_grant_va_mapping(
    unsigned long addr, unsigned long frame, struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    unsigned long gl1mfn;
    int rc = 0;
    
    pl1e = guest_map_l1e(v, addr, &gl1mfn);
    if ( !pl1e )
    {
        MEM_LOG("Could not find L1 PTE for address %lx", addr);
        return GNTST_general_error;
    }
    ol1e = *pl1e;

    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                l1e_get_pfn(ol1e), addr, frame);
        rc = GNTST_general_error;
        goto out;
    }

    /* Delete pagetable entry. */
    if ( unlikely(!UPDATE_ENTRY(l1, pl1e, ol1e, l1e_empty(), gl1mfn, v)) )
    {
        MEM_LOG("Cannot delete PTE entry at %p", (unsigned long *)pl1e);
        rc = GNTST_general_error;
        goto out;
    }

 out:
    guest_unmap_l1e(v, pl1e);
    return rc;
}

int create_grant_host_mapping(
    uint64_t addr, unsigned long frame, unsigned int flags)
{
    l1_pgentry_t pte = l1e_from_pfn(frame, GRANT_PTE_FLAGS);

    if ( (flags & GNTMAP_application_map) )
        l1e_add_flags(pte,_PAGE_USER);
    if ( !(flags & GNTMAP_readonly) )
        l1e_add_flags(pte,_PAGE_RW);

    if ( flags & GNTMAP_contains_pte )
        return create_grant_pte_mapping(addr, pte, current);
    return create_grant_va_mapping(addr, pte, current);
}

int destroy_grant_host_mapping(
    uint64_t addr, unsigned long frame, unsigned int flags)
{
    if ( flags & GNTMAP_contains_pte )
        return destroy_grant_pte_mapping(addr, frame, current->domain);
    return destroy_grant_va_mapping(addr, frame, current);
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    u32 _d, _nd, x, y;

    spin_lock(&d->page_alloc_lock);

    /*
     * The tricky bit: atomically release ownership while there is just one 
     * benign reference to the page (PGC_allocated). If that reference 
     * disappears then the deallocation routine will safely spin.
     */
    _d  = pickle_domptr(d);
    _nd = page->u.inuse._domain;
    y   = page->count_info;
    do {
        x = y;
        if (unlikely((x & (PGC_count_mask|PGC_allocated)) !=
                     (1 | PGC_allocated)) || unlikely(_nd != _d)) { 
            MEM_LOG("gnttab_transfer: Bad page %p: ed=%p(%u), sd=%p,"
                    " caf=%08x, taf=%" PRtype_info "\n", 
                    (void *) page_to_mfn(page),
                    d, d->domain_id, unpickle_domptr(_nd), x, 
                    page->u.inuse.type_info);
            spin_unlock(&d->page_alloc_lock);
            return -1;
        }
        __asm__ __volatile__(
            LOCK_PREFIX "cmpxchg8b %2"
            : "=d" (_nd), "=a" (y),
            "=m" (*(volatile u64 *)(&page->count_info))
            : "0" (_d), "1" (x), "c" (NULL), "b" (x) );
    } while (unlikely(_nd != _d) || unlikely(y != x));

    /*
     * Unlink from 'd'. At least one reference remains (now anonymous), so 
     * noone else is spinning to try to delete this page from 'd'.
     */
    if ( !(memflags & MEMF_no_refcount) )
        d->tot_pages--;
    list_del(&page->list);

    spin_unlock(&d->page_alloc_lock);

    return 0;
}

int do_update_va_mapping(unsigned long va, u64 val64,
                         unsigned long flags)
{
    l1_pgentry_t   val = l1e_from_intpte(val64);
    struct vcpu   *v   = current;
    struct domain *d   = v->domain;
    l1_pgentry_t  *pl1e;
    unsigned long  vmask, bmap_ptr, gl1mfn;
    cpumask_t      pmask;
    int            rc  = 0;

    perfc_incrc(calls_to_update_va);

    if ( unlikely(!__addr_ok(va) && !paging_mode_external(d)) )
        return -EINVAL;

    LOCK_BIGLOCK(d);

    pl1e = guest_map_l1e(v, va, &gl1mfn);

    if ( unlikely(!pl1e || !mod_l1_entry(pl1e, val, gl1mfn)) )
        rc = -EINVAL;

    if ( pl1e )
        guest_unmap_l1e(v, pl1e);
    pl1e = NULL;

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            local_flush_tlb();
            break;
        case UVMF_ALL:
            flush_tlb_mask(d->domain_dirty_cpumask);
            break;
        default:
            if ( unlikely(!IS_COMPAT(d) ?
                          get_user(vmask, (unsigned long *)bmap_ptr) :
                          get_user(vmask, (unsigned int *)bmap_ptr)) )
                rc = -EFAULT;
            pmask = vcpumask_to_pcpumask(d, vmask);
            flush_tlb_mask(pmask);
            break;
        }
        break;

    case UVMF_INVLPG:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            if ( !paging_mode_enabled(d) 
                 || (paging_invlpg(current, va) != 0) ) 
                local_flush_tlb_one(va);
            break;
        case UVMF_ALL:
            flush_tlb_one_mask(d->domain_dirty_cpumask, va);
            break;
        default:
            if ( unlikely(get_user(vmask, (unsigned long *)bmap_ptr)) )
                rc = -EFAULT;
            pmask = vcpumask_to_pcpumask(d, vmask);
            flush_tlb_one_mask(pmask, va);
            break;
        }
        break;
    }

    process_deferred_ops();
    
    UNLOCK_BIGLOCK(d);

    return rc;
}

int do_update_va_mapping_otherdomain(unsigned long va, u64 val64,
                                     unsigned long flags,
                                     domid_t domid)
{
    int rc;

    if ( unlikely(!IS_PRIV(current->domain)) )
        return -EPERM;

    if ( !set_foreigndom(domid) )
        return -ESRCH;

    rc = do_update_va_mapping(va, val64, flags);

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
    for ( i = 0; i < nr_pages; i++ ) {
        mfn = frames[i] = gmfn_to_mfn(d, frames[i]);
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_gdt_page) )
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
    long ret;

    /* Rechecked in set_gdt, but ensures a sane limit for copy_from_user(). */
    if ( entries > FIRST_RESERVED_GDT_ENTRY )
        return -EINVAL;
    
    if ( copy_from_guest((unsigned long *)frames, frame_list, nr_pages) )
        return -EFAULT;

    LOCK_BIGLOCK(current->domain);

    if ( (ret = set_gdt(current, frames, entries)) == 0 )
        local_flush_tlb();

    UNLOCK_BIGLOCK(current->domain);

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

    LOCK_BIGLOCK(dom);

    mfn = gmfn_to_mfn(dom, gmfn);
    if ( (((unsigned int)pa % sizeof(struct desc_struct)) != 0) ||
         !mfn_valid(mfn) ||
         !check_descriptor(dom, &d) )
    {
        UNLOCK_BIGLOCK(dom);
        return -EINVAL;
    }

    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, dom)) )
    {
        UNLOCK_BIGLOCK(dom);
        return -EINVAL;
    }

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_gdt_page:
        if ( unlikely(!get_page_type(page, PGT_gdt_page)) )
            goto out;
        break;
    case PGT_ldt_page:
        if ( unlikely(!get_page_type(page, PGT_ldt_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    mark_dirty(dom, mfn);

    /* All is good so make the update. */
    gdt_pent = map_domain_page(mfn);
    memcpy(&gdt_pent[offset], &d, 8);
    unmap_domain_page(gdt_pent);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    UNLOCK_BIGLOCK(dom);

    return ret;
}

typedef struct e820entry e820entry_t;
DEFINE_XEN_GUEST_HANDLE(e820entry_t);

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    switch ( op )
    {
    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;
        unsigned long prev_mfn, mfn = 0, gpfn;
        struct domain *d;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        if ( xatp.domid == DOMID_SELF )
            d = rcu_lock_current_domain();
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = rcu_lock_domain_by_id(xatp.domid)) == NULL )
            return -ESRCH;

        switch ( xatp.space )
        {
        case XENMAPSPACE_shared_info:
            if ( xatp.idx == 0 )
                mfn = virt_to_mfn(d->shared_info);
            break;
        case XENMAPSPACE_grant_table:
            spin_lock(&d->grant_table->lock);

            if ( (xatp.idx >= nr_grant_frames(d->grant_table)) &&
                 (xatp.idx < max_nr_grant_frames) )
                gnttab_grow_table(d, xatp.idx + 1);

            if ( xatp.idx < nr_grant_frames(d->grant_table) )
                mfn = virt_to_mfn(d->grant_table->shared[xatp.idx]);

            spin_unlock(&d->grant_table->lock);
            break;
        default:
            break;
        }

        if ( !paging_mode_translate(d) || (mfn == 0) )
        {
            rcu_unlock_domain(d);
            return -EINVAL;
        }

        LOCK_BIGLOCK(d);

        /* Remove previously mapped page if it was present. */
        prev_mfn = gmfn_to_mfn(d, xatp.gpfn);
        if ( mfn_valid(prev_mfn) )
        {
            if ( IS_XEN_HEAP_FRAME(mfn_to_page(prev_mfn)) )
                /* Xen heap frames are simply unhooked from this phys slot. */
                guest_physmap_remove_page(d, xatp.gpfn, prev_mfn);
            else
                /* Normal domain memory is freed, to avoid leaking memory. */
                guest_remove_page(d, xatp.gpfn);
        }

        /* Unmap from old location, if any. */
        gpfn = get_gpfn_from_mfn(mfn);
        if ( gpfn != INVALID_M2P_ENTRY )
            guest_physmap_remove_page(d, gpfn, mfn);

        /* Map at new location. */
        guest_physmap_add_page(d, xatp.gpfn, mfn);

        UNLOCK_BIGLOCK(d);

        rcu_unlock_domain(d);

        break;
    }

    case XENMEM_set_memory_map:
    {
        struct xen_foreign_memory_map fmap;
        struct domain *d;
        int rc;

        if ( copy_from_guest(&fmap, arg, 1) )
            return -EFAULT;

        if ( fmap.map.nr_entries > ARRAY_SIZE(d->arch.e820) )
            return -EINVAL;

        if ( fmap.domid == DOMID_SELF )
            d = rcu_lock_current_domain();
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = rcu_lock_domain_by_id(fmap.domid)) == NULL )
            return -ESRCH;

        rc = copy_from_guest(&d->arch.e820[0], fmap.map.buffer,
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
        if ( copy_to_guest(map.buffer, &d->arch.e820[0], map.nr_entries) ||
             copy_to_guest(arg, &map, 1) )
            return -EFAULT;

        return 0;
    }

    case XENMEM_machine_memory_map:
    {
        struct xen_memory_map memmap;
        XEN_GUEST_HANDLE(e820entry_t) buffer;
        int count;

        if ( !IS_PRIV(current->domain) )
            return -EINVAL;

        if ( copy_from_guest(&memmap, arg, 1) )
            return -EFAULT;
        if ( memmap.nr_entries < e820.nr_map + 1 )
            return -EINVAL;

        buffer = guest_handle_cast(memmap.buffer, e820entry_t);

        count = min((unsigned int)e820.nr_map, memmap.nr_entries);
        if ( copy_to_guest(buffer, &e820.map[0], count) < 0 )
            return -EFAULT;

        memmap.nr_entries = count;

        if ( copy_to_guest(arg, &memmap, 1) )
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

        if ( copy_to_guest(arg, &mapping, 1) )
            return -EFAULT;

        return 0;
    }

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
    unsigned long *val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned int rc;
    unsigned long addr = offset;

    *val = 0;
    if ( (rc = copy_from_user((void *)val, (void *)addr, bytes)) != 0 )
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
    struct page_info *page;
    l1_pgentry_t pte, ol1e, nl1e, *pl1e;
    struct vcpu *v = current;
    struct domain *d = v->domain;

    /* Only allow naturally-aligned stores within the original %cr2 page. */
    if ( unlikely(((addr^ptwr_ctxt->cr2) & PAGE_MASK) || (addr & (bytes-1))) )
    {
        MEM_LOG("Bad ptwr access (cr2=%lx, addr=%lx, bytes=%u)",
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
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_l1_page_table);
    ASSERT((page->u.inuse.type_info & PGT_count_mask) != 0);
    ASSERT(page_get_owner(page) == d);

    /* Check the new PTE. */
    nl1e = l1e_from_intpte(val);
    if ( unlikely(!get_page_from_l1e(gl1e_to_ml1e(d, nl1e), d)) )
    {
        if ( (CONFIG_PAGING_LEVELS == 3 || IS_COMPAT(d)) &&
             (bytes == 4) && (addr & 4) && !do_cmpxchg &&
             (l1e_get_flags(nl1e) & _PAGE_PRESENT) )
        {
            /*
             * If this is an upper-half write to a PAE PTE then we assume that
             * the guest has simply got the two writes the wrong way round. We
             * zap the PRESENT bit on the assumption that the bottom half will
             * be written immediately after we return to the guest.
             */
            MEM_LOG("ptwr_emulate: fixing up invalid PAE PTE %"PRIpte,
                    l1e_get_intpte(nl1e));
            l1e_remove_flags(nl1e, _PAGE_PRESENT);
        }
        else
        {
            MEM_LOG("ptwr_emulate: could not get_page_from_l1e()");
            return X86EMUL_UNHANDLEABLE;
        }
    }

    adjust_guest_l1e(nl1e, d);

    /* Checked successfully: do the update (write or cmpxchg). */
    pl1e = map_domain_page(page_to_mfn(page));
    pl1e = (l1_pgentry_t *)((unsigned long)pl1e + (addr & ~PAGE_MASK));
    if ( do_cmpxchg )
    {
        int okay;
        intpte_t t = old;
        ol1e = l1e_from_intpte(old);

        okay = paging_cmpxchg_guest_entry(v, (intpte_t *) pl1e, 
                                          &t, val, _mfn(mfn));
        okay = (okay && t == old);

        if ( !okay )
        {
            unmap_domain_page(pl1e);
            put_page_from_l1e(gl1e_to_ml1e(d, nl1e), d);
            return X86EMUL_CMPXCHG_FAILED;
        }
    }
    else
    {
        ol1e = *pl1e;
        if ( !UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, page_to_mfn(page), v) )
            BUG();
    }

    unmap_domain_page(pl1e);

    /* Finally, drop the old PTE. */
    put_page_from_l1e(gl1e_to_ml1e(d, ol1e), d);

    return X86EMUL_OKAY;
}

static int ptwr_emulated_write(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return ptwr_emulated_update(
        offset, 0, val, bytes, 0,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static int ptwr_emulated_cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long old,
    unsigned long new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return ptwr_emulated_update(
        offset, old, new, bytes, 1,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static int ptwr_emulated_cmpxchg8b(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long old,
    unsigned long old_hi,
    unsigned long new,
    unsigned long new_hi,
    struct x86_emulate_ctxt *ctxt)
{
    if ( CONFIG_PAGING_LEVELS == 2 )
        return X86EMUL_UNHANDLEABLE;
    return ptwr_emulated_update(
        offset, ((u64)old_hi << 32) | old, ((u64)new_hi << 32) | new, 8, 1,
        container_of(ctxt, struct ptwr_emulate_ctxt, ctxt));
}

static struct x86_emulate_ops ptwr_emulate_ops = {
    .read       = ptwr_emulated_read,
    .insn_fetch = ptwr_emulated_read,
    .write      = ptwr_emulated_write,
    .cmpxchg    = ptwr_emulated_cmpxchg,
    .cmpxchg8b  = ptwr_emulated_cmpxchg8b
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

    LOCK_BIGLOCK(d);

    /*
     * Attempt to read the PTE that maps the VA being accessed. By checking for
     * PDE validity in the L2 we avoid many expensive fixups in __get_user().
     */
    guest_get_eff_l1e(v, addr, &pte);
    if ( !(l1e_get_flags(pte) & _PAGE_PRESENT) )
        goto bail;
    page = l1e_get_page(pte);

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((l1e_get_flags(pte) & (_PAGE_PRESENT|_PAGE_RW)) != _PAGE_PRESENT) ||
         ((page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table) ||
         ((page->u.inuse.type_info & PGT_count_mask) == 0) ||
         (page_get_owner(page) != d) )
        goto bail;

    ptwr_ctxt.ctxt.regs = regs;
    ptwr_ctxt.ctxt.addr_size = ptwr_ctxt.ctxt.sp_size =
        IS_COMPAT(d) ? 32 : BITS_PER_LONG;
    ptwr_ctxt.cr2 = addr;
    ptwr_ctxt.pte = pte;

    rc = x86_emulate(&ptwr_ctxt.ctxt, &ptwr_emulate_ops);
    if ( rc == X86EMUL_UNHANDLEABLE )
        goto bail;

    UNLOCK_BIGLOCK(d);
    perfc_incrc(ptwr_emulations);
    return EXCRET_fault_fixed;

 bail:
    UNLOCK_BIGLOCK(d);
    return 0;
}

int map_pages_to_xen(
    unsigned long virt,
    unsigned long mfn,
    unsigned long nr_mfns,
    unsigned long flags)
{
    l2_pgentry_t *pl2e, ol2e;
    l1_pgentry_t *pl1e, ol1e;
    unsigned int  i;

    unsigned int  map_small_pages = !!(flags & MAP_SMALL_PAGES);
    flags &= ~MAP_SMALL_PAGES;

    while ( nr_mfns != 0 )
    {
        pl2e = virt_to_xen_l2e(virt);

        if ( ((((virt>>PAGE_SHIFT) | mfn) & ((1<<PAGETABLE_ORDER)-1)) == 0) &&
             (nr_mfns >= (1<<PAGETABLE_ORDER)) &&
             !map_small_pages )
        {
            /* Super-page mapping. */
            ol2e = *pl2e;
            l2e_write(pl2e, l2e_from_pfn(mfn, flags|_PAGE_PSE));

            if ( (l2e_get_flags(ol2e) & _PAGE_PRESENT) )
            {
                local_flush_tlb_pge();
                if ( !(l2e_get_flags(ol2e) & _PAGE_PSE) )
                    free_xen_pagetable(mfn_to_virt(l2e_get_pfn(ol2e)));
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
                clear_page(pl1e);
                l2e_write(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                             __PAGE_HYPERVISOR));
            }
            else if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
            {
                pl1e = alloc_xen_pagetable();
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    l1e_write(&pl1e[i],
                              l1e_from_pfn(l2e_get_pfn(*pl2e) + i,
                                           l2e_get_flags(*pl2e) & ~_PAGE_PSE));
                l2e_write(pl2e, l2e_from_pfn(virt_to_mfn(pl1e),
                                             __PAGE_HYPERVISOR));
                local_flush_tlb_pge();
            }

            pl1e  = l2e_to_l1e(*pl2e) + l1_table_offset(virt);
            ol1e  = *pl1e;
            l1e_write(pl1e, l1e_from_pfn(mfn, flags));
            if ( (l1e_get_flags(ol1e) & _PAGE_PRESENT) )
                local_flush_tlb_one(virt);

            virt    += 1UL << L1_PAGETABLE_SHIFT;
            mfn     += 1UL;
            nr_mfns -= 1UL;
        }
    }

    return 0;
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
    map_pages_to_xen(
        PAGE_OFFSET, 0, xenheap_phys_end >> PAGE_SHIFT,
        __PAGE_HYPERVISOR|MAP_SMALL_PAGES);
}

static void __memguard_change_range(void *p, unsigned long l, int guard)
{
    unsigned long _p = (unsigned long)p;
    unsigned long _l = (unsigned long)l;
    unsigned long flags = __PAGE_HYPERVISOR | MAP_SMALL_PAGES;

    /* Ensure we are dealing with a page-aligned whole number of pages. */
    ASSERT((_p&PAGE_MASK) != 0);
    ASSERT((_l&PAGE_MASK) != 0);
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
    BUILD_BUG_ON((DEBUG_STACK_SIZE + PAGE_SIZE) > STACK_SIZE);
    p = (void *)((unsigned long)p + STACK_SIZE - DEBUG_STACK_SIZE - PAGE_SIZE);
    memguard_guard_range(p, PAGE_SIZE);
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
