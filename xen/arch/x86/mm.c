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
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/x86_emulate.h>
#include <public/memory.h>

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                           \
  printk("DOM%u: (file=mm.c, line=%d) " _f "\n", \
         current->domain->domain_id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

static void free_l2_table(struct page_info *page);
static void free_l1_table(struct page_info *page);

static int mod_l2_entry(l2_pgentry_t *, l2_pgentry_t, unsigned long,
                        unsigned long type);
static int mod_l1_entry(l1_pgentry_t *, l1_pgentry_t);

/* Used to defer flushing of memory structures. */
static struct {
#define DOP_FLUSH_TLB      (1<<0) /* Flush the local TLB.                    */
#define DOP_FLUSH_ALL_TLBS (1<<1) /* Flush TLBs of all VCPUs of current dom. */
#define DOP_RELOAD_LDT     (1<<2) /* Reload the LDT shadow mapping.          */
    unsigned int   deferred_ops;
    /* If non-NULL, specifies a foreign subject domain for some operations. */
    struct domain *foreign;
} __cacheline_aligned percpu_info[NR_CPUS];

/*
 * Returns the current foreign domain; defaults to the currently-executing
 * domain if a foreign override hasn't been specified.
 */
#define FOREIGNDOM (percpu_info[smp_processor_id()].foreign ?: current->domain)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
static struct domain *dom_xen, *dom_io;

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long max_page;
unsigned long total_pages;

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

    memset(percpu_info, 0, sizeof(percpu_info));

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain();
    spin_lock_init(&dom_xen->page_alloc_lock);
    atomic_set(&dom_xen->refcnt, 1);
    dom_xen->domain_id = DOMID_XEN;

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain();
    spin_lock_init(&dom_io->page_alloc_lock);
    atomic_set(&dom_io->refcnt, 1);
    dom_io->domain_id = DOMID_IO;

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

void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT(page->count_info == 0);
    page->count_info |= PGC_allocated | 1;

    if ( unlikely(d->xenheap_pages++ == 0) )
        get_knownalive_domain(d);
    list_add_tail(&page->list, &d->xenpage_list);

    spin_unlock(&d->page_alloc_lock);
}

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

void write_ptbase(struct vcpu *v)
{
    write_cr3(pagetable_get_paddr(v->arch.monitor_table));
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
        v->arch.perdomain_ptes[i] = l1e_empty();
        page = mfn_to_page(pfn);
        ASSERT_PAGE_IS_TYPE(page, PGT_ldt_page);
        ASSERT_PAGE_IS_DOMAIN(page, v->domain);
        put_page_and_type(page);
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    percpu_info[v->processor].deferred_ops |= DOP_FLUSH_TLB | DOP_RELOAD_LDT;
}


static int alloc_segdesc_page(struct page_info *page)
{
    struct desc_struct *descs;
    int i;

    descs = map_domain_page(page_to_mfn(page));

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(&descs[i])) )
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
    int res;

#if defined(__x86_64__)
    /* If in user mode, switch to kernel mode just to read LDT mapping. */
    int user_mode = !(v->arch.flags & TF_kernel_mode);
#define TOGGLE_MODE() if ( user_mode ) toggle_guest_mode(v)
#elif defined(__i386__)
#define TOGGLE_MODE() ((void)0)
#endif

    BUG_ON(unlikely(in_irq()));

    shadow_sync_va(v, gva);

    TOGGLE_MODE();
    __copy_from_user(&l1e, &linear_pg_table[l1_linear_offset(gva)],
                     sizeof(l1e));
    TOGGLE_MODE();

    if ( unlikely(!(l1e_get_flags(l1e) & _PAGE_PRESENT)) )
        return 0;

    gmfn = l1e_get_pfn(l1e);
    mfn = gmfn_to_mfn(d, gmfn);
    if ( unlikely(!VALID_MFN(mfn)) )
        return 0;

    res = get_page_and_type(mfn_to_page(mfn), d, PGT_ldt_page);

    if ( !res && unlikely(shadow_mode_refcounts(d)) )
    {
        shadow_lock(d);
        shadow_remove_all_write_access(d, gmfn, mfn);
        res = get_page_and_type(mfn_to_page(mfn), d, PGT_ldt_page);
        shadow_unlock(d);
    }

    if ( unlikely(!res) )
        return 0;

    nl1e = l1e_from_pfn(mfn, l1e_get_flags(l1e) | _PAGE_RW);

    v->arch.perdomain_ptes[off + 16] = nl1e;
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
static int 
get_linear_pagetable(
    root_pgentry_t re, unsigned long re_pfn, struct domain *d)
{
    unsigned long x, y;
    struct page_info *page;
    unsigned long pfn;

    ASSERT( !shadow_mode_refcounts(d) );

    if ( (root_get_flags(re) & _PAGE_RW) )
    {
        MEM_LOG("Attempt to create linear p.t. with write perms");
        return 0;
    }

    if ( (pfn = root_get_pfn(re)) != re_pfn )
    {
        /* Make sure the mapped frame belongs to the correct domain. */
        if ( unlikely(!get_page_from_pagenr(pfn, d)) )
            return 0;

        /*
         * Make sure that the mapped frame is an already-validated L2 table. 
         * If so, atomically increment the count (checking for overflow).
         */
        page = mfn_to_page(pfn);
        y = page->u.inuse.type_info;
        do {
            x = y;
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||
                 unlikely((x & (PGT_type_mask|PGT_validated)) != 
                          (PGT_root_page_table|PGT_validated)) )
            {
                put_page(page);
                return 0;
            }
        }
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );
    }

    return 1;
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
            MEM_LOG("Non-privileged attempt to map I/O space %08lx", mfn);
            return 0;
        }

        /* No reference counting for out-of-range I/O pages. */
        if ( !mfn_valid(mfn) )
            return 1;

        d = dom_io;
    }

    okay = ((l1e_get_flags(l1e) & _PAGE_RW) ?
            get_page_and_type(page, d, PGT_writable_page) :
            get_page(page, d));
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
static int 
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn,
    struct domain *d, unsigned long vaddr)
{
    int rc;

    ASSERT(!shadow_mode_refcounts(d));

    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L2 flags %x", l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return 0;
    }

    vaddr >>= L2_PAGETABLE_SHIFT;
    vaddr <<= PGT_va_shift;
    rc = get_page_and_type_from_pagenr(
        l2e_get_pfn(l2e), PGT_l1_page_table | vaddr, d);
#if CONFIG_PAGING_LEVELS == 2
    if ( unlikely(!rc) )
        rc = get_linear_pagetable(l2e, pfn, d);
#endif
    return rc;
}


#if CONFIG_PAGING_LEVELS >= 3
static int 
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn,
    struct domain *d, unsigned long vaddr)
{
    int rc;

    ASSERT(!shadow_mode_refcounts(d));

    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3e_get_flags(l3e) & L3_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L3 flags %x", l3e_get_flags(l3e) & L3_DISALLOW_MASK);
        return 0;
    }

    vaddr >>= L3_PAGETABLE_SHIFT;
    vaddr <<= PGT_va_shift;
    rc = get_page_and_type_from_pagenr(
        l3e_get_pfn(l3e),
        PGT_l2_page_table | vaddr, d);
#if CONFIG_PAGING_LEVELS == 3
    if ( unlikely(!rc) )
        rc = get_linear_pagetable(l3e, pfn, d);
#endif
    return rc;
}
#endif /* 3 level */

#if CONFIG_PAGING_LEVELS >= 4
static int 
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, 
    struct domain *d, unsigned long vaddr)
{
    int rc;

    ASSERT( !shadow_mode_refcounts(d) );

    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4e_get_flags(l4e) & L4_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L4 flags %x", l4e_get_flags(l4e) & L4_DISALLOW_MASK);
        return 0;
    }

    vaddr >>= L4_PAGETABLE_SHIFT;
    vaddr <<= PGT_va_shift;
    rc = get_page_and_type_from_pagenr(
        l4e_get_pfn(l4e), 
        PGT_l3_page_table | vaddr, d);

    if ( unlikely(!rc) )
        rc = get_linear_pagetable(l4e, pfn, d);

    return rc;
}
#endif /* 4 level */


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

    if ( l1e_get_flags(l1e) & _PAGE_RW )
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
        put_page_and_type(mfn_to_page(l2e_get_pfn(l2e)));
}


#if CONFIG_PAGING_LEVELS >= 3
static void put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn)
{
    if ( (l3e_get_flags(l3e) & _PAGE_PRESENT) && 
         (l3e_get_pfn(l3e) != pfn) )
        put_page_and_type(mfn_to_page(l3e_get_pfn(l3e)));
}
#endif

#if CONFIG_PAGING_LEVELS >= 4
static void put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn)
{
    if ( (l4e_get_flags(l4e) & _PAGE_PRESENT) && 
         (l4e_get_pfn(l4e) != pfn) )
        put_page_and_type(mfn_to_page(l4e_get_pfn(l4e)));
}
#endif

static int alloc_l1_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l1_pgentry_t  *pl1e;
    int            i;

    ASSERT(!shadow_mode_refcounts(d));

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) &&
             unlikely(!get_page_from_l1e(pl1e[i], d)) )
            goto fail;

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

#ifdef CONFIG_X86_PAE
static int create_pae_xen_mappings(l3_pgentry_t *pl3e)
{
    struct page_info *page;
    l2_pgentry_t    *pl2e;
    l3_pgentry_t     l3e3;
    int              i;

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
     *  1. Cannot appear in slots != 3 because the page would then then have
     *     unknown va backpointer, which get_page_type() explicitly disallows.
     *  2. Cannot appear in another page table's L3:
     *     a. alloc_l3_table() calls this function and this check will fail
     *     b. mod_l3_entry() disallows updates to slot 3 in an existing table
     */
    page = l3e_get_page(l3e3);
    BUG_ON(page->u.inuse.type_info & PGT_pinned);
    BUG_ON((page->u.inuse.type_info & PGT_count_mask) == 0);
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        MEM_LOG("PAE L3 3rd slot is shared");
        return 0;
    }

    /* Xen private mappings. */
    pl2e = map_domain_page(l3e_get_pfn(l3e3));
    memcpy(&pl2e[L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1)],
           &idle_pg_table_l2[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        pl2e[l2_table_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_page(
                virt_to_page(page_get_owner(page)->arch.mm_perdomain_pt) + i,
                __PAGE_HYPERVISOR);
    for ( i = 0; i < (LINEARPT_MBYTES >> (L2_PAGETABLE_SHIFT - 20)); i++ )
        pl2e[l2_table_offset(LINEAR_PT_VIRT_START) + i] =
            (l3e_get_flags(pl3e[i]) & _PAGE_PRESENT) ?
            l2e_from_pfn(l3e_get_pfn(pl3e[i]), __PAGE_HYPERVISOR) :
        l2e_empty();
    unmap_domain_page(pl2e);

    return 1;
}

static inline int l1_backptr(
    unsigned long *backptr, unsigned long offset_in_l2, unsigned long l2_type)
{
    unsigned long l2_backptr = l2_type & PGT_va_mask;
    BUG_ON(l2_backptr == PGT_va_unknown);
    if ( l2_backptr == PGT_va_mutable )
        return 0;
    *backptr = 
        ((l2_backptr >> PGT_va_shift) << L3_PAGETABLE_SHIFT) | 
        (offset_in_l2 << L2_PAGETABLE_SHIFT);
    return 1;
}

#elif CONFIG_X86_64
# define create_pae_xen_mappings(pl3e) (1)

static inline int l1_backptr(
    unsigned long *backptr, unsigned long offset_in_l2, unsigned long l2_type)
{
    unsigned long l2_backptr = l2_type & PGT_va_mask;
    BUG_ON(l2_backptr == PGT_va_unknown);

    *backptr = ((l2_backptr >> PGT_va_shift) << L3_PAGETABLE_SHIFT) | 
        (offset_in_l2 << L2_PAGETABLE_SHIFT);
    return 1;
}

static inline int l2_backptr(
    unsigned long *backptr, unsigned long offset_in_l3, unsigned long l3_type)
{
    unsigned long l3_backptr = l3_type & PGT_va_mask;
    BUG_ON(l3_backptr == PGT_va_unknown);

    *backptr = ((l3_backptr >> PGT_va_shift) << L4_PAGETABLE_SHIFT) | 
        (offset_in_l3 << L3_PAGETABLE_SHIFT);
    return 1;
}

static inline int l3_backptr(
    unsigned long *backptr, unsigned long offset_in_l4, unsigned long l4_type)
{
    unsigned long l4_backptr = l4_type & PGT_va_mask;
    BUG_ON(l4_backptr == PGT_va_unknown);

    *backptr = (offset_in_l4 << L4_PAGETABLE_SHIFT);
    return 1;
}
#else
# define create_pae_xen_mappings(pl3e) (1)
# define l1_backptr(bp,l2o,l2t) \
    ({ *(bp) = (unsigned long)(l2o) << L2_PAGETABLE_SHIFT; 1; })
#endif

static int alloc_l2_table(struct page_info *page, unsigned long type)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    unsigned long  vaddr;
    l2_pgentry_t  *pl2e;
    int            i;

    /* See the code in shadow_promote() to understand why this is here. */
    if ( (PGT_base_page_table == PGT_l2_page_table) &&
         unlikely(shadow_mode_refcounts(d)) )
        return 1;
    ASSERT(!shadow_mode_refcounts(d));
    
    pl2e = map_domain_page(pfn);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( !l1_backptr(&vaddr, i, type) )
            goto fail;
        if ( is_guest_l2_slot(type, i) &&
             unlikely(!get_page_from_l2e(pl2e[i], pfn, d, vaddr)) )
            goto fail;
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
        if ( is_guest_l2_slot(type, i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_page(pl2e);
    return 0;
}


#if CONFIG_PAGING_LEVELS >= 3
static int alloc_l3_table(struct page_info *page, unsigned long type)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    unsigned long  vaddr;
    l3_pgentry_t  *pl3e;
    int            i;

    ASSERT(!shadow_mode_refcounts(d));

#ifdef CONFIG_X86_PAE
    if ( pfn >= 0x100000 )
    {
        MEM_LOG("PAE pgd must be below 4GB (0x%lx >= 0x100000)", pfn);
        return 0;
    }
#endif

    pl3e = map_domain_page(pfn);
    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
    {
#if CONFIG_PAGING_LEVELS >= 4
        if ( !l2_backptr(&vaddr, i, type) )
            goto fail;
#else
        vaddr = (unsigned long)i << L3_PAGETABLE_SHIFT;
#endif
        if ( is_guest_l3_slot(i) &&
             unlikely(!get_page_from_l3e(pl3e[i], pfn, d, vaddr)) )
            goto fail;
    }

    if ( !create_pae_xen_mappings(pl3e) )
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
#define alloc_l3_table(page, type) (0)
#endif

#if CONFIG_PAGING_LEVELS >= 4
static int alloc_l4_table(struct page_info *page, unsigned long type)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_mfn(page);
    l4_pgentry_t  *pl4e = page_to_virt(page);
    unsigned long vaddr;
    int            i;

    /* See the code in shadow_promote() to understand why this is here. */
    if ( (PGT_base_page_table == PGT_l4_page_table) &&
         shadow_mode_refcounts(d) )
        return 1;
    ASSERT(!shadow_mode_refcounts(d));

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
    {
        if ( !l3_backptr(&vaddr, i, type) )
            goto fail;

        if ( is_guest_l4_slot(i) &&
             unlikely(!get_page_from_l4e(pl4e[i], pfn, d, vaddr)) )
            goto fail;
    }

    /* Xen private mappings. */
    memcpy(&pl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));
    pl4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_pfn(pfn, __PAGE_HYPERVISOR);
    pl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_page(
            virt_to_page(page_get_owner(page)->arch.mm_perdomain_l3),
            __PAGE_HYPERVISOR);

    return 1;

 fail:
    MEM_LOG("Failure in alloc_l4_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l4_slot(i) )
            put_page_from_l4e(pl4e[i], pfn);

    return 0;
}
#else
#define alloc_l4_table(page, type) (0)
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
    unsigned long pfn = page_to_mfn(page);
    l2_pgentry_t *pl2e;
    int i;

    pl2e = map_domain_page(pfn);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l2_slot(page->u.inuse.type_info, i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_page(pl2e);
}


#if CONFIG_PAGING_LEVELS >= 3

static void free_l3_table(struct page_info *page)
{
    unsigned long pfn = page_to_mfn(page);
    l3_pgentry_t *pl3e;
    int           i;

    pl3e = map_domain_page(pfn);

    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l3_slot(i) )
            put_page_from_l3e(pl3e[i], pfn);

    unmap_domain_page(pl3e);
}

#endif

#if CONFIG_PAGING_LEVELS >= 4

static void free_l4_table(struct page_info *page)
{
    unsigned long pfn = page_to_mfn(page);
    l4_pgentry_t *pl4e = page_to_virt(page);
    int           i;

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l4_slot(i) )
            put_page_from_l4e(pl4e[i], pfn);
}

#endif

static inline int update_l1e(l1_pgentry_t *pl1e, 
                             l1_pgentry_t  ol1e, 
                             l1_pgentry_t  nl1e)
{
    intpte_t o = l1e_get_intpte(ol1e);
    intpte_t n = l1e_get_intpte(nl1e);

    if ( unlikely(cmpxchg_user(pl1e, o, n) != 0) ||
         unlikely(o != l1e_get_intpte(ol1e)) )
    {
        MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte
                ": saw %" PRIpte,
                l1e_get_intpte(ol1e),
                l1e_get_intpte(nl1e),
                o);
        return 0;
    }
    return 1;
}


/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e)
{
    l1_pgentry_t ol1e;
    struct domain *d = current->domain;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return 0;

    if ( unlikely(shadow_mode_refcounts(d)) )
        return update_l1e(pl1e, ol1e, nl1e);

    if ( l1e_get_flags(nl1e) & _PAGE_PRESENT )
    {
        if ( unlikely(l1e_get_flags(nl1e) & L1_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L1 flags %x",
                    l1e_get_flags(nl1e) & L1_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping, r/w and presence. */
        if ( !l1e_has_changed(ol1e, nl1e, _PAGE_RW | _PAGE_PRESENT))
            return update_l1e(pl1e, ol1e, nl1e);

        if ( unlikely(!get_page_from_l1e(nl1e, FOREIGNDOM)) )
            return 0;
        
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        {
            put_page_from_l1e(nl1e, d);
            return 0;
        }
    }
    else
    {
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
            return 0;
    }

    put_page_from_l1e(ol1e, d);
    return 1;
}

#define UPDATE_ENTRY(_t,_p,_o,_n) ({                                    \
    intpte_t __o = cmpxchg((intpte_t *)(_p),                            \
                           _t ## e_get_intpte(_o),                      \
                           _t ## e_get_intpte(_n));                     \
    if ( __o != _t ## e_get_intpte(_o) )                                \
        MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte              \
                ": saw %" PRIpte "",                                    \
                (_t ## e_get_intpte(_o)),                               \
                (_t ## e_get_intpte(_n)),                               \
                (__o));                                                 \
    (__o == _t ## e_get_intpte(_o)); })

/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, 
                        l2_pgentry_t nl2e, 
                        unsigned long pfn,
                        unsigned long type)
{
    l2_pgentry_t ol2e;
    unsigned long vaddr = 0;

    if ( unlikely(!is_guest_l2_slot(type,pgentry_ptr_to_slot(pl2e))) )
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
        if ( !l2e_has_changed(ol2e, nl2e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l2, pl2e, ol2e, nl2e);

        if ( unlikely(!l1_backptr(&vaddr, pgentry_ptr_to_slot(pl2e), type)) ||
             unlikely(!get_page_from_l2e(nl2e, pfn, current->domain, vaddr)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
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
                        unsigned long pfn,
                        unsigned long type)
{
    l3_pgentry_t ol3e;
    unsigned long vaddr;
    int okay;

    if ( unlikely(!is_guest_l3_slot(pgentry_ptr_to_slot(pl3e))) )
    {
        MEM_LOG("Illegal L3 update attempt in Xen-private area %p", pl3e);
        return 0;
    }

#ifdef CONFIG_X86_PAE
    /*
     * Disallow updates to final L3 slot. It contains Xen mappings, and it
     * would be a pain to ensure they remain continuously valid throughout.
     */
    if ( pgentry_ptr_to_slot(pl3e) >= 3 )
        return 0;
#endif

    if ( unlikely(__copy_from_user(&ol3e, pl3e, sizeof(ol3e)) != 0) )
        return 0;

    if ( l3e_get_flags(nl3e) & _PAGE_PRESENT )
    {
        if ( unlikely(l3e_get_flags(nl3e) & L3_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L3 flags %x",
                    l3e_get_flags(nl3e) & L3_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if (!l3e_has_changed(ol3e, nl3e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l3, pl3e, ol3e, nl3e);

#if CONFIG_PAGING_LEVELS >= 4
        if ( unlikely(!l2_backptr(&vaddr, pgentry_ptr_to_slot(pl3e), type)) ||
             unlikely(!get_page_from_l3e(nl3e, pfn, current->domain, vaddr)) )
            return 0; 
#else
        vaddr = (((unsigned long)pl3e & ~PAGE_MASK) / sizeof(l3_pgentry_t))
            << L3_PAGETABLE_SHIFT;
        if ( unlikely(!get_page_from_l3e(nl3e, pfn, current->domain, vaddr)) )
            return 0;
#endif

        if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e)) )
        {
            put_page_from_l3e(nl3e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e)) )
    {
        return 0;
    }

    okay = create_pae_xen_mappings(pl3e);
    BUG_ON(!okay);

    put_page_from_l3e(ol3e, pfn);
    return 1;
}

#endif

#if CONFIG_PAGING_LEVELS >= 4

/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e, 
                        l4_pgentry_t nl4e, 
                        unsigned long pfn,
                        unsigned long type)
{
    l4_pgentry_t ol4e;
    unsigned long vaddr;

    if ( unlikely(!is_guest_l4_slot(pgentry_ptr_to_slot(pl4e))) )
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

        /* Fast path for identical mapping and presence. */
        if (!l4e_has_changed(ol4e, nl4e, _PAGE_PRESENT))
            return UPDATE_ENTRY(l4, pl4e, ol4e, nl4e);

        if ( unlikely(!l3_backptr(&vaddr, pgentry_ptr_to_slot(pl4e), type)) ||
             unlikely(!get_page_from_l4e(nl4e, pfn, current->domain, vaddr)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e)) )
        {
            put_page_from_l4e(nl4e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e)) )
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

    if ( owner != NULL )
        mark_dirty(owner, page_to_mfn(page));

    switch ( type & PGT_type_mask )
    {
    case PGT_l1_page_table:
        return alloc_l1_table(page);
    case PGT_l2_page_table:
        return alloc_l2_table(page, type);
    case PGT_l3_page_table:
        return alloc_l3_table(page, type);
    case PGT_l4_page_table:
        return alloc_l4_table(page, type);
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
        percpu_info[smp_processor_id()].deferred_ops |= DOP_FLUSH_ALL_TLBS;

        if ( unlikely(shadow_mode_enabled(owner)) )
        {
            /* Raw page tables are rewritten during save/restore. */
            if ( !shadow_mode_translate(owner) )
                mark_dirty(owner, page_to_mfn(page));

            if ( shadow_mode_refcounts(owner) )
                return;

            gmfn = mfn_to_gmfn(owner, page_to_mfn(page));
            ASSERT(VALID_M2P(gmfn));
            remove_shadow(owner, gmfn, type & PGT_type_mask);
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

        /*
         * The page should always be validated while a reference is held. The 
         * exception is during domain destruction, when we forcibly invalidate 
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) || 
               test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. Races are harmless. */
            page->tlbflush_timestamp = tlbflush_current_time();
            
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
        }
        else if ( unlikely(((nx & (PGT_pinned | PGT_count_mask)) == 
                            (PGT_pinned | 1)) &&
                           ((nx & PGT_type_mask) != PGT_writable_page)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, unsigned long type)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

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
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                if ( (x & PGT_type_mask) != (type & PGT_type_mask) )
                {
                    /*
                     * On type change we check to flush stale TLB
                     * entries. This may be unnecessary (e.g., page
                     * was GDT/LDT) but those circumstances should be
                     * very rare.
                     */
                    cpumask_t mask =
                        page_get_owner(page)->domain_dirty_cpumask;
                    tlbflush_filter(mask, page->tlbflush_timestamp);

                    if ( unlikely(!cpus_empty(mask)) )
                    {
                        perfc_incrc(need_flush_tlb_flush);
                        flush_tlb_mask(mask);
                    }
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else
        {
            if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
            {
                if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
                {
                    if ( current->domain == page_get_owner(page) )
                    {
                        /*
                         * This ensures functions like set_gdt() see up-to-date
                         * type info without needing to clean up writable p.t.
                         * state on the fast path.
                         */
                        LOCK_BIGLOCK(current->domain);
                        cleanup_writable_pagetable(current->domain);
                        y = page->u.inuse.type_info;
                        UNLOCK_BIGLOCK(current->domain);
                        /* Can we make progress now? */
                        if ( ((y & PGT_type_mask) == (type & PGT_type_mask)) ||
                             ((y & PGT_count_mask) == 0) )
                            goto again;
                    }
                    if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                         ((type & PGT_type_mask) != PGT_l1_page_table) )
                        MEM_LOG("Bad type (saw %" PRtype_info
                                " != exp %" PRtype_info ") "
                                "for mfn %lx (pfn %lx)",
                                x, type, page_to_mfn(page),
                                get_gpfn_from_mfn(page_to_mfn(page)));
                    return 0;
                }
                else if ( (x & PGT_va_mask) == PGT_va_mutable )
                {
                    /* The va backpointer is mutable, hence we update it. */
                    nx &= ~PGT_va_mask;
                    nx |= type; /* we know the actual type is correct */
                }
                else if ( ((type & PGT_va_mask) != PGT_va_mutable) &&
                          ((type & PGT_va_mask) != (x & PGT_va_mask)) )
                {
#ifdef CONFIG_X86_PAE
                    /* We use backptr as extra typing. Cannot be unknown. */
                    if ( (type & PGT_type_mask) == PGT_l2_page_table )
                        return 0;
#endif
                    /* This table is possibly mapped at multiple locations. */
                    nx &= ~PGT_va_mask;
                    nx |= PGT_va_unknown;
                }
            }
            if ( unlikely(!(x & PGT_validated)) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                    cpu_relax();
                goto again;
            }
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

    ASSERT(writable_pagetable_in_sync(d));

    if ( shadow_mode_refcounts(d) )
    {
        okay = get_page_from_pagenr(mfn, d);
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while installing new baseptr %lx", mfn);
            return 0;
        }
    }
    else
    {
        okay = get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d);
        if ( unlikely(!okay) )
        {
            /* Switch to idle pagetable: this VCPU has no active p.t. now. */
            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = mk_pagetable(0);
            update_pagetables(v);
            write_cr3(__pa(idle_pg_table));
            if ( old_base_mfn != 0 )
                put_page_and_type(mfn_to_page(old_base_mfn));

            /* Retry the validation with no active p.t. for this VCPU. */
            okay = get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d);
            if ( !okay )
            {
                /* Failure here is unrecoverable: the VCPU has no pagetable! */
                MEM_LOG("Fatal error while installing new baseptr %lx", mfn);
                domain_crash(d);
                percpu_info[v->processor].deferred_ops = 0;
                return 0;
            }
        }
    }

    invalidate_shadow_ldt(v);

    old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
    v->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
    update_pagetables(v); /* update shadow_table and monitor_table */

    write_ptbase(v);

    if ( likely(old_base_mfn != 0) )
    {
        if ( shadow_mode_refcounts(d) )
            put_page(mfn_to_page(old_base_mfn));
        else
            put_page_and_type(mfn_to_page(old_base_mfn));
    }

    /* CR3 also holds a ref to its shadow... */
    if ( shadow_mode_enabled(d) )
    {
        if ( v->arch.monitor_shadow_ref )
            put_shadow_ref(v->arch.monitor_shadow_ref);
        v->arch.monitor_shadow_ref =
            pagetable_get_pfn(v->arch.monitor_table);
        ASSERT(!page_get_owner(mfn_to_page(v->arch.monitor_shadow_ref)));
        get_shadow_ref(v->arch.monitor_shadow_ref);
    }

    return 1;
}

static void process_deferred_ops(unsigned int cpu)
{
    unsigned int deferred_ops;
    struct domain *d = current->domain;

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( deferred_ops & (DOP_FLUSH_ALL_TLBS|DOP_FLUSH_TLB) )
    {
        if ( shadow_mode_enabled(d) )
            shadow_sync_all(d);
        if ( deferred_ops & DOP_FLUSH_ALL_TLBS )
            flush_tlb_mask(d->domain_dirty_cpumask);
        else
            local_flush_tlb();
    }

    if ( deferred_ops & DOP_RELOAD_LDT )
        (void)map_ldt_shadow_page(0);

    if ( unlikely(percpu_info[cpu].foreign != NULL) )
    {
        put_domain(percpu_info[cpu].foreign);
        percpu_info[cpu].foreign = NULL;
    }
}

static int set_foreigndom(unsigned int cpu, domid_t domid)
{
    struct domain *e, *d = current->domain;
    int okay = 1;

    ASSERT(percpu_info[cpu].foreign == NULL);

    if ( likely(domid == DOMID_SELF) )
        goto out;

    if ( domid == d->domain_id )
    {
        MEM_LOG("Dom %u tried to specify itself as foreign domain",
                d->domain_id);
        okay = 0;
    }
    else if ( !IS_PRIV(d) )
    {
        switch ( domid )
        {
        case DOMID_IO:
            get_knownalive_domain(dom_io);
            percpu_info[cpu].foreign = dom_io;
            break;
        default:
            MEM_LOG("Dom %u cannot set foreign dom", d->domain_id);
            okay = 0;
            break;
        }
    }
    else
    {
        percpu_info[cpu].foreign = e = find_domain_by_id(domid);
        if ( e == NULL )
        {
            switch ( domid )
            {
            case DOMID_XEN:
                get_knownalive_domain(dom_xen);
                percpu_info[cpu].foreign = dom_xen;
                break;
            case DOMID_IO:
                get_knownalive_domain(dom_io);
                percpu_info[cpu].foreign = dom_io;
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
    GUEST_HANDLE(mmuext_op_t) uops,
    unsigned int count,
    GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom)
{
    struct mmuext_op op;
    int rc = 0, i = 0, okay, cpu = smp_processor_id();
    unsigned long mfn, type;
    unsigned int done = 0;
    struct page_info *page;
    struct vcpu *v = current;
    struct domain *d = v->domain;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }

    if ( !set_foreigndom(cpu, foreigndom) )
    {
        rc = -ESRCH;
        goto out;
    }

    if ( unlikely(!guest_handle_okay(uops, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

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
        mfn  = op.arg1.mfn;
        page = mfn_to_page(mfn);

        switch ( op.cmd )
        {
        case MMUEXT_PIN_L1_TABLE:
            type = PGT_l1_page_table | PGT_va_mutable;

        pin_page:
            if ( shadow_mode_refcounts(FOREIGNDOM) )
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
            
            break;

#ifndef CONFIG_X86_PAE /* Unsafe on PAE because of Xen-private mappings. */
        case MMUEXT_PIN_L2_TABLE:
            type = PGT_l2_page_table | PGT_va_mutable;
            goto pin_page;
#endif

        case MMUEXT_PIN_L3_TABLE:
            type = PGT_l3_page_table | PGT_va_mutable;
            goto pin_page;

        case MMUEXT_PIN_L4_TABLE:
            type = PGT_l4_page_table | PGT_va_mutable;
            goto pin_page;

        case MMUEXT_UNPIN_TABLE:
            if ( shadow_mode_refcounts(d) )
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
            }
            else
            {
                okay = 0;
                put_page(page);
                MEM_LOG("Mfn %lx not pinned", mfn);
            }
            break;

        case MMUEXT_NEW_BASEPTR:
            mfn = gmfn_to_mfn(current->domain, mfn);
            okay = new_guest_cr3(mfn);
            percpu_info[cpu].deferred_ops &= ~DOP_FLUSH_TLB;
            break;
        
#ifdef __x86_64__
        case MMUEXT_NEW_USER_BASEPTR:
            okay = get_page_and_type_from_pagenr(
                mfn, PGT_root_page_table, d);
            if ( unlikely(!okay) )
            {
                MEM_LOG("Error while installing new mfn %lx", mfn);
            }
            else
            {
                unsigned long old_mfn =
                    pagetable_get_pfn(v->arch.guest_table_user);
                v->arch.guest_table_user = mk_pagetable(mfn << PAGE_SHIFT);
                if ( old_mfn != 0 )
                    put_page_and_type(mfn_to_page(old_mfn));
            }
            break;
#endif
        
        case MMUEXT_TLB_FLUSH_LOCAL:
            percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;
            break;
    
        case MMUEXT_INVLPG_LOCAL:
            if ( shadow_mode_enabled(d) )
                shadow_invlpg(v, op.arg1.linear_addr);
            local_flush_tlb_one(op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            unsigned long vmask;
            cpumask_t     pmask;
            if ( unlikely(get_user(vmask, (unsigned long *)op.arg2.vcpumask)) )
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

            if ( shadow_mode_external(d) )
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
                percpu_info[cpu].deferred_ops &= ~DOP_RELOAD_LDT;
                if ( ents != 0 )
                    percpu_info[cpu].deferred_ops |= DOP_RELOAD_LDT;
            }
            break;
        }

        default:
            MEM_LOG("Invalid extended pt command 0x%x", op.cmd);
            okay = 0;
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        guest_handle_add_offset(uops, 1);
    }

 out:
    process_deferred_ops(cpu);

    /* Add incremental work we have done to the @done output parameter. */
    done += i;
    if ( unlikely(!guest_handle_is_null(pdone)) )
        copy_to_guest(pdone, &done, 1);

    UNLOCK_BIGLOCK(d);
    return rc;
}

int do_mmu_update(
    GUEST_HANDLE(mmu_update_t) ureqs,
    unsigned int count,
    GUEST_HANDLE(uint) pdone,
    unsigned int foreigndom)
{
    struct mmu_update req;
    void *va;
    unsigned long gpfn, gmfn, mfn;
    struct page_info *page;
    int rc = 0, okay = 1, i = 0, cpu = smp_processor_id();
    unsigned int cmd, done = 0;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long type_info;
    struct domain_mmap_cache mapcache, sh_mapcache;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    if ( unlikely(shadow_mode_enabled(d)) )
        check_pagetable(v, "pre-mmu"); /* debug */

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(!guest_handle_is_null(pdone)) )
            (void)copy_from_guest(&done, pdone, 1);
    }

    domain_mmap_cache_init(&mapcache);
    domain_mmap_cache_init(&sh_mapcache);

    if ( !set_foreigndom(cpu, foreigndom) )
    {
        rc = -ESRCH;
        goto out;
    }

    perfc_incrc(calls_to_mmu_update); 
    perfc_addc(num_page_updates, count);
    perfc_incr_histo(bpt_updates, count, PT_UPDATES);

    if ( unlikely(!guest_handle_okay(ureqs, count)) )
    {
        rc = -EFAULT;
        goto out;
    }

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
                ASSERT( !shadow_mode_refcounts(d) );
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    l1_pgentry_t l1e;

                    /* FIXME: doesn't work with PAE */
                    l1e = l1e_from_intpte(req.val);
                    okay = mod_l1_entry(va, l1e);
                    if ( okay && unlikely(shadow_mode_enabled(d)) )
                        shadow_l1_normal_pt_update(
                            d, req.ptr, l1e, &sh_mapcache);
                    put_page_type(page);
                }
                break;
            case PGT_l2_page_table:
                ASSERT( !shadow_mode_refcounts(d) );
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    l2_pgentry_t l2e;

                    /* FIXME: doesn't work with PAE */
                    l2e = l2e_from_intpte(req.val);
                    okay = mod_l2_entry(
                        (l2_pgentry_t *)va, l2e, mfn, type_info);
                    if ( okay && unlikely(shadow_mode_enabled(d)) )
                        shadow_l2_normal_pt_update(
                            d, req.ptr, l2e, &sh_mapcache);
                    put_page_type(page);
                }
                break;
#if CONFIG_PAGING_LEVELS >= 3
            case PGT_l3_page_table:
                ASSERT( !shadow_mode_refcounts(d) );
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    l3_pgentry_t l3e;

                    /* FIXME: doesn't work with PAE */
                    l3e = l3e_from_intpte(req.val);
                    okay = mod_l3_entry(va, l3e, mfn, type_info);
                    if ( okay && unlikely(shadow_mode_enabled(d)) )
                        shadow_l3_normal_pt_update(
                            d, req.ptr, l3e, &sh_mapcache);
                    put_page_type(page);
                }
                break;
#endif
#if CONFIG_PAGING_LEVELS >= 4
            case PGT_l4_page_table:
                ASSERT( !shadow_mode_refcounts(d) );
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    l4_pgentry_t l4e;

                    l4e = l4e_from_intpte(req.val);
                    okay = mod_l4_entry(va, l4e, mfn, type_info);
                    if ( okay && unlikely(shadow_mode_enabled(d)) )
                        shadow_l4_normal_pt_update(
                            d, req.ptr, l4e, &sh_mapcache);
                    put_page_type(page);
                }
                break;
#endif
            default:
                if ( likely(get_page_type(page, PGT_writable_page)) )
                {
                    if ( shadow_mode_enabled(d) )
                    {
                        shadow_lock(d);

                        __mark_dirty(d, mfn);

                        if ( page_is_page_table(page) &&
                             !page_out_of_sync(page) )
                        {
                            shadow_mark_mfn_out_of_sync(v, gmfn, mfn);
                        }
                    }

                    *(intpte_t *)va = req.val;
                    okay = 1;

                    if ( shadow_mode_enabled(d) )
                        shadow_unlock(d);

                    put_page_type(page);
                }
                break;
            }

            unmap_domain_page_with_cache(va, &mapcache);

            put_page(page);
            break;

        case MMU_MACHPHYS_UPDATE:

            if ( shadow_mode_translate(FOREIGNDOM) )
            {
                MEM_LOG("can't mutate m2p table of translate mode guest");
                break;
            }

            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            if ( unlikely(!get_page_from_pagenr(mfn, FOREIGNDOM)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            set_gpfn_from_mfn(mfn, gpfn);
            okay = 1;

            mark_dirty(FOREIGNDOM, mfn);

            put_page(mfn_to_page(mfn));
            break;

        default:
            MEM_LOG("Invalid page update command %x", cmd);
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        guest_handle_add_offset(ureqs, 1);
    }

 out:
    domain_mmap_cache_destroy(&mapcache);
    domain_mmap_cache_destroy(&sh_mapcache);

    process_deferred_ops(cpu);

    /* Add incremental work we have done to the @done output parameter. */
    done += i;
    if ( unlikely(!guest_handle_is_null(pdone)) )
        copy_to_guest(pdone, &done, 1);

    if ( unlikely(shadow_mode_enabled(d)) )
        check_pagetable(v, "post-mmu"); /* debug */

    UNLOCK_BIGLOCK(d);
    return rc;
}


static int create_grant_pte_mapping(
    unsigned long pte_addr, l1_pgentry_t _nl1e, struct vcpu *v)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    u32 type_info;
    l1_pgentry_t ol1e;
    struct domain *d = v->domain;

    ASSERT(spin_is_locked(&d->big_lock));
    ASSERT(!shadow_mode_refcounts(d));

    gmfn = pte_addr >> PAGE_SHIFT;
    mfn = gmfn_to_mfn(d, gmfn);

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + (pte_addr & ~PAGE_MASK));
    page = mfn_to_page(mfn);

    type_info = page->u.inuse.type_info;
    if ( ((type_info & PGT_type_mask) != PGT_l1_page_table) ||
         !get_page_type(page, type_info & (PGT_type_mask|PGT_va_mask)) )
    {
        MEM_LOG("Grant map attempted to update a non-L1 page");
        rc = GNTST_general_error;
        goto failed;
    }

    if ( __copy_from_user(&ol1e, (l1_pgentry_t *)va, sizeof(ol1e)) ||
         !update_l1e(va, ol1e, _nl1e) )
    {
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    } 

    put_page_from_l1e(ol1e, d);

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        struct domain_mmap_cache sh_mapcache;
        domain_mmap_cache_init(&sh_mapcache);
        shadow_l1_normal_pt_update(d, pte_addr, _nl1e, &sh_mapcache);
        domain_mmap_cache_destroy(&sh_mapcache);
    }

    put_page_type(page);
 
 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}

static int destroy_grant_pte_mapping(
    unsigned long addr, unsigned long frame, struct domain *d)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gmfn, mfn;
    struct page_info *page;
    u32 type_info;
    l1_pgentry_t ol1e;

    ASSERT(!shadow_mode_refcounts(d));

    gmfn = addr >> PAGE_SHIFT;
    mfn = gmfn_to_mfn(d, gmfn);

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + (addr & ~PAGE_MASK));
    page = mfn_to_page(mfn);

    type_info = page->u.inuse.type_info;
    if ( ((type_info & PGT_type_mask) != PGT_l1_page_table) ||
         !get_page_type(page, type_info & (PGT_type_mask|PGT_va_mask)) )
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
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                (unsigned long)l1e_get_intpte(ol1e), addr, frame);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    /* Delete pagetable entry. */
    if ( unlikely(__put_user(0, (intpte_t *)va)))
    {
        MEM_LOG("Cannot delete PTE entry at %p", va);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        struct domain_mmap_cache sh_mapcache;
        domain_mmap_cache_init(&sh_mapcache);
        shadow_l1_normal_pt_update(d, addr, l1e_empty(), &sh_mapcache);
        domain_mmap_cache_destroy(&sh_mapcache);
    }

    put_page_type(page);

 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}


static int create_grant_va_mapping(
    unsigned long va, l1_pgentry_t _nl1e, struct vcpu *v)
{
    l1_pgentry_t *pl1e, ol1e;
    struct domain *d = v->domain;
    
    ASSERT(spin_is_locked(&d->big_lock));
    ASSERT(!shadow_mode_refcounts(d));

    /*
     * This is actually overkill - we don't need to sync the L1 itself,
     * just everything involved in getting to this L1 (i.e. we need
     * linear_pg_table[l1_linear_offset(va)] to be in sync)...
     */
    __shadow_sync_va(v, va);

    pl1e = &linear_pg_table[l1_linear_offset(va)];

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) ||
         !update_l1e(pl1e, ol1e, _nl1e) )
        return GNTST_general_error;

    put_page_from_l1e(ol1e, d);

    if ( unlikely(shadow_mode_enabled(d)) )
        shadow_do_update_va_mapping(va, _nl1e, v);

    return GNTST_okay;
}

static int destroy_grant_va_mapping(
    unsigned long addr, unsigned long frame)
{
    l1_pgentry_t *pl1e, ol1e;
    
    pl1e = &linear_pg_table[l1_linear_offset(addr)];

    if ( unlikely(__get_user(ol1e.l1, &pl1e->l1) != 0) )
    {
        MEM_LOG("Could not find PTE entry for address %lx", addr);
        return GNTST_general_error;
    }

    /*
     * Check that the virtual address supplied is actually mapped to
     * frame.
     */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                l1e_get_pfn(ol1e), addr, frame);
        return GNTST_general_error;
    }

    /* Delete pagetable entry. */
    if ( unlikely(__put_user(0, &pl1e->l1)) )
    {
        MEM_LOG("Cannot delete PTE entry at %p", (unsigned long *)pl1e);
        return GNTST_general_error;
    }
    
    return 0;
}

int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
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
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    if ( flags & GNTMAP_contains_pte )
        return destroy_grant_pte_mapping(addr, frame, current->domain);
    return destroy_grant_va_mapping(addr, frame);
}

int steal_page_for_grant_transfer(
    struct domain *d, struct page_info *page)
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
            DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u), sd=%p,"
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
    unsigned int   cpu = smp_processor_id();
    unsigned long  vmask, bmap_ptr;
    cpumask_t      pmask;
    int            rc  = 0;

    perfc_incrc(calls_to_update_va);

    if ( unlikely(!__addr_ok(va) && !shadow_mode_external(d)) )
        return -EINVAL;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    if ( unlikely(shadow_mode_enabled(d)) )
        check_pagetable(v, "pre-va"); /* debug */

    if ( unlikely(!mod_l1_entry(&linear_pg_table[l1_linear_offset(va)],
                                val)) )
        rc = -EINVAL;

    if ( likely(rc == 0) && unlikely(shadow_mode_enabled(d)) )
    {
        if ( unlikely(percpu_info[cpu].foreign &&
                      (shadow_mode_translate(d) ||
                       shadow_mode_translate(percpu_info[cpu].foreign))) )
        {
            /*
             * The foreign domain's pfn's are in a different namespace. There's
             * not enough information in just a gpte to figure out how to
             * (re-)shadow this entry.
             */
            domain_crash(d);
        }
    
        rc = shadow_do_update_va_mapping(va, val, v);

        check_pagetable(v, "post-va"); /* debug */
    }

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            if ( unlikely(shadow_mode_enabled(d)) )
                shadow_sync_all(d);
            local_flush_tlb();
            break;
        case UVMF_ALL:
            flush_tlb_mask(d->domain_dirty_cpumask);
            break;
        default:
            if ( unlikely(get_user(vmask, (unsigned long *)bmap_ptr)) )
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
            if ( unlikely(shadow_mode_enabled(d)) )
                shadow_invlpg(current, va);
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

    process_deferred_ops(cpu);
    
    UNLOCK_BIGLOCK(d);

    return rc;
}

int do_update_va_mapping_otherdomain(unsigned long va, u64 val64,
                                     unsigned long flags,
                                     domid_t domid)
{
    unsigned int cpu = smp_processor_id();
    int rc;

    if ( unlikely(!IS_PRIV(current->domain)) )
        return -EPERM;

    if ( !set_foreigndom(cpu, domid) )
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
        v->arch.perdomain_ptes[i] = l1e_empty();
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

    shadow_sync_all(d);

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
        v->arch.perdomain_ptes[i] =
            l1e_from_pfn(frames[i], __PAGE_HYPERVISOR);
    }

    return 0;

 fail:
    while ( i-- > 0 )
        put_page_and_type(mfn_to_page(frames[i]));
    return -EINVAL;
}


long do_set_gdt(GUEST_HANDLE(ulong) frame_list, unsigned int entries)
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

    if ( !VALID_MFN(mfn = gmfn_to_mfn(dom, gmfn)) ||
         (((unsigned int)pa % sizeof(struct desc_struct)) != 0) ||
         !mfn_valid(mfn) ||
         !check_descriptor(&d) )
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

    if ( shadow_mode_enabled(dom) )
    {
        shadow_lock(dom);

        __mark_dirty(dom, mfn);

        if ( page_is_page_table(page) && !page_out_of_sync(page) )
            shadow_mark_mfn_out_of_sync(current, gmfn, mfn);
    }

    /* All is good so make the update. */
    gdt_pent = map_domain_page(mfn);
    memcpy(&gdt_pent[offset], &d, 8);
    unmap_domain_page(gdt_pent);

    if ( shadow_mode_enabled(dom) )
        shadow_unlock(dom);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    UNLOCK_BIGLOCK(dom);

    return ret;
}


long arch_memory_op(int op, GUEST_HANDLE(void) arg)
{
    struct xen_reserved_phys_area xrpa;
    unsigned long pfn;
    struct domain *d;
    unsigned int i;

    switch ( op )
    {
    case XENMEM_reserved_phys_area:
        if ( copy_from_guest(&xrpa, arg, 1) )
            return -EFAULT;

        /* No guest has more than one reserved area. */
        if ( xrpa.idx != 0 )
            return -ESRCH;

        if ( (d = find_domain_by_id(xrpa.domid)) == NULL )
            return -ESRCH;

        /* Only initialised translated guests have a reserved area. */
        if ( !shadow_mode_translate(d) || (d->max_pages == 0) )
        {
            put_domain(d);
            return -ESRCH;
        }

        LOCK_BIGLOCK(d);
        if ( d->arch.first_reserved_pfn == 0 )
        {
            d->arch.first_reserved_pfn = pfn = d->max_pages;
            guest_physmap_add_page(
                d, pfn + 0, virt_to_maddr(d->shared_info) >> PAGE_SHIFT);
            for ( i = 0; i < NR_GRANT_FRAMES; i++ )
                guest_physmap_add_page(
                    d, pfn + 1 + i, gnttab_shared_mfn(d, d->grant_table, i));
        }
        UNLOCK_BIGLOCK(d);

        xrpa.first_gpfn = d->arch.first_reserved_pfn;
        xrpa.nr_gpfns   = 32;

        put_domain(d);

        if ( copy_to_guest(arg, &xrpa, 1) )
            return -EFAULT;

        break;

    default:
        return subarch_memory_op(op, arg);
    }

    return 0;
}


/*************************
 * Writable Pagetables
 */

#ifdef VVERBOSE
int ptwr_debug = 0x0;
#define PTWR_PRINTK(_f, _a...) \
 do { if ( unlikely(ptwr_debug) ) printk( _f , ## _a ); } while ( 0 )
#define PTWR_PRINT_WHICH (which ? 'I' : 'A')
#else
#define PTWR_PRINTK(_f, _a...) ((void)0)
#endif


#ifdef PERF_ARRAYS

/**************** writeable pagetables profiling functions *****************/

#define ptwr_eip_buckets        256

int ptwr_eip_stat_threshold[] = {1, 10, 50, 100, L1_PAGETABLE_ENTRIES};

#define ptwr_eip_stat_thresholdN (sizeof(ptwr_eip_stat_threshold)/sizeof(int))

struct {
    unsigned long eip;
    domid_t       id;
    u32           val[ptwr_eip_stat_thresholdN];
} typedef ptwr_eip_stat_t;

ptwr_eip_stat_t ptwr_eip_stats[ptwr_eip_buckets];

static inline unsigned int ptwr_eip_stat_hash( unsigned long eip, domid_t id )
{
    return (((unsigned long) id) ^ eip ^ (eip>>8) ^ (eip>>16) ^ (eip>24)) % 
        ptwr_eip_buckets;
}

static void ptwr_eip_stat_inc(u32 *n)
{
    int i, j;

    if ( ++(*n) != 0 )
        return;

    *n = ~0;

    /* Re-scale all buckets. */
    for ( i = 0; i <ptwr_eip_buckets; i++ )
        for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
            ptwr_eip_stats[i].val[j] >>= 1;
}

static void ptwr_eip_stat_update(unsigned long eip, domid_t id, int modified)
{
    int i, j, b;

    i = b = ptwr_eip_stat_hash(eip, id);

    do
    {
        if ( !ptwr_eip_stats[i].eip )
        {
            /* doesn't exist */
            ptwr_eip_stats[i].eip = eip;
            ptwr_eip_stats[i].id = id;
            memset(ptwr_eip_stats[i].val,0, sizeof(ptwr_eip_stats[i].val));
        }

        if ( ptwr_eip_stats[i].eip == eip )
        {
            for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
                if ( modified <= ptwr_eip_stat_threshold[j] )
                    break;
            BUG_ON(j >= ptwr_eip_stat_thresholdN);
            ptwr_eip_stat_inc(&ptwr_eip_stats[i].val[j]);
            return;
        }

        i = (i+1) % ptwr_eip_buckets;
    }
    while ( i != b );
   
    printk("ptwr_eip_stat: too many EIPs in use!\n");
    
    ptwr_eip_stat_print();
    ptwr_eip_stat_reset();
}

void ptwr_eip_stat_reset(void)
{
    memset(ptwr_eip_stats, 0, sizeof(ptwr_eip_stats));
}

void ptwr_eip_stat_print(void)
{
    struct domain *e;
    domid_t d;
    int i, j;

    for_each_domain( e )
    {
        d = e->domain_id;

        for ( i = 0; i < ptwr_eip_buckets; i++ )
        {
            if ( ptwr_eip_stats[i].eip && ptwr_eip_stats[i].id != d )
                continue;

            printk("D %d  eip %08lx ",
                   ptwr_eip_stats[i].id, ptwr_eip_stats[i].eip);

            for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
                printk("<=%u %4u \t",
                       ptwr_eip_stat_threshold[j],
                       ptwr_eip_stats[i].val[j]);
            printk("\n");
        }
    }
}

#else /* PERF_ARRAYS */

#define ptwr_eip_stat_update(eip, id, modified) ((void)0)

#endif

/*******************************************************************/

/* Re-validate a given p.t. page, given its prior snapshot */
int revalidate_l1(
    struct domain *d, l1_pgentry_t *l1page, l1_pgentry_t *snapshot)
{
    l1_pgentry_t ol1e, nl1e;
    int modified = 0, i;

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        ol1e = snapshot[i];
        nl1e = l1page[i];

        if ( likely(l1e_get_intpte(ol1e) == l1e_get_intpte(nl1e)) )
            continue;

        /* Update number of entries modified. */
        modified++;

        /*
         * Fast path for PTEs that have merely been write-protected
         * (e.g., during a Unix fork()). A strict reduction in privilege.
         */
        if ( likely(l1e_get_intpte(ol1e) == (l1e_get_intpte(nl1e)|_PAGE_RW)) )
        {
            if ( likely(l1e_get_flags(nl1e) & _PAGE_PRESENT) )
                put_page_type(mfn_to_page(l1e_get_pfn(nl1e)));
            continue;
        }

        if ( unlikely(!get_page_from_l1e(nl1e, d)) )
        {
            /*
             * Make the remaining p.t's consistent before crashing, so the
             * reference counts are correct.
             */
            memcpy(&l1page[i], &snapshot[i],
                   (L1_PAGETABLE_ENTRIES - i) * sizeof(l1_pgentry_t));

            /* Crash the offending domain. */
            MEM_LOG("ptwr: Could not revalidate l1 page");
            domain_crash(d);
            break;
        }
        
        put_page_from_l1e(ol1e, d);
    }

    return modified;
}


/* Flush the given writable p.t. page and write-protect it again. */
void ptwr_flush(struct domain *d, const int which)
{
    unsigned long l1va;
    l1_pgentry_t  *pl1e, pte, *ptep;
    l2_pgentry_t  *pl2e;
    unsigned int   modified;

#ifdef CONFIG_X86_64
    struct vcpu *v = current;
    int user_mode = !(v->arch.flags & TF_kernel_mode);
#endif

    ASSERT(!shadow_mode_enabled(d));

    if ( unlikely(d->arch.ptwr[which].vcpu != current) )
        /* Don't use write_ptbase: it may switch to guest_user on x86/64! */
        write_cr3(pagetable_get_paddr(
            d->arch.ptwr[which].vcpu->arch.guest_table));
    else
        TOGGLE_MODE();

    l1va = d->arch.ptwr[which].l1va;
    ptep = (l1_pgentry_t *)&linear_pg_table[l1_linear_offset(l1va)];

    /*
     * STEP 1. Write-protect the p.t. page so no more updates can occur.
     */

    if ( unlikely(__get_user(pte.l1, &ptep->l1)) )
    {
        MEM_LOG("ptwr: Could not read pte at %p", ptep);
        /*
         * Really a bug. We could read this PTE during the initial fault,
         * and pagetables can't have changed meantime.
         */
        BUG();
    }
    PTWR_PRINTK("[%c] disconnected_l1va at %p is %"PRIpte"\n",
                PTWR_PRINT_WHICH, ptep, l1e_get_intpte(pte));
    l1e_remove_flags(pte, _PAGE_RW);

    /* Write-protect the p.t. page in the guest page table. */
    if ( unlikely(__put_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not update pte at %p", ptep);
        /*
         * Really a bug. We could write this PTE during the initial fault,
         * and pagetables can't have changed meantime.
         */
        BUG();
    }

    /* Ensure that there are no stale writable mappings in any TLB. */
    /* NB. INVLPG is a serialising instruction: flushes pending updates. */
    flush_tlb_one_mask(d->domain_dirty_cpumask, l1va);
    PTWR_PRINTK("[%c] disconnected_l1va at %p now %"PRIpte"\n",
                PTWR_PRINT_WHICH, ptep, l1e_get_intpte(pte));

    /*
     * STEP 2. Validate any modified PTEs.
     */

    if ( likely(d == current->domain) )
    {
        pl1e = map_domain_page(l1e_get_pfn(pte));
        modified = revalidate_l1(d, pl1e, d->arch.ptwr[which].page);
        unmap_domain_page(pl1e);
        perfc_incr_histo(wpt_updates, modified, PT_UPDATES);
        ptwr_eip_stat_update(d->arch.ptwr[which].eip, d->domain_id, modified);
        d->arch.ptwr[which].prev_nr_updates = modified;
    }
    else
    {
        /*
         * Must make a temporary global mapping, since we are running in the
         * wrong address space, so no access to our own mapcache.
         */
        pl1e = map_domain_page_global(l1e_get_pfn(pte));
        modified = revalidate_l1(d, pl1e, d->arch.ptwr[which].page);
        unmap_domain_page_global(pl1e);
    }

    /*
     * STEP 3. Reattach the L1 p.t. page into the current address space.
     */

    if ( which == PTWR_PT_ACTIVE )
    {
        pl2e = &__linear_l2_table[d->arch.ptwr[which].l2_idx];
        l2e_add_flags(*pl2e, _PAGE_PRESENT); 
    }

    /*
     * STEP 4. Final tidy-up.
     */

    d->arch.ptwr[which].l1va = 0;

    if ( unlikely(d->arch.ptwr[which].vcpu != current) )
        write_ptbase(current);
    else 
        TOGGLE_MODE();
}

static int ptwr_emulated_update(
    unsigned long addr,
    paddr_t old,
    paddr_t val,
    unsigned int bytes,
    unsigned int do_cmpxchg)
{
    unsigned long pfn, l1va;
    struct page_info *page;
    l1_pgentry_t pte, ol1e, nl1e, *pl1e;
    struct domain *d = current->domain;

    /* Aligned access only, thank you. */
    if ( !access_ok(addr, bytes) || ((addr & (bytes-1)) != 0) )
    {
        MEM_LOG("ptwr_emulate: Unaligned or bad size ptwr access (%d, %lx)",
                bytes, addr);
        return X86EMUL_UNHANDLEABLE;
    }

    /* Turn a sub-word access into a full-word access. */
    if ( bytes != sizeof(paddr_t) )
    {
        int           rc;
        paddr_t    full;
        unsigned int  offset = addr & (sizeof(paddr_t)-1);

        /* Align address; read full word. */
        addr &= ~(sizeof(paddr_t)-1);
        if ( (rc = x86_emulate_read_std(addr, (unsigned long *)&full,
                                        sizeof(paddr_t))) )
            return rc; 
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

    /*
     * We must not emulate an update to a PTE that is temporarily marked
     * writable by the batched ptwr logic, else we can corrupt page refcnts! 
     */
    if ( ((l1va = d->arch.ptwr[PTWR_PT_ACTIVE].l1va) != 0) &&
         (l1_linear_offset(l1va) == l1_linear_offset(addr)) )
        ptwr_flush(d, PTWR_PT_ACTIVE);
    if ( ((l1va = d->arch.ptwr[PTWR_PT_INACTIVE].l1va) != 0) &&
         (l1_linear_offset(l1va) == l1_linear_offset(addr)) )
        ptwr_flush(d, PTWR_PT_INACTIVE);

    /* Read the PTE that maps the page being updated. */
    if ( __copy_from_user(&pte, &linear_pg_table[l1_linear_offset(addr)],
                          sizeof(pte)) )
    {
        MEM_LOG("ptwr_emulate: Cannot read thru linear_pg_table");
        return X86EMUL_UNHANDLEABLE;
    }

    pfn  = l1e_get_pfn(pte);
    page = mfn_to_page(pfn);

    /* We are looking only for read-only mappings of p.t. pages. */
    ASSERT((l1e_get_flags(pte) & (_PAGE_RW|_PAGE_PRESENT)) == _PAGE_PRESENT);
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_l1_page_table);
    ASSERT((page->u.inuse.type_info & PGT_count_mask) != 0);
    ASSERT(page_get_owner(page) == d);

    /* Check the new PTE. */
    nl1e = l1e_from_intpte(val);
    if ( unlikely(!get_page_from_l1e(nl1e, d)) )
    {
        MEM_LOG("ptwr_emulate: could not get_page_from_l1e()");
        return X86EMUL_UNHANDLEABLE;
    }

    /* Checked successfully: do the update (write or cmpxchg). */
    pl1e = map_domain_page(page_to_mfn(page));
    pl1e = (l1_pgentry_t *)((unsigned long)pl1e + (addr & ~PAGE_MASK));
    if ( do_cmpxchg )
    {
        ol1e = l1e_from_intpte(old);
        if ( cmpxchg((intpte_t *)pl1e, old, val) != old )
        {
            unmap_domain_page(pl1e);
            put_page_from_l1e(nl1e, d);
            return X86EMUL_CMPXCHG_FAILED;
        }
    }
    else
    {
        ol1e  = *pl1e;
        *pl1e = nl1e;
    }
    unmap_domain_page(pl1e);

    /* Finally, drop the old PTE. */
    put_page_from_l1e(ol1e, d);

    return X86EMUL_CONTINUE;
}

static int ptwr_emulated_write(
    unsigned long addr,
    unsigned long val,
    unsigned int bytes)
{
    return ptwr_emulated_update(addr, 0, val, bytes, 0);
}

static int ptwr_emulated_cmpxchg(
    unsigned long addr,
    unsigned long old,
    unsigned long new,
    unsigned int bytes)
{
    return ptwr_emulated_update(addr, old, new, bytes, 1);
}

static int ptwr_emulated_cmpxchg8b(
    unsigned long addr,
    unsigned long old,
    unsigned long old_hi,
    unsigned long new,
    unsigned long new_hi)
{
    if ( CONFIG_PAGING_LEVELS == 2 )
        return X86EMUL_UNHANDLEABLE;
    else
        return ptwr_emulated_update(
            addr, ((u64)old_hi << 32) | old, ((u64)new_hi << 32) | new, 8, 1);
}

static struct x86_mem_emulator ptwr_mem_emulator = {
    .read_std           = x86_emulate_read_std,
    .write_std          = x86_emulate_write_std,
    .read_emulated      = x86_emulate_read_std,
    .write_emulated     = ptwr_emulated_write,
    .cmpxchg_emulated   = ptwr_emulated_cmpxchg,
    .cmpxchg8b_emulated = ptwr_emulated_cmpxchg8b
};

/* Write page fault handler: check if guest is trying to modify a PTE. */
int ptwr_do_page_fault(struct domain *d, unsigned long addr, 
                       struct cpu_user_regs *regs)
{
    unsigned long    pfn;
    struct page_info *page;
    l1_pgentry_t    *pl1e, pte;
    l2_pgentry_t    *pl2e, l2e;
    int              which, flags;
    unsigned long    l2_idx;

    if ( unlikely(shadow_mode_enabled(d)) )
        return 0;

    /*
     * Attempt to read the PTE that maps the VA being accessed. By checking for
     * PDE validity in the L2 we avoid many expensive fixups in __get_user().
     */
    if ( !(l2e_get_flags(__linear_l2_table[l2_linear_offset(addr)]) &
           _PAGE_PRESENT) ||
         __copy_from_user(&pte,&linear_pg_table[l1_linear_offset(addr)],
                          sizeof(pte)) )
    {
        return 0;
    }

    pfn  = l1e_get_pfn(pte);
    page = mfn_to_page(pfn);

#ifdef CONFIG_X86_64
#define WRPT_PTE_FLAGS (_PAGE_RW | _PAGE_PRESENT | _PAGE_USER)
#else
#define WRPT_PTE_FLAGS (_PAGE_RW | _PAGE_PRESENT)
#endif

    /*
     * Check the required flags for a valid wrpt mapping. If the page is
     * already writable then we can return straight to the guest (SMP race).
     * We decide whether or not to propagate the fault by testing for write
     * permissions in page directories by writing back to the linear mapping.
     */
    if ( (flags = l1e_get_flags(pte) & WRPT_PTE_FLAGS) == WRPT_PTE_FLAGS )
        return !__put_user(
            pte.l1, &linear_pg_table[l1_linear_offset(addr)].l1);

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((flags | _PAGE_RW) != WRPT_PTE_FLAGS) ||
         ((page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table) ||
         ((page->u.inuse.type_info & PGT_count_mask) == 0) ||
         (page_get_owner(page) != d) )
    {
        return 0;
    }

#if 0 /* Leave this in as useful for debugging */ 
    goto emulate; 
#endif

    PTWR_PRINTK("ptwr_page_fault on l1 pt at va %lx, pfn %lx, eip %lx\n",
                addr, pfn, (unsigned long)regs->eip);
    
    /* Get the L2 index at which this L1 p.t. is always mapped. */
    l2_idx = page->u.inuse.type_info & PGT_va_mask;
    if ( unlikely(l2_idx >= PGT_va_unknown) )
        goto emulate; /* Urk! This L1 is mapped in multiple L2 slots! */
    l2_idx >>= PGT_va_shift;

    if ( unlikely(l2_idx == l2_linear_offset(addr)) )
        goto emulate; /* Urk! Pagetable maps itself! */

    /*
     * Is the L1 p.t. mapped into the current address space? If so we call it
     * an ACTIVE p.t., otherwise it is INACTIVE.
     */
    pl2e = &__linear_l2_table[l2_idx];
    which = PTWR_PT_INACTIVE;

    if ( (__get_user(l2e.l2, &pl2e->l2) == 0) && (l2e_get_pfn(l2e) == pfn) )
    {
        /*
         * Check the PRESENT bit to set ACTIVE mode.
         * If the PRESENT bit is clear, we may be conflicting with the current 
         * ACTIVE p.t. (it may be the same p.t. mapped at another virt addr).
         * The ptwr_flush call below will restore the PRESENT bit.
         */
        if ( likely(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
             (d->arch.ptwr[PTWR_PT_ACTIVE].l1va &&
              (l2_idx == d->arch.ptwr[PTWR_PT_ACTIVE].l2_idx)) )
            which = PTWR_PT_ACTIVE;
    }

    /*
     * If this is a multi-processor guest then ensure that the page is hooked
     * into at most one L2 table, which must be the one running on this VCPU.
     */
    if ( (d->vcpu[0]->next_in_list != NULL) &&
         ((page->u.inuse.type_info & PGT_count_mask) != 
          (!!(page->u.inuse.type_info & PGT_pinned) +
           (which == PTWR_PT_ACTIVE))) )
    {
        /* Could be conflicting writable mappings from other VCPUs. */
        cleanup_writable_pagetable(d);
        goto emulate;
    }

    /*
     * We only allow one ACTIVE and one INACTIVE p.t. to be updated at at 
     * time. If there is already one, we must flush it out.
     */
    if ( d->arch.ptwr[which].l1va )
        ptwr_flush(d, which);

    /*
     * If last batch made no updates then we are probably stuck. Emulate this 
     * update to ensure we make progress.
     */
    if ( d->arch.ptwr[which].prev_nr_updates == 0 )
    {
        /* Ensure that we don't get stuck in an emulation-only rut. */
        d->arch.ptwr[which].prev_nr_updates = 1;
        goto emulate;
    }

    PTWR_PRINTK("[%c] batched ptwr_page_fault at va %lx, pt for %08lx, "
                "pfn %lx\n", PTWR_PRINT_WHICH, addr,
                l2_idx << L2_PAGETABLE_SHIFT, pfn);

    d->arch.ptwr[which].l1va   = addr | 1;
    d->arch.ptwr[which].l2_idx = l2_idx;
    d->arch.ptwr[which].vcpu   = current;

#ifdef PERF_ARRAYS
    d->arch.ptwr[which].eip    = regs->eip;
#endif

    /* For safety, disconnect the L1 p.t. page from current space. */
    if ( which == PTWR_PT_ACTIVE )
    {
        l2e_remove_flags(*pl2e, _PAGE_PRESENT);
        flush_tlb_mask(d->domain_dirty_cpumask);
    }
    
    /* Temporarily map the L1 page, and make a copy of it. */
    pl1e = map_domain_page(pfn);
    memcpy(d->arch.ptwr[which].page, pl1e, PAGE_SIZE);
    unmap_domain_page(pl1e);

    /* Finally, make the p.t. page writable by the guest OS. */
    l1e_add_flags(pte, _PAGE_RW);
    if ( unlikely(__put_user(pte.l1,
                             &linear_pg_table[l1_linear_offset(addr)].l1)) )
    {
        MEM_LOG("ptwr: Could not update pte at %p", (unsigned long *)
                &linear_pg_table[l1_linear_offset(addr)]);
        /* Toss the writable pagetable state and crash. */
        d->arch.ptwr[which].l1va = 0;
        domain_crash(d);
        return 0;
    }
    
    return EXCRET_fault_fixed;

 emulate:
    if ( x86_emulate_memop(guest_cpu_user_regs(), addr,
                           &ptwr_mem_emulator, X86EMUL_MODE_HOST) )
        return 0;
    perfc_incrc(ptwr_emulations);
    return EXCRET_fault_fixed;
}

int ptwr_init(struct domain *d)
{
    void *x = alloc_xenheap_page();
    void *y = alloc_xenheap_page();

    if ( (x == NULL) || (y == NULL) )
    {
        free_xenheap_page(x);
        free_xenheap_page(y);
        return -ENOMEM;
    }

    d->arch.ptwr[PTWR_PT_ACTIVE].page   = x;
    d->arch.ptwr[PTWR_PT_INACTIVE].page = y;

    return 0;
}

void ptwr_destroy(struct domain *d)
{
    LOCK_BIGLOCK(d);
    cleanup_writable_pagetable(d);
    UNLOCK_BIGLOCK(d);
    free_xenheap_page(d->arch.ptwr[PTWR_PT_ACTIVE].page);
    free_xenheap_page(d->arch.ptwr[PTWR_PT_INACTIVE].page);
}

void cleanup_writable_pagetable(struct domain *d)
{
    if ( unlikely(!VM_ASSIST(d, VMASST_TYPE_writable_pagetables)) )
        return;

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_sync_all(d);
    }
    else
    {
        if ( d->arch.ptwr[PTWR_PT_ACTIVE].l1va )
            ptwr_flush(d, PTWR_PT_ACTIVE);
        if ( d->arch.ptwr[PTWR_PT_INACTIVE].l1va )
            ptwr_flush(d, PTWR_PT_INACTIVE);
    }
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
            ol2e  = *pl2e;
            *pl2e = l2e_from_pfn(mfn, flags|_PAGE_PSE);

            if ( (l2e_get_flags(ol2e) & _PAGE_PRESENT) )
            {
                local_flush_tlb_pge();
                if ( !(l2e_get_flags(ol2e) & _PAGE_PSE) )
                    free_xen_pagetable(l2e_get_page(*pl2e));
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
                pl1e = page_to_virt(alloc_xen_pagetable());
                clear_page(pl1e);
                *pl2e = l2e_from_page(virt_to_page(pl1e), __PAGE_HYPERVISOR);
            }
            else if ( l2e_get_flags(*pl2e) & _PAGE_PSE )
            {
                pl1e = page_to_virt(alloc_xen_pagetable());
                for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
                    pl1e[i] = l1e_from_pfn(
                        l2e_get_pfn(*pl2e) + i,
                        l2e_get_flags(*pl2e) & ~_PAGE_PSE);
                *pl2e = l2e_from_page(virt_to_page(pl1e), __PAGE_HYPERVISOR);
                local_flush_tlb_pge();
            }

            pl1e  = l2e_to_l1e(*pl2e) + l1_table_offset(virt);
            ol1e  = *pl1e;
            *pl1e = l1e_from_pfn(mfn, flags);
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
    enum fixed_addresses idx, unsigned long p, unsigned long flags)
{
    if ( unlikely(idx >= __end_of_fixed_addresses) )
        BUG();
    map_pages_to_xen(fix_to_virt(idx), p >> PAGE_SHIFT, 1, flags);
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
