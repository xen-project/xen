/******************************************************************************
 * arch/x86/memory.c
 * 
 * Copyright (c) 2002-2004 K A Fraser
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
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <asm/ldt.h>

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                           \
  printk("DOM%u: (file=memory.c, line=%d) " _f "\n", \
         current->domain->id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

static int alloc_l2_table(struct pfn_info *page);
static int alloc_l1_table(struct pfn_info *page);
static int get_page_from_pagenr(unsigned long page_nr, struct domain *d);
static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         u32 type,
                                         struct domain *d);

static void free_l2_table(struct pfn_info *page);
static void free_l1_table(struct pfn_info *page);

static int mod_l2_entry(l2_pgentry_t *, l2_pgentry_t, unsigned long);
static int mod_l1_entry(l1_pgentry_t *, l1_pgentry_t);

/* Used to defer flushing of memory structures. */
static struct {
#define DOP_FLUSH_TLB   (1<<0) /* Flush the TLB.                 */
#define DOP_RELOAD_LDT  (1<<1) /* Reload the LDT shadow mapping. */
    unsigned long  deferred_ops;
    /* If non-NULL, specifies a foreign subject domain for some operations. */
    struct domain *foreign;
} __cacheline_aligned percpu_info[NR_CPUS];

/*
 * Returns the current foreign domain; defaults to the currently-executing
 * domain if a foreign override hasn't been specified.
 */
#define FOREIGNDOM (percpu_info[smp_processor_id()].foreign ? : current->domain)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
static struct domain *dom_xen, *dom_io;

/* Frame table and its size in pages. */
struct pfn_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;

void __init init_frametable(void)
{
    unsigned long i, p;

    frame_table      = (struct pfn_info *)FRAMETABLE_VIRT_START;
    frame_table_size = max_page * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

    for ( i = 0; i < frame_table_size; i += (4UL << 20) )
    {
        p = alloc_boot_pages(min(frame_table_size - i, 4UL << 20), 4UL << 20);
        if ( p == 0 )
            panic("Not enough memory for frame table\n");
        idle_pg_table[(FRAMETABLE_VIRT_START + i) >> L2_PAGETABLE_SHIFT] =
            mk_l2_pgentry(p | __PAGE_HYPERVISOR | _PAGE_PSE);
    }

    memset(frame_table, 0, frame_table_size);
}

void arch_init_memory(void)
{
    unsigned long mfn, i;

    /*
     * We are rather picky about the layout of 'struct pfn_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them. Also, just for sanity, we assert the size
     * of the structure here.
     */
    if ( (offsetof(struct pfn_info, u.inuse.domain) != 
          (offsetof(struct pfn_info, count_info) + sizeof(u32))) ||
         (sizeof(struct pfn_info) != 24) )
    {
        printk("Weird pfn_info layout (%ld,%ld,%d)\n",
               offsetof(struct pfn_info, count_info),
               offsetof(struct pfn_info, u.inuse.domain),
               sizeof(struct pfn_info));
        for ( ; ; ) ;
    }

    memset(percpu_info, 0, sizeof(percpu_info));

    /* Initialise to a magic of 0x55555555 so easier to spot bugs later. */
    memset(machine_to_phys_mapping, 0x55, 4<<20);

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain_struct();
    atomic_set(&dom_xen->refcnt, 1);
    dom_xen->id = DOMID_XEN;

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns no pages but is considered a special case when
     * mapping I/O pages, as the mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain_struct();
    atomic_set(&dom_io->refcnt, 1);
    dom_io->id = DOMID_IO;

    /* M2P table is mappable read-only by privileged domains. */
    mfn = l2_pgentry_to_pagenr(
        idle_pg_table[RDWR_MPT_VIRT_START >> L2_PAGETABLE_SHIFT]);
    for ( i = 0; i < 1024; i++ )
    {
        frame_table[mfn+i].count_info        = PGC_allocated | 1;
        frame_table[mfn+i].u.inuse.type_info = PGT_gdt_page | 1; /* non-RW */
        frame_table[mfn+i].u.inuse.domain    = dom_xen;
    }
}

static void __invalidate_shadow_ldt(struct exec_domain *d)
{
    int i;
    unsigned long pfn;
    struct pfn_info *page;
    
    d->mm.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1_pgentry_to_pagenr(d->mm.perdomain_ptes[i]);
        if ( pfn == 0 ) continue;
        d->mm.perdomain_ptes[i] = mk_l1_pgentry(0);
        page = &frame_table[pfn];
        ASSERT_PAGE_IS_TYPE(page, PGT_ldt_page);
        ASSERT_PAGE_IS_DOMAIN(page, d->domain);
        put_page_and_type(page);
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    percpu_info[d->processor].deferred_ops |= DOP_FLUSH_TLB | DOP_RELOAD_LDT;
}


static inline void invalidate_shadow_ldt(struct exec_domain *d)
{
    if ( d->mm.shadow_ldt_mapcnt != 0 )
        __invalidate_shadow_ldt(d);
}


static int alloc_segdesc_page(struct pfn_info *page)
{
    unsigned long *descs = map_domain_mem((page-frame_table) << PAGE_SHIFT);
    int i;

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(&descs[i*2])) )
            goto fail;

    unmap_domain_mem(descs);
    return 1;

 fail:
    unmap_domain_mem(descs);
    return 0;
}


/* Map shadow page at offset @off. */
int map_ldt_shadow_page(unsigned int off)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    unsigned long l1e;

    if ( unlikely(in_irq()) )
        BUG();

    __get_user(l1e, (unsigned long *)&linear_pg_table[(ed->mm.ldt_base >> 
                                                       PAGE_SHIFT) + off]);

    if ( unlikely(!(l1e & _PAGE_PRESENT)) ||
         unlikely(!get_page_and_type(&frame_table[l1e >> PAGE_SHIFT], 
                                     d, PGT_ldt_page)) )
        return 0;

    ed->mm.perdomain_ptes[off + 16] = mk_l1_pgentry(l1e | _PAGE_RW);
    ed->mm.shadow_ldt_mapcnt++;

    return 1;
}


static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct pfn_info *page = &frame_table[page_nr];

    if ( unlikely(!pfn_is_ram(page_nr)) )
    {
        MEM_LOG("Pfn %08lx is not RAM", page_nr);
        return 0;
    }

    if ( unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %08lx", page_nr);
        return 0;
    }

    return 1;
}


static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         u32 type,
                                         struct domain *d)
{
    struct pfn_info *page = &frame_table[page_nr];

    if ( unlikely(!get_page_from_pagenr(page_nr, d)) )
        return 0;

    if ( unlikely(!get_page_type(page, type)) )
    {
#ifdef VERBOSE
        if ( (type & PGT_type_mask) != PGT_l1_page_table )
            MEM_LOG("Bad page type for pfn %08lx (%08x)", 
                    page_nr, page->u.inuse.type_info);
#endif
        put_page(page);
        return 0;
    }

    return 1;
}


/*
 * We allow an L2 tables to map each other (a.k.a. linear page tables). It
 * needs some special care with reference counst and access permissions:
 *  1. The mapping entry must be read-only, or the guest may get write access
 *     to its own PTEs.
 *  2. We must only bump the reference counts for an *already validated*
 *     L2 table, or we can end up in a deadlock in get_page_type() by waiting
 *     on a validation that is required to complete that validation.
 *  3. We only need to increment the reference counts for the mapped page
 *     frame if it is mapped by a different L2 table. This is sufficient and
 *     also necessary to allow validation of an L2 table mapping itself.
 */
static int 
get_linear_pagetable(
    l2_pgentry_t l2e, unsigned long pfn, struct domain *d)
{
    u32 x, y;
    struct pfn_info *page;

    if ( (l2_pgentry_val(l2e) & _PAGE_RW) )
    {
        MEM_LOG("Attempt to create linear p.t. with write perms");
        return 0;
    }

    if ( (l2_pgentry_val(l2e) >> PAGE_SHIFT) != pfn )
    {
        /* Make sure the mapped frame belongs to the correct domain. */
        if ( unlikely(!get_page_from_pagenr(l2_pgentry_to_pagenr(l2e), d)) )
            return 0;

        /*
         * Make sure that the mapped frame is an already-validated L2 table. 
         * If so, atomically increment the count (checking for overflow).
         */
        page = &frame_table[l2_pgentry_to_pagenr(l2e)];
        y = page->u.inuse.type_info;
        do {
            x = y;
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||
                 unlikely((x & (PGT_type_mask|PGT_validated)) != 
                          (PGT_l2_page_table|PGT_validated)) )
            {
                put_page(page);
                return 0;
            }
        }
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );
    }

    return 1;
}


static int
get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *d)
{
    unsigned long l1v = l1_pgentry_val(l1e);
    unsigned long pfn = l1_pgentry_to_pagenr(l1e);
    struct pfn_info *page = &frame_table[pfn];
    extern int domain_iomem_in_pfn(struct domain *d, unsigned long pfn);

    if ( !(l1v & _PAGE_PRESENT) )
        return 1;

    if ( unlikely(l1v & (_PAGE_GLOBAL|_PAGE_PAT)) )
    {
        MEM_LOG("Bad L1 type settings %04lx", l1v & (_PAGE_GLOBAL|_PAGE_PAT));
        return 0;
    }

    if ( unlikely(!pfn_is_ram(pfn)) )
    {
        /* Revert to caller privileges if FD == DOMID_IO. */
        if ( d == dom_io )
            d = current->domain;

        if ( IS_PRIV(d) )
            return 1;

        if ( IS_CAPABLE_PHYSDEV(d) )
            return domain_iomem_in_pfn(d, pfn);

        MEM_LOG("Non-privileged attempt to map I/O space %08lx", pfn);
        return 0;
    }

    return ((l1v & _PAGE_RW) ?
            get_page_and_type(page, d, PGT_writable_page) :
            get_page(page, d));
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
static int 
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn,
    struct domain *d, unsigned long va_idx)
{
    int rc;

    if ( !(l2_pgentry_val(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2_pgentry_val(l2e) & (_PAGE_GLOBAL|_PAGE_PSE))) )
    {
        MEM_LOG("Bad L2 page type settings %04lx",
                l2_pgentry_val(l2e) & (_PAGE_GLOBAL|_PAGE_PSE));
        return 0;
    }

    rc = get_page_and_type_from_pagenr(
        l2_pgentry_to_pagenr(l2e), 
        PGT_l1_page_table | (va_idx<<PGT_va_shift), d);

    if ( unlikely(!rc) )
        return get_linear_pagetable(l2e, pfn, d);

    return 1;
}


static void put_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    unsigned long    l1v  = l1_pgentry_val(l1e);
    unsigned long    pfn  = l1_pgentry_to_pagenr(l1e);
    struct pfn_info *page = &frame_table[pfn];
    struct domain   *e;

    if ( !(l1v & _PAGE_PRESENT) || !pfn_is_ram(pfn) )
        return;

    e = page->u.inuse.domain;
    if ( unlikely(e != d) )
    {
        /*
         * Unmap a foreign page that may have been mapped via a grant table.
         * Note that this can fail for a privileged domain that can map foreign
         * pages via MMUEXT_SET_FOREIGNDOM. Such domains can have some mappings
         * counted via a grant entry and some counted directly in the page
         * structure's reference count. Note that reference counts won't get
         * dangerously confused as long as we always try to decrement the
         * grant entry first. We may end up with a mismatch between which
         * mappings and which unmappings are counted via the grant entry, but
         * really it doesn't matter as privileged domains have carte blanche.
         */
        if ( likely(gnttab_check_unmap(e, d, pfn, !(l1v & _PAGE_RW))) )
            return;
        /* Assume this mapping was made via MMUEXT_SET_FOREIGNDOM... */
    }

    if ( l1v & _PAGE_RW )
    {
        put_page_and_type(page);
    }
    else
    {
        /* We expect this is rare so we blow the entire shadow LDT. */
        if ( unlikely(((page->u.inuse.type_info & PGT_type_mask) == 
                       PGT_ldt_page)) &&
             unlikely(((page->u.inuse.type_info & PGT_count_mask) != 0)) )
            invalidate_shadow_ldt(e->exec_domain[0]);
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static void put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( (l2_pgentry_val(l2e) & _PAGE_PRESENT) && 
         ((l2_pgentry_val(l2e) >> PAGE_SHIFT) != pfn) )
        put_page_and_type(&frame_table[l2_pgentry_to_pagenr(l2e)]);
}


static int alloc_l2_table(struct pfn_info *page)
{
    struct domain *d = page->u.inuse.domain;
    unsigned long  page_nr = page_to_pfn(page);
    l2_pgentry_t  *pl2e;
    int            i;
   
    pl2e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        if ( unlikely(!get_page_from_l2e(pl2e[i], page_nr, d, i)) )
            goto fail;

#if defined(__i386__)
    /* Now we add our private high mappings. */
    memcpy(&pl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
           &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
           HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
    pl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((page_nr << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    pl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(page->u.inuse.domain->mm_perdomain_pt) | 
                      __PAGE_HYPERVISOR);
#endif

    unmap_domain_mem(pl2e);
    return 1;

 fail:
    while ( i-- > 0 )
        put_page_from_l2e(pl2e[i], page_nr);

    unmap_domain_mem(pl2e);
    return 0;
}


static int alloc_l1_table(struct pfn_info *page)
{
    struct domain *d = page->u.inuse.domain;
    unsigned long  page_nr = page_to_pfn(page);
    l1_pgentry_t  *pl1e;
    int            i;

    pl1e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        if ( unlikely(!get_page_from_l1e(pl1e[i], d)) )
            goto fail;

    unmap_domain_mem(pl1e);
    return 1;

 fail:
    while ( i-- > 0 )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_mem(pl1e);
    return 0;
}


static void free_l2_table(struct pfn_info *page)
{
    unsigned long page_nr = page - frame_table;
    l2_pgentry_t *pl2e;
    int i;

    pl2e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        put_page_from_l2e(pl2e[i], page_nr);

    unmap_domain_mem(pl2e);
}


static void free_l1_table(struct pfn_info *page)
{
    struct domain *d = page->u.inuse.domain;
    unsigned long page_nr = page - frame_table;
    l1_pgentry_t *pl1e;
    int i;

    pl1e = map_domain_mem(page_nr << PAGE_SHIFT);

    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        put_page_from_l1e(pl1e[i], d);

    unmap_domain_mem(pl1e);
}


static inline int update_l2e(l2_pgentry_t *pl2e, 
                             l2_pgentry_t  ol2e, 
                             l2_pgentry_t  nl2e)
{
    unsigned long o = cmpxchg((unsigned long *)pl2e, 
                              l2_pgentry_val(ol2e), 
                              l2_pgentry_val(nl2e));
    if ( o != l2_pgentry_val(ol2e) )
        MEM_LOG("Failed to update %08lx -> %08lx: saw %08lx\n",
                l2_pgentry_val(ol2e), l2_pgentry_val(nl2e), o);
    return (o == l2_pgentry_val(ol2e));
}


/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, 
                        l2_pgentry_t nl2e, 
                        unsigned long pfn)
{
    l2_pgentry_t ol2e;
    unsigned long _ol2e;

    if ( unlikely((((unsigned long)pl2e & (PAGE_SIZE-1)) >> 2) >=
                  DOMAIN_ENTRIES_PER_L2_PAGETABLE) )
    {
        MEM_LOG("Illegal L2 update attempt in Xen-private area %p", pl2e);
        return 0;
    }

    if ( unlikely(__get_user(_ol2e, (unsigned long *)pl2e) != 0) )
        return 0;
    ol2e = mk_l2_pgentry(_ol2e);

    if ( l2_pgentry_val(nl2e) & _PAGE_PRESENT )
    {
        /* Differ in mapping (bits 12-31) or presence (bit 0)? */
        if ( ((l2_pgentry_val(ol2e) ^ l2_pgentry_val(nl2e)) & ~0xffe) == 0 )
            return update_l2e(pl2e, ol2e, nl2e);

        if ( unlikely(!get_page_from_l2e(nl2e, pfn, current->domain,
                                        ((unsigned long)pl2e & 
                                         ~PAGE_MASK) >> 2)) )
            return 0;

        if ( unlikely(!update_l2e(pl2e, ol2e, nl2e)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
        
        put_page_from_l2e(ol2e, pfn);
        return 1;
    }

    if ( unlikely(!update_l2e(pl2e, ol2e, nl2e)) )
        return 0;

    put_page_from_l2e(ol2e, pfn);
    return 1;
}


static inline int update_l1e(l1_pgentry_t *pl1e, 
                             l1_pgentry_t  ol1e, 
                             l1_pgentry_t  nl1e)
{
    unsigned long o = l1_pgentry_val(ol1e);
    unsigned long n = l1_pgentry_val(nl1e);

    if ( unlikely(cmpxchg_user(pl1e, o, n) != 0) ||
         unlikely(o != l1_pgentry_val(ol1e)) )
    {
        MEM_LOG("Failed to update %08lx -> %08lx: saw %08lx\n",
                l1_pgentry_val(ol1e), l1_pgentry_val(nl1e), o);
        return 0;
    }

    return 1;
}


/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e)
{
    l1_pgentry_t ol1e;
    unsigned long _ol1e;
    struct domain *d = current->domain;

    if ( unlikely(__get_user(_ol1e, (unsigned long *)pl1e) != 0) )
    {
        MEM_LOG("Bad get_user\n");
        return 0;
    }
    
    ol1e = mk_l1_pgentry(_ol1e);

    if ( l1_pgentry_val(nl1e) & _PAGE_PRESENT )
    {
        /* Differ in mapping (bits 12-31), r/w (bit 1), or presence (bit 0)? */
        if ( ((l1_pgentry_val(ol1e) ^ l1_pgentry_val(nl1e)) & ~0xffc) == 0 )
            return update_l1e(pl1e, ol1e, nl1e);

        if ( unlikely(!get_page_from_l1e(nl1e, FOREIGNDOM)) )
            return 0;
        
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        {
            put_page_from_l1e(nl1e, d);
            return 0;
        }
        
        put_page_from_l1e(ol1e, d);
        return 1;
    }

    if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        return 0;
    
    put_page_from_l1e(ol1e, d);
    return 1;
}


int alloc_page_type(struct pfn_info *page, unsigned int type)
{
    switch ( type )
    {
    case PGT_l1_page_table:
        return alloc_l1_table(page);
    case PGT_l2_page_table:
        return alloc_l2_table(page);
    case PGT_gdt_page:
    case PGT_ldt_page:
        return alloc_segdesc_page(page);
    default:
        printk("Bad type in alloc_page_type %x t=%x c=%x\n", 
               type, page->u.inuse.type_info,
               page->count_info);
        BUG();
    }

    return 0;
}


void free_page_type(struct pfn_info *page, unsigned int type)
{
    struct domain *d = page->u.inuse.domain;

    switch ( type )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        break;

    case PGT_l2_page_table:
        free_l2_table(page);
        break;

    default:
        BUG();
    }

    if ( unlikely(d->exec_domain[0]->mm.shadow_mode) && 
         (get_shadow_status(&d->exec_domain[0]->mm, page_to_pfn(page)) & PSH_shadowed) )
    {
        unshadow_table(page_to_pfn(page), type);
        put_shadow_status(&d->exec_domain[0]->mm);
    }
}


void put_page_type(struct pfn_info *page)
{
    u32 nx, x, y = page->u.inuse.type_info;

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
               test_bit(DF_DYING, &page->u.inuse.domain->d_flags));

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
                /* We cleared the 'valid bit' so we do the clear up. */
                free_page_type(page, x & PGT_type_mask);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
        else if ( unlikely((nx & (PGT_pinned | PGT_count_mask)) == 
                           (PGT_pinned | 1)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct pfn_info *page, u32 type)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %08lx\n", page_to_pfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. This 
                 * may be unnecessary (e.g., page was GDT/LDT) but those
                 * circumstances should be very rare.
                 */
                struct domain *d = page->u.inuse.domain;
                if ( unlikely(NEED_FLUSH(tlbflush_time[d->exec_domain[0]->processor],
                                         page->tlbflush_timestamp)) )
                {
                    perfc_incr(need_flush_tlb_flush);
                    flush_tlb_cpu(d->exec_domain[0]->processor);
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
        else if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
        {
            if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
            {
                if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                     ((type & PGT_type_mask) != PGT_l1_page_table) )
                    MEM_LOG("Bad type (saw %08x != exp %08x) for pfn %08lx\n",
                            x & PGT_type_mask, type, page_to_pfn(page));
                return 0;
            }
            else if ( (x & PGT_va_mask) == PGT_va_mutable )
            {
                /* The va backpointer is mutable, hence we update it. */
                nx &= ~PGT_va_mask;
                nx |= type; /* we know the actual type is correct */
            }
            else if ( unlikely((x & PGT_va_mask) != (type & PGT_va_mask)) )
            {
                /* This table is potentially mapped at multiple locations. */
                nx &= ~PGT_va_mask;
                nx |= PGT_va_unknown;
            }
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) == x )
            {
                rep_nop();
                barrier();
            }
            goto again;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type & PGT_type_mask)) )
        {
            MEM_LOG("Error while validating pfn %08lx for type %08x."
                    " caf=%08x taf=%08x\n",
                    page_to_pfn(page), type,
                    page->count_info,
                    page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}


static int do_extended_command(unsigned long ptr, unsigned long val)
{
    int okay = 1, cpu = smp_processor_id();
    unsigned int cmd = val & MMUEXT_CMD_MASK;
    unsigned long pfn = ptr >> PAGE_SHIFT;
    unsigned long old_base_pfn;
    struct pfn_info *page = &frame_table[pfn];
    struct exec_domain *ed = current;
    struct domain *d = ed->domain, *nd, *e;
    u32 x, y;
    domid_t domid;
    grant_ref_t gntref;

    switch ( cmd )
    {
    case MMUEXT_PIN_L1_TABLE:
    case MMUEXT_PIN_L2_TABLE:
        /*
         * We insist that, if you pin an L1 page, it's the first thing that
         * you do to it. This is because we require the backptr to still be
         * mutable. This assumption seems safe.
         */
        okay = get_page_and_type_from_pagenr(
            pfn, 
            ((cmd==MMUEXT_PIN_L2_TABLE) ? 
             PGT_l2_page_table : (PGT_l1_page_table|PGT_va_mutable)),
            FOREIGNDOM);

        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while pinning pfn %08lx", pfn);
            break;
        }

        if ( unlikely(test_and_set_bit(_PGT_pinned,
                                       &page->u.inuse.type_info)) )
        {
            MEM_LOG("Pfn %08lx already pinned", pfn);
            put_page_and_type(page);
            okay = 0;
            break;
        }

        break;

    case MMUEXT_UNPIN_TABLE:
        if ( unlikely(!(okay = get_page_from_pagenr(pfn, FOREIGNDOM))) )
        {
            MEM_LOG("Page %08lx bad domain (dom=%p)",
                    ptr, page->u.inuse.domain);
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
            MEM_LOG("Pfn %08lx not pinned", pfn);
        }
        break;

    case MMUEXT_NEW_BASEPTR:
        okay = get_page_and_type_from_pagenr(pfn, PGT_l2_page_table, d);
        if ( likely(okay) )
        {
            invalidate_shadow_ldt(ed);

            percpu_info[cpu].deferred_ops &= ~DOP_FLUSH_TLB;
            old_base_pfn = pagetable_val(ed->mm.pagetable) >> PAGE_SHIFT;
            ed->mm.pagetable = mk_pagetable(pfn << PAGE_SHIFT);

            shadow_mk_pagetable(&ed->mm);

            write_ptbase(&ed->mm);

            put_page_and_type(&frame_table[old_base_pfn]);
        }
        else
        {
            MEM_LOG("Error while installing new baseptr %08lx", ptr);
        }
        break;
        
    case MMUEXT_TLB_FLUSH:
        percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;
        break;
    
    case MMUEXT_INVLPG:
        __flush_tlb_one(ptr);
        break;

    case MMUEXT_FLUSH_CACHE:
        if ( unlikely(!IS_CAPABLE_PHYSDEV(d)) )
        {
            MEM_LOG("Non-physdev domain tried to FLUSH_CACHE.\n");
            okay = 0;
        }
        else
        {
            wbinvd();
        }
        break;

    case MMUEXT_SET_LDT:
    {
        unsigned long ents = val >> MMUEXT_CMD_SHIFT;
        if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
             (ents > 8192) ||
             ((ptr+ents*LDT_ENTRY_SIZE) < ptr) ||
             ((ptr+ents*LDT_ENTRY_SIZE) > PAGE_OFFSET) )
        {
            okay = 0;
            MEM_LOG("Bad args to SET_LDT: ptr=%08lx, ents=%08lx", ptr, ents);
        }
        else if ( (ed->mm.ldt_ents != ents) || 
                  (ed->mm.ldt_base != ptr) )
        {
            invalidate_shadow_ldt(ed);
            ed->mm.ldt_base = ptr;
            ed->mm.ldt_ents = ents;
            load_LDT(ed);
            percpu_info[cpu].deferred_ops &= ~DOP_RELOAD_LDT;
            if ( ents != 0 )
                percpu_info[cpu].deferred_ops |= DOP_RELOAD_LDT;
        }
        break;
    }

    case MMUEXT_SET_FOREIGNDOM:
        domid = (domid_t)(val >> 16);

        if ( (e = percpu_info[cpu].foreign) != NULL )
            put_domain(e);
        percpu_info[cpu].foreign = NULL;

        if ( !IS_PRIV(d) )
        {
            switch ( domid )
            {
            case DOMID_IO:
                get_knownalive_domain(dom_io);
                percpu_info[cpu].foreign = dom_io;
                break;
            default:
                MEM_LOG("Dom %u cannot set foreign dom\n", d->id);
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
        break;

    case MMUEXT_TRANSFER_PAGE:
        domid  = (domid_t)(val >> 16);
        gntref = (grant_ref_t)((val & 0xFF00) | ((ptr >> 2) & 0x00FF));
        
        if ( unlikely(IS_XEN_HEAP_FRAME(page)) ||
             unlikely(!pfn_is_ram(pfn)) ||
             unlikely((e = find_domain_by_id(domid)) == NULL) )
        {
            MEM_LOG("Bad frame (%08lx) or bad domid (%d).\n", pfn, domid);
            okay = 0;
            break;
        }

        spin_lock(&d->page_alloc_lock);

        /*
         * The tricky bit: atomically release ownership while there is just one
         * benign reference to the page (PGC_allocated). If that reference
         * disappears then the deallocation routine will safely spin.
         */
        nd = page->u.inuse.domain;
        y  = page->count_info;
        do {
            x = y;
            if ( unlikely((x & (PGC_count_mask|PGC_allocated)) != 
                          (1|PGC_allocated)) ||
                 unlikely(nd != d) )
            {
                MEM_LOG("Bad page values %08lx: ed=%p(%u), sd=%p,"
                        " caf=%08x, taf=%08x\n", page_to_pfn(page),
                        d, d->id, nd, x, page->u.inuse.type_info);
                spin_unlock(&d->page_alloc_lock);
                put_domain(e);
                return 0;
            }
            __asm__ __volatile__(
                LOCK_PREFIX "cmpxchg8b %2"
                : "=d" (nd), "=a" (y),
                "=m" (*(volatile u64 *)(&page->count_info))
                : "0" (d), "1" (x), "c" (NULL), "b" (x) );
        } 
        while ( unlikely(nd != d) || unlikely(y != x) );

        /*
         * Unlink from 'd'. At least one reference remains (now anonymous), so
         * noone else is spinning to try to delete this page from 'd'.
         */
        d->tot_pages--;
        list_del(&page->list);
        
        spin_unlock(&d->page_alloc_lock);

        spin_lock(&e->page_alloc_lock);

        /*
         * Check that 'e' will accept the page and has reservation headroom.
         * Also, a domain mustn't have PGC_allocated pages when it is dying.
         */
        ASSERT(e->tot_pages <= e->max_pages);
        if ( unlikely(test_bit(DF_DYING, &e->d_flags)) ||
             unlikely(e->tot_pages == e->max_pages) ||
             unlikely(!gnttab_prepare_for_transfer(e, d, gntref)) )
        {
            MEM_LOG("Transferee has no reservation headroom (%d,%d), or "
                    "provided a bad grant ref, or is dying (%08lx).\n",
                    e->tot_pages, e->max_pages, e->d_flags);
            spin_unlock(&e->page_alloc_lock);
            put_domain(e);
            okay = 0;
            break;
        }

        /* Okay, add the page to 'e'. */
        if ( unlikely(e->tot_pages++ == 0) )
            get_knownalive_domain(e);
        list_add_tail(&page->list, &e->page_list);
        page->u.inuse.domain = e;

        spin_unlock(&e->page_alloc_lock);

        /* Transfer is all done: tell the guest about its new page frame. */
        gnttab_notify_transfer(e, gntref, pfn);
        
        put_domain(e);
        break;

    case MMUEXT_REASSIGN_PAGE:
        if ( unlikely(!IS_PRIV(d)) )
        {
            MEM_LOG("Dom %u has no reassignment priv", d->id);
            okay = 0;
            break;
        }

        e = percpu_info[cpu].foreign;
        if ( unlikely(e == NULL) )
        {
            MEM_LOG("No FOREIGNDOM to reassign pfn %08lx to", pfn);
            okay = 0;
            break;
        }

        /*
         * Grab both page_list locks, in order. This prevents the page from
         * disappearing elsewhere while we modify the owner, and we'll need
         * both locks if we're successful so that we can change lists.
         */
        if ( d < e )
        {
            spin_lock(&d->page_alloc_lock);
            spin_lock(&e->page_alloc_lock);
        }
        else
        {
            spin_lock(&e->page_alloc_lock);
            spin_lock(&d->page_alloc_lock);
        }

        /* A domain shouldn't have PGC_allocated pages when it is dying. */
        if ( unlikely(test_bit(DF_DYING, &e->d_flags)) ||
             unlikely(IS_XEN_HEAP_FRAME(page)) )
        {
            MEM_LOG("Reassignment page is Xen heap, or dest dom is dying.");
            okay = 0;
            goto reassign_fail;
        }

        /*
         * The tricky bit: atomically change owner while there is just one
         * benign reference to the page (PGC_allocated). If that reference
         * disappears then the deallocation routine will safely spin.
         */
        nd = page->u.inuse.domain;
        y  = page->count_info;
        do {
            x = y;
            if ( unlikely((x & (PGC_count_mask|PGC_allocated)) != 
                          (1|PGC_allocated)) ||
                 unlikely(nd != d) )
            {
                MEM_LOG("Bad page values %08lx: ed=%p(%u), sd=%p,"
                        " caf=%08x, taf=%08x\n", page_to_pfn(page),
                        d, d->id, nd, x, page->u.inuse.type_info);
                okay = 0;
                goto reassign_fail;
            }
            __asm__ __volatile__(
                LOCK_PREFIX "cmpxchg8b %3"
                : "=d" (nd), "=a" (y), "=c" (e),
                "=m" (*(volatile u64 *)(&page->count_info))
                : "0" (d), "1" (x), "c" (e), "b" (x) );
        } 
        while ( unlikely(nd != d) || unlikely(y != x) );
        
        /*
         * Unlink from 'd'. We transferred at least one reference to 'e', so
         * noone else is spinning to try to delete this page from 'd'.
         */
        d->tot_pages--;
        list_del(&page->list);
        
        /*
         * Add the page to 'e'. Someone may already have removed the last
         * reference and want to remove the page from 'e'. However, we have
         * the lock so they'll spin waiting for us.
         */
        if ( unlikely(e->tot_pages++ == 0) )
            get_knownalive_domain(e);
        list_add_tail(&page->list, &e->page_list);

    reassign_fail:        
        spin_unlock(&d->page_alloc_lock);
        spin_unlock(&e->page_alloc_lock);
        break;

    case MMUEXT_CLEAR_FOREIGNDOM:
        if ( (e = percpu_info[cpu].foreign) != NULL )
            put_domain(e);
        percpu_info[cpu].foreign = NULL;
        break;

    default:
        MEM_LOG("Invalid extended pt command 0x%08lx", val & MMUEXT_CMD_MASK);
        okay = 0;
        break;
    }

    return okay;
}

int do_mmu_update(
    mmu_update_t *ureqs, unsigned int count, unsigned int *pdone)
{
/*
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 * We steal the next 15 bits to remember the current FOREIGNDOM.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))
#define MMU_UPDATE_PREEMPT_FDOM_SHIFT ((sizeof(int)*8)-16)
#define MMU_UPDATE_PREEMPT_FDOM_MASK  (0x7FFFU<<MMU_UPDATE_PREEMPT_FDOM_SHIFT)

    mmu_update_t req;
    unsigned long va = 0, deferred_ops, pfn, prev_pfn = 0;
    struct pfn_info *page;
    int rc = 0, okay = 1, i = 0, cpu = smp_processor_id();
    unsigned int cmd, done = 0;
    unsigned long prev_spfn = 0;
    l1_pgentry_t *prev_spl1e = 0;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    u32 type_info;
    domid_t domid;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d, PTWR_CLEANUP_ACTIVE | PTWR_CLEANUP_INACTIVE);

    /*
     * If we are resuming after preemption, read how much work we have already
     * done. This allows us to set the @done output parameter correctly.
     * We also reset FOREIGNDOM here.
     */
    if ( unlikely(count&(MMU_UPDATE_PREEMPTED|MMU_UPDATE_PREEMPT_FDOM_MASK)) )
    {
        if ( !(count & MMU_UPDATE_PREEMPTED) )
        {
            /* Count overflow into private FOREIGNDOM field. */
            MEM_LOG("do_mmu_update count is too large");
            rc = -EINVAL;
            goto out;
        }
        count &= ~MMU_UPDATE_PREEMPTED;
        domid = count >> MMU_UPDATE_PREEMPT_FDOM_SHIFT;
        count &= ~MMU_UPDATE_PREEMPT_FDOM_MASK;
        if ( unlikely(pdone != NULL) )
            (void)get_user(done, pdone);
        if ( (domid != current->domain->id) &&
             !do_extended_command(0, MMUEXT_SET_FOREIGNDOM | (domid << 16)) )
        {
            rc = -EINVAL;
            goto out;
        }
    }

    perfc_incrc(calls_to_mmu_update); 
    perfc_addc(num_page_updates, count);

    if ( unlikely(!array_access_ok(VERIFY_READ, ureqs, count, sizeof(req))) )
    {
        rc = -EFAULT;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_mmu_update, 3, ureqs, 
                (count - i) |
                (FOREIGNDOM->id << MMU_UPDATE_PREEMPT_FDOM_SHIFT) | 
                MMU_UPDATE_PREEMPTED, pdone);
            break;
        }

        if ( unlikely(__copy_from_user(&req, ureqs, sizeof(req)) != 0) )
        {
            MEM_LOG("Bad __copy_from_user");
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);
        pfn = req.ptr >> PAGE_SHIFT;

        okay = 0;

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             */
        case MMU_NORMAL_PT_UPDATE:
            if ( unlikely(!get_page_from_pagenr(pfn, current->domain)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            if ( likely(prev_pfn == pfn) )
            {
                va = (va & PAGE_MASK) | (req.ptr & ~PAGE_MASK);
            }
            else
            {
                if ( prev_pfn != 0 )
                    unmap_domain_mem((void *)va);
                va = (unsigned long)map_domain_mem(req.ptr);
                prev_pfn = pfn;
            }

            page = &frame_table[pfn];
            switch ( (type_info = page->u.inuse.type_info) & PGT_type_mask )
            {
            case PGT_l1_page_table: 
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    okay = mod_l1_entry((l1_pgentry_t *)va, 
                                        mk_l1_pgentry(req.val)); 

                    if ( unlikely(ed->mm.shadow_mode) && okay &&
                         (get_shadow_status(&ed->mm, page-frame_table) &
                          PSH_shadowed) )
                    {
                        shadow_l1_normal_pt_update(
                            req.ptr, req.val, &prev_spfn, &prev_spl1e);
                        put_shadow_status(&ed->mm);
                    }

                    put_page_type(page);
                }
                break;
            case PGT_l2_page_table:
                if ( likely(get_page_type(page, PGT_l2_page_table)) )
                {
                    okay = mod_l2_entry((l2_pgentry_t *)va, 
                                        mk_l2_pgentry(req.val),
                                        pfn); 

                    if ( unlikely(ed->mm.shadow_mode) && okay &&
                         (get_shadow_status(&ed->mm, page-frame_table) & 
                          PSH_shadowed) )
                    {
                        shadow_l2_normal_pt_update(req.ptr, req.val);
                        put_shadow_status(&ed->mm);
                    }

                    put_page_type(page);
                }
                break;
            default:
                if ( likely(get_page_type(page, PGT_writable_page)) )
                {
                    *(unsigned long *)va = req.val;
                    okay = 1;
                    put_page_type(page);
                }
                break;
            }

            put_page(page);
            break;

        case MMU_MACHPHYS_UPDATE:
            if ( unlikely(!get_page_from_pagenr(pfn, FOREIGNDOM)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            machine_to_phys_mapping[pfn] = req.val;
            okay = 1;

            /*
             * If in log-dirty mode, mark the corresponding pseudo-physical
             * page as dirty.
             */
            if ( unlikely(ed->mm.shadow_mode == SHM_logdirty) && 
                 mark_dirty(&ed->mm, pfn) )
                ed->mm.shadow_dirty_block_count++;

            put_page(&frame_table[pfn]);
            break;

            /*
             * MMU_EXTENDED_COMMAND: Extended command is specified
             * in the least-siginificant bits of the 'value' field.
             */
        case MMU_EXTENDED_COMMAND:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            okay = do_extended_command(req.ptr, req.val);
            break;

        default:
            MEM_LOG("Invalid page update command %08lx", req.ptr);
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        ureqs++;
    }

 out:
    if ( prev_pfn != 0 )
        unmap_domain_mem((void *)va);

    if ( unlikely(prev_spl1e != 0) ) 
        unmap_domain_mem((void *)prev_spl1e);

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( deferred_ops & DOP_FLUSH_TLB )
        local_flush_tlb();
        
    if ( deferred_ops & DOP_RELOAD_LDT )
        (void)map_ldt_shadow_page(0);

    if ( unlikely(percpu_info[cpu].foreign != NULL) )
    {
        put_domain(percpu_info[cpu].foreign);
        percpu_info[cpu].foreign = NULL;
    }

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(pdone != NULL) )
        __put_user(done + i, pdone);

    UNLOCK_BIGLOCK(d);
    return rc;
}


int do_update_va_mapping(unsigned long page_nr, 
                         unsigned long val, 
                         unsigned long flags)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int err = 0;
    unsigned int cpu = ed->processor;
    unsigned long deferred_ops;

    perfc_incrc(calls_to_update_va);

    if ( unlikely(page_nr >= (HYPERVISOR_VIRT_START >> PAGE_SHIFT)) )
        return -EINVAL;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d, PTWR_CLEANUP_ACTIVE | PTWR_CLEANUP_INACTIVE);

    /*
     * XXX When we make this support 4MB superpages we should also deal with 
     * the case of updating L2 entries.
     */

    if ( unlikely(!mod_l1_entry(&linear_pg_table[page_nr], 
                                mk_l1_pgentry(val))) )
        err = -EINVAL;

    if ( unlikely(ed->mm.shadow_mode) )
    {
        unsigned long sval;

        l1pte_propagate_from_guest(&ed->mm, &val, &sval);

        if ( unlikely(__put_user(sval, ((unsigned long *)(
            &shadow_linear_pg_table[page_nr])))) )
        {
            /*
             * Since L2's are guranteed RW, failure indicates the page was not 
             * shadowed, so ignore.
             */
            perfc_incrc(shadow_update_va_fail);
        }

        /*
         * If we're in log-dirty mode then we need to note that we've updated
         * the PTE in the PT-holding page. We need the machine frame number
         * for this.
         */
        if ( ed->mm.shadow_mode == SHM_logdirty )
            mark_dirty(&current->mm, va_to_l1mfn(page_nr << PAGE_SHIFT));  
  
        check_pagetable(&ed->mm, ed->mm.pagetable, "va"); /* debug */
    }

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( unlikely(deferred_ops & DOP_FLUSH_TLB) || 
         unlikely(flags & UVMF_FLUSH_TLB) )
        local_flush_tlb();
    else if ( unlikely(flags & UVMF_INVLPG) )
        __flush_tlb_one(page_nr << PAGE_SHIFT);

    if ( unlikely(deferred_ops & DOP_RELOAD_LDT) )
        (void)map_ldt_shadow_page(0);
    
    UNLOCK_BIGLOCK(d);

    return err;
}

int do_update_va_mapping_otherdomain(unsigned long page_nr, 
                                     unsigned long val, 
                                     unsigned long flags,
                                     domid_t domid)
{
    unsigned int cpu = smp_processor_id();
    struct domain *d;
    int rc;

    if ( unlikely(!IS_PRIV(current->domain)) )
        return -EPERM;

    percpu_info[cpu].foreign = d = find_domain_by_id(domid);
    if ( unlikely(d == NULL) )
    {
        MEM_LOG("Unknown domain '%u'", domid);
        return -ESRCH;
    }

    rc = do_update_va_mapping(page_nr, val, flags);

    put_domain(d);
    percpu_info[cpu].foreign = NULL;

    return rc;
}



/*************************
 * Writable Pagetables
 */

ptwr_info_t ptwr_info[NR_CPUS];

#ifdef VERBOSE
int ptwr_debug = 0x0;
#define PTWR_PRINTK(_f, _a...) \
 do { if ( unlikely(ptwr_debug) ) printk( _f , ## _a ); } while ( 0 )
#define PTWR_PRINT_WHICH (which ? 'I' : 'A')
#else
#define PTWR_PRINTK(_f, _a...) ((void)0)
#endif

/* Flush the given writable p.t. page and write-protect it again. */
void ptwr_flush(const int which)
{
    unsigned long  sstat, spte, pte, *ptep, l1va;
    l1_pgentry_t  *sl1e = NULL, *pl1e, ol1e, nl1e;
    l2_pgentry_t  *pl2e;
    int            i, cpu = smp_processor_id();
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;

    l1va = ptwr_info[cpu].ptinfo[which].l1va;
    ptep = (unsigned long *)&linear_pg_table[l1va>>PAGE_SHIFT];

    /*
     * STEP 1. Write-protect the p.t. page so no more updates can occur.
     */

    if ( unlikely(__get_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not read pte at %p\n", ptep);
        /*
         * Really a bug. We could read this PTE during the initial fault,
         * and pagetables can't have changed meantime. XXX Multi-CPU guests?
         */
        BUG();
    }
    PTWR_PRINTK("[%c] disconnected_l1va at %p is %08lx\n",
                PTWR_PRINT_WHICH, ptep, pte);
    pte &= ~_PAGE_RW;

    if ( unlikely(ed->mm.shadow_mode) )
    {
        /* Write-protect the p.t. page in the shadow page table. */
        l1pte_propagate_from_guest(&ed->mm, &pte, &spte);
        __put_user(
            spte, (unsigned long *)&shadow_linear_pg_table[l1va>>PAGE_SHIFT]);

        /* Is the p.t. page itself shadowed? Map it into Xen space if so. */
        sstat = get_shadow_status(&ed->mm, pte >> PAGE_SHIFT);
        if ( sstat & PSH_shadowed )
            sl1e = map_domain_mem((sstat & PSH_pfn_mask) << PAGE_SHIFT);
    }

    /* Write-protect the p.t. page in the guest page table. */
    if ( unlikely(__put_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not update pte at %p\n", ptep);
        /*
         * Really a bug. We could write this PTE during the initial fault,
         * and pagetables can't have changed meantime. XXX Multi-CPU guests?
         */
        BUG();
    }

    /* Ensure that there are no stale writable mappings in any TLB. */
    /* NB. INVLPG is a serialising instruction: flushes pending updates. */
#if 1
    __flush_tlb_one(l1va); /* XXX Multi-CPU guests? */
#else
    flush_tlb_all();
#endif
    PTWR_PRINTK("[%c] disconnected_l1va at %p now %08lx\n",
                PTWR_PRINT_WHICH, ptep, pte);

    /*
     * STEP 2. Validate any modified PTEs.
     */

    pl1e = ptwr_info[cpu].ptinfo[which].pl1e;
    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
    {
        ol1e = ptwr_info[cpu].ptinfo[which].page[i];
        nl1e = pl1e[i];

        if ( likely(l1_pgentry_val(ol1e) == l1_pgentry_val(nl1e)) )
            continue;

        /*
         * Fast path for PTEs that have merely been write-protected
         * (e.g., during a Unix fork()). A strict reduction in privilege.
         */
        if ( likely(l1_pgentry_val(ol1e) == (l1_pgentry_val(nl1e)|_PAGE_RW)) )
        {
            if ( likely(l1_pgentry_val(nl1e) & _PAGE_PRESENT) )
            {
                if ( unlikely(sl1e != NULL) )
                    l1pte_propagate_from_guest(
                        &ed->mm, &l1_pgentry_val(nl1e), 
                        &l1_pgentry_val(sl1e[i]));
                put_page_type(&frame_table[l1_pgentry_to_pagenr(nl1e)]);
            }
            continue;
        }

        if ( unlikely(!get_page_from_l1e(nl1e, d)) )
        {
            MEM_LOG("ptwr: Could not re-validate l1 page\n");
            /*
             * Make the remaining p.t's consistent before crashing, so the
             * reference counts are correct.
             */
            memcpy(&pl1e[i], &ptwr_info[cpu].ptinfo[which].page[i],
                   (ENTRIES_PER_L1_PAGETABLE - i) * sizeof(l1_pgentry_t));
            unmap_domain_mem(pl1e);
            ptwr_info[cpu].ptinfo[which].l1va = 0;
            UNLOCK_BIGLOCK(d);
            domain_crash();
        }
        
        if ( unlikely(sl1e != NULL) )
            l1pte_propagate_from_guest(
                &ed->mm, &l1_pgentry_val(nl1e), &l1_pgentry_val(sl1e[i]));

        if ( unlikely(l1_pgentry_val(ol1e) & _PAGE_PRESENT) )
            put_page_from_l1e(ol1e, d);
    }
    unmap_domain_mem(pl1e);

    /*
     * STEP 3. Reattach the L1 p.t. page into the current address space.
     */

    if ( (which == PTWR_PT_ACTIVE) && likely(!ed->mm.shadow_mode) )
    {
        pl2e = &linear_l2_table[ptwr_info[cpu].ptinfo[which].l2_idx];
        *pl2e = mk_l2_pgentry(l2_pgentry_val(*pl2e) | _PAGE_PRESENT); 
    }

    /*
     * STEP 4. Final tidy-up.
     */

    ptwr_info[cpu].ptinfo[which].l1va = 0;

    if ( unlikely(sl1e != NULL) )
    {
        unmap_domain_mem(sl1e);
        put_shadow_status(&ed->mm);
    }
}

/* Write page fault handler: check if guest is trying to modify a PTE. */
int ptwr_do_page_fault(unsigned long addr)
{
    unsigned long    pte, pfn, l2e;
    struct pfn_info *page;
    l2_pgentry_t    *pl2e;
    int              which, cpu = smp_processor_id();
    u32              l2_idx;

    /*
     * Attempt to read the PTE that maps the VA being accessed. By checking for
     * PDE validity in the L2 we avoid many expensive fixups in __get_user().
     */
    if ( !(l2_pgentry_val(linear_l2_table[addr>>L2_PAGETABLE_SHIFT]) &
           _PAGE_PRESENT) ||
         __get_user(pte, (unsigned long *)&linear_pg_table[addr>>PAGE_SHIFT]) )
    {
        return 0;
    }

    pfn  = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((pte & (_PAGE_RW | _PAGE_PRESENT)) != _PAGE_PRESENT) ||
         ((page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table) )
    {
        return 0;
    }
    
    /* Get the L2 index at which this L1 p.t. is always mapped. */
    l2_idx = page->u.inuse.type_info & PGT_va_mask;
    if ( unlikely(l2_idx >= PGT_va_unknown) )
    {
        domain_crash(); /* Urk! This L1 is mapped in multiple L2 slots! */
    }
    l2_idx >>= PGT_va_shift;

    if ( l2_idx == (addr >> L2_PAGETABLE_SHIFT) )
    {
        MEM_LOG("PTWR failure! Pagetable maps itself at %08lx\n", addr);
        domain_crash();
    }

    /*
     * Is the L1 p.t. mapped into the current address space? If so we call it
     * an ACTIVE p.t., otherwise it is INACTIVE.
     */
    pl2e = &linear_l2_table[l2_idx];
    l2e  = l2_pgentry_val(*pl2e);
    which = PTWR_PT_INACTIVE;
    if ( (l2e >> PAGE_SHIFT) == pfn )
    {
        /* Check the PRESENT bit to set ACTIVE. */
        if ( likely(l2e & _PAGE_PRESENT) )
            which = PTWR_PT_ACTIVE;
        else {
            /*
             * If the PRESENT bit is clear, we may be conflicting with
             * the current ACTIVE p.t. (it may be the same p.t. mapped
             * at another virt addr).
             * The ptwr_flush call below will restore the PRESENT bit.
             */
            if ( ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va &&
                 l2_idx == ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l2_idx )
                which = PTWR_PT_ACTIVE;
        }
    }
    
    PTWR_PRINTK("[%c] page_fault on l1 pt at va %08lx, pt for %08x, "
                "pfn %08lx\n", PTWR_PRINT_WHICH,
                addr, l2_idx << L2_PAGETABLE_SHIFT, pfn);
    
    /*
     * We only allow one ACTIVE and one INACTIVE p.t. to be updated at at 
     * time. If there is already one, we must flush it out.
     */
    if ( ptwr_info[cpu].ptinfo[which].l1va )
        ptwr_flush(which);

    ptwr_info[cpu].ptinfo[which].l1va   = addr | 1;
    ptwr_info[cpu].ptinfo[which].l2_idx = l2_idx;
    
    /* For safety, disconnect the L1 p.t. page from current space. */
    if ( (which == PTWR_PT_ACTIVE) && likely(!current->mm.shadow_mode) )
    {
        *pl2e = mk_l2_pgentry(l2e & ~_PAGE_PRESENT);
#if 1
        flush_tlb(); /* XXX Multi-CPU guests? */
#else
        flush_tlb_all();
#endif
    }
    
    /* Temporarily map the L1 page, and make a copy of it. */
    ptwr_info[cpu].ptinfo[which].pl1e = map_domain_mem(pfn << PAGE_SHIFT);
    memcpy(ptwr_info[cpu].ptinfo[which].page,
           ptwr_info[cpu].ptinfo[which].pl1e,
           ENTRIES_PER_L1_PAGETABLE * sizeof(l1_pgentry_t));
    
    /* Finally, make the p.t. page writable by the guest OS. */
    pte |= _PAGE_RW;
    PTWR_PRINTK("[%c] update %p pte to %08lx\n", PTWR_PRINT_WHICH,
                &linear_pg_table[addr>>PAGE_SHIFT], pte);
    if ( unlikely(__put_user(pte, (unsigned long *)
                             &linear_pg_table[addr>>PAGE_SHIFT])) )
    {
        MEM_LOG("ptwr: Could not update pte at %p\n", (unsigned long *)
                &linear_pg_table[addr>>PAGE_SHIFT]);
        /* Toss the writable pagetable state and crash. */
        unmap_domain_mem(ptwr_info[cpu].ptinfo[which].pl1e);
        ptwr_info[cpu].ptinfo[which].l1va = 0;
        domain_crash();
    }
    
    return EXCRET_fault_fixed;
}

static __init int ptwr_init(void)
{
    int i;

    for ( i = 0; i < smp_num_cpus; i++ )
    {
        ptwr_info[i].ptinfo[PTWR_PT_ACTIVE].page =
            (void *)alloc_xenheap_page();
        ptwr_info[i].ptinfo[PTWR_PT_INACTIVE].page =
            (void *)alloc_xenheap_page();
    }

    return 0;
}
__initcall(ptwr_init);




/************************************************************************/
/************************************************************************/
/************************************************************************/

#ifndef NDEBUG

void ptwr_status(void)
{
    unsigned long pte, *ptep, pfn;
    struct pfn_info *page;
    int cpu = smp_processor_id();

    ptep = (unsigned long *)&linear_pg_table
        [ptwr_info[cpu].ptinfo[PTWR_PT_INACTIVE].l1va>>PAGE_SHIFT];

    if ( __get_user(pte, ptep) ) {
        MEM_LOG("ptwr: Could not read pte at %p\n", ptep);
        domain_crash();
    }

    pfn = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];
    printk("need to alloc l1 page %p\n", page);
    /* make pt page writable */
    printk("need to make read-only l1-page at %p is %08lx\n",
           ptep, pte);

    if ( ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va == 0 )
        return;

    if ( __get_user(pte, (unsigned long *)
                    ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va) ) {
        MEM_LOG("ptwr: Could not read pte at %p\n", (unsigned long *)
                ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va);
        domain_crash();
    }
    pfn = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];
}

void audit_domain(struct domain *d)
{
    int ttot=0, ctot=0, io_mappings=0, lowmem_mappings=0;

    void adjust (struct pfn_info *page, int dir, int adjtype)
    {
        int count = page->count_info & PGC_count_mask;

        if ( adjtype )
        {
            int tcount = page->u.inuse.type_info & PGT_count_mask;
            
            ttot++;

            tcount += dir;

            if ( tcount < 0 )
            {
                /* This will only come out once. */
                printk("Audit %d: type count whent below zero pfn=%x "
                       "taf=%x otaf=%x\n",
                       d->id, page-frame_table,
                       page->u.inuse.type_info,
                       page->tlbflush_timestamp);
            }
            
            page->u.inuse.type_info =
                (page->u.inuse.type_info & ~PGT_count_mask) | 
                (tcount & PGT_count_mask);
        }

        ctot++;
        count += dir;
        if ( count < 0 )
        {
            /* This will only come out once. */
            printk("Audit %d: general count whent below zero pfn=%x "
                   "taf=%x otaf=%x\n",
                   d->id, page-frame_table,
                   page->u.inuse.type_info,
                   page->tlbflush_timestamp);
        }
            
        page->count_info =
            (page->count_info & ~PGC_count_mask) | 
            (count & PGC_count_mask);            

    }

    void scan_for_pfn(struct domain *d, unsigned long xpfn)
    {
        unsigned long pfn, *pt;
        struct list_head *list_ent;
        struct pfn_info *page;
        int i;

        list_ent = d->page_list.next;
        for ( i = 0; (list_ent != &d->page_list); i++ )
        {
            pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;
            page = &frame_table[pfn];
            
            switch ( page->u.inuse.type_info & PGT_type_mask )
            {
            case PGT_l1_page_table:
            case PGT_l2_page_table:
                pt = map_domain_mem(pfn<<PAGE_SHIFT);
                for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
                    if ( (pt[i] & _PAGE_PRESENT) &&
                         ((pt[i] >> PAGE_SHIFT) == xpfn) )
                        printk("     found dom=%d i=%x pfn=%lx t=%x c=%x\n",
                               d->id, i, pfn, page->u.inuse.type_info,
                               page->count_info);
                unmap_domain_mem(pt);           
            }

            list_ent = frame_table[pfn].list.next;
        }

    }

    void scan_for_pfn_remote(unsigned long xpfn)
    {
        struct domain *e;
        for_each_domain ( e )
            scan_for_pfn( e, xpfn );            
    }   

    int i;
    unsigned long pfn;
    struct list_head *list_ent;
    struct pfn_info *page;

    if ( d != current->domain )
        domain_pause(d);
    synchronise_pagetables(~0UL);

    printk("pt base=%lx sh_info=%x\n",
           pagetable_val(d->exec_domain[0]->mm.pagetable)>>PAGE_SHIFT,
           virt_to_page(d->shared_info)-frame_table);
           
    spin_lock(&d->page_alloc_lock);

    /* PHASE 0 */

    list_ent = d->page_list.next;
    for ( i = 0; (list_ent != &d->page_list); i++ )
    {
        pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;       
        page = &frame_table[pfn];

        if ( page->u.inuse.domain != d )
            BUG();

        if ( (page->u.inuse.type_info & PGT_count_mask) >
             (page->count_info & PGC_count_mask) )
            printk("taf > caf %x %x pfn=%lx\n",
                   page->u.inuse.type_info, page->count_info, pfn );
 
#if 0   /* SYSV shared memory pages plus writeable files. */
        if ( (page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page && 
             (page->u.inuse.type_info & PGT_count_mask) > 1 )
        {
            printk("writeable page with type count >1: pfn=%lx t=%x c=%x\n",
                  pfn,
                  page->u.inuse.type_info,
                  page->count_info );
            scan_for_pfn_remote(pfn);
        }
#endif
        if ( (page->u.inuse.type_info & PGT_type_mask) == PGT_none && 
             (page->u.inuse.type_info & PGT_count_mask) > 1 )
        {
            printk("normal page with type count >1: pfn=%lx t=%x c=%x\n",
                  pfn,
                  page->u.inuse.type_info,
                  page->count_info );
        }

        /* Use tlbflush_timestamp to store original type_info. */
        page->tlbflush_timestamp = page->u.inuse.type_info;

        list_ent = frame_table[pfn].list.next;
    }


    /* PHASE 1 */

    adjust(&frame_table[pagetable_val(d->exec_domain[0]->mm.pagetable)>>PAGE_SHIFT], -1, 1);

    list_ent = d->page_list.next;
    for ( i = 0; (list_ent != &d->page_list); i++ )
    {
        unsigned long *pt;
        pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;       
        page = &frame_table[pfn];

        if ( page->u.inuse.domain != d )
            BUG();

        switch ( page->u.inuse.type_info & PGT_type_mask )
        {
        case PGT_l2_page_table:

            if ( (page->u.inuse.type_info & PGT_validated) != PGT_validated )
                printk("Audit %d: L2 not validated %x\n",
                       d->id, page->u.inuse.type_info);

            if ( (page->u.inuse.type_info & PGT_pinned) != PGT_pinned )
                printk("Audit %d: L2 not pinned %x\n",
                       d->id, page->u.inuse.type_info);
            else
                adjust( page, -1, 1 );
           
            pt = map_domain_mem( pfn<<PAGE_SHIFT );

            for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
            {
                if ( pt[i] & _PAGE_PRESENT )
                {
                    unsigned long l1pfn = pt[i]>>PAGE_SHIFT;
                    struct pfn_info *l1page = &frame_table[l1pfn];

                    if ( l1page->u.inuse.domain != d )
                    {
                        printk("L2: Skip bizarre page belonging to other "
                               "dom %p\n", l1page->u.inuse.domain);    
                        continue;
                    }
                    
                    if ( (l1page->u.inuse.type_info & PGT_type_mask) ==
                         PGT_l2_page_table )
                        printk("Audit %d: [%x] Found %s Linear PT "
                               "t=%x pfn=%lx\n", d->id, i, 
                               (l1pfn==pfn) ? "Self" : "Other",
                               l1page->u.inuse.type_info,
                               l1pfn);
                    else if ( (l1page->u.inuse.type_info & PGT_type_mask) !=
                              PGT_l1_page_table )
                        printk("Audit %d: [%x] Expected L1 t=%x pfn=%lx\n",
                               d->id, i,
                               l1page->u.inuse.type_info,
                               l1pfn);

                    adjust(l1page, -1, 1);
                }
            }

            unmap_domain_mem(pt);

            break;


        case PGT_l1_page_table:
            
            if ( (page->u.inuse.type_info & PGT_pinned) == PGT_pinned )
                adjust( page, -1, 1 );

            if ( (page->u.inuse.type_info & PGT_validated) != PGT_validated )
                printk("Audit %d: L1 not validated %x\n",
                       d->id, page->u.inuse.type_info);
#if 0
            if ( (page->u.inuse.type_info & PGT_pinned) != PGT_pinned )
                printk("Audit %d: L1 not pinned %x\n",
                       d->id, page->u.inuse.type_info);
#endif
            pt = map_domain_mem( pfn<<PAGE_SHIFT );

            for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
            {
                if ( pt[i] & _PAGE_PRESENT )
                {
                    unsigned long l1pfn = pt[i]>>PAGE_SHIFT;
                    struct pfn_info *l1page = &frame_table[l1pfn];

                    if ( l1pfn < 0x100 )
                    {
                        lowmem_mappings++;
                        continue;
                    }

                    if ( l1pfn > max_page )
                    {
                        io_mappings++;
                        continue;
                    }

                    if ( pt[i] & _PAGE_RW )
                    {

                        if ( (l1page->u.inuse.type_info & PGT_type_mask) ==
                             PGT_l1_page_table ||
                             (l1page->u.inuse.type_info & PGT_type_mask) ==
                             PGT_l2_page_table )
                            printk("Audit %d: [%x] Ilegal RW t=%x pfn=%lx\n",
                                   d->id, i,
                                   l1page->u.inuse.type_info,
                                   l1pfn);

                    }

                    if ( l1page->u.inuse.domain != d )
                    {
                        printk("Audit %d: [%lx,%x] Skip foreign page dom=%lx "
                               "pfn=%lx c=%08x t=%08x m2p=%lx\n",
                               d->id, pfn, i,
                               (unsigned long)l1page->u.inuse.domain,
                               l1pfn,
                               l1page->count_info,
                               l1page->u.inuse.type_info,
                               machine_to_phys_mapping[l1pfn]);    
                        continue;
                    }

                    adjust(l1page, -1, 0);
                }
            }

            unmap_domain_mem(pt);

            break;
        }       

        list_ent = frame_table[pfn].list.next;
    }

    if ( (io_mappings > 0) || (lowmem_mappings > 0) )
        printk("Audit %d: Found %d lowmem mappings and %d io mappings\n",
               d->id, lowmem_mappings, io_mappings);

    /* PHASE 2 */

    ctot = ttot = 0;
    list_ent = d->page_list.next;
    for ( i = 0; (list_ent != &d->page_list); i++ )
    {
        pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;
        page = &frame_table[pfn];

        switch ( page->u.inuse.type_info & PGT_type_mask)
        {
        case PGT_l1_page_table:
        case PGT_l2_page_table:
            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                printk("Audit %d: type count!=0 t=%x ot=%x c=%x pfn=%lx\n",
                       d->id, page->u.inuse.type_info, 
                       page->tlbflush_timestamp,
                       page->count_info, pfn );
                scan_for_pfn_remote(pfn);
            }
        default:
            if ( (page->count_info & PGC_count_mask) != 1 )
            {
                printk("Audit %d: gen count!=1 (c=%x) t=%x ot=%x pfn=%lx\n",
                       d->id, 
                       page->count_info,
                       page->u.inuse.type_info, 
                       page->tlbflush_timestamp, pfn );
                scan_for_pfn_remote(pfn);
            }
            break;
        }

        list_ent = frame_table[pfn].list.next;
    }

    /* PHASE 3 */

    list_ent = d->page_list.next;
    for ( i = 0; (list_ent != &d->page_list); i++ )
    {
        unsigned long *pt;
        pfn = list_entry(list_ent, struct pfn_info, list) - frame_table;
        page = &frame_table[pfn];

        switch ( page->u.inuse.type_info & PGT_type_mask )
        {
        case PGT_l2_page_table:
            if ( (page->u.inuse.type_info & PGT_pinned) == PGT_pinned )
                adjust( page, 1, 1 );          

            pt = map_domain_mem( pfn<<PAGE_SHIFT );

            for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
            {
                if ( pt[i] & _PAGE_PRESENT )
                {
                    unsigned long l1pfn = pt[i]>>PAGE_SHIFT;
                    struct pfn_info *l1page = &frame_table[l1pfn];

                    if ( l1page->u.inuse.domain == d)
                        adjust(l1page, 1, 1);
                }
            }

            unmap_domain_mem(pt);
            break;

        case PGT_l1_page_table:
            if ( (page->u.inuse.type_info & PGT_pinned) == PGT_pinned )
                adjust( page, 1, 1 );

            pt = map_domain_mem( pfn<<PAGE_SHIFT );

            for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
            {
                if ( pt[i] & _PAGE_PRESENT )
                {
                    unsigned long l1pfn = pt[i]>>PAGE_SHIFT;
                    struct pfn_info *l1page = &frame_table[l1pfn];

                    if ( (l1page->u.inuse.domain != d) ||
                         (l1pfn < 0x100) || (l1pfn > max_page) )
                        continue;

                    adjust(l1page, 1, 0);
                }
            }

            unmap_domain_mem(pt);
            break;
        }


        page->tlbflush_timestamp = 0;

        list_ent = frame_table[pfn].list.next;
    }

    spin_unlock(&d->page_alloc_lock);

    adjust(&frame_table[pagetable_val(d->exec_domain[0]->mm.pagetable)>>PAGE_SHIFT], 1, 1);

    printk("Audit %d: Done. ctot=%d ttot=%d\n", d->id, ctot, ttot );

    if ( d != current->domain )
        domain_unpause(d);
}

void audit_domains(void)
{
    struct domain *d;
    for_each_domain ( d )
        audit_domain(d);
}

void audit_domains_key(unsigned char key)
{
    audit_domains();
}

#endif
