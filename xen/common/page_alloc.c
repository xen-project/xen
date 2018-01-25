/******************************************************************************
 * page_alloc.c
 * 
 * Simple buddy heap allocator for Xen.
 * 
 * Copyright (c) 2002-2004 K A Fraser
 * Copyright (c) 2006 IBM Ryan Harper <ryanh@us.ibm.com>
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
 * In general Xen maintains two pools of memory:
 *
 * - Xen heap: Memory which is always mapped (i.e accessible by
 *             virtual address), via a permanent and contiguous
 *             "direct mapping". Macros like va() and pa() are valid
 *             for such memory and it is always permissible to stash
 *             pointers to Xen heap memory in data structures etc.
 *
 *             Xen heap pages are always anonymous (that is, not tied
 *             or accounted to any particular domain).
 *
 * - Dom heap: Memory which must be explicitly mapped, usually
 *             transiently with map_domain_page(), in order to be
 *             used. va() and pa() are not valid for such memory. Care
 *             should be taken when stashing pointers to dom heap
 *             pages that those mappings are permanent (e.g. vmap() or
 *             map_domain_page_global()), it is not safe to stash
 *             transient mappings such as those from map_domain_page()
 *
 *             Dom heap pages are often tied to a particular domain,
 *             but need not be (passing domain==NULL results in an
 *             anonymous dom heap allocation).
 *
 * The exact nature of this split is a (sub)arch decision which can
 * select one of three main variants:
 *
 * CONFIG_SEPARATE_XENHEAP=y
 *
 *   The xen heap is maintained as an entirely separate heap.
 *
 *   Arch code arranges for some (perhaps small) amount of physical
 *   memory to be covered by a direct mapping and registers that
 *   memory as the Xen heap (via init_xenheap_pages()) and the
 *   remainder as the dom heap.
 *
 *   This mode of operation is most commonly used by 32-bit arches
 *   where the virtual address space is insufficient to map all RAM.
 *
 * CONFIG_SEPARATE_XENHEAP=n W/ DIRECT MAP OF ALL RAM
 *
 *   All of RAM is covered by a permanent contiguous mapping and there
 *   is only a single heap.
 *
 *   Memory allocated from the Xen heap is flagged (in
 *   page_info.count_info) with PGC_xen_heap. Memory allocated from
 *   the Dom heap must still be explicitly mapped before use
 *   (e.g. with map_domain_page) in particular in common code.
 *
 *   xenheap_max_mfn() should not be called by arch code.
 *
 *   This mode of operation is most commonly used by 64-bit arches
 *   which have sufficient free virtual address space to permanently
 *   map the largest practical amount RAM currently expected on that
 *   arch.
 *
 * CONFIG_SEPARATE_XENHEAP=n W/ DIRECT MAP OF ONLY PARTIAL RAM
 *
 *   There is a single heap, but only the beginning (up to some
 *   threshold) is covered by a permanent contiguous mapping.
 *
 *   Memory allocated from the Xen heap is allocated from below the
 *   threshold and flagged with PGC_xen_heap. Memory allocated from
 *   the dom heap is allocated from anywhere in the heap (although it
 *   will prefer to allocate from as high as possible to try and keep
 *   Xen heap suitable memory available).
 *
 *   Arch code must call xenheap_max_mfn() to signal the limit of the
 *   direct mapping.
 *
 *   This mode of operation is most commonly used by 64-bit arches
 *   which have a restricted amount of virtual address space available
 *   for a direct map (due to e.g. reservations for other purposes)
 *   such that it is not possible to map all of RAM on systems with
 *   the largest practical amount of RAM currently expected on that
 *   arch.
 *
 * Boot Allocator
 *
 *   In addition to the two primary pools (xen heap and dom heap) a
 *   third "boot allocator" is used at start of day. This is a
 *   simplified allocator which can be used.
 *
 *   Typically all memory which is destined to be dom heap memory
 *   (which is everything in the CONFIG_SEPARATE_XENHEAP=n
 *   configurations) is first allocated to the boot allocator (with
 *   init_boot_pages()) and is then handed over to the main dom heap in
 *   end_boot_allocator().
 *
 * "Contiguous" mappings
 *
 *   Note that although the above talks about "contiguous" mappings
 *   some architectures implement a scheme ("PDX compression") to
 *   compress unused portions of the machine address space (i.e. large
 *   gaps between distinct banks of memory) in order to avoid creating
 *   enormous frame tables and direct maps which mostly map
 *   nothing. Thus a contiguous mapping may still have distinct
 *   regions within it.
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/keyhandler.h>
#include <xen/perfc.h>
#include <xen/pfn.h>
#include <xen/numa.h>
#include <xen/nodemask.h>
#include <xen/event.h>
#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#include <public/sysctl.h>
#include <public/sched.h>
#include <asm/page.h>
#include <asm/numa.h>
#include <asm/flushtlb.h>
#ifdef CONFIG_X86
#include <asm/guest.h>
#include <asm/p2m.h>
#include <asm/setup.h> /* for highmem_start only */
#else
#define p2m_pod_offline_or_broken_hit(pg) 0
#define p2m_pod_offline_or_broken_replace(pg) BUG_ON(pg != NULL)
#endif

/*
 * Comma-separated list of hexadecimal page numbers containing bad bytes.
 * e.g. 'badpage=0x3f45,0x8a321'.
 */
static char __initdata opt_badpage[100] = "";
string_param("badpage", opt_badpage);

/*
 * no-bootscrub -> Free pages are not zeroed during boot.
 */
static bool_t opt_bootscrub __initdata = 1;
boolean_param("bootscrub", opt_bootscrub);

/*
 * bootscrub_chunk -> Amount of bytes to scrub lockstep on non-SMT CPUs
 * on all NUMA nodes.
 */
static unsigned long __initdata opt_bootscrub_chunk = MB(128);
size_param("bootscrub_chunk", opt_bootscrub_chunk);

#ifdef CONFIG_SCRUB_DEBUG
static bool __read_mostly scrub_debug;
#else
#define scrub_debug    false
#endif

/*
 * Bit width of the DMA heap -- used to override NUMA-node-first.
 * allocation strategy, which can otherwise exhaust low memory.
 */
static unsigned int dma_bitsize;
integer_param("dma_bits", dma_bitsize);

/* Offlined page list, protected by heap_lock. */
PAGE_LIST_HEAD(page_offlined_list);
/* Broken page list, protected by heap_lock. */
PAGE_LIST_HEAD(page_broken_list);

/*************************
 * BOOT-TIME ALLOCATOR
 */

/*
 * first_valid_mfn is exported because it is use in ARM specific NUMA
 * helpers. See comment in asm-arm/numa.h.
 */
unsigned long first_valid_mfn = ~0UL;

static struct bootmem_region {
    unsigned long s, e; /* MFNs @s through @e-1 inclusive are free */
} *__initdata bootmem_region_list;
static unsigned int __initdata nr_bootmem_regions;

struct scrub_region {
    unsigned long offset;
    unsigned long start;
    unsigned long per_cpu_sz;
    unsigned long rem;
    cpumask_t cpus;
};
static struct scrub_region __initdata region[MAX_NUMNODES];
static unsigned long __initdata chunk_size;

static void __init bootmem_region_add(unsigned long s, unsigned long e)
{
    unsigned int i;

    if ( (bootmem_region_list == NULL) && (s < e) )
        bootmem_region_list = mfn_to_virt(s++);

    if ( s >= e )
        return;

    for ( i = 0; i < nr_bootmem_regions; i++ )
        if ( s < bootmem_region_list[i].e )
            break;

    BUG_ON((i < nr_bootmem_regions) && (e > bootmem_region_list[i].s));
    BUG_ON(nr_bootmem_regions == (PAGE_SIZE / sizeof(struct bootmem_region)));

    memmove(&bootmem_region_list[i+1], &bootmem_region_list[i],
            (nr_bootmem_regions - i) * sizeof(*bootmem_region_list));
    bootmem_region_list[i] = (struct bootmem_region) { s, e };
    nr_bootmem_regions++;
}

static void __init bootmem_region_zap(unsigned long s, unsigned long e)
{
    unsigned int i;

    for ( i = 0; i < nr_bootmem_regions; i++ )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( e <= r->s )
            break;
        if ( s >= r->e )
            continue;
        if ( s <= r->s )
        {
            r->s = min(e, r->e);
        }
        else if ( e >= r->e )
        {
            r->e = s;
        }
        else
        {
            unsigned long _e = r->e;
            r->e = s;
            bootmem_region_add(e, _e);
        }
    }
}

void __init init_boot_pages(paddr_t ps, paddr_t pe)
{
    unsigned long bad_spfn, bad_epfn;
    const char *p;
#ifdef CONFIG_X86
    const unsigned long *badpage = NULL;
    unsigned int i, array_size;

    BUILD_BUG_ON(8 * sizeof(frame_table->u.free.first_dirty) <
                 MAX_ORDER + 1);
#endif
    BUILD_BUG_ON(sizeof(frame_table->u) != sizeof(unsigned long));

    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    first_valid_mfn = min_t(unsigned long, ps >> PAGE_SHIFT, first_valid_mfn);

    bootmem_region_add(ps >> PAGE_SHIFT, pe >> PAGE_SHIFT);

#ifdef CONFIG_X86
    /* 
     * Here we put platform-specific memory range workarounds, i.e.
     * memory known to be corrupt or otherwise in need to be reserved on
     * specific platforms.
     * We get these certain pages and remove them from memory region list.
     */
    badpage = get_platform_badpages(&array_size);
    if ( badpage )
    {
        for ( i = 0; i < array_size; i++ )
        {
            bootmem_region_zap(*badpage >> PAGE_SHIFT,
                               (*badpage >> PAGE_SHIFT) + 1);
            badpage++;
        }
    }

    if ( xen_guest )
    {
        badpage = hypervisor_reserved_pages(&array_size);
        if ( badpage )
        {
            for ( i = 0; i < array_size; i++ )
            {
                bootmem_region_zap(*badpage >> PAGE_SHIFT,
                                   (*badpage >> PAGE_SHIFT) + 1);
                badpage++;
            }
        }
    }
#endif

    /* Check new pages against the bad-page list. */
    p = opt_badpage;
    while ( *p != '\0' )
    {
        bad_spfn = simple_strtoul(p, &p, 0);
        bad_epfn = bad_spfn;

        if ( *p == '-' )
        {
            p++;
            bad_epfn = simple_strtoul(p, &p, 0);
            if ( bad_epfn < bad_spfn )
                bad_epfn = bad_spfn;
        }

        if ( *p == ',' )
            p++;
        else if ( *p != '\0' )
            break;

        bootmem_region_zap(bad_spfn, bad_epfn+1);
    }
}

mfn_t __init alloc_boot_pages(unsigned long nr_pfns, unsigned long pfn_align)
{
    unsigned long pg, _e;
    unsigned int i = nr_bootmem_regions;

    BUG_ON(!nr_bootmem_regions);

    while ( i-- )
    {
        struct bootmem_region *r = &bootmem_region_list[i];

        pg = (r->e - nr_pfns) & ~(pfn_align - 1);
        if ( pg >= r->e || pg < r->s )
            continue;

#if defined(CONFIG_X86) && !defined(NDEBUG)
        /*
         * Filtering pfn_align == 1 since the only allocations using a bigger
         * alignment are the ones used for setting up the frame table chunks.
         * Those allocations get remapped anyway, i.e. them not having 1:1
         * mappings always accessible is not a problem.
         */
        if ( highmem_start && pfn_align == 1 &&
             r->e > PFN_DOWN(highmem_start) )
        {
            pg = r->s;
            if ( pg + nr_pfns > PFN_DOWN(highmem_start) )
                continue;
            r->s = pg + nr_pfns;
            return _mfn(pg);
        }
#endif

        _e = r->e;
        r->e = pg;
        bootmem_region_add(pg + nr_pfns, _e);
        return _mfn(pg);
    }

    BUG();
}



/*************************
 * BINARY BUDDY ALLOCATOR
 */

#define MEMZONE_XEN 0
#define NR_ZONES    (PADDR_BITS - PAGE_SHIFT + 1)

#define bits_to_zone(b) (((b) < (PAGE_SHIFT + 1)) ? 1 : ((b) - PAGE_SHIFT))
#define page_to_zone(pg) (is_xen_heap_page(pg) ? MEMZONE_XEN :  \
                          (flsl(page_to_mfn(pg)) ? : 1))

typedef struct page_list_head heap_by_zone_and_order_t[NR_ZONES][MAX_ORDER+1];
static heap_by_zone_and_order_t *_heap[MAX_NUMNODES];
#define heap(node, zone, order) ((*_heap[node])[zone][order])

static unsigned long node_need_scrub[MAX_NUMNODES];

static unsigned long *avail[MAX_NUMNODES];
static long total_avail_pages;

/* TMEM: Reserve a fraction of memory for mid-size (0<order<9) allocations.*/
static long midsize_alloc_zone_pages;
#define MIDSIZE_ALLOC_FRAC 128

static DEFINE_SPINLOCK(heap_lock);
static long outstanding_claims; /* total outstanding claims by all domains */

unsigned long domain_adjust_tot_pages(struct domain *d, long pages)
{
    long dom_before, dom_after, dom_claimed, sys_before, sys_after;

    ASSERT(spin_is_locked(&d->page_alloc_lock));
    d->tot_pages += pages;

    /*
     * can test d->claimed_pages race-free because it can only change
     * if d->page_alloc_lock and heap_lock are both held, see also
     * domain_set_outstanding_pages below
     */
    if ( !d->outstanding_pages )
        goto out;

    spin_lock(&heap_lock);
    /* adjust domain outstanding pages; may not go negative */
    dom_before = d->outstanding_pages;
    dom_after = dom_before - pages;
    BUG_ON(dom_before < 0);
    dom_claimed = dom_after < 0 ? 0 : dom_after;
    d->outstanding_pages = dom_claimed;
    /* flag accounting bug if system outstanding_claims would go negative */
    sys_before = outstanding_claims;
    sys_after = sys_before - (dom_before - dom_claimed);
    BUG_ON(sys_after < 0);
    outstanding_claims = sys_after;
    spin_unlock(&heap_lock);

out:
    return d->tot_pages;
}

int domain_set_outstanding_pages(struct domain *d, unsigned long pages)
{
    int ret = -ENOMEM;
    unsigned long claim, avail_pages;

    /*
     * take the domain's page_alloc_lock, else all d->tot_page adjustments
     * must always take the global heap_lock rather than only in the much
     * rarer case that d->outstanding_pages is non-zero
     */
    spin_lock(&d->page_alloc_lock);
    spin_lock(&heap_lock);

    /* pages==0 means "unset" the claim. */
    if ( pages == 0 )
    {
        outstanding_claims -= d->outstanding_pages;
        d->outstanding_pages = 0;
        ret = 0;
        goto out;
    }

    /* only one active claim per domain please */
    if ( d->outstanding_pages )
    {
        ret = -EINVAL;
        goto out;
    }

    /* disallow a claim not exceeding current tot_pages or above max_pages */
    if ( (pages <= d->tot_pages) || (pages > d->max_pages) )
    {
        ret = -EINVAL;
        goto out;
    }

    /* how much memory is available? */
    avail_pages = total_avail_pages;

    /* Note: The usage of claim means that allocation from a guest *might*
     * have to come from freeable memory. Using free memory is always better, if
     * it is available, than using freeable memory.
     *
     * But that is OK as once the claim has been made, it still can take minutes
     * before the claim is fully satisfied. Tmem can make use of the unclaimed
     * pages during this time (to store ephemeral/freeable pages only,
     * not persistent pages).
     */
    avail_pages += tmem_freeable_pages();
    avail_pages -= outstanding_claims;

    /*
     * Note, if domain has already allocated memory before making a claim
     * then the claim must take tot_pages into account
     */
    claim = pages - d->tot_pages;
    if ( claim > avail_pages )
        goto out;

    /* yay, claim fits in available memory, stake the claim, success! */
    d->outstanding_pages = claim;
    outstanding_claims += d->outstanding_pages;
    ret = 0;

out:
    spin_unlock(&heap_lock);
    spin_unlock(&d->page_alloc_lock);
    return ret;
}

void get_outstanding_claims(uint64_t *free_pages, uint64_t *outstanding_pages)
{
    spin_lock(&heap_lock);
    *outstanding_pages = outstanding_claims;
    *free_pages =  avail_domheap_pages();
    spin_unlock(&heap_lock);
}

static bool_t __read_mostly first_node_initialised;
#ifndef CONFIG_SEPARATE_XENHEAP
static unsigned int __read_mostly xenheap_bits;
#else
#define xenheap_bits 0
#endif

static unsigned long init_node_heap(int node, unsigned long mfn,
                                    unsigned long nr, bool_t *use_tail)
{
    /* First node to be discovered has its heap metadata statically alloced. */
    static heap_by_zone_and_order_t _heap_static;
    static unsigned long avail_static[NR_ZONES];
    unsigned long needed = (sizeof(**_heap) +
                            sizeof(**avail) * NR_ZONES +
                            PAGE_SIZE - 1) >> PAGE_SHIFT;
    int i, j;

    if ( !first_node_initialised )
    {
        _heap[node] = &_heap_static;
        avail[node] = avail_static;
        first_node_initialised = 1;
        needed = 0;
    }
    else if ( *use_tail && nr >= needed &&
              arch_mfn_in_directmap(mfn + nr) &&
              (!xenheap_bits ||
               !((mfn + nr - 1) >> (xenheap_bits - PAGE_SHIFT))) )
    {
        _heap[node] = mfn_to_virt(mfn + nr - needed);
        avail[node] = mfn_to_virt(mfn + nr - 1) +
                      PAGE_SIZE - sizeof(**avail) * NR_ZONES;
    }
    else if ( nr >= needed &&
              arch_mfn_in_directmap(mfn + needed) &&
              (!xenheap_bits ||
               !((mfn + needed - 1) >> (xenheap_bits - PAGE_SHIFT))) )
    {
        _heap[node] = mfn_to_virt(mfn);
        avail[node] = mfn_to_virt(mfn + needed - 1) +
                      PAGE_SIZE - sizeof(**avail) * NR_ZONES;
        *use_tail = 0;
    }
    else if ( get_order_from_bytes(sizeof(**_heap)) ==
              get_order_from_pages(needed) )
    {
        _heap[node] = alloc_xenheap_pages(get_order_from_pages(needed), 0);
        BUG_ON(!_heap[node]);
        avail[node] = (void *)_heap[node] + (needed << PAGE_SHIFT) -
                      sizeof(**avail) * NR_ZONES;
        needed = 0;
    }
    else
    {
        _heap[node] = xmalloc(heap_by_zone_and_order_t);
        avail[node] = xmalloc_array(unsigned long, NR_ZONES);
        BUG_ON(!_heap[node] || !avail[node]);
        needed = 0;
    }

    memset(avail[node], 0, NR_ZONES * sizeof(long));

    for ( i = 0; i < NR_ZONES; i++ )
        for ( j = 0; j <= MAX_ORDER; j++ )
            INIT_PAGE_LIST_HEAD(&heap(node, i, j));

    return needed;
}

/* Default to 64 MiB */
#define DEFAULT_LOW_MEM_VIRQ    (((paddr_t) 64)   << 20)
#define MAX_LOW_MEM_VIRQ        (((paddr_t) 1024) << 20)

static paddr_t __read_mostly opt_low_mem_virq = ((paddr_t) -1);
size_param("low_mem_virq_limit", opt_low_mem_virq);

/* Thresholds to control hysteresis. In pages */
/* When memory grows above this threshold, reset hysteresis.
 * -1 initially to not reset until at least one virq issued. */
static unsigned long low_mem_virq_high      = -1UL;
/* Threshold at which we issue virq */
static unsigned long low_mem_virq_th        = 0;
/* Original threshold after all checks completed */
static unsigned long low_mem_virq_orig      = 0;
/* Order for current threshold */
static unsigned int  low_mem_virq_th_order  = 0;

/* Perform bootstrapping checks and set bounds */
static void __init setup_low_mem_virq(void)
{
    unsigned int order;
    paddr_t threshold;
    bool_t halve;

    /* If the user specifies zero, then he/she doesn't want this virq
     * to ever trigger. */
    if ( opt_low_mem_virq == 0 )
    {
        low_mem_virq_th = -1UL;
        return;
    }

    /* If the user did not specify a knob, remember that */
    halve = (opt_low_mem_virq == ((paddr_t) -1));
    threshold = halve ? DEFAULT_LOW_MEM_VIRQ : opt_low_mem_virq;

    /* Dom0 has already been allocated by now. So check we won't be
     * complaining immediately with whatever's left of the heap. */
    threshold = min(threshold,
                    ((paddr_t) total_avail_pages) << PAGE_SHIFT);

    /* Then, cap to some predefined maximum */
    threshold = min(threshold, MAX_LOW_MEM_VIRQ);

    /* If the user specified no knob, and we are at the current available
     * level, halve the threshold. */
    if ( halve &&
         (threshold == (((paddr_t) total_avail_pages) << PAGE_SHIFT)) )
        threshold >>= 1;

    /* Zero? Have to fire immediately */
    threshold = max(threshold, (paddr_t) PAGE_SIZE);

    /* Threshold bytes -> pages */
    low_mem_virq_th = threshold >> PAGE_SHIFT;

    /* Next, round the threshold down to the next order */
    order = get_order_from_pages(low_mem_virq_th);
    if ( (1UL << order) > low_mem_virq_th )
        order--;

    /* Set bounds, ready to go */
    low_mem_virq_th = low_mem_virq_orig = 1UL << order;
    low_mem_virq_th_order = order;

    printk("Initial low memory virq threshold set at %#lx pages.\n",
            low_mem_virq_th);
}

static void check_low_mem_virq(void)
{
    unsigned long avail_pages = total_avail_pages +
        tmem_freeable_pages() - outstanding_claims;

    if ( unlikely(avail_pages <= low_mem_virq_th) )
    {
        send_global_virq(VIRQ_ENOMEM);

        /* Update thresholds. Next warning will be when we drop below
         * next order. However, we wait until we grow beyond one
         * order above us to complain again at the current order */
        low_mem_virq_high   = 1UL << (low_mem_virq_th_order + 1);
        if ( low_mem_virq_th_order > 0 )
            low_mem_virq_th_order--;
        low_mem_virq_th     = 1UL << low_mem_virq_th_order;
        return;
    }

    if ( unlikely(avail_pages >= low_mem_virq_high) )
    {
        /* Reset hysteresis. Bring threshold up one order.
         * If we are back where originally set, set high
         * threshold to -1 to avoid further growth of
         * virq threshold. */
        low_mem_virq_th_order++;
        low_mem_virq_th = 1UL << low_mem_virq_th_order;
        if ( low_mem_virq_th == low_mem_virq_orig )
            low_mem_virq_high = -1UL;
        else
            low_mem_virq_high = 1UL << (low_mem_virq_th_order + 2);
    }
}

/* Pages that need a scrub are added to tail, otherwise to head. */
static void page_list_add_scrub(struct page_info *pg, unsigned int node,
                                unsigned int zone, unsigned int order,
                                unsigned int first_dirty)
{
    PFN_ORDER(pg) = order;
    pg->u.free.first_dirty = first_dirty;
    pg->u.free.scrub_state = BUDDY_NOT_SCRUBBING;

    if ( first_dirty != INVALID_DIRTY_IDX )
    {
        ASSERT(first_dirty < (1U << order));
        page_list_add_tail(pg, &heap(node, zone, order));
    }
    else
        page_list_add(pg, &heap(node, zone, order));
}

/* SCRUB_PATTERN needs to be a repeating series of bytes. */
#ifndef NDEBUG
#define SCRUB_PATTERN        0xc2c2c2c2c2c2c2c2ULL
#else
#define SCRUB_PATTERN        0ULL
#endif
#define SCRUB_BYTE_PATTERN   (SCRUB_PATTERN & 0xff)

static void poison_one_page(struct page_info *pg)
{
#ifdef CONFIG_SCRUB_DEBUG
    mfn_t mfn = _mfn(page_to_mfn(pg));
    uint64_t *ptr;

    if ( !scrub_debug )
        return;

    ptr = map_domain_page(mfn);
    *ptr = ~SCRUB_PATTERN;
    unmap_domain_page(ptr);
#endif
}

static void check_one_page(struct page_info *pg)
{
#ifdef CONFIG_SCRUB_DEBUG
    mfn_t mfn = _mfn(page_to_mfn(pg));
    const uint64_t *ptr;
    unsigned int i;

    if ( !scrub_debug )
        return;

    ptr = map_domain_page(mfn);
    for ( i = 0; i < PAGE_SIZE / sizeof (*ptr); i++ )
        BUG_ON(ptr[i] != SCRUB_PATTERN);
    unmap_domain_page(ptr);
#endif
}

static void check_and_stop_scrub(struct page_info *head)
{
    if ( head->u.free.scrub_state == BUDDY_SCRUBBING )
    {
        typeof(head->u.free) pgfree;

        head->u.free.scrub_state = BUDDY_SCRUB_ABORT;
        spin_lock_kick();
        for ( ; ; )
        {
            /* Can't ACCESS_ONCE() a bitfield. */
            pgfree.val = ACCESS_ONCE(head->u.free.val);
            if ( pgfree.scrub_state != BUDDY_SCRUB_ABORT )
                break;
            cpu_relax();
        }
    }
}

static struct page_info *get_free_buddy(unsigned int zone_lo,
                                        unsigned int zone_hi,
                                        unsigned int order, unsigned int memflags,
                                        const struct domain *d)
{
    nodeid_t first_node, node = MEMF_get_node(memflags), req_node = node;
    nodemask_t nodemask = d ? d->node_affinity : node_online_map;
    unsigned int j, zone, nodemask_retry = 0;
    struct page_info *pg;
    bool use_unscrubbed = (memflags & MEMF_no_scrub);

    if ( node == NUMA_NO_NODE )
    {
        if ( d != NULL )
        {
            node = next_node(d->last_alloc_node, nodemask);
            if ( node >= MAX_NUMNODES )
                node = first_node(nodemask);
        }
        if ( node >= MAX_NUMNODES )
            node = cpu_to_node(smp_processor_id());
    }
    else if ( unlikely(node >= MAX_NUMNODES) )
    {
        ASSERT_UNREACHABLE();
        return NULL;
    }
    first_node = node;

    /*
     * Start with requested node, but exhaust all node memory in requested 
     * zone before failing, only calc new node value if we fail to find memory 
     * in target node, this avoids needless computation on fast-path.
     */
    for ( ; ; )
    {
        zone = zone_hi;
        do {
            /* Check if target node can support the allocation. */
            if ( !avail[node] || (avail[node][zone] < (1UL << order)) )
                continue;

            /* Find smallest order which can satisfy the request. */
            for ( j = order; j <= MAX_ORDER; j++ )
            {
                if ( (pg = page_list_remove_head(&heap(node, zone, j))) )
                {
                    if ( pg->u.free.first_dirty == INVALID_DIRTY_IDX )
                        return pg;
                    /*
                     * We grab single pages (order=0) even if they are
                     * unscrubbed. Given that scrubbing one page is fairly quick
                     * it is not worth breaking higher orders.
                     */
                    if ( (order == 0) || use_unscrubbed )
                    {
                        check_and_stop_scrub(pg);
                        return pg;
                    }

                    page_list_add_tail(pg, &heap(node, zone, j));
                }
            }
        } while ( zone-- > zone_lo ); /* careful: unsigned zone may wrap */

        if ( (memflags & MEMF_exact_node) && req_node != NUMA_NO_NODE )
            return NULL;

        /* Pick next node. */
        if ( !node_isset(node, nodemask) )
        {
            /* Very first node may be caller-specified and outside nodemask. */
            ASSERT(!nodemask_retry);
            first_node = node = first_node(nodemask);
            if ( node < MAX_NUMNODES )
                continue;
        }
        else if ( (node = next_node(node, nodemask)) >= MAX_NUMNODES )
            node = first_node(nodemask);
        if ( node == first_node )
        {
            /* When we have tried all in nodemask, we fall back to others. */
            if ( (memflags & MEMF_exact_node) || nodemask_retry++ )
                return NULL;
            nodes_andnot(nodemask, node_online_map, nodemask);
            first_node = node = first_node(nodemask);
            if ( node >= MAX_NUMNODES )
                return NULL;
        }
    }
}

/* Allocate 2^@order contiguous pages. */
static struct page_info *alloc_heap_pages(
    unsigned int zone_lo, unsigned int zone_hi,
    unsigned int order, unsigned int memflags,
    struct domain *d)
{
    nodeid_t node;
    unsigned int i, buddy_order, zone, first_dirty;
    unsigned long request = 1UL << order;
    struct page_info *pg;
    bool need_tlbflush = false;
    uint32_t tlbflush_timestamp = 0;
    unsigned int dirty_cnt = 0;

    /* Make sure there are enough bits in memflags for nodeID. */
    BUILD_BUG_ON((_MEMF_bits - _MEMF_node) < (8 * sizeof(nodeid_t)));

    ASSERT(zone_lo <= zone_hi);
    ASSERT(zone_hi < NR_ZONES);

    if ( unlikely(order > MAX_ORDER) )
        return NULL;

    spin_lock(&heap_lock);

    /*
     * Claimed memory is considered unavailable unless the request
     * is made by a domain with sufficient unclaimed pages.
     */
    if ( (outstanding_claims + request >
          total_avail_pages + tmem_freeable_pages()) &&
          ((memflags & MEMF_no_refcount) ||
           !d || d->outstanding_pages < request) )
    {
        spin_unlock(&heap_lock);
        return NULL;
    }

    /*
     * TMEM: When available memory is scarce due to tmem absorbing it, allow
     * only mid-size allocations to avoid worst of fragmentation issues.
     * Others try tmem pools then fail.  This is a workaround until all
     * post-dom0-creation-multi-page allocations can be eliminated.
     */
    if ( ((order == 0) || (order >= 9)) &&
         (total_avail_pages <= midsize_alloc_zone_pages) &&
         tmem_freeable_pages() )
    {
        /* Try to free memory from tmem. */
        pg = tmem_relinquish_pages(order, memflags);
        spin_unlock(&heap_lock);
        return pg;
    }

    pg = get_free_buddy(zone_lo, zone_hi, order, memflags, d);
    /* Try getting a dirty buddy if we couldn't get a clean one. */
    if ( !pg && !(memflags & MEMF_no_scrub) )
        pg = get_free_buddy(zone_lo, zone_hi, order,
                            memflags | MEMF_no_scrub, d);
    if ( !pg )
    {
        /* No suitable memory blocks. Fail the request. */
        spin_unlock(&heap_lock);
        return NULL;
    }

    node = phys_to_nid(page_to_maddr(pg));
    zone = page_to_zone(pg);
    buddy_order = PFN_ORDER(pg);

    first_dirty = pg->u.free.first_dirty;

    /* We may have to halve the chunk a number of times. */
    while ( buddy_order != order )
    {
        buddy_order--;
        page_list_add_scrub(pg, node, zone, buddy_order,
                            (1U << buddy_order) > first_dirty ?
                            first_dirty : INVALID_DIRTY_IDX);
        pg += 1U << buddy_order;

        if ( first_dirty != INVALID_DIRTY_IDX )
        {
            /* Adjust first_dirty */
            if ( first_dirty >= 1U << buddy_order )
                first_dirty -= 1U << buddy_order;
            else
                first_dirty = 0; /* We've moved past original first_dirty */
        }
    }

    ASSERT(avail[node][zone] >= request);
    avail[node][zone] -= request;
    total_avail_pages -= request;
    ASSERT(total_avail_pages >= 0);

    check_low_mem_virq();

    if ( d != NULL )
        d->last_alloc_node = node;

    for ( i = 0; i < (1 << order); i++ )
    {
        /* Reference count must continuously be zero for free pages. */
        BUG_ON((pg[i].count_info & ~PGC_need_scrub) != PGC_state_free);

        /* PGC_need_scrub can only be set if first_dirty is valid */
        ASSERT(first_dirty != INVALID_DIRTY_IDX || !(pg[i].count_info & PGC_need_scrub));

        /* Preserve PGC_need_scrub so we can check it after lock is dropped. */
        pg[i].count_info = PGC_state_inuse | (pg[i].count_info & PGC_need_scrub);

        if ( !(memflags & MEMF_no_tlbflush) )
            accumulate_tlbflush(&need_tlbflush, &pg[i],
                                &tlbflush_timestamp);

        /* Initialise fields which have other uses for free pages. */
        pg[i].u.inuse.type_info = 0;
        page_set_owner(&pg[i], NULL);

        /* Ensure cache and RAM are consistent for platforms where the
         * guest can control its own visibility of/through the cache.
         */
        flush_page_to_ram(page_to_mfn(&pg[i]), !(memflags & MEMF_no_icache_flush));
    }

    spin_unlock(&heap_lock);

    if ( first_dirty != INVALID_DIRTY_IDX ||
         (scrub_debug && !(memflags & MEMF_no_scrub)) )
    {
        for ( i = 0; i < (1U << order); i++ )
        {
            if ( test_bit(_PGC_need_scrub, &pg[i].count_info) )
            {
                if ( !(memflags & MEMF_no_scrub) )
                    scrub_one_page(&pg[i]);

                dirty_cnt++;

                spin_lock(&heap_lock);
                pg[i].count_info &= ~PGC_need_scrub;
                spin_unlock(&heap_lock);
            }
            else if ( !(memflags & MEMF_no_scrub) )
                check_one_page(&pg[i]);
        }

        if ( dirty_cnt )
        {
            spin_lock(&heap_lock);
            node_need_scrub[node] -= dirty_cnt;
            spin_unlock(&heap_lock);
        }
    }

    if ( need_tlbflush )
        filtered_flush_tlb_mask(tlbflush_timestamp);

    return pg;
}

/* Remove any offlined page in the buddy pointed to by head. */
static int reserve_offlined_page(struct page_info *head)
{
    unsigned int node = phys_to_nid(page_to_maddr(head));
    int zone = page_to_zone(head), i, head_order = PFN_ORDER(head), count = 0;
    struct page_info *cur_head;
    unsigned int cur_order, first_dirty;

    ASSERT(spin_is_locked(&heap_lock));

    cur_head = head;

    check_and_stop_scrub(head);
    /*
     * We may break the buddy so let's mark the head as clean. Then, when
     * merging chunks back into the heap, we will see whether the chunk has
     * unscrubbed pages and set its first_dirty properly.
     */
    first_dirty = head->u.free.first_dirty;
    head->u.free.first_dirty = INVALID_DIRTY_IDX;

    page_list_del(head, &heap(node, zone, head_order));

    while ( cur_head < (head + (1 << head_order)) )
    {
        struct page_info *pg;
        int next_order;

        if ( page_state_is(cur_head, offlined) )
        {
            cur_head++;
            if ( first_dirty != INVALID_DIRTY_IDX && first_dirty )
                first_dirty--;
            continue;
        }

        next_order = cur_order = 0;

        while ( cur_order < head_order )
        {
            next_order = cur_order + 1;

            if ( (cur_head + (1 << next_order)) >= (head + ( 1 << head_order)) )
                goto merge;

            for ( i = (1 << cur_order), pg = cur_head + (1 << cur_order );
                  i < (1 << next_order);
                  i++, pg++ )
                if ( page_state_is(pg, offlined) )
                    break;
            if ( i == ( 1 << next_order) )
            {
                cur_order = next_order;
                continue;
            }
            else
            {
            merge:
                /* We don't consider merging outside the head_order. */
                page_list_add_scrub(cur_head, node, zone, cur_order,
                                    (1U << cur_order) > first_dirty ?
                                    first_dirty : INVALID_DIRTY_IDX);
                cur_head += (1 << cur_order);

                /* Adjust first_dirty if needed. */
                if ( first_dirty != INVALID_DIRTY_IDX )
                {
                    if ( first_dirty >=  1U << cur_order )
                        first_dirty -= 1U << cur_order;
                    else
                        first_dirty = 0;
                }

                break;
            }
        }
    }

    for ( cur_head = head; cur_head < head + ( 1UL << head_order); cur_head++ )
    {
        if ( !page_state_is(cur_head, offlined) )
            continue;

        avail[node][zone]--;
        total_avail_pages--;
        ASSERT(total_avail_pages >= 0);

        page_list_add_tail(cur_head,
                           test_bit(_PGC_broken, &cur_head->count_info) ?
                           &page_broken_list : &page_offlined_list);

        count++;
    }

    return count;
}

static nodemask_t node_scrubbing;

/*
 * If get_node is true this will return closest node that needs to be scrubbed,
 * with appropriate bit in node_scrubbing set.
 * If get_node is not set, this will return *a* node that needs to be scrubbed.
 * node_scrubbing bitmask will no be updated.
 * If no node needs scrubbing then NUMA_NO_NODE is returned.
 */
static unsigned int node_to_scrub(bool get_node)
{
    nodeid_t node = cpu_to_node(smp_processor_id()), local_node;
    nodeid_t closest = NUMA_NO_NODE;
    u8 dist, shortest = 0xff;

    if ( node == NUMA_NO_NODE )
        node = 0;

    if ( node_need_scrub[node] &&
         (!get_node || !node_test_and_set(node, node_scrubbing)) )
        return node;

    /*
     * See if there are memory-only nodes that need scrubbing and choose
     * the closest one.
     */
    local_node = node;
    for ( ; ; )
    {
        do {
            node = cycle_node(node, node_online_map);
        } while ( !cpumask_empty(&node_to_cpumask(node)) &&
                  (node != local_node) );

        if ( node == local_node )
            break;

        if ( node_need_scrub[node] )
        {
            if ( !get_node )
                return node;

            dist = __node_distance(local_node, node);

            /*
             * Grab the node right away. If we find a closer node later we will
             * release this one. While there is a chance that another CPU will
             * not be able to scrub that node when it is searching for scrub work
             * at the same time it will be able to do so next time it wakes up.
             * The alternative would be to perform this search under a lock but
             * then we'd need to take this lock every time we come in here.
             */
            if ( (dist < shortest || closest == NUMA_NO_NODE) &&
                 !node_test_and_set(node, node_scrubbing) )
            {
                if ( closest != NUMA_NO_NODE )
                    node_clear(closest, node_scrubbing);
                shortest = dist;
                closest = node;
            }
        }
    }

    return closest;
}

struct scrub_wait_state {
    struct page_info *pg;
    unsigned int first_dirty;
    bool drop;
};

static void scrub_continue(void *data)
{
    struct scrub_wait_state *st = data;

    if ( st->drop )
        return;

    if ( st->pg->u.free.scrub_state == BUDDY_SCRUB_ABORT )
    {
        /* There is a waiter for this buddy. Release it. */
        st->drop = true;
        st->pg->u.free.first_dirty = st->first_dirty;
        smp_wmb();
        st->pg->u.free.scrub_state = BUDDY_NOT_SCRUBBING;
    }
}

bool scrub_free_pages(void)
{
    struct page_info *pg;
    unsigned int zone;
    unsigned int cpu = smp_processor_id();
    bool preempt = false;
    nodeid_t node;
    unsigned int cnt = 0;
  
    node = node_to_scrub(true);
    if ( node == NUMA_NO_NODE )
        return false;
 
    spin_lock(&heap_lock);

    for ( zone = 0; zone < NR_ZONES; zone++ )
    {
        unsigned int order = MAX_ORDER;

        do {
            while ( !page_list_empty(&heap(node, zone, order)) )
            {
                unsigned int i, dirty_cnt;
                struct scrub_wait_state st;

                /* Unscrubbed pages are always at the end of the list. */
                pg = page_list_last(&heap(node, zone, order));
                if ( pg->u.free.first_dirty == INVALID_DIRTY_IDX )
                    break;

                ASSERT(pg->u.free.scrub_state == BUDDY_NOT_SCRUBBING);
                pg->u.free.scrub_state = BUDDY_SCRUBBING;

                spin_unlock(&heap_lock);

                dirty_cnt = 0;

                for ( i = pg->u.free.first_dirty; i < (1U << order); i++)
                {
                    if ( test_bit(_PGC_need_scrub, &pg[i].count_info) )
                    {
                        scrub_one_page(&pg[i]);
                        /*
                         * We can modify count_info without holding heap
                         * lock since we effectively locked this buddy by
                         * setting its scrub_state.
                         */
                        pg[i].count_info &= ~PGC_need_scrub;
                        dirty_cnt++;
                        cnt += 100; /* scrubbed pages add heavier weight. */
                    }
                    else
                        cnt++;

                    if ( pg->u.free.scrub_state == BUDDY_SCRUB_ABORT )
                    {
                        /* Someone wants this chunk. Drop everything. */

                        pg->u.free.first_dirty = (i == (1U << order) - 1) ?
                            INVALID_DIRTY_IDX : i + 1; 
                        smp_wmb();
                        pg->u.free.scrub_state = BUDDY_NOT_SCRUBBING;

                        spin_lock(&heap_lock);
                        node_need_scrub[node] -= dirty_cnt;
                        spin_unlock(&heap_lock);
                        goto out_nolock;
                    }

                    /*
                     * Scrub a few (8) pages before becoming eligible for
                     * preemption. But also count non-scrubbing loop iterations
                     * so that we don't get stuck here with an almost clean
                     * heap.
                     */
                    if ( cnt > 800 && softirq_pending(cpu) )
                    {
                        preempt = true;
                        break;
                    }
                }

                st.pg = pg;
                /*
                 * get_free_buddy() grabs a buddy with first_dirty set to
                 * INVALID_DIRTY_IDX so we can't set pg's first_dirty here.
                 * It will be set either below or in the lock callback (in
                 * scrub_continue()).
                 */
                st.first_dirty = (i >= (1U << order) - 1) ?
                    INVALID_DIRTY_IDX : i + 1;
                st.drop = false;
                spin_lock_cb(&heap_lock, scrub_continue, &st);

                node_need_scrub[node] -= dirty_cnt;

                if ( st.drop )
                    goto out;

                if ( i >= (1U << order) - 1 )
                {
                    page_list_del(pg, &heap(node, zone, order));
                    page_list_add_scrub(pg, node, zone, order, INVALID_DIRTY_IDX);
                }
                else
                    pg->u.free.first_dirty = i + 1;

                pg->u.free.scrub_state = BUDDY_NOT_SCRUBBING;

                if ( preempt || (node_need_scrub[node] == 0) )
                    goto out;
            }
        } while ( order-- != 0 );
    }

 out:
    spin_unlock(&heap_lock);

 out_nolock:
    node_clear(node, node_scrubbing);
    return node_to_scrub(false) != NUMA_NO_NODE;
}

/* Free 2^@order set of pages. */
static void free_heap_pages(
    struct page_info *pg, unsigned int order, bool need_scrub)
{
    unsigned long mask, mfn = page_to_mfn(pg);
    unsigned int i, node = phys_to_nid(page_to_maddr(pg)), tainted = 0;
    unsigned int zone = page_to_zone(pg);

    ASSERT(order <= MAX_ORDER);
    ASSERT(node >= 0);

    spin_lock(&heap_lock);

    for ( i = 0; i < (1 << order); i++ )
    {
        /*
         * Cannot assume that count_info == 0, as there are some corner cases
         * where it isn't the case and yet it isn't a bug:
         *  1. page_get_owner() is NULL
         *  2. page_get_owner() is a domain that was never accessible by
         *     its domid (e.g., failed to fully construct the domain).
         *  3. page was never addressable by the guest (e.g., it's an
         *     auto-translate-physmap guest and the page was never included
         *     in its pseudophysical address space).
         * In all the above cases there can be no guest mappings of this page.
         */
        ASSERT(!page_state_is(&pg[i], offlined));
        pg[i].count_info =
            ((pg[i].count_info & PGC_broken) |
             (page_state_is(&pg[i], offlining)
              ? PGC_state_offlined : PGC_state_free));
        if ( page_state_is(&pg[i], offlined) )
            tainted = 1;

        /* If a page has no owner it will need no safety TLB flush. */
        pg[i].u.free.need_tlbflush = (page_get_owner(&pg[i]) != NULL);
        if ( pg[i].u.free.need_tlbflush )
            page_set_tlbflush_timestamp(&pg[i]);

        /* This page is not a guest frame any more. */
        page_set_owner(&pg[i], NULL); /* set_gpfn_from_mfn snoops pg owner */
        set_gpfn_from_mfn(mfn + i, INVALID_M2P_ENTRY);

        if ( need_scrub )
        {
            pg[i].count_info |= PGC_need_scrub;
            poison_one_page(&pg[i]);
        }
    }

    avail[node][zone] += 1 << order;
    total_avail_pages += 1 << order;
    if ( need_scrub )
    {
        node_need_scrub[node] += 1 << order;
        pg->u.free.first_dirty = 0;
    }
    else
        pg->u.free.first_dirty = INVALID_DIRTY_IDX;

    if ( tmem_enabled() )
        midsize_alloc_zone_pages = max(
            midsize_alloc_zone_pages, total_avail_pages / MIDSIZE_ALLOC_FRAC);

    /* Merge chunks as far as possible. */
    while ( order < MAX_ORDER )
    {
        mask = 1UL << order;

        if ( (page_to_mfn(pg) & mask) )
        {
            struct page_info *predecessor = pg - mask;

            /* Merge with predecessor block? */
            if ( !mfn_valid(_mfn(page_to_mfn(predecessor))) ||
                 !page_state_is(predecessor, free) ||
                 (PFN_ORDER(predecessor) != order) ||
                 (phys_to_nid(page_to_maddr(predecessor)) != node) )
                break;

            check_and_stop_scrub(predecessor);

            page_list_del(predecessor, &heap(node, zone, order));

            /* Keep predecessor's first_dirty if it is already set. */
            if ( predecessor->u.free.first_dirty == INVALID_DIRTY_IDX &&
                 pg->u.free.first_dirty != INVALID_DIRTY_IDX )
                predecessor->u.free.first_dirty = (1U << order) +
                                                  pg->u.free.first_dirty;

            pg = predecessor;
        }
        else
        {
            struct page_info *successor = pg + mask;

            /* Merge with successor block? */
            if ( !mfn_valid(_mfn(page_to_mfn(successor))) ||
                 !page_state_is(successor, free) ||
                 (PFN_ORDER(successor) != order) ||
                 (phys_to_nid(page_to_maddr(successor)) != node) )
                break;

            check_and_stop_scrub(successor);

            page_list_del(successor, &heap(node, zone, order));
        }

        order++;
    }

    page_list_add_scrub(pg, node, zone, order, pg->u.free.first_dirty);

    if ( tainted )
        reserve_offlined_page(pg);

    spin_unlock(&heap_lock);
}


/*
 * Following rules applied for page offline:
 * Once a page is broken, it can't be assigned anymore
 * A page will be offlined only if it is free
 * return original count_info
 */
static unsigned long mark_page_offline(struct page_info *pg, int broken)
{
    unsigned long nx, x, y = pg->count_info;

    ASSERT(page_is_ram_type(page_to_mfn(pg), RAM_TYPE_CONVENTIONAL));
    ASSERT(spin_is_locked(&heap_lock));

    do {
        nx = x = y;

        if ( ((x & PGC_state) != PGC_state_offlined) &&
             ((x & PGC_state) != PGC_state_offlining) )
        {
            nx &= ~PGC_state;
            nx |= (((x & PGC_state) == PGC_state_free)
                   ? PGC_state_offlined : PGC_state_offlining);
        }

        if ( broken )
            nx |= PGC_broken;

        if ( x == nx )
            break;
    } while ( (y = cmpxchg(&pg->count_info, x, nx)) != x );

    return y;
}

static int reserve_heap_page(struct page_info *pg)
{
    struct page_info *head = NULL;
    unsigned int i, node = phys_to_nid(page_to_maddr(pg));
    unsigned int zone = page_to_zone(pg);

    for ( i = 0; i <= MAX_ORDER; i++ )
    {
        struct page_info *tmp;

        if ( page_list_empty(&heap(node, zone, i)) )
            continue;

        page_list_for_each_safe ( head, tmp, &heap(node, zone, i) )
        {
            if ( (head <= pg) &&
                 (head + (1UL << i) > pg) )
                return reserve_offlined_page(head);
        }
    }

    return -EINVAL;

}

int offline_page(unsigned long mfn, int broken, uint32_t *status)
{
    unsigned long old_info = 0;
    struct domain *owner;
    struct page_info *pg;

    if ( !mfn_valid(_mfn(mfn)) )
    {
        dprintk(XENLOG_WARNING,
                "try to offline page out of range %lx\n", mfn);
        return -EINVAL;
    }

    *status = 0;
    pg = mfn_to_page(mfn);

    if ( is_xen_fixed_mfn(mfn) )
    {
        *status = PG_OFFLINE_XENPAGE | PG_OFFLINE_FAILED |
          (DOMID_XEN << PG_OFFLINE_OWNER_SHIFT);
        return -EPERM;
    }

    /*
     * N.B. xen's txt in x86_64 is marked reserved and handled already.
     * Also kexec range is reserved.
     */
    if ( !page_is_ram_type(mfn, RAM_TYPE_CONVENTIONAL) )
    {
        *status = PG_OFFLINE_FAILED | PG_OFFLINE_NOT_CONV_RAM;
        return -EINVAL;
    }

    /*
     * NB. When broken page belong to guest, usually hypervisor will
     * notify the guest to handle the broken page. However, hypervisor
     * need to prevent malicious guest access the broken page again.
     * Under such case, hypervisor shutdown guest, preventing recursive mce.
     */
    if ( (pg->count_info & PGC_broken) && (owner = page_get_owner(pg)) )
    {
        *status = PG_OFFLINE_AGAIN;
        domain_crash(owner);
        return 0;
    }

    spin_lock(&heap_lock);

    old_info = mark_page_offline(pg, broken);

    if ( page_state_is(pg, offlined) )
    {
        reserve_heap_page(pg);

        spin_unlock(&heap_lock);

        *status = broken ? PG_OFFLINE_OFFLINED | PG_OFFLINE_BROKEN
                         : PG_OFFLINE_OFFLINED;
        return 0;
    }

    spin_unlock(&heap_lock);

    if ( (owner = page_get_owner_and_reference(pg)) )
    {
        if ( p2m_pod_offline_or_broken_hit(pg) )
        {
            put_page(pg);
            p2m_pod_offline_or_broken_replace(pg);
            *status = PG_OFFLINE_OFFLINED;
        }
        else
        {
            *status = PG_OFFLINE_OWNED | PG_OFFLINE_PENDING |
                      (owner->domain_id << PG_OFFLINE_OWNER_SHIFT);
            /* Release the reference since it will not be allocated anymore */
            put_page(pg);
        }
    }
    else if ( old_info & PGC_xen_heap )
    {
        *status = PG_OFFLINE_XENPAGE | PG_OFFLINE_PENDING |
                  (DOMID_XEN << PG_OFFLINE_OWNER_SHIFT);
    }
    else
    {
        /*
         * assign_pages does not hold heap_lock, so small window that the owner
         * may be set later, but please notice owner will only change from
         * NULL to be set, not verse, since page is offlining now.
         * No windows If called from #MC handler, since all CPU are in softirq
         * If called from user space like CE handling, tools can wait some time
         * before call again.
         */
        *status = PG_OFFLINE_ANONYMOUS | PG_OFFLINE_FAILED |
                  (DOMID_INVALID << PG_OFFLINE_OWNER_SHIFT );
    }

    if ( broken )
        *status |= PG_OFFLINE_BROKEN;

    return 0;
}

/*
 * Online the memory.
 *   The caller should make sure end_pfn <= max_page,
 *   if not, expand_pages() should be called prior to online_page().
 */
unsigned int online_page(unsigned long mfn, uint32_t *status)
{
    unsigned long x, nx, y;
    struct page_info *pg;
    int ret;

    if ( !mfn_valid(_mfn(mfn)) )
    {
        dprintk(XENLOG_WARNING, "call expand_pages() first\n");
        return -EINVAL;
    }

    pg = mfn_to_page(mfn);

    spin_lock(&heap_lock);

    y = pg->count_info;
    do {
        ret = *status = 0;

        if ( y & PGC_broken )
        {
            ret = -EINVAL;
            *status = PG_ONLINE_FAILED |PG_ONLINE_BROKEN;
            break;
        }

        if ( (y & PGC_state) == PGC_state_offlined )
        {
            page_list_del(pg, &page_offlined_list);
            *status = PG_ONLINE_ONLINED;
        }
        else if ( (y & PGC_state) == PGC_state_offlining )
        {
            *status = PG_ONLINE_ONLINED;
        }
        else
        {
            break;
        }

        x = y;
        nx = (x & ~PGC_state) | PGC_state_inuse;
    } while ( (y = cmpxchg(&pg->count_info, x, nx)) != x );

    spin_unlock(&heap_lock);

    if ( (y & PGC_state) == PGC_state_offlined )
        free_heap_pages(pg, 0, false);

    return ret;
}

int query_page_offline(unsigned long mfn, uint32_t *status)
{
    struct page_info *pg;

    if ( !mfn_valid(_mfn(mfn)) || !page_is_ram_type(mfn, RAM_TYPE_CONVENTIONAL) )
    {
        dprintk(XENLOG_WARNING, "call expand_pages() first\n");
        return -EINVAL;
    }

    *status = 0;
    spin_lock(&heap_lock);

    pg = mfn_to_page(mfn);

    if ( page_state_is(pg, offlining) )
        *status |= PG_OFFLINE_STATUS_OFFLINE_PENDING;
    if ( pg->count_info & PGC_broken )
        *status |= PG_OFFLINE_STATUS_BROKEN;
    if ( page_state_is(pg, offlined) )
        *status |= PG_OFFLINE_STATUS_OFFLINED;

    spin_unlock(&heap_lock);

    return 0;
}

/*
 * Hand the specified arbitrary page range to the specified heap zone
 * checking the node_id of the previous page.  If they differ and the
 * latter is not on a MAX_ORDER boundary, then we reserve the page by
 * not freeing it to the buddy allocator.
 */
static void init_heap_pages(
    struct page_info *pg, unsigned long nr_pages)
{
    unsigned long i;

    /*
     * Some pages may not go through the boot allocator (e.g reserved
     * memory at boot but released just after --- kernel, initramfs,
     * etc.).
     * Update first_valid_mfn to ensure those regions are covered.
     */
    spin_lock(&heap_lock);
    first_valid_mfn = min_t(unsigned long, page_to_mfn(pg), first_valid_mfn);
    spin_unlock(&heap_lock);

    for ( i = 0; i < nr_pages; i++ )
    {
        unsigned int nid = phys_to_nid(page_to_maddr(pg+i));

        if ( unlikely(!avail[nid]) )
        {
            unsigned long s = page_to_mfn(pg + i);
            unsigned long e = page_to_mfn(pg + nr_pages - 1) + 1;
            bool_t use_tail = (nid == phys_to_nid(pfn_to_paddr(e - 1))) &&
                              !(s & ((1UL << MAX_ORDER) - 1)) &&
                              (find_first_set_bit(e) <= find_first_set_bit(s));
            unsigned long n;

            n = init_node_heap(nid, page_to_mfn(pg+i), nr_pages - i,
                               &use_tail);
            BUG_ON(i + n > nr_pages);
            if ( n && !use_tail )
            {
                i += n - 1;
                continue;
            }
            if ( i + n == nr_pages )
                break;
            nr_pages -= n;
        }

        free_heap_pages(pg + i, 0, scrub_debug);
    }
}

static unsigned long avail_heap_pages(
    unsigned int zone_lo, unsigned int zone_hi, unsigned int node)
{
    unsigned int i, zone;
    unsigned long free_pages = 0;

    if ( zone_hi >= NR_ZONES )
        zone_hi = NR_ZONES - 1;

    for_each_online_node(i)
    {
        if ( !avail[i] )
            continue;
        for ( zone = zone_lo; zone <= zone_hi; zone++ )
            if ( (node == -1) || (node == i) )
                free_pages += avail[i][zone];
    }

    return free_pages;
}

unsigned long total_free_pages(void)
{
    return total_avail_pages - midsize_alloc_zone_pages;
}

void __init end_boot_allocator(void)
{
    unsigned int i;

    /* Pages that are free now go to the domain sub-allocator. */
    for ( i = 0; i < nr_bootmem_regions; i++ )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( (r->s < r->e) &&
             (phys_to_nid(pfn_to_paddr(r->s)) == cpu_to_node(0)) )
        {
            init_heap_pages(mfn_to_page(r->s), r->e - r->s);
            r->e = r->s;
            break;
        }
    }
    for ( i = nr_bootmem_regions; i-- > 0; )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( r->s < r->e )
            init_heap_pages(mfn_to_page(r->s), r->e - r->s);
    }
    nr_bootmem_regions = 0;
    init_heap_pages(virt_to_page(bootmem_region_list), 1);

    if ( !dma_bitsize && (num_online_nodes() > 1) )
        dma_bitsize = arch_get_dma_bitsize();

    printk("Domain heap initialised");
    if ( dma_bitsize )
        printk(" DMA width %u bits", dma_bitsize);
    printk("\n");
}

static void __init smp_scrub_heap_pages(void *data)
{
    unsigned long mfn, start, end;
    struct page_info *pg;
    struct scrub_region *r;
    unsigned int temp_cpu, cpu_idx = 0;
    nodeid_t node;
    unsigned int cpu = smp_processor_id();

    if ( data )
        r = data;
    else
    {
        node = cpu_to_node(cpu);
        if ( node == NUMA_NO_NODE )
            return;
        r = &region[node];
    }

    /* Determine the current CPU's index into CPU's linked to this node. */
    for_each_cpu ( temp_cpu, &r->cpus )
    {
        if ( cpu == temp_cpu )
            break;
        cpu_idx++;
    }

    /* Calculate the starting mfn for this CPU's memory block. */
    start = r->start + (r->per_cpu_sz * cpu_idx) + r->offset;

    /* Calculate the end mfn into this CPU's memory block for this iteration. */
    if ( r->offset + chunk_size >= r->per_cpu_sz )
    {
        end = r->start + (r->per_cpu_sz * cpu_idx) + r->per_cpu_sz;

        if ( r->rem && (cpumask_weight(&r->cpus) - 1 == cpu_idx) )
            end += r->rem;
    }
    else
        end = start + chunk_size;

    for ( mfn = start; mfn < end; mfn++ )
    {
        pg = mfn_to_page(mfn);

        /* Check the mfn is valid and page is free. */
        if ( !mfn_valid(_mfn(mfn)) || !page_state_is(pg, free) )
            continue;

        scrub_one_page(pg);
    }
}

static int __init find_non_smt(unsigned int node, cpumask_t *dest)
{
    cpumask_t node_cpus;
    unsigned int i, cpu;

    cpumask_and(&node_cpus, &node_to_cpumask(node), &cpu_online_map);
    cpumask_clear(dest);
    for_each_cpu ( i, &node_cpus )
    {
        if ( cpumask_intersects(dest, per_cpu(cpu_sibling_mask, i)) )
            continue;
        cpu = cpumask_first(per_cpu(cpu_sibling_mask, i));
        __cpumask_set_cpu(cpu, dest);
    }
    return cpumask_weight(dest);
}

/*
 * Scrub all unallocated pages in all heap zones. This function uses all
 * online cpu's to scrub the memory in parallel.
 */
static void __init scrub_heap_pages(void)
{
    cpumask_t node_cpus, all_worker_cpus;
    unsigned int i, j;
    unsigned long offset, max_per_cpu_sz = 0;
    unsigned long start, end;
    unsigned long rem = 0;
    int last_distance, best_node;
    int cpus;

    cpumask_clear(&all_worker_cpus);
    /* Scrub block size. */
    chunk_size = opt_bootscrub_chunk >> PAGE_SHIFT;
    if ( chunk_size == 0 )
        chunk_size = MB(128) >> PAGE_SHIFT;

    /* Round #0 - figure out amounts and which CPUs to use. */
    for_each_online_node ( i )
    {
        if ( !node_spanned_pages(i) )
            continue;
        /* Calculate Node memory start and end address. */
        start = max(node_start_pfn(i), first_valid_mfn);
        end = min(node_start_pfn(i) + node_spanned_pages(i), max_page);
        /* Just in case NODE has 1 page and starts below first_valid_mfn. */
        end = max(end, start);
        /* CPUs that are online and on this node (if none, that it is OK). */
        cpus = find_non_smt(i, &node_cpus);
        cpumask_or(&all_worker_cpus, &all_worker_cpus, &node_cpus);
        if ( cpus <= 0 )
        {
            /* No CPUs on this node. Round #2 will take of it. */
            rem = 0;
            region[i].per_cpu_sz = (end - start);
        }
        else
        {
            rem = (end - start) % cpus;
            region[i].per_cpu_sz = (end - start) / cpus;
            if ( region[i].per_cpu_sz > max_per_cpu_sz )
                max_per_cpu_sz = region[i].per_cpu_sz;
        }
        region[i].start = start;
        region[i].rem = rem;
        cpumask_copy(&region[i].cpus, &node_cpus);
    }

    printk("Scrubbing Free RAM on %d nodes using %d CPUs\n", num_online_nodes(),
           cpumask_weight(&all_worker_cpus));

    /* Round: #1 - do NUMA nodes with CPUs. */
    for ( offset = 0; offset < max_per_cpu_sz; offset += chunk_size )
    {
        for_each_online_node ( i )
            region[i].offset = offset;

        process_pending_softirqs();

        spin_lock(&heap_lock);
        on_selected_cpus(&all_worker_cpus, smp_scrub_heap_pages, NULL, 1);
        spin_unlock(&heap_lock);

        printk(".");
    }

    /*
     * Round #2: NUMA nodes with no CPUs get scrubbed with CPUs on the node
     * closest to us and with CPUs.
     */
    for_each_online_node ( i )
    {
        node_cpus = node_to_cpumask(i);

        if ( !cpumask_empty(&node_cpus) )
            continue;

        last_distance = INT_MAX;
        best_node = first_node(node_online_map);
        /* Figure out which NODE CPUs are close. */
        for_each_online_node ( j )
        {
            u8 distance;

            if ( cpumask_empty(&node_to_cpumask(j)) )
                continue;

            distance = __node_distance(i, j);
            if ( (distance < last_distance) && (distance != NUMA_NO_DISTANCE) )
            {
                last_distance = distance;
                best_node = j;
            }
        }
        /*
         * Use CPUs from best node, and if there are no CPUs on the
         * first node (the default) use the BSP.
         */
        cpus = find_non_smt(best_node, &node_cpus);
        if ( cpus == 0 )
        {
            __cpumask_set_cpu(smp_processor_id(), &node_cpus);
            cpus = 1;
        }
        /* We already have the node information from round #0. */
        region[i].rem = region[i].per_cpu_sz % cpus;
        region[i].per_cpu_sz /= cpus;
        max_per_cpu_sz = region[i].per_cpu_sz;
        cpumask_copy(&region[i].cpus, &node_cpus);

        for ( offset = 0; offset < max_per_cpu_sz; offset += chunk_size )
        {
            region[i].offset = offset;

            process_pending_softirqs();

            spin_lock(&heap_lock);
            on_selected_cpus(&node_cpus, smp_scrub_heap_pages, &region[i], 1);
            spin_unlock(&heap_lock);

            printk(".");
        }
    }

    printk("done.\n");

#ifdef CONFIG_SCRUB_DEBUG
    scrub_debug = true;
#endif
}

void __init heap_init_late(void)
{
    /*
     * Now that the heap is initialized set bounds
     * for the low mem virq algorithm.
     */
    setup_low_mem_virq();

    if ( opt_bootscrub )
        scrub_heap_pages();
}


/*************************
 * XEN-HEAP SUB-ALLOCATOR
 */

#if defined(CONFIG_SEPARATE_XENHEAP)

void init_xenheap_pages(paddr_t ps, paddr_t pe)
{
    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    /*
     * Yuk! Ensure there is a one-page buffer between Xen and Dom zones, to
     * prevent merging of power-of-two blocks across the zone boundary.
     */
    if ( ps && !is_xen_heap_mfn(paddr_to_pfn(ps)-1) )
        ps += PAGE_SIZE;
    if ( !is_xen_heap_mfn(paddr_to_pfn(pe)) )
        pe -= PAGE_SIZE;

    memguard_guard_range(maddr_to_virt(ps), pe - ps);

    init_heap_pages(maddr_to_page(ps), (pe - ps) >> PAGE_SHIFT);
}


void *alloc_xenheap_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pg;

    ASSERT(!in_irq());

    pg = alloc_heap_pages(MEMZONE_XEN, MEMZONE_XEN,
                          order, memflags | MEMF_no_scrub, NULL);
    if ( unlikely(pg == NULL) )
        return NULL;

    memguard_unguard_range(page_to_virt(pg), 1 << (order + PAGE_SHIFT));

    return page_to_virt(pg);
}


void free_xenheap_pages(void *v, unsigned int order)
{
    ASSERT(!in_irq());

    if ( v == NULL )
        return;

    memguard_guard_range(v, 1 << (order + PAGE_SHIFT));

    free_heap_pages(virt_to_page(v), order, false);
}

#else

void __init xenheap_max_mfn(unsigned long mfn)
{
    ASSERT(!first_node_initialised);
    ASSERT(!xenheap_bits);
    BUILD_BUG_ON(PADDR_BITS >= BITS_PER_LONG);
    xenheap_bits = min(flsl(mfn + 1) - 1 + PAGE_SHIFT, PADDR_BITS);
    printk(XENLOG_INFO "Xen heap: %u bits\n", xenheap_bits);
}

void init_xenheap_pages(paddr_t ps, paddr_t pe)
{
    init_domheap_pages(ps, pe);
}

void *alloc_xenheap_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pg;
    unsigned int i;

    ASSERT(!in_irq());

    if ( xenheap_bits && (memflags >> _MEMF_bits) > xenheap_bits )
        memflags &= ~MEMF_bits(~0U);
    if ( !(memflags >> _MEMF_bits) )
        memflags |= MEMF_bits(xenheap_bits);

    pg = alloc_domheap_pages(NULL, order, memflags | MEMF_no_scrub);
    if ( unlikely(pg == NULL) )
        return NULL;

    for ( i = 0; i < (1u << order); i++ )
        pg[i].count_info |= PGC_xen_heap;

    return page_to_virt(pg);
}

void free_xenheap_pages(void *v, unsigned int order)
{
    struct page_info *pg;
    unsigned int i;

    ASSERT(!in_irq());

    if ( v == NULL )
        return;

    pg = virt_to_page(v);

    for ( i = 0; i < (1u << order); i++ )
        pg[i].count_info &= ~PGC_xen_heap;

    free_heap_pages(pg, order, true);
}

#endif



/*************************
 * DOMAIN-HEAP SUB-ALLOCATOR
 */

void init_domheap_pages(paddr_t ps, paddr_t pe)
{
    unsigned long smfn, emfn;

    ASSERT(!in_irq());

    smfn = round_pgup(ps) >> PAGE_SHIFT;
    emfn = round_pgdown(pe) >> PAGE_SHIFT;

    if ( emfn <= smfn )
        return;

    init_heap_pages(mfn_to_page(smfn), emfn - smfn);
}


int assign_pages(
    struct domain *d,
    struct page_info *pg,
    unsigned int order,
    unsigned int memflags)
{
    int rc = 0;
    unsigned long i;

    spin_lock(&d->page_alloc_lock);

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Cannot assign page to domain%d -- dying.\n",
                d->domain_id);
        rc = -EINVAL;
        goto out;
    }

    if ( !(memflags & MEMF_no_refcount) )
    {
        if ( unlikely((d->tot_pages + (1 << order)) > d->max_pages) )
        {
            if ( !tmem_enabled() || order != 0 || d->tot_pages != d->max_pages )
                gprintk(XENLOG_INFO, "Over-allocation for domain %u: "
                        "%u > %u\n", d->domain_id,
                        d->tot_pages + (1 << order), d->max_pages);
            rc = -E2BIG;
            goto out;
        }

        if ( unlikely(d->tot_pages == 0) )
            get_knownalive_domain(d);

        domain_adjust_tot_pages(d, 1 << order);
    }

    for ( i = 0; i < (1 << order); i++ )
    {
        ASSERT(page_get_owner(&pg[i]) == NULL);
        ASSERT((pg[i].count_info & ~(PGC_allocated | 1)) == 0);
        page_set_owner(&pg[i], d);
        smp_wmb(); /* Domain pointer must be visible before updating refcnt. */
        pg[i].count_info = PGC_allocated | 1;
        page_list_add_tail(&pg[i], &d->page_list);
    }

 out:
    spin_unlock(&d->page_alloc_lock);
    return rc;
}


struct page_info *alloc_domheap_pages(
    struct domain *d, unsigned int order, unsigned int memflags)
{
    struct page_info *pg = NULL;
    unsigned int bits = memflags >> _MEMF_bits, zone_hi = NR_ZONES - 1;
    unsigned int dma_zone;

    ASSERT(!in_irq());

    bits = domain_clamp_alloc_bitsize(memflags & MEMF_no_owner ? NULL : d,
                                      bits ? : (BITS_PER_LONG+PAGE_SHIFT));
    if ( (zone_hi = min_t(unsigned int, bits_to_zone(bits), zone_hi)) == 0 )
        return NULL;

    if ( memflags & MEMF_no_owner )
        memflags |= MEMF_no_refcount;

    if ( dma_bitsize && ((dma_zone = bits_to_zone(dma_bitsize)) < zone_hi) )
        pg = alloc_heap_pages(dma_zone + 1, zone_hi, order, memflags, d);

    if ( (pg == NULL) &&
         ((memflags & MEMF_no_dma) ||
          ((pg = alloc_heap_pages(MEMZONE_XEN + 1, zone_hi, order,
                                  memflags, d)) == NULL)) )
         return NULL;

    if ( d && !(memflags & MEMF_no_owner) &&
         assign_pages(d, pg, order, memflags) )
    {
        free_heap_pages(pg, order, memflags & MEMF_no_scrub);
        return NULL;
    }
    
    return pg;
}

void free_domheap_pages(struct page_info *pg, unsigned int order)
{
    struct domain *d = page_get_owner(pg);
    unsigned int i;
    bool_t drop_dom_ref;

    ASSERT(!in_irq());

    if ( unlikely(is_xen_heap_page(pg)) )
    {
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
            arch_free_heap_page(d, &pg[i]);

        d->xenheap_pages -= 1 << order;
        drop_dom_ref = (d->xenheap_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    }
    else
    {
        bool_t scrub;

        if ( likely(d) && likely(d != dom_cow) )
        {
            /* NB. May recursively lock from relinquish_memory(). */
            spin_lock_recursive(&d->page_alloc_lock);

            for ( i = 0; i < (1 << order); i++ )
            {
                BUG_ON((pg[i].u.inuse.type_info & PGT_count_mask) != 0);
                arch_free_heap_page(d, &pg[i]);
            }

            drop_dom_ref = !domain_adjust_tot_pages(d, -(1 << order));

            spin_unlock_recursive(&d->page_alloc_lock);

            /*
             * Normally we expect a domain to clear pages before freeing them,
             * if it cares about the secrecy of their contents. However, after
             * a domain has died we assume responsibility for erasure.
             */
            scrub = d->is_dying || scrub_debug;
        }
        else
        {
            /*
             * All we need to check is that on dom_cow only order-0 chunks
             * make it here. Due to the if() above, the only two possible
             * cases right now are d == NULL and d == dom_cow. To protect
             * against relaxation of that if() condition without updating the
             * check here, don't check d != dom_cow for now.
             */
            ASSERT(!d || !order);
            drop_dom_ref = 0;
            scrub = 1;
        }

        free_heap_pages(pg, order, scrub);
    }

    if ( drop_dom_ref )
        put_domain(d);
}

unsigned long avail_domheap_pages_region(
    unsigned int node, unsigned int min_width, unsigned int max_width)
{
    int zone_lo, zone_hi;

    zone_lo = min_width ? bits_to_zone(min_width) : (MEMZONE_XEN + 1);
    zone_lo = max_t(int, MEMZONE_XEN + 1, min_t(int, NR_ZONES - 1, zone_lo));

    zone_hi = max_width ? bits_to_zone(max_width) : (NR_ZONES - 1);
    zone_hi = max_t(int, MEMZONE_XEN + 1, min_t(int, NR_ZONES - 1, zone_hi));

    return avail_heap_pages(zone_lo, zone_hi, node);
}

unsigned long avail_domheap_pages(void)
{
    return avail_heap_pages(MEMZONE_XEN + 1,
                            NR_ZONES - 1,
                            -1);
}

unsigned long avail_node_heap_pages(unsigned int nodeid)
{
    return avail_heap_pages(MEMZONE_XEN, NR_ZONES -1, nodeid);
}


static void pagealloc_info(unsigned char key)
{
    unsigned int zone = MEMZONE_XEN;
    unsigned long n, total = 0;

    printk("Physical memory information:\n");
    printk("    Xen heap: %lukB free\n",
           avail_heap_pages(zone, zone, -1) << (PAGE_SHIFT-10));

    while ( ++zone < NR_ZONES )
    {
        if ( (zone + PAGE_SHIFT) == dma_bitsize )
        {
            printk("    DMA heap: %lukB free\n", total << (PAGE_SHIFT-10));
            total = 0;
        }

        if ( (n = avail_heap_pages(zone, zone, -1)) != 0 )
        {
            total += n;
            printk("    heap[%02u]: %lukB free\n", zone, n << (PAGE_SHIFT-10));
        }
    }

    printk("    Dom heap: %lukB free\n", total << (PAGE_SHIFT-10));
}

static __init int pagealloc_keyhandler_init(void)
{
    register_keyhandler('m', pagealloc_info, "memory info", 1);
    return 0;
}
__initcall(pagealloc_keyhandler_init);


void scrub_one_page(struct page_info *pg)
{
    if ( unlikely(pg->count_info & PGC_broken) )
        return;

#ifndef NDEBUG
    /* Avoid callers relying on allocations returning zeroed pages. */
    unmap_domain_page(memset(__map_domain_page(pg),
                             SCRUB_BYTE_PATTERN, PAGE_SIZE));
#else
    /* For a production build, clear_page() is the fastest way to scrub. */
    clear_domain_page(_mfn(page_to_mfn(pg)));
#endif
}

static void dump_heap(unsigned char key)
{
    s_time_t      now = NOW();
    int           i, j;

    printk("'%c' pressed -> dumping heap info (now-0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now);

    for ( i = 0; i < MAX_NUMNODES; i++ )
    {
        if ( !avail[i] )
            continue;
        for ( j = 0; j < NR_ZONES; j++ )
            printk("heap[node=%d][zone=%d] -> %lu pages\n",
                   i, j, avail[i][j]);
    }

    for ( i = 0; i < MAX_NUMNODES; i++ )
    {
        if ( !node_need_scrub[i] )
            continue;
        printk("Node %d has %lu unscrubbed pages\n", i, node_need_scrub[i]);
    }
}

static __init int register_heap_trigger(void)
{
    register_keyhandler('H', dump_heap, "dump heap info", 1);
    return 0;
}
__initcall(register_heap_trigger);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
