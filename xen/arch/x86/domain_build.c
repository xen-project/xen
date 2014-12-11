/******************************************************************************
 * domain_build.c
 * 
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/kernel.h>
#include <xen/domain.h>
#include <xen/version.h>
#include <xen/iocap.h>
#include <xen/bitops.h>
#include <xen/compat.h>
#include <xen/libelf.h>
#include <xen/pfn.h>
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/e820.h>
#include <asm/acpi.h>
#include <asm/setup.h>
#include <asm/bzimage.h> /* for bzimage_parse */
#include <asm/io_apic.h>
#include <asm/hap.h>

#include <public/version.h>

static long __initdata dom0_nrpages;
static long __initdata dom0_min_nrpages;
static long __initdata dom0_max_nrpages = LONG_MAX;

/*
 * dom0_mem=[min:<min_amt>,][max:<max_amt>,][<amt>]
 * 
 * <min_amt>: The minimum amount of memory which should be allocated for dom0.
 * <max_amt>: The maximum amount of memory which should be allocated for dom0.
 * <amt>:     The precise amount of memory to allocate for dom0.
 * 
 * Notes:
 *  1. <amt> is clamped from below by <min_amt> and from above by available
 *     memory and <max_amt>
 *  2. <min_amt> is clamped from above by available memory and <max_amt>
 *  3. <min_amt> is ignored if it is greater than <max_amt>
 *  4. If <amt> is not specified, it is calculated as follows:
 *     "All of memory is allocated to domain 0, minus 1/16th which is reserved
 *      for uses such as DMA buffers (the reservation is clamped to 128MB)."
 * 
 * Each value can be specified as positive or negative:
 *  If +ve: The specified amount is an absolute value.
 *  If -ve: The specified amount is subtracted from total available memory.
 */
static long __init parse_amt(const char *s, const char **ps)
{
    long pages = parse_size_and_unit((*s == '-') ? s+1 : s, ps) >> PAGE_SHIFT;
    return (*s == '-') ? -pages : pages;
}
static void __init parse_dom0_mem(const char *s)
{
    do {
        if ( !strncmp(s, "min:", 4) )
            dom0_min_nrpages = parse_amt(s+4, &s);
        else if ( !strncmp(s, "max:", 4) )
            dom0_max_nrpages = parse_amt(s+4, &s);
        else
            dom0_nrpages = parse_amt(s, &s);
        if ( *s != ',' )
            break;
    } while ( *s++ == ',' );
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int __initdata opt_dom0_max_vcpus_min = 1;
static unsigned int __initdata opt_dom0_max_vcpus_max = UINT_MAX;

static void __init parse_dom0_max_vcpus(const char *s)
{
    if (*s == '-')              /* -M */
        opt_dom0_max_vcpus_max = simple_strtoul(s + 1, &s, 0);
    else                        /* N, N-, or N-M */
    {
        opt_dom0_max_vcpus_min = simple_strtoul(s, &s, 0);
        if (*s++ == '\0')       /* N */
            opt_dom0_max_vcpus_max = opt_dom0_max_vcpus_min;
        else if (*s != '\0')    /* N-M */
            opt_dom0_max_vcpus_max = simple_strtoul(s, &s, 0);
    }
}
custom_param("dom0_max_vcpus", parse_dom0_max_vcpus);

unsigned int __init dom0_max_vcpus(void)
{
    unsigned max_vcpus;

    max_vcpus = num_cpupool_cpus(cpupool0);
    if ( opt_dom0_max_vcpus_min > max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_min;
    if ( opt_dom0_max_vcpus_max < max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_max;
    if ( max_vcpus > MAX_VIRT_CPUS )
        max_vcpus = MAX_VIRT_CPUS;

    return max_vcpus;
}

struct vcpu *__init alloc_dom0_vcpu0(struct domain *dom0)
{
    unsigned int max_vcpus = dom0_max_vcpus();

    dom0->vcpu = xzalloc_array(struct vcpu *, max_vcpus);
    if ( !dom0->vcpu )
        return NULL;
    dom0->max_vcpus = max_vcpus;

    return alloc_vcpu(dom0, 0, 0);
}

static bool_t __initdata opt_dom0_shadow;
boolean_param("dom0_shadow", opt_dom0_shadow);

static char __initdata opt_dom0_ioports_disable[200] = "";
string_param("dom0_ioports_disable", opt_dom0_ioports_disable);

/* Allow ring-3 access in long mode as guest cannot use ring 1 ... */
#define BASE_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L1_PROT (BASE_PROT|_PAGE_GUEST_KERNEL)
/* ... except for compatibility mode guests. */
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (BASE_PROT|_PAGE_DIRTY)
#define L3_PROT (BASE_PROT|_PAGE_DIRTY)
#define L4_PROT (BASE_PROT|_PAGE_DIRTY)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static struct page_info * __init alloc_chunk(
    struct domain *d, unsigned long max_pages)
{
    static unsigned int __initdata last_order = MAX_ORDER;
    static unsigned int __initdata memflags = MEMF_no_dma;
    struct page_info *page;
    unsigned int order = get_order_from_pages(max_pages), free_order;

    if ( order > last_order )
        order = last_order;
    else if ( max_pages & (max_pages - 1) )
        --order;
    while ( (page = alloc_domheap_pages(d, order, memflags)) == NULL )
        if ( order-- == 0 )
            break;
    if ( page )
        last_order = order;
    else if ( memflags )
    {
        /*
         * Allocate up to 2MB at a time: It prevents allocating very large
         * chunks from DMA pools before the >4GB pool is fully depleted.
         */
        last_order = 21 - PAGE_SHIFT;
        memflags = 0;
        return alloc_chunk(d, max_pages);
    }

    /*
     * Make a reasonable attempt at finding a smaller chunk at a higher
     * address, to avoid allocating from low memory as much as possible.
     */
    for ( free_order = order; !memflags && page && order--; )
    {
        struct page_info *pg2;

        if ( d->tot_pages + (1 << order) > d->max_pages )
            continue;
        pg2 = alloc_domheap_pages(d, order, 0);
        if ( pg2 > page )
        {
            free_domheap_pages(page, free_order);
            page = pg2;
            free_order = order;
        }
        else if ( pg2 )
            free_domheap_pages(pg2, order);
    }
    return page;
}

static unsigned long __init compute_dom0_nr_pages(
    struct domain *d, struct elf_dom_parms *parms, unsigned long initrd_len)
{
    unsigned long avail = avail_domheap_pages() + initial_images_nrpages();
    unsigned long nr_pages = dom0_nrpages;
    unsigned long min_pages = dom0_min_nrpages;
    unsigned long max_pages = dom0_max_nrpages;

    /* Reserve memory for further dom0 vcpu-struct allocations... */
    avail -= (d->max_vcpus - 1UL)
             << get_order_from_bytes(sizeof(struct vcpu));
    /* ...and compat_l4's, if needed. */
    if ( is_pv_32on64_domain(d) )
        avail -= d->max_vcpus - 1;

    /* Reserve memory for iommu_dom0_init() (rough estimate). */
    if ( iommu_enabled )
    {
        unsigned int s;

        for ( s = 9; s < BITS_PER_LONG; s += 9 )
            avail -= max_pdx >> s;
    }

    /*
     * If domain 0 allocation isn't specified, reserve 1/16th of available
     * memory for things like DMA buffers. This reservation is clamped to 
     * a maximum of 128MB.
     */
    if ( nr_pages == 0 )
        nr_pages = -min(avail / 16, 128UL << (20 - PAGE_SHIFT));

    /* Negative memory specification means "all memory - specified amount". */
    if ( (long)nr_pages  < 0 ) nr_pages  += avail;
    if ( (long)min_pages < 0 ) min_pages += avail;
    if ( (long)max_pages < 0 ) max_pages += avail;

    /* Clamp dom0 memory according to min/max limits and available memory. */
    nr_pages = max(nr_pages, min_pages);
    nr_pages = min(nr_pages, max_pages);
    nr_pages = min(nr_pages, avail);

    if ( (parms->p2m_base == UNSET_ADDR) && (dom0_nrpages <= 0) &&
         ((dom0_min_nrpages <= 0) || (nr_pages > min_pages)) )
    {
        /*
         * Legacy Linux kernels (i.e. such without a XEN_ELFNOTE_INIT_P2M
         * note) require that there is enough virtual space beyond the initial
         * allocation to set up their initial page tables. This space is
         * roughly the same size as the p2m table, so make sure the initial
         * allocation doesn't consume more than about half the space that's
         * available between params.virt_base and the address space end.
         */
        unsigned long vstart, vend, end;
        size_t sizeof_long = is_pv_32bit_domain(d) ? sizeof(int) : sizeof(long);

        vstart = parms->virt_base;
        vend = round_pgup(parms->virt_kend);
        if ( !parms->elf_notes[XEN_ELFNOTE_MOD_START_PFN].data.num )
            vend += round_pgup(initrd_len);
        end = vend + nr_pages * sizeof_long;

        if ( end > vstart )
            end += end - vstart;
        if ( end <= vstart ||
             (sizeof_long < sizeof(end) && end > (1UL << (8 * sizeof_long))) )
        {
            end = sizeof_long >= sizeof(end) ? 0 : 1UL << (8 * sizeof_long);
            nr_pages = (end - vend) / (2 * sizeof_long);
            if ( dom0_min_nrpages > 0 && nr_pages < min_pages )
                nr_pages = min_pages;
            printk("Dom0 memory clipped to %lu pages\n", nr_pages);
        }
    }

    d->max_pages = min_t(unsigned long, max_pages, UINT_MAX);

    return nr_pages;
}

static void __init process_dom0_ioports_disable(struct domain *dom0)
{
    unsigned long io_from, io_to;
    char *t, *s = opt_dom0_ioports_disable;
    const char *u;

    if ( *s == '\0' )
        return;

    while ( (t = strsep(&s, ",")) != NULL )
    {
        io_from = simple_strtoul(t, &u, 16);
        if ( u == t )
        {
        parse_error:
            printk("Invalid ioport range <%s> "
                   "in dom0_ioports_disable, skipping\n", t);
            continue;
        }

        if ( *u == '\0' )
            io_to = io_from;
        else if ( *u == '-' )
            io_to = simple_strtoul(u + 1, &u, 16);
        else
            goto parse_error;

        if ( (*u != '\0') || (io_to < io_from) || (io_to >= 65536) )
            goto parse_error;

        printk("Disabling dom0 access to ioport range %04lx-%04lx\n",
            io_from, io_to);

        if ( ioports_deny_access(dom0, io_from, io_to) != 0 )
            BUG();
    }
}

static __init void pvh_add_mem_mapping(struct domain *d, unsigned long gfn,
                                       unsigned long mfn, unsigned long nr_mfns)
{
    unsigned long i;
    int rc;

    for ( i = 0; i < nr_mfns; i++ )
    {
        if ( (rc = set_mmio_p2m_entry(d, gfn + i, _mfn(mfn + i))) )
            panic("pvh_add_mem_mapping: gfn:%lx mfn:%lx i:%ld rc:%d\n",
                  gfn, mfn, i, rc);
        if ( !(i & 0xfffff) )
                process_pending_softirqs();
    }
}

/*
 * Set the 1:1 map for all non-RAM regions for dom 0. Thus, dom0 will have
 * the entire io region mapped in the EPT/NPT.
 *
 * pvh fixme: The following doesn't map MMIO ranges when they sit above the
 *            highest E820 covered address.
 */
static __init void pvh_map_all_iomem(struct domain *d, unsigned long nr_pages)
{
    unsigned long start_pfn, end_pfn, end = 0, start = 0;
    const struct e820entry *entry;
    unsigned long nump, nmap, navail, mfn, nr_holes = 0;
    unsigned int i;
    struct page_info *page;
    int rc;

    for ( i = 0, entry = e820.map; i < e820.nr_map; i++, entry++ )
    {
        end = entry->addr + entry->size;

        if ( entry->type == E820_RAM || entry->type == E820_UNUSABLE ||
             i == e820.nr_map - 1 )
        {
            start_pfn = PFN_DOWN(start);

            /* Unused RAM areas are marked UNUSABLE, so skip them too */
            if ( entry->type == E820_RAM || entry->type == E820_UNUSABLE )
                end_pfn = PFN_UP(entry->addr);
            else
                end_pfn = PFN_UP(end);

            if ( start_pfn < end_pfn )
            {
                nump = end_pfn - start_pfn;
                /* Add pages to the mapping */
                pvh_add_mem_mapping(d, start_pfn, start_pfn, nump);
                if ( start_pfn < nr_pages )
                    nr_holes += (end_pfn < nr_pages) ?
                                    nump : (nr_pages - start_pfn);
            }
            start = end;
        }
    }

    /*
     * Some BIOSes may not report io space above ram that is less than 4GB. So
     * we map any non-ram upto 4GB.
     */
    if ( end < GB(4) )
    {
        start_pfn = PFN_UP(end);
        end_pfn = (GB(4)) >> PAGE_SHIFT;
        nump = end_pfn - start_pfn;
        pvh_add_mem_mapping(d, start_pfn, start_pfn, nump);
    }

    /*
     * Add the memory removed by the holes at the end of the
     * memory map.
     */
    page = page_list_first(&d->page_list);
    for ( i = 0, entry = e820.map; i < e820.nr_map && nr_holes > 0;
          i++, entry++ )
    {
        if ( entry->type != E820_RAM )
            continue;

        end_pfn = PFN_UP(entry->addr + entry->size);
        if ( end_pfn <= nr_pages )
            continue;

        navail = end_pfn - nr_pages;
        nmap = min(navail, nr_holes);
        nr_holes -= nmap;
        start_pfn = max_t(unsigned long, nr_pages, PFN_DOWN(entry->addr));
        /*
         * Populate this memory region using the pages
         * previously removed by the MMIO holes.
         */
        do
        {
            mfn = page_to_mfn(page);
            if ( get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY )
                continue;

            rc = guest_physmap_add_page(d, start_pfn, mfn, 0);
            if ( rc != 0 )
                panic("Unable to add gpfn %#lx mfn %#lx to Dom0 physmap: %d",
                      start_pfn, mfn, rc);
            start_pfn++;
            nmap--;
            if ( !(nmap & 0xfffff) )
                process_pending_softirqs();
        } while ( ((page = page_list_next(page, &d->page_list)) != NULL)
                  && nmap );
        ASSERT(nmap == 0);
        if ( page == NULL )
            break;
    }

    ASSERT(nr_holes == 0);
}

static __init void pvh_setup_e820(struct domain *d, unsigned long nr_pages)
{
    struct e820entry *entry, *entry_guest;
    unsigned int i;
    unsigned long pages, cur_pages = 0;

    /*
     * Craft the e820 memory map for Dom0 based on the hardware e820 map.
     */
    d->arch.e820 = xzalloc_array(struct e820entry, e820.nr_map);
    if ( !d->arch.e820 )
        panic("Unable to allocate memory for Dom0 e820 map");
    entry_guest = d->arch.e820;

    /* Clamp e820 memory map to match the memory assigned to Dom0 */
    for ( i = 0, entry = e820.map; i < e820.nr_map; i++, entry++ )
    {
        if ( entry->type != E820_RAM )
        {
            *entry_guest = *entry;
            goto next;
        }

        if ( nr_pages == cur_pages )
        {
            /*
             * We already have all the assigned memory,
             * skip this entry
             */
            continue;
        }

        *entry_guest = *entry;
        pages = PFN_UP(entry_guest->size);
        if ( (cur_pages + pages) > nr_pages )
        {
            /* Truncate region */
            entry_guest->size = (nr_pages - cur_pages) << PAGE_SHIFT;
            cur_pages = nr_pages;
        }
        else
        {
            cur_pages += pages;
        }
 next:
        d->arch.nr_e820++;
        entry_guest++;
    }
    ASSERT(cur_pages == nr_pages);
    ASSERT(d->arch.nr_e820 <= e820.nr_map);
}

static __init void dom0_update_physmap(struct domain *d, unsigned long pfn,
                                   unsigned long mfn, unsigned long vphysmap_s)
{
    if ( is_pvh_domain(d) )
    {
        int rc = guest_physmap_add_page(d, pfn, mfn, 0);
        BUG_ON(rc);
        return;
    }
    if ( !is_pv_32on64_domain(d) )
        ((unsigned long *)vphysmap_s)[pfn] = mfn;
    else
        ((unsigned int *)vphysmap_s)[pfn] = mfn;

    set_gpfn_from_mfn(mfn, pfn);
}

/* Replace mfns with pfns in dom0 page tables */
static __init void pvh_fixup_page_tables_for_hap(struct vcpu *v,
                                                 unsigned long v_start,
                                                 unsigned long v_end)
{
    int i, j, k;
    l4_pgentry_t *pl4e, *l4start;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned long cr3_pfn;

    ASSERT(paging_mode_enabled(v->domain));

    l4start = map_domain_page(pagetable_get_pfn(v->arch.guest_table));

    /* Clear entries prior to guest L4 start */
    pl4e = l4start + l4_table_offset(v_start);
    memset(l4start, 0, (unsigned long)pl4e - (unsigned long)l4start);

    for ( ; pl4e <= l4start + l4_table_offset(v_end - 1); pl4e++ )
    {
        pl3e = map_l3t_from_l4e(*pl4e);
        for ( i = 0; i < PAGE_SIZE / sizeof(*pl3e); i++, pl3e++ )
        {
            if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
                continue;

            pl2e = map_l2t_from_l3e(*pl3e);
            for ( j = 0; j < PAGE_SIZE / sizeof(*pl2e); j++, pl2e++ )
            {
                if ( !(l2e_get_flags(*pl2e)  & _PAGE_PRESENT) )
                    continue;

                pl1e = map_l1t_from_l2e(*pl2e);
                for ( k = 0; k < PAGE_SIZE / sizeof(*pl1e); k++, pl1e++ )
                {
                    if ( !(l1e_get_flags(*pl1e) & _PAGE_PRESENT) )
                        continue;

                    *pl1e = l1e_from_pfn(get_gpfn_from_mfn(l1e_get_pfn(*pl1e)),
                                         l1e_get_flags(*pl1e));
                }
                unmap_domain_page(pl1e);
                *pl2e = l2e_from_pfn(get_gpfn_from_mfn(l2e_get_pfn(*pl2e)),
                                     l2e_get_flags(*pl2e));
            }
            unmap_domain_page(pl2e);
            *pl3e = l3e_from_pfn(get_gpfn_from_mfn(l3e_get_pfn(*pl3e)),
                                 l3e_get_flags(*pl3e));
        }
        unmap_domain_page(pl3e);
        *pl4e = l4e_from_pfn(get_gpfn_from_mfn(l4e_get_pfn(*pl4e)),
                             l4e_get_flags(*pl4e));
    }

    /* Clear entries post guest L4. */
    if ( (unsigned long)pl4e & (PAGE_SIZE - 1) )
        memset(pl4e, 0, PAGE_SIZE - ((unsigned long)pl4e & (PAGE_SIZE - 1)));

    unmap_domain_page(l4start);

    cr3_pfn = get_gpfn_from_mfn(paddr_to_pfn(v->arch.cr3));
    v->arch.hvm_vcpu.guest_cr[3] = pfn_to_paddr(cr3_pfn);

    /*
     * Finally, we update the paging modes (hap_update_paging_modes). This will
     * create monitor_table for us, update v->arch.cr3, and update vmcs.cr3.
     */
    paging_update_paging_modes(v);
}

static __init void mark_pv_pt_pages_rdonly(struct domain *d,
                                           l4_pgentry_t *l4start,
                                           unsigned long vpt_start,
                                           unsigned long nr_pt_pages)
{
    unsigned long count;
    struct page_info *page;
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    pl4e = l4start + l4_table_offset(vpt_start);
    pl3e = l4e_to_l3e(*pl4e);
    pl3e += l3_table_offset(vpt_start);
    pl2e = l3e_to_l2e(*pl3e);
    pl2e += l2_table_offset(vpt_start);
    pl1e = l2e_to_l1e(*pl2e);
    pl1e += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ )
    {
        l1e_remove_flags(*pl1e, _PAGE_RW);
        page = mfn_to_page(l1e_get_pfn(*pl1e));

        /* Read-only mapping + PGC_allocated + page-table page. */
        page->count_info         = PGC_allocated | 3;
        page->u.inuse.type_info |= PGT_validated | 1;

        /* Top-level p.t. is pinned. */
        if ( (page->u.inuse.type_info & PGT_type_mask) ==
             (!is_pv_32on64_domain(d) ?
              PGT_l4_page_table : PGT_l3_page_table) )
        {
            page->count_info        += 1;
            page->u.inuse.type_info += 1 | PGT_pinned;
        }

        /* Iterate. */
        if ( !((unsigned long)++pl1e & (PAGE_SIZE - 1)) )
        {
            if ( !((unsigned long)++pl2e & (PAGE_SIZE - 1)) )
            {
                if ( !((unsigned long)++pl3e & (PAGE_SIZE - 1)) )
                    pl3e = l4e_to_l3e(*++pl4e);
                pl2e = l3e_to_l2e(*pl3e);
            }
            pl1e = l2e_to_l1e(*pl2e);
        }
    }
}

static __init void setup_pv_physmap(struct domain *d, unsigned long pgtbl_pfn,
                                    unsigned long v_start, unsigned long v_end,
                                    unsigned long vphysmap_start,
                                    unsigned long vphysmap_end,
                                    unsigned long nr_pages)
{
    struct page_info *page = NULL;
    l4_pgentry_t *pl4e, *l4start = map_domain_page(pgtbl_pfn);
    l3_pgentry_t *pl3e = NULL;
    l2_pgentry_t *pl2e = NULL;
    l1_pgentry_t *pl1e = NULL;

    if ( v_start <= vphysmap_end && vphysmap_start <= v_end )
        panic("DOM0 P->M table overlaps initial mapping");

    while ( vphysmap_start < vphysmap_end )
    {
        if ( d->tot_pages + ((round_pgup(vphysmap_end) - vphysmap_start)
                             >> PAGE_SHIFT) + 3 > nr_pages )
            panic("Dom0 allocation too small for initial P->M table");

        if ( pl1e )
        {
            unmap_domain_page(pl1e);
            pl1e = NULL;
        }
        if ( pl2e )
        {
            unmap_domain_page(pl2e);
            pl2e = NULL;
        }
        if ( pl3e )
        {
            unmap_domain_page(pl3e);
            pl3e = NULL;
        }
        pl4e = l4start + l4_table_offset(vphysmap_start);
        if ( !l4e_get_intpte(*pl4e) )
        {
            page = alloc_domheap_page(d, 0);
            if ( !page )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l3_page_table | PGT_validated | 1;
            pl3e = __map_domain_page(page);
            clear_page(pl3e);
            *pl4e = l4e_from_page(page, L4_PROT);
        } else
            pl3e = map_domain_page(l4e_get_pfn(*pl4e));

        pl3e += l3_table_offset(vphysmap_start);
        if ( !l3e_get_intpte(*pl3e) )
        {
            if ( cpu_has_page1gb &&
                 !(vphysmap_start & ((1UL << L3_PAGETABLE_SHIFT) - 1)) &&
                 vphysmap_end >= vphysmap_start + (1UL << L3_PAGETABLE_SHIFT) &&
                 (page = alloc_domheap_pages(d,
                                             L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                                             0)) != NULL )
            {
                *pl3e = l3e_from_page(page, L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                vphysmap_start += 1UL << L3_PAGETABLE_SHIFT;
                continue;
            }
            if ( (page = alloc_domheap_page(d, 0)) == NULL )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l2_page_table | PGT_validated | 1;
            pl2e = __map_domain_page(page);
            clear_page(pl2e);
            *pl3e = l3e_from_page(page, L3_PROT);
        }
        else
           pl2e = map_domain_page(l3e_get_pfn(*pl3e));

        pl2e += l2_table_offset(vphysmap_start);
        if ( !l2e_get_intpte(*pl2e) )
        {
            if ( !(vphysmap_start & ((1UL << L2_PAGETABLE_SHIFT) - 1)) &&
                 vphysmap_end >= vphysmap_start + (1UL << L2_PAGETABLE_SHIFT) &&
                 (page = alloc_domheap_pages(d,
                                             L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                                             0)) != NULL )
            {
                *pl2e = l2e_from_page(page, L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                if ( opt_allow_superpage )
                    get_superpage(page_to_mfn(page), d);
                vphysmap_start += 1UL << L2_PAGETABLE_SHIFT;
                continue;
            }
            if ( (page = alloc_domheap_page(d, 0)) == NULL )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l1_page_table | PGT_validated | 1;
            pl1e = __map_domain_page(page);
            clear_page(pl1e);
            *pl2e = l2e_from_page(page, L2_PROT);
        }
        else
            pl1e = map_domain_page(l2e_get_pfn(*pl2e));

        pl1e += l1_table_offset(vphysmap_start);
        BUG_ON(l1e_get_intpte(*pl1e));
        page = alloc_domheap_page(d, 0);
        if ( !page )
            break;

        *pl1e = l1e_from_page(page, L1_PROT|_PAGE_DIRTY);
        vphysmap_start += PAGE_SIZE;
        vphysmap_start &= PAGE_MASK;
    }
    if ( !page )
        panic("Not enough RAM for DOM0 P->M table");

    if ( pl1e )
        unmap_domain_page(pl1e);
    if ( pl2e )
        unmap_domain_page(pl2e);
    if ( pl3e )
        unmap_domain_page(pl3e);

    unmap_domain_page(l4start);
}

int __init construct_dom0(
    struct domain *d,
    const module_t *image, unsigned long image_headroom,
    module_t *initrd,
    void *(*bootstrap_map)(const module_t *),
    char *cmdline)
{
    int i, cpu, rc, compatible, compat32, order, machine;
    struct cpu_user_regs *regs;
    unsigned long pfn, mfn;
    unsigned long nr_pages;
    unsigned long nr_pt_pages;
    unsigned long alloc_spfn;
    unsigned long alloc_epfn;
    unsigned long initrd_pfn = -1, initrd_mfn = 0;
    unsigned long count;
    struct page_info *page = NULL;
    start_info_t *si;
    struct vcpu *v = d->vcpu[0];
    unsigned long long value;
    char *image_base = bootstrap_map(image);
    unsigned long image_len = image->mod_end;
    char *image_start = image_base + image_headroom;
    unsigned long initrd_len = initrd ? initrd->mod_end : 0;
    l4_pgentry_t *l4tab = NULL, *l4start = NULL;
    l3_pgentry_t *l3tab = NULL, *l3start = NULL;
    l2_pgentry_t *l2tab = NULL, *l2start = NULL;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;
    paddr_t shared_info_paddr = 0;
    u32 save_pvh_pg_mode = 0;

    /*
     * This fully describes the memory layout of the initial domain. All 
     * *_start address are page-aligned, except v_start (and v_end) which are 
     * superpage-aligned.
     */
    struct elf_binary elf;
    struct elf_dom_parms parms;
    unsigned long vkern_start;
    unsigned long vkern_end;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long vphysmap_start;
    unsigned long vphysmap_end;
    unsigned long vstartinfo_start;
    unsigned long vstartinfo_end;
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_start;
    unsigned long v_end;

    /* Machine address of next candidate page-table page. */
    paddr_t mpt_alloc;

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    d->max_pages = ~0U;

    if ( (rc = bzimage_parse(image_base, &image_start, &image_len)) != 0 )
        return rc;

    if ( (rc = elf_init(&elf, image_start, image_len)) != 0 )
        return rc;
#ifdef VERBOSE
    elf_set_verbose(&elf);
#endif
    elf_parse_binary(&elf);
    if ( (rc = elf_xen_parse(&elf, &parms)) != 0 )
        goto out;

    /* compatibility check */
    compatible = 0;
    compat32   = 0;
    machine = elf_uval(&elf, elf.ehdr, e_machine);
    printk(" Xen  kernel: 64-bit, lsb, compat32\n");
    if (elf_32bit(&elf) && parms.pae == PAEKERN_bimodal)
        parms.pae = PAEKERN_extended_cr3;
    if (elf_32bit(&elf) && parms.pae && machine == EM_386)
    {
        compat32 = 1;
        compatible = 1;
    }
    if (elf_64bit(&elf) && machine == EM_X86_64)
        compatible = 1;
    printk(" Dom0 kernel: %s%s, %s, paddr %#" PRIx64 " -> %#" PRIx64 "\n",
           elf_64bit(&elf) ? "64-bit" : "32-bit",
           parms.pae       ? ", PAE"  : "",
           elf_msb(&elf)   ? "msb"    : "lsb",
           elf.pstart, elf.pend);
    if ( elf.bsd_symtab_pstart )
        printk(" Dom0 symbol map %#" PRIx64 " -> %#" PRIx64 "\n",
               elf.bsd_symtab_pstart, elf.bsd_symtab_pend);

    if ( !compatible )
    {
        printk("Mismatch between Xen and DOM0 kernel\n");
        rc = -EINVAL;
        goto out;
    }

    if ( parms.elf_notes[XEN_ELFNOTE_SUPPORTED_FEATURES].type != XEN_ENT_NONE )
    {
        if ( !test_bit(XENFEAT_dom0, parms.f_supported) )
        {
            printk("Kernel does not support Dom0 operation\n");
            rc = -EINVAL;
            goto out;
        }
        if ( is_pvh_domain(d) &&
             !test_bit(XENFEAT_hvm_callback_vector, parms.f_supported) )
        {
            printk("Kernel does not support PVH mode\n");
            rc = -EINVAL;
            goto out;
        }
    }

    if ( compat32 )
    {
        d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 1;
        v->vcpu_info = (void *)&d->shared_info->compat.vcpu_info[0];
        if ( setup_compat_arg_xlat(v) != 0 )
            BUG();
    }

    nr_pages = compute_dom0_nr_pages(d, &parms, initrd_len);

    if ( parms.pae == PAEKERN_extended_cr3 )
            set_bit(VMASST_TYPE_pae_extended_cr3, &d->vm_assist);

    if ( (parms.virt_hv_start_low != UNSET_ADDR) && elf_32bit(&elf) )
    {
        unsigned long mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        value = (parms.virt_hv_start_low + mask) & ~mask;
        BUG_ON(!is_pv_32bit_domain(d));
        if ( value > __HYPERVISOR_COMPAT_VIRT_START )
            panic("Domain 0 expects too high a hypervisor start address");
        HYPERVISOR_COMPAT_VIRT_START(d) =
            max_t(unsigned int, m2p_compat_vstart, value);
    }

    if ( (parms.p2m_base != UNSET_ADDR) && elf_32bit(&elf) )
    {
        printk(XENLOG_WARNING "P2M table base ignored\n");
        parms.p2m_base = UNSET_ADDR;
    }

    domain_set_alloc_bitsize(d);

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    v_start          = parms.virt_base;
    vkern_start      = parms.virt_kstart;
    vkern_end        = parms.virt_kend;
    if ( parms.elf_notes[XEN_ELFNOTE_MOD_START_PFN].data.num )
    {
        vinitrd_start  = vinitrd_end = 0;
        vphysmap_start = round_pgup(vkern_end);
    }
    else
    {
        vinitrd_start  = round_pgup(vkern_end);
        vinitrd_end    = vinitrd_start + initrd_len;
        vphysmap_start = round_pgup(vinitrd_end);
    }
    vphysmap_end     = vphysmap_start + (nr_pages * (!is_pv_32on64_domain(d) ?
                                                     sizeof(unsigned long) :
                                                     sizeof(unsigned int)));
    if ( parms.p2m_base != UNSET_ADDR )
        vphysmap_end = vphysmap_start;
    vstartinfo_start = round_pgup(vphysmap_end);
    vstartinfo_end   = (vstartinfo_start +
                        sizeof(struct start_info) +
                        sizeof(struct dom0_vga_console_info));

    if ( is_pvh_domain(d) )
    {
        shared_info_paddr = round_pgup(vstartinfo_end) - v_start;
        vstartinfo_end   += PAGE_SIZE;
    }

    vpt_start        = round_pgup(vstartinfo_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstack_start     = vpt_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1);
        if ( (v_end - vstack_end) < (512UL << 10) )
            v_end += 1UL << 22; /* Add extra 4MB to get >= 512kB padding. */
#define NR(_l,_h,_s) \
    (((((_h) + ((1UL<<(_s))-1)) & ~((1UL<<(_s))-1)) - \
       ((_l) & ~((1UL<<(_s))-1))) >> (_s))
        if ( (!is_pv_32on64_domain(d) + /* # L4 */
              NR(v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              (!is_pv_32on64_domain(d) ?
               NR(v_start, v_end, L3_PAGETABLE_SHIFT) : /* # L2 */
               4) + /* # compat L2 */
              NR(v_start, v_end, L2_PAGETABLE_SHIFT))  /* # L1 */
             <= nr_pt_pages )
            break;
    }

    count = v_end - v_start;
    if ( vinitrd_start )
        count -= PAGE_ALIGN(initrd_len);
    order = get_order_from_bytes(count);
    if ( (1UL << order) + PFN_UP(initrd_len) > nr_pages )
        panic("Domain 0 allocation is too small for kernel image");

    if ( parms.p2m_base != UNSET_ADDR )
    {
        vphysmap_start = parms.p2m_base;
        vphysmap_end   = vphysmap_start + nr_pages * sizeof(unsigned long);
    }
    page = alloc_domheap_pages(d, order, 0);
    if ( page == NULL )
        panic("Not enough RAM for domain 0 allocation");
    alloc_spfn = page_to_mfn(page);
    alloc_epfn = alloc_spfn + d->tot_pages;

    if ( initrd_len )
    {
        initrd_pfn = vinitrd_start ?
                     (vinitrd_start - v_start) >> PAGE_SHIFT :
                     d->tot_pages;
        initrd_mfn = mfn = initrd->mod_start;
        count = PFN_UP(initrd_len);
        if ( d->arch.physaddr_bitsize &&
             ((mfn + count - 1) >> (d->arch.physaddr_bitsize - PAGE_SHIFT)) )
        {
            order = get_order_from_pages(count);
            page = alloc_domheap_pages(d, order, 0);
            if ( !page )
                panic("Not enough RAM for domain 0 initrd");
            for ( count = -count; order--; )
                if ( count & (1UL << order) )
                {
                    free_domheap_pages(page, order);
                    page += 1UL << order;
                }
            memcpy(page_to_virt(page), mfn_to_virt(initrd->mod_start),
                   initrd_len);
            mpt_alloc = (paddr_t)initrd->mod_start << PAGE_SHIFT;
            init_domheap_pages(mpt_alloc,
                               mpt_alloc + PAGE_ALIGN(initrd_len));
            initrd->mod_start = initrd_mfn = page_to_mfn(page);
        }
        else
        {
            while ( count-- )
                if ( assign_pages(d, mfn_to_page(mfn++), 0, 0) )
                    BUG();
        }
        initrd->mod_end = 0;
    }

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Dom0 alloc.:   %"PRIpaddr"->%"PRIpaddr,
           pfn_to_paddr(alloc_spfn), pfn_to_paddr(alloc_epfn));
    if ( d->tot_pages < nr_pages )
        printk(" (%lu pages to be allocated)",
               nr_pages - d->tot_pages);
    if ( initrd )
    {
        mpt_alloc = (paddr_t)initrd->mod_start << PAGE_SHIFT;
        printk("\n Init. ramdisk: %"PRIpaddr"->%"PRIpaddr,
               mpt_alloc, mpt_alloc + initrd_len);
    }
    printk("\nVIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %p->%p\n"
           " Init. ramdisk: %p->%p\n"
           " Phys-Mach map: %p->%p\n"
           " Start info:    %p->%p\n"
           " Page tables:   %p->%p\n"
           " Boot stack:    %p->%p\n"
           " TOTAL:         %p->%p\n",
           _p(vkern_start), _p(vkern_end),
           _p(vinitrd_start), _p(vinitrd_end),
           _p(vphysmap_start), _p(vphysmap_end),
           _p(vstartinfo_start), _p(vstartinfo_end),
           _p(vpt_start), _p(vpt_end),
           _p(vstack_start), _p(vstack_end),
           _p(v_start), _p(v_end));
    printk(" ENTRY ADDRESS: %p\n", _p(parms.virt_entry));

    mpt_alloc = (vpt_start - v_start) + pfn_to_paddr(alloc_spfn);
    if ( vinitrd_start )
        mpt_alloc -= PAGE_ALIGN(initrd_len);

    /* Overlap with Xen protected area? */
    if ( !is_pv_32on64_domain(d) ?
         ((v_start < HYPERVISOR_VIRT_END) &&
          (v_end > HYPERVISOR_VIRT_START)) :
         (v_end > HYPERVISOR_COMPAT_VIRT_START(d)) )
    {
        printk("DOM0 image overlaps with Xen private area.\n");
        rc = -EINVAL;
        goto out;
    }

    if ( is_pv_32on64_domain(d) )
    {
        v->arch.pv_vcpu.failsafe_callback_cs = FLAT_COMPAT_KERNEL_CS;
        v->arch.pv_vcpu.event_callback_cs    = FLAT_COMPAT_KERNEL_CS;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    if ( !is_pv_32on64_domain(d) )
    {
        maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l4_page_table;
        l4start = l4tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
    }
    else
    {
        page = alloc_domheap_page(NULL, 0);
        if ( !page )
            panic("Not enough RAM for domain 0 PML4");
        page->u.inuse.type_info = PGT_l4_page_table|PGT_validated|1;
        l4start = l4tab = page_to_virt(page);
        maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l3_page_table;
        l3start = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
    }
    clear_page(l4tab);
    init_guest_l4_table(l4tab, d);
    v->arch.guest_table = pagetable_from_paddr(__pa(l4start));
    if ( is_pv_32on64_domain(d) )
        v->arch.guest_table_user = v->arch.guest_table;

    l4tab += l4_table_offset(v_start);
    pfn = alloc_spfn;
    for ( count = 0; count < ((v_end-v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l1_page_table;
            l1start = l1tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(v_start);
            if ( !((unsigned long)l2tab & (PAGE_SIZE-1)) )
            {
                maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l2_page_table;
                l2start = l2tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                clear_page(l2tab);
                if ( count == 0 )
                    l2tab += l2_table_offset(v_start);
                if ( !((unsigned long)l3tab & (PAGE_SIZE-1)) )
                {
                    if ( count || !l3start )
                    {
                        maddr_to_page(mpt_alloc)->u.inuse.type_info =
                            PGT_l3_page_table;
                        l3start = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                    }
                    l3tab = l3start;
                    clear_page(l3tab);
                    if ( count == 0 )
                        l3tab += l3_table_offset(v_start);
                    *l4tab = l4e_from_paddr(__pa(l3start), L4_PROT);
                    l4tab++;
                }
                *l3tab = l3e_from_paddr(__pa(l2start), L3_PROT);
                l3tab++;
            }
            *l2tab = l2e_from_paddr(__pa(l1start), L2_PROT);
            l2tab++;
        }
        if ( count < initrd_pfn || count >= initrd_pfn + PFN_UP(initrd_len) )
            mfn = pfn++;
        else
            mfn = initrd_mfn++;
        *l1tab = l1e_from_pfn(mfn, (!is_pv_32on64_domain(d) ?
                                    L1_PROT : COMPAT_L1_PROT));
        l1tab++;

        if ( !paging_mode_translate(d) )
        {
            page = mfn_to_page(mfn);
            if ( !page->u.inuse.type_info &&
                 !get_page_and_type(page, d, PGT_writable_page) )
                BUG();
        }
    }

    if ( is_pv_32on64_domain(d) )
    {
        /* Ensure the first four L3 entries are all populated. */
        for ( i = 0, l3tab = l3start; i < 4; ++i, ++l3tab )
        {
            if ( !l3e_get_intpte(*l3tab) )
            {
                maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l2_page_table;
                l2tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                clear_page(l2tab);
                *l3tab = l3e_from_paddr(__pa(l2tab), L3_PROT);
            }
            if ( i == 3 )
                l3e_get_page(*l3tab)->u.inuse.type_info |= PGT_pae_xen_l2;
        }
        /* Install read-only guest visible MPT mapping. */
        l2tab = l3e_to_l2e(l3start[3]);
        memcpy(&l2tab[COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d)],
               &compat_idle_pg_table_l2[l2_table_offset(HIRO_COMPAT_MPT_VIRT_START)],
               COMPAT_L2_PAGETABLE_XEN_SLOTS(d) * sizeof(*l2tab));
    }

    /* Pages that are part of page tables must be read only. */
    if  ( is_pv_domain(d) )
        mark_pv_pt_pages_rdonly(d, l4start, vpt_start, nr_pt_pages);

    /* Mask all upcalls... */
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        shared_info(d, vcpu_info[i].evtchn_upcall_mask) = 1;

    printk("Dom0 has maximum %u VCPUs\n", d->max_vcpus);

    cpu = cpumask_first(cpupool0->cpu_valid);
    for ( i = 1; i < d->max_vcpus; i++ )
    {
        cpu = cpumask_cycle(cpu, cpupool0->cpu_valid);
        (void)alloc_vcpu(d, i, cpu);
    }

    /*
     * pvh: we temporarily disable d->arch.paging.mode so that we can build cr3
     * needed to run on dom0's page tables.
     */
    save_pvh_pg_mode = d->arch.paging.mode;
    d->arch.paging.mode = 0;

    /* Set up CR3 value for write_ptbase */
    if ( paging_mode_enabled(d) )
        paging_update_paging_modes(v);
    else
        update_cr3(v);

    /* We run on dom0's page tables for the final part of the build process. */
    write_ptbase(v);
    mapcache_override_current(v);

    /* Copy the OS image and free temporary buffer. */
    elf.dest_base = (void*)vkern_start;
    elf.dest_size = vkern_end - vkern_start;
    rc = elf_load_binary(&elf);
    if ( rc < 0 )
    {
        printk("Failed to load the kernel binary\n");
        goto out;
    }
    bootstrap_map(NULL);

    if ( UNSET_ADDR != parms.virt_hypercall )
    {
        if ( (parms.virt_hypercall < v_start) ||
             (parms.virt_hypercall >= v_end) )
        {
            mapcache_override_current(NULL);
            write_ptbase(current);
            printk("Invalid HYPERCALL_PAGE field in ELF notes.\n");
            rc = -1;
            goto out;
        }
        hypercall_page_initialise(
            d, (void *)(unsigned long)parms.virt_hypercall);
    }

    /* Free temporary buffers. */
    discard_initial_images();

    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    clear_page(si);
    si->nr_pages = nr_pages;

    si->shared_info = virt_to_maddr(d->shared_info);

    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    if ( !vinitrd_start && initrd_len )
        si->flags   |= SIF_MOD_START_PFN;
    si->flags       |= (xen_processor_pmbits << 8) & SIF_PM_MASK;
    si->pt_base      = vpt_start;
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;
    snprintf(si->magic, sizeof(si->magic), "xen-3.0-x86_%d%s",
             elf_64bit(&elf) ? 64 : 32, parms.pae ? "p" : "");

    count = d->tot_pages;

    /* Set up the phys->machine table if not part of the initial mapping. */
    if ( is_pv_domain(d) && parms.p2m_base != UNSET_ADDR )
    {
        pfn = pagetable_get_pfn(v->arch.guest_table);
        setup_pv_physmap(d, pfn, v_start, v_end, vphysmap_start, vphysmap_end,
                         nr_pages);
    }

    if ( is_pvh_domain(d) )
    {
        unsigned long hap_pages, memkb = nr_pages * (PAGE_SIZE / 1024);

        /* Copied from: libxl_get_required_shadow_memory() */
        memkb = 4 * (256 * d->max_vcpus + 2 * (memkb / 1024));
        hap_pages = ( (memkb + 1023) / 1024) << (20 - PAGE_SHIFT);
        hap_set_alloc_for_pvh_dom0(d, hap_pages);
    }

    /*
     * We enable paging mode again so guest_physmap_add_page will do the
     * right thing for us.
     */
    d->arch.paging.mode = save_pvh_pg_mode;

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < count; pfn++ )
    {
        mfn = pfn + alloc_spfn;
        if ( pfn >= initrd_pfn )
        {
            if ( pfn < initrd_pfn + PFN_UP(initrd_len) )
                mfn = initrd->mod_start + (pfn - initrd_pfn);
            else
                mfn -= PFN_UP(initrd_len);
        }
#ifndef NDEBUG
#define REVERSE_START ((v_end - v_start) >> PAGE_SHIFT)
        if ( pfn > REVERSE_START && (vinitrd_start || pfn < initrd_pfn) )
            mfn = alloc_epfn - (pfn - REVERSE_START);
#endif
        dom0_update_physmap(d, pfn, mfn, vphysmap_start);
        if (!(pfn & 0xfffff))
            process_pending_softirqs();
    }
    si->first_p2m_pfn = pfn;
    si->nr_p2m_frames = d->tot_pages - count;
    page_list_for_each ( page, &d->page_list )
    {
        mfn = page_to_mfn(page);
        BUG_ON(SHARED_M2P(get_gpfn_from_mfn(mfn)));
        if ( get_gpfn_from_mfn(mfn) >= count )
        {
            BUG_ON(is_pv_32bit_domain(d));
            if ( !paging_mode_translate(d) && !page->u.inuse.type_info &&
                 !get_page_and_type(page, d, PGT_writable_page) )
                BUG();

            dom0_update_physmap(d, pfn, mfn, vphysmap_start);
            ++pfn;
            if (!(pfn & 0xfffff))
                process_pending_softirqs();
        }
    }
    BUG_ON(pfn != d->tot_pages);
#ifndef NDEBUG
    alloc_epfn += PFN_UP(initrd_len) + si->nr_p2m_frames;
#endif
    while ( pfn < nr_pages )
    {
        if ( (page = alloc_chunk(d, nr_pages - d->tot_pages)) == NULL )
            panic("Not enough RAM for DOM0 reservation");
        while ( pfn < d->tot_pages )
        {
            mfn = page_to_mfn(page);
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - (alloc_epfn - alloc_spfn)))
#endif
            dom0_update_physmap(d, pfn, mfn, vphysmap_start);
#undef pfn
            page++; pfn++;
            if (!(pfn & 0xfffff))
                process_pending_softirqs();
        }
    }

    if ( initrd_len != 0 )
    {
        si->mod_start = vinitrd_start ?: initrd_pfn;
        si->mod_len   = initrd_len;
    }

    memset(si->cmd_line, 0, sizeof(si->cmd_line));
    if ( cmdline != NULL )
        strlcpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line));

    if ( fill_console_start_info((void *)(si + 1)) )
    {
        si->console.dom0.info_off  = sizeof(struct start_info);
        si->console.dom0.info_size = sizeof(struct dom0_vga_console_info);
    }

    /*
     * PVH: We need to update si->shared_info while we are on dom0 page tables,
     * but need to defer the p2m update until after we have fixed up the
     * page tables for PVH so that the m2p for the si pte entry returns
     * correct pfn.
     */
    if ( is_pvh_domain(d) )
        si->shared_info = shared_info_paddr;

    if ( is_pv_32on64_domain(d) )
        xlat_start_info(si, XLAT_start_info_console_dom0);

    /* Return to idle domain's page tables. */
    mapcache_override_current(NULL);
    write_ptbase(current);

    update_domain_wallclock_time(d);

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_KERNEL_DS
     *       CS:EIP = FLAT_KERNEL_CS:start_pc
     *       SS:ESP = FLAT_KERNEL_SS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     */
    regs = &v->arch.user_regs;
    regs->ds = regs->es = regs->fs = regs->gs =
        !is_pv_32on64_domain(d) ? FLAT_KERNEL_DS : FLAT_COMPAT_KERNEL_DS;
    regs->ss = (!is_pv_32on64_domain(d) ?
                FLAT_KERNEL_SS : FLAT_COMPAT_KERNEL_SS);
    regs->cs = (!is_pv_32on64_domain(d) ?
                FLAT_KERNEL_CS : FLAT_COMPAT_KERNEL_CS);
    regs->eip = parms.virt_entry;
    regs->esp = vstack_end;
    regs->esi = vstartinfo_start;
    regs->eflags = X86_EFLAGS_IF;

    if ( opt_dom0_shadow )
    {
        if ( is_pvh_domain(d) )
        {
            printk("Unsupported option dom0_shadow for PVH\n");
            return -EINVAL;
        }
        if ( paging_enable(d, PG_SH_enable) == 0 ) 
            paging_update_paging_modes(v);
    }

    if ( supervisor_mode_kernel )
    {
        v->arch.pv_vcpu.kernel_ss &= ~3;
        v->arch.user_regs.ss &= ~3;
        v->arch.user_regs.es &= ~3;
        v->arch.user_regs.ds &= ~3;
        v->arch.user_regs.fs &= ~3;
        v->arch.user_regs.gs &= ~3;
        printk("Dom0 runs in ring 0 (supervisor mode)\n");
        if ( !test_bit(XENFEAT_supervisor_mode_kernel,
                       parms.f_supported) )
            panic("Dom0 does not support supervisor-mode execution");
    }
    else
    {
        if ( test_bit(XENFEAT_supervisor_mode_kernel, parms.f_required) )
            panic("Dom0 requires supervisor-mode execution");
    }

    rc = 0;

    /* The hardware domain is initially permitted full I/O capabilities. */
    rc |= ioports_permit_access(d, 0, 0xFFFF);
    rc |= iomem_permit_access(d, 0UL, ~0UL);
    rc |= irqs_permit_access(d, 1, nr_irqs_gsi - 1);

    /*
     * Modify I/O port access permissions.
     */
    /* Master Interrupt Controller (PIC). */
    rc |= ioports_deny_access(d, 0x20, 0x21);
    /* Slave Interrupt Controller (PIC). */
    rc |= ioports_deny_access(d, 0xA0, 0xA1);
    /* Interval Timer (PIT). */
    rc |= ioports_deny_access(d, 0x40, 0x43);
    /* PIT Channel 2 / PC Speaker Control. */
    rc |= ioports_deny_access(d, 0x61, 0x61);
    /* ACPI PM Timer. */
    if ( pmtmr_ioport )
        rc |= ioports_deny_access(d, pmtmr_ioport, pmtmr_ioport + 3);
    /* PCI configuration space (NB. 0xcf8 has special treatment). */
    rc |= ioports_deny_access(d, 0xcfc, 0xcff);
    /* Command-line I/O ranges. */
    process_dom0_ioports_disable(d);

    /*
     * Modify I/O memory access permissions.
     */
    /* Local APIC. */
    if ( mp_lapic_addr != 0 )
    {
        mfn = paddr_to_pfn(mp_lapic_addr);
        rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* I/O APICs. */
    for ( i = 0; i < nr_ioapics; i++ )
    {
        mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);
        if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
            rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* MSI range. */
    rc |= iomem_deny_access(d, paddr_to_pfn(MSI_ADDR_BASE_LO),
                            paddr_to_pfn(MSI_ADDR_BASE_LO +
                                         MSI_ADDR_DEST_ID_MASK));
    /* HyperTransport range. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        rc |= iomem_deny_access(d, paddr_to_pfn(0xfdULL << 32),
                                paddr_to_pfn((1ULL << 40) - 1));

    /* Remove access to E820_UNUSABLE I/O regions above 1MB. */
    for ( i = 0; i < e820.nr_map; i++ )
    {
        unsigned long sfn, efn;
        sfn = max_t(unsigned long, paddr_to_pfn(e820.map[i].addr), 0x100ul);
        efn = paddr_to_pfn(e820.map[i].addr + e820.map[i].size - 1);
        if ( (e820.map[i].type == E820_UNUSABLE) &&
             (e820.map[i].size != 0) &&
             (sfn <= efn) )
            rc |= iomem_deny_access(d, sfn, efn);
    }

    BUG_ON(rc != 0);

    if ( elf_check_broken(&elf) )
        printk(" Xen warning: dom0 kernel broken ELF: %s\n",
               elf_check_broken(&elf));

    if ( is_pvh_domain(d) )
    {
        /* finally, fixup the page table, replacing mfns with pfns */
        pvh_fixup_page_tables_for_hap(v, v_start, v_end);

        /* the pt has correct pfn for si, now update the mfn in the p2m */
        mfn = virt_to_mfn(d->shared_info);
        pfn = shared_info_paddr >> PAGE_SHIFT;
        dom0_update_physmap(d, pfn, mfn, 0);

        pvh_map_all_iomem(d, nr_pages);
        pvh_setup_e820(d, nr_pages);
    }

    if ( d->domain_id == hardware_domid )
        iommu_hwdom_init(d);

    return 0;

out:
    if ( elf_check_broken(&elf) )
        printk(" Xen dom0 kernel broken ELF: %s\n",
               elf_check_broken(&elf));

    return rc;
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
