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
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/e820.h>

#include <public/version.h>

int __init bzimage_parse(
    char *output, char **image_start, unsigned long *image_len);

extern unsigned long initial_images_nrpages(void);
extern void discard_initial_images(void);

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

static unsigned int __initdata opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

struct vcpu *__init alloc_dom0_vcpu0(void)
{
    if ( opt_dom0_max_vcpus == 0 )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > MAX_VIRT_CPUS )
        opt_dom0_max_vcpus = MAX_VIRT_CPUS;

    dom0->vcpu = xmalloc_array(struct vcpu *, opt_dom0_max_vcpus);
    if ( !dom0->vcpu )
        return NULL;
    memset(dom0->vcpu, 0, opt_dom0_max_vcpus * sizeof(*dom0->vcpu));
    dom0->max_vcpus = opt_dom0_max_vcpus;

    return alloc_vcpu(dom0, 0, 0);
}

static unsigned int opt_dom0_shadow;
boolean_param("dom0_shadow", opt_dom0_shadow);

static char opt_dom0_ioports_disable[200] = "";
string_param("dom0_ioports_disable", opt_dom0_ioports_disable);

#if defined(__i386__)
/* No ring-3 access in initial leaf page tables. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT)
#elif defined(__x86_64__)
/* Allow ring-3 access in long mode as guest cannot use ring 1 ... */
#define BASE_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L1_PROT (BASE_PROT|_PAGE_GUEST_KERNEL)
/* ... except for compatibility mode guests. */
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (BASE_PROT|_PAGE_DIRTY)
#define L3_PROT (BASE_PROT|_PAGE_DIRTY)
#define L4_PROT (BASE_PROT|_PAGE_DIRTY)
#endif

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static struct page_info * __init alloc_chunk(
    struct domain *d, unsigned long max_pages)
{
    struct page_info *page;
    unsigned int order;
    /*
     * Allocate up to 2MB at a time: It prevents allocating very large chunks
     * from DMA pools before the >4GB pool is fully depleted.
     */
    if ( max_pages > (2UL << (20 - PAGE_SHIFT)) )
        max_pages = 2UL << (20 - PAGE_SHIFT);
    order = get_order_from_pages(max_pages);
    if ( (max_pages & (max_pages-1)) != 0 )
        order--;
    while ( (page = alloc_domheap_pages(d, order, 0)) == NULL )
        if ( order-- == 0 )
            break;
    return page;
}

static unsigned long __init compute_dom0_nr_pages(
#ifdef __x86_64__
    unsigned long vstart, unsigned long vend, size_t sizeof_long)
#else
    void)
#endif
{
    unsigned long avail = avail_domheap_pages() + initial_images_nrpages();
    unsigned long nr_pages = dom0_nrpages;
    unsigned long min_pages = dom0_min_nrpages;
    unsigned long max_pages = dom0_max_nrpages;

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

#ifdef __x86_64__
    if ( vstart && dom0_nrpages <= 0 &&
         (dom0_min_nrpages <= 0 || nr_pages > min_pages) )
    {
        /*
         * Legacy Linux kernels (i.e. such without a XEN_ELFNOTE_INIT_P2M
         * note) require that there is enough virtual space beyond the initial
         * allocation to set up their initial page tables. This space is
         * roughly the same size as the p2m table, so make sure the initial
         * allocation doesn't consume more than about half the space that's
         * available between params.virt_base and the address space end.
         */
        unsigned long end = vend + nr_pages * sizeof_long;

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
#endif

    return nr_pages;
}

static void __init process_dom0_ioports_disable(void)
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

int __init construct_dom0(
    struct domain *d,
    unsigned long _image_base,
    unsigned long _image_start, unsigned long image_len,
    unsigned long _initrd_start, unsigned long initrd_len,
    char *cmdline)
{
    int i, rc, compatible, compat32, order, machine;
    struct cpu_user_regs *regs;
    unsigned long pfn, mfn;
    unsigned long nr_pages;
    unsigned long nr_pt_pages;
    unsigned long alloc_spfn;
    unsigned long alloc_epfn;
    unsigned long count;
    struct page_info *page = NULL;
    start_info_t *si;
    struct vcpu *v = d->vcpu[0];
    unsigned long long value;
#if defined(__i386__)
    char *image_base   = (char *)_image_base;   /* use lowmem mappings */
    char *image_start  = (char *)_image_start;  /* use lowmem mappings */
    char *initrd_start = (char *)_initrd_start; /* use lowmem mappings */
#elif defined(__x86_64__)
    char *image_base   = __va(_image_base);
    char *image_start  = __va(_image_start);
    char *initrd_start = __va(_initrd_start);
#endif
#if CONFIG_PAGING_LEVELS >= 4
    l4_pgentry_t *l4tab = NULL, *l4start = NULL;
#endif
    l3_pgentry_t *l3tab = NULL, *l3start = NULL;
    l2_pgentry_t *l2tab = NULL, *l2start = NULL;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;

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
    unsigned long mpt_alloc;

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
        return rc;

    /* compatibility check */
    compatible = 0;
    compat32   = 0;
    machine = elf_uval(&elf, elf.ehdr, e_machine);
    switch (CONFIG_PAGING_LEVELS) {
    case 3: /* x86_32p */
        if (parms.pae == PAEKERN_bimodal)
            parms.pae = PAEKERN_extended_cr3;
        printk(" Xen  kernel: 32-bit, PAE, lsb\n");
        if (elf_32bit(&elf) && parms.pae && machine == EM_386)
            compatible = 1;
        break;
    case 4: /* x86_64 */
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
        break;
    }
    printk(" Dom0 kernel: %s%s, %s, paddr 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
           elf_64bit(&elf) ? "64-bit" : "32-bit",
           parms.pae       ? ", PAE"  : "",
           elf_msb(&elf)   ? "msb"    : "lsb",
           elf.pstart, elf.pend);
    if ( elf.bsd_symtab_pstart )
        printk(" Dom0 symbol map 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
               elf.bsd_symtab_pstart, elf.bsd_symtab_pend);

    if ( !compatible )
    {
        printk("Mismatch between Xen and DOM0 kernel\n");
        return -EINVAL;
    }

#if defined(__x86_64__)
    if ( compat32 )
    {
        d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 1;
        v->vcpu_info = (void *)&d->shared_info->compat.vcpu_info[0];

        nr_pages = compute_dom0_nr_pages(parms.virt_base,
            round_pgup(parms.virt_kend) + round_pgup(initrd_len),
            sizeof(unsigned int));
    }
    else if (parms.p2m_base != UNSET_ADDR)
        nr_pages = compute_dom0_nr_pages(0, 0, 0);
    else
        nr_pages = compute_dom0_nr_pages(parms.virt_base,
            round_pgup(parms.virt_kend) + round_pgup(initrd_len),
            sizeof(unsigned long));
#else
    nr_pages = compute_dom0_nr_pages();
#endif

    if ( parms.pae == PAEKERN_extended_cr3 )
            set_bit(VMASST_TYPE_pae_extended_cr3, &d->vm_assist);

    if ( (parms.virt_hv_start_low != UNSET_ADDR) && elf_32bit(&elf) )
    {
        unsigned long mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        value = (parms.virt_hv_start_low + mask) & ~mask;
        BUG_ON(!is_pv_32bit_domain(d));
#if defined(__i386__)
        if ( value > HYPERVISOR_VIRT_START )
            panic("Domain 0 expects too high a hypervisor start address.\n");
#else
        if ( value > __HYPERVISOR_COMPAT_VIRT_START )
            panic("Domain 0 expects too high a hypervisor start address.\n");
        HYPERVISOR_COMPAT_VIRT_START(d) =
            max_t(unsigned int, m2p_compat_vstart, value);
#endif
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
    vinitrd_start    = round_pgup(vkern_end);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * (!is_pv_32on64_domain(d) ?
                                                     sizeof(unsigned long) :
                                                     sizeof(unsigned int)));
    if ( parms.p2m_base != UNSET_ADDR )
        vphysmap_end = vphysmap_start;
    vstartinfo_start = round_pgup(vphysmap_end);
    vstartinfo_end   = (vstartinfo_start +
                        sizeof(struct start_info) +
                        sizeof(struct dom0_vga_console_info));
    vpt_start        = round_pgup(vstartinfo_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstack_start     = vpt_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1);
        if ( (v_end - vstack_end) < (512UL << 10) )
            v_end += 1UL << 22; /* Add extra 4MB to get >= 512kB padding. */
#if defined(__i386__)
        /* 5 pages: 1x 3rd + 4x 2nd level */
        if ( (((v_end - v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >>
               L2_PAGETABLE_SHIFT) + 5) <= nr_pt_pages )
            break;
#elif defined(__x86_64__)
#define NR(_l,_h,_s) \
    (((((_h) + ((1UL<<(_s))-1)) & ~((1UL<<(_s))-1)) - \
       ((_l) & ~((1UL<<(_s))-1))) >> (_s))
        if ( (1 + /* # L4 */
              NR(v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              (!is_pv_32on64_domain(d) ?
               NR(v_start, v_end, L3_PAGETABLE_SHIFT) : /* # L2 */
               4) + /* # compat L2 */
              NR(v_start, v_end, L2_PAGETABLE_SHIFT))  /* # L1 */
             <= nr_pt_pages )
            break;
#endif
    }

    order = get_order_from_bytes(v_end - v_start);
    if ( (1UL << order) > nr_pages )
        panic("Domain 0 allocation is too small for kernel image.\n");

#ifdef __i386__
    /* Ensure that our low-memory 1:1 mapping covers the allocation. */
    page = alloc_domheap_pages(d, order, MEMF_bits(30));
#else
    if ( parms.p2m_base != UNSET_ADDR )
    {
        vphysmap_start = parms.p2m_base;
        vphysmap_end   = vphysmap_start + nr_pages * sizeof(unsigned long);
    }
    page = alloc_domheap_pages(d, order, 0);
#endif
    if ( page == NULL )
        panic("Not enough RAM for domain 0 allocation.\n");
    alloc_spfn = page_to_mfn(page);
    alloc_epfn = alloc_spfn + d->tot_pages;

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Dom0 alloc.:   %"PRIpaddr"->%"PRIpaddr,
           pfn_to_paddr(alloc_spfn), pfn_to_paddr(alloc_epfn));
    if ( d->tot_pages < nr_pages )
        printk(" (%lu pages to be allocated)",
               nr_pages - d->tot_pages);
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

    mpt_alloc = (vpt_start - v_start) +
        (unsigned long)pfn_to_paddr(alloc_spfn);

#if defined(__i386__)
    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( v_start < (1UL<<30) )
    {
        printk("Initial loading isn't allowed to lowest 1GB of memory.\n");
        return -EINVAL;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    l3start = l3tab = (l3_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += 4*PAGE_SIZE;
    for (i = 0; i < L3_PAGETABLE_ENTRIES; i++) {
        copy_page(l2tab + i * L2_PAGETABLE_ENTRIES,
                  idle_pg_table_l2 + i * L2_PAGETABLE_ENTRIES);
        l3tab[i] = l3e_from_paddr((u32)l2tab + i*PAGE_SIZE, L3_PROT);
        l2tab[(LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT)+i] =
            l2e_from_paddr((u32)l2tab + i*PAGE_SIZE, __PAGE_HYPERVISOR);
    }
    v->arch.guest_table = pagetable_from_paddr((unsigned long)l3start);

    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        l2tab[l2_linear_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_page(perdomain_pt_page(d, i), __PAGE_HYPERVISOR);

    l2tab += l2_linear_offset(v_start);
    mfn = alloc_spfn;
    for ( count = 0; count < ((v_end-v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc;
            mpt_alloc += PAGE_SIZE;
            *l2tab = l2e_from_paddr((unsigned long)l1start, L2_PROT);
            l2tab++;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(v_start);
        }
        *l1tab = l1e_from_pfn(mfn, L1_PROT);
        l1tab++;
        
        page = mfn_to_page(mfn);
        if ( !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
    }

    /* Pages that are part of page tables must be read only. */
    l2tab = l2start + l2_linear_offset(vpt_start);
    l1start = l1tab = (l1_pgentry_t *)(u32)l2e_get_paddr(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        page = mfn_to_page(l1e_get_pfn(*l1tab));
        if ( !opt_dom0_shadow )
            l1e_remove_flags(*l1tab, _PAGE_RW);
        else
            if ( !get_page_type(page, PGT_writable_page) )
                BUG();

        switch ( count )
        {
        case 0:
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l3_page_table;
            get_page(page, d); /* an extra ref because of readable mapping */

            /* Get another ref to L3 page so that it can be pinned. */
            page->u.inuse.type_info++;
            page->count_info++;
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
            break;
        case 1 ... 4:
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l2_page_table;
            if ( count == 4 )
                page->u.inuse.type_info |= PGT_pae_xen_l2;
            get_page(page, d); /* an extra ref because of readable mapping */
            break;
        default:
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l1_page_table;
            get_page(page, d); /* an extra ref because of readable mapping */
            break;
        }
        if ( !((unsigned long)++l1tab & (PAGE_SIZE - 1)) )
            l1start = l1tab = (l1_pgentry_t *)(u32)l2e_get_paddr(*++l2tab);
    }

#elif defined(__x86_64__)

    /* Overlap with Xen protected area? */
    if ( !is_pv_32on64_domain(d) ?
         ((v_start < HYPERVISOR_VIRT_END) &&
          (v_end > HYPERVISOR_VIRT_START)) :
         (v_end > HYPERVISOR_COMPAT_VIRT_START(d)) )
    {
        printk("DOM0 image overlaps with Xen private area.\n");
        return -EINVAL;
    }

    if ( is_pv_32on64_domain(d) )
    {
        v->arch.guest_context.failsafe_callback_cs = FLAT_COMPAT_KERNEL_CS;
        v->arch.guest_context.event_callback_cs    = FLAT_COMPAT_KERNEL_CS;
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
            panic("Not enough RAM for domain 0 PML4.\n");
        page->u.inuse.type_info = PGT_l4_page_table|PGT_validated|1;
        l4start = l4tab = page_to_virt(page);
    }
    copy_page(l4tab, idle_pg_table);
    l4tab[0] = l4e_empty(); /* zap trampoline mapping */
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_paddr(__pa(l4start), __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(d->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    v->arch.guest_table = pagetable_from_paddr(__pa(l4start));
    if ( is_pv_32on64_domain(d) )
        v->arch.guest_table_user = v->arch.guest_table;

    l4tab += l4_table_offset(v_start);
    mfn = alloc_spfn;
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
                    maddr_to_page(mpt_alloc)->u.inuse.type_info =
                        PGT_l3_page_table;
                    l3start = l3tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
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
        *l1tab = l1e_from_pfn(mfn, (!is_pv_32on64_domain(d) ?
                                    L1_PROT : COMPAT_L1_PROT));
        l1tab++;

        page = mfn_to_page(mfn);
        if ( (page->u.inuse.type_info == 0) &&
             !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
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
    l4tab = l4start + l4_table_offset(vpt_start);
    l3start = l3tab = l4e_to_l3e(*l4tab);
    l3tab += l3_table_offset(vpt_start);
    l2start = l2tab = l3e_to_l2e(*l3tab);
    l2tab += l2_table_offset(vpt_start);
    l1start = l1tab = l2e_to_l1e(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        l1e_remove_flags(*l1tab, _PAGE_RW);
        page = mfn_to_page(l1e_get_pfn(*l1tab));

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
        if ( !((unsigned long)++l1tab & (PAGE_SIZE - 1)) )
        {
            if ( !((unsigned long)++l2tab & (PAGE_SIZE - 1)) )
            {
                if ( !((unsigned long)++l3tab & (PAGE_SIZE - 1)) )
                    l3start = l3tab = l4e_to_l3e(*++l4tab);
                l2start = l2tab = l3e_to_l2e(*l3tab);
            }
            l1start = l1tab = l2e_to_l1e(*l2tab);
        }
    }

#endif /* __x86_64__ */

    /* Mask all upcalls... */
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        shared_info(d, vcpu_info[i].evtchn_upcall_mask) = 1;

    printk("Dom0 has maximum %u VCPUs\n", opt_dom0_max_vcpus);

    for ( i = 1; i < opt_dom0_max_vcpus; i++ )
        (void)alloc_vcpu(d, i, i % num_online_cpus());

    /* Set up CR3 value for write_ptbase */
    if ( paging_mode_enabled(d) )
        paging_update_paging_modes(v);
    else
        update_cr3(v);

    /* We run on dom0's page tables for the final part of the build process. */
    write_ptbase(v);

    /* Copy the OS image and free temporary buffer. */
    elf.dest = (void*)vkern_start;
    elf_load_binary(&elf);

    if ( UNSET_ADDR != parms.virt_hypercall )
    {
        if ( (parms.virt_hypercall < v_start) ||
             (parms.virt_hypercall >= v_end) )
        {
            write_ptbase(current);
            printk("Invalid HYPERCALL_PAGE field in ELF notes.\n");
            return -1;
        }
        hypercall_page_initialise(
            d, (void *)(unsigned long)parms.virt_hypercall);
    }

    /* Copy the initial ramdisk. */
    if ( initrd_len != 0 )
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);

    /* Free temporary buffers. */
    discard_initial_images();

    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    clear_page(si);
    si->nr_pages = nr_pages;

    si->shared_info = virt_to_maddr(d->shared_info);

    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->flags       |= (xen_processor_pmbits << 8) & SIF_PM_MASK;
    si->pt_base      = vpt_start + 2 * PAGE_SIZE * !!is_pv_32on64_domain(d);
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;
    snprintf(si->magic, sizeof(si->magic), "xen-3.0-x86_%d%s",
             elf_64bit(&elf) ? 64 : 32, parms.pae ? "p" : "");

    count = d->tot_pages;
#ifdef __x86_64__
    /* Set up the phys->machine table if not part of the initial mapping. */
    if ( parms.p2m_base != UNSET_ADDR )
    {
        unsigned long va = vphysmap_start;

        if ( v_start <= vphysmap_end && vphysmap_start <= v_end )
            panic("DOM0 P->M table overlaps initial mapping");

        while ( va < vphysmap_end )
        {
            if ( d->tot_pages + ((round_pgup(vphysmap_end) - va)
                                 >> PAGE_SHIFT) + 3 > nr_pages )
                panic("Dom0 allocation too small for initial P->M table.\n");

            l4tab = l4start + l4_table_offset(va);
            if ( !l4e_get_intpte(*l4tab) )
            {
                page = alloc_domheap_page(d, 0);
                if ( !page )
                    break;
                /* No mapping, PGC_allocated + page-table page. */
                page->count_info = PGC_allocated | 2;
                page->u.inuse.type_info =
                    PGT_l3_page_table | PGT_validated | 1;
                clear_page(page_to_virt(page));
                *l4tab = l4e_from_page(page, L4_PROT);
            }
            l3tab = page_to_virt(l4e_get_page(*l4tab));
            l3tab += l3_table_offset(va);
            if ( !l3e_get_intpte(*l3tab) )
            {
                if ( cpu_has_page1gb &&
                     !(va & ((1UL << L3_PAGETABLE_SHIFT) - 1)) &&
                     vphysmap_end >= va + (1UL << L3_PAGETABLE_SHIFT) &&
                     (page = alloc_domheap_pages(d,
                                                 L3_PAGETABLE_SHIFT -
                                                     PAGE_SHIFT,
                                                 0)) != NULL )
                {
                    *l3tab = l3e_from_page(page,
                                           L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                    va += 1UL << L3_PAGETABLE_SHIFT;
                    continue;
                }
                if ( (page = alloc_domheap_page(d, 0)) == NULL )
                    break;
                else
                {
                    /* No mapping, PGC_allocated + page-table page. */
                    page->count_info = PGC_allocated | 2;
                    page->u.inuse.type_info =
                        PGT_l2_page_table | PGT_validated | 1;
                    clear_page(page_to_virt(page));
                    *l3tab = l3e_from_page(page, L3_PROT);
                }
            }
            l2tab = page_to_virt(l3e_get_page(*l3tab));
            l2tab += l2_table_offset(va);
            if ( !l2e_get_intpte(*l2tab) )
            {
                if ( !(va & ((1UL << L2_PAGETABLE_SHIFT) - 1)) &&
                     vphysmap_end >= va + (1UL << L2_PAGETABLE_SHIFT) &&
                     (page = alloc_domheap_pages(d,
                                                 L2_PAGETABLE_SHIFT -
                                                     PAGE_SHIFT,
                                                 0)) != NULL )
                {
                    *l2tab = l2e_from_page(page,
                                           L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                    va += 1UL << L2_PAGETABLE_SHIFT;
                    continue;
                }
                if ( (page = alloc_domheap_page(d, 0)) == NULL )
                    break;
                else
                {
                    /* No mapping, PGC_allocated + page-table page. */
                    page->count_info = PGC_allocated | 2;
                    page->u.inuse.type_info =
                        PGT_l1_page_table | PGT_validated | 1;
                    clear_page(page_to_virt(page));
                    *l2tab = l2e_from_page(page, L2_PROT);
                }
            }
            l1tab = page_to_virt(l2e_get_page(*l2tab));
            l1tab += l1_table_offset(va);
            BUG_ON(l1e_get_intpte(*l1tab));
            page = alloc_domheap_page(d, 0);
            if ( !page )
                break;
            *l1tab = l1e_from_page(page, L1_PROT|_PAGE_DIRTY);
            va += PAGE_SIZE;
            va &= PAGE_MASK;
        }
        if ( !page )
            panic("Not enough RAM for DOM0 P->M table.\n");
    }
#endif

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < count; pfn++ )
    {
        mfn = pfn + alloc_spfn;
#ifndef NDEBUG
#define REVERSE_START ((v_end - v_start) >> PAGE_SHIFT)
        if ( pfn > REVERSE_START )
            mfn = alloc_epfn - (pfn - REVERSE_START);
#endif
        if ( !is_pv_32on64_domain(d) )
            ((unsigned long *)vphysmap_start)[pfn] = mfn;
        else
            ((unsigned int *)vphysmap_start)[pfn] = mfn;
        set_gpfn_from_mfn(mfn, pfn);
        if (!(pfn & 0xfffff))
            process_pending_timers();
    }
    si->first_p2m_pfn = pfn;
    si->nr_p2m_frames = d->tot_pages - count;
    page_list_for_each ( page, &d->page_list )
    {
        mfn = page_to_mfn(page);
        if ( get_gpfn_from_mfn(mfn) >= count )
        {
            BUG_ON(is_pv_32bit_domain(d));
            if ( !page->u.inuse.type_info &&
                 !get_page_and_type(page, d, PGT_writable_page) )
                BUG();
            ((unsigned long *)vphysmap_start)[pfn] = mfn;
            set_gpfn_from_mfn(mfn, pfn);
            ++pfn;
#ifndef NDEBUG
            ++alloc_epfn;
#endif
            if (!(pfn & 0xfffff))
                process_pending_timers();
        }
    }
    BUG_ON(pfn != d->tot_pages);
    while ( pfn < nr_pages )
    {
        if ( (page = alloc_chunk(d, nr_pages - d->tot_pages)) == NULL )
            panic("Not enough RAM for DOM0 reservation.\n");
        while ( pfn < d->tot_pages )
        {
            mfn = page_to_mfn(page);
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - (alloc_epfn - alloc_spfn)))
#endif
            if ( !is_pv_32on64_domain(d) )
                ((unsigned long *)vphysmap_start)[pfn] = mfn;
            else
                ((unsigned int *)vphysmap_start)[pfn] = mfn;
            set_gpfn_from_mfn(mfn, pfn);
#undef pfn
            page++; pfn++;
            if (!(pfn & 0xfffff))
                process_pending_timers();
        }
    }

    if ( initrd_len != 0 )
    {
        si->mod_start = vinitrd_start;
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

#if defined(__x86_64__)
    if ( is_pv_32on64_domain(d) )
        xlat_start_info(si, XLAT_start_info_console_dom0);
#endif

    /* Return to idle domain's page tables. */
    write_ptbase(current);

#if defined(__i386__)
    /* Destroy low mappings - they were only for our convenience. */
    zap_low_mappings(l2start);
#endif

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
    regs = &v->arch.guest_context.user_regs;
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
        if ( paging_enable(d, PG_SH_enable) == 0 ) 
            paging_update_paging_modes(v);

    if ( supervisor_mode_kernel )
    {
        v->arch.guest_context.kernel_ss &= ~3;
        v->arch.guest_context.user_regs.ss &= ~3;
        v->arch.guest_context.user_regs.es &= ~3;
        v->arch.guest_context.user_regs.ds &= ~3;
        v->arch.guest_context.user_regs.fs &= ~3;
        v->arch.guest_context.user_regs.gs &= ~3;
        printk("Dom0 runs in ring 0 (supervisor mode)\n");
        if ( !test_bit(XENFEAT_supervisor_mode_kernel,
                       parms.f_supported) )
            panic("Dom0 does not support supervisor-mode execution\n");
    }
    else
    {
        if ( test_bit(XENFEAT_supervisor_mode_kernel, parms.f_required) )
            panic("Dom0 requires supervisor-mode execution\n");
    }

    rc = 0;

    /* DOM0 is permitted full I/O capabilities. */
    rc |= ioports_permit_access(dom0, 0, 0xFFFF);
    rc |= iomem_permit_access(dom0, 0UL, ~0UL);
    rc |= irqs_permit_access(dom0, 0, d->nr_pirqs - 1);

    /*
     * Modify I/O port access permissions.
     */
    /* Master Interrupt Controller (PIC). */
    rc |= ioports_deny_access(dom0, 0x20, 0x21);
    /* Slave Interrupt Controller (PIC). */
    rc |= ioports_deny_access(dom0, 0xA0, 0xA1);
    /* Interval Timer (PIT). */
    rc |= ioports_deny_access(dom0, 0x40, 0x43);
    /* PIT Channel 2 / PC Speaker Control. */
    rc |= ioports_deny_access(dom0, 0x61, 0x61);
    /* PCI configuration space (NB. 0xcf8 has special treatment). */
    rc |= ioports_deny_access(dom0, 0xcfc, 0xcff);
    /* Command-line I/O ranges. */
    process_dom0_ioports_disable();

    /*
     * Modify I/O memory access permissions.
     */
    /* Local APIC. */
    if ( mp_lapic_addr != 0 )
    {
        mfn = paddr_to_pfn(mp_lapic_addr);
        rc |= iomem_deny_access(dom0, mfn, mfn);
    }
    /* I/O APICs. */
    for ( i = 0; i < nr_ioapics; i++ )
    {
        mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);
        if ( smp_found_config )
            rc |= iomem_deny_access(dom0, mfn, mfn);
    }

    /* Remove access to E820_UNUSABLE I/O regions above 1MB. */
    for ( i = 0; i < e820.nr_map; i++ )
    {
        unsigned long sfn, efn;
        sfn = max_t(unsigned long, paddr_to_pfn(e820.map[i].addr), 0x100ul);
        efn = paddr_to_pfn(e820.map[i].addr + e820.map[i].size - 1);
        if ( (e820.map[i].type == E820_UNUSABLE) &&
             (e820.map[i].size != 0) &&
             (sfn <= efn) )
            rc |= iomem_deny_access(dom0, sfn, efn);
    }

    BUG_ON(rc != 0);

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
