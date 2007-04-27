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
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/paging.h>

#include <public/version.h>
#include <public/libelf.h>

extern unsigned long initial_images_nrpages(void);
extern void discard_initial_images(void);

static long dom0_nrpages, dom0_min_nrpages, dom0_max_nrpages = LONG_MAX;

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
static long parse_amt(const char *s, const char **ps)
{
    long pages = parse_size_and_unit((*s == '-') ? s+1 : s, ps) >> PAGE_SHIFT;
    return (*s == '-') ? -pages : pages;
}
static void parse_dom0_mem(const char *s)
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

static unsigned int opt_dom0_max_vcpus;
integer_param("dom0_max_vcpus", opt_dom0_max_vcpus);

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

static struct page_info *alloc_chunk(struct domain *d, unsigned long max_pages)
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

static unsigned long compute_dom0_nr_pages(void)
{
    unsigned long avail = avail_domheap_pages() + initial_images_nrpages();

    /*
     * If domain 0 allocation isn't specified, reserve 1/16th of available
     * memory for things like DMA buffers. This reservation is clamped to 
     * a maximum of 128MB.
     */
    if ( dom0_nrpages == 0 )
    {
        dom0_nrpages = avail;
        dom0_nrpages = min(dom0_nrpages / 16, 128L << (20 - PAGE_SHIFT));
        dom0_nrpages = -dom0_nrpages;
    }

    /* Negative memory specification means "all memory - specified amount". */
    if ( dom0_nrpages     < 0 ) dom0_nrpages     += avail;
    if ( dom0_min_nrpages < 0 ) dom0_min_nrpages += avail;
    if ( dom0_max_nrpages < 0 ) dom0_max_nrpages += avail;

    /* Clamp dom0 memory according to min/max limits and available memory. */
    dom0_nrpages = max(dom0_nrpages, dom0_min_nrpages);
    dom0_nrpages = min(dom0_nrpages, dom0_max_nrpages);
    dom0_nrpages = min(dom0_nrpages, (long)avail);

    return dom0_nrpages;
}

static void process_dom0_ioports_disable(void)
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

int construct_dom0(struct domain *d,
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
    char *image_start  = (char *)_image_start;  /* use lowmem mappings */
    char *initrd_start = (char *)_initrd_start; /* use lowmem mappings */
#elif defined(__x86_64__)
    char *image_start  = __va(_image_start);
    char *initrd_start = __va(_initrd_start);
#endif
#if CONFIG_PAGING_LEVELS >= 4
    l4_pgentry_t *l4tab = NULL, *l4start = NULL;
#endif
#if CONFIG_PAGING_LEVELS >= 3
    l3_pgentry_t *l3tab = NULL, *l3start = NULL;
#endif
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

    /* Features supported. */
    uint32_t dom0_features_supported[XENFEAT_NR_SUBMAPS] = { 0 };
    uint32_t dom0_features_required[XENFEAT_NR_SUBMAPS] = { 0 };

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(v->is_initialised);

    printk("*** LOADING DOMAIN 0 ***\n");

    d->max_pages = ~0U;

    nr_pages = compute_dom0_nr_pages();

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
    case 2: /* x86_32 */
        if (parms.pae == PAEKERN_bimodal)
            parms.pae = PAEKERN_no;
        printk(" Xen  kernel: 32-bit, lsb\n");
        if (elf_32bit(&elf) && !parms.pae && machine == EM_386)
            compatible = 1;
        break;
    case 3: /* x86_32p */
        if (parms.pae == PAEKERN_bimodal)
            parms.pae = PAEKERN_extended_cr3;
        printk(" Xen  kernel: 32-bit, PAE, lsb\n");
        if (elf_32bit(&elf) && parms.pae && machine == EM_386)
            compatible = 1;
        break;
    case 4: /* x86_64 */
#ifndef CONFIG_COMPAT
        printk(" Xen  kernel: 64-bit, lsb\n");
#else
        printk(" Xen  kernel: 64-bit, lsb, compat32\n");
        if (elf_32bit(&elf) && parms.pae == PAEKERN_bimodal)
            parms.pae = PAEKERN_extended_cr3;
        if (elf_32bit(&elf) && parms.pae && machine == EM_386)
        {
            compat32 = 1;
            compatible = 1;
        }
#endif
        if (elf_64bit(&elf) && machine == EM_X86_64)
            compatible = 1;
        break;
    }
    printk(" Dom0 kernel: %s%s, %s, paddr 0x%" PRIx64 " -> 0x%" PRIx64 "\n",
           elf_64bit(&elf) ? "64-bit" : "32-bit",
           parms.pae       ? ", PAE"  : "",
           elf_msb(&elf)   ? "msb"    : "lsb",
           elf.pstart, elf.pend);

    if ( !compatible )
    {
        printk("Mismatch between Xen and DOM0 kernel\n");
        return -EINVAL;
    }

#ifdef CONFIG_COMPAT
    if ( compat32 )
    {
        l1_pgentry_t gdt_l1e;

        d->arch.is_32bit_pv = d->arch.has_32bit_shinfo = 1;
        v->vcpu_info = (void *)&d->shared_info->compat.vcpu_info[0];

        if ( nr_pages != (unsigned int)nr_pages )
            nr_pages = UINT_MAX;

        /*
         * Map compatibility Xen segments into every VCPU's GDT. See
         * arch_domain_create() for further comments.
         */
        gdt_l1e = l1e_from_page(virt_to_page(compat_gdt_table),
                                PAGE_HYPERVISOR);
        for ( i = 0; i < MAX_VIRT_CPUS; i++ )
            d->arch.mm_perdomain_pt[((i << GDT_LDT_VCPU_SHIFT) +
                                     FIRST_RESERVED_GDT_PAGE)] = gdt_l1e;
        local_flush_tlb_one(GDT_LDT_VIRT_START + FIRST_RESERVED_GDT_BYTE);
    }
#endif
    if ( parms.pae == PAEKERN_extended_cr3 )
            set_bit(VMASST_TYPE_pae_extended_cr3, &d->vm_assist);

    if ( UNSET_ADDR != parms.virt_hv_start_low && elf_32bit(&elf) )
    {
#if CONFIG_PAGING_LEVELS < 4
        unsigned long mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
#else
        unsigned long mask = is_pv_32bit_domain(d)
                             ? (1UL << L2_PAGETABLE_SHIFT) - 1
                             : (1UL << L4_PAGETABLE_SHIFT) - 1;
#endif

        value = (parms.virt_hv_start_low + mask) & ~mask;
#ifdef CONFIG_COMPAT
        HYPERVISOR_COMPAT_VIRT_START(d) =
            max_t(unsigned int, m2p_compat_vstart, value);
        d->arch.physaddr_bitsize = !is_pv_32on64_domain(d) ? 64 :
            fls((1UL << 32) - HYPERVISOR_COMPAT_VIRT_START(d)) - 1
            + (PAGE_SIZE - 2);
        if ( value > (!is_pv_32on64_domain(d) ?
                      HYPERVISOR_VIRT_START :
                      __HYPERVISOR_COMPAT_VIRT_START) )
#else
        if ( value > HYPERVISOR_VIRT_START )
#endif
            panic("Domain 0 expects too high a hypervisor start address.\n");
    }

    if ( parms.f_required[0] /* Huh? -- kraxel */ )
            panic("Domain 0 requires an unsupported hypervisor feature.\n");

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
#if defined(__i386__) && !defined(CONFIG_X86_PAE)
        if ( (((v_end - v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >>
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
#elif defined(__i386__) && defined(CONFIG_X86_PAE)
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
    page = alloc_domheap_pages(d, order,
                               MEMF_bits(30 + (v_start >> 31)));
#else
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

    if ( ((v_end - v_start)>>PAGE_SHIFT) > nr_pages )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-v_start)>>20, nr_pages>>(20-PAGE_SHIFT));
        return -ENOMEM;
    }

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
#if CONFIG_PAGING_LEVELS == 3
    l3start = l3tab = (l3_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += 4*PAGE_SIZE;
    memcpy(l2tab, idle_pg_table_l2, 4*PAGE_SIZE);
    for (i = 0; i < 4; i++) {
        l3tab[i] = l3e_from_paddr((u32)l2tab + i*PAGE_SIZE, L3_PROT);
        l2tab[(LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT)+i] =
            l2e_from_paddr((u32)l2tab + i*PAGE_SIZE, __PAGE_HYPERVISOR);
    }
    v->arch.guest_table = pagetable_from_paddr((unsigned long)l3start);
#else
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    memcpy(l2tab, idle_pg_table, PAGE_SIZE);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        l2e_from_paddr((unsigned long)l2start, __PAGE_HYPERVISOR);
    v->arch.guest_table = pagetable_from_paddr((unsigned long)l2start);
#endif

    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        l2tab[l2_linear_offset(PERDOMAIN_VIRT_START) + i] =
            l2e_from_page(virt_to_page(d->arch.mm_perdomain_pt) + i,
                          __PAGE_HYPERVISOR);

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

#if CONFIG_PAGING_LEVELS == 3
        switch (count) {
        case 0:
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l3_page_table;
            get_page(page, d); /* an extra ref because of readable mapping */

            /* Get another ref to L3 page so that it can be pinned. */
            if ( !get_page_and_type(page, d, PGT_l3_page_table) )
                BUG();
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
#else
        if ( count == 0 )
        {
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l2_page_table;

            /*
             * No longer writable: decrement the type_count.
             * Installed as CR3: increment both the ref_count and type_count.
             * Net: just increment the ref_count.
             */
            get_page(page, d); /* an extra ref because of readable mapping */

            /* Get another ref to L2 page so that it can be pinned. */
            if ( !get_page_and_type(page, d, PGT_l2_page_table) )
                BUG();
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
        }
        else
        {
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l1_page_table;

            /*
             * No longer writable: decrement the type_count.
             * This is an L1 page, installed in a validated L2 page:
             * increment both the ref_count and type_count.
             * Net: just increment the ref_count.
             */
            get_page(page, d); /* an extra ref because of readable mapping */
        }
#endif
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
        page = alloc_domheap_page(NULL);
        if ( !page )
            panic("Not enough RAM for domain 0 PML4.\n");
        l4start = l4tab = page_to_virt(page);
    }
    memcpy(l4tab, idle_pg_table, PAGE_SIZE);
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_paddr(__pa(l4start), __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(d->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    v->arch.guest_table = pagetable_from_paddr(__pa(l4start));
    if ( is_pv_32on64_domain(d) )
    {
        v->arch.guest_table_user = v->arch.guest_table;
        if ( setup_arg_xlat_area(v, l4start) < 0 )
            panic("Not enough RAM for domain 0 hypercall argument translation.\n");
    }

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

#ifdef CONFIG_COMPAT
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
#endif

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
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info(d, vcpu_info[i].evtchn_upcall_mask) = 1;

    if ( opt_dom0_max_vcpus == 0 )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > num_online_cpus() )
        opt_dom0_max_vcpus = num_online_cpus();
    if ( opt_dom0_max_vcpus > MAX_VIRT_CPUS )
        opt_dom0_max_vcpus = MAX_VIRT_CPUS;
    if ( opt_dom0_max_vcpus > BITS_PER_GUEST_LONG(d) )
        opt_dom0_max_vcpus = BITS_PER_GUEST_LONG(d);
    printk("Dom0 has maximum %u VCPUs\n", opt_dom0_max_vcpus);

    for ( i = 1; i < opt_dom0_max_vcpus; i++ )
        (void)alloc_vcpu(d, i, i);

    /* Set up CR3 value for write_ptbase */
    if ( paging_mode_enabled(v->domain) )
        paging_update_paging_modes(v);
    else
        update_cr3(v);

    /* Install the new page tables. */
    local_irq_disable();
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
            local_irq_enable();
            printk("Invalid HYPERCALL_PAGE field in ELF notes.\n");
            return -1;
        }
        hypercall_page_initialise(d, (void *)(unsigned long)parms.virt_hypercall);
    }

    /* Copy the initial ramdisk. */
    if ( initrd_len != 0 )
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);

    /* Free temporary buffers. */
    discard_initial_images();

    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    memset(si, 0, PAGE_SIZE);
    si->nr_pages = nr_pages;

    si->shared_info = virt_to_maddr(d->shared_info);

    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->pt_base      = vpt_start + 2 * PAGE_SIZE * !!is_pv_32on64_domain(d);
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;
    snprintf(si->magic, sizeof(si->magic), "xen-%i.%i-x86_%d%s",
            xen_major_version(), xen_minor_version(),
            elf_64bit(&elf) ? 64 : 32,
            parms.pae ? "p" : "");

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < d->tot_pages; pfn++ )
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
    }
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
        }
    }

    if ( initrd_len != 0 )
    {
        si->mod_start = vinitrd_start;
        si->mod_len   = initrd_len;
        printk("Initrd len 0x%lx, start at 0x%lx\n",
               si->mod_len, si->mod_start);
    }

    memset(si->cmd_line, 0, sizeof(si->cmd_line));
    if ( cmdline != NULL )
        strlcpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line));

    if ( fill_console_start_info((void *)(si + 1)) )
    {
        si->console.dom0.info_off  = sizeof(struct start_info);
        si->console.dom0.info_size = sizeof(struct dom0_vga_console_info);
    }

#ifdef CONFIG_COMPAT
    if ( is_pv_32on64_domain(d) )
        xlat_start_info(si, XLAT_start_info_console_dom0);
#endif

    /* Reinstate the caller's page tables. */
    write_ptbase(current);
    local_irq_enable();

#if defined(__i386__)
    /* Destroy low mappings - they were only for our convenience. */
    zap_low_mappings(l2start);
    zap_low_mappings(idle_pg_table_l2);
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
                       dom0_features_supported) )
            panic("Dom0 does not support supervisor-mode execution\n");
    }
    else
    {
        if ( test_bit(XENFEAT_supervisor_mode_kernel, dom0_features_required) )
            panic("Dom0 requires supervisor-mode execution\n");
    }

    rc = 0;

    /* DOM0 is permitted full I/O capabilities. */
    rc |= ioports_permit_access(dom0, 0, 0xFFFF);
    rc |= iomem_permit_access(dom0, 0UL, ~0UL);
    rc |= irqs_permit_access(dom0, 0, NR_IRQS-1);

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
