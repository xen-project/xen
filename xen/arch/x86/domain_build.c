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
#include <xen/elf.h>
#include <xen/kernel.h>
#include <xen/domain.h>
#include <xen/compile.h>
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/physdev.h>
#include <asm/shadow.h>

static long dom0_nrpages;

/*
 * dom0_mem:
 *  If +ve:
 *   * The specified amount of memory is allocated to domain 0.
 *  If -ve:
 *   * All of memory is allocated to domain 0, minus the specified amount.
 *  If not specified: 
 *   * All of memory is allocated to domain 0, minus 1/16th which is reserved
 *     for uses such as DMA buffers (the reservation is clamped to 128MB).
 */
static void parse_dom0_mem(char *s)
{
    unsigned long long bytes;
    char *t = s;
    if ( *s == '-' )
        t++;
    bytes = parse_size_and_unit(t);
    dom0_nrpages = bytes >> PAGE_SHIFT;
    if ( *s == '-' )
        dom0_nrpages = -dom0_nrpages;
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int opt_dom0_shadow = 0;
boolean_param("dom0_shadow", opt_dom0_shadow);

static unsigned int opt_dom0_translate = 0;
boolean_param("dom0_translate", opt_dom0_translate);

static char opt_dom0_ioports_disable[200] = "";
string_param("dom0_ioports_disable", opt_dom0_ioports_disable);

#if defined(__i386__)
/* No ring-3 access in initial leaf page tables. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT)
#elif defined(__x86_64__)
/* Allow ring-3 access in long mode as guest cannot use ring 1. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#endif

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static struct pfn_info *alloc_chunk(struct domain *d, unsigned long max_pages)
{
    struct pfn_info *page;
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

static void process_dom0_ioports_disable()
{
    unsigned long io_from, io_to, io_nr;
    char *t, *u, *s = opt_dom0_ioports_disable;

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

        io_nr = io_to - io_from + 1;
        physdev_modify_ioport_access_range(dom0, 0, io_from, io_nr);
    }
}

int construct_dom0(struct domain *d,
                   unsigned long _image_start, unsigned long image_len, 
                   unsigned long _initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    int i, rc, dom0_pae, xen_pae, order;
    unsigned long pfn, mfn;
    unsigned long nr_pages;
    unsigned long nr_pt_pages;
    unsigned long alloc_spfn;
    unsigned long alloc_epfn;
    unsigned long count;
    struct pfn_info *page = NULL;
    start_info_t *si;
    struct vcpu *v = d->vcpu[0];
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
    struct domain_setup_info dsi;
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
    unsigned long v_end;

    /* Machine address of next candidate page-table page. */
    unsigned long mpt_alloc;

    extern void physdev_init_dom0(struct domain *);
    extern void translate_l2pgtable(
        struct domain *d, l1_pgentry_t *p2m, unsigned long l2mfn);

    /* Sanity! */
    BUG_ON(d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

    memset(&dsi, 0, sizeof(struct domain_setup_info));
    dsi.image_addr = (unsigned long)image_start;
    dsi.image_len  = image_len;

    printk("*** LOADING DOMAIN 0 ***\n");

    d->max_pages = ~0U;

    /*
     * If domain 0 allocation isn't specified, reserve 1/16th of available
     * memory for things like DMA buffers. This reservation is clamped to 
     * a maximum of 128MB.
     */
    if ( dom0_nrpages == 0 )
    {
        dom0_nrpages = avail_domheap_pages() +
            ((initrd_len + PAGE_SIZE - 1) >> PAGE_SHIFT) +
            ((image_len  + PAGE_SIZE - 1) >> PAGE_SHIFT);
        dom0_nrpages = min(dom0_nrpages / 16, 128L << (20 - PAGE_SHIFT));
        dom0_nrpages = -dom0_nrpages;
    }

    /* Negative memory specification means "all memory - specified amount". */
    if ( dom0_nrpages < 0 )
        nr_pages = avail_domheap_pages() +
            ((initrd_len + PAGE_SIZE - 1) >> PAGE_SHIFT) +
            ((image_len  + PAGE_SIZE - 1) >> PAGE_SHIFT) +
            dom0_nrpages;
    else
        nr_pages = dom0_nrpages;

    if ( (rc = parseelfimage(&dsi)) != 0 )
        return rc;

    if ( dsi.xen_section_string == NULL )
    {
        printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
        return -EINVAL;
    }

    dom0_pae = !!strstr(dsi.xen_section_string, "PAE=yes");
    xen_pae  = (CONFIG_PAGING_LEVELS == 3);
    if ( dom0_pae != xen_pae )
    {
        printk("PAE mode mismatch between Xen and DOM0 (xen=%s, dom0=%s)\n",
               xen_pae ? "yes" : "no", dom0_pae ? "yes" : "no");
        return -EINVAL;
    }
    if (strstr(dsi.xen_section_string, "SHADOW=translate"))
        opt_dom0_translate = 1;

    /* Align load address to 4MB boundary. */
    dsi.v_start &= ~((1UL<<22)-1);

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    vinitrd_start    = round_pgup(dsi.v_end);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
    vstartinfo_start = round_pgup(vphysmap_end);
    vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
    vpt_start        = vstartinfo_end;
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstack_start     = vpt_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1);
        if ( (v_end - vstack_end) < (512UL << 10) )
            v_end += 1UL << 22; /* Add extra 4MB to get >= 512kB padding. */
#if defined(__i386__) && !defined(CONFIG_X86_PAE)
        if ( (((v_end - dsi.v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
#elif defined(__i386__) && defined(CONFIG_X86_PAE)
        /* 5 pages: 1x 3rd + 4x 2nd level */
        if ( (((v_end - dsi.v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 5) <= nr_pt_pages )
            break;
#elif defined(__x86_64__)
#define NR(_l,_h,_s) \
    (((((_h) + ((1UL<<(_s))-1)) & ~((1UL<<(_s))-1)) - \
       ((_l) & ~((1UL<<(_s))-1))) >> (_s))
        if ( (1 + /* # L4 */
              NR(dsi.v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              NR(dsi.v_start, v_end, L3_PAGETABLE_SHIFT) + /* # L2 */
              NR(dsi.v_start, v_end, L2_PAGETABLE_SHIFT))  /* # L1 */
             <= nr_pt_pages )
            break;
#endif
    }

    order = get_order_from_bytes(v_end - dsi.v_start);
    if ( (1UL << order) > nr_pages )
        panic("Domain 0 allocation is too small for kernel image.\n");

    /* Allocate from DMA pool: PAE L3 table must be below 4GB boundary. */
    if ( (page = alloc_domheap_pages(d, order, ALLOC_DOM_DMA)) == NULL )
        panic("Not enough RAM for domain 0 allocation.\n");
    alloc_spfn = page_to_pfn(page);
    alloc_epfn = alloc_spfn + d->tot_pages;

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Dom0 alloc.:   %"PRIphysaddr"->%"PRIphysaddr,
           pfn_to_phys(alloc_spfn), pfn_to_phys(alloc_epfn));
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
           _p(dsi.v_kernstart), _p(dsi.v_kernend), 
           _p(vinitrd_start), _p(vinitrd_end),
           _p(vphysmap_start), _p(vphysmap_end),
           _p(vstartinfo_start), _p(vstartinfo_end),
           _p(vpt_start), _p(vpt_end),
           _p(vstack_start), _p(vstack_end),
           _p(dsi.v_start), _p(v_end));
    printk(" ENTRY ADDRESS: %p\n", _p(dsi.v_kernentry));

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        return -ENOMEM;
    }

    mpt_alloc = (vpt_start - dsi.v_start) + 
        (unsigned long)pfn_to_phys(alloc_spfn);

    /*
     * We're basically forcing default RPLs to 1, so that our "what privilege
     * level are we returning to?" logic works.
     */
    v->arch.guest_context.kernel_ss = FLAT_KERNEL_SS;
    for ( i = 0; i < 256; i++ ) 
        v->arch.guest_context.trap_ctxt[i].cs = FLAT_KERNEL_CS;

#if defined(__i386__)

    v->arch.guest_context.failsafe_callback_cs = FLAT_KERNEL_CS;
    v->arch.guest_context.event_callback_cs    = FLAT_KERNEL_CS;

    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( dsi.v_start < (1UL<<30) )
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
    {
        unsigned long va;
        for (va = PERDOMAIN_VIRT_START; va < PERDOMAIN_VIRT_END;
             va += (1 << L2_PAGETABLE_SHIFT)) {
            l2tab[va >> L2_PAGETABLE_SHIFT] =
                l2e_from_paddr(__pa(d->arch.mm_perdomain_pt) +
                               (va-PERDOMAIN_VIRT_START),
                               __PAGE_HYPERVISOR);
        }
    }
    v->arch.guest_table = mk_pagetable((unsigned long)l3start);
#else
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    memcpy(l2tab, &idle_pg_table[0], PAGE_SIZE);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        l2e_from_paddr((unsigned long)l2start, __PAGE_HYPERVISOR);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        l2e_from_paddr(__pa(d->arch.mm_perdomain_pt), __PAGE_HYPERVISOR);
    v->arch.guest_table = mk_pagetable((unsigned long)l2start);
#endif

    l2tab += l2_linear_offset(dsi.v_start);
    mfn = alloc_spfn;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc; 
            mpt_alloc += PAGE_SIZE;
            *l2tab = l2e_from_paddr((unsigned long)l1start, L2_PROT);
            l2tab++;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
        }
        *l1tab = l1e_from_pfn(mfn, L1_PROT);
        l1tab++;
        
        page = pfn_to_page(mfn);
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
        page = pfn_to_page(l1e_get_pfn(*l1tab));
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
            page->u.inuse.type_info |=
                (count-1) << PGT_va_shift;
            get_page(page, d); /* an extra ref because of readable mapping */
            break;
        default:
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l1_page_table;
            page->u.inuse.type_info |= 
                ((dsi.v_start>>L2_PAGETABLE_SHIFT)+(count-5))<<PGT_va_shift;
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
            page->u.inuse.type_info |= 
                ((dsi.v_start>>L2_PAGETABLE_SHIFT)+(count-1))<<PGT_va_shift;

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
    if ( (dsi.v_start < HYPERVISOR_VIRT_END) &&
         (v_end > HYPERVISOR_VIRT_START) )
    {
        printk("DOM0 image overlaps with Xen private area.\n");
        return -EINVAL;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l4_page_table;
    l4start = l4tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
    memcpy(l4tab, &idle_pg_table[0], PAGE_SIZE);
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_from_paddr(__pa(l4start), __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_from_paddr(__pa(d->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    v->arch.guest_table = mk_pagetable(__pa(l4start));

    l4tab += l4_table_offset(dsi.v_start);
    mfn = alloc_spfn;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l1_page_table;
            l1start = l1tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
            if ( !((unsigned long)l2tab & (PAGE_SIZE-1)) )
            {
                phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l2_page_table;
                l2start = l2tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                clear_page(l2tab);
                if ( count == 0 )
                    l2tab += l2_table_offset(dsi.v_start);
                if ( !((unsigned long)l3tab & (PAGE_SIZE-1)) )
                {
                    phys_to_page(mpt_alloc)->u.inuse.type_info =
                        PGT_l3_page_table;
                    l3start = l3tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                    clear_page(l3tab);
                    if ( count == 0 )
                        l3tab += l3_table_offset(dsi.v_start);
                    *l4tab = l4e_from_paddr(__pa(l3start), L4_PROT);
                    l4tab++;
                }
                *l3tab = l3e_from_paddr(__pa(l2start), L3_PROT);
                l3tab++;
            }
            *l2tab = l2e_from_paddr(__pa(l1start), L2_PROT);
            l2tab++;
        }
        *l1tab = l1e_from_pfn(mfn, L1_PROT);
        l1tab++;

        page = pfn_to_page(mfn);
        if ( (page->u.inuse.type_info == 0) &&
             !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
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
        page = pfn_to_page(l1e_get_pfn(*l1tab));

        /* Read-only mapping + PGC_allocated + page-table page. */
        page->count_info         = PGC_allocated | 3;
        page->u.inuse.type_info |= PGT_validated | 1;

        /* Top-level p.t. is pinned. */
        if ( (page->u.inuse.type_info & PGT_type_mask) == PGT_l4_page_table )
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
        d->shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

    for ( i = 1; i < num_online_cpus(); i++ )
        (void)alloc_vcpu(d, i, i);

    /* Set up monitor table */
    update_pagetables(v);

    /* Install the new page tables. */
    local_irq_disable();
    write_ptbase(v);

    /* Copy the OS image and free temporary buffer. */
    (void)loadelfimage(&dsi);

    init_domheap_pages(
        _image_start, (_image_start+image_len+PAGE_SIZE-1) & PAGE_MASK);

    /* Copy the initial ramdisk and free temporary buffer. */
    if ( initrd_len != 0 )
    {
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);
        init_domheap_pages(
            _initrd_start, (_initrd_start+initrd_len+PAGE_SIZE-1) & PAGE_MASK);
    }

    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    memset(si, 0, PAGE_SIZE);
    si->nr_pages = nr_pages;

    si->shared_info = virt_to_phys(d->shared_info);
    if ( opt_dom0_translate )
    {
        si->shared_info  = max_page << PAGE_SHIFT;
        set_pfn_from_mfn(virt_to_phys(d->shared_info) >> PAGE_SHIFT, max_page);
    }

    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->pt_base      = vpt_start;
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;
    sprintf(si->magic, "xen-%i.%i-x86_%d%s",
            XEN_VERSION, XEN_SUBVERSION, BITS_PER_LONG, xen_pae ? "p" : "");

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < d->tot_pages; pfn++ )
    {
        mfn = pfn + alloc_spfn;
#ifndef NDEBUG
#define REVERSE_START ((v_end - dsi.v_start) >> PAGE_SHIFT)
        if ( !opt_dom0_translate && (pfn > REVERSE_START) )
            mfn = alloc_epfn - (pfn - REVERSE_START);
#endif
        ((unsigned long *)vphysmap_start)[pfn] = mfn;
        set_pfn_from_mfn(mfn, pfn);
    }
    while ( pfn < nr_pages )
    {
        if ( (page = alloc_chunk(d, nr_pages - d->tot_pages)) == NULL )
            panic("Not enough RAM for DOM0 reservation.\n");
        while ( pfn < d->tot_pages )
        {
            mfn = page_to_pfn(page);
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - (alloc_epfn - alloc_spfn)))
#endif
            ((unsigned long *)vphysmap_start)[pfn] = mfn;
            set_pfn_from_mfn(mfn, pfn);
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
        strncpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line)-1);

    /* Reinstate the caller's page tables. */
    write_ptbase(current);
    local_irq_enable();

#if defined(__i386__)
    /* Destroy low mappings - they were only for our convenience. */
    zap_low_mappings(l2start);
    zap_low_mappings(idle_pg_table_l2);
#endif
    
    /* DOM0 gets access to everything. */
    physdev_init_dom0(d);

    init_domain_time(d);

    set_bit(_VCPUF_initialised, &v->vcpu_flags);

    new_thread(v, dsi.v_kernentry, vstack_end, vstartinfo_start);

    if ( opt_dom0_shadow || opt_dom0_translate )
    {
        printk("dom0: shadow enable\n");
        shadow_mode_enable(d, (opt_dom0_translate
                               ? SHM_enable | SHM_refcounts | SHM_translate
                               : SHM_enable));
        if ( opt_dom0_translate )
        {
            printk("dom0: shadow translate\n");
#if defined(__i386__) && defined(CONFIG_X86_PAE)
            printk("FIXME: PAE code needed here: %s:%d (%s)\n",
                   __FILE__, __LINE__, __FUNCTION__);
            for ( ; ; )
                __asm__ __volatile__ ( "hlt" );
#else
            /* Hmm, what does this?
               Looks like isn't portable across 32/64 bit and pae/non-pae ...
               -- kraxel */

            /* mafetter: This code is mostly a hack in order to be able to
             * test with dom0's which are running with shadow translate.
             * I expect we'll rip this out once we have a stable set of
             * domU clients which use the various shadow modes, but it's
             * useful to leave this here for now...
             */

            // map this domain's p2m table into current page table,
            // so that we can easily access it.
            //
            ASSERT( root_get_intpte(idle_pg_table[1]) == 0 );
            ASSERT( pagetable_get_paddr(d->arch.phys_table) );
            idle_pg_table[1] = root_from_paddr(
                pagetable_get_paddr(d->arch.phys_table), __PAGE_HYPERVISOR);
            translate_l2pgtable(d, (l1_pgentry_t *)(1u << L2_PAGETABLE_SHIFT),
                                pagetable_get_pfn(v->arch.guest_table));
            idle_pg_table[1] = root_empty();
            local_flush_tlb();
#endif
        }

        update_pagetables(v); /* XXX SMP */
        printk("dom0: shadow setup done\n");
    }

    /*
     * Modify I/O port access permissions.
     */
    /* Master Interrupt Controller (PIC). */
    physdev_modify_ioport_access_range(dom0, 0, 0x20, 2);
    /* Slave Interrupt Controller (PIC). */
    physdev_modify_ioport_access_range(dom0, 0, 0xA0, 2);
    /* Interval Timer (PIT). */
    physdev_modify_ioport_access_range(dom0, 0, 0x40, 4);
    /* PIT Channel 2 / PC Speaker Control. */
    physdev_modify_ioport_access_range(dom0, 0, 0x61, 1);
    /* Command-line passed i/o ranges */
    process_dom0_ioports_disable();

    return 0;
}

int elf_sanity_check(Elf_Ehdr *ehdr)
{
    if ( !IS_ELF(*ehdr) ||
#if defined(__i386__)
         (ehdr->e_ident[EI_CLASS] != ELFCLASS32) ||
         (ehdr->e_machine != EM_386) ||
#elif defined(__x86_64__)
         (ehdr->e_ident[EI_CLASS] != ELFCLASS64) ||
         (ehdr->e_machine != EM_X86_64) ||
#endif
         (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) ||
         (ehdr->e_type != ET_EXEC) )
    {
        printk("DOM0 image is not a Xen-compatible Elf image.\n");
        return 0;
    }

    return 1;
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
