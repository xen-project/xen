/******************************************************************************
 * pv/dom0_build.c
 *
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/console.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/libelf.h>
#include <xen/multiboot.h>
#include <xen/paging.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/bzimage.h>
#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/page.h>
#include <asm/pv/mm.h>
#include <asm/setup.h>

/* Allow ring-3 access in long mode as guest cannot use ring 1 ... */
#define BASE_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L1_PROT (BASE_PROT|_PAGE_GUEST_KERNEL)
/* ... except for compatibility mode guests. */
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (BASE_PROT|_PAGE_DIRTY)
#define L3_PROT (BASE_PROT|_PAGE_DIRTY)
#define L4_PROT (BASE_PROT|_PAGE_DIRTY)

void __init dom0_update_physmap(struct domain *d, unsigned long pfn,
                                unsigned long mfn, unsigned long vphysmap_s)
{
    if ( !is_pv_32bit_domain(d) )
        ((unsigned long *)vphysmap_s)[pfn] = mfn;
    else
        ((unsigned int *)vphysmap_s)[pfn] = mfn;

    set_gpfn_from_mfn(mfn, pfn);
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
        page = mfn_to_page(l1e_get_mfn(*pl1e));

        /* Read-only mapping + PGC_allocated + page-table page. */
        page->count_info         = PGC_allocated | 3;
        page->u.inuse.type_info |= PGT_validated | 1;

        /* Top-level p.t. is pinned. */
        if ( (page->u.inuse.type_info & PGT_type_mask) ==
             (!is_pv_32bit_domain(d) ?
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
    l4_pgentry_t *pl4e, *l4start = map_domain_page(_mfn(pgtbl_pfn));
    l3_pgentry_t *pl3e = NULL;
    l2_pgentry_t *pl2e = NULL;
    l1_pgentry_t *pl1e = NULL;

    if ( v_start <= vphysmap_end && vphysmap_start <= v_end )
        panic("DOM0 P->M table overlaps initial mapping\n");

    while ( vphysmap_start < vphysmap_end )
    {
        if ( d->tot_pages + ((round_pgup(vphysmap_end) - vphysmap_start)
                             >> PAGE_SHIFT) + 3 > nr_pages )
            panic("Dom0 allocation too small for initial P->M table\n");

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
            page = alloc_domheap_page(d, MEMF_no_scrub);
            if ( !page )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l3_page_table | PGT_validated | 1;
            pl3e = __map_domain_page(page);
            clear_page(pl3e);
            *pl4e = l4e_from_page(page, L4_PROT);
        } else
            pl3e = map_l3t_from_l4e(*pl4e);

        pl3e += l3_table_offset(vphysmap_start);
        if ( !l3e_get_intpte(*pl3e) )
        {
            /*
             * 1G superpages aren't supported by the shadow code.  Avoid using
             * them if we are liable to need to start shadowing dom0.  This
             * assumes that there are no circumstances where we will activate
             * logdirty mode on dom0.
             */
            if ( (!IS_ENABLED(CONFIG_SHADOW_PAGING) ||
                  !d->arch.pv.check_l1tf) && cpu_has_page1gb &&
                 !(vphysmap_start & ((1UL << L3_PAGETABLE_SHIFT) - 1)) &&
                 vphysmap_end >= vphysmap_start + (1UL << L3_PAGETABLE_SHIFT) &&
                 (page = alloc_domheap_pages(d,
                                             L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                                             MEMF_no_scrub)) != NULL )
            {
                *pl3e = l3e_from_page(page, L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                vphysmap_start += 1UL << L3_PAGETABLE_SHIFT;
                continue;
            }
            if ( (page = alloc_domheap_page(d, MEMF_no_scrub)) == NULL )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l2_page_table | PGT_validated | 1;
            pl2e = __map_domain_page(page);
            clear_page(pl2e);
            *pl3e = l3e_from_page(page, L3_PROT);
        }
        else
            pl2e = map_l2t_from_l3e(*pl3e);

        pl2e += l2_table_offset(vphysmap_start);
        if ( !l2e_get_intpte(*pl2e) )
        {
            if ( !(vphysmap_start & ((1UL << L2_PAGETABLE_SHIFT) - 1)) &&
                 vphysmap_end >= vphysmap_start + (1UL << L2_PAGETABLE_SHIFT) &&
                 (page = alloc_domheap_pages(d,
                                             L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                                             MEMF_no_scrub)) != NULL )
            {
                *pl2e = l2e_from_page(page, L1_PROT|_PAGE_DIRTY|_PAGE_PSE);
                vphysmap_start += 1UL << L2_PAGETABLE_SHIFT;
                continue;
            }
            if ( (page = alloc_domheap_page(d, MEMF_no_scrub)) == NULL )
                break;

            /* No mapping, PGC_allocated + page-table page. */
            page->count_info = PGC_allocated | 2;
            page->u.inuse.type_info = PGT_l1_page_table | PGT_validated | 1;
            pl1e = __map_domain_page(page);
            clear_page(pl1e);
            *pl2e = l2e_from_page(page, L2_PROT);
        }
        else
            pl1e = map_l1t_from_l2e(*pl2e);

        pl1e += l1_table_offset(vphysmap_start);
        BUG_ON(l1e_get_intpte(*pl1e));
        page = alloc_domheap_page(d, MEMF_no_scrub);
        if ( !page )
            break;

        *pl1e = l1e_from_page(page, L1_PROT|_PAGE_DIRTY);
        vphysmap_start += PAGE_SIZE;
        vphysmap_start &= PAGE_MASK;
    }
    if ( !page )
        panic("Not enough RAM for DOM0 P->M table\n");

    if ( pl1e )
        unmap_domain_page(pl1e);
    if ( pl2e )
        unmap_domain_page(pl2e);
    if ( pl3e )
        unmap_domain_page(pl3e);

    unmap_domain_page(l4start);
}

static struct page_info * __init alloc_chunk(struct domain *d,
                                             unsigned long max_pages)
{
    static unsigned int __initdata last_order = MAX_ORDER;
    struct page_info *page;
    unsigned int order = get_order_from_pages(max_pages), free_order;

    if ( order > last_order )
        order = last_order;
    else if ( max_pages & (max_pages - 1) )
        --order;
    while ( (page = alloc_domheap_pages(d, order, dom0_memflags |
                                                  MEMF_no_scrub)) == NULL )
        if ( order-- == 0 )
            break;
    if ( page )
        last_order = order;
    else if ( dom0_memflags )
    {
        /*
         * Allocate up to 2MB at a time: It prevents allocating very large
         * chunks from DMA pools before the >4GB pool is fully depleted.
         */
        last_order = 21 - PAGE_SHIFT;
        dom0_memflags = 0;
        return alloc_chunk(d, max_pages);
    }

    /*
     * Make a reasonable attempt at finding a smaller chunk at a higher
     * address, to avoid allocating from low memory as much as possible.
     */
    for ( free_order = order; !dom0_memflags && page && order--; )
    {
        struct page_info *pg2;

        if ( d->tot_pages + (1 << order) > d->max_pages )
            continue;
        pg2 = alloc_domheap_pages(d, order, MEMF_exact_node | MEMF_no_scrub);
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

int __init dom0_construct_pv(struct domain *d,
                             const module_t *image,
                             unsigned long image_headroom,
                             module_t *initrd,
                             char *cmdline)
{
    int i, cpu, rc, compatible, order, machine;
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
    void *image_base = bootstrap_map(image);
    unsigned long image_len = image->mod_end;
    void *image_start = image_base + image_headroom;
    unsigned long initrd_len = initrd ? initrd->mod_end : 0;
    l4_pgentry_t *l4tab = NULL, *l4start = NULL;
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
    unsigned long vxenstore_start = 0;
    unsigned long vxenstore_end = 0;
    unsigned long vconsole_start = 0;
    unsigned long vconsole_end = 0;
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_start;
    unsigned long v_end;

    /* Machine address of next candidate page-table page. */
    paddr_t mpt_alloc;

    printk(XENLOG_INFO "*** Building a PV Dom%d ***\n", d->domain_id);

    d->max_pages = ~0U;

    if ( (rc = bzimage_parse(image_base, &image_start, &image_len)) != 0 )
        return rc;

    if ( (rc = elf_init(&elf, image_start, image_len)) != 0 )
        return rc;

    if ( opt_dom0_verbose )
        elf_set_verbose(&elf);

    elf_parse_binary(&elf);
    if ( (rc = elf_xen_parse(&elf, &parms)) != 0 )
        goto out;

    /* compatibility check */
    compatible = 0;
    machine = elf_uval(&elf, elf.ehdr, e_machine);
    printk(" Xen  kernel: 64-bit, lsb, compat32\n");
    if ( elf_32bit(&elf) && parms.pae == XEN_PAE_BIMODAL )
        parms.pae = XEN_PAE_EXTCR3;
    if ( elf_32bit(&elf) && parms.pae && machine == EM_386 )
    {
        if ( unlikely(rc = switch_compat(d)) )
        {
            printk("Dom0 failed to switch to compat: %d\n", rc);
            return rc;
        }

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
        if ( !pv_shim && !test_bit(XENFEAT_dom0, parms.f_supported) )
        {
            printk("Kernel does not support Dom0 operation\n");
            rc = -EINVAL;
            goto out;
        }
    }

    nr_pages = dom0_compute_nr_pages(d, &parms, initrd_len);

    if ( parms.pae == XEN_PAE_EXTCR3 )
            set_bit(VMASST_TYPE_pae_extended_cr3, &d->vm_assist);

    if ( !pv_shim && (parms.virt_hv_start_low != UNSET_ADDR) &&
         elf_32bit(&elf) )
    {
        unsigned long mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        value = (parms.virt_hv_start_low + mask) & ~mask;
        BUG_ON(!is_pv_32bit_domain(d));
        if ( value > __HYPERVISOR_COMPAT_VIRT_START )
            panic("Domain 0 expects too high a hypervisor start address\n");
        HYPERVISOR_COMPAT_VIRT_START(d) =
            max_t(unsigned int, m2p_compat_vstart, value);
    }

    if ( (parms.p2m_base != UNSET_ADDR) && elf_32bit(&elf) )
    {
        printk(XENLOG_WARNING "P2M table base ignored\n");
        parms.p2m_base = UNSET_ADDR;
    }

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
    if ( parms.unmapped_initrd )
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
    vphysmap_end     = vphysmap_start + (nr_pages * (!is_pv_32bit_domain(d) ?
                                                     sizeof(unsigned long) :
                                                     sizeof(unsigned int)));
    if ( parms.p2m_base != UNSET_ADDR )
        vphysmap_end = vphysmap_start;
    vstartinfo_start = round_pgup(vphysmap_end);
    vstartinfo_end   = vstartinfo_start + sizeof(struct start_info);

    if ( pv_shim )
    {
        vxenstore_start  = round_pgup(vstartinfo_end);
        vxenstore_end    = vxenstore_start + PAGE_SIZE;
        vconsole_start   = vxenstore_end;
        vconsole_end     = vconsole_start + PAGE_SIZE;
        vpt_start        = vconsole_end;
    }
    else
    {
        vpt_start        = round_pgup(vstartinfo_end);
        vstartinfo_end  += sizeof(struct dom0_vga_console_info);
    }

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
        if ( (!is_pv_32bit_domain(d) + /* # L4 */
              NR(v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              (!is_pv_32bit_domain(d) ?
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
        panic("Domain 0 allocation is too small for kernel image\n");

    if ( parms.p2m_base != UNSET_ADDR )
    {
        vphysmap_start = parms.p2m_base;
        vphysmap_end   = vphysmap_start + nr_pages * sizeof(unsigned long);
    }
    page = alloc_domheap_pages(d, order, MEMF_no_scrub);
    if ( page == NULL )
        panic("Not enough RAM for domain 0 allocation\n");
    alloc_spfn = mfn_x(page_to_mfn(page));
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
            page = alloc_domheap_pages(d, order, MEMF_no_scrub);
            if ( !page )
                panic("Not enough RAM for domain 0 initrd\n");
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
            initrd->mod_start = initrd_mfn = mfn_x(page_to_mfn(page));
        }
        else
        {
            while ( count-- )
                if ( assign_pages(d, mfn_to_page(_mfn(mfn++)), 0, 0) )
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
           " Xenstore ring: %p->%p\n"
           " Console ring:  %p->%p\n"
           " Page tables:   %p->%p\n"
           " Boot stack:    %p->%p\n"
           " TOTAL:         %p->%p\n",
           _p(vkern_start), _p(vkern_end),
           _p(vinitrd_start), _p(vinitrd_end),
           _p(vphysmap_start), _p(vphysmap_end),
           _p(vstartinfo_start), _p(vstartinfo_end),
           _p(vxenstore_start), _p(vxenstore_end),
           _p(vconsole_start), _p(vconsole_end),
           _p(vpt_start), _p(vpt_end),
           _p(vstack_start), _p(vstack_end),
           _p(v_start), _p(v_end));
    printk(" ENTRY ADDRESS: %p\n", _p(parms.virt_entry));

    process_pending_softirqs();

    mpt_alloc = (vpt_start - v_start) + pfn_to_paddr(alloc_spfn);
    if ( vinitrd_start )
        mpt_alloc -= PAGE_ALIGN(initrd_len);

    /* Overlap with Xen protected area? */
    if ( !is_pv_32bit_domain(d) ?
         ((v_start < HYPERVISOR_VIRT_END) &&
          (v_end > HYPERVISOR_VIRT_START)) :
         (v_end > HYPERVISOR_COMPAT_VIRT_START(d)) )
    {
        printk("DOM0 image overlaps with Xen private area.\n");
        rc = -EINVAL;
        goto out;
    }

    if ( is_pv_32bit_domain(d) )
    {
        v->arch.pv.failsafe_callback_cs = FLAT_COMPAT_KERNEL_CS;
        v->arch.pv.event_callback_cs    = FLAT_COMPAT_KERNEL_CS;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    if ( !is_pv_32bit_domain(d) )
    {
        maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l4_page_table;
        l4start = l4tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
        clear_page(l4tab);
        init_xen_l4_slots(l4tab, _mfn(virt_to_mfn(l4start)),
                          d, INVALID_MFN, true);
        v->arch.guest_table = pagetable_from_paddr(__pa(l4start));
    }
    else
    {
        /* Monitor table already created by switch_compat(). */
        l4start = l4tab = __va(pagetable_get_paddr(v->arch.guest_table));
        /* See public/xen.h on why the following is needed. */
        maddr_to_page(mpt_alloc)->u.inuse.type_info = PGT_l3_page_table;
        l3start = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
    }

    l4tab += l4_table_offset(v_start);
    pfn = alloc_spfn;
    for ( count = 0; count < ((v_end-v_start) >> PAGE_SHIFT); count++ )
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
        *l1tab = l1e_from_pfn(mfn, (!is_pv_32bit_domain(d) ?
                                    L1_PROT : COMPAT_L1_PROT));
        l1tab++;

        page = mfn_to_page(_mfn(mfn));
        if ( !page->u.inuse.type_info &&
             !get_page_and_type(page, d, PGT_writable_page) )
            BUG();
    }

    if ( is_pv_32bit_domain(d) )
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

        init_xen_pae_l2_slots(l3e_to_l2e(l3start[3]), d);
    }

    /* Pages that are part of page tables must be read only. */
    mark_pv_pt_pages_rdonly(d, l4start, vpt_start, nr_pt_pages);

    /* Mask all upcalls... */
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        shared_info(d, vcpu_info[i].evtchn_upcall_mask) = 1;

    printk("Dom%u has maximum %u VCPUs\n", d->domain_id, d->max_vcpus);

    cpu = v->processor;
    for ( i = 1; i < d->max_vcpus; i++ )
    {
        const struct vcpu *p = dom0_setup_vcpu(d, i, cpu);

        if ( p )
            cpu = p->processor;
    }

    domain_update_node_affinity(d);
    d->arch.paging.mode = 0;

    /* Set up CR3 value for write_ptbase */
    if ( paging_mode_enabled(d) )
        paging_update_paging_modes(v);
    else
        update_cr3(v);

    /* We run on dom0's page tables for the final part of the build process. */
    switch_cr3_cr4(cr3_pa(v->arch.cr3), read_cr4());
    mapcache_override_current(v);

    /* Copy the OS image and free temporary buffer. */
    elf.dest_base = (void*)vkern_start;
    elf.dest_size = vkern_end - vkern_start;
    elf_set_vcpu(&elf, v);
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
            switch_cr3_cr4(current->arch.cr3, read_cr4());
            printk("Invalid HYPERCALL_PAGE field in ELF notes.\n");
            rc = -EINVAL;
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

    if ( !pv_shim )
        si->flags    = SIF_PRIVILEGED | SIF_INITDOMAIN;
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
    if ( parms.p2m_base != UNSET_ADDR )
    {
        pfn = pagetable_get_pfn(v->arch.guest_table);
        setup_pv_physmap(d, pfn, v_start, v_end, vphysmap_start, vphysmap_end,
                         nr_pages);
    }

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
        if ( !(pfn & 0xfffff) )
            process_pending_softirqs();
    }
    si->first_p2m_pfn = pfn;
    si->nr_p2m_frames = d->tot_pages - count;
    page_list_for_each ( page, &d->page_list )
    {
        mfn = mfn_x(page_to_mfn(page));
        BUG_ON(SHARED_M2P(get_gpfn_from_mfn(mfn)));
        if ( get_gpfn_from_mfn(mfn) >= count )
        {
            BUG_ON(is_pv_32bit_domain(d));
            if ( !page->u.inuse.type_info &&
                 !get_page_and_type(page, d, PGT_writable_page) )
                BUG();

            dom0_update_physmap(d, pfn, mfn, vphysmap_start);
            ++pfn;
            if ( !(pfn & 0xfffff) )
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
            panic("Not enough RAM for DOM0 reservation\n");
        while ( pfn < d->tot_pages )
        {
            mfn = mfn_x(page_to_mfn(page));
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - (alloc_epfn - alloc_spfn)))
#endif
            dom0_update_physmap(d, pfn, mfn, vphysmap_start);
#undef pfn
            page++; pfn++;
            if ( !(pfn & 0xfffff) )
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

#ifdef CONFIG_VIDEO
    if ( !pv_shim && fill_console_start_info((void *)(si + 1)) )
    {
        si->console.dom0.info_off  = sizeof(struct start_info);
        si->console.dom0.info_size = sizeof(struct dom0_vga_console_info);
    }
#endif

    /*
     * TODO: provide an empty stub for fill_console_start_info in the
     * !CONFIG_VIDEO case so the logic here can be simplified.
     */
    if ( pv_shim )
        pv_shim_setup_dom(d, l4start, v_start, vxenstore_start, vconsole_start,
                          vphysmap_start, si);

    if ( is_pv_32bit_domain(d) )
        xlat_start_info(si, pv_shim ? XLAT_start_info_console_domU
                                    : XLAT_start_info_console_dom0);

    /* Return to idle domain's page tables. */
    mapcache_override_current(NULL);
    switch_cr3_cr4(current->arch.cr3, read_cr4());

    update_domain_wallclock_time(d);

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_KERNEL_DS
     *       CS:rIP = FLAT_KERNEL_CS:start_pc
     *       SS:rSP = FLAT_KERNEL_SS:start_stack
     *          rSI = start_info
     *  [rAX,rBX,rCX,rDX,rDI,rBP,R8-R15 are zero]
     */
    regs = &v->arch.user_regs;
    regs->ds = regs->es = regs->fs = regs->gs =
        !is_pv_32bit_domain(d) ? FLAT_KERNEL_DS : FLAT_COMPAT_KERNEL_DS;
    regs->ss = (!is_pv_32bit_domain(d) ?
                FLAT_KERNEL_SS : FLAT_COMPAT_KERNEL_SS);
    regs->cs = (!is_pv_32bit_domain(d) ?
                FLAT_KERNEL_CS : FLAT_COMPAT_KERNEL_CS);
    regs->rip = parms.virt_entry;
    regs->rsp = vstack_end;
    regs->rsi = vstartinfo_start;
    regs->eflags = X86_EFLAGS_IF;

    /*
     * We don't call arch_set_info_guest(), so some initialisation needs doing
     * by hand:
     *  - Reset the GDT to reference zero_page
     */
    pv_destroy_gdt(v);

    if ( test_bit(XENFEAT_supervisor_mode_kernel, parms.f_required) )
        panic("Dom0 requires supervisor-mode execution\n");

    rc = dom0_setup_permissions(d);
    BUG_ON(rc != 0);

    if ( d->domain_id == hardware_domid )
        iommu_hwdom_init(d);

    /* Activate shadow mode, if requested.  Reuse the pv_l1tf tasklet. */
#ifdef CONFIG_SHADOW_PAGING
    if ( opt_dom0_shadow )
    {
        printk("Switching dom0 to using shadow paging\n");
        tasklet_schedule(&d->arch.paging.shadow.pv_l1tf_tasklet);
    }
#endif

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

out:
    if ( elf_check_broken(&elf) )
        printk(XENLOG_WARNING "Dom0 kernel broken ELF: %s\n",
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
