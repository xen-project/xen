/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * domain_build.c
 * 
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <xen/event.h>
#include <xen/elf.h>
#include <xen/kernel.h>
#include <asm/shadow.h>

/* No ring-3 access in initial page tables. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

int construct_dom0(struct domain *d,
                   unsigned long alloc_start,
                   unsigned long alloc_end,
                   unsigned long _image_start, unsigned long image_len, 
                   unsigned long _initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    char *dst;
    int i, rc;
    unsigned long pfn, mfn;
    unsigned long nr_pages = (alloc_end - alloc_start) >> PAGE_SHIFT;
    unsigned long nr_pt_pages;
    unsigned long count;
    l2_pgentry_t *l2tab, *l2start;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;
    struct pfn_info *page = NULL;
    start_info_t *si;
    struct exec_domain *ed = d->exec_domain[0];
    char *image_start  = (char *)_image_start;  /* use lowmem mappings */
    char *initrd_start = (char *)_initrd_start; /* use lowmem mappings */

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

    /* Sanity! */
    if ( d->id != 0 ) 
        BUG();
    if ( test_bit(DF_CONSTRUCTED, &d->d_flags) ) 
        BUG();

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    printk("*** LOADING DOMAIN 0 ***\n");

    /*
     * This is all a bit grim. We've moved the modules to the "safe" physical 
     * memory region above MAP_DIRECTMAP_ADDRESS (48MB). Later in this 
     * routine we're going to copy it down into the region that's actually 
     * been allocated to domain 0. This is highly likely to be overlapping, so 
     * we use a forward copy.
     * 
     * MAP_DIRECTMAP_ADDRESS should be safe. The worst case is a machine with 
     * 4GB and lots of network/disk cards that allocate loads of buffers. 
     * We'll have to revisit this if we ever support PAE (64GB).
     */

    rc = parseelfimage(image_start, image_len, &dsi);
    if ( rc != 0 )
        return rc;

    /* Set up domain options */
    if ( dsi.use_writable_pagetables )
        vm_assist(d, VMASST_CMD_enable, VMASST_TYPE_writable_pagetables);

    /* Align load address to 4MB boundary. */
    dsi.v_start &= ~((1UL<<22)-1);

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    vinitrd_start    = round_pgup(dsi.v_kernend);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * sizeof(unsigned long));
    vpt_start        = round_pgup(vphysmap_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1);
        if ( (v_end - vstack_end) < (512UL << 10) )
            v_end += 1UL << 22; /* Add extra 4MB to get >= 512kB padding. */
        if ( (((v_end - dsi.v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
    }

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Kernel image:  %p->%p\n"
           " Initrd image:  %p->%p\n"
           " Dom0 alloc.:   %p->%p\n",
           _image_start, _image_start + image_len,
           _initrd_start, _initrd_start + initrd_len,
           alloc_start, alloc_end);
    printk("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %p->%p\n"
           " Init. ramdisk: %p->%p\n"
           " Phys-Mach map: %p->%p\n"
           " Page tables:   %p->%p\n"
           " Start info:    %p->%p\n"
           " Boot stack:    %p->%p\n"
           " TOTAL:         %p->%p\n",
           dsi.v_kernstart, dsi.v_kernend, 
           vinitrd_start, vinitrd_end,
           vphysmap_start, vphysmap_end,
           vpt_start, vpt_end,
           vstartinfo_start, vstartinfo_end,
           vstack_start, vstack_end,
           dsi.v_start, v_end);
    printk(" ENTRY ADDRESS: %p\n", dsi.v_kernentry);

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        return -ENOMEM;
    }

    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( dsi.v_start < (1UL<<30) )
    {
        printk("Initial loading isn't allowed to lowest 1GB of memory.\n");
        return -EINVAL;
    }

    /* Paranoia: scrub DOM0's memory allocation. */
    printk("Scrubbing DOM0 RAM: ");
    dst = (char *)alloc_start;
    while ( dst < (char *)alloc_end )
    {
#define SCRUB_BYTES (100 * 1024 * 1024) /* 100MB */
        printk(".");
        touch_nmi_watchdog();
        if ( ((char *)alloc_end - dst) > SCRUB_BYTES )
        {
            memset(dst, 0, SCRUB_BYTES);
            dst += SCRUB_BYTES;
        }
        else
        {
            memset(dst, 0, (char *)alloc_end - dst);
            break;
        }
    }
    printk("done.\n");

    /* Construct a frame-allocation list for the initial domain. */
    for ( mfn = (alloc_start>>PAGE_SHIFT); 
          mfn < (alloc_end>>PAGE_SHIFT); 
          mfn++ )
    {
        page = &frame_table[mfn];
        page_set_owner(page, d);
        page->u.inuse.type_info = 0;
        page->count_info        = PGC_allocated | 1;
        list_add_tail(&page->list, &d->page_list);
        d->tot_pages++; d->max_pages++;
    }

    mpt_alloc = (vpt_start - dsi.v_start) + alloc_start;

    SET_GDT_ENTRIES(ed, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(ed, DEFAULT_GDT_ADDRESS);

    /*
     * We're basically forcing default RPLs to 1, so that our "what privilege
     * level are we returning to?" logic works.
     */
    ed->arch.failsafe_selector = FLAT_KERNEL_CS;
    ed->arch.event_selector    = FLAT_KERNEL_CS;
    ed->arch.kernel_ss = FLAT_KERNEL_SS;
    for ( i = 0; i < 256; i++ ) 
        ed->arch.traps[i].cs = FLAT_KERNEL_CS;

    /* WARNING: The new domain must have its 'processor' field filled in! */
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    memcpy(l2tab, &idle_pg_table[0], PAGE_SIZE);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry((unsigned long)l2start | __PAGE_HYPERVISOR);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(d->arch.mm_perdomain_pt) | __PAGE_HYPERVISOR);
    ed->arch.pagetable = mk_pagetable((unsigned long)l2start);

    l2tab += l2_table_offset(dsi.v_start);
    mfn = alloc_start >> PAGE_SHIFT;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc; 
            mpt_alloc += PAGE_SIZE;
            *l2tab++ = mk_l2_pgentry((unsigned long)l1start | L2_PROT);
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
        }
        *l1tab++ = mk_l1_pgentry((mfn << PAGE_SHIFT) | L1_PROT);
        
        page = &frame_table[mfn];
        if ( !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
    }

    /* Pages that are part of page tables must be read only. */
    l2tab = l2start + l2_table_offset(vpt_start);
    l1start = l1tab = (l1_pgentry_t *)l2_pgentry_to_phys(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        *l1tab = mk_l1_pgentry(l1_pgentry_val(*l1tab) & ~_PAGE_RW);
        page = &frame_table[l1_pgentry_to_pfn(*l1tab)];
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
        if ( !((unsigned long)++l1tab & (PAGE_SIZE - 1)) )
            l1start = l1tab = (l1_pgentry_t *)l2_pgentry_to_phys(*++l2tab);
    }

    /* Set up shared-info area. */
    update_dom_time(d);
    d->shared_info->domain_time = 0;
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
    d->shared_info->n_vcpu = smp_num_cpus;

    /* Install the new page tables. */
    __cli();
    write_ptbase(ed);

    /* Copy the OS image. */
    (void)loadelfimage(image_start);

    /* Copy the initial ramdisk. */
    if ( initrd_len != 0 )
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);
    
    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    memset(si, 0, PAGE_SIZE);
    si->nr_pages     = d->tot_pages;
    si->shared_info  = virt_to_phys(d->shared_info);
    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->pt_base      = vpt_start;
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < d->tot_pages; pfn++ )
    {
        mfn = pfn + (alloc_start>>PAGE_SHIFT);
#ifndef NDEBUG
#define REVERSE_START ((v_end - dsi.v_start) >> PAGE_SHIFT)
        if ( pfn > REVERSE_START )
            mfn = (alloc_end>>PAGE_SHIFT) - (pfn - REVERSE_START);
#endif
        ((unsigned long *)vphysmap_start)[pfn] = mfn;
        machine_to_phys_mapping[mfn] = pfn;
    }

    if ( initrd_len != 0 )
    {
        si->mod_start = vinitrd_start;
        si->mod_len   = initrd_len;
        printk("Initrd len 0x%lx, start at 0x%p\n",
               si->mod_len, si->mod_start);
    }

    dst = si->cmd_line;
    if ( cmdline != NULL )
    {
        for ( i = 0; i < 255; i++ )
        {
            if ( cmdline[i] == '\0' )
                break;
            *dst++ = cmdline[i];
        }
    }
    *dst = '\0';

    /* Reinstate the caller's page tables. */
    write_ptbase(current);
    __sti();

    /* Destroy low mappings - they were only for our convenience. */
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        if ( l2_pgentry_val(l2start[i]) & _PAGE_PSE )
            l2start[i] = mk_l2_pgentry(0);
    zap_low_mappings(); /* Do the same for the idle page tables. */
    
    /* DOM0 gets access to everything. */
    physdev_init_dom0(d);

    set_bit(DF_CONSTRUCTED, &d->d_flags);

    new_thread(ed, dsi.v_kernentry, vstack_end, vstartinfo_start);

#ifndef NDEBUG
    if (0) /* XXXXX DO NOT CHECK IN ENABLED !!! (but useful for testing so leave) */
    {
        shadow_lock(d);
        shadow_mode_enable(d, SHM_test); 
        shadow_unlock(d);
    }
#endif

    return 0;
}

int elf_sanity_check(Elf_Ehdr *ehdr)
{
    if ( !IS_ELF(*ehdr) ||
         (ehdr->e_ident[EI_CLASS] != ELFCLASS32) ||
         (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) ||
         (ehdr->e_type != ET_EXEC) ||
         (ehdr->e_machine != EM_386) )
    {
        printk("DOM0 image is not i386-compatible executable Elf image.\n");
        return 0;
    }

    return 1;
}
