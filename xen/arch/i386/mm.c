#include <xeno/config.h>
#include <xeno/lib.h>
#include <xeno/init.h>
#include <xeno/mm.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/fixmap.h>
#include <asm/domain_page.h>

static inline void set_pte_phys (unsigned long vaddr,
                                 l1_pgentry_t entry)
{
    l2_pgentry_t *l2ent;
    l1_pgentry_t *l1ent;

    l2ent = idle0_pg_table + l2_table_offset(vaddr);
    l1ent = l2_pgentry_to_l1(*l2ent) + l1_table_offset(vaddr);
    *l1ent = entry;

    /* It's enough to flush this one mapping. */
    __flush_tlb_one(vaddr);
}

void __set_fixmap (enum fixed_addresses idx, 
                   l1_pgentry_t entry)
{
    unsigned long address = __fix_to_virt(idx);

    if (idx >= __end_of_fixed_addresses) {
        printk("Invalid __set_fixmap\n");
        return;
    }
    set_pte_phys(address, entry);
}

static void __init fixrange_init (unsigned long start, 
                                  unsigned long end, l2_pgentry_t *pg_base)
{
    l2_pgentry_t *l2e;
    int i;
    unsigned long vaddr, page;

    vaddr = start;
    i = l2_table_offset(vaddr);
    l2e = pg_base + i;

    for ( ; (i < ENTRIES_PER_L2_PAGETABLE) && (vaddr != end); l2e++, i++ ) 
    {
        if ( !l2_pgentry_empty(*l2e) ) continue;
        page = (unsigned long)get_free_page(GFP_KERNEL);
        clear_page(page);
        *l2e = mk_l2_pgentry(__pa(page) | PAGE_HYPERVISOR);
        vaddr += 1 << L2_PAGETABLE_SHIFT;
    }
}

void __init paging_init(void)
{
    unsigned long addr;
    void *ioremap_pt;

    /* XXX initialised in boot.S */
    /*if ( cpu_has_pge ) set_in_cr4(X86_CR4_PGE);*/
    /*if ( cpu_has_pse ) set_in_cr4(X86_CR4_PSE);*/
    /*if ( cpu_has_pae ) set_in_cr4(X86_CR4_PAE);*/

    /*
     * Fixed mappings, only the page table structure has to be
     * created - mappings will be set by set_fixmap():
     */
    addr = FIXADDR_START & ~((1<<L2_PAGETABLE_SHIFT)-1);
    fixrange_init(addr, 0, idle0_pg_table);

    /* Create page table for ioremap(). */
    ioremap_pt = (void *)get_free_page(GFP_KERNEL);
    clear_page(ioremap_pt);
    idle0_pg_table[IOREMAP_VIRT_START >> L2_PAGETABLE_SHIFT] = 
        mk_l2_pgentry(__pa(ioremap_pt) | PAGE_HYPERVISOR);

    /* Create read-only mapping of MPT for guest-OS use. */
    idle0_pg_table[READONLY_MPT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        idle0_pg_table[RDWR_MPT_VIRT_START >> L2_PAGETABLE_SHIFT];
    mk_l2_readonly(idle0_pg_table + 
                   (READONLY_MPT_VIRT_START >> L2_PAGETABLE_SHIFT));
}

void __init zap_low_mappings (void)
{
    int i, j;
    for ( i = 0; i < smp_num_cpus; i++ )
    {
        for ( j = 0; j < DOMAIN_ENTRIES_PER_L2_PAGETABLE; j++ )
        {
            idle_pg_table[i][j] = mk_l2_pgentry(0);
        }
    }
    flush_tlb_all();
}


long do_stack_switch(unsigned long ss, unsigned long esp)
{
    int nr = smp_processor_id();
    struct tss_struct *t = &init_tss[nr];

    if ( (ss == __HYPERVISOR_CS) || (ss == __HYPERVISOR_DS) )
        return -1;

    current->thread.ss1  = ss;
    current->thread.esp1 = esp;
    t->ss1  = ss;
    t->esp1 = esp;

    return 0;
}


/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(unsigned long a, unsigned long b)
{
    unsigned long base, limit;

    /* A not-present descriptor will always fault, so is safe. */
    if ( !(b & _SEGMENT_P) ) 
        goto good;

    /*
     * We don't allow a DPL of zero. There is no legitimate reason for 
     * specifying DPL==0, and it gets rather dangerous if we also accept call 
     * gates (consider a call gate pointing at another guestos descriptor with 
     * DPL 0 -- this would get the OS ring-0 privileges).
     */
    if ( (b & _SEGMENT_DPL) == 0 )
        goto bad;

    if ( !(b & _SEGMENT_S) )
    {
        /*
         * System segment:
         *  1. Don't allow interrupt or trap gates as they belong in the IDT.
         *  2. Don't allow TSS descriptors or task gates as we don't
         *     virtualise x86 tasks.
         *  3. Don't allow LDT descriptors because they're unnecessary and
         *     I'm uneasy about allowing an LDT page to contain LDT
         *     descriptors. In any case, Xen automatically creates the
         *     required descriptor when reloading the LDT register.
         *  4. We allow call gates but they must not jump to a private segment.
         */

        /* Disallow everything but call gates. */
        if ( (b & _SEGMENT_TYPE) != 0xc00 )
            goto bad;

        /* Can't allow far jump to a Xen-private segment. */
        if ( !VALID_CODESEL(a>>16) )
            goto bad;

        /* Reserved bits must be zero. */
        if ( (b & 0xe0) != 0 )
            goto bad;
        
        /* No base/limit check is needed for a call gate. */
        goto good;
    }
    
    /* Check that base/limit do not overlap Xen-private space. */
    base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    limit = (b&0xf0000) | (a&0xffff);
    limit++; /* We add one because limit is inclusive. */
    if ( (b & _SEGMENT_G) )
        limit <<= 12;
    if ( ((base + limit) <= base) || 
         ((base + limit) >= PAGE_OFFSET) )
        goto bad;

 good:
    return 1;
 bad:
    return 0;
}


long do_set_gdt(unsigned long *frame_list, unsigned int entries)
{
    /* NB. There are 512 8-byte entries per GDT page. */
    unsigned int i, nr_pages = (entries + 511) / 512;
    unsigned long frames[16], pfn, *gdt_page, flags;
    long ret = -EINVAL;
    struct pfn_info *page;

    if ( (entries < FIRST_DOMAIN_GDT_ENTRY) || (entries > 8192) ) 
        return -EINVAL;

    if ( copy_from_user(frames, frame_list, nr_pages * sizeof(unsigned long)) )
        return -EFAULT;

    spin_lock_irqsave(&current->page_lock, flags);

    /* Check the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        if ( frames[i] >= max_page ) 
            goto out;
        
        page = frame_table + frames[i];
        if ( (page->flags & PG_domain_mask) != current->domain )
            goto out;

        if ( (page->flags & PG_type_mask) != PGT_gdt_page )
        {
            if ( page->type_count != 0 )
                goto out;

            /* Check all potential GDT entries in the page. */
            gdt_page = map_domain_mem(frames[0] << PAGE_SHIFT);
            for ( i = 0; i < 512; i++ )
                if ( !check_descriptor(gdt_page[i*2], gdt_page[i*2+1]) )
                    goto out;
            unmap_domain_mem(gdt_page);
        }
    }

    /* Tear down the old GDT. */
    for ( i = 0; i < 16; i++ )
    {
        pfn = l1_pgentry_to_pagenr(current->mm.perdomain_pt[i]);
        current->mm.perdomain_pt[i] = mk_l1_pgentry(0);
        if ( pfn == 0 ) continue;
        page = frame_table + pfn;
        put_page_type(page);
        put_page_tot(page);
    }

    /* Install the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        current->mm.perdomain_pt[i] =
            mk_l1_pgentry((frames[i] << PAGE_SHIFT) | __PAGE_HYPERVISOR);
        
        page = frame_table + frames[i];
        page->flags &= ~PG_type_mask;
        page->flags |= PGT_gdt_page;
        get_page_type(page);
        get_page_tot(page);
    }

    flush_tlb();

    /* Copy over first entries of the new GDT. */
    memcpy((void *)GDT_VIRT_START, gdt_table, FIRST_DOMAIN_GDT_ENTRY*8);
    
    SET_GDT_ADDRESS(current, GDT_VIRT_START);
    SET_GDT_ENTRIES(current, (entries*8)-1);
    __asm__ __volatile__ ("lgdt %0" : "=m" (*current->mm.gdt));

    ret = 0; /* success */

 out:
    spin_unlock_irqrestore(&current->page_lock, flags);
    return ret;
}


long do_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    unsigned long *gdt_pent, flags, pfn = pa >> PAGE_SHIFT;
    struct pfn_info *page;
    long ret = -EINVAL;

    if ( (pa & 7) || (pfn >= max_page) || !check_descriptor(word1, word2) )
        return -EINVAL;

    spin_lock_irqsave(&current->page_lock, flags);

    page = frame_table + pfn;
    if ( (page->flags & PG_domain_mask) != current->domain )
        goto out;

    /* Check if the given frame is in use in an unsafe context. */
    switch ( (page->flags & PG_type_mask) )
    {
    case PGT_gdt_page:
        /* Disallow updates of Xen-private descriptors in the current GDT. */
        if ( (l1_pgentry_to_pagenr(current->mm.perdomain_pt[0]) == pfn) &&
             (((pa&(PAGE_SIZE-1))>>3) < FIRST_DOMAIN_GDT_ENTRY) )
            goto out;
    case PGT_ldt_page:
    case PGT_writeable_page:
        break;
    default:
        if ( page->type_count != 0 )
            goto out;
    }

    /* All is good so make the update. */
    gdt_pent = map_domain_mem(pa);
    gdt_pent[0] = word1;
    gdt_pent[1] = word2;
    unmap_domain_mem(gdt_pent);

    ret = 0; /* success */

 out:
    spin_unlock_irqrestore(&current->page_lock, flags);
    return ret;
}
