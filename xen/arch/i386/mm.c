/******************************************************************************
 * arch/i386/mm.c
 * 
 * Modifications to Linux original are copyright (c) 2002-2003, K A Fraser
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

    l2ent = &idle_pg_table[l2_table_offset(vaddr)];
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
        *l2e = mk_l2_pgentry(__pa(page) | __PAGE_HYPERVISOR);
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
    fixrange_init(addr, 0, idle_pg_table);

    /* Create page table for ioremap(). */
    ioremap_pt = (void *)get_free_page(GFP_KERNEL);
    clear_page(ioremap_pt);
    idle_pg_table[IOREMAP_VIRT_START >> L2_PAGETABLE_SHIFT] = 
        mk_l2_pgentry(__pa(ioremap_pt) | __PAGE_HYPERVISOR);

    /* Create read-only mapping of MPT for guest-OS use. */
    idle_pg_table[READONLY_MPT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        idle_pg_table[RDWR_MPT_VIRT_START >> L2_PAGETABLE_SHIFT];
    mk_l2_readonly(idle_pg_table + 
                   (READONLY_MPT_VIRT_START >> L2_PAGETABLE_SHIFT));

    /* Set up mapping cache for domain pages. */
    mapcache = (unsigned long *)get_free_page(GFP_KERNEL);
    clear_page(mapcache);
    idle_pg_table[MAPCACHE_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(mapcache) | __PAGE_HYPERVISOR);

    /* Set up linear page table mapping. */
    idle_pg_table[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        mk_l2_pgentry(__pa(idle_pg_table) | __PAGE_HYPERVISOR);

}

void __init zap_low_mappings (void)
{
    int i;
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        idle_pg_table[i] = mk_l2_pgentry(0);
    flush_tlb_all();
}


long do_stack_switch(unsigned long ss, unsigned long esp)
{
    int nr = smp_processor_id();
    struct tss_struct *t = &init_tss[nr];

    /* We need to do this check as we load and use SS on guest's behalf. */
    if ( (ss & 3) == 0 )
        return -EPERM;

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
         ((base + limit) > PAGE_OFFSET) )
        goto bad;

 good:
    return 1;
 bad:
    return 0;
}


long set_gdt(struct task_struct *p, 
             unsigned long *frames,
             unsigned int entries)
{
    /* NB. There are 512 8-byte entries per GDT page. */
    unsigned int i, j, nr_pages = (entries + 511) / 512;
    unsigned long pfn, *gdt_page;
    long ret = -EINVAL;
    struct pfn_info *page;
    struct desc_struct *vgdt;

    spin_lock(&p->page_lock);

    /* Check the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        if ( frames[i] >= max_page ) 
            goto out;
        
        page = frame_table + frames[i];
        if ( (page->flags & PG_domain_mask) != p->domain )
            goto out;

        if ( (page->flags & PG_type_mask) != PGT_gdt_page )
        {
            if ( page->type_count != 0 )
                goto out;

            /* Check all potential GDT entries in the page. */
            gdt_page = map_domain_mem(frames[0] << PAGE_SHIFT);
            for ( j = 0; j < 512; j++ )
                if ( !check_descriptor(gdt_page[j*2], gdt_page[j*2+1]) )
                    goto out;
            unmap_domain_mem(gdt_page);
        }
    }

    /* Tear down the old GDT. */
    for ( i = 0; i < 16; i++ )
    {
        pfn = l1_pgentry_to_pagenr(p->mm.perdomain_pt[i]);
        p->mm.perdomain_pt[i] = mk_l1_pgentry(0);
        if ( pfn == 0 ) continue;
        page = frame_table + pfn;
        ASSERT((page->flags & PG_type_mask) == PGT_gdt_page);
        ASSERT((page->flags & PG_domain_mask) == p->domain);
        ASSERT((page->type_count != 0) && (page->tot_count != 0));
        put_page_type(page);
        put_page_tot(page);
    }

    /* Install the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
    {
        p->mm.perdomain_pt[i] =
            mk_l1_pgentry((frames[i] << PAGE_SHIFT) | __PAGE_HYPERVISOR);
        
        page = frame_table + frames[i];
        page->flags &= ~(PG_type_mask | PG_need_flush);
        page->flags |= PGT_gdt_page;
        get_page_type(page);
        get_page_tot(page);
    }

    /* Copy reserved GDT entries to the new GDT. */
    vgdt = map_domain_mem(frames[i] << PAGE_SHIFT);
    memcpy(vgdt + FIRST_RESERVED_GDT_ENTRY, 
           gdt_table + FIRST_RESERVED_GDT_ENTRY, 
           NR_RESERVED_GDT_ENTRIES*8);
    unmap_domain_mem(vgdt);

    SET_GDT_ADDRESS(p, GDT_VIRT_START);
    SET_GDT_ENTRIES(p, (entries*8)-1);

    ret = 0; /* success */

 out:
    spin_unlock(&p->page_lock);
    return ret;
}


long do_set_gdt(unsigned long *frame_list, unsigned int entries)
{
    unsigned int nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    long ret;

    if ( (entries <= LAST_RESERVED_GDT_ENTRY) || (entries > 8192) ) 
        return -EINVAL;
    
    if ( copy_from_user(frames, frame_list, nr_pages * sizeof(unsigned long)) )
        return -EFAULT;

    if ( (ret = set_gdt(current, frames, entries)) == 0 )
    {
        local_flush_tlb();
        __asm__ __volatile__ ("lgdt %0" : "=m" (*current->mm.gdt));
    }

    return ret;
}


long do_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    unsigned long *gdt_pent, pfn = pa >> PAGE_SHIFT;
    struct pfn_info *page;
    long ret = -EINVAL;

    if ( (pa & 7) || (pfn >= max_page) || !check_descriptor(word1, word2) )
        return -EINVAL;

    spin_lock(&current->page_lock);

    page = frame_table + pfn;
    if ( (page->flags & PG_domain_mask) != current->domain )
        goto out;

    /* Check if the given frame is in use in an unsafe context. */
    switch ( (page->flags & PG_type_mask) )
    {
    case PGT_gdt_page:
        /* Disallow updates of Xen-reserved descriptors in the current GDT. */
        if ( (l1_pgentry_to_pagenr(current->mm.perdomain_pt[0]) == pfn) &&
             (((pa&(PAGE_SIZE-1))>>3) >= FIRST_RESERVED_GDT_ENTRY) &&
             (((pa&(PAGE_SIZE-1))>>3) <= LAST_RESERVED_GDT_ENTRY) )
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
    spin_unlock(&current->page_lock);
    return ret;
}
