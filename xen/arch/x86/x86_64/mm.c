/******************************************************************************
 * arch/x86/x86_64/mm.c
 * 
 * Modifications to Linux original are copyright (c) 2004, K A Fraser
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

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/domain_page.h>

void *safe_page_alloc(void)
{
    extern int early_boot;
    if ( early_boot )
        return __va(alloc_boot_pages(PAGE_SIZE, PAGE_SIZE));
    return (void *)alloc_xenheap_page();
}

/* Map physical byte range (@p, @p+@s) at virt address @v in pagetable @pt. */
int map_pages(
    pagetable_t *pt,
    unsigned long v,
    unsigned long p,
    unsigned long s,
    unsigned long flags)
{
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    void         *newpg;

    while ( s != 0 )
    {
        pl4e = &pt[l4_table_offset(v)];
        if ( !(l4_pgentry_val(*pl4e) & _PAGE_PRESENT) )
        {
            newpg = safe_page_alloc();
            clear_page(newpg);
            *pl4e = mk_l4_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
        }

        pl3e = l4_pgentry_to_l3(*pl4e) + l3_table_offset(v);
        if ( !(l3_pgentry_val(*pl3e) & _PAGE_PRESENT) )
        {
            newpg = safe_page_alloc();
            clear_page(newpg);
            *pl3e = mk_l3_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
        }

        pl2e = l3_pgentry_to_l2(*pl3e) + l2_table_offset(v);

        if ( ((s|v|p) & ((1<<L2_PAGETABLE_SHIFT)-1)) == 0 )
        {
            /* Super-page mapping. */
            if ( (l2_pgentry_val(*pl2e) & _PAGE_PRESENT) )
                __flush_tlb_pge();
            *pl2e = mk_l2_pgentry(p|flags|_PAGE_PSE);

            v += 1 << L2_PAGETABLE_SHIFT;
            p += 1 << L2_PAGETABLE_SHIFT;
            s -= 1 << L2_PAGETABLE_SHIFT;
        }
        else
        {
            /* Normal page mapping. */
            if ( !(l2_pgentry_val(*pl2e) & _PAGE_PRESENT) )
            {
                newpg = safe_page_alloc();
                clear_page(newpg);
                *pl2e = mk_l2_pgentry(__pa(newpg) | __PAGE_HYPERVISOR);
            }
            pl1e = l2_pgentry_to_l1(*pl2e) + l1_table_offset(v);
            if ( (l1_pgentry_val(*pl1e) & _PAGE_PRESENT) )
                __flush_tlb_one(v);
            *pl1e = mk_l1_pgentry(p|flags);

            v += 1 << L1_PAGETABLE_SHIFT;
            p += 1 << L1_PAGETABLE_SHIFT;
            s -= 1 << L1_PAGETABLE_SHIFT;
        }
    }

    return 0;
}

void __set_fixmap(
    enum fixed_addresses idx, unsigned long p, unsigned long flags)
{
    if ( unlikely(idx >= __end_of_fixed_addresses) )
        BUG();
    map_pages(idle_pg_table, fix_to_virt(idx), p, PAGE_SIZE, flags);
}


void __init paging_init(void)
{
    void *newpt;
    unsigned long i, p, max;

    /* Map all of physical memory. */
    max = (max_page + (1UL << L2_PAGETABLE_SHIFT) - 1UL) &
        ~((1UL << L2_PAGETABLE_SHIFT) - 1UL);
    map_pages(idle_pg_table, PAGE_OFFSET, 0, max, PAGE_HYPERVISOR);

    /*
     * Allocate and map the machine-to-phys table.
     * This also ensures L3 is present for ioremap().
     */
    for ( i = 0; i < max_page; i += ((1UL << L2_PAGETABLE_SHIFT) / 8) )
    {
        p = alloc_boot_pages(1UL << L2_PAGETABLE_SHIFT,
                             1UL << L2_PAGETABLE_SHIFT);
        if ( p == 0 )
            panic("Not enough memory for m2p table\n");
        map_pages(idle_pg_table, RDWR_MPT_VIRT_START + i*8, p, 
                  1UL << L2_PAGETABLE_SHIFT, PAGE_HYPERVISOR);
        memset((void *)(RDWR_MPT_VIRT_START + i*8), 0x55,
               1UL << L2_PAGETABLE_SHIFT);
    }

    /* Create read-only mapping of MPT for guest-OS use. */
    newpt = (void *)alloc_xenheap_page();
    clear_page(newpt);
    idle_pg_table[l4_table_offset(RO_MPT_VIRT_START)] =
        mk_l4_pgentry((__pa(newpt) | __PAGE_HYPERVISOR | _PAGE_USER) &
                      ~_PAGE_RW);
    /* Copy the L3 mappings from the RDWR_MPT area. */
    p  = l4_pgentry_val(idle_pg_table[l4_table_offset(RDWR_MPT_VIRT_START)]);
    p &= PAGE_MASK;
    p += l3_table_offset(RDWR_MPT_VIRT_START) * sizeof(l3_pgentry_t);
    newpt = (void *)((unsigned long)newpt +
                     (l3_table_offset(RO_MPT_VIRT_START) *
                      sizeof(l3_pgentry_t)));
    memcpy(newpt, __va(p),
           (RDWR_MPT_VIRT_END - RDWR_MPT_VIRT_START) >> L3_PAGETABLE_SHIFT);

    /* Set up linear page table mapping. */
    idle_pg_table[l4_table_offset(LINEAR_PT_VIRT_START)] =
        mk_l4_pgentry(__pa(idle_pg_table) | __PAGE_HYPERVISOR);
}

void __init zap_low_mappings(void)
{
    idle_pg_table[0] = mk_l4_pgentry(0);
    flush_tlb_all_pge();
}

void subarch_init_memory(struct domain *dom_xen)
{
    unsigned long i, v, m2p_start_mfn;
    l3_pgentry_t l3e;
    l2_pgentry_t l2e;

    /* M2P table is mappable read-only by privileged domains. */
    for ( v  = RDWR_MPT_VIRT_START; 
          v != RDWR_MPT_VIRT_END;
          v += 1 << L2_PAGETABLE_SHIFT )
    {
        l3e = l4_pgentry_to_l3(idle_pg_table[l4_table_offset(v)])[
            l3_table_offset(v)];
        if ( !(l3_pgentry_val(l3e) & _PAGE_PRESENT) )
            continue;
        l2e = l3_pgentry_to_l2(l3e)[l2_table_offset(v)];
        if ( !(l2_pgentry_val(l2e) & _PAGE_PRESENT) )
            continue;
        m2p_start_mfn = l2_pgentry_to_pagenr(l2e);

        for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        {
            frame_table[m2p_start_mfn+i].count_info        = PGC_allocated | 1;
            /* gdt to make sure it's only mapped read-only by non-privileged
               domains. */
            frame_table[m2p_start_mfn+i].u.inuse.type_info = PGT_gdt_page | 1;
            frame_table[m2p_start_mfn+i].u.inuse.domain    = dom_xen;
        }
    }
}

/*
 * Allows shooting down of borrowed page-table use on specific CPUs.
 * Specifically, we borrow page tables when running the idle domain.
 */
static void __synchronise_pagetables(void *mask)
{
    struct exec_domain *ed = current;
    if ( ((unsigned long)mask & (1 << ed->processor)) &&
         is_idle_task(ed->domain) )
        write_ptbase(&ed->mm);
}
void synchronise_pagetables(unsigned long cpu_mask)
{
    __synchronise_pagetables((void *)cpu_mask);
    smp_call_function(__synchronise_pagetables, (void *)cpu_mask, 1, 1);
}

long do_stack_switch(unsigned long ss, unsigned long esp)
{
    if ( (ss & 3) != 3 )
        return -EPERM;
    current->thread.guestos_ss = ss;
    current->thread.guestos_sp = esp;
    return 0;
}


/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(unsigned long *d)
{
    unsigned long base, limit, a = d[0], b = d[1];

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

#if 0
        /* Can't allow far jump to a Xen-private segment. */
        if ( !VALID_CODESEL(a>>16) )
            goto bad;
#endif

        /* Reserved bits must be zero. */
        if ( (b & 0xe0) != 0 )
            goto bad;
        
        /* No base/limit check is needed for a call gate. */
        goto good;
    }
    
    /* Check that base is at least a page away from Xen-private area. */
    base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    if ( base >= (PAGE_OFFSET - PAGE_SIZE) )
        goto bad;

    /* Check and truncate the limit if necessary. */
    limit = (b&0xf0000) | (a&0xffff);
    limit++; /* We add one because limit is inclusive. */
    if ( (b & _SEGMENT_G) )
        limit <<= 12;

    if ( (b & (_SEGMENT_CODE | _SEGMENT_EC)) == _SEGMENT_EC )
    {
        /*
         * Grows-down limit check. 
         * NB. limit == 0xFFFFF provides no access      (if G=1).
         *     limit == 0x00000 provides 4GB-4kB access (if G=1).
         */
        if ( (base + limit) > base )
        {
            limit = -(base & PAGE_MASK);
            goto truncate;
        }
    }
    else
    {
        /*
         * Grows-up limit check.
         * NB. limit == 0xFFFFF provides 4GB access (if G=1).
         *     limit == 0x00000 provides 4kB access (if G=1).
         */
        if ( ((base + limit) <= base) || 
             ((base + limit) > PAGE_OFFSET) )
        {
            limit = PAGE_OFFSET - base;
        truncate:
            if ( !(b & _SEGMENT_G) )
                goto bad; /* too dangerous; too hard to work out... */
            limit = (limit >> 12) - 1;
            d[0] &= ~0x0ffff; d[0] |= limit & 0x0ffff;
            d[1] &= ~0xf0000; d[1] |= limit & 0xf0000;
        }
    }

 good:
    return 1;
 bad:
    return 0;
}


void destroy_gdt(struct exec_domain *ed)
{
    int i;
    unsigned long pfn;

    for ( i = 0; i < 16; i++ )
    {
        if ( (pfn = l1_pgentry_to_pagenr(ed->mm.perdomain_ptes[i])) != 0 )
            put_page_and_type(&frame_table[pfn]);
        ed->mm.perdomain_ptes[i] = mk_l1_pgentry(0);
    }
}


long set_gdt(struct exec_domain *ed, 
             unsigned long *frames,
             unsigned int entries)
{
    struct domain *d = ed->domain;
    /* NB. There are 512 8-byte entries per GDT page. */
    int i = 0, nr_pages = (entries + 511) / 512;
    struct desc_struct *vgdt;
    unsigned long pfn;

    /* Check the first page in the new GDT. */
    if ( (pfn = frames[0]) >= max_page )
        goto fail;

    /* The first page is special because Xen owns a range of entries in it. */
    if ( !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
    {
        /* GDT checks failed: try zapping the Xen reserved entries. */
        if ( !get_page_and_type(&frame_table[pfn], d, PGT_writable_page) )
            goto fail;
        vgdt = map_domain_mem(pfn << PAGE_SHIFT);
        memset(vgdt + FIRST_RESERVED_GDT_ENTRY, 0,
               NR_RESERVED_GDT_ENTRIES*8);
        unmap_domain_mem(vgdt);
        put_page_and_type(&frame_table[pfn]);

        /* Okay, we zapped the entries. Now try the GDT checks again. */
        if ( !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
            goto fail;
    }

    /* Check the remaining pages in the new GDT. */
    for ( i = 1; i < nr_pages; i++ )
        if ( ((pfn = frames[i]) >= max_page) ||
             !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
            goto fail;

    /* Copy reserved GDT entries to the new GDT. */
    vgdt = map_domain_mem(frames[0] << PAGE_SHIFT);
    memcpy(vgdt + FIRST_RESERVED_GDT_ENTRY, 
           gdt_table + FIRST_RESERVED_GDT_ENTRY, 
           NR_RESERVED_GDT_ENTRIES*8);
    unmap_domain_mem(vgdt);

    /* Tear down the old GDT. */
    destroy_gdt(ed);

    /* Install the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
        ed->mm.perdomain_ptes[i] =
            mk_l1_pgentry((frames[i] << PAGE_SHIFT) | __PAGE_HYPERVISOR);

    SET_GDT_ADDRESS(ed, GDT_VIRT_START(ed));
    SET_GDT_ENTRIES(ed, entries);

    return 0;

 fail:
    while ( i-- > 0 )
        put_page_and_type(&frame_table[frames[i]]);
    return -EINVAL;
}


long do_set_gdt(unsigned long *frame_list, unsigned int entries)
{
    int nr_pages = (entries + 511) / 512;
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
    unsigned long *gdt_pent, pfn = pa >> PAGE_SHIFT, d[2];
    struct pfn_info *page;
    long ret = -EINVAL;

    d[0] = word1;
    d[1] = word2;

    if ( (pa & 7) || (pfn >= max_page) || !check_descriptor(d) )
        return -EINVAL;

    page = &frame_table[pfn];
    if ( unlikely(!get_page(page, current->domain)) )
        return -EINVAL;

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_gdt_page:
        /* Disallow updates of Xen-reserved descriptors in the current GDT. */
        if ( (l1_pgentry_to_pagenr(current->mm.perdomain_ptes[0]) == pfn) &&
             (((pa&(PAGE_SIZE-1))>>3) >= FIRST_RESERVED_GDT_ENTRY) &&
             (((pa&(PAGE_SIZE-1))>>3) <= LAST_RESERVED_GDT_ENTRY) )
            goto out;
        if ( unlikely(!get_page_type(page, PGT_gdt_page)) )
            goto out;
        break;
    case PGT_ldt_page:
        if ( unlikely(!get_page_type(page, PGT_ldt_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    /* All is good so make the update. */
    gdt_pent = map_domain_mem(pa);
    memcpy(gdt_pent, d, 8);
    unmap_domain_mem(gdt_pent);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);
    return ret;
}

#ifdef MEMORY_GUARD

#if 1

void *memguard_init(void *heap_start) { return heap_start; }
void memguard_guard_range(void *p, unsigned long l) {}
void memguard_unguard_range(void *p, unsigned long l) {}

#else

void *memguard_init(void *heap_start)
{
    l1_pgentry_t *l1;
    int i, j;

    /* Round the allocation pointer up to a page boundary. */
    heap_start = (void *)(((unsigned long)heap_start + (PAGE_SIZE-1)) & 
                          PAGE_MASK);

    /* Memory guarding is incompatible with super pages. */
    for ( i = 0; i < (xenheap_phys_end >> L2_PAGETABLE_SHIFT); i++ )
    {
        l1 = (l1_pgentry_t *)heap_start;
        heap_start = (void *)((unsigned long)heap_start + PAGE_SIZE);
        for ( j = 0; j < ENTRIES_PER_L1_PAGETABLE; j++ )
            l1[j] = mk_l1_pgentry((i << L2_PAGETABLE_SHIFT) |
                                   (j << L1_PAGETABLE_SHIFT) | 
                                  __PAGE_HYPERVISOR);
        idle_pg_table[i] = idle_pg_table[i + l2_table_offset(PAGE_OFFSET)] =
            mk_l2_pgentry(virt_to_phys(l1) | __PAGE_HYPERVISOR);
    }

    return heap_start;
}

static void __memguard_change_range(void *p, unsigned long l, int guard)
{
    l1_pgentry_t *l1;
    l2_pgentry_t *l2;
    unsigned long _p = (unsigned long)p;
    unsigned long _l = (unsigned long)l;

    /* Ensure we are dealing with a page-aligned whole number of pages. */
    ASSERT((_p&PAGE_MASK) != 0);
    ASSERT((_l&PAGE_MASK) != 0);
    ASSERT((_p&~PAGE_MASK) == 0);
    ASSERT((_l&~PAGE_MASK) == 0);

    while ( _l != 0 )
    {
        l2  = &idle_pg_table[l2_table_offset(_p)];
        l1  = l2_pgentry_to_l1(*l2) + l1_table_offset(_p);
        if ( guard )
            *l1 = mk_l1_pgentry(l1_pgentry_val(*l1) & ~_PAGE_PRESENT);
        else
            *l1 = mk_l1_pgentry(l1_pgentry_val(*l1) | _PAGE_PRESENT);
        _p += PAGE_SIZE;
        _l -= PAGE_SIZE;
    }
}

void memguard_guard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 1);
    local_flush_tlb();
}

void memguard_unguard_range(void *p, unsigned long l)
{
    __memguard_change_range(p, l, 0);
}

#endif

#endif
