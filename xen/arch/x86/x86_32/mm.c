/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * arch/x86/x86_32/mm.c
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

/* Map physical byte range (@p, @p+@s) at virt address @v in pagetable @pt. */
int map_pages(
    root_pgentry_t *pt,
    unsigned long v,
    unsigned long p,
    unsigned long s,
    unsigned long flags)
{
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    void         *newpg;

    while ( s != 0 )
    {
        pl2e = &pt[l2_table_offset(v)];

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
                newpg = (void *)alloc_xenheap_page();
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
    void *ioremap_pt;
    unsigned long v, l2e;
    struct pfn_info *pg;

    /* Allocate and map the machine-to-phys table. */
    if ( (pg = alloc_domheap_pages(NULL, 10)) == NULL )
        panic("Not enough memory to bootstrap Xen.\n");
    idle_pg_table[l2_table_offset(RDWR_MPT_VIRT_START)] =
        mk_l2_pgentry(page_to_phys(pg) | __PAGE_HYPERVISOR | _PAGE_PSE);
    memset((void *)RDWR_MPT_VIRT_START, 0x55, 4UL << 20);

    /* Xen 4MB mappings can all be GLOBAL. */
    if ( cpu_has_pge )
    {
        for ( v = HYPERVISOR_VIRT_START; v; v += (1 << L2_PAGETABLE_SHIFT) )
        {
             l2e = l2_pgentry_val(idle_pg_table[l2_table_offset(v)]);
             if ( l2e & _PAGE_PSE )
                 l2e |= _PAGE_GLOBAL;
             idle_pg_table[v >> L2_PAGETABLE_SHIFT] = mk_l2_pgentry(l2e);
        }
    }

    /* Create page table for ioremap(). */
    ioremap_pt = (void *)alloc_xenheap_page();
    clear_page(ioremap_pt);
    idle_pg_table[l2_table_offset(IOREMAP_VIRT_START)] =
        mk_l2_pgentry(__pa(ioremap_pt) | __PAGE_HYPERVISOR);

    /* Create read-only mapping of MPT for guest-OS use. */
    idle_pg_table[l2_table_offset(RO_MPT_VIRT_START)] =
        mk_l2_pgentry(l2_pgentry_val(
            idle_pg_table[l2_table_offset(RDWR_MPT_VIRT_START)]) & ~_PAGE_RW);

    /* Set up mapping cache for domain pages. */
    mapcache = (unsigned long *)alloc_xenheap_page();
    clear_page(mapcache);
    idle_pg_table[l2_table_offset(MAPCACHE_VIRT_START)] =
        mk_l2_pgentry(__pa(mapcache) | __PAGE_HYPERVISOR);

    /* Set up linear page table mapping. */
    idle_pg_table[l2_table_offset(LINEAR_PT_VIRT_START)] =
        mk_l2_pgentry(__pa(idle_pg_table) | __PAGE_HYPERVISOR);
}

void __init zap_low_mappings(void)
{
    int i;
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        idle_pg_table[i] = mk_l2_pgentry(0);
    flush_tlb_all_pge();
}

void subarch_init_memory(struct domain *dom_xen)
{
    unsigned long i, m2p_start_mfn;

    /*
     * We are rather picky about the layout of 'struct pfn_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them. Also, just for sanity, we assert the size
     * of the structure here.
     */
    if ( (offsetof(struct pfn_info, u.inuse._domain) != 
          (offsetof(struct pfn_info, count_info) + sizeof(u32))) ||
         (sizeof(struct pfn_info) != 24) )
    {
        printk("Weird pfn_info layout (%ld,%ld,%d)\n",
               offsetof(struct pfn_info, count_info),
               offsetof(struct pfn_info, u.inuse._domain),
               sizeof(struct pfn_info));
        for ( ; ; ) ;
    }

    /* M2P table is mappable read-only by privileged domains. */
    m2p_start_mfn = l2_pgentry_to_pfn(
        idle_pg_table[l2_table_offset(RDWR_MPT_VIRT_START)]);
    for ( i = 0; i < 1024; i++ )
    {
        frame_table[m2p_start_mfn+i].count_info = PGC_allocated | 1;
	/* gdt to make sure it's only mapped read-only by non-privileged
	   domains. */
        frame_table[m2p_start_mfn+i].u.inuse.type_info = PGT_gdt_page | 1;
        page_set_owner(&frame_table[m2p_start_mfn+i], dom_xen);
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
        write_ptbase(ed);
}
void synchronise_pagetables(unsigned long cpu_mask)
{
    __synchronise_pagetables((void *)cpu_mask);
    smp_call_function(__synchronise_pagetables, (void *)cpu_mask, 1, 1);
}

long do_stack_switch(unsigned long ss, unsigned long esp)
{
    int nr = smp_processor_id();
    struct tss_struct *t = &init_tss[nr];

    /* We need to do this check as we load and use SS on guest's behalf. */
    if ( (ss & 3) == 0 )
        return -EPERM;

    current->arch.guestos_ss = ss;
    current->arch.guestos_sp = esp;
    t->ss1  = ss;
    t->esp1 = esp;

    return 0;
}


/* Returns TRUE if given descriptor is valid for GDT or LDT. */
int check_descriptor(struct desc_struct *d)
{
    unsigned long base, limit;
    u32 a = d->a, b = d->b;

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
            d->a &= ~0x0ffff; d->a |= limit & 0x0ffff;
            d->b &= ~0xf0000; d->b |= limit & 0xf0000;
        }
    }

 good:
    return 1;
 bad:
    return 0;
}


#ifdef MEMORY_GUARD

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
        for ( j = 0; j < L1_PAGETABLE_ENTRIES; j++ )
            l1[j] = mk_l1_pgentry((i << L2_PAGETABLE_SHIFT) |
                                   (j << L1_PAGETABLE_SHIFT) | 
                                  __PAGE_HYPERVISOR);
        idle_pg_table[i + l2_table_offset(PAGE_OFFSET)] =
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

void memguard_guard_stack(void *p)
{
    memguard_guard_range(p, PAGE_SIZE);
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
