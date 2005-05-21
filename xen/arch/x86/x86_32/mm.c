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

struct pfn_info *alloc_xen_pagetable(void)
{
    extern int early_boot;
    extern unsigned long xenheap_phys_start;
    struct pfn_info *pg;

    if ( !early_boot )
    {
        void *v = (void *)alloc_xenheap_page();
        return ((v == NULL) ? NULL : virt_to_page(v));
    }

    pg = phys_to_page(xenheap_phys_start);
    xenheap_phys_start += PAGE_SIZE;
    return pg;
}

void free_xen_pagetable(struct pfn_info *pg)
{
    free_xenheap_page((unsigned long)page_to_virt(pg));
}

l2_pgentry_t *virt_to_xen_l2e(unsigned long v)
{
    return &idle_pg_table[l2_table_offset(v)];
}

void __init paging_init(void)
{
    void *ioremap_pt;
    unsigned long v;
    struct pfn_info *m2p_pg;

    /* Allocate and map the machine-to-phys table. */
    if ( (m2p_pg = alloc_domheap_pages(NULL, 10)) == NULL )
        panic("Not enough memory to bootstrap Xen.\n");
    idle_pg_table[l2_table_offset(RDWR_MPT_VIRT_START)] =
        l2e_create_page(m2p_pg, __PAGE_HYPERVISOR | _PAGE_PSE);
    memset((void *)RDWR_MPT_VIRT_START, 0x55, 4UL << 20);

    /* Xen 4MB mappings can all be GLOBAL. */
    if ( cpu_has_pge )
    {
        for ( v = HYPERVISOR_VIRT_START; v; v += (1 << L2_PAGETABLE_SHIFT) )
        {
            if (l2e_get_flags(idle_pg_table[l2_table_offset(v)]) & _PAGE_PSE)
                l2e_add_flags(&idle_pg_table[l2_table_offset(v)],
                              _PAGE_GLOBAL);
        }
    }

    /* Create page table for ioremap(). */
    ioremap_pt = (void *)alloc_xenheap_page();
    clear_page(ioremap_pt);
    idle_pg_table[l2_table_offset(IOREMAP_VIRT_START)] =
        l2e_create_page(virt_to_page(ioremap_pt), __PAGE_HYPERVISOR);

    /*
     * Create read-only mapping of MPT for guest-OS use.
     * NB. Remove the global bit so that shadow_mode_translate()==true domains
     *     can reused this address space for their phys-to-machine mapping.
     */
    idle_pg_table[l2_table_offset(RO_MPT_VIRT_START)] =
        l2e_create_page(m2p_pg, (__PAGE_HYPERVISOR | _PAGE_PSE) & ~_PAGE_RW);

    /* Set up mapping cache for domain pages. */
    mapcache = (l1_pgentry_t *)alloc_xenheap_page();
    clear_page(mapcache);
    idle_pg_table[l2_table_offset(MAPCACHE_VIRT_START)] =
        l2e_create_page(virt_to_page(mapcache), __PAGE_HYPERVISOR);

    /* Set up linear page table mapping. */
    idle_pg_table[l2_table_offset(LINEAR_PT_VIRT_START)] =
        l2e_create_page(virt_to_page(idle_pg_table), __PAGE_HYPERVISOR);
}

void __init zap_low_mappings(void)
{
    int i;
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        idle_pg_table[i] = l2e_empty();
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
    m2p_start_mfn = l2e_get_pfn(
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


long do_stack_switch(unsigned long ss, unsigned long esp)
{
    int nr = smp_processor_id();
    struct tss_struct *t = &init_tss[nr];

    if ( (ss & 3) != 1 )
        return -EPERM;

    current->arch.guest_context.kernel_ss = ss;
    current->arch.guest_context.kernel_sp = esp;
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
     * gates (consider a call gate pointing at another kernel descriptor with 
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
    if ( base >= (GUEST_SEGMENT_MAX_ADDR - PAGE_SIZE) )
        goto bad;

    /* Check and truncate the limit if necessary. */
    limit = (b&0xf0000) | (a&0xffff);
    limit++; /* We add one because limit is inclusive. */
    if ( (b & _SEGMENT_G) )
        limit <<= 12;

    if ( (b & (_SEGMENT_CODE | _SEGMENT_EC)) == _SEGMENT_EC )
    {
        /*
         * DATA, GROWS-DOWN.
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
         * DATA, GROWS-UP. 
         * CODE (CONFORMING AND NON-CONFORMING).
         * Grows-up limit check.
         * NB. limit == 0xFFFFF provides 4GB access (if G=1).
         *     limit == 0x00000 provides 4kB access (if G=1).
         */
        if ( ((base + limit) <= base) || 
             ((base + limit) > GUEST_SEGMENT_MAX_ADDR) )
        {
            limit = GUEST_SEGMENT_MAX_ADDR - base;
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

void memguard_guard_stack(void *p)
{
    memguard_guard_range(p, PAGE_SIZE);
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
