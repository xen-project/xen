#include <xeno/config.h>
#include <xeno/lib.h>
#include <xeno/init.h>
#include <xeno/mm.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/fixmap.h>

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
    idle0_pg_table[MAPCACHE_VIRT_START >> L2_PAGETABLE_SHIFT] = 
        mk_l2_pgentry(__pa(ioremap_pt) | PAGE_HYPERVISOR);
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


long do_set_guest_stack(unsigned long ss, unsigned long esp)
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
