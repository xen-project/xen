/*
 * arch/i386/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */

#include <xeno/config.h>
#include <xeno/lib.h>
#include <xeno/mm.h>
#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/page.h>

static unsigned long remap_base = 0;

#define PAGE_ALIGN(addr)    (((addr)+PAGE_SIZE-1)&PAGE_MASK)

static void new_l2e(l2_pgentry_t *pl2e)
{
    l1_pgentry_t *pl1e = (l1_pgentry_t *)get_free_page(GFP_KERNEL);
    if ( !pl1e ) BUG();
    clear_page(pl1e);
    *pl2e = mk_l2_pgentry(__pa(pl1e)|__PAGE_HYPERVISOR);
}


void * __ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags)
{
    unsigned long vaddr;
    unsigned long offset, cur=0, last_addr;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    /* First time through, start allocating from far end of virtual memory. */
    if ( !remap_base ) remap_base = IOREMAP_VIRT_START;

    /* Don't allow wraparound or zero size */
    last_addr = phys_addr + size - 1;
    if (!size || last_addr < phys_addr)
        return NULL;

    /*
     * Don't remap the low PCI/ISA area, it's always mapped..
     */
    if (phys_addr >= 0xA0000 && last_addr < 0x100000)
        return phys_to_virt(phys_addr);

    if(remap_base + size > IOREMAP_VIRT_END-1) {
      printk("ioremap: going past end of reserved space!\n");
      return NULL;
    }
#if 0
    /*
     * Don't allow anybody to remap normal RAM that we're using..
     */
    if (phys_addr < virt_to_phys(high_memory)) {
        char *t_addr, *t_end;
        struct pfn_info *page;

        t_addr = __va(phys_addr);
        t_end = t_addr + (size - 1);
	   
        for(page = virt_to_page(t_addr); page <= virt_to_page(t_end); page++)
            if(!PageReserved(page))
                return NULL;
    }
#endif

    /*
     * Mappings have to be page-aligned
     */
    offset = phys_addr & ~PAGE_MASK;
    phys_addr &= PAGE_MASK;
    size = PAGE_ALIGN(last_addr) - phys_addr;

    /*
     * Ok, go for it..
     */
    vaddr = remap_base;
    remap_base += size;
    pl2e = &idle_pg_table[l2_table_offset(vaddr)];
    if ( l2_pgentry_empty(*pl2e) ) new_l2e(pl2e);
    pl1e = l2_pgentry_to_l1(*pl2e++) + l1_table_offset(vaddr);
    for ( ; ; ) 
    {
        if ( !l1_pgentry_empty(*pl1e) ) BUG();
        *pl1e++ = mk_l1_pgentry((phys_addr+cur)|PAGE_HYPERVISOR|flags);
        cur += PAGE_SIZE;
        if ( cur == size ) break;
        if ( !((unsigned long)pl1e & (PAGE_SIZE-1)) )
        {
            if ( l2_pgentry_empty(*pl2e) ) new_l2e(pl2e);
            pl1e = l2_pgentry_to_l1(*pl2e++);        
        }
    }

    flush_tlb_all();

    return (void *) (offset + (char *)vaddr);
}

void iounmap(void *addr)
{
    /* NOP for now. */
}
