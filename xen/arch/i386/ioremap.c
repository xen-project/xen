/*
 * arch/i386/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/page.h>

static unsigned long remap_base = IOREMAP_VIRT_START;

#define PAGE_ALIGN(addr)    (((addr)+PAGE_SIZE-1)&PAGE_MASK)

void * __ioremap(unsigned long phys_addr, 
                 unsigned long size, 
                 unsigned long flags)
{
    unsigned long vaddr;
    unsigned long offset, cur=0, last_addr;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    /* Don't allow wraparound or zero size */
    last_addr = phys_addr + size - 1;
    if ( (size == 0) || (last_addr < phys_addr) )
        return NULL;

    /* Don't remap the low PCI/ISA area: it's always mapped. */
    if ( (phys_addr >= 0xA0000) && (last_addr < 0x100000) )
        return phys_to_virt(phys_addr);

    if ( (remap_base + size) > (IOREMAP_VIRT_END - 1) )
    {
        printk("ioremap: going past end of reserved space!\n");
        return NULL;
    }

    /* Mappings have to be page-aligned. */
    offset = phys_addr & ~PAGE_MASK;
    phys_addr &= PAGE_MASK;
    size = PAGE_ALIGN(last_addr) - phys_addr;

    /* Ok, go for it. */
    vaddr = remap_base;
    remap_base += size;
    pl2e = &idle_pg_table[l2_table_offset(vaddr)];
    pl1e = l2_pgentry_to_l1(*pl2e++) + l1_table_offset(vaddr);
    do {
        *pl1e++ = mk_l1_pgentry((phys_addr+cur)|PAGE_HYPERVISOR|flags);
    }
    while ( (cur += PAGE_SIZE) != size );

    return (void *)(offset + (char *)vaddr);
}

void iounmap(void *addr)
{
    /* NOP for now. */
}
