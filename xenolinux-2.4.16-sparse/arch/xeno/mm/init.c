/*
 *  linux/arch/i386/mm/init.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 */

#include <linux/config.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#ifdef CONFIG_BLK_DEV_INITRD
#include <linux/blk.h>
#endif
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>
#include <asm/apic.h>
#include <asm/tlb.h>

mmu_gather_t mmu_gathers[NR_CPUS];
unsigned long highstart_pfn, highend_pfn;
static unsigned long totalram_pages;
static unsigned long totalhigh_pages;

int do_check_pgt_cache(int low, int high)
{
    int freed = 0;
    if(pgtable_cache_size > high) {
        do {
            if (!QUICKLIST_EMPTY(pgd_quicklist)) {
                free_pgd_slow(get_pgd_fast());
                freed++;
            }
            if (!QUICKLIST_EMPTY(pte_quicklist)) {
                pte_free_slow(pte_alloc_one_fast(NULL, 0));
                freed++;
            }
        } while(pgtable_cache_size > low);
    }
    return freed;
}

void show_mem(void)
{
    int i, total = 0, reserved = 0;
    int shared = 0, cached = 0;
    int highmem = 0;

    printk("Mem-info:\n");
    show_free_areas();
    printk("Free swap:       %6dkB\n",nr_swap_pages<<(PAGE_SHIFT-10));
    i = max_mapnr;
    while (i-- > 0) {
        total++;
        if (PageHighMem(mem_map+i))
            highmem++;
        if (PageReserved(mem_map+i))
            reserved++;
        else if (PageSwapCache(mem_map+i))
            cached++;
        else if (page_count(mem_map+i))
            shared += page_count(mem_map+i) - 1;
    }
    printk("%d pages of RAM\n", total);
    printk("%d pages of HIGHMEM\n",highmem);
    printk("%d reserved pages\n",reserved);
    printk("%d pages shared\n",shared);
    printk("%d pages swap cached\n",cached);
    printk("%ld pages in page table cache\n",pgtable_cache_size);
    show_buffers();
}

/* References to section boundaries */

extern char _text, _etext, _edata, __bss_start, _end;
extern char __init_begin, __init_end;

static inline void set_pte_phys (unsigned long vaddr,
                                 unsigned long phys, pgprot_t flags)
{
    pgprot_t prot;
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;

    pgd = init_mm.pgd + __pgd_offset(vaddr);
    if (pgd_none(*pgd)) {
        printk("PAE BUG #00!\n");
        return;
    }
    pmd = pmd_offset(pgd, vaddr);
    if (pmd_none(*pmd)) {
        printk("PAE BUG #01!\n");
        return;
    }
    pte = pte_offset(pmd, vaddr);
    if (pte_val(*pte))
        pte_ERROR(*pte);
    pgprot_val(prot) = pgprot_val(PAGE_KERNEL) | pgprot_val(flags);

    /* We queue directly, avoiding hidden phys->machine translation. */
    queue_l1_entry_update(__pa(pte), phys | pgprot_val(prot));

    /*
     * It's enough to flush this one mapping.
     * (PGE mappings get flushed as well)
     */
    __flush_tlb_one(vaddr);
}

void __set_fixmap (enum fixed_addresses idx, unsigned long phys, 
                   pgprot_t flags)
{
    unsigned long address = __fix_to_virt(idx);

    if (idx >= __end_of_fixed_addresses) {
        printk("Invalid __set_fixmap\n");
        return;
    }
    set_pte_phys(address, phys, flags);
}

static void __init fixrange_init (unsigned long start, 
                                  unsigned long end, pgd_t *pgd_base)
{
    pgd_t *pgd, *kpgd;
    pmd_t *pmd, *kpmd;
    pte_t *pte, *kpte;
    int i, j;
    unsigned long vaddr;

    vaddr = start;
    i = __pgd_offset(vaddr);
    j = __pmd_offset(vaddr);
    pgd = pgd_base + i;

    for ( ; (i < PTRS_PER_PGD) && (vaddr != end); pgd++, i++) {
        pmd = (pmd_t *)pgd;
        for (; (j < PTRS_PER_PMD) && (vaddr != end); pmd++, j++) {
            if (pmd_none(*pmd)) {
                pte = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
                clear_page(pte);
                kpgd = pgd_offset_k((unsigned long)pte);
                kpmd = pmd_offset(kpgd, (unsigned long)pte);
                kpte = pte_offset(kpmd, (unsigned long)pte);                
                queue_l1_entry_update(__pa(kpte), 
                                      (*(unsigned long *)kpte)&~_PAGE_RW);
                set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte)));
            }
            vaddr += PMD_SIZE;
        }
        j = 0;
    }

    XENO_flush_page_update_queue();
}

void __init paging_init(void)
{
    unsigned long zones_size[MAX_NR_ZONES] = {0, 0, 0};
    unsigned int max_dma, high, low;
    unsigned long vaddr;
    
    max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
    low = max_low_pfn;
    high = highend_pfn;
    
    if (low < max_dma)
    {
        zones_size[ZONE_DMA] = low;
    }
    else 
    {
        zones_size[ZONE_DMA] = max_dma;
        zones_size[ZONE_NORMAL] = low - max_dma;
    }
    free_area_init(zones_size);

    /*
     * Fixed mappings, only the page table structure has to be created - 
     * mappings will be set by set_fixmap():
     */
    vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
    fixrange_init(vaddr, HYPERVISOR_VIRT_START, init_mm.pgd);

    /*
     * XXX We do this conversion early, so that all other page tables
     * will automatically get this mapping.
     */
    set_fixmap(FIX_BLKRING_BASE, start_info.blk_ring);
}


static inline int page_is_ram (unsigned long pagenr)
{
    return 1;
}

void __init mem_init(void)
{
    int codesize, reservedpages, datasize, initsize;
    int tmp;

    max_mapnr = num_physpages = max_low_pfn;
    high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);

    /* clear the zero-page */
    memset(empty_zero_page, 0, PAGE_SIZE);

    /* this will put all low memory onto the freelists */
    totalram_pages += free_all_bootmem();

    reservedpages = 0;
    for (tmp = 0; tmp < max_low_pfn; tmp++)
        /*
         * Only count reserved RAM pages
         */
        if (page_is_ram(tmp) && PageReserved(mem_map+tmp))
            reservedpages++;
    codesize =  (unsigned long) &_etext - (unsigned long) &_text;
    datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
    initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

    printk("Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init, %ldk highmem)\n",
           (unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
           max_mapnr << (PAGE_SHIFT-10),
           codesize >> 10,
           reservedpages << (PAGE_SHIFT-10),
           datasize >> 10,
           initsize >> 10,
           (unsigned long) (totalhigh_pages << (PAGE_SHIFT-10))
        );

    boot_cpu_data.wp_works_ok = 1;
}

void free_initmem(void)
{
    unsigned long addr;

    addr = (unsigned long)(&__init_begin);
    for (; addr < (unsigned long)(&__init_end); addr += PAGE_SIZE) {
        ClearPageReserved(virt_to_page(addr));
        set_page_count(virt_to_page(addr), 1);
        free_page(addr);
        totalram_pages++;
    }
    printk ("Freeing unused kernel memory: %dk freed\n", (&__init_end - &__init_begin) >> 10);
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
    if (start < end)
        printk ("Freeing initrd memory: %ldk freed\n", (end - start) >> 10);
    for (; start < end; start += PAGE_SIZE) {
        ClearPageReserved(virt_to_page(start));
        set_page_count(virt_to_page(start), 1);
        free_page(start);
        totalram_pages++;
    }
}
#endif

void si_meminfo(struct sysinfo *val)
{
    val->totalram = totalram_pages;
    val->sharedram = 0;
    val->freeram = nr_free_pages();
    val->bufferram = atomic_read(&buffermem_pages);
    val->totalhigh = totalhigh_pages;
    val->freehigh = nr_free_highpages();
    val->mem_unit = PAGE_SIZE;
    return;
}
