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
#include <linux/slab.h>

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
 
/*
 * NOTE: pagetable_init alloc all the fixmap pagetables contiguous on the
 * physical space so we can cache the place of the first one and move
 * around without checking the pgd every time.
 */

#if CONFIG_HIGHMEM
pte_t *kmap_pte;
pgprot_t kmap_prot;

#define kmap_get_fixmap_pte(vaddr) \
    pte_offset(pmd_offset(pgd_offset_k(vaddr), (vaddr)), (vaddr))

void __init kmap_init(void)
{
    unsigned long kmap_vstart;

    /* cache the first kmap pte */
    kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
    kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

    kmap_prot = PAGE_KERNEL;
}
#endif /* CONFIG_HIGHMEM */

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
                                 unsigned long phys, pgprot_t prot)
{
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

    queue_l1_entry_update(pte, phys | pgprot_val(prot));

    /*
     * It's enough to flush this one mapping.
     * (PGE mappings get flushed as well)
     */
    __flush_tlb_one(vaddr);
}

void __set_fixmap(enum fixed_addresses idx, unsigned long phys, 
                  pgprot_t flags)
{
    unsigned long address = __fix_to_virt(idx);

    if (idx >= __end_of_fixed_addresses) {
        printk("Invalid __set_fixmap\n");
        return;
    }
    set_pte_phys(address, phys, flags);
}

void clear_fixmap(enum fixed_addresses idx)
{
    set_pte_phys(__fix_to_virt(idx), 0, __pgprot(0));
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
#if CONFIG_X86_PAE
        if (pgd_none(*pgd)) {
            pmd = (pmd_t *) alloc_bootmem_low_pages(PAGE_SIZE);
            set_pgd(pgd, __pgd(__pa(pmd) + 0x1));
            if (pmd != pmd_offset(pgd, 0))
                printk("PAE BUG #02!\n");
        }
        pmd = pmd_offset(pgd, vaddr);
#else
        pmd = (pmd_t *)pgd;
#endif
        for (; (j < PTRS_PER_PMD) && (vaddr != end); pmd++, j++) {
            if (pmd_none(*pmd)) {
                pte = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
                clear_page(pte);
                kpgd = pgd_offset_k((unsigned long)pte);
                kpmd = pmd_offset(kpgd, (unsigned long)pte);
                kpte = pte_offset(kpmd, (unsigned long)pte);
                queue_l1_entry_update(kpte,
                                      (*(unsigned long *)kpte)&~_PAGE_RW);

                set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte)));
            }
            vaddr += PMD_SIZE;
        }
        j = 0;
    }
	
    XEN_flush_page_update_queue();
}


static void __init pagetable_init (void)
{
    unsigned long vaddr, end;
    pgd_t *kpgd, *pgd, *pgd_base;
    int i, j, k;
    pmd_t *kpmd, *pmd;
    pte_t *kpte, *pte, *pte_base;

    /* create tables only for boot_pfn frames.  max_low_pfn may be sized for
     * pages yet to be allocated from the hypervisor, or it may be set
     * to override the xen_start_info amount of memory
     */
    int boot_pfn = min(xen_start_info.nr_pages,max_low_pfn);

    /*
     * This can be zero as well - no problem, in that case we exit
     * the loops anyway due to the PTRS_PER_* conditions.
     */
    end = (unsigned long)__va(boot_pfn *PAGE_SIZE);

    pgd_base = init_mm.pgd;
    i = __pgd_offset(PAGE_OFFSET);
    pgd = pgd_base + i;

    for (; i < PTRS_PER_PGD; pgd++, i++) {
        vaddr = i*PGDIR_SIZE;
        if (end && (vaddr >= end))
            break;
        pmd = (pmd_t *)pgd;
        for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
            vaddr = i*PGDIR_SIZE + j*PMD_SIZE;
            if (end && (vaddr >= end))
                break;

            /* Filled in for us already? */
            if ( pmd_val(*pmd) & _PAGE_PRESENT )
                continue;

            pte_base = pte = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);

            for (k = 0; k < PTRS_PER_PTE; pte++, k++) {
                vaddr = i*PGDIR_SIZE + j*PMD_SIZE + k*PAGE_SIZE;
                if (end && (vaddr >= end))
                    break;
                *pte = mk_pte_phys(__pa(vaddr), PAGE_KERNEL);
            }
            kpgd = pgd_offset_k((unsigned long)pte_base);
            kpmd = pmd_offset(kpgd, (unsigned long)pte_base);
            kpte = pte_offset(kpmd, (unsigned long)pte_base);
            queue_l1_entry_update(kpte,
                                  (*(unsigned long *)kpte)&~_PAGE_RW);
            set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte_base)));
            XEN_flush_page_update_queue();
        }
    }

    /*
     * Fixed mappings, only the page table structure has to be
     * created - mappings will be set by set_fixmap():
     */
    vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
    fixrange_init(vaddr, HYPERVISOR_VIRT_START, init_mm.pgd);

#if CONFIG_HIGHMEM
    /*
     * Permanent kmaps:
     */
    vaddr = PKMAP_BASE;
    fixrange_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, init_mm.pgd);

    pgd = init_mm.pgd + __pgd_offset(vaddr);
    pmd = pmd_offset(pgd, vaddr);
    pte = pte_offset(pmd, vaddr);
    pkmap_page_table = pte;
#endif
}

static void __init zone_sizes_init(void)
{
    unsigned long zones_size[MAX_NR_ZONES] = {0, 0, 0};
    unsigned int max_dma, high, low;

    max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
    low = max_low_pfn;
    high = highend_pfn;

    if (low < max_dma)
        zones_size[ZONE_DMA] = low;
    else {
        zones_size[ZONE_DMA] = max_dma;
        zones_size[ZONE_NORMAL] = low - max_dma;
#ifdef CONFIG_HIGHMEM
        zones_size[ZONE_HIGHMEM] = high - low;
#endif
    }
    free_area_init(zones_size);
}

void __init paging_init(void)
{
    pagetable_init();

    zone_sizes_init();
    /* Switch to the real shared_info page, and clear the dummy page. */
    set_fixmap(FIX_SHARED_INFO, xen_start_info.shared_info);
    HYPERVISOR_shared_info = (shared_info_t *)fix_to_virt(FIX_SHARED_INFO);
    memset(empty_zero_page, 0, sizeof(empty_zero_page));

#ifdef CONFIG_HIGHMEM
    kmap_init();
#endif
}

static inline int page_is_ram (unsigned long pagenr)
{
    return 1;
}

static inline int page_kills_ppro(unsigned long pagenr)
{
    return 0;
}

#ifdef CONFIG_HIGHMEM
void __init one_highpage_init(struct page *page, int pfn, int bad_ppro)
{
    if (!page_is_ram(pfn)) {
        SetPageReserved(page);
        return;
    }
	
    if (bad_ppro && page_kills_ppro(pfn)) {
        SetPageReserved(page);
        return;
    }
	
    ClearPageReserved(page);
    set_bit(PG_highmem, &page->flags);
    atomic_set(&page->count, 1);
    __free_page(page);
    totalhigh_pages++;
}
#endif /* CONFIG_HIGHMEM */

static void __init set_max_mapnr_init(void)
{
#ifdef CONFIG_HIGHMEM
    highmem_start_page = mem_map + highstart_pfn;
    max_mapnr = num_physpages = highend_pfn;
    num_mappedpages = max_low_pfn;
#else
    max_mapnr = num_mappedpages = num_physpages = max_low_pfn;
#endif
}

static int __init free_pages_init(void)
{
#ifdef CONFIG_HIGHMEM
    int bad_ppro = 0;
#endif
    int reservedpages, pfn;

    /* add only boot_pfn pages of low memory to free list.
     * max_low_pfn may be sized for
     * pages yet to be allocated from the hypervisor, or it may be set
     * to override the xen_start_info amount of memory
     */
    int boot_pfn = min(xen_start_info.nr_pages,max_low_pfn);

    /* this will put all low memory onto the freelists */
    totalram_pages += free_all_bootmem();

    reservedpages = 0;
    for (pfn = 0; pfn < boot_pfn ; pfn++) {
        /*
         * Only count reserved RAM pages
         */
        if (page_is_ram(pfn) && PageReserved(mem_map+pfn))
            reservedpages++;
    }
#ifdef CONFIG_HIGHMEM
    for (pfn = xen_start_info.nr_pages-1; pfn >= highstart_pfn; pfn--)
        one_highpage_init((struct page *) (mem_map + pfn), pfn, bad_ppro);
    totalram_pages += totalhigh_pages;
#endif
    return reservedpages;
}

void __init mem_init(void)
{
    int codesize, reservedpages, datasize, initsize;

    if (!mem_map)
        BUG();

#ifdef CONFIG_HIGHMEM
    /* check that fixmap and pkmap do not overlap */
    if (PKMAP_BASE+LAST_PKMAP*PAGE_SIZE >= FIXADDR_START) {
	printk(KERN_ERR "fixmap and kmap areas overlap - this will crash\n");
	printk(KERN_ERR "pkstart: %lxh pkend: %lxh fixstart %lxh\n",
	       PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE, FIXADDR_START);
	BUG();
    }
#endif

    set_max_mapnr_init();

    high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);

    /* clear the zero-page */
    memset(empty_zero_page, 0, PAGE_SIZE);

    reservedpages = free_pages_init();

    codesize =  (unsigned long) &_etext - (unsigned long) &_text;
    datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
    initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

    printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init, %ldk highmem)\n",
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
    printk (KERN_INFO "Freeing unused kernel memory: %dk freed\n", (&__init_end - &__init_begin) >> 10);
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
    if (start < end)
        printk (KERN_INFO "Freeing initrd memory: %ldk freed\n", (end - start) >> 10);
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
    val->totalram = max_pfn;
    val->sharedram = 0;
    val->freeram = nr_free_pages();
    val->bufferram = atomic_read(&buffermem_pages);
    val->totalhigh = max_pfn-max_low_pfn;
    val->freehigh = nr_free_highpages();
    val->mem_unit = PAGE_SIZE;
    return;
}

#if defined(CONFIG_X86_PAE)
struct kmem_cache_s *pae_pgd_cachep;
void __init pgtable_cache_init(void)
{
    /*
     * PAE pgds must be 16-byte aligned:
	 */
    pae_pgd_cachep = kmem_cache_create("pae_pgd", 32, 0,
                                       SLAB_HWCACHE_ALIGN | SLAB_MUST_HWCACHE_ALIGN, NULL, NULL);
    if (!pae_pgd_cachep)
        panic("init_pae(): Cannot alloc pae_pgd SLAB cache");
}
#endif /* CONFIG_X86_PAE */
