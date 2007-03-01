/* 
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: mm.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: Grzegorz Milos
 *              
 *        Date: Aug 2003, chages Aug 2005
 * 
 * Environment: Xen Minimal OS
 * Description: memory management related functions
 *              contains buddy page allocator from Xen.
 *
 ****************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>
#include <mm.h>
#include <types.h>
#include <lib.h>
#include <xmalloc.h>

#ifdef MM_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=mm.c, line=%d) " _f "\n", __LINE__, ## _a)
#else
#define DEBUG(_f, _a...)    ((void)0)
#endif

unsigned long *phys_to_machine_mapping;
extern char *stack;
extern void page_walk(unsigned long virt_addr);

void new_pt_frame(unsigned long *pt_pfn, unsigned long prev_l_mfn, 
                                unsigned long offset, unsigned long level)
{   
    pgentry_t *tab = (pgentry_t *)start_info.pt_base;
    unsigned long pt_page = (unsigned long)pfn_to_virt(*pt_pfn); 
    unsigned long prot_e, prot_t, pincmd;
    mmu_update_t mmu_updates[1];
    struct mmuext_op pin_request;
    
    prot_e = prot_t = pincmd = 0;
    DEBUG("Allocating new L%d pt frame for pt_pfn=%lx, "
           "prev_l_mfn=%lx, offset=%lx", 
           level, *pt_pfn, prev_l_mfn, offset);

    /* We need to clear the page, otherwise we might fail to map it
       as a page table page */
    memset((unsigned long*)pfn_to_virt(*pt_pfn), 0, PAGE_SIZE);  
 
    switch ( level )
    {
    case L1_FRAME:
         prot_e = L1_PROT;
         prot_t = L2_PROT;
         pincmd = MMUEXT_PIN_L1_TABLE;
         break;
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    case L2_FRAME:
         prot_e = L2_PROT;
         prot_t = L3_PROT;
         pincmd = MMUEXT_PIN_L2_TABLE;
         break;
#endif
#if defined(__x86_64__)
    case L3_FRAME:
         prot_e = L3_PROT;
         prot_t = L4_PROT;
         pincmd = MMUEXT_PIN_L3_TABLE;
         break;
#endif
    default:
         printk("new_pt_frame() called with invalid level number %d\n", level);
         do_exit();
         break;
    }

    /* Update the entry */
#if defined(__x86_64__)
    tab = pte_to_virt(tab[l4_table_offset(pt_page)]);
    tab = pte_to_virt(tab[l3_table_offset(pt_page)]);
#endif
#if defined(CONFIG_X86_PAE)
    tab = pte_to_virt(tab[l3_table_offset(pt_page)]);
#endif

    mmu_updates[0].ptr = ((pgentry_t)tab[l2_table_offset(pt_page)] & PAGE_MASK) + 
                         sizeof(pgentry_t) * l1_table_offset(pt_page);
    mmu_updates[0].val = (pgentry_t)pfn_to_mfn(*pt_pfn) << PAGE_SHIFT | 
                         (prot_e & ~_PAGE_RW);
    if(HYPERVISOR_mmu_update(mmu_updates, 1, NULL, DOMID_SELF) < 0)
    {
         printk("PTE for new page table page could not be updated\n");
         do_exit();
    }
                        
    /* Pin the page to provide correct protection */
    pin_request.cmd = pincmd;
    pin_request.arg1.mfn = pfn_to_mfn(*pt_pfn);
    if(HYPERVISOR_mmuext_op(&pin_request, 1, NULL, DOMID_SELF) < 0)
    {
        printk("ERROR: pinning failed\n");
        do_exit();
    }

    /* Now fill the new page table page with entries.
       Update the page directory as well. */
    mmu_updates[0].ptr = ((pgentry_t)prev_l_mfn << PAGE_SHIFT) + sizeof(pgentry_t) * offset;
    mmu_updates[0].val = (pgentry_t)pfn_to_mfn(*pt_pfn) << PAGE_SHIFT | prot_t;
    if(HYPERVISOR_mmu_update(mmu_updates, 1, NULL, DOMID_SELF) < 0) 
    {
       printk("ERROR: mmu_update failed\n");
       do_exit();
    }

    *pt_pfn += 1;
}

/* Checks if a pagetable frame is needed (if weren't allocated by Xen) */
static int need_pt_frame(unsigned long virt_address, int level)
{
    unsigned long hyp_virt_start = HYPERVISOR_VIRT_START;
#if defined(__x86_64__)
    unsigned long hyp_virt_end = HYPERVISOR_VIRT_END;
#else
    unsigned long hyp_virt_end = 0xffffffff;
#endif

    /* In general frames will _not_ be needed if they were already
       allocated to map the hypervisor into our VA space */
#if defined(__x86_64__)
    if(level == L3_FRAME)
    {
        if(l4_table_offset(virt_address) >= 
           l4_table_offset(hyp_virt_start) &&
           l4_table_offset(virt_address) <= 
           l4_table_offset(hyp_virt_end))
            return 0;
        return 1;
    } else
#endif

#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    if(level == L2_FRAME)
    {
#if defined(__x86_64__)
        if(l4_table_offset(virt_address) >= 
           l4_table_offset(hyp_virt_start) &&
           l4_table_offset(virt_address) <= 
           l4_table_offset(hyp_virt_end))
#endif
            if(l3_table_offset(virt_address) >= 
               l3_table_offset(hyp_virt_start) &&
               l3_table_offset(virt_address) <= 
               l3_table_offset(hyp_virt_end))
                return 0;

        return 1;
    } else 
#endif /* defined(__x86_64__) || defined(CONFIG_X86_PAE) */

    /* Always need l1 frames */
    if(level == L1_FRAME)
        return 1;

    printk("ERROR: Unknown frame level %d, hypervisor %llx,%llx\n", 
        level, hyp_virt_start, hyp_virt_end);
    return -1;
}

void build_pagetable(unsigned long *start_pfn, unsigned long *max_pfn)
{
    unsigned long start_address, end_address;
    unsigned long pfn_to_map, pt_pfn = *start_pfn;
    static mmu_update_t mmu_updates[L1_PAGETABLE_ENTRIES + 1];
    pgentry_t *tab = (pgentry_t *)start_info.pt_base, page;
    unsigned long mfn = pfn_to_mfn(virt_to_pfn(start_info.pt_base));
    unsigned long offset;
    int count = 0;

    pfn_to_map = (start_info.nr_pt_frames - NOT_L1_FRAMES) * L1_PAGETABLE_ENTRIES;

    if (*max_pfn >= virt_to_pfn(HYPERVISOR_VIRT_START))
    {
        printk("WARNING: Mini-OS trying to use Xen virtual space. "
               "Truncating memory from %dMB to ",
               ((unsigned long)pfn_to_virt(*max_pfn) - (unsigned long)&_text)>>20);
        *max_pfn = virt_to_pfn(HYPERVISOR_VIRT_START - PAGE_SIZE);
        printk("%dMB\n",
               ((unsigned long)pfn_to_virt(*max_pfn) - (unsigned long)&_text)>>20);
    }

    start_address = (unsigned long)pfn_to_virt(pfn_to_map);
    end_address = (unsigned long)pfn_to_virt(*max_pfn);

    /* We worked out the virtual memory range to map, now mapping loop */
    printk("Mapping memory range 0x%lx - 0x%lx\n", start_address, end_address);

    while(start_address < end_address)
    {
        tab = (pgentry_t *)start_info.pt_base;
        mfn = pfn_to_mfn(virt_to_pfn(start_info.pt_base));

#if defined(__x86_64__)
        offset = l4_table_offset(start_address);
        /* Need new L3 pt frame */
        if(!(start_address & L3_MASK)) 
            if(need_pt_frame(start_address, L3_FRAME)) 
                new_pt_frame(&pt_pfn, mfn, offset, L3_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
        offset = l3_table_offset(start_address);
        /* Need new L2 pt frame */
        if(!(start_address & L2_MASK))
            if(need_pt_frame(start_address, L2_FRAME))
                new_pt_frame(&pt_pfn, mfn, offset, L2_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
        offset = l2_table_offset(start_address);        
        /* Need new L1 pt frame */
        if(!(start_address & L1_MASK))
            if(need_pt_frame(start_address, L1_FRAME)) 
                new_pt_frame(&pt_pfn, mfn, offset, L1_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        offset = l1_table_offset(start_address);

        mmu_updates[count].ptr = ((pgentry_t)mfn << PAGE_SHIFT) + sizeof(pgentry_t) * offset;
        mmu_updates[count].val = (pgentry_t)pfn_to_mfn(pfn_to_map++) << PAGE_SHIFT | L1_PROT;
        count++;
        if (count == L1_PAGETABLE_ENTRIES || pfn_to_map == *max_pfn)
        {
            if(HYPERVISOR_mmu_update(mmu_updates, count, NULL, DOMID_SELF) < 0)
            {
                printk("PTE could not be updated\n");
                do_exit();
            }
            count = 0;
        }
        start_address += PAGE_SIZE;
    }

    *start_pfn = pt_pfn;
}


void mem_test(unsigned long *start_add, unsigned long *end_add)
{
    unsigned long mask = 0x10000;
    unsigned long *pointer;

    for(pointer = start_add; pointer < end_add; pointer++)
    {
        if(!(((unsigned long)pointer) & 0xfffff))
        {
            printk("Writing to %lx\n", pointer);
            page_walk((unsigned long)pointer);
        }
        *pointer = (unsigned long)pointer & ~mask;
    }

    for(pointer = start_add; pointer < end_add; pointer++)
    {
        if(((unsigned long)pointer & ~mask) != *pointer)
            printk("Read error at 0x%lx. Read: 0x%lx, should read 0x%lx\n",
                (unsigned long)pointer, 
                *pointer, 
                ((unsigned long)pointer & ~mask));
    }

}

static pgentry_t *demand_map_pgt;
static void *demand_map_area_start;

void arch_init_demand_mapping_area(unsigned long max_pfn)
{
    unsigned long mfn;
    pgentry_t *tab;
    unsigned long start_addr;
    unsigned long pt_pfn;
    unsigned offset;

    /* Round up to four megs.  + 1024 rather than + 1023 since we want
       to be sure we don't end up in the same place we started. */
    max_pfn = (max_pfn + L1_PAGETABLE_ENTRIES) & ~(L1_PAGETABLE_ENTRIES - 1);
    if (max_pfn == 0 ||
            (unsigned long)pfn_to_virt(max_pfn + L1_PAGETABLE_ENTRIES) >=
            HYPERVISOR_VIRT_START) {
        printk("Too much memory; no room for demand map hole.\n");
        do_exit();
    }

    demand_map_area_start = pfn_to_virt(max_pfn);
    printk("Demand map pfns start at %lx (%p).\n", max_pfn,
            demand_map_area_start);
    start_addr = (unsigned long)demand_map_area_start;

    tab = (pgentry_t *)start_info.pt_base;
    mfn = virt_to_mfn(start_info.pt_base);
    pt_pfn = virt_to_pfn(alloc_page());

#if defined(__x86_64__)
    offset = l4_table_offset(start_addr);
    if (!(tab[offset] & _PAGE_PRESENT)) {
        new_pt_frame(&pt_pfn, mfn, offset, L3_FRAME);
        pt_pfn = virt_to_pfn(alloc_page());
    }
    ASSERT(tab[offset] & _PAGE_PRESENT);
    mfn = pte_to_mfn(tab[offset]);
    tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    offset = l3_table_offset(start_addr);
    if (!(tab[offset] & _PAGE_PRESENT)) {
        new_pt_frame(&pt_pfn, mfn, offset, L2_FRAME);
        pt_pfn = virt_to_pfn(alloc_page());
    }
    ASSERT(tab[offset] & _PAGE_PRESENT);
    mfn = pte_to_mfn(tab[offset]);
    tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
    offset = l2_table_offset(start_addr);
    if (tab[offset] & _PAGE_PRESENT) {
        printk("Demand map area already has a page table covering it?\n");
        BUG();
    }
    demand_map_pgt = pfn_to_virt(pt_pfn);
    new_pt_frame(&pt_pfn, mfn, offset, L1_FRAME);
    ASSERT(tab[offset] & _PAGE_PRESENT);
    printk("Initialised demand area.\n");
}

void *map_frames(unsigned long *f, unsigned long n)
{
    unsigned long x;
    unsigned long y = 0;
    mmu_update_t mmu_updates[16];
    int rc;

    if (n > 16) {
        printk("Tried to map too many (%ld) frames at once.\n", n);
        return NULL;
    }

    /* Find a run of n contiguous frames */
    for (x = 0; x <= 1024 - n; x += y + 1) {
        for (y = 0; y < n; y++)
            if (demand_map_pgt[x+y] & _PAGE_PRESENT)
                break;
        if (y == n)
            break;
    }
    if (y != n) {
        printk("Failed to map %ld frames!\n", n);
        return NULL;
    }

    /* Found it at x.  Map it in. */
    for (y = 0; y < n; y++) {
        mmu_updates[y].ptr = virt_to_mach(&demand_map_pgt[x + y]);
        mmu_updates[y].val = (f[y] << PAGE_SHIFT) | L1_PROT;
    }

    rc = HYPERVISOR_mmu_update(mmu_updates, n, NULL, DOMID_SELF);
    if (rc < 0) {
        printk("Map %ld failed: %d.\n", n, rc);
        return NULL;
    } else {
        return (void *)(unsigned long)((unsigned long)demand_map_area_start +
                x * PAGE_SIZE);
    }
}


void arch_init_p2m(unsigned long max_pfn)
{
#define L1_P2M_SHIFT    10
#define L2_P2M_SHIFT    20    
#define L3_P2M_SHIFT    30    
#define L1_P2M_ENTRIES  (1 << L1_P2M_SHIFT)    
#define L2_P2M_ENTRIES  (1 << (L2_P2M_SHIFT - L1_P2M_SHIFT))    
#define L3_P2M_ENTRIES  (1 << (L3_P2M_SHIFT - L2_P2M_SHIFT))    
#define L1_P2M_MASK     (L1_P2M_ENTRIES - 1)    
#define L2_P2M_MASK     (L2_P2M_ENTRIES - 1)    
#define L3_P2M_MASK     (L3_P2M_ENTRIES - 1)    
    
    unsigned long *l1_list, *l2_list, *l3_list;
    unsigned long pfn;
    
    l3_list = (unsigned long *)alloc_page(); 
    for(pfn=0; pfn<max_pfn; pfn++)
    {
        if(!(pfn % (L1_P2M_ENTRIES * L2_P2M_ENTRIES)))
        {
            l2_list = (unsigned long*)alloc_page();
            if((pfn >> L3_P2M_SHIFT) > 0)
            {
                printk("Error: Too many pfns.\n");
                do_exit();
            }
            l3_list[(pfn >> L2_P2M_SHIFT)] = virt_to_mfn(l2_list);  
        }
        if(!(pfn % (L1_P2M_ENTRIES)))
        {
            l1_list = (unsigned long*)alloc_page();
            l2_list[(pfn >> L1_P2M_SHIFT) & L2_P2M_MASK] = 
                virt_to_mfn(l1_list); 
        }

        l1_list[pfn & L1_P2M_MASK] = pfn_to_mfn(pfn); 
    }
    HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list = 
        virt_to_mfn(l3_list);
    HYPERVISOR_shared_info->arch.max_pfn = max_pfn;
}

void arch_init_mm(unsigned long* start_pfn_p, unsigned long* max_pfn_p)
{

    unsigned long start_pfn, max_pfn;

    printk("  _text:        %p\n", &_text);
    printk("  _etext:       %p\n", &_etext);
    printk("  _edata:       %p\n", &_edata);
    printk("  stack start:  %p\n", &stack);
    printk("  _end:         %p\n", &_end);

    /* First page follows page table pages and 3 more pages (store page etc) */
    start_pfn = PFN_UP(to_phys(start_info.pt_base)) + 
                start_info.nr_pt_frames + 3;
    max_pfn = start_info.nr_pages;
   
    printk("  start_pfn:    %lx\n", start_pfn);
    printk("  max_pfn:      %lx\n", max_pfn);

    build_pagetable(&start_pfn, &max_pfn);

    *start_pfn_p = start_pfn;
    *max_pfn_p = max_pfn;
}

