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
extern char _text, _etext, _edata, _end;


/*********************
 * ALLOCATION BITMAP
 *  One bit per page of memory. Bit set => page is allocated.
 */

static unsigned long *alloc_bitmap;
#define PAGES_PER_MAPWORD (sizeof(unsigned long) * 8)

#define allocated_in_map(_pn) \
(alloc_bitmap[(_pn)/PAGES_PER_MAPWORD] & (1<<((_pn)&(PAGES_PER_MAPWORD-1))))


/*
 * Hint regarding bitwise arithmetic in map_{alloc,free}:
 *  -(1<<n)  sets all bits >= n. 
 *  (1<<n)-1 sets all bits <  n.
 * Variable names in map_{alloc,free}:
 *  *_idx == Index into `alloc_bitmap' array.
 *  *_off == Bit offset within an element of the `alloc_bitmap' array.
 */

static void map_alloc(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

    curr_idx  = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] |= ((1<<end_off)-1) & -(1<<start_off);
    }
    else 
    {
        alloc_bitmap[curr_idx] |= -(1<<start_off);
        while ( ++curr_idx < end_idx ) alloc_bitmap[curr_idx] = ~0L;
        alloc_bitmap[curr_idx] |= (1<<end_off)-1;
    }
}


static void map_free(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

    curr_idx = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] &= -(1<<end_off) | ((1<<start_off)-1);
    }
    else 
    {
        alloc_bitmap[curr_idx] &= (1<<start_off)-1;
        while ( ++curr_idx != end_idx ) alloc_bitmap[curr_idx] = 0;
        alloc_bitmap[curr_idx] &= -(1<<end_off);
    }
}



/*************************
 * BINARY BUDDY ALLOCATOR
 */

typedef struct chunk_head_st chunk_head_t;
typedef struct chunk_tail_st chunk_tail_t;

struct chunk_head_st {
    chunk_head_t  *next;
    chunk_head_t **pprev;
    int            level;
};

struct chunk_tail_st {
    int level;
};

/* Linked lists of free chunks of different powers-of-two in size. */
#define FREELIST_SIZE ((sizeof(void*)<<3)-PAGE_SHIFT)
static chunk_head_t *free_head[FREELIST_SIZE];
static chunk_head_t  free_tail[FREELIST_SIZE];
#define FREELIST_EMPTY(_l) ((_l)->next == NULL)

#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

#ifdef MM_DEBUG
/*
 * Prints allocation[0/1] for @nr_pages, starting at @start
 * address (virtual).
 */
static void print_allocation(void *start, int nr_pages)
{
    unsigned long pfn_start = virt_to_pfn(start);
    int count;
    for(count = 0; count < nr_pages; count++)
        if(allocated_in_map(pfn_start + count)) printk("1");
        else printk("0");
        
    printk("\n");        
}

/*
 * Prints chunks (making them with letters) for @nr_pages starting
 * at @start (virtual).
 */
static void print_chunks(void *start, int nr_pages)
{
    char chunks[1001], current='A';
    int order, count;
    chunk_head_t *head;
    unsigned long pfn_start = virt_to_pfn(start);
   
    memset(chunks, (int)'_', 1000);
    if(nr_pages > 1000) 
    {
        DEBUG("Can only pring 1000 pages. Increase buffer size.");
    }
    
    for(order=0; order < FREELIST_SIZE; order++)
    {
        head = free_head[order];
        while(!FREELIST_EMPTY(head))
        {
            for(count = 0; count < 1<< head->level; count++)
            {
                if(count + virt_to_pfn(head) - pfn_start < 1000)
                    chunks[count + virt_to_pfn(head) - pfn_start] = current;
            }
            head = head->next;
            current++;
        }
    }
    chunks[nr_pages] = '\0';
    printk("%s\n", chunks);
}
#endif



/*
 * Initialise allocator, placing addresses [@min,@max] in free pool.
 * @min and @max are PHYSICAL addresses.
 */
static void init_page_allocator(unsigned long min, unsigned long max)
{
    int i;
    unsigned long range, bitmap_size;
    chunk_head_t *ch;
    chunk_tail_t *ct;

    for ( i = 0; i < FREELIST_SIZE; i++ )
    {
        free_head[i]       = &free_tail[i];
        free_tail[i].pprev = &free_head[i];
        free_tail[i].next  = NULL;
    }

    min = round_pgup  (min);
    max = round_pgdown(max);

    /* Allocate space for the allocation bitmap. */
    bitmap_size  = (max+1) >> (PAGE_SHIFT+3);
    bitmap_size  = round_pgup(bitmap_size);
    alloc_bitmap = (unsigned long *)to_virt(min);
    min         += bitmap_size;
    range        = max - min;

    /* All allocated by default. */
    memset(alloc_bitmap, ~0, bitmap_size);
    /* Free up the memory we've been given to play with. */
    map_free(min>>PAGE_SHIFT, range>>PAGE_SHIFT);

    /* The buddy lists are addressed in high memory. */
    min += VIRT_START;
    max += VIRT_START;

    while ( range != 0 )
    {
        /*
         * Next chunk is limited by alignment of min, but also
         * must not be bigger than remaining range.
         */
        for ( i = PAGE_SHIFT; (1<<(i+1)) <= range; i++ )
            if ( min & (1<<i) ) break;


        ch = (chunk_head_t *)min;
        min   += (1<<i);
        range -= (1<<i);
        ct = (chunk_tail_t *)min-1;
        i -= PAGE_SHIFT;
        ch->level       = i;
        ch->next        = free_head[i];
        ch->pprev       = &free_head[i];
        ch->next->pprev = &ch->next;
        free_head[i]    = ch;
        ct->level       = i;
    }
}


/* Allocate 2^@order contiguous pages. Returns a VIRTUAL address. */
unsigned long alloc_pages(int order)
{
    int i;
    chunk_head_t *alloc_ch, *spare_ch;
    chunk_tail_t            *spare_ct;


    /* Find smallest order which can satisfy the request. */
    for ( i = order; i < FREELIST_SIZE; i++ ) {
	if ( !FREELIST_EMPTY(free_head[i]) ) 
	    break;
    }

    if ( i == FREELIST_SIZE ) goto no_memory;
 
    /* Unlink a chunk. */
    alloc_ch = free_head[i];
    free_head[i] = alloc_ch->next;
    alloc_ch->next->pprev = alloc_ch->pprev;

    /* We may have to break the chunk a number of times. */
    while ( i != order )
    {
        /* Split into two equal parts. */
        i--;
        spare_ch = (chunk_head_t *)((char *)alloc_ch + (1<<(i+PAGE_SHIFT)));
        spare_ct = (chunk_tail_t *)((char *)spare_ch + (1<<(i+PAGE_SHIFT)))-1;

        /* Create new header for spare chunk. */
        spare_ch->level = i;
        spare_ch->next  = free_head[i];
        spare_ch->pprev = &free_head[i];
        spare_ct->level = i;

        /* Link in the spare chunk. */
        spare_ch->next->pprev = &spare_ch->next;
        free_head[i] = spare_ch;
    }
    
    map_alloc(to_phys(alloc_ch)>>PAGE_SHIFT, 1<<order);

    return((unsigned long)alloc_ch);

 no_memory:

    printk("Cannot handle page request order %d!\n", order);

    return 0;
}

void free_pages(void *pointer, int order)
{
    chunk_head_t *freed_ch, *to_merge_ch;
    chunk_tail_t *freed_ct;
    unsigned long mask;
    
    /* First free the chunk */
    map_free(virt_to_pfn(pointer), 1 << order);
    
    /* Create free chunk */
    freed_ch = (chunk_head_t *)pointer;
    freed_ct = (chunk_tail_t *)((char *)pointer + (1<<(order + PAGE_SHIFT)))-1;
    
    /* Now, possibly we can conseal chunks together */
    while(order < FREELIST_SIZE)
    {
        mask = 1 << (order + PAGE_SHIFT);
        if((unsigned long)freed_ch & mask) 
        {
            to_merge_ch = (chunk_head_t *)((char *)freed_ch - mask);
            if(allocated_in_map(virt_to_pfn(to_merge_ch)) ||
                    to_merge_ch->level != order)
                break;
            
            /* Merge with predecessor */
            freed_ch = to_merge_ch;   
        }
        else 
        {
            to_merge_ch = (chunk_head_t *)((char *)freed_ch + mask);
            if(allocated_in_map(virt_to_pfn(to_merge_ch)) ||
                    to_merge_ch->level != order)
                break;
            
            /* Merge with successor */
            freed_ct = (chunk_tail_t *)((char *)to_merge_ch + mask);
        }
        
        /* We are commited to merging, unlink the chunk */
        *(to_merge_ch->pprev) = to_merge_ch->next;
        to_merge_ch->next->pprev = to_merge_ch->pprev;
        
        order++;
    }

    /* Link the new chunk */
    freed_ch->level = order;
    freed_ch->next  = free_head[order];
    freed_ch->pprev = &free_head[order];
    freed_ct->level = order;
    
    freed_ch->next->pprev = &freed_ch->next;
    free_head[order] = freed_ch;   
   
}
void build_pagetable(unsigned long *start_pfn, unsigned long *max_pfn)
{
    unsigned long pfn_to_map, pt_frame;
    unsigned long mach_ptd, max_mach_ptd;
    int count;
    unsigned long mach_pte, virt_pte;
    unsigned long *ptd = (unsigned long *)start_info.pt_base;
    mmu_update_t mmu_updates[L1_PAGETABLE_ENTRIES + 1];
    struct mmuext_op pin_request;
    
    /* Firstly work out what is the first pfn that is not yet in page tables
       NB. Assuming that builder fills whole pt_frames (which it does at the
       moment)
     */  
    pfn_to_map = (start_info.nr_pt_frames - 1) * L1_PAGETABLE_ENTRIES;
    DEBUG("start_pfn=%ld, first pfn_to_map %ld, max_pfn=%ld", 
            *start_pfn, pfn_to_map, *max_pfn);

    /* Machine address of page table directory */
    mach_ptd = phys_to_machine(to_phys(start_info.pt_base));
    mach_ptd += sizeof(void *) * 
        l2_table_offset((unsigned long)to_virt(PFN_PHYS(pfn_to_map)));
  
    max_mach_ptd = sizeof(void *) * 
        l2_table_offset((unsigned long)to_virt(PFN_PHYS(*max_pfn)));
    
    /* Check that we are not trying to access Xen region */
    if(max_mach_ptd > sizeof(void *) * l2_table_offset(HYPERVISOR_VIRT_START))
    {
        printk("WARNING: mini-os will not use all the memory supplied\n");
        max_mach_ptd = sizeof(void *) * l2_table_offset(HYPERVISOR_VIRT_START);
        *max_pfn = virt_to_pfn(HYPERVISOR_VIRT_START - PAGE_SIZE);
    }
    max_mach_ptd += phys_to_machine(to_phys(start_info.pt_base));
    DEBUG("Max_mach_ptd 0x%lx", max_mach_ptd); 
   
    pt_frame = *start_pfn;
    /* Should not happen - no empty, mapped pages */
    if(pt_frame >= pfn_to_map)
    {
        printk("ERROR: Not even a single empty, mapped page\n");
        *(int*)0=0;
    }
    
    while(mach_ptd < max_mach_ptd)
    {
        /* Correct protection needs to be set for the new page table frame */
        virt_pte = (unsigned long)to_virt(PFN_PHYS(pt_frame));
        mach_pte = ptd[l2_table_offset(virt_pte)] & ~(PAGE_SIZE-1);
        mach_pte += sizeof(void *) * l1_table_offset(virt_pte);
        DEBUG("New page table page: pfn=0x%lx, mfn=0x%lx, virt_pte=0x%lx, "
                "mach_pte=0x%lx", pt_frame, pfn_to_mfn(pt_frame), 
                virt_pte, mach_pte);
        
        /* Update the entry */
        mmu_updates[0].ptr = mach_pte;
        mmu_updates[0].val = pfn_to_mfn(pt_frame) << PAGE_SHIFT | 
                                                    (L1_PROT & ~_PAGE_RW);
        if(HYPERVISOR_mmu_update(mmu_updates, 1, NULL, DOMID_SELF) < 0)
        {
            printk("PTE for new page table page could not be updated\n");
            *(int*)0=0;
        }
        
        /* Pin the page to provide correct protection */
        pin_request.cmd = MMUEXT_PIN_L1_TABLE;
        pin_request.mfn = pfn_to_mfn(pt_frame);
        if(HYPERVISOR_mmuext_op(&pin_request, 1, NULL, DOMID_SELF) < 0)
        {
            printk("ERROR: pinning failed\n");
            *(int*)0=0;
        }
        
        /* Now fill the new page table page with entries.
           Update the page directory as well. */
        count = 0;
        mmu_updates[count].ptr = mach_ptd;
        mmu_updates[count].val = pfn_to_mfn(pt_frame) << PAGE_SHIFT |
                                                         L2_PROT;
        count++;
        mach_ptd += sizeof(void *);
        mach_pte = phys_to_machine(PFN_PHYS(pt_frame++));
        
        for(;count <= L1_PAGETABLE_ENTRIES && pfn_to_map <= *max_pfn; count++)
        {
            mmu_updates[count].ptr = mach_pte;
            mmu_updates[count].val = 
                pfn_to_mfn(pfn_to_map++) << PAGE_SHIFT | L1_PROT;
            if(count == 1) DEBUG("mach_pte 0x%lx", mach_pte);
            mach_pte += sizeof(void *);
        }
        if(HYPERVISOR_mmu_update(mmu_updates, count, NULL, DOMID_SELF) < 0) 
        {            
            printk("ERROR: mmu_update failed\n");
            *(int*)0=0;
        }
        (*start_pfn)++;
    }

    *start_pfn = pt_frame;
}

void init_mm(void)
{

    unsigned long start_pfn, max_pfn;

    printk("MM: Init\n");

    printk("  _text:        %p\n", &_text);
    printk("  _etext:       %p\n", &_etext);
    printk("  _edata:       %p\n", &_edata);
    printk("  stack start:  %p\n", &stack);
    printk("  _end:         %p\n", &_end);

    /* set up minimal memory infos */
    phys_to_machine_mapping = (unsigned long *)start_info.mfn_list;
   
    /* First page follows page table pages and 3 more pages (store page etc) */
    start_pfn = PFN_UP(__pa(start_info.pt_base)) + start_info.nr_pt_frames + 3;
    max_pfn = start_info.nr_pages;

    printk("  start_pfn:    %lx\n", start_pfn);
    printk("  max_pfn:      %lx\n", max_pfn);


    build_pagetable(&start_pfn, &max_pfn);
    
#ifdef __i386__
    /*
     * now we can initialise the page allocator
     */
    printk("MM: Initialise page allocator for %lx(%lx)-%lx(%lx)\n",
           (u_long)to_virt(PFN_PHYS(start_pfn)), PFN_PHYS(start_pfn), 
           (u_long)to_virt(PFN_PHYS(max_pfn)), PFN_PHYS(max_pfn));
    init_page_allocator(PFN_PHYS(start_pfn), PFN_PHYS(max_pfn));   
#endif
    
    printk("MM: done\n");
}
