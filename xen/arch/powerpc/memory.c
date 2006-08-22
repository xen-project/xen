/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Dan Poff <poff@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */
#include <xen/sched.h>
#include <xen/mm.h>
#include "of-devtree.h"
#include "oftree.h"

unsigned long xenheap_phys_end;
struct membuf {
    ulong start;
    ulong size;
};

typedef void (*walk_mem_fn)(struct membuf *, uint);

static ulong free_xenheap(ulong start, ulong end)
{
    start = ALIGN_UP(start, PAGE_SIZE);
    end = ALIGN_DOWN(end, PAGE_SIZE);

    printk("%s: 0x%lx - 0x%lx\n", __func__, start, end);

    if (oftree <= end && oftree >= start) {
        printk("%s:     Go around the devtree: 0x%lx - 0x%lx\n",
               __func__, oftree, oftree_end);
        init_xenheap_pages(start, ALIGN_DOWN(oftree, PAGE_SIZE));
        init_xenheap_pages(ALIGN_UP(oftree_end, PAGE_SIZE), end);
    } else {
        init_xenheap_pages(start, end);
    }

    return ALIGN_UP(end, PAGE_SIZE);
}

static void set_max_page(struct membuf *mb, uint entries)
{
    int i;

    for (i = 0; i < entries; i++) {
        ulong end_page;

        end_page = (mb[i].start + mb[i].size) >> PAGE_SHIFT;

        if (end_page > max_page)
            max_page = end_page;
    }
}

/* mark all memory from modules onward as unused, skipping hole(s),
 * and returning size of hole(s) */
static void heap_init(struct membuf *mb, uint entries)
{
    int i;
    ulong start_blk;
    ulong end_blk = 0;

	for (i = 0; i < entries; i++) {
	    start_blk = mb[i].start;
	    end_blk = start_blk + mb[i].size;

	    if (start_blk < xenheap_phys_end) {
            if (xenheap_phys_end > end_blk) {
                panic("xenheap spans LMB\n");
            }
            if (xenheap_phys_end == end_blk)
                continue;

            start_blk = xenheap_phys_end;
        }

        init_boot_pages(start_blk, end_blk);
        total_pages += (end_blk - start_blk) >> PAGE_SHIFT;
	}
}

static void ofd_walk_mem(void *m, walk_mem_fn fn)
{
    ofdn_t n;
    uint p_len;
    struct membuf mb[8];
    static char name[] = "memory";

    n = ofd_node_find_by_prop(m, OFD_ROOT, "device_type", name, sizeof(name));
    while (n > 0) {

        p_len = ofd_getprop(m, n, "reg", mb, sizeof (mb));
        if (p_len <= 0) {
            panic("ofd_getprop(): failed\n");
        }
        if (p_len > sizeof(mb))
            panic("%s: buffer is not big enuff for this firmware: "
                  "0x%lx < 0x%x\n", __func__, sizeof(mb), p_len);

        fn(mb, p_len / sizeof(mb[0]));
        n = ofd_node_find_next(m, n);
    }
}

static void setup_xenheap(module_t *mod, int mcount)
{
    int i;
    ulong freemem;

    freemem = ALIGN_UP((ulong)_end, PAGE_SIZE);

    for (i = 0; i < mcount; i++) {
        u32 s;

        if(mod[i].mod_end == mod[i].mod_start)
            continue;

        s = ALIGN_DOWN(mod[i].mod_start, PAGE_SIZE);

        if (mod[i].mod_start > (ulong)_start &&
            mod[i].mod_start < (ulong)_end) {
            /* mod was linked in */
            continue;
        }

        if (s < freemem) 
            panic("module addresses must assend\n");

        free_xenheap(freemem, s);
        freemem = ALIGN_UP(mod[i].mod_end, PAGE_SIZE);
        
    }

    /* the rest of the xenheap, starting at the end of modules */
    free_xenheap(freemem, xenheap_phys_end);
}

void memory_init(module_t *mod, int mcount)
{
    ulong eomem;
    ulong heap_start, heap_size;

    printk("Physical RAM map:\n");

    /* lets find out how much memory there is and set max_page */
    max_page = 0;
    ofd_walk_mem((void *)oftree, set_max_page);
    eomem = max_page << PAGE_SHIFT;

    if (eomem == 0){
        panic("ofd_walk_mem() failed\n");
    }
    printk("End of RAM: %luMB (%lukB)\n", eomem >> 20, eomem >> 10);

    /* Architecturally the first 4 pages are exception hendlers, we
     * will also be copying down some code there */
    heap_start = 4 << PAGE_SHIFT;
    if (oftree < (ulong)_start)
        heap_start = ALIGN_UP(oftree_end, PAGE_SIZE);

    heap_start = init_boot_allocator(heap_start);
    if (heap_start > (ulong)_start) {
        panic("space below _start (%p) is not enough memory "
              "for heap (0x%lx)\n", _start, heap_start);
    }

    /* we give the first RMA to the hypervisor */
    xenheap_phys_end = rma_size(cpu_rma_order());

    /* allow everything else to be allocated */
    total_pages = 0;
    ofd_walk_mem((void *)oftree, heap_init);
    if (total_pages == 0)
        panic("heap_init: failed");

    if (total_pages > max_page)
        panic("total_pages > max_page: 0x%lx > 0x%lx\n",
              total_pages, max_page);

    printk("total_pages: 0x%016lx\n", total_pages);

    init_frametable();
    end_boot_allocator();

    /* Add memory between the beginning of the heap and the beginning
     * of out text */
    free_xenheap(heap_start, (ulong)_start);

    heap_size = xenheap_phys_end - heap_start;
    printk("Xen heap: %luMB (%lukB)\n", heap_size >> 20, heap_size >> 10);

    setup_xenheap(mod, mcount);

    eomem = avail_domheap_pages();
    printk("Domheap pages: 0x%lx %luMB (%lukB)\n", eomem,
           (eomem << PAGE_SHIFT) >> 20,
           (eomem << PAGE_SHIFT) >> 10);
}
