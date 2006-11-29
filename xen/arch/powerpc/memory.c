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
#include "rtas.h"

#undef DEBUG
#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
#else
#define DBG(fmt...)
#endif

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, excluding the
 * page_info table and allocation bitmap.
 */
static unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;
integer_param("xenheap_megabytes", opt_xenheap_megabytes);

unsigned long xenheap_phys_end;
static uint nr_pages;
static ulong xenheap_size;
static ulong save_start;
static ulong save_end;

struct membuf {
    ulong start;
    ulong size;
};

typedef void (*walk_mem_fn)(struct membuf *, uint);

static ulong free_xenheap(ulong start, ulong end)
{
    start = ALIGN_UP(start, PAGE_SIZE);
    end = ALIGN_DOWN(end, PAGE_SIZE);

    DBG("%s: 0x%lx - 0x%lx\n", __func__, start, end);

    /* need to do this better */
    if (save_start <= end && save_start >= start) {
        DBG("%s:     Go around the saved area: 0x%lx - 0x%lx\n",
               __func__, save_start, save_end);
        init_xenheap_pages(start, ALIGN_DOWN(save_start, PAGE_SIZE));
        xenheap_size += ALIGN_DOWN(save_start, PAGE_SIZE) - start;

        init_xenheap_pages(ALIGN_UP(save_end, PAGE_SIZE), end);
        xenheap_size += end - ALIGN_UP(save_end, PAGE_SIZE);
    } else {
        init_xenheap_pages(start, end);
        xenheap_size += end - start;
    }

    return ALIGN_UP(end, PAGE_SIZE);
}

static void set_max_page(struct membuf *mb, uint entries)
{
    int i;

    for (i = 0; i < entries; i++) {
        ulong end_page;

        printk("  %016lx: %016lx\n", mb[i].start, mb[i].size);
        nr_pages += mb[i].size >> PAGE_SHIFT;

        end_page = (mb[i].start + mb[i].size) >> PAGE_SHIFT;
        if (end_page > max_page)
            max_page = end_page;
    }
}

/* mark all memory from modules onward as unused */
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

        if (mod[i].mod_end == mod[i].mod_start)
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
    ulong heap_start;
    ulong xh_pages;

    /* lets find out how much memory there is and set max_page */
    max_page = 0;
    printk("Physical RAM map:\n");
    ofd_walk_mem((void *)oftree, set_max_page);
    eomem = max_page << PAGE_SHIFT;

    if (eomem == 0){
        panic("ofd_walk_mem() failed\n");
    }

    /* find the portion of memory we need to keep safe */
    save_start = oftree;
    save_end = oftree_end;
    if (rtas_base) {
        if (save_start > rtas_base)
            save_start = rtas_base;
        if (save_end < rtas_end)
            save_end = rtas_end;
    }

    /* minimum heap has to reach to the end of all Xen required memory */
    xh_pages = ALIGN_UP(save_end, PAGE_SIZE) >> PAGE_SHIFT;
    xh_pages += opt_xenheap_megabytes << (20 - PAGE_SHIFT);

    /* While we are allocating HTABS from The Xen Heap we need it to
     * be larger */
    xh_pages  += nr_pages >> 5;

    xenheap_phys_end = xh_pages << PAGE_SHIFT;
    printk("End of Xen Area: %luMiB (%luKiB)\n",
           xenheap_phys_end >> 20, xenheap_phys_end >> 10);

    printk("End of RAM: %luMiB (%luKiB)\n", eomem >> 20, eomem >> 10);

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

    /* allow everything else to be allocated */
    total_pages = 0;
    ofd_walk_mem((void *)oftree, heap_init);
    if (total_pages == 0)
        panic("heap_init: failed");

    if (total_pages > max_page)
        panic("total_pages > max_page: 0x%lx > 0x%lx\n",
              total_pages, max_page);

    DBG("total_pages: 0x%016lx\n", total_pages);

    init_frametable();
    end_boot_allocator();

    /* Add memory between the beginning of the heap and the beginning
     * of our text */
    free_xenheap(heap_start, (ulong)_start);
    setup_xenheap(mod, mcount);
    printk("Xen Heap: %luMiB (%luKiB)\n",
           xenheap_size >> 20, xenheap_size >> 10);

    eomem = avail_domheap_pages();
    printk("Dom Heap: %luMiB (%luKiB)\n",
           (eomem << PAGE_SHIFT) >> 20,
           (eomem << PAGE_SHIFT) >> 10);
}
