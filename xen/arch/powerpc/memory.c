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
 * Copyright IBM Corp. 2006, 2007
 *
 * Authors: Dan Poff <poff@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/numa.h>
#include "of-devtree.h"
#include "oftree.h"
#include "rtas.h"

#define DEBUG
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

struct membuf {
    ulong start;
    ulong size;
};

typedef void (*walk_mem_fn)(struct membuf *, uint);

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

        DBG("boot free: %016lx - %016lx\n", start_blk, end_blk);
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

void memory_init(module_t *mod, int mcount)
{
    ulong eomem;
    ulong bitmap_start = ~0UL;
    ulong bitmap_end;
    ulong bitmap_size;
    ulong xh_pages;
    ulong start;
    ulong end;
    int pos;

    /* lets find out how much memory there is and set max_page */
    max_page = 0;
    printk("Physical RAM map:\n");
    ofd_walk_mem((void *)oftree, set_max_page);
    eomem = max_page << PAGE_SHIFT;
    if (eomem == 0) {
        panic("ofd_walk_mem() failed\n");
    }

    xh_pages = opt_xenheap_megabytes << (20 - PAGE_SHIFT);

    /* While we are allocating HTABS from The Xen Heap we need it to
     * be larger */
    xh_pages += nr_pages >> 5;

    xenheap_phys_end = xh_pages << PAGE_SHIFT;
    printk("End of Xen Area: %luMiB (%luKiB)\n",
           xenheap_phys_end >> 20, xenheap_phys_end >> 10);

    printk("End of RAM: %luMiB (%luKiB)\n", eomem >> 20, eomem >> 10);

    /* The boot allocator requires one bit per page. Find a spot for it. */
    bitmap_size = max_page / 8;
    pos = boot_of_mem_avail(0, &start, &end);
    while (pos >= 0) {
        if (end - start >= bitmap_size) {
            bitmap_start = start;
            bitmap_end = init_boot_allocator(bitmap_start);
            printk("boot allocator @ %lx - %lx\n", bitmap_start, bitmap_end);
            break;
        }
        pos = boot_of_mem_avail(pos, &start, &end);
    }
    if (bitmap_start == ~0UL)
        panic("Couldn't find 0x%lx bytes for boot allocator.", bitmap_size);

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

    numa_initmem_init(0, max_page);

    /* Domain heap gets all the unclaimed memory. */
    end_boot_allocator();

    /* Create initial xen heap by finding non-reserved memory. */
    pos = boot_of_mem_avail(0, &start, &end);
    while (pos >= 0) {
        if (end == ~0UL)
            end = xenheap_phys_end;

        /* Problem: the bitmap itself is not reserved. */
        if ((start >= bitmap_start) && (start < bitmap_end)) {
            /* Start is inside bitmap. */
            start = bitmap_end;
        }
        if ((end > bitmap_start) && (end <= bitmap_end)) {
            /* End is inside bitmap. */
            end = bitmap_start;
        }
        if ((start < bitmap_start) && (end > bitmap_end)) {
            /* Range encompasses bitmap. First free low part, then high. */
            xenheap_size += bitmap_start - start;
            DBG("xenheap: %016lx - %016lx\n", start, bitmap_start);
            init_xenheap_pages(start, bitmap_start);
            start = bitmap_end;
        }

        xenheap_size += end - start;
        DBG("xenheap: %016lx - %016lx\n", start, end);
        init_xenheap_pages(start, end);

        pos = boot_of_mem_avail(pos, &start, &end);
    }

    printk("Xen Heap: %luMiB (%luKiB)\n",
           xenheap_size >> 20, xenheap_size >> 10);

    eomem = avail_domheap_pages();
    printk("Dom Heap: %luMiB (%luKiB)\n",
           (eomem << PAGE_SHIFT) >> 20,
           (eomem << PAGE_SHIFT) >> 10);
}
