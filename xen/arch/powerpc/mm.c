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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/shadow.h>
#include <xen/kernel.h>
#include <xen/sched.h>
#include <asm/misc.h>
#include <asm/init.h>
#include <asm/page.h>

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;
unsigned long total_pages;

int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    panic("%s called\n", __func__);
    return 1;
}

int destroy_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    panic("%s called\n", __func__);
    return 1;
}

int steal_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    panic("%s called\n", __func__);
    return 1;
}


int get_page_type(struct page_info *page, u32 type)
{
    panic("%s called\n", __func__);
    return 1;
}

void put_page_type(struct page_info *page)
{
    panic("%s called\n", __func__);
}

void __init init_frametable(void)
{
    unsigned long p;

    frame_table_size = PFN_UP(max_page * sizeof(struct page_info));

    p = alloc_boot_pages(min(frame_table_size, 4UL << 20), 1);
    if (p == 0)
        panic("Not enough memory for frame table\n");

    frame_table = (struct page_info *)(p << PAGE_SHIFT);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

    memset(frame_table, 0, frame_table_size);
}

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    printk("%s: no PPC specific memory ops\n", __func__);
    return -ENOSYS;
}

void clear_page(void *page)
{
    if (on_mambo()) {
        extern void *mambo_memset(void *,int ,__kernel_size_t);
        mambo_memset(page, 0, PAGE_SIZE);
    } else {
        memset(page, 0, PAGE_SIZE);
    }
}

extern void copy_page(void *dp, void *sp)
{
    if (on_mambo()) {
        extern void *mambo_memcpy(void *,const void *,__kernel_size_t);
        mambo_memcpy(dp, sp, PAGE_SIZE);
    } else {
        memcpy(dp, sp, PAGE_SIZE);
    }
}

ulong pfn2mfn(struct domain *d, long pfn, int *type)
{
    ulong rma_base_mfn = page_to_mfn(d->arch.rma_page);
    ulong rma_size_mfn = 1UL << d->arch.rma_order;
    ulong mfn;
    int t;

    if (pfn < rma_size_mfn) {
        mfn = pfn + rma_base_mfn;
        t = PFN_TYPE_RMA;
    } else if (pfn >= d->arch.logical_base_pfn &&
               pfn < d->arch.logical_end_pfn) {
        if (test_bit(_DOMF_privileged, &d->domain_flags)) {
            /* This hack allows dom0 to map all memory, necessary to
             * initialize domU state. */
            mfn = pfn;
        } else {
            panic("we do not handle the logical area yet\n");
            mfn = 0;
        }

        t = PFN_TYPE_LOGICAL;
    } else {
        /* don't know */
        mfn = pfn;
        t = PFN_TYPE_IO;
    }

    if (type != NULL)
        *type = t;

    return mfn;
}

void guest_physmap_add_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    panic("%s\n", __func__);
}
void guest_physmap_remove_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    panic("%s\n", __func__);
}
void shadow_drop_references(
    struct domain *d, struct page_info *page)
{
    panic("%s\n", __func__);
}
