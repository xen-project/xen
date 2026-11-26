/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/brk.h>
#include <xen/efi.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/page-defs.h>

#if __has_include(<asm/brk.h>)
# include <asm/brk.h>
#else
static inline unsigned long brk_adjust_start(unsigned long start)
{
    return start;
}
#endif

extern char __brk_start[];
extern const char __bss_end[];

unsigned long __ro_after_init brk_end;

static unsigned long __initdata allocated;

void *__init brk_alloc(size_t size)
{
    void *ptr;
    unsigned long alloc = allocated;

    if ( brk_end )
        return NULL;

    /* Allocations PAGE_SIZE and up will be page-aligned. */
    if ( size >= PAGE_SIZE )
        alloc = ROUNDUP(alloc, PAGE_SIZE);

    ptr = __brk_start + alloc;

    alloc += ROUNDUP(size, sizeof(void *));

    if ( alloc > __bss_end - __brk_start )
    {
        /* Expected to be fatal to boot, but cannot be panic(). */
        printk_once_init(
            "%pS: over-sized BRK request: %zu bytes\n",
            __builtin_extract_return_addr(__builtin_return_address(0)),
            size);
        return NULL;
    }

    allocated = alloc;

    return ptr;
}

void __init brk_cease(void)
{
    allocated = ROUNDUP(allocated, PAGE_SIZE);

    brk_end = (unsigned long)__brk_start + allocated;
}

void __init brk_free_unused(void)
{
    unsigned long start, end = (unsigned long)__bss_end;

    brk_cease();

    start = brk_adjust_start(brk_end);

    if ( start >= end )
        return;

    destroy_xen_mappings(start, PAGE_ALIGN_2M(end));

    /*
     * By reserving needed space early (on x86: in the E820 map), excess space
     * gets freed way before we make it here.  Don't free the range a 2nd time.
     */

    printk(XENLOG_INFO "Freed %lukB unused BRK memory\n", (end - start) >> 10);
}
