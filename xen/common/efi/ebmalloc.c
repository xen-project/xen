#include "efi.h"
#include <xen/init.h>

#ifdef CONFIG_ARM
/*
 * TODO: Enable EFI boot allocator on ARM.
 * This code can be common for x86 and ARM.
 * Things TODO on ARM before enabling ebmalloc:
 *   - estimate required EBMALLOC_SIZE value,
 *   - where (in which section) ebmalloc_mem[] should live; if in
 *     .bss.page_aligned, as it is right now, then whole BSS zeroing
 *     have to be disabled in xen/arch/arm/arm64/head.S; though BSS
 *     should be initialized somehow before use of variables living there,
 *   - use ebmalloc() in ARM/common EFI boot code,
 *   - call free_ebmalloc_unused_mem() somewhere in init code.
 */
#define EBMALLOC_SIZE	MB(0)
#else
#define EBMALLOC_SIZE	MB(1)
#endif

static char __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    ebmalloc_mem[EBMALLOC_SIZE];
static unsigned long __initdata ebmalloc_allocated;

/* EFI boot allocator. */
void __init *ebmalloc(size_t size)
{
    void *ptr = ebmalloc_mem + ebmalloc_allocated;

    ebmalloc_allocated += ROUNDUP(size, sizeof(void *));

    if ( ebmalloc_allocated > sizeof(ebmalloc_mem) )
        blexit(L"Out of static memory\r\n");

    return ptr;
}

void __init free_ebmalloc_unused_mem(void)
{
#if 0 /* FIXME: Putting a hole in the BSS breaks the IOMMU mappings for dom0. */
    unsigned long start, end;

    start = (unsigned long)ebmalloc_mem + PAGE_ALIGN(ebmalloc_allocated);
    end = (unsigned long)ebmalloc_mem + sizeof(ebmalloc_mem);

    destroy_xen_mappings(start, end);
    init_xenheap_pages(__pa(start), __pa(end));

    printk(XENLOG_INFO "Freed %lukB unused BSS memory\n", (end - start) >> 10);
#endif
}
