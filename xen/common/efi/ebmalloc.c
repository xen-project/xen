#include "efi.h"
#include <xen/init.h>
#include <xen/mm.h>

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
static unsigned long __read_mostly ebmalloc_allocated;

/* EFI boot allocator. */
void __init *ebmalloc(size_t size)
{
    void *ptr = ebmalloc_mem + ebmalloc_allocated;

    ebmalloc_allocated += ROUNDUP(size, sizeof(void *));

    if ( ebmalloc_allocated > sizeof(ebmalloc_mem) )
        blexit(L"Out of static memory\r\n");

    return ptr;
}

bool efi_boot_mem_unused(unsigned long *start, unsigned long *end)
{
    /* FIXME: Drop once the call here with two NULLs goes away. */
    if ( !start && !end )
    {
        ebmalloc_allocated = sizeof(ebmalloc_mem);
        return false;
    }

    *start = (unsigned long)ebmalloc_mem + PAGE_ALIGN(ebmalloc_allocated);
    *end = (unsigned long)ebmalloc_mem + sizeof(ebmalloc_mem);

    return *start < *end;
}

void __init free_ebmalloc_unused_mem(void)
{
    unsigned long start, end;

    if ( !efi_boot_mem_unused(&start, &end) )
        return;

    destroy_xen_mappings(start, end);

#ifdef CONFIG_X86
    /*
     * By reserving the space early in the E820 map, it gets freed way before
     * we make it here. Don't free the range a 2nd time.
     */
#else
    init_xenheap_pages(__pa(start), __pa(end));
#endif

    printk(XENLOG_INFO "Freed %lukB unused BSS memory\n", (end - start) >> 10);
}
