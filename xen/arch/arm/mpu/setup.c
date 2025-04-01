/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <asm/setup.h>

void __init setup_pagetables(void) {}

void * __init early_fdt_map(paddr_t fdt_paddr)
{
    BUG_ON("unimplemented");
    return NULL;
}

/*
 * copy_from_paddr - copy data from a physical address
 * @dst: destination virtual address
 * @paddr: source physical address
 * @len: length to copy
 */
void __init copy_from_paddr(void *dst, paddr_t paddr, unsigned long len)
{
    BUG_ON("unimplemented");
}

void __init remove_early_mappings(void)
{
    BUG_ON("unimplemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
