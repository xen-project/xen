/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/types.h>

struct page_info *frame_table;

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Unlike MMU, MPU does not use pages for translation. However, we continue
     * to use PAGE_SIZE to denote 4KB. This is so that the existing memory
     * management based on pages, continue to work for now.
     */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);
}

void __init setup_mm(void)
{
    BUG_ON("unimplemented");
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int nf)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

void dump_hyp_walk(vaddr_t addr)
{
    BUG_ON("unimplemented");
}

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void)
{
    BUG_ON("unimplemented");
}

void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned int flags)
{
    BUG_ON("unimplemented");
    return NULL;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
