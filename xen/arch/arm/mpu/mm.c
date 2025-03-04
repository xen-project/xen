/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/sizes.h>

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Unlike MMU, MPU does not use pages for translation. However, we continue
     * to use PAGE_SIZE to denote 4KB. This is so that the existing memory
     * management based on pages, continue to work for now.
     */
    BUILD_BUG_ON(PAGE_SIZE != SZ_4K);
}
