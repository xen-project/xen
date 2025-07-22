/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_BOOTFDT_H
#define X86_BOOTFDT_H

#include <xen/types.h>

struct arch_boot_module
{
    /*
     * Module State Flags:
     *   relocated:   indicates module has been relocated in memory.
     *   released:    indicates module's pages have been freed.
     */
    bool relocated:1;
    bool released:1;

    /*
     * A boot module may need decompressing by Xen.  Headroom is an estimate of
     * the additional space required to decompress the module.
     *
     * Headroom is accounted for at the start of the module.  Decompressing is
     * done in-place with input=start, output=start-headroom, expecting the
     * pointers to become equal (give or take some rounding) when decompression
     * is complete.
     *
     * Memory layout at boot:
     *
     *               start ----+
     *                         v
     *   |<-----headroom------>|<------size------->|
     *                         +-------------------+
     *                         | Compressed Module |
     *   +---------------------+-------------------+
     *   |           Decompressed Module           |
     *   +-----------------------------------------+
     */
    unsigned long headroom;
    paddr_t cmdline_pa;
};

#endif /* X86_BOOTFDT_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
