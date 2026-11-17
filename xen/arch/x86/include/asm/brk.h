/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_BRK_H
#define X86_BRK_H

static inline unsigned long brk_adjust_start(unsigned long start)
{
    unsigned int subsys;

    /*
     * Only xen.efi will have the symbol __subsystem__ available, and it'll
     * be non-zero (10) there.  In ELF the symbol will be undefined, and
     * hence zero will be loaded into the register.
     */
    asm_inline ( ".weak __subsystem__; mov $__subsystem__, %0"
                 : "=r" (subsys) );

    /* using_2M_mapping() isn't available here. */
    if ( IS_ENABLED(CONFIG_XEN_ALIGN_2M) || subsys )
        start = PAGE_ALIGN_2M(start);

    return start;
}

#endif /* X86_BRK_H */
