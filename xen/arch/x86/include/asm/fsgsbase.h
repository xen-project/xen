/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_FSGSBASE_H
#define X86_FSGSBASE_H

#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/x86-defns.h>

/*
 * On hardware supporting FSGSBASE, the value loaded into hardware is the
 * guest kernel's choice for 64bit PV guests (Xen's choice for Idle, HVM and
 * 32bit PV).
 *
 * Therefore, the {RD,WR}{FS,GS}BASE instructions are only safe to use if
 * %cr4.fsgsbase is set.
 */
static inline unsigned long __rdfsbase(void)
{
    unsigned long base;

    asm volatile ( "rdfsbase %0" : "=r" (base) );

    return base;
}

static inline unsigned long __rdgsbase(void)
{
    unsigned long base;

    asm volatile ( "rdgsbase %0" : "=r" (base) );

    return base;
}

static inline unsigned long __rdgs_shadow(void)
{
    unsigned long base;

    asm_inline volatile ( "swapgs\n\t"
                          "rdgsbase %0\n\t"
                          "swapgs" : "=r" (base) );

    return base;
}

static inline void __wrfsbase(unsigned long base)
{
    asm volatile ( "wrfsbase %0" :: "r" (base) );
}

static inline void __wrgsbase(unsigned long base)
{
    asm volatile ( "wrgsbase %0" :: "r" (base) );
}

static inline void __wrgs_shadow(unsigned long base)
{
    asm_inline volatile ( "swapgs\n\t"
                          "wrgsbase %0\n\t"
                          "swapgs"
                          :: "r" (base) );
}

static inline unsigned long read_fs_base(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdfsbase();

    rdmsrl(MSR_FS_BASE, base);

    return base;
}

static inline unsigned long read_gs_base(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdgsbase();

    rdmsrl(MSR_GS_BASE, base);

    return base;
}

static inline unsigned long read_gs_shadow(void)
{
    unsigned long base;

    if ( read_cr4() & X86_CR4_FSGSBASE )
        return __rdgs_shadow();

    rdmsrl(MSR_SHADOW_GS_BASE, base);

    return base;
}

static inline void write_fs_base(unsigned long base)
{
    if ( read_cr4() & X86_CR4_FSGSBASE )
        __wrfsbase(base);
    else
        wrmsrl(MSR_FS_BASE, base);
}

static inline void write_gs_base(unsigned long base)
{
    if ( read_cr4() & X86_CR4_FSGSBASE )
        __wrgsbase(base);
    else
        wrmsrl(MSR_GS_BASE, base);
}

static inline void write_gs_shadow(unsigned long base)
{
    if ( read_cr4() & X86_CR4_FSGSBASE )
        __wrgs_shadow(base);
    else
        wrmsrl(MSR_SHADOW_GS_BASE, base);
}

#endif /* X86_FSGSBASE_H */
