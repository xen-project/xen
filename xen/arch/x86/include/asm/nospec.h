/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. */

#ifndef _ASM_X86_NOSPEC_H
#define _ASM_X86_NOSPEC_H

#include <asm/alternative.h>

/* Allow to insert a read memory barrier into conditionals */
static always_inline bool barrier_nospec_true(void)
{
#ifdef CONFIG_SPECULATIVE_HARDEN_BRANCH
    alternative("lfence #nospec-true", "", X86_FEATURE_SC_NO_BRANCH_HARDEN);
#endif
    return true;
}

static always_inline bool barrier_nospec_false(void)
{
#ifdef CONFIG_SPECULATIVE_HARDEN_BRANCH
    alternative("lfence #nospec-false", "", X86_FEATURE_SC_NO_BRANCH_HARDEN);
#endif
    return false;
}

/* Allow to protect evaluation of conditionals with respect to speculation */
static always_inline bool evaluate_nospec(bool condition)
{
    if ( condition )
        return barrier_nospec_true();
    else
        return barrier_nospec_false();
}

/* Allow to block speculative execution in generic code */
static always_inline void block_speculation(void)
{
    barrier_nospec_true();
}

/**
 * array_index_mask_nospec() - generate a mask that is ~0UL when the
 *      bounds check succeeds and 0 otherwise
 * @index: array element index
 * @size: number of elements in array
 *
 * Returns:
 *     0 - (index < size)
 */
static inline unsigned long array_index_mask_nospec(unsigned long index,
                                                    unsigned long size)
{
    unsigned long mask;

    asm volatile ( "cmp %[size], %[index]; sbb %[mask], %[mask];"
                   : [mask] "=r" (mask)
                   : [size] "g" (size), [index] "r" (index) );

    return mask;
}

/* Override default implementation in nospec.h. */
#define array_index_mask_nospec array_index_mask_nospec

static always_inline void arch_block_lock_speculation(void)
{
    alternative("lfence", "", X86_FEATURE_SC_NO_LOCK_HARDEN);
}

/* Allow to insert a read memory barrier into conditionals */
static always_inline bool barrier_lock_true(void)
{
    alternative("lfence #nospec-true", "", X86_FEATURE_SC_NO_LOCK_HARDEN);
    return true;
}

static always_inline bool barrier_lock_false(void)
{
    alternative("lfence #nospec-false", "", X86_FEATURE_SC_NO_LOCK_HARDEN);
    return false;
}

static always_inline bool arch_lock_evaluate_nospec(bool condition)
{
    if ( condition )
        return barrier_lock_true();
    else
        return barrier_lock_false();
}

#endif /* _ASM_X86_NOSPEC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
