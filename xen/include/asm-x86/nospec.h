/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. */

#ifndef _ASM_X86_NOSPEC_H
#define _ASM_X86_NOSPEC_H

#include <asm/alternative.h>

/* Allow to insert a read memory barrier into conditionals */
static always_inline bool barrier_nospec_true(void)
{
#ifdef CONFIG_HVM
    alternative("", "lfence", X86_FEATURE_SC_L1TF_VULN);
#endif
    return true;
}

/* Allow to protect evaluation of conditionals with respect to speculation */
static always_inline bool evaluate_nospec(bool condition)
{
    return condition ? barrier_nospec_true() : !barrier_nospec_true();
}

/* Allow to block speculative execution in generic code */
static always_inline void block_speculation(void)
{
    barrier_nospec_true();
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
