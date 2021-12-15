/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. */

#ifndef _ASM_ARM_NOSPEC_H
#define _ASM_ARM_NOSPEC_H

static inline bool evaluate_nospec(bool condition)
{
    return condition;
}

static inline void block_speculation(void)
{
}

#endif /* _ASM_ARM_NOSPEC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
