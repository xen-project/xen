/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved. */

#ifndef _ASM_ARM_NOSPEC_H
#define _ASM_ARM_NOSPEC_H

#if defined(CONFIG_ARM_32)
# include <asm/arm32/nospec.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/nospec.h>
#else
# error "unknown ARM variant"
#endif

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
