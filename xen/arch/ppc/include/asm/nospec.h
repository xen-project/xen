/* SPDX-License-Identifier: GPL-2.0-only */
/* From arch/arm/include/asm/nospec.h. */
#ifndef __ASM_PPC_NOSPEC_H__
#define __ASM_PPC_NOSPEC_H__

static inline bool evaluate_nospec(bool condition)
{
    return condition;
}

static inline void block_speculation(void)
{
}

#endif /* __ASM_PPC_NOSPEC_H__ */
