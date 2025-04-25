/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_MM_TYPES_H
#define XEN_MM_TYPES_H

/*
 * Types used to abstract away architecture-specific details in the memory
 * management code.
 *
 * Architectures need only provide their own asm/mm-types.h if they want to
 * override the defaults given here.
 */
#if __has_include(<asm/mm-types.h>)
# include <asm/mm-types.h>
#else /* !__has_include(<asm/mm-types.h>) */

typedef unsigned int pte_attr_t;

#endif /* !__has_include(<asm/mm-types.h>) */
#endif /* XEN_MM_TYPES_H */
