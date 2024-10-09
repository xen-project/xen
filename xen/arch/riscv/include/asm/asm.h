/* SPDX-License-Identifier: (GPL-2.0-only) */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef ASM__RISCV__ASM_H
#define ASM__RISCV__ASM_H

#ifdef __ASSEMBLY__
#include <xen/linkage.h>
#define __ASM_STR(x)	x
#else
#define __ASM_STR(x)	#x
#endif

#if __riscv_xlen == 64
#define __REG_SEL(a, b)	__ASM_STR(a)
#elif __riscv_xlen == 32
#define __REG_SEL(a, b)	__ASM_STR(b)
#else
#error "Unexpected __riscv_xlen"
#endif

#define REG_L		__REG_SEL(ld, lw)
#define REG_S		__REG_SEL(sd, sw)

#if __SIZEOF_POINTER__ == 8
#ifdef __ASSEMBLY__
#define RISCV_PTR		.dword
#else
#define RISCV_PTR		".dword"
#endif
#elif __SIZEOF_POINTER__ == 4
#ifdef __ASSEMBLY__
#define RISCV_PTR		.word
#else
#define RISCV_PTR		".word"
#endif
#else
#error "Unexpected __SIZEOF_POINTER__"
#endif

#if (__SIZEOF_INT__ == 4)
#define RISCV_INT		__ASM_STR(.word)
#else
#error "Unexpected __SIZEOF_INT__"
#endif

#if (__SIZEOF_SHORT__ == 2)
#define RISCV_SHORT		__ASM_STR(.half)
#else
#error "Unexpected __SIZEOF_SHORT__"
#endif

#endif /* ASM__RISCV__ASM_H */
