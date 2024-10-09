/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef ASM__RISCV__CSR_H
#define ASM__RISCV__CSR_H

#include <asm/asm.h>
#include <xen/const.h>
#include <asm/riscv_encoding.h>

#ifndef __ASSEMBLY__

#define csr_read(csr)                                           \
({                                                              \
    register unsigned long __v;                                 \
    __asm__ __volatile__ ( "csrr %0, " __ASM_STR(csr)           \
                           : "=r" (__v)                         \
                           : : "memory" );                      \
    __v;                                                        \
})

#define csr_write(csr, val)                                     \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrw " __ASM_STR(csr) ", %0"        \
                           : /* no outputs */                   \
                           : "rK" (__v)                         \
                           : "memory" );                        \
})

#define csr_swap(csr, val)                                      \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrrw %0, " __ASM_STR(csr) ", %1"   \
                           : "=r" (__v)                         \
                           : "rK" (__v)                         \
                           : "memory" );                        \
    __v;                                                        \
})

#define csr_read_set(csr, val)                                  \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrrs %0, " __ASM_STR(csr) ", %1"   \
                           : "=r" (__v)                         \
                           : "rK" (__v)                         \
                           : "memory" );                        \
    __v;                                                        \
})

#define csr_set(csr, val)                                       \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrs " __ASM_STR(csr) ", %0"        \
                           : /* no outputs */                   \
                           : "rK" (__v)                         \
                           : "memory" );                        \
})

#define csr_read_clear(csr, val)                                \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrrc %0, " __ASM_STR(csr) ", %1"   \
                           : "=r" (__v)                         \
                           : "rK" (__v)                         \
                           : "memory" );                        \
    __v;                                                        \
})

#define csr_clear(csr, val)                                     \
({                                                              \
    unsigned long __v = (unsigned long)(val);                   \
    __asm__ __volatile__ ( "csrc " __ASM_STR(csr) ", %0"        \
                           : /* no outputs */                   \
                           : "rK" (__v)                         \
                           : "memory" );                        \
})

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__CSR_H */
