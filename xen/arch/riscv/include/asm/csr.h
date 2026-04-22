/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef ASM__RISCV__CSR_H
#define ASM__RISCV__CSR_H

#include <xen/const.h>

#include <asm/asm.h>
#include <asm/extable.h>
#include <asm/riscv_encoding.h>

#ifndef __ASSEMBLER__

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

#ifdef CONFIG_RISCV_32
#define csr_write64(csr, val)       \
({                                  \
    uint64_t v_ = (val);            \
    csr_write(csr, v_);             \
    csr_write(csr ## H, v_ >> 32);  \
})
#else
#define csr_write64(csr, val)       \
({                                  \
    csr_write(csr, val);            \
    (void)csr ## H;                 \
})
#endif

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

static always_inline bool csr_read_safe(unsigned long csr,
                                        unsigned long *val)
{
#ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
    asm_inline goto (
        "1: csrr %[val], %[csr]\n"
        ASM_EXTABLE(1b, %l[fault])
        : [val] "=r" (*val)
        : [csr] "i" (csr)
        :
        : fault );

    return true;

 fault:
    return false;
#else
    bool allowed = false;

    asm_inline volatile (
        "1: csrr %[val], %[csr]\n"
        "   li %[allowed], 1\n"
        "2:\n"
        ASM_EXTABLE(1b, 2b)
        : [val] "=&r" (*val), [allowed] "+r" (allowed)
        : [csr] "i" (csr) );

    return allowed;
#endif
}

#endif /* __ASSEMBLER__ */

#endif /* ASM__RISCV__CSR_H */
