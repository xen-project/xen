/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef RISCV_CSR_H
#define RISCV_CSR_H

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
#define csr_write64(name, val)              \
({                                          \
    uint64_t v_ = (val);                    \
    csr_write(CSR_ ## name, v_);            \
    csr_write(CSR_ ## name ## H, v_ >> 32); \
})

/*
 * The two halves are read by separate instructions, so a CSR which hardware
 * increments can carry from the low half into the high one in between,
 * yielding a value the CSR never held. Re-read the high half and retry the
 * sequence if it changed.
 *
 * Only needed for CSRs which change under Xen's feet.
 */
#define csr_volatile_read64(name)                            \
({                                                           \
    uint32_t lo_, old_, hi_ = csr_read(CSR_ ## name ## H);   \
                                                             \
    do {                                                     \
        old_ = hi_;                                          \
        lo_ = csr_read(CSR_ ## name);                        \
    } while ( (hi_ = csr_read(CSR_ ## name ## H)) != old_ ); \
                                                             \
    ((uint64_t)hi_ << 32) | lo_;                             \
})
#else
#define csr_write64(name, val) csr_write(CSR_ ## name, val)
#define csr_read64(name) csr_read(CSR_ ## name)
#define csr_volatile_read64 csr_read64
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

#endif /* RISCV_CSR_H */
