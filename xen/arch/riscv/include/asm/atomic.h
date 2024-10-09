 /* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Taken and modified from Linux.
 *
 * The following changes were done:
 * - * atomic##prefix##_*xchg_*(atomic##prefix##_t *v, c_t n) were updated
 *     to use__*xchg_generic()
 * - drop casts in write_atomic() as they are unnecessary
 * - drop introduction of WRITE_ONCE() and READ_ONCE().
 *   Xen provides ACCESS_ONCE()
 * - remove zero-length array access in read_atomic()
 * - drop defines similar to pattern
 *   #define atomic_add_return_relaxed   atomic_add_return_relaxed
 * - move not RISC-V specific functions to asm-generic/atomics-ops.h
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2024 Vates SAS
 */

#ifndef ASM__RISCV__ATOMIC_H
#define ASM__RISCV__ATOMIC_H

#include <xen/atomic.h>

#include <asm/cmpxchg.h>
#include <asm/fence.h>
#include <asm/io.h>
#include <asm/system.h>

void __bad_atomic_size(void);

static always_inline void read_atomic_size(const volatile void *p,
                                           void *res,
                                           unsigned int size)
{
    switch ( size )
    {
    case 1: *(uint8_t *)res = readb_cpu(p); break;
    case 2: *(uint16_t *)res = readw_cpu(p); break;
    case 4: *(uint32_t *)res = readl_cpu(p); break;
#ifndef CONFIG_RISCV_32
    case 8: *(uint64_t *)res = readq_cpu(p); break;
#endif
    default: __bad_atomic_size(); break;
    }
}

#define read_atomic(p) ({                                   \
    union { typeof(*(p)) val; char c[sizeof(*(p))]; } x_;   \
    read_atomic_size(p, x_.c, sizeof(*(p)));                \
    x_.val;                                                 \
})

static always_inline void _write_atomic(volatile void *p,
                                        unsigned long x,
                                        unsigned int size)
{
    switch ( size )
    {
    case 1: writeb_cpu(x, p); break;
    case 2: writew_cpu(x, p); break;
    case 4: writel_cpu(x, p); break;
#ifndef CONFIG_RISCV_32
    case 8: writeq_cpu(x, p); break;
#endif
    default: __bad_atomic_size(); break;
    }
}

#define write_atomic(p, x)                                          \
({                                                                  \
    union { typeof(*(p)) v; unsigned long ul; } x_ = { .ul = 0UL }; \
    x_.v = (x);                                                     \
    _write_atomic(p, x_.ul, sizeof(*(p)));                          \
})

static always_inline void _add_sized(volatile void *p,
                                     unsigned long x, unsigned int size)
{
    switch ( size )
    {
    case 1:
    {
        volatile uint8_t *ptr = p;
        write_atomic(ptr, read_atomic(ptr) + x);
        break;
    }
    case 2:
    {
        volatile uint16_t *ptr = p;
        write_atomic(ptr, read_atomic(ptr) + x);
        break;
    }
    case 4:
    {
        volatile uint32_t *ptr = p;
        write_atomic(ptr, read_atomic(ptr) + x);
        break;
    }
#ifndef CONFIG_RISCV_32
    case 8:
    {
        volatile uint64_t *ptr = p;
        write_atomic(ptr, read_atomic(ptr) + x);
        break;
    }
#endif
    default: __bad_atomic_size(); break;
    }
}

#define add_sized(p, x)                                 \
({                                                      \
    typeof(*(p)) x_ = (x);                              \
    _add_sized(p, x_, sizeof(*(p)));                    \
})

#define __atomic_acquire_fence() \
    asm volatile ( RISCV_ACQUIRE_BARRIER ::: "memory" )

#define __atomic_release_fence() \
    asm volatile ( RISCV_RELEASE_BARRIER ::: "memory" )

/*
 * First, the atomic ops that have no ordering constraints and therefor don't
 * have the AQ or RL bits set.  These don't return anything, so there's only
 * one version to worry about.
 */
#define ATOMIC_OP(op, asm_op, unary_op, asm_type, c_type, prefix)  \
static inline                                               \
void atomic##prefix##_##op(c_type i, atomic##prefix##_t *v) \
{                                                           \
    asm volatile (                                          \
        "   amo" #asm_op "." #asm_type " zero, %1, %0"      \
        : "+A" (v->counter)                                 \
        : "r" (unary_op i)                                  \
        : "memory" );                                       \
}                                                           \

/*
 * Only CONFIG_GENERIC_ATOMIC64=y was ported to Xen that is the reason why
 * last argument for ATOMIC_OP isn't used.
 */
#define ATOMIC_OPS(op, asm_op, unary_op)                    \
        ATOMIC_OP (op, asm_op, unary_op, w, int,   )

ATOMIC_OPS(add, add, +)
ATOMIC_OPS(sub, add, -)
ATOMIC_OPS(and, and, +)
ATOMIC_OPS( or,  or, +)
ATOMIC_OPS(xor, xor, +)

#undef ATOMIC_OP
#undef ATOMIC_OPS

#include <asm-generic/atomic-ops.h>

/*
 * Atomic ops that have ordered variant.
 * There's two flavors of these: the arithmatic ops have both fetch and return
 * versions, while the logical ops only have fetch versions.
 */
#define ATOMIC_FETCH_OP(op, asm_op, unary_op, asm_type, c_type, prefix) \
static inline                                                       \
c_type atomic##prefix##_fetch_##op(c_type i, atomic##prefix##_t *v) \
{                                                                   \
    register c_type ret;                                            \
    asm volatile (                                                  \
        "   amo" #asm_op "." #asm_type ".aqrl  %1, %2, %0"          \
        : "+A" (v->counter), "=r" (ret)                             \
        : "r" (unary_op i)                                          \
        : "memory" );                                               \
    return ret;                                                     \
}

#define ATOMIC_OP_RETURN(op, asm_op, c_op, unary_op, asm_type, c_type, prefix) \
static inline                                                           \
c_type atomic##prefix##_##op##_return(c_type i, atomic##prefix##_t *v)  \
{                                                                       \
    return atomic##prefix##_fetch_##op(i, v) c_op (unary_op i);         \
}

/*
 * Only CONFIG_GENERIC_ATOMIC64=y was ported to Xen that is the reason why
 * last argument of ATOMIC_FETCH_OP, ATOMIC_OP_RETURN isn't used.
 */
#define ATOMIC_OPS(op, asm_op, unary_op)                        \
        ATOMIC_FETCH_OP( op, asm_op,    unary_op, w, int,   )   \
        ATOMIC_OP_RETURN(op, asm_op, +, unary_op, w, int,   )

ATOMIC_OPS(add, add, +)
ATOMIC_OPS(sub, add, -)

#undef ATOMIC_OPS

#define ATOMIC_OPS(op, asm_op) \
        ATOMIC_FETCH_OP(op, asm_op, +, w, int,   )

ATOMIC_OPS(and, and)
ATOMIC_OPS( or,  or)
ATOMIC_OPS(xor, xor)

#undef ATOMIC_OPS

#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN

/* This is required to provide a full barrier on success. */
static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
    int prev, rc;

    asm volatile (
        "0: lr.w     %[p],  %[c]\n"
        "   beq      %[p],  %[u], 1f\n"
        "   add      %[rc], %[p], %[a]\n"
        "   sc.w.aqrl  %[rc], %[rc], %[c]\n"
        "   bnez     %[rc], 0b\n"
        "1:\n"
        : [p] "=&r" (prev), [rc] "=&r" (rc), [c] "+A" (v->counter)
        : [a] "r" (a), [u] "r" (u)
        : "memory");
    return prev;
}

static inline int atomic_sub_if_positive(atomic_t *v, int offset)
{
    int prev, rc;

    asm volatile (
        "0: lr.w     %[p],  %[c]\n"
        "   sub      %[rc], %[p], %[o]\n"
        "   bltz     %[rc], 1f\n"
        "   sc.w.aqrl  %[rc], %[rc], %[c]\n"
        "   bnez     %[rc], 0b\n"
        "1:\n"
        : [p] "=&r" (prev), [rc] "=&r" (rc), [c] "+A" (v->counter)
        : [o] "r" (offset)
        : "memory" );
    return prev - offset;
}

/*
 * atomic_{cmp,}xchg is required to have exactly the same ordering semantics as
 * {cmp,}xchg and the operations that return.
 */
#define ATOMIC_OP(c_t, prefix)                                  \
static inline                                                   \
c_t atomic##prefix##_xchg(atomic##prefix##_t *v, c_t n)         \
{                                                               \
    return __xchg(&v->counter, n, sizeof(c_t));                 \
}                                                               \
static inline                                                   \
c_t atomic##prefix##_cmpxchg(atomic##prefix##_t *v, c_t o, c_t n) \
{                                                               \
    return __cmpxchg(&v->counter, o, n, sizeof(c_t));           \
}

#define ATOMIC_OPS() \
    ATOMIC_OP(int,   )

ATOMIC_OPS()

#undef ATOMIC_OPS
#undef ATOMIC_OP

#endif /* ASM__RISCV__ATOMIC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
