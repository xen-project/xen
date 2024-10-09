/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2014 Regents of the University of California */

#ifndef ASM__RISCV__CMPXCHG_H
#define ASM__RISCV__CMPXCHG_H

#include <xen/compiler.h>
#include <xen/lib.h>

#include <asm/fence.h>
#include <asm/io.h>
#include <asm/system.h>

#define _amoswap_generic(ptr, new, ret, sfx) \
    asm volatile ( \
        " amoswap" sfx " %0, %2, %1" \
        : "=r" (ret), "+A" (*(ptr)) \
        : "r" (new) \
        : "memory" );

/*
 * To not face an issue that gas doesn't understand ANDN instruction
 * it is encoded using .insn directive.
 */
#ifdef __riscv_zbb
#define ANDN_INSN(rd, rs1, rs2)                 \
    ".insn r OP, 0x7, 0x20, " rd ", " rs1 ", " rs2 "\n"
#else
#define ANDN_INSN(rd, rs1, rs2)                 \
    "not " rd ", " rs2 "\n"                     \
    "and " rd ", " rs1 ", " rd "\n"
#endif

/*
 * For LR and SC, the A extension requires that the address held in rs1 be
 * naturally aligned to the size of the operand (i.e., eight-byte aligned
 * for 64-bit words and four-byte aligned for 32-bit words).
 * If the address is not naturally aligned, an address-misaligned exception
 * or an access-fault exception will be generated.
 *
 * Thereby:
 * - for 1-byte xchg access the containing word by clearing low two bits.
 * - for 2-byte xchg access the containing word by clearing bit 1.
 *
 * If resulting 4-byte access is still misalgined, it will fault just as
 * non-emulated 4-byte access would.
 */
#define emulate_xchg_1_2(ptr, new, lr_sfx, sc_sfx) \
({ \
    uint32_t *aligned_ptr; \
    unsigned long alignment_mask = sizeof(*aligned_ptr) - sizeof(*(ptr)); \
    unsigned int new_val_bit = \
        ((unsigned long)(ptr) & alignment_mask) * BITS_PER_BYTE; \
    unsigned long mask = \
        GENMASK(((sizeof(*(ptr))) * BITS_PER_BYTE) - 1, 0) << new_val_bit; \
    unsigned int new_ = (new) << new_val_bit; \
    unsigned int old; \
    unsigned int scratch; \
    \
    aligned_ptr = (uint32_t *)((unsigned long)(ptr) & ~alignment_mask); \
    \
    asm volatile ( \
        "0: lr.w" lr_sfx " %[old], %[ptr_]\n" \
        ANDN_INSN("%[scratch]", "%[old]", "%[mask]") \
        "   or   %[scratch], %[scratch], %z[new_]\n" \
        "   sc.w" sc_sfx " %[scratch], %[scratch], %[ptr_]\n" \
        "   bnez %[scratch], 0b\n" \
        : [old] "=&r" (old), [scratch] "=&r" (scratch), \
          [ptr_] "+A" (*aligned_ptr) \
        : [new_] "rJ" (new_), [mask] "r" (mask) \
        : "memory" ); \
    \
    (__typeof__(*(ptr)))((old & mask) >> new_val_bit); \
})

/*
 * This function doesn't exist, so you'll get a linker error
 * if something tries to do an invalid xchg().
 */
extern unsigned long __bad_xchg(volatile void *ptr, unsigned int size);

static always_inline unsigned long __xchg(volatile void *ptr,
                                          unsigned long new,
                                          unsigned int size)
{
    unsigned long ret;

    switch ( size )
    {
    case 1:
        ret = emulate_xchg_1_2((volatile uint8_t *)ptr, new, ".aq", ".aqrl");
        break;
    case 2:
        ret = emulate_xchg_1_2((volatile uint16_t *)ptr, new, ".aq", ".aqrl");
        break;
    case 4:
        _amoswap_generic((volatile uint32_t *)ptr, new, ret, ".w.aqrl");
        break;
#ifndef CONFIG_RISCV_32
    case 8:
        _amoswap_generic((volatile uint64_t *)ptr, new, ret, ".d.aqrl");
        break;
#endif
    default:
        return __bad_xchg(ptr, size);
    }

    return ret;
}

#define xchg(ptr, x) \
({ \
    __typeof__(*(ptr)) n_ = (x); \
    (__typeof__(*(ptr))) \
        __xchg(ptr, (unsigned long)n_, sizeof(*(ptr))); \
})

#define _generic_cmpxchg(ptr, old, new, lr_sfx, sc_sfx) \
 ({ \
    unsigned int rc; \
    unsigned long ret; \
    unsigned long mask = GENMASK(((sizeof(*(ptr))) * BITS_PER_BYTE) - 1, 0); \
    asm volatile ( \
        "0: lr" lr_sfx " %[ret], %[ptr_]\n" \
        "   and  %[ret], %[ret], %[mask]\n" \
        "   bne  %[ret], %z[old_], 1f\n" \
        "   sc" sc_sfx " %[rc], %z[new_], %[ptr_]\n" \
        "   bnez %[rc], 0b\n" \
        "1:\n" \
        : [ret] "=&r" (ret), [rc] "=&r" (rc), [ptr_] "+A" (*ptr) \
        : [old_] "rJ" (old), [new_] "rJ" (new), [mask] "r" (mask)  \
        : "memory" ); \
    ret; \
 })

/*
 * For LR and SC, the A extension requires that the address held in rs1 be
 * naturally aligned to the size of the operand (i.e., eight-byte aligned
 * for 64-bit words and four-byte aligned for 32-bit words).
 * If the address is not naturally aligned, an address-misaligned exception
 * or an access-fault exception will be generated.
 *
 * Thereby:
 * - for 1-byte xchg access the containing word by clearing low two bits
 * - for 2-byte xchg ccess the containing word by clearing first bit.
 *
 * If resulting 4-byte access is still misalgined, it will fault just as
 * non-emulated 4-byte access would.
 *
 * old_val was casted to unsigned long for cmpxchgptr()
 */
#define emulate_cmpxchg_1_2(ptr, old, new, lr_sfx, sc_sfx) \
({ \
    uint32_t *aligned_ptr; \
    unsigned long alignment_mask = sizeof(*aligned_ptr) - sizeof(*(ptr)); \
    uint8_t new_val_bit = \
        ((unsigned long)(ptr) & alignment_mask) * BITS_PER_BYTE; \
    unsigned long mask = \
        GENMASK(((sizeof(*(ptr))) * BITS_PER_BYTE) - 1, 0) << new_val_bit; \
    unsigned int old_ = (old) << new_val_bit; \
    unsigned int new_ = (new) << new_val_bit; \
    unsigned int old_val; \
    unsigned int scratch; \
    \
    aligned_ptr = (uint32_t *)((unsigned long)ptr & ~alignment_mask); \
    \
    asm volatile ( \
        "0: lr.w" lr_sfx " %[scratch], %[ptr_]\n" \
        "   and  %[old_val], %[scratch], %[mask]\n" \
        "   bne  %[old_val], %z[old_], 1f\n" \
        /* the following line is an equivalent to: \
         *     scratch = old_val & ~mask; \
         * And to elimanate one ( likely register ) input it was decided \
         * to use: \
         *     scratch = old_val ^ scratch \
         */ \
        "   xor  %[scratch], %[old_val], %[scratch]\n" \
        "   or   %[scratch], %[scratch], %z[new_]\n" \
        "   sc.w" sc_sfx " %[scratch], %[scratch], %[ptr_]\n" \
        "   bnez %[scratch], 0b\n" \
        "1:\n" \
        : [old_val] "=&r" (old_val), [scratch] "=&r" (scratch), \
          [ptr_] "+A" (*aligned_ptr) \
        : [old_] "rJ" (old_), [new_] "rJ" (new_), \
          [mask] "r" (mask) \
        : "memory" ); \
    \
    (__typeof__(*(ptr)))((unsigned long)old_val >> new_val_bit); \
})

/*
 * This function doesn't exist, so you'll get a linker error
 * if something tries to do an invalid cmpxchg().
 */
extern unsigned long __bad_cmpxchg(volatile void *ptr, unsigned int size);

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
static always_inline unsigned long __cmpxchg(volatile void *ptr,
                                             unsigned long old,
                                             unsigned long new,
                                             unsigned int size)
{
    unsigned long ret;

    switch ( size )
    {
    case 1:
        ret = emulate_cmpxchg_1_2((volatile uint8_t *)ptr, old, new,
                                  ".aq", ".aqrl");
        break;
    case 2:
        ret = emulate_cmpxchg_1_2((volatile uint16_t *)ptr, old, new,
                                   ".aq", ".aqrl");
        break;
    case 4:
        ret = _generic_cmpxchg((volatile uint32_t *)ptr, old, new,
                          ".w.aq", ".w.aqrl");
        break;
#ifndef CONFIG_32BIT
    case 8:
        ret = _generic_cmpxchg((volatile uint64_t *)ptr, old, new,
                           ".d.aq", ".d.aqrl");
        break;
#endif
    default:
        return __bad_cmpxchg(ptr, size);
    }

    return ret;
}

#define cmpxchg(ptr, o, n) \
({ \
    __typeof__(*(ptr)) o_ = (o); \
    __typeof__(*(ptr)) n_ = (n); \
    (__typeof__(*(ptr))) \
    __cmpxchg(ptr, (unsigned long)o_, (unsigned long)n_, \
              sizeof(*(ptr))); \
})

#endif /* ASM__RISCV__CMPXCHG_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
