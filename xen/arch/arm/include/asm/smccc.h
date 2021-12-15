/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2017, EPAM Systems
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __ASM_ARM_SMCCC_H__
#define __ASM_ARM_SMCCC_H__

#include <asm/alternative.h>
#include <asm/cpufeature.h>

#define SMCCC_VERSION_MAJOR_SHIFT            16
#define SMCCC_VERSION_MINOR_MASK             \
        ((1U << SMCCC_VERSION_MAJOR_SHIFT) - 1)
#define SMCCC_VERSION_MAJOR_MASK             ~SMCCC_VERSION_MINOR_MASK
#define SMCCC_VERSION_MAJOR(ver)             \
        (((ver) & SMCCC_VERSION_MAJOR_MASK) >> SMCCC_VERSION_MAJOR_SHIFT)
#define SMCCC_VERSION_MINOR(ver)             \
        ((ver) & SMCCC_VERSION_MINOR_MASK)

#define SMCCC_VERSION(major, minor)          \
    (((major) << SMCCC_VERSION_MAJOR_SHIFT) | (minor))

#define ARM_SMCCC_VERSION_1_0   SMCCC_VERSION(1, 0)
#define ARM_SMCCC_VERSION_1_1   SMCCC_VERSION(1, 1)

/*
 * This file provides common defines for ARM SMC Calling Convention as
 * specified in
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

#define ARM_SMCCC_STD_CALL              _AC(0,U)
#define ARM_SMCCC_FAST_CALL             _AC(1,U)
#define ARM_SMCCC_TYPE_SHIFT            31

#define ARM_SMCCC_CONV_32               _AC(0,U)
#define ARM_SMCCC_CONV_64               _AC(1,U)
#define ARM_SMCCC_CONV_SHIFT            30

#define ARM_SMCCC_OWNER_MASK            _AC(0x3F,U)
#define ARM_SMCCC_OWNER_SHIFT           24

#define ARM_SMCCC_FUNC_MASK             _AC(0xFFFF,U)

#ifndef __ASSEMBLY__

extern uint32_t smccc_ver;

/* Check if this is fast call. */
static inline bool smccc_is_fast_call(register_t funcid)
{
    return funcid & (ARM_SMCCC_FAST_CALL << ARM_SMCCC_TYPE_SHIFT);
}

/* Chek if this is 64-bit call. */
static inline bool smccc_is_conv_64(register_t funcid)
{
    return funcid & (ARM_SMCCC_CONV_64 << ARM_SMCCC_CONV_SHIFT);
}

/* Get function number from function identifier. */
static inline uint32_t smccc_get_fn(register_t funcid)
{
    return funcid & ARM_SMCCC_FUNC_MASK;
}

/* Get service owner number from function identifier. */
static inline uint32_t smccc_get_owner(register_t funcid)
{
    return (funcid >> ARM_SMCCC_OWNER_SHIFT) & ARM_SMCCC_OWNER_MASK;
}

/*
 * struct arm_smccc_res - Result from SMC call
 * @a0 - @a3 result values from registers 0 to 3
 */
struct arm_smccc_res {
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
};

/* SMCCC v1.1 implementation madness follows */
#define ___count_args(_0, _1, _2, _3, _4, _5, _6, _7, _8, x, ...) x

#define __count_args(...)                               \
    ___count_args(__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)

#define __constraint_write_0                        \
    "+r" (r0), "=&r" (r1), "=&r" (r2), "=&r" (r3)
#define __constraint_write_1                        \
    "+r" (r0), "+r" (r1), "=&r" (r2), "=&r" (r3)
#define __constraint_write_2                        \
    "+r" (r0), "+r" (r1), "+r" (r2), "=&r" (r3)
#define __constraint_write_3                        \
    "+r" (r0), "+r" (r1), "+r" (r2), "+r" (r3)
#define __constraint_write_4    __constraint_write_3
#define __constraint_write_5    __constraint_write_4
#define __constraint_write_6    __constraint_write_5
#define __constraint_write_7    __constraint_write_6

#define __constraint_read_0
#define __constraint_read_1
#define __constraint_read_2
#define __constraint_read_3
#define __constraint_read_4 "r" (r4)
#define __constraint_read_5 __constraint_read_4, "r" (r5)
#define __constraint_read_6 __constraint_read_5, "r" (r6)
#define __constraint_read_7 __constraint_read_6, "r" (r7)

#define __declare_arg_0(a0, res)                            \
    struct arm_smccc_res    *___res = res;                  \
    register unsigned long  r0 ASM_REG(0) = (uint32_t)a0;   \
    register unsigned long  r1 ASM_REG(1);                  \
    register unsigned long  r2 ASM_REG(2);                  \
    register unsigned long  r3 ASM_REG(3)

#define __declare_arg_1(a0, a1, res)                        \
    typeof(a1) __a1 = a1;                                   \
    struct arm_smccc_res    *___res = res;                  \
    register unsigned long  r0 ASM_REG(0) = (uint32_t)a0;   \
    register unsigned long  r1 ASM_REG(1) = __a1;           \
    register unsigned long  r2 ASM_REG(2);                  \
    register unsigned long  r3 ASM_REG(3)

#define __declare_arg_2(a0, a1, a2, res)                    \
    typeof(a1) __a1 = a1;                                   \
    typeof(a2) __a2 = a2;                                   \
    struct arm_smccc_res    *___res = res;				    \
    register unsigned long  r0 ASM_REG(0) = (uint32_t)a0;   \
    register unsigned long  r1 ASM_REG(1) = __a1;           \
    register unsigned long  r2 ASM_REG(2) = __a2;           \
    register unsigned long  r3 ASM_REG(3)

#define __declare_arg_3(a0, a1, a2, a3, res)                \
    typeof(a1) __a1 = a1;                                   \
    typeof(a2) __a2 = a2;                                   \
    typeof(a3) __a3 = a3;                                   \
    struct arm_smccc_res    *___res = res;                  \
    register unsigned long  r0 ASM_REG(0) = (uint32_t)a0;   \
    register unsigned long  r1 ASM_REG(1) = __a1;           \
    register unsigned long  r2 ASM_REG(2) = __a2;           \
    register unsigned long  r3 ASM_REG(3) = __a3

#define __declare_arg_4(a0, a1, a2, a3, a4, res)        \
    typeof(a4) __a4 = a4;                               \
    __declare_arg_3(a0, a1, a2, a3, res);               \
    register unsigned long r4 ASM_REG(4) = __a4

#define __declare_arg_5(a0, a1, a2, a3, a4, a5, res)    \
    typeof(a5) __a5 = a5;                               \
    __declare_arg_4(a0, a1, a2, a3, a4, res);           \
    register typeof(a5) r5 ASM_REG(5) = __a5

#define __declare_arg_6(a0, a1, a2, a3, a4, a5, a6, res)    \
    typeof(a6) __a6 = a6;                                   \
    __declare_arg_5(a0, a1, a2, a3, a4, a5, res);           \
    register typeof(a6) r6 ASM_REG(6) = __a6

#define __declare_arg_7(a0, a1, a2, a3, a4, a5, a6, a7, res)    \
    typeof(a7) __a7 = a7;                                       \
    __declare_arg_6(a0, a1, a2, a3, a4, a5, a6, res);           \
    register typeof(a7) r7 ASM_REG(7) = __a7

#define ___declare_args(count, ...) __declare_arg_ ## count(__VA_ARGS__)
#define __declare_args(count, ...)  ___declare_args(count, __VA_ARGS__)

#define ___constraints(count)                       \
    : __constraint_write_ ## count                  \
    : __constraint_read_ ## count                   \
    : "memory"
#define __constraints(count)    ___constraints(count)

/*
 * arm_smccc_1_1_smc() - make an SMCCC v1.1 compliant SMC call
 *
 * This is a variadic macro taking one to eight source arguments, and
 * an optional return structure.
 *
 * @a0-a7: arguments passed in registers 0 to 7
 * @res: result values from registers 0 to 3
 *
 * This macro is used to make SMC calls following SMC Calling Convention v1.1.
 * The content of the supplied param are copied to registers 0 to 7 prior
 * to the SMC instruction. The return values are updated with the content
 * from register 0 to 3 on return from the SMC instruction if not NULL.
 *
 * We have an output list that is not necessarily used, and GCC feels
 * entitled to optimise the whole sequence away. "volatile" is what
 * makes it stick.
 */
#define arm_smccc_1_1_smc(...)                                  \
    do {                                                        \
        __declare_args(__count_args(__VA_ARGS__), __VA_ARGS__); \
        asm volatile("smc #0\n"                                 \
                     __constraints(__count_args(__VA_ARGS__))); \
        if ( ___res )                                           \
        *___res = (typeof(*___res)){r0, r1, r2, r3};            \
    } while ( 0 )

/*
 * The calling convention for arm32 is the same for both SMCCC v1.0 and
 * v1.1.
 */
#ifdef CONFIG_ARM_32
#define arm_smccc_1_0_smc(...) arm_smccc_1_1_smc(__VA_ARGS__)
#define arm_smccc_smc(...) arm_smccc_1_1_smc(__VA_ARGS__)
#else

void __arm_smccc_1_0_smc(register_t a0, register_t a1, register_t a2,
                         register_t a3, register_t a4, register_t a5,
                         register_t a6, register_t a7,
                         struct arm_smccc_res *res);

/* Macros to handle variadic parameter for SMCCC v1.0 helper */
#define __arm_smccc_1_0_smc_7(a0, a1, a2, a3, a4, a5, a6, a7, res)  \
    __arm_smccc_1_0_smc(a0, a1, a2, a3, a4, a5, a6, a7, res)

#define __arm_smccc_1_0_smc_6(a0, a1, a2, a3, a4, a5, a6, res)  \
    __arm_smccc_1_0_smc_7(a0, a1, a2, a3, a4, a5, a6, 0, res)

#define __arm_smccc_1_0_smc_5(a0, a1, a2, a3, a4, a5, res)  \
    __arm_smccc_1_0_smc_6(a0, a1, a2, a3, a4, a5, 0, res)

#define __arm_smccc_1_0_smc_4(a0, a1, a2, a3, a4, res)  \
    __arm_smccc_1_0_smc_5(a0, a1, a2, a3, a4, 0, res)

#define __arm_smccc_1_0_smc_3(a0, a1, a2, a3, res)  \
    __arm_smccc_1_0_smc_4(a0, a1, a2, a3, 0, res)

#define __arm_smccc_1_0_smc_2(a0, a1, a2, res)  \
    __arm_smccc_1_0_smc_3(a0, a1, a2, 0, res)

#define __arm_smccc_1_0_smc_1(a0, a1, res)  \
    __arm_smccc_1_0_smc_2(a0, a1, 0, res)

#define __arm_smccc_1_0_smc_0(a0, res)  \
    __arm_smccc_1_0_smc_1(a0, 0, res)

#define ___arm_smccc_1_0_smc_count(count, ...)    \
    __arm_smccc_1_0_smc_ ## count(__VA_ARGS__)

#define __arm_smccc_1_0_smc_count(count, ...)   \
    ___arm_smccc_1_0_smc_count(count, __VA_ARGS__)

#define arm_smccc_1_0_smc(...)                                              \
        __arm_smccc_1_0_smc_count(__count_args(__VA_ARGS__), __VA_ARGS__)

#define arm_smccc_smc(...)                                      \
    do {                                                        \
        if ( cpus_have_const_cap(ARM_SMCCC_1_1) )               \
            arm_smccc_1_1_smc(__VA_ARGS__);                     \
        else                                                    \
            arm_smccc_1_0_smc(__VA_ARGS__);                     \
    } while ( 0 )
#endif /* CONFIG_ARM_64 */

#endif /* __ASSEMBLY__ */

/*
 * Construct function identifier from call type (fast or standard),
 * calling convention (32 or 64 bit), service owner and function number.
 */
#define ARM_SMCCC_CALL_VAL(type, calling_convention, owner, func_num)           \
        (((type) << ARM_SMCCC_TYPE_SHIFT) |                                     \
         ((calling_convention) << ARM_SMCCC_CONV_SHIFT) |                       \
         (((owner) & ARM_SMCCC_OWNER_MASK) << ARM_SMCCC_OWNER_SHIFT) |          \
         (func_num))

/* List of known service owners */
#define ARM_SMCCC_OWNER_ARCH            0
#define ARM_SMCCC_OWNER_CPU             1
#define ARM_SMCCC_OWNER_SIP             2
#define ARM_SMCCC_OWNER_OEM             3
#define ARM_SMCCC_OWNER_STANDARD        4
#define ARM_SMCCC_OWNER_HYPERVISOR      5
#define ARM_SMCCC_OWNER_TRUSTED_APP     48
#define ARM_SMCCC_OWNER_TRUSTED_APP_END 49
#define ARM_SMCCC_OWNER_TRUSTED_OS      50
#define ARM_SMCCC_OWNER_TRUSTED_OS_END  63

/* List of generic function numbers */
#define ARM_SMCCC_CALL_COUNT_FID(owner)             \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_##owner,     \
                       0xFF00)

#define ARM_SMCCC_CALL_UID_FID(owner)               \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_##owner,     \
                       0xFF01)

#define ARM_SMCCC_REVISION_FID(owner)               \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_##owner,     \
                       0xFF03)

#define ARM_SMCCC_VERSION_FID                       \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_ARCH,        \
                       0x0)                         \

#define ARM_SMCCC_ARCH_FEATURES_FID                 \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_ARCH,        \
                       0x1)

#define ARM_SMCCC_ARCH_WORKAROUND_1_FID             \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_ARCH,        \
                       0x8000)

#define ARM_SMCCC_ARCH_WORKAROUND_2_FID             \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_ARCH,        \
                       0x7FFF)

/* SMCCC error codes */
#define ARM_SMCCC_NOT_REQUIRED          (-2)
#define ARM_SMCCC_ERR_UNKNOWN_FUNCTION  (-1)
#define ARM_SMCCC_NOT_SUPPORTED         (-1)
#define ARM_SMCCC_SUCCESS               (0)

/* SMCCC function identifier range which is reserved for existing APIs */
#define ARM_SMCCC_RESERVED_RANGE_START  0x0
#define ARM_SMCCC_RESERVED_RANGE_END    0x0100FFFF

#endif  /* __ASM_ARM_SMCCC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:b
 */
