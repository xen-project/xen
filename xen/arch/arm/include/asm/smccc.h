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
#define ARM_SMCCC_VERSION_1_2   SMCCC_VERSION(1, 2)

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

#ifndef __ASSEMBLER__

#include <xen/macros.h>
#include <xen/types.h>

#include <asm/asm_defns.h>

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

#define __constraint_read_1 "r" (arg0)
#define __constraint_read_2 __constraint_read_1, "r" (arg1)
#define __constraint_read_3 __constraint_read_2, "r" (arg2)
#define __constraint_read_4 __constraint_read_3, "r" (arg3)
#define __constraint_read_5 __constraint_read_4, "r" (arg4)
#define __constraint_read_6 __constraint_read_5, "r" (arg5)
#define __constraint_read_7 __constraint_read_6, "r" (arg6)
#define __constraint_read_8 __constraint_read_7, "r" (arg7)

/*
 * Macro arguments MUST be evaluated before being assigned to a register
 * variable.
 *
 * This is manual register scheduling for the asm() statement, and any other
 * logic to evaluate may clobber the already-scheduled registers.
 */
#define __declare_arg_1(a0)                             \
    auto __a0 = (uint32_t)(a0);                         \
    register unsigned long  arg0 ASM_REG(0) = __a0

#define __declare_arg_2(a0, a1)                         \
    auto __a1 = (a1);                                   \
    __declare_arg_1(a0);                                \
    register auto           arg1 ASM_REG(1) = __a1

#define __declare_arg_3(a0, a1, a2)                     \
    auto __a2 = (a2);                                   \
    __declare_arg_2(a0, a1);                            \
    register auto           arg2 ASM_REG(2) = __a2

#define __declare_arg_4(a0, a1, a2, a3)                 \
    auto __a3 = (a3);                                   \
    __declare_arg_3(a0, a1, a2);                        \
    register auto           arg3 ASM_REG(3) = __a3

#define __declare_arg_5(a0, a1, a2, a3, a4)             \
    auto __a4 = (a4);                                   \
    __declare_arg_4(a0, a1, a2, a3);                    \
    register auto           arg4 ASM_REG(4) = __a4

#define __declare_arg_6(a0, a1, a2, a3, a4, a5)         \
    auto __a5 = (a5);                                   \
    __declare_arg_5(a0, a1, a2, a3, a4);                \
    register auto           arg5 ASM_REG(5) = __a5

#define __declare_arg_7(a0, a1, a2, a3, a4, a5, a6)     \
    auto __a6 = (a6);                                   \
    __declare_arg_6(a0, a1, a2, a3, a4, a5);            \
    register auto           arg6 ASM_REG(6) = __a6

#define __declare_arg_8(a0, a1, a2, a3, a4, a5, a6, a7) \
    auto __a7 = (a7);                                   \
    __declare_arg_7(a0, a1, a2, a3, a4, a5, a6);        \
    register auto           arg7 ASM_REG(7) = __a7

#define ___declare_args(count, ...) __declare_arg_ ## count(__VA_ARGS__)
#define __declare_args(count, ...)  ___declare_args(count, __VA_ARGS__)

#ifdef CONFIG_ARM_32

/*
 * arm_smccc_1_1_smc() - make an SMCCC v1.1 compliant SMC call
 *
 * This is a variadic macro taking one to eight source arguments, and
 * returns four values.
 *
 * @a0-a7: arguments passed in registers 0 to 7
 * @res: result values from registers 0 to 3
 *
 * This macro is used to make SMC calls following SMC Calling Convention v1.1.
 * The content of the supplied param are copied to registers 0 to 7 prior
 * to the SMC instruction.
 *
 * We have an output list that is not necessarily used, and GCC feels
 * entitled to optimise the whole sequence away. "volatile" is what
 * makes it stick.
 */
#define arm_smccc_1_1_smc(...)                                  \
    ({                                                          \
        register unsigned long r0 ASM_REG(0);                   \
        register unsigned long r1 ASM_REG(1);                   \
        register unsigned long r2 ASM_REG(2);                   \
        register unsigned long r3 ASM_REG(3);                   \
        __declare_args(count_args(__VA_ARGS__), __VA_ARGS__);   \
        asm volatile (                                          \
            "smc #0"                                            \
            : "=r" (r0), "=r" (r1), "=r" (r2), "=r" (r3)        \
            : PASTE(__constraint_read_,                         \
                    count_args(__VA_ARGS__))                    \
            : "memory" );                                       \
        (struct arm_smccc_res){ r0, r1, r2, r3 };               \
    })

/*
 * The calling convention for arm32 is the same for both SMCCC v1.0 and
 * v1.1.
 */
#define arm_smccc_smc(...) arm_smccc_1_1_smc(__VA_ARGS__)

/* Make an SMCCC v1.1 compliant SMC call with guest register state. */
static inline void arm_smccc_guest_smc(struct cpu_user_regs *regs)
{
    struct arm_smccc_res res;

    res = arm_smccc_1_1_smc(regs->r0, regs->r1, regs->r2, regs->r3,
                            regs->r4, regs->r5, regs->r6, regs->r7);

    regs->r0 = res.a0;
    regs->r1 = res.a1;
    regs->r2 = res.a2;
    regs->r3 = res.a3;
}

#else /* CONFIG_ARM_64 */

/*
 * Make an SMC call compatible with both SMCCC v1.1 and v1.0.
 *
 * SMCCC v1.0 says that x4 through x17 are clobbered.  SMCCC v1.1 says they
 * are strictly preserved.  Always mark x4 through x17 as clobbered.
 */
#define arm_smccc_smc(...)                                      \
    ({                                                          \
        register unsigned long r0  ASM_REG(0);                  \
        register unsigned long r1  ASM_REG(1);                  \
        register unsigned long r2  ASM_REG(2);                  \
        register unsigned long r3  ASM_REG(3);                  \
        /* Potentially clobbered in SMCCC v1.0 */               \
        register unsigned long c4  ASM_REG(4);                  \
        register unsigned long c5  ASM_REG(5);                  \
        register unsigned long c6  ASM_REG(6);                  \
        register unsigned long c7  ASM_REG(7);                  \
        register unsigned long c8  ASM_REG(8);                  \
        register unsigned long c9  ASM_REG(9);                  \
        register unsigned long c10 ASM_REG(10);                 \
        register unsigned long c11 ASM_REG(11);                 \
        register unsigned long c12 ASM_REG(12);                 \
        register unsigned long c13 ASM_REG(13);                 \
        register unsigned long c14 ASM_REG(14);                 \
        register unsigned long c15 ASM_REG(15);                 \
        register unsigned long c16 ASM_REG(16);                 \
        register unsigned long c17 ASM_REG(17);                 \
        __declare_args(count_args(__VA_ARGS__), __VA_ARGS__);   \
        asm volatile (                                          \
            "smc #0"                                            \
            : "=r" (r0),  "=r" (r1),  "=r" (r2),  "=r" (r3),    \
              "=r" (c4),  "=r" (c5),  "=r" (c6),  "=r" (c7),    \
              "=r" (c8),  "=r" (c9),  "=r" (c10), "=r" (c11),   \
              "=r" (c12), "=r" (c13), "=r" (c14), "=r" (c15),   \
              "=r" (c16), "=r" (c17)                            \
            : PASTE(__constraint_read_,                         \
                    count_args(__VA_ARGS__))                    \
            : "memory" );                                       \
        (struct arm_smccc_res){ r0, r1, r2, r3 };               \
    })

#define arm_smccc_1_1_smc(...) arm_smccc_smc(__VA_ARGS__)

/* Make an SMCCC v1.1 compliant SMC call with guest register state. */
static inline void arm_smccc_guest_smc(struct cpu_user_regs *regs)
{
    struct arm_smccc_res res;

    res = arm_smccc_1_1_smc(regs->x0, regs->x1, regs->x2, regs->x3,
                            regs->x4, regs->x5, regs->x6, regs->x7);

    regs->x0 = res.a0;
    regs->x1 = res.a1;
    regs->x2 = res.a2;
    regs->x3 = res.a3;
}

/*
 * struct arm_smccc_1_2_regs - Arguments for or Results from SMC call
 * @a0-a17 argument values from registers 0 to 17
 */
struct arm_smccc_1_2_regs {
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long a4;
    unsigned long a5;
    unsigned long a6;
    unsigned long a7;
    unsigned long a8;
    unsigned long a9;
    unsigned long a10;
    unsigned long a11;
    unsigned long a12;
    unsigned long a13;
    unsigned long a14;
    unsigned long a15;
    unsigned long a16;
    unsigned long a17;
};

/*
 * arm_smccc_1_2_smc() - make SMC calls
 * @args: arguments passed via struct arm_smccc_1_2_regs
 * @res: result values via struct arm_smccc_1_2_regs
 *
 * This function is used to make SMC calls following SMC Calling Convention
 * v1.2 or above. The content of the supplied param are copied from the
 * structure to registers prior to the SMC instruction. The return values
 * are updated with the content from registers on return from the SMC
 * instruction.
 */
void arm_smccc_1_2_smc(const struct arm_smccc_1_2_regs *args,
                       struct arm_smccc_1_2_regs *res);
#endif /* CONFIG_ARM_64 */

#endif /* __ASSEMBLER__ */

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

#define ARM_SMCCC_ARCH_WORKAROUND_3_FID             \
    ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
                       ARM_SMCCC_CONV_32,           \
                       ARM_SMCCC_OWNER_ARCH,        \
                       0x3FFF)

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
