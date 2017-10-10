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

/*
 * This file provides common defines for ARM SMC Calling Convention as
 * specified in
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

#define ARM_SMCCC_STD_CALL              0U
#define ARM_SMCCC_FAST_CALL             1U
#define ARM_SMCCC_TYPE_SHIFT            31

#define ARM_SMCCC_CONV_32               0U
#define ARM_SMCCC_CONV_64               1U
#define ARM_SMCCC_CONV_SHIFT            30

#define ARM_SMCCC_OWNER_MASK            0x3FU
#define ARM_SMCCC_OWNER_SHIFT           24

#define ARM_SMCCC_FUNC_MASK             0xFFFFU

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
#define ARM_SMCCC_FUNC_CALL_COUNT       0xFF00
#define ARM_SMCCC_FUNC_CALL_UID         0xFF01
#define ARM_SMCCC_FUNC_CALL_REVISION    0xFF03

/* Only one error code defined in SMCCC */
#define ARM_SMCCC_ERR_UNKNOWN_FUNCTION  (-1)

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
