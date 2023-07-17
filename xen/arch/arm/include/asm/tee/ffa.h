/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/include/asm/tee/ffa.h
 *
 * Arm Firmware Framework for ARMv8-A(FFA) mediator
 *
 * Copyright (C) 2023  Linaro Limited
 */

#ifndef __ASM_ARM_TEE_FFA_H__
#define __ASM_ARM_TEE_FFA_H__

#include <xen/const.h>

#include <asm/smccc.h>
#include <asm/types.h>

#define FFA_FNUM_MIN_VALUE              _AC(0x60,U)
#define FFA_FNUM_MAX_VALUE              _AC(0x86,U)

static inline bool is_ffa_fid(uint32_t fid)
{
    uint32_t fn = fid & ARM_SMCCC_FUNC_MASK;

    return fn >= FFA_FNUM_MIN_VALUE && fn <= FFA_FNUM_MAX_VALUE;
}

#ifdef CONFIG_FFA
#define FFA_NR_FUNCS    12
#else
#define FFA_NR_FUNCS    0
#endif

#endif /*__ASM_ARM_TEE_FFA_H__*/
