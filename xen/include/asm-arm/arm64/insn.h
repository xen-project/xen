/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014 Zi Shen Lim <zlim.lnx@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ARCH_ARM_ARM64_INSN
#define __ARCH_ARM_ARM64_INSN

#include <xen/config.h>
#include <xen/types.h>
#include <xen/stdbool.h>

enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR,
	AARCH64_INSN_IMM_26,
	AARCH64_INSN_IMM_19,
	AARCH64_INSN_IMM_16,
	AARCH64_INSN_IMM_14,
	AARCH64_INSN_IMM_12,
	AARCH64_INSN_IMM_9,
	AARCH64_INSN_IMM_7,
	AARCH64_INSN_IMM_6,
	AARCH64_INSN_IMM_S,
	AARCH64_INSN_IMM_R,
	AARCH64_INSN_IMM_MAX
};

#define	__AARCH64_INSN_FUNCS(abbr, mask, val)	\
static always_inline bool_t aarch64_insn_is_##abbr(u32 code) \
{ return (code & (mask)) == (val); } \
static always_inline u32 aarch64_insn_get_##abbr##_value(void) \
{ return (val); }

__AARCH64_INSN_FUNCS(b,		0xFC000000, 0x14000000)
__AARCH64_INSN_FUNCS(bl,	0xFC000000, 0x94000000)
__AARCH64_INSN_FUNCS(cbz,	0x7F000000, 0x34000000)
__AARCH64_INSN_FUNCS(cbnz,	0x7F000000, 0x35000000)
__AARCH64_INSN_FUNCS(tbz,	0x7F000000, 0x36000000)
__AARCH64_INSN_FUNCS(tbnz,	0x7F000000, 0x37000000)
__AARCH64_INSN_FUNCS(bcond,	0xFF000010, 0x54000000)

bool aarch64_insn_is_branch_imm(u32 insn);

u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
				  u32 insn, u64 imm);

s32 aarch64_get_branch_offset(u32 insn);
u32 aarch64_set_branch_offset(u32 insn, s32 offset);

/* Wrapper for common code */
static inline bool insn_is_branch_imm(u32 insn)
{
    return aarch64_insn_is_branch_imm(insn);
}

static inline s32 insn_get_branch_offset(u32 insn)
{
    return aarch64_get_branch_offset(insn);
}

static inline u32 insn_set_branch_offset(u32 insn, s32 offset)
{
    return aarch64_set_branch_offset(insn, offset);
}

#endif /* !__ARCH_ARM_ARM64_INSN */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
