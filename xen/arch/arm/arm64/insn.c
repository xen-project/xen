/*
 * Based on Linux v4.6 arch/arm64/kernel.ins.c
 *
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
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
#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sizes.h>
#include <xen/bitops.h>
#include <asm/insn.h>
#include <asm/arm64/insn.h>

#define __kprobes
#define pr_err(fmt, ...) printk(XENLOG_ERR fmt, ## __VA_ARGS__)

bool aarch64_insn_is_branch_imm(u32 insn)
{
	return (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn) ||
		aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn) ||
		aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
		aarch64_insn_is_bcond(insn));
}

static int __kprobes aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
{
	u32 immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("aarch64_insn_decode_immediate: unknown immediate encoding %d\n",
			       type);
			return 0;
		}
	}

	return (insn >> shift) & mask;
}

u32 __kprobes aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
				  u32 insn, u64 imm)
{
	u32 immlo, immhi, mask;
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
		imm >>= ADR_IMM_HILOSPLIT;
		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
		imm = immlo | immhi;
		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("aarch64_insn_encode_immediate: unknown immediate encoding %d\n",
			       type);
			return AARCH64_BREAK_FAULT;
		}
	}

	/* Update the immediate field. */
	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}

static inline long branch_imm_common(unsigned long pc, unsigned long addr,
				     long range)
{
	long offset;

	if ((pc & 0x3) || (addr & 0x3)) {
		pr_err("%s: A64 instructions must be word aligned\n", __func__);
		return range;
	}

	offset = ((long)addr - (long)pc);

	if (offset < -range || offset >= range) {
		pr_err("%s: offset out of range\n", __func__);
		return range;
	}

	return offset;
}

u32 __kprobes aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
					  enum aarch64_insn_branch_type type)
{
	u32 insn;
	long offset;

	/*
	 * B/BL support [-128M, 128M) offset
	 * ARM64 virtual address arrangement guarantees all kernel and module
	 * texts are within +/-128M.
	 */
	offset = branch_imm_common(pc, addr, SZ_128M);
	if (offset >= SZ_128M)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_BRANCH_LINK:
		insn = aarch64_insn_get_bl_value();
		break;
	case AARCH64_INSN_BRANCH_NOLINK:
		insn = aarch64_insn_get_b_value();
		break;
	default:
		pr_err("%s: unknown branch encoding %d\n", __func__, type);
		return AARCH64_BREAK_FAULT;
	}

	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn,
					     offset >> 2);
}

u32 __kprobes aarch64_insn_gen_hint(enum aarch64_insn_hint_op op)
{
	return aarch64_insn_get_hint_value() | op;
}

u32 __kprobes aarch64_insn_gen_nop(void)
{
	return aarch64_insn_gen_hint(AARCH64_INSN_HINT_NOP);
}

/*
 * Decode the imm field of a branch, and return the byte offset as a
 * signed value (so it can be used when computing a new branch
 * target).
 */
s32 aarch64_get_branch_offset(u32 insn)
{
	s32 imm;

	if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_26, insn);
		return (imm << 6) >> 4;
	}

	if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
	    aarch64_insn_is_bcond(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_19, insn);
		return (imm << 13) >> 11;
	}

	if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn)) {
		imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_14, insn);
		return (imm << 18) >> 16;
	}

	/* Unhandled instruction */
	BUG();
}

/*
 * Encode the displacement of a branch in the imm field and return the
 * updated instruction.
 */
u32 aarch64_set_branch_offset(u32 insn, s32 offset)
{
	if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn))
		return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn,
						     offset >> 2);

	if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
	    aarch64_insn_is_bcond(insn))
		return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn,
						     offset >> 2);

	if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn))
		return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_14, insn,
						     offset >> 2);

	/* Unhandled instruction */
	BUG();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
