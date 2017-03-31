/*
  * Copyright (C) 2017 ARM Ltd.
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
#include <xen/lib.h>
#include <xen/bitops.h>
#include <xen/sizes.h>
#include <asm/insn.h>

/* Mask of branch instructions' immediate. */
#define BRANCH_INSN_IMM_MASK    GENMASK(23, 0)
/* Shift of branch instructions' immediate. */
#define BRANCH_INSN_IMM_SHIFT   0

static uint32_t branch_insn_encode_immediate(uint32_t insn, int32_t offset)
{
    uint32_t imm;

    /*
     * Encode the offset to imm. All ARM32 instructions must be word aligned.
     * Therefore the offset value's bits [1:0] equal to zero.
     * (see ARM DDI 0406C.c A8.8.18/A8.8.25 for more encode/decode details
     * about ARM32 branch instructions)
     */
    imm = ((offset >> 2) & BRANCH_INSN_IMM_MASK) << BRANCH_INSN_IMM_SHIFT;

    /* Update the immediate field. */
    insn &= ~(BRANCH_INSN_IMM_MASK << BRANCH_INSN_IMM_SHIFT);
    insn |= imm;

    return insn;
}

/*
 * Decode the branch offset from a branch instruction's imm field.
 * The branch offset is a signed value, so it can be used to compute
 * a new branch target.
 */
int32_t aarch32_get_branch_offset(uint32_t insn)
{
    uint32_t imm;

    /* Retrieve imm from branch instruction. */
    imm = ( insn >> BRANCH_INSN_IMM_SHIFT ) & BRANCH_INSN_IMM_MASK;

    /*
     * Check the imm signed bit. If the imm is a negative value, we
     * have to extend the imm to a full 32 bit negative value.
     */
    if ( imm & BIT(23) )
        imm |= GENMASK(31, 24);

    return (int32_t)(imm << 2);
}

/*
 * Encode the displacement of a branch in the imm field and return the
 * updated instruction.
 */
uint32_t aarch32_set_branch_offset(uint32_t insn, int32_t offset)
{
    /* B/BL support [-32M, 32M) offset (see ARM DDI 0406C.c A4.3). */
    if ( offset < -SZ_32M || offset >= SZ_32M )
    {
        printk(XENLOG_ERR
               "%s: new branch offset out of range.\n", __func__);
        return BUG_OPCODE;
    }

    return branch_insn_encode_immediate(insn, offset);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
