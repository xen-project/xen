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
#ifndef __ARCH_ARM_ARM32_INSN
#define __ARCH_ARM_ARM32_INSN

#include <xen/types.h>

int32_t aarch32_get_branch_offset(uint32_t insn);
uint32_t aarch32_set_branch_offset(uint32_t insn, int32_t offset);

/* Wrapper for common code */
static inline bool insn_is_branch_imm(uint32_t insn)
{
    /*
     * Xen is using ARM execution state only on ARM32 platform. So, the
     * Thumb branch instructions (CBZ, CBNZ, TBB and TBH) will not be used
     * in Xen. The left ARM32 branch instructions are BX, BLX, BL and B.
     * BX is using register as parameter, we don't need to rewrite it. So,
     * we only need to check BLX, BL and B encodings in this function.
     *
     * From ARM DDI 0406C.c Section A8.8.18 and A8.8.25, we can see these
     * three branch instructions' encodings:
     * - b   cccc1010xxxxxxxxxxxxxxxxxxxxxxxx
     * - bl  cccc1011xxxxxxxxxxxxxxxxxxxxxxxx
     * - blx 1111101Hxxxxxxxxxxxxxxxxxxxxxxxx
     *
     * The H bit of blx can be 0 or 1, it depends on the Instruction Sets of
     * target instruction. Regardless, if we mask the conditional bits and
     * bit 24 (H bit of blx), we can see all above branch instructions have
     * the same value 0x0A000000.
     *
     * And from ARM DDI 0406C.c Section A5.7 Table A5-23, we can see that the
     * blx is the only one unconditional instruction has the same value as
     * conditional branch instructions. So, mask the conditional bits will not
     * make other unconditional instruction to hit this check.
     */
    return ( (insn & 0x0E000000) == 0x0A000000 );
}

static inline int32_t insn_get_branch_offset(uint32_t insn)
{
    return aarch32_get_branch_offset(insn);
}

static inline uint32_t insn_set_branch_offset(uint32_t insn, int32_t offset)
{
    return aarch32_set_branch_offset(insn, offset);
}

#endif /* !__ARCH_ARM_ARM32_INSN */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
