/*
 * emulate.h: SVM instruction emulation bits.
 * Copyright (c) 2005, AMD Corporation.
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_SVM_EMULATE_H__
#define __ASM_X86_HVM_SVM_EMULATE_H__

/* Enumerate some standard instructions that we support */
enum instruction_index {
    INSTR_INVD,
    INSTR_WBINVD,
    INSTR_CPUID,
    INSTR_RDMSR,
    INSTR_WRMSR,
    INSTR_VMCALL,
    INSTR_HLT,
    INSTR_INT3,
    INSTR_RDTSC,
    INSTR_PAUSE,
    INSTR_XSETBV,
    INSTR_VMRUN,
    INSTR_VMLOAD,
    INSTR_VMSAVE,
    INSTR_STGI,
    INSTR_CLGI,
    INSTR_INVLPGA,
    INSTR_MAX_COUNT /* Must be last - Number of instructions supported */
};

struct vcpu;

int __get_instruction_length_from_list(
    struct vcpu *, const enum instruction_index *, unsigned int list_count);

static inline int __get_instruction_length(
    struct vcpu *v, enum instruction_index instr)
{
    return __get_instruction_length_from_list(v, &instr, 1);
}

#endif /* __ASM_X86_HVM_SVM_EMULATE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
