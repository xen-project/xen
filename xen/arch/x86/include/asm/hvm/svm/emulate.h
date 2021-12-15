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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_HVM_SVM_EMULATE_H__
#define __ASM_X86_HVM_SVM_EMULATE_H__

/*
 * Encoding for svm_get_insn_len().  We take X86EMUL_OPC() for the main
 * opcode, shifted left to make room for the ModRM byte.
 *
 * The Grp7 instructions have their ModRM byte expressed in octal for easier
 * cross referencing with the opcode extension table.
 */
#define INSTR_ENC(opc, modrm) (((opc) << 8) | (modrm))

#define INSTR_PAUSE       INSTR_ENC(X86EMUL_OPC_F3(0, 0x90), 0)
#define INSTR_INT3        INSTR_ENC(X86EMUL_OPC(   0, 0xcc), 0)
#define INSTR_ICEBP       INSTR_ENC(X86EMUL_OPC(   0, 0xf1), 0)
#define INSTR_HLT         INSTR_ENC(X86EMUL_OPC(   0, 0xf4), 0)
#define INSTR_XSETBV      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0321)
#define INSTR_VMRUN       INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0330)
#define INSTR_VMCALL      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0331)
#define INSTR_VMLOAD      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0332)
#define INSTR_VMSAVE      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0333)
#define INSTR_STGI        INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0334)
#define INSTR_CLGI        INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0335)
#define INSTR_INVLPGA     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0337)
#define INSTR_RDTSCP      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0371)
#define INSTR_INVD        INSTR_ENC(X86EMUL_OPC(0x0f, 0x08), 0)
#define INSTR_WBINVD      INSTR_ENC(X86EMUL_OPC(0x0f, 0x09), 0)
#define INSTR_WRMSR       INSTR_ENC(X86EMUL_OPC(0x0f, 0x30), 0)
#define INSTR_RDTSC       INSTR_ENC(X86EMUL_OPC(0x0f, 0x31), 0)
#define INSTR_RDMSR       INSTR_ENC(X86EMUL_OPC(0x0f, 0x32), 0)
#define INSTR_CPUID       INSTR_ENC(X86EMUL_OPC(0x0f, 0xa2), 0)

struct vcpu;

unsigned int svm_get_insn_len(struct vcpu *v, unsigned int instr_enc);
unsigned int svm_get_task_switch_insn_len(void);

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
