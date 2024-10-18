/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svm.h: SVM Architecture related definitions
 *
 * Copyright (c) 2005, AMD Corporation.
 * Copyright (c) 2004, Intel Corporation.
 */

#ifndef __X86_HVM_SVM_SVM_PRIV_H__
#define __X86_HVM_SVM_SVM_PRIV_H__

#include <xen/types.h>

struct cpu_user_regs;
struct cpuinfo_x86;
struct vcpu;

void svm_asid_init(const struct cpuinfo_x86 *c);
void svm_asid_handle_vmrun(void);

unsigned long *svm_msrbit(unsigned long *msr_bitmap, uint32_t msr);
void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len);

static inline void svm_vmload_pa(paddr_t vmcb)
{
    asm volatile (
        ".byte 0x0f,0x01,0xda" /* vmload */
        : : "a" (vmcb) : "memory" );
}

static inline void svm_vmsave_pa(paddr_t vmcb)
{
    asm volatile (
        ".byte 0x0f,0x01,0xdb" /* vmsave */
        : : "a" (vmcb) : "memory" );
}

static inline void svm_invlpga(unsigned long linear, uint32_t asid)
{
    asm volatile (
        ".byte 0x0f,0x01,0xdf"
        : /* output */
        : /* input */
        "a" (linear), "c" (asid) );
}

/*
 * Encoding for svm_get_insn_len().  We take X86EMUL_OPC() for the main
 * opcode, shifted left to make room for the ModRM byte.
 *
 * The Grp7 instructions have their ModRM byte expressed in octal for easier
 * cross referencing with the opcode extension table.
 */
#define INSTR_ENC(opc, modrm) (((opc) << 8) | (modrm))

#define INSTR_PAUSE      INSTR_ENC(X86EMUL_OPC_F3(0, 0x90), 0)
#define INSTR_INT3       INSTR_ENC(X86EMUL_OPC(   0, 0xcc), 0)
#define INSTR_ICEBP      INSTR_ENC(X86EMUL_OPC(   0, 0xf1), 0)
#define INSTR_HLT        INSTR_ENC(X86EMUL_OPC(   0, 0xf4), 0)
#define INSTR_XSETBV     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0321) /* octal-ok */
#define INSTR_VMRUN      INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0330) /* octal-ok */
#define INSTR_VMCALL     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0331) /* octal-ok */
#define INSTR_VMLOAD     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0332) /* octal-ok */
#define INSTR_VMSAVE     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0333) /* octal-ok */
#define INSTR_STGI       INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0334) /* octal-ok */
#define INSTR_CLGI       INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0335) /* octal-ok */
#define INSTR_INVLPGA    INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0337) /* octal-ok */
#define INSTR_RDTSCP     INSTR_ENC(X86EMUL_OPC(0x0f, 0x01), 0371) /* octal-ok */
#define INSTR_INVD       INSTR_ENC(X86EMUL_OPC(0x0f, 0x08), 0)
#define INSTR_WBINVD     INSTR_ENC(X86EMUL_OPC(0x0f, 0x09), 0)
#define INSTR_WRMSR      INSTR_ENC(X86EMUL_OPC(0x0f, 0x30), 0)
#define INSTR_RDTSC      INSTR_ENC(X86EMUL_OPC(0x0f, 0x31), 0)
#define INSTR_RDMSR      INSTR_ENC(X86EMUL_OPC(0x0f, 0x32), 0)
#define INSTR_CPUID      INSTR_ENC(X86EMUL_OPC(0x0f, 0xa2), 0)

unsigned int svm_get_insn_len(struct vcpu *v, unsigned int instr_enc);
unsigned int svm_get_task_switch_insn_len(void);

/* TSC rate */
#define DEFAULT_TSC_RATIO       0x0000000100000000ULL
#define TSC_RATIO_RSVD_BITS     0xffffff0000000000ULL

/* EXITINFO1 fields on NPT faults */
#define _NPT_PFEC_with_gla     32
#define NPT_PFEC_with_gla      (1UL<<_NPT_PFEC_with_gla)
#define _NPT_PFEC_in_gpt       33
#define NPT_PFEC_in_gpt        (1UL<<_NPT_PFEC_in_gpt)

#endif /* __X86_HVM_SVM_SVM_PRIV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
