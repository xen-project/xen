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
 *
 */

#ifndef __ASM_X86_HVM_SVM_EMULATE_H__
#define __ASM_X86_HVM_SVM_EMULATE_H__

typedef enum OPERATING_MODE_ {
    INVALID_OPERATING_MODE = -1,
    LEGACY_MODE,
    LEGACY_16BIT,
    LONG_MODE,
    COMP_MODE,
    COMP_16BIT,
    OPMODE_16BIT,

    LEGACY_32BIT,
    COMP_32BIT,
    OPMODE_32BIT,

    LONG_64BIT,
    UNKNOWN_OP_MODE,
    NUM_OPERATING_MODES
} OPERATING_MODE;


/* Enumerate some standard instructions that we support */
enum instruction_index {
    INSTR_INVD,
    INSTR_CPUID,
    INSTR_RDMSR,
    INSTR_WRMSR,
    INSTR_RDTSC,
    INSTR_RDTSCP,
    INSTR_CLI,
    INSTR_STI,
    INSTR_RDPMC,
    INSTR_CLGI,
    INSTR_STGI,
    INSTR_VMRUN,
    INSTR_VMLOAD,
    INSTR_VMSAVE,
    INSTR_VMCALL,
    INSTR_PAUSE,
    INSTR_SKINIT,
    INSTR_MOV2CR, /* Mov register to CR */
    INSTR_MOVCR2, /* Not MOV CR2, but MOV CRn to register  */
    INSTR_MOV2DR,
    INSTR_MOVDR2,
    INSTR_PUSHF,
    INSTR_POPF,
    INSTR_RSM,
    INSTR_INVLPG,
    INSTR_INVLPGA,
    INSTR_HLT,
    INSTR_CLTS,
    INSTR_LMSW,
    INSTR_SMSW,
    INSTR_MAX_COUNT /* Must be last - Number of instructions supported */
};


extern unsigned long get_effective_addr_modrm64(
        struct cpu_user_regs *regs, const u8 prefix, int inst_len,
        const u8 *operand, u8 *size);
extern unsigned long get_effective_addr_sib(struct vmcb_struct *vmcb, 
        struct cpu_user_regs *regs, const u8 prefix, const u8 *operand, 
        u8 *size);
extern OPERATING_MODE get_operating_mode (struct vmcb_struct *vmcb);
extern unsigned int decode_dest_reg(u8 prefix, u8 modrm);
extern unsigned int decode_src_reg(u8 prefix, u8 modrm);
extern unsigned long svm_rip2pointer(struct vcpu *v);
extern int __get_instruction_length_from_list(struct vcpu *v,
        enum instruction_index *list, unsigned int list_count, 
        u8 *guest_eip_buf, enum instruction_index *match);


static inline int __get_instruction_length(struct vcpu *v, 
        enum instruction_index instr, u8 *guest_eip_buf)
{
    return __get_instruction_length_from_list(
        v, &instr, 1, guest_eip_buf, NULL);
}


static inline unsigned int is_prefix(u8 opc)
{
    switch ( opc ) {
    case 0x66:
    case 0x67:
    case 0x2E:
    case 0x3E:
    case 0x26:
    case 0x64:
    case 0x65:
    case 0x36:
    case 0xF0:
    case 0xF3:
    case 0xF2:
#if __x86_64__
    case 0x40 ... 0x4f:
#endif /* __x86_64__ */
        return 1;
    }
    return 0;
}


static inline int skip_prefix_bytes(u8 *buf, size_t size)
{
    int index;
    for ( index = 0; index < size && is_prefix(buf[index]); index++ )
        continue;
    return index;
}



static void inline __update_guest_eip(
    struct vmcb_struct *vmcb, int inst_len) 
{
    ASSERT(inst_len > 0);
    vmcb->rip += inst_len;
}

#endif /* __ASM_X86_HVM_SVM_EMULATE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
