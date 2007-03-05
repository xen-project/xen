/*
 * emulate.c: handling SVM emulate instructions help.
 * Copyright (c) 2005 AMD Corporation.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>


extern int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip,
        int inst_len);

#define REX_PREFIX_BASE 0x40
#define REX_X           0x02
#define REX_W           0x08
#define REX_R           0x04
#define REX_B           0x01

#define IS_REX_PREFIX(prefix) ((prefix & 0xf0) == REX_PREFIX_BASE)

#define DECODE_MODRM_MOD(modrm) ((modrm & 0xC0) >> 6)

#define DECODE_MODRM_REG(prefix, modrm)                             \
    ((prefix & REX_R) && IS_REX_PREFIX(prefix))                     \
        ? (0x08 | ((modrm >> 3) & 0x07)) : ((modrm >> 3) & 0x07)

#define DECODE_MODRM_RM(prefix, modrm)                              \
    ((prefix & REX_B) && IS_REX_PREFIX(prefix))                     \
        ? (0x08 | (modrm & 0x07)) : (modrm & 0x07)

#define DECODE_SIB_SCALE(sib) DECODE_MODRM_MOD(sib)

#define DECODE_SIB_INDEX(prefix, sib)                               \
    ((prefix & REX_X) && IS_REX_PREFIX(prefix))                     \
        ? (0x08 | ((sib >> 3) & 0x07)) : ((sib >> 3) & 0x07)

#define DECODE_SIB_BASE(prefix, sib) DECODE_MODRM_RM(prefix, sib)


static inline unsigned long DECODE_GPR_VALUE(struct vmcb_struct *vmcb, 
        struct cpu_user_regs *regs, u8 gpr_rm)
{
    unsigned long value;
    switch (gpr_rm) 
    { 
    case 0x0: 
        value = regs->eax;
        break;
    case 0x1:
        value = regs->ecx;
        break;
    case 0x2:
        value = regs->edx;
        break;
    case 0x3:
        value = regs->ebx;
        break;
    case 0x4:
        value = (unsigned long)vmcb->rsp;
    case 0x5:
        value = regs->ebp;
        break;
    case 0x6:
        value = regs->esi;
        break;
    case 0x7:
        value = regs->edi;
        break;
#if __x86_64__
    case 0x8:
        value = regs->r8;
        break;
    case 0x9:
        value = regs->r9;
        break;
    case 0xA:
        value = regs->r10;
        break;
    case 0xB:
        value = regs->r11;
        break;
    case 0xC:
        value = regs->r12;
        break;
    case 0xD:
        value = regs->r13;
        break;
    case 0xE:
        value = regs->r14;
        break;
    case 0xF:
        value = regs->r15;
        break;
#endif
    default:
        printk("Invlaid gpr_rm = %d\n", gpr_rm);
        ASSERT(0);
        value = (unsigned long)-1; /* error retrun */
    }
    return value;
}


#define CHECK_LENGTH64(num) \
    if (num > length) \
    { \
        *size = 0; \
        return (unsigned long) -1; \
    }

#define modrm operand [0]

#define sib operand [1]


unsigned long get_effective_addr_modrm64(struct cpu_user_regs *regs, 
                                         const u8 prefix, int inst_len,
                                         const u8 *operand, u8 *size)
{
    unsigned long effective_addr = (unsigned long) -1;
    u8 length, modrm_mod, modrm_rm;
    u32 disp = 0;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    HVM_DBG_LOG(DBG_LEVEL_1, "get_effective_addr_modrm64(): prefix = %x, "
            "length = %d, operand[0,1] = %x %x.\n", prefix, *size, operand [0],
            operand [1]);

    if ((NULL == size) || (NULL == operand) || (1 > *size))
    {
        *size = 0;
        return effective_addr;
    }

    modrm_mod = DECODE_MODRM_MOD(modrm);
    modrm_rm = DECODE_MODRM_RM(prefix, modrm);

    length = *size;
    *size = 1;
    switch (modrm_rm)
    {
    case 0x4:
#if __x86_64__
    case 0xC:
#endif
        if (modrm_mod < 3)
        {
            *size = length;
            effective_addr = get_effective_addr_sib(vmcb, regs, prefix, operand, size);
        }
        else
        {
            effective_addr = DECODE_GPR_VALUE(vmcb, regs, modrm_rm);
        }
        break;

    case 0x5:
        if (0 < modrm_mod)
        {
            effective_addr = regs->ebp;
            *size = 1;
            break;
        }
#if __x86_64__
        /* FALLTHRU */
    case 0xD:
        if (0 < modrm_mod)
        {
            *size = 1;
            effective_addr = regs->r13;
            break;
        }
#endif

        CHECK_LENGTH64(*size + (u8)sizeof(u32));

        memcpy (&disp, operand + 1, sizeof (u32));
        *size += sizeof (u32);

#if __x86_64__
        /* 64-bit mode */
        if (vmcb->cs.attr.fields.l && svm_long_mode_enabled(v))
            return vmcb->rip + inst_len + *size + disp;
#endif
        return disp;

    default:
        effective_addr = DECODE_GPR_VALUE(vmcb, regs, modrm_rm);

    }

    if (3 > modrm_mod)
    {
        if (1 == modrm_mod )
        {
            CHECK_LENGTH64(*size + (u8)sizeof(u8));
            disp = sib;
            *size += sizeof (u8);
        }
        else if (2 == modrm_mod )
        {
            CHECK_LENGTH64(*size + sizeof (u32));
            memcpy (&disp, operand + 1, sizeof (u32));
            *size += sizeof (u32);
        }

        effective_addr += disp;
    }

    return effective_addr;
}


unsigned long get_effective_addr_sib(struct vmcb_struct *vmcb, 
        struct cpu_user_regs *regs, const u8 prefix, const u8 *operand, 
        u8 *size)
{
    unsigned long base, effective_addr = (unsigned long)-1;
    u8 sib_scale, sib_idx, sib_base, length;
    u32 disp = 0;

    if (NULL == size || NULL == operand || 2 > *size)
    {
        *size = 0;
        return effective_addr;
    }

    sib_scale = DECODE_SIB_SCALE(sib);
    sib_idx = DECODE_SIB_INDEX(prefix, sib);
    sib_base = DECODE_SIB_BASE(prefix, sib);

    base = DECODE_GPR_VALUE(vmcb, regs, sib_base);

    if ((unsigned long)-1 == base)
    {
        /* 
         * Surely this is wrong. base should be allowed to be -1, even if
         * it's not the usual case...
         */
        *size = 0;
        return base;
    }

    length = *size;
    *size = 2;
    if (0x5 == (sib_base & 0x5))
    {
        switch (DECODE_MODRM_MOD(modrm))
        {
        case 0:
            CHECK_LENGTH64(*size + (u8)sizeof(u32));
            memcpy (&disp, operand + 2, sizeof(u32));
            *size += sizeof(u32);
            base = disp;
            break;

        case 1:
            CHECK_LENGTH64(*size + (u8)sizeof (u8));
            *size += sizeof(u8);
            base += operand [2];
            break;

        case 2:
            CHECK_LENGTH64(*size + (u8)sizeof (u32));
            memcpy(&disp, operand + 2, sizeof(u32));
            *size += sizeof(u32);
            base += disp;
        }
    }

    if (4 == sib_idx)
        return base;

    effective_addr = DECODE_GPR_VALUE(vmcb, regs, sib_idx);

    effective_addr <<= sib_scale;

    return (effective_addr + base);
}


/* Get the register/mode number of src register in ModRM register. */
unsigned int decode_dest_reg(u8 prefix, u8 m)
{
    return DECODE_MODRM_REG(prefix, m);
}

unsigned int decode_src_reg(u8 prefix, u8 m)
{
    return DECODE_MODRM_RM(prefix, m);
}


unsigned long svm_rip2pointer(struct vcpu *v)
{
    /*
     * The following is subtle. Intuitively this code would be something like:
     *
     *  if (16bit) addr = (cs << 4) + rip; else addr = rip;
     *
     * However, this code doesn't work for code executing after CR0.PE=0,
     * but before the %cs has been updated. We don't get signalled when
     * %cs is update, but fortunately, base contain the valid base address
     * no matter what kind of addressing is used.
     */
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long p = vmcb->cs.base + vmcb->rip;
    if (!(vmcb->cs.attr.fields.l && svm_long_mode_enabled(v)))
        return (u32)p; /* mask to 32 bits */
    /* NB. Should mask to 16 bits if in real mode or 16-bit protected mode. */
    return p;
}


#define MAKE_INSTR(nm, ...) static const u8 OPCODE_##nm[] = { __VA_ARGS__ }

/* 
 * Here's how it works:
 * First byte: Length. 
 * Following bytes: Opcode bytes. 
 * Special case: Last byte, if zero, doesn't need to match. 
 */
MAKE_INSTR(INVD,   2, 0x0f, 0x08);
MAKE_INSTR(CPUID,  2, 0x0f, 0xa2);
MAKE_INSTR(RDMSR,  2, 0x0f, 0x32);
MAKE_INSTR(WRMSR,  2, 0x0f, 0x30);
MAKE_INSTR(RDTSC,  2, 0x0f, 0x31);
MAKE_INSTR(RDTSCP, 3, 0x0f, 0x01, 0xf9);
MAKE_INSTR(CLI,    1, 0xfa);
MAKE_INSTR(STI,    1, 0xfb);
MAKE_INSTR(RDPMC,  2, 0x0f, 0x33);
MAKE_INSTR(CLGI,   3, 0x0f, 0x01, 0xdd);
MAKE_INSTR(STGI,   3, 0x0f, 0x01, 0xdc);
MAKE_INSTR(VMRUN,  3, 0x0f, 0x01, 0xd8);
MAKE_INSTR(VMLOAD, 3, 0x0f, 0x01, 0xda);
MAKE_INSTR(VMSAVE, 3, 0x0f, 0x01, 0xdb);
MAKE_INSTR(VMCALL, 3, 0x0f, 0x01, 0xd9);
MAKE_INSTR(PAUSE,  2, 0xf3, 0x90);
MAKE_INSTR(SKINIT, 3, 0x0f, 0x01, 0xde);
MAKE_INSTR(MOV2CR, 3, 0x0f, 0x22, 0x00);
MAKE_INSTR(MOVCR2, 3, 0x0f, 0x20, 0x00);
MAKE_INSTR(MOV2DR, 3, 0x0f, 0x23, 0x00);
MAKE_INSTR(MOVDR2, 3, 0x0f, 0x21, 0x00);
MAKE_INSTR(PUSHF,  1, 0x9c);
MAKE_INSTR(POPF,   1, 0x9d);
MAKE_INSTR(RSM,    2, 0x0f, 0xaa);
MAKE_INSTR(INVLPG, 3, 0x0f, 0x01, 0x00);
MAKE_INSTR(INVLPGA,3, 0x0f, 0x01, 0xdf);
MAKE_INSTR(HLT,    1, 0xf4);
MAKE_INSTR(CLTS,   2, 0x0f, 0x06);
MAKE_INSTR(LMSW,   3, 0x0f, 0x01, 0x00);
MAKE_INSTR(SMSW,   3, 0x0f, 0x01, 0x00);

static const u8 *opc_bytes[INSTR_MAX_COUNT] = 
{
    [INSTR_INVD]   = OPCODE_INVD,
    [INSTR_CPUID]  = OPCODE_CPUID,
    [INSTR_RDMSR]  = OPCODE_RDMSR,
    [INSTR_WRMSR]  = OPCODE_WRMSR,
    [INSTR_RDTSC]  = OPCODE_RDTSC,
    [INSTR_RDTSCP] = OPCODE_RDTSCP,
    [INSTR_CLI]    = OPCODE_CLI,
    [INSTR_STI]    = OPCODE_STI,
    [INSTR_RDPMC]  = OPCODE_RDPMC,
    [INSTR_CLGI]   = OPCODE_CLGI,
    [INSTR_STGI]   = OPCODE_STGI,
    [INSTR_VMRUN]  = OPCODE_VMRUN,
    [INSTR_VMLOAD] = OPCODE_VMLOAD,
    [INSTR_VMSAVE] = OPCODE_VMSAVE,
    [INSTR_VMCALL] = OPCODE_VMCALL,
    [INSTR_PAUSE]  = OPCODE_PAUSE,
    [INSTR_SKINIT] = OPCODE_SKINIT,
    [INSTR_MOV2CR] = OPCODE_MOV2CR,
    [INSTR_MOVCR2] = OPCODE_MOVCR2,
    [INSTR_MOV2DR] = OPCODE_MOV2DR,
    [INSTR_MOVDR2] = OPCODE_MOVDR2,
    [INSTR_PUSHF]  = OPCODE_PUSHF,
    [INSTR_POPF]   = OPCODE_POPF,
    [INSTR_RSM]    = OPCODE_RSM,
    [INSTR_INVLPG] = OPCODE_INVLPG,
    [INSTR_INVLPGA]= OPCODE_INVLPGA,
    [INSTR_CLTS]   = OPCODE_CLTS,
    [INSTR_HLT]    = OPCODE_HLT,
    [INSTR_LMSW]   = OPCODE_LMSW,
    [INSTR_SMSW]   = OPCODE_SMSW
};

/* 
 * Intel has a vmcs entry to give the instruction length. AMD doesn't.  So we
 * have to do a little bit of work to find out... 
 *
 * The caller can either pass a NULL pointer to the guest_eip_buf, or a pointer
 * to enough bytes to satisfy the instruction including prefix bytes.
 */
int __get_instruction_length_from_list(struct vcpu *v,
        enum instruction_index *list, unsigned int list_count, 
        u8 *guest_eip_buf, enum instruction_index *match)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int inst_len = 0;
    unsigned int i;
    unsigned int j;
    int found = 0;
    enum instruction_index instr = 0;
    u8 buffer[MAX_INST_LEN];
    u8 *buf;
    const u8 *opcode = NULL;

    if (guest_eip_buf)
    {
        buf = guest_eip_buf;
    }
    else
    {
        inst_copy_from_guest(buffer, svm_rip2pointer(v), MAX_INST_LEN);
        buf = buffer;
    }

    for (j = 0; j < list_count; j++)
    {
        instr = list[j];
        opcode = opc_bytes[instr];
        ASSERT(opcode);

        while (inst_len < MAX_INST_LEN && 
                is_prefix(buf[inst_len]) && 
                !is_prefix(opcode[1]))
            inst_len++;

        ASSERT(opcode[0] <= 15);    /* Make sure the table is correct. */
        found = 1;

        for (i = 0; i < opcode[0]; i++)
        {
            /* If the last byte is zero, we just accept it without checking */
            if (i == opcode[0]-1 && opcode[i+1] == 0)
                break;

            if (buf[inst_len+i] != opcode[i+1])
            {
                found = 0;
                break;
            }
        }

        if (found)
            break;
    }

    /* It's a match */
    if (found)
    {
        inst_len += opcode[0];

        ASSERT(inst_len <= MAX_INST_LEN);

        if (match)
            *match = instr;

        return inst_len;
    }

    printk("%s: Mismatch between expected and actual instruction bytes: "
            "eip = %lx\n",  __func__, (unsigned long)vmcb->rip);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
