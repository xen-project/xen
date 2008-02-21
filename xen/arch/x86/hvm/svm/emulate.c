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

int inst_copy_from_guest(
    unsigned char *buf, unsigned long guest_eip, int inst_len);

static unsigned int is_prefix(u8 opc)
{
    switch ( opc )
    {
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

static unsigned long svm_rip2pointer(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned long p = vmcb->cs.base + guest_cpu_user_regs()->eip;
    if ( !(vmcb->cs.attr.fields.l && hvm_long_mode_enabled(v)) )
        return (u32)p; /* mask to 32 bits */
    return p;
}

/* 
 * Here's how it works:
 * First byte: Length. 
 * Following bytes: Opcode bytes. 
 * Special case: Last byte, if zero, doesn't need to match. 
 */
#define MAKE_INSTR(nm, ...) static const u8 OPCODE_##nm[] = { __VA_ARGS__ }
MAKE_INSTR(INVD,   2, 0x0f, 0x08);
MAKE_INSTR(WBINVD, 2, 0x0f, 0x09);
MAKE_INSTR(CPUID,  2, 0x0f, 0xa2);
MAKE_INSTR(RDMSR,  2, 0x0f, 0x32);
MAKE_INSTR(WRMSR,  2, 0x0f, 0x30);
MAKE_INSTR(VMCALL, 3, 0x0f, 0x01, 0xd9);
MAKE_INSTR(HLT,    1, 0xf4);
MAKE_INSTR(INT3,   1, 0xcc);

static const u8 *opc_bytes[INSTR_MAX_COUNT] = 
{
    [INSTR_INVD]   = OPCODE_INVD,
    [INSTR_WBINVD] = OPCODE_WBINVD,
    [INSTR_CPUID]  = OPCODE_CPUID,
    [INSTR_RDMSR]  = OPCODE_RDMSR,
    [INSTR_WRMSR]  = OPCODE_WRMSR,
    [INSTR_VMCALL] = OPCODE_VMCALL,
    [INSTR_HLT]    = OPCODE_HLT,
    [INSTR_INT3]   = OPCODE_INT3
};

int __get_instruction_length_from_list(struct vcpu *v,
        enum instruction_index *list, unsigned int list_count, 
        u8 *guest_eip_buf, enum instruction_index *match)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    unsigned int i, j, inst_len = 0;
    int found = 0;
    enum instruction_index instr = 0;
    u8 buffer[MAX_INST_LEN];
    u8 *buf;
    const u8 *opcode = NULL;

    if ( guest_eip_buf )
    {
        buf = guest_eip_buf;
    }
    else
    {
        inst_copy_from_guest(buffer, svm_rip2pointer(v), MAX_INST_LEN);
        buf = buffer;
    }

    for ( j = 0; j < list_count; j++ )
    {
        instr = list[j];
        opcode = opc_bytes[instr];
        ASSERT(opcode);

        while ( (inst_len < MAX_INST_LEN) && 
                is_prefix(buf[inst_len]) && 
                !is_prefix(opcode[1]) )
            inst_len++;

        ASSERT(opcode[0] <= 15);    /* Make sure the table is correct. */
        found = 1;

        for ( i = 0; i < opcode[0]; i++ )
        {
            /* If the last byte is zero, we just accept it without checking */
            if ( (i == (opcode[0]-1)) && (opcode[i+1] == 0) )
                break;

            if ( buf[inst_len+i] != opcode[i+1] )
            {
                found = 0;
                break;
            }
        }

        if ( found )
            goto done;
    }

    printk("%s: Mismatch between expected and actual instruction bytes: "
            "eip = %lx\n",  __func__, (unsigned long)vmcb->rip);
    return 0;

 done:
    inst_len += opcode[0];
    ASSERT(inst_len <= MAX_INST_LEN);
    if ( match )
        *match = instr;
    return inst_len;
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
