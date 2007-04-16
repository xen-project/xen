/*
 * platform.c: handling x86 platform related MMIO instructions
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
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
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <asm/regs.h>
#include <asm/x86_emulate.h>
#include <asm/paging.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <public/hvm/ioreq.h>

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/current.h>

#define DECODE_success  1
#define DECODE_failure  0

#define mk_operand(size_reg, index, seg, flag) \
    (((size_reg) << 24) | ((index) << 16) | ((seg) << 8) | (flag))

#if defined (__x86_64__)
static inline long __get_reg_value(unsigned long reg, int size)
{
    switch ( size ) {
    case BYTE_64:
        return (char)(reg & 0xFF);
    case WORD:
        return (short)(reg & 0xFFFF);
    case LONG:
        return (int)(reg & 0xFFFFFFFF);
    case QUAD:
        return (long)(reg);
    default:
        printk("Error: (__get_reg_value) Invalid reg size\n");
        domain_crash_synchronous();
    }
}

long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs)
{
    if ( size == BYTE ) {
        switch ( index ) {
        case 0: /* %al */
            return (char)(regs->rax & 0xFF);
        case 1: /* %cl */
            return (char)(regs->rcx & 0xFF);
        case 2: /* %dl */
            return (char)(regs->rdx & 0xFF);
        case 3: /* %bl */
            return (char)(regs->rbx & 0xFF);
        case 4: /* %ah */
            return (char)((regs->rax & 0xFF00) >> 8);
        case 5: /* %ch */
            return (char)((regs->rcx & 0xFF00) >> 8);
        case 6: /* %dh */
            return (char)((regs->rdx & 0xFF00) >> 8);
        case 7: /* %bh */
            return (char)((regs->rbx & 0xFF00) >> 8);
        default:
            printk("Error: (get_reg_value) Invalid index value\n");
            domain_crash_synchronous();
        }
        /* NOTREACHED */
    }

    switch ( index ) {
    case 0: return __get_reg_value(regs->rax, size);
    case 1: return __get_reg_value(regs->rcx, size);
    case 2: return __get_reg_value(regs->rdx, size);
    case 3: return __get_reg_value(regs->rbx, size);
    case 4: return __get_reg_value(regs->rsp, size);
    case 5: return __get_reg_value(regs->rbp, size);
    case 6: return __get_reg_value(regs->rsi, size);
    case 7: return __get_reg_value(regs->rdi, size);
    case 8: return __get_reg_value(regs->r8, size);
    case 9: return __get_reg_value(regs->r9, size);
    case 10: return __get_reg_value(regs->r10, size);
    case 11: return __get_reg_value(regs->r11, size);
    case 12: return __get_reg_value(regs->r12, size);
    case 13: return __get_reg_value(regs->r13, size);
    case 14: return __get_reg_value(regs->r14, size);
    case 15: return __get_reg_value(regs->r15, size);
    default:
        printk("Error: (get_reg_value) Invalid index value\n");
        domain_crash_synchronous();
    }
}
#elif defined (__i386__)
static inline long __get_reg_value(unsigned long reg, int size)
{
    switch ( size ) {
    case WORD:
        return (short)(reg & 0xFFFF);
    case LONG:
        return (int)(reg & 0xFFFFFFFF);
    default:
        printk("Error: (__get_reg_value) Invalid reg size\n");
        domain_crash_synchronous();
    }
}

long get_reg_value(int size, int index, int seg, struct cpu_user_regs *regs)
{
    if ( size == BYTE ) {
        switch ( index ) {
        case 0: /* %al */
            return (char)(regs->eax & 0xFF);
        case 1: /* %cl */
            return (char)(regs->ecx & 0xFF);
        case 2: /* %dl */
            return (char)(regs->edx & 0xFF);
        case 3: /* %bl */
            return (char)(regs->ebx & 0xFF);
        case 4: /* %ah */
            return (char)((regs->eax & 0xFF00) >> 8);
        case 5: /* %ch */
            return (char)((regs->ecx & 0xFF00) >> 8);
        case 6: /* %dh */
            return (char)((regs->edx & 0xFF00) >> 8);
        case 7: /* %bh */
            return (char)((regs->ebx & 0xFF00) >> 8);
        default:
            printk("Error: (get_reg_value) Invalid index value\n");
            domain_crash_synchronous();
        }
    }

    switch ( index ) {
    case 0: return __get_reg_value(regs->eax, size);
    case 1: return __get_reg_value(regs->ecx, size);
    case 2: return __get_reg_value(regs->edx, size);
    case 3: return __get_reg_value(regs->ebx, size);
    case 4: return __get_reg_value(regs->esp, size);
    case 5: return __get_reg_value(regs->ebp, size);
    case 6: return __get_reg_value(regs->esi, size);
    case 7: return __get_reg_value(regs->edi, size);
    default:
        printk("Error: (get_reg_value) Invalid index value\n");
        domain_crash_synchronous();
    }
}
#endif

static inline unsigned char *check_prefix(unsigned char *inst,
                                          struct hvm_io_op *mmio_op,
                                          unsigned char *ad_size,
                                          unsigned char *op_size,
                                          unsigned char *seg_sel,
                                          unsigned char *rex_p)
{
    while ( 1 ) {
        switch ( *inst ) {
            /* rex prefix for em64t instructions */
        case 0x40 ... 0x4f:
            *rex_p = *inst;
            break;
        case 0xf3: /* REPZ */
            mmio_op->flags = REPZ;
            break;
        case 0xf2: /* REPNZ */
            mmio_op->flags = REPNZ;
            break;
        case 0xf0: /* LOCK */
            break;
        case 0x2e: /* CS */
        case 0x36: /* SS */
        case 0x3e: /* DS */
        case 0x26: /* ES */
        case 0x64: /* FS */
        case 0x65: /* GS */
            *seg_sel = *inst;
            break;
        case 0x66: /* 32bit->16bit */
            *op_size = WORD;
            break;
        case 0x67:
            *ad_size = WORD;
            break;
        default:
            return inst;
        }
        inst++;
    }
}

static inline unsigned long get_immediate(int ad_size, const unsigned char *inst, int op_size)
{
    int mod, reg, rm;
    unsigned long val = 0;
    int i;

    mod = (*inst >> 6) & 3;
    reg = (*inst >> 3) & 7;
    rm = *inst & 7;

    inst++; //skip ModR/M byte
    if ( ad_size != WORD && mod != 3 && rm == 4 ) {
        inst++; //skip SIB byte
    }

    switch ( mod ) {
    case 0:
        if ( ad_size == WORD ) {
            if ( rm == 6 )
                inst = inst + 2; //disp16, skip 2 bytes
        }
        else {
            if ( rm == 5 )
                inst = inst + 4; //disp32, skip 4 bytes
        }
        break;
    case 1:
        inst++; //disp8, skip 1 byte
        break;
    case 2:
        if ( ad_size == WORD )
            inst = inst + 2; //disp16, skip 2 bytes
        else
            inst = inst + 4; //disp32, skip 4 bytes
        break;
    }

    if ( op_size == QUAD )
        op_size = LONG;

    for ( i = 0; i < op_size; i++ ) {
        val |= (*inst++ & 0xff) << (8 * i);
    }

    return val;
}

/* Some instructions, like "add $imm8, r/m16"/"MOV $imm32, r/m64" require
 * the src immediate operand be sign-extented befere the op is executed. Here
 * we always sign-extend the operand to a "unsigned long" variable.
 *
 * Note: to simplify the logic here, the sign-extension here may be performed
 * redundantly against some instructions, like "MOV $imm16, r/m16" -- however
 * this is harmless, since we always remember the operand's size.
 */
static inline unsigned long get_immediate_sign_ext(int ad_size,
                                                   const unsigned char *inst,
                                                   int op_size)
{
    unsigned long result = get_immediate(ad_size, inst, op_size);

    if ( op_size == QUAD )
        op_size = LONG;

    ASSERT( op_size == BYTE || op_size == WORD || op_size == LONG );

    if ( result & (1UL << ((8*op_size) - 1)) )
    {
        unsigned long mask = ~0UL >> (8 * (sizeof(mask) - op_size));
        result = ~mask | (result & mask);
    }
    return result;
}

static inline int get_index(const unsigned char *inst, unsigned char rex)
{
    int mod, reg, rm;
    int rex_r, rex_b;

    mod = (*inst >> 6) & 3;
    reg = (*inst >> 3) & 7;
    rm = *inst & 7;

    rex_r = (rex >> 2) & 1;
    rex_b = rex & 1;

    //Only one operand in the instruction is register
    if ( mod == 3 ) {
        return (rm + (rex_b << 3));
    } else {
        return (reg + (rex_r << 3));
    }
    return 0;
}

static void init_instruction(struct hvm_io_op *mmio_op)
{
    mmio_op->instr = 0;

    mmio_op->flags = 0;

    mmio_op->operand[0] = 0;
    mmio_op->operand[1] = 0;
    mmio_op->immediate = 0;
}

#define GET_OP_SIZE_FOR_BYTE(size_reg)      \
    do {                                    \
        if ( rex )                          \
            (size_reg) = BYTE_64;           \
        else                                \
            (size_reg) = BYTE;              \
    } while( 0 )

#define GET_OP_SIZE_FOR_NONEBYTE(op_size)   \
    do {                                    \
        if ( rex & 0x8 )                    \
            (op_size) = QUAD;               \
        else if ( (op_size) != WORD )       \
            (op_size) = LONG;               \
    } while( 0 )


/*
 * Decode mem,accumulator operands (as in <opcode> m8/m16/m32, al,ax,eax)
 */
static inline int mem_acc(unsigned char size, struct hvm_io_op *mmio)
{
    mmio->operand[0] = mk_operand(size, 0, 0, MEMORY);
    mmio->operand[1] = mk_operand(size, 0, 0, REGISTER);
    return DECODE_success;
}

/*
 * Decode accumulator,mem operands (as in <opcode> al,ax,eax, m8/m16/m32)
 */
static inline int acc_mem(unsigned char size, struct hvm_io_op *mmio)
{
    mmio->operand[0] = mk_operand(size, 0, 0, REGISTER);
    mmio->operand[1] = mk_operand(size, 0, 0, MEMORY);
    return DECODE_success;
}

/*
 * Decode mem,reg operands (as in <opcode> r32/16, m32/16)
 */
static int mem_reg(unsigned char size, unsigned char *opcode,
                   struct hvm_io_op *mmio_op, unsigned char rex)
{
    int index = get_index(opcode + 1, rex);

    mmio_op->operand[0] = mk_operand(size, 0, 0, MEMORY);
    mmio_op->operand[1] = mk_operand(size, index, 0, REGISTER);
    return DECODE_success;
}

/*
 * Decode reg,mem operands (as in <opcode> m32/16, r32/16)
 */
static int reg_mem(unsigned char size, unsigned char *opcode,
                   struct hvm_io_op *mmio_op, unsigned char rex)
{
    int index = get_index(opcode + 1, rex);

    mmio_op->operand[0] = mk_operand(size, index, 0, REGISTER);
    mmio_op->operand[1] = mk_operand(size, 0, 0, MEMORY);
    return DECODE_success;
}

static int mmio_decode(int address_bytes, unsigned char *opcode,
                       struct hvm_io_op *mmio_op,
                       unsigned char *ad_size, unsigned char *op_size,
                       unsigned char *seg_sel)
{
    unsigned char size_reg = 0;
    unsigned char rex = 0;
    int index;

    *ad_size = 0;
    *op_size = 0;
    *seg_sel = 0;
    init_instruction(mmio_op);

    opcode = check_prefix(opcode, mmio_op, ad_size, op_size, seg_sel, &rex);

    switch ( address_bytes )
    {
    case 2:
        if ( *op_size == WORD )
            *op_size = LONG;
        else if ( *op_size == LONG )
            *op_size = WORD;
        else if ( *op_size == 0 )
            *op_size = WORD;
        if ( *ad_size == WORD )
            *ad_size = LONG;
        else if ( *ad_size == LONG )
            *ad_size = WORD;
        else if ( *ad_size == 0 )
            *ad_size = WORD;
        break;
    case 4:
        if ( *op_size == 0 )
            *op_size = LONG;
        if ( *ad_size == 0 )
            *ad_size = LONG;
        break;
#ifdef __x86_64__
    case 8:
        if ( *op_size == 0 )
            *op_size = rex & 0x8 ? QUAD : LONG;
        if ( *ad_size == WORD )
            *ad_size = LONG;
        else if ( *ad_size == 0 )
            *ad_size = QUAD;
        break;
#endif
    }

    /* the operands order in comments conforms to AT&T convention */

    switch ( *opcode ) {

    case 0x00: /* add r8, m8 */
        mmio_op->instr = INSTR_ADD;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x03: /* add m32/16, r32/16 */
        mmio_op->instr = INSTR_ADD;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0x08: /* or r8, m8 */	
        mmio_op->instr = INSTR_OR;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x09: /* or r32/16, m32/16 */
        mmio_op->instr = INSTR_OR;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x0A: /* or m8, r8 */
        mmio_op->instr = INSTR_OR;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_reg(size_reg, opcode, mmio_op, rex);

    case 0x0B: /* or m32/16, r32/16 */
        mmio_op->instr = INSTR_OR;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0x20: /* and r8, m8 */
        mmio_op->instr = INSTR_AND;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x21: /* and r32/16, m32/16 */
        mmio_op->instr = INSTR_AND;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x22: /* and m8, r8 */
        mmio_op->instr = INSTR_AND;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_reg(size_reg, opcode, mmio_op, rex);

    case 0x23: /* and m32/16, r32/16 */
        mmio_op->instr = INSTR_AND;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0x2B: /* sub m32/16, r32/16 */
        mmio_op->instr = INSTR_SUB;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0x30: /* xor r8, m8 */
        mmio_op->instr = INSTR_XOR;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x31: /* xor r32/16, m32/16 */
        mmio_op->instr = INSTR_XOR;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x32: /* xor m8, r8 */
        mmio_op->instr = INSTR_XOR;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_reg(size_reg, opcode, mmio_op, rex);

    case 0x38: /* cmp r8, m8 */
        mmio_op->instr = INSTR_CMP;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x39: /* cmp r32/16, m32/16 */
        mmio_op->instr = INSTR_CMP;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x3A: /* cmp m8, r8 */
        mmio_op->instr = INSTR_CMP;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_reg(size_reg, opcode, mmio_op, rex);

    case 0x3B: /* cmp m32/16, r32/16 */
        mmio_op->instr = INSTR_CMP;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0x80:
    case 0x81:
    case 0x83:
    {
        unsigned char ins_subtype = (opcode[1] >> 3) & 7;

        if ( opcode[0] == 0x80 ) {
            *op_size = BYTE;
            GET_OP_SIZE_FOR_BYTE(size_reg);
        } else {
            GET_OP_SIZE_FOR_NONEBYTE(*op_size);
            size_reg = *op_size;
        }

        /* opcode 0x83 always has a single byte operand */
        if ( opcode[0] == 0x83 )
            mmio_op->immediate =
                get_immediate_sign_ext(*ad_size, opcode + 1, BYTE);
        else
            mmio_op->immediate =
                get_immediate_sign_ext(*ad_size, opcode + 1, *op_size);

        mmio_op->operand[0] = mk_operand(size_reg, 0, 0, IMMEDIATE);
        mmio_op->operand[1] = mk_operand(size_reg, 0, 0, MEMORY);

        switch ( ins_subtype ) {
        case 0: /* add $imm, m32/16 */
            mmio_op->instr = INSTR_ADD;
            return DECODE_success;

        case 1: /* or $imm, m32/16 */
            mmio_op->instr = INSTR_OR;
            return DECODE_success;

        case 4: /* and $imm, m32/16 */
            mmio_op->instr = INSTR_AND;
            return DECODE_success;

        case 5: /* sub $imm, m32/16 */
            mmio_op->instr = INSTR_SUB;
            return DECODE_success;

        case 6: /* xor $imm, m32/16 */
            mmio_op->instr = INSTR_XOR;
            return DECODE_success;

        case 7: /* cmp $imm, m32/16 */
            mmio_op->instr = INSTR_CMP;
            return DECODE_success;

        default:
            printk("%x/%x, This opcode isn't handled yet!\n",
                   *opcode, ins_subtype);
            return DECODE_failure;
        }
    }

    case 0x84:  /* test r8, m8 */
        mmio_op->instr = INSTR_TEST;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x85: /* test r16/32, m16/32 */
        mmio_op->instr = INSTR_TEST;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x86:  /* xchg m8, r8 */
        mmio_op->instr = INSTR_XCHG;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x87:  /* xchg m16/32, r16/32 */
        mmio_op->instr = INSTR_XCHG;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x88: /* mov r8, m8 */
        mmio_op->instr = INSTR_MOV;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return reg_mem(size_reg, opcode, mmio_op, rex);

    case 0x89: /* mov r32/16, m32/16 */
        mmio_op->instr = INSTR_MOV;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return reg_mem(*op_size, opcode, mmio_op, rex);

    case 0x8A: /* mov m8, r8 */
        mmio_op->instr = INSTR_MOV;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_reg(size_reg, opcode, mmio_op, rex);

    case 0x8B: /* mov m32/16, r32/16 */
        mmio_op->instr = INSTR_MOV;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_reg(*op_size, opcode, mmio_op, rex);

    case 0xA0: /* mov <addr>, al */
        mmio_op->instr = INSTR_MOV;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return mem_acc(size_reg, mmio_op);

    case 0xA1: /* mov <addr>, ax/eax */
        mmio_op->instr = INSTR_MOV;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return mem_acc(*op_size, mmio_op);

    case 0xA2: /* mov al, <addr> */
        mmio_op->instr = INSTR_MOV;
        *op_size = BYTE;
        GET_OP_SIZE_FOR_BYTE(size_reg);
        return acc_mem(size_reg, mmio_op);

    case 0xA3: /* mov ax/eax, <addr> */
        mmio_op->instr = INSTR_MOV;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return acc_mem(*op_size, mmio_op);

    case 0xA4: /* movsb */
        mmio_op->instr = INSTR_MOVS;
        *op_size = BYTE;
        return DECODE_success;

    case 0xA5: /* movsw/movsl */
        mmio_op->instr = INSTR_MOVS;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return DECODE_success;

    case 0xAA: /* stosb */
        mmio_op->instr = INSTR_STOS;
        *op_size = BYTE;
        return DECODE_success;

    case 0xAB: /* stosw/stosl */
        mmio_op->instr = INSTR_STOS;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return DECODE_success;

    case 0xAC: /* lodsb */
        mmio_op->instr = INSTR_LODS;
        *op_size = BYTE;
        return DECODE_success;

    case 0xAD: /* lodsw/lodsl */
        mmio_op->instr = INSTR_LODS;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        return DECODE_success;

    case 0xC6:
        if ( ((opcode[1] >> 3) & 7) == 0 ) { /* mov $imm8, m8 */
            mmio_op->instr = INSTR_MOV;
            *op_size = BYTE;

            mmio_op->operand[0] = mk_operand(*op_size, 0, 0, IMMEDIATE);
            mmio_op->immediate  =
                    get_immediate(*ad_size, opcode + 1, *op_size);
            mmio_op->operand[1] = mk_operand(*op_size, 0, 0, MEMORY);

            return DECODE_success;
        } else
            return DECODE_failure;

    case 0xC7:
        if ( ((opcode[1] >> 3) & 7) == 0 ) { /* mov $imm16/32, m16/32 */
            mmio_op->instr = INSTR_MOV;
            GET_OP_SIZE_FOR_NONEBYTE(*op_size);

            mmio_op->operand[0] = mk_operand(*op_size, 0, 0, IMMEDIATE);
            mmio_op->immediate =
                    get_immediate_sign_ext(*ad_size, opcode + 1, *op_size);
            mmio_op->operand[1] = mk_operand(*op_size, 0, 0, MEMORY);

            return DECODE_success;
        } else
            return DECODE_failure;

    case 0xF6:
    case 0xF7:
        if ( ((opcode[1] >> 3) & 7) == 0 ) { /* test $imm8/16/32, m8/16/32 */
            mmio_op->instr = INSTR_TEST;

            if ( opcode[0] == 0xF6 ) {
                *op_size = BYTE;
                GET_OP_SIZE_FOR_BYTE(size_reg);
            } else {
                GET_OP_SIZE_FOR_NONEBYTE(*op_size);
                size_reg = *op_size;
            }

            mmio_op->operand[0] = mk_operand(size_reg, 0, 0, IMMEDIATE);
            mmio_op->immediate =
                    get_immediate_sign_ext(*ad_size, opcode + 1, *op_size);
            mmio_op->operand[1] = mk_operand(size_reg, 0, 0, MEMORY);

            return DECODE_success;
        } else
            return DECODE_failure;

    case 0xFE:
    case 0xFF:
    {
        unsigned char ins_subtype = (opcode[1] >> 3) & 7;

        if ( opcode[0] == 0xFE ) {
            *op_size = BYTE;
            GET_OP_SIZE_FOR_BYTE(size_reg);
        } else {
            GET_OP_SIZE_FOR_NONEBYTE(*op_size);
            size_reg = *op_size;
        }

        mmio_op->immediate = 1;
        mmio_op->operand[0] = mk_operand(size_reg, 0, 0, IMMEDIATE);
        mmio_op->operand[1] = mk_operand(size_reg, 0, 0, MEMORY);

        switch ( ins_subtype ) {
        case 0: /* inc */
            mmio_op->instr = INSTR_ADD;
            return DECODE_success;

        case 1: /* dec */
            mmio_op->instr = INSTR_SUB;
            return DECODE_success;

        case 6: /* push */
            mmio_op->instr = INSTR_PUSH;
            mmio_op->operand[0] = mmio_op->operand[1];
            return DECODE_success;

        default:
            printk("%x/%x, This opcode isn't handled yet!\n",
                   *opcode, ins_subtype);
            return DECODE_failure;
        }
    }

    case 0x0F:
        break;

    default:
        printk("%x, This opcode isn't handled yet!\n", *opcode);
        return DECODE_failure;
    }

    switch ( *++opcode ) {
    case 0xB6: /* movzx m8, r16/r32/r64 */
        mmio_op->instr = INSTR_MOVZX;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        index = get_index(opcode + 1, rex);
        mmio_op->operand[0] = mk_operand(BYTE, 0, 0, MEMORY);
        mmio_op->operand[1] = mk_operand(*op_size, index, 0, REGISTER);
        return DECODE_success;

    case 0xB7: /* movzx m16, r32/r64 */
        mmio_op->instr = INSTR_MOVZX;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        index = get_index(opcode + 1, rex);
        mmio_op->operand[0] = mk_operand(WORD, 0, 0, MEMORY);
        mmio_op->operand[1] = mk_operand(*op_size, index, 0, REGISTER);
        return DECODE_success;

    case 0xBE: /* movsx m8, r16/r32/r64 */
        mmio_op->instr = INSTR_MOVSX;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        index = get_index(opcode + 1, rex);
        mmio_op->operand[0] = mk_operand(BYTE, 0, 0, MEMORY);
        mmio_op->operand[1] = mk_operand(*op_size, index, 0, REGISTER);
        return DECODE_success;

    case 0xBF: /* movsx m16, r32/r64 */
        mmio_op->instr = INSTR_MOVSX;
        GET_OP_SIZE_FOR_NONEBYTE(*op_size);
        index = get_index(opcode + 1, rex);
        mmio_op->operand[0] = mk_operand(WORD, 0, 0, MEMORY);
        mmio_op->operand[1] = mk_operand(*op_size, index, 0, REGISTER);
        return DECODE_success;

    case 0xA3: /* bt r32, m32 */
        mmio_op->instr = INSTR_BT;
        index = get_index(opcode + 1, rex);
        *op_size = LONG;
        mmio_op->operand[0] = mk_operand(*op_size, index, 0, REGISTER);
        mmio_op->operand[1] = mk_operand(*op_size, 0, 0, MEMORY);
        return DECODE_success;

    case 0xBA:
        if ( ((opcode[1] >> 3) & 7) == 4 ) /* BT $imm8, m16/32/64 */
        {
            mmio_op->instr = INSTR_BT;
            GET_OP_SIZE_FOR_NONEBYTE(*op_size);
            mmio_op->operand[0] = mk_operand(BYTE, 0, 0, IMMEDIATE);
            mmio_op->immediate =
                    (signed char)get_immediate(*ad_size, opcode + 1, BYTE);
            mmio_op->operand[1] = mk_operand(*op_size, 0, 0, MEMORY);
            return DECODE_success;
        }
        else
        {
            printk("0f %x, This opcode subtype isn't handled yet\n", *opcode);
            return DECODE_failure;
        }

    default:
        printk("0f %x, This opcode isn't handled yet\n", *opcode);
        return DECODE_failure;
    }
}

int inst_copy_from_guest(unsigned char *buf, unsigned long guest_eip, int inst_len)
{
    if ( inst_len > MAX_INST_LEN || inst_len <= 0 )
        return 0;
    if ( hvm_copy_from_guest_virt(buf, guest_eip, inst_len) )
        return 0;
    return inst_len;
}

void send_pio_req(unsigned long port, unsigned long count, int size,
                  paddr_t value, int dir, int df, int value_is_ptr)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    if ( size == 0 || count == 0 ) {
        printk("null pio request? port %lx, count %lx, "
               "size %d, value %"PRIpaddr", dir %d, value_is_ptr %d.\n",
               port, count, size, value, dir, value_is_ptr);
    }

    vio = get_ioreq(v);
    if ( vio == NULL ) {
        printk("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send pio with something already pending (%d)?\n",
               p->state);

    p->dir = dir;
    p->data_is_ptr = value_is_ptr;

    p->type = IOREQ_TYPE_PIO;
    p->size = size;
    p->addr = port;
    p->count = count;
    p->df = df;

    p->io_count++;

    p->data = value;

    if ( hvm_portio_intercept(p) )
    {
        p->state = STATE_IORESP_READY;
        hvm_io_assist();
        return;
    }

    hvm_send_assist_req(v);
}

static void send_mmio_req(unsigned char type, unsigned long gpa,
                          unsigned long count, int size, paddr_t value,
                          int dir, int df, int value_is_ptr)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    if ( size == 0 || count == 0 ) {
        printk("null mmio request? type %d, gpa %lx, "
               "count %lx, size %d, value %"PRIpaddr"x, dir %d, "
               "value_is_ptr %d.\n",
               type, gpa, count, size, value, dir, value_is_ptr);
    }

    vio = get_ioreq(v);
    if (vio == NULL) {
        printk("bad shared page\n");
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;

    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send mmio with something already pending (%d)?\n",
               p->state);
    p->dir = dir;
    p->data_is_ptr = value_is_ptr;

    p->type = type;
    p->size = size;
    p->addr = gpa;
    p->count = count;
    p->df = df;

    p->io_count++;

    p->data = value;

    if ( hvm_mmio_intercept(p) || hvm_buffered_io_intercept(p) )
    {
        p->state = STATE_IORESP_READY;
        hvm_io_assist();
        return;
    }

    hvm_send_assist_req(v);
}

void send_timeoffset_req(unsigned long timeoff)
{
    ioreq_t p[1];

    if ( timeoff == 0 )
        return;

    memset(p, 0, sizeof(*p));

    p->type = IOREQ_TYPE_TIMEOFFSET;
    p->size = 4;
    p->dir = IOREQ_WRITE;
    p->data = timeoff;

    p->state = STATE_IOREQ_READY;

    if ( !hvm_buffered_io_send(p) )
        printk("Unsuccessful timeoffset update\n");
}

/* Ask ioemu mapcache to invalidate mappings. */
void send_invalidate_req(void)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_ioreq(v);
    if ( vio == NULL )
    {
        printk("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    p = &vio->vp_ioreq;
    if ( p->state != STATE_IOREQ_NONE )
        printk("WARNING: send invalidate req with something "
               "already pending (%d)?\n", p->state);

    p->type = IOREQ_TYPE_INVALIDATE;
    p->size = 4;
    p->dir = IOREQ_WRITE;
    p->data = ~0UL; /* flush all */
    p->io_count++;

    hvm_send_assist_req(v);
}

static void mmio_operands(int type, unsigned long gpa,
                          struct hvm_io_op *mmio_op,
                          unsigned char op_size)
{
    unsigned long value = 0;
    int df, index, size_reg;
    struct cpu_user_regs *regs = &mmio_op->io_context;

    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    size_reg = operand_size(mmio_op->operand[0]);

    if ( mmio_op->operand[0] & REGISTER ) {            /* dest is memory */
        index = operand_index(mmio_op->operand[0]);
        value = get_reg_value(size_reg, index, 0, regs);
        send_mmio_req(type, gpa, 1, op_size, value, IOREQ_WRITE, df, 0);
    } else if ( mmio_op->operand[0] & IMMEDIATE ) {    /* dest is memory */
        value = mmio_op->immediate;
        send_mmio_req(type, gpa, 1, op_size, value, IOREQ_WRITE, df, 0);
    } else if ( mmio_op->operand[0] & MEMORY ) {       /* dest is register */
        /* send the request and wait for the value */
        if ( (mmio_op->instr == INSTR_MOVZX) ||
             (mmio_op->instr == INSTR_MOVSX) )
            send_mmio_req(type, gpa, 1, size_reg, 0, IOREQ_READ, df, 0);
        else
            send_mmio_req(type, gpa, 1, op_size, 0, IOREQ_READ, df, 0);
    } else {
        printk("%s: invalid dest mode.\n", __func__);
        domain_crash_synchronous();
    }
}

#define GET_REPEAT_COUNT() \
     (mmio_op->flags & REPZ ? (ad_size == WORD ? regs->ecx & 0xFFFF : regs->ecx) : 1)


void handle_mmio(unsigned long gpa)
{
    unsigned long inst_addr;
    struct hvm_io_op *mmio_op;
    struct cpu_user_regs *regs;
    unsigned char inst[MAX_INST_LEN], ad_size, op_size, seg_sel;
    int i, address_bytes, df, inst_len;
    struct vcpu *v = current;

    mmio_op = &v->arch.hvm_vcpu.io_op;
    regs = &mmio_op->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);
    hvm_store_cpu_guest_regs(v, regs, NULL);

    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    address_bytes = hvm_guest_x86_mode(v);
    inst_addr = hvm_get_segment_base(v, x86_seg_cs) + regs->eip;
    inst_len = hvm_instruction_length(inst_addr, address_bytes);
    if ( inst_len <= 0 )
    {
        printk("handle_mmio: failed to get instruction length\n");
        domain_crash_synchronous();
    }

    memset(inst, 0, MAX_INST_LEN);
    if ( inst_copy_from_guest(inst, inst_addr, inst_len) != inst_len ) {
        printk("handle_mmio: failed to copy instruction\n");
        domain_crash_synchronous();
    }

    if ( mmio_decode(address_bytes, inst, mmio_op, &ad_size,
                     &op_size, &seg_sel) == DECODE_failure ) {
        printk("handle_mmio: failed to decode instruction\n");
        printk("mmio opcode: gpa 0x%lx, len %d:", gpa, inst_len);
        for ( i = 0; i < inst_len; i++ )
            printk(" %02x", inst[i] & 0xFF);
        printk("\n");
        domain_crash_synchronous();
    }

    regs->eip += inst_len; /* advance %eip */

    switch ( mmio_op->instr ) {
    case INSTR_MOV:
        mmio_operands(IOREQ_TYPE_COPY, gpa, mmio_op, op_size);
        break;

    case INSTR_MOVS:
    {
        unsigned long count = GET_REPEAT_COUNT();
        int sign = regs->eflags & X86_EFLAGS_DF ? -1 : 1;
        unsigned long addr, gfn; 
        paddr_t paddr;
        int dir, size = op_size;

        ASSERT(count);

        /* determine non-MMIO address */
        addr = regs->edi;
        if ( ad_size == WORD )
            addr &= 0xFFFF;
        addr += hvm_get_segment_base(v, x86_seg_es);
        gfn = paging_gva_to_gfn(v, addr);
        paddr = (paddr_t)gfn << PAGE_SHIFT | (addr & ~PAGE_MASK);
        if ( paddr == gpa )
        {
            enum x86_segment seg;

            dir = IOREQ_WRITE;
            addr = regs->esi;
            if ( ad_size == WORD )
                addr &= 0xFFFF;
            switch ( seg_sel )
            {
            case 0x26: seg = x86_seg_es; break;
            case 0x2e: seg = x86_seg_cs; break;
            case 0x36: seg = x86_seg_ss; break;
            case 0:
            case 0x3e: seg = x86_seg_ds; break;
            case 0x64: seg = x86_seg_fs; break;
            case 0x65: seg = x86_seg_gs; break;
            default: domain_crash_synchronous();
            }
            addr += hvm_get_segment_base(v, seg);
            gfn = paging_gva_to_gfn(v, addr);
            paddr = (paddr_t)gfn << PAGE_SHIFT | (addr & ~PAGE_MASK);
        }
        else
            dir = IOREQ_READ;

        if ( gfn == INVALID_GFN ) 
        {
            /* The guest does not have the non-mmio address mapped. 
             * Need to send in a page fault */
            int errcode = 0;
            /* IO read --> memory write */
            if ( dir == IOREQ_READ ) errcode |= PFEC_write_access;
            regs->eip -= inst_len; /* do not advance %eip */
            hvm_inject_exception(TRAP_page_fault, errcode, addr);
            return;
        }

        /*
         * In case of a movs spanning multiple pages, we break the accesses
         * up into multiple pages (the device model works with non-continguous
         * physical guest pages). To copy just one page, we adjust %ecx and
         * do not advance %eip so that the next rep;movs copies the next page.
         * Unaligned accesses, for example movsl starting at PGSZ-2, are
         * turned into a single copy where we handle the overlapping memory
         * copy ourself. After this copy succeeds, "rep movs" is executed
         * again.
         */
        if ( (addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK) ) {
            unsigned long value = 0;

            mmio_op->flags |= OVERLAP;

            if ( dir == IOREQ_WRITE ) {
                if ( hvm_paging_enabled(v) )
                {
                    int rv = hvm_copy_from_guest_virt(&value, addr, size);
                    if ( rv != 0 ) 
                    {
                        /* Failed on the page-spanning copy.  Inject PF into
                         * the guest for the address where we failed */
                        regs->eip -= inst_len; /* do not advance %eip */
                        /* Must set CR2 at the failing address */ 
                        addr += size - rv;
                        gdprintk(XENLOG_DEBUG, "Pagefault on non-io side of a "
                                 "page-spanning MMIO: va=%#lx\n", addr);
                        hvm_inject_exception(TRAP_page_fault, 0, addr);
                        return;
                    }
                }
                else
                    (void) hvm_copy_from_guest_phys(&value, addr, size);
            } else /* dir != IOREQ_WRITE */
                /* Remember where to write the result, as a *VA*.
                 * Must be a VA so we can handle the page overlap 
                 * correctly in hvm_mmio_assist() */
                mmio_op->addr = addr;

            if ( count != 1 )
                regs->eip -= inst_len; /* do not advance %eip */

            send_mmio_req(IOREQ_TYPE_COPY, gpa, 1, size, value, dir, df, 0);
        } else {
            unsigned long last_addr = sign > 0 ? addr + count * size - 1
                                               : addr - (count - 1) * size;

            if ( (addr & PAGE_MASK) != (last_addr & PAGE_MASK) )
            {
                regs->eip -= inst_len; /* do not advance %eip */

                if ( sign > 0 )
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size + 1;
            }

            ASSERT(count);

            send_mmio_req(IOREQ_TYPE_COPY, gpa, count, size, 
                          paddr, dir, df, 1);
        }
        break;
    }

    case INSTR_MOVZX:
    case INSTR_MOVSX:
        mmio_operands(IOREQ_TYPE_COPY, gpa, mmio_op, op_size);
        break;

    case INSTR_STOS:
        /*
         * Since the destination is always in (contiguous) mmio space we don't
         * need to break it up into pages.
         */
        send_mmio_req(IOREQ_TYPE_COPY, gpa,
                      GET_REPEAT_COUNT(), op_size, regs->eax, IOREQ_WRITE, df, 0);
        break;

    case INSTR_LODS:
        /*
         * Since the source is always in (contiguous) mmio space we don't
         * need to break it up into pages.
         */
        mmio_op->operand[0] = mk_operand(op_size, 0, 0, REGISTER);
        send_mmio_req(IOREQ_TYPE_COPY, gpa,
                      GET_REPEAT_COUNT(), op_size, 0, IOREQ_READ, df, 0);
        break;

    case INSTR_OR:
        mmio_operands(IOREQ_TYPE_OR, gpa, mmio_op, op_size);
        break;

    case INSTR_AND:
        mmio_operands(IOREQ_TYPE_AND, gpa, mmio_op, op_size);
        break;

    case INSTR_ADD:
        mmio_operands(IOREQ_TYPE_ADD, gpa, mmio_op, op_size);
        break;

    case INSTR_SUB:
        mmio_operands(IOREQ_TYPE_SUB, gpa, mmio_op, op_size);
        break;

    case INSTR_XOR:
        mmio_operands(IOREQ_TYPE_XOR, gpa, mmio_op, op_size);
        break;

    case INSTR_PUSH:
        if ( ad_size == WORD )
        {
            mmio_op->addr = (uint16_t)(regs->esp - op_size);
            regs->esp = mmio_op->addr | (regs->esp & ~0xffff);
        }
        else
        {
            regs->esp -= op_size;
            mmio_op->addr = regs->esp;
        }
        /* send the request and wait for the value */
        send_mmio_req(IOREQ_TYPE_COPY, gpa, 1, op_size, 0, IOREQ_READ, df, 0);
        break;

    case INSTR_CMP:        /* Pass through */
    case INSTR_TEST:
        /* send the request and wait for the value */
        send_mmio_req(IOREQ_TYPE_COPY, gpa, 1, op_size, 0, IOREQ_READ, df, 0);
        break;

    case INSTR_BT:
    {
        unsigned long value = 0;
        int index, size;

        if ( mmio_op->operand[0] & REGISTER )
        {
            index = operand_index(mmio_op->operand[0]);
            size = operand_size(mmio_op->operand[0]);
            value = get_reg_value(size, index, 0, regs);
        }
        else if ( mmio_op->operand[0] & IMMEDIATE )
        {
            mmio_op->immediate = mmio_op->immediate;
            value = mmio_op->immediate;
        }
        send_mmio_req(IOREQ_TYPE_COPY, gpa + (value >> 5), 1,
                      op_size, 0, IOREQ_READ, df, 0);
        break;
    }

    case INSTR_XCHG:
        if ( mmio_op->operand[0] & REGISTER ) {
            long value;
            unsigned long operand = mmio_op->operand[0];
            value = get_reg_value(operand_size(operand),
                                  operand_index(operand), 0,
                                  regs);
            /* send the request and wait for the value */
            send_mmio_req(IOREQ_TYPE_XCHG, gpa, 1,
                          op_size, value, IOREQ_WRITE, df, 0);
        } else {
            /* the destination is a register */
            long value;
            unsigned long operand = mmio_op->operand[1];
            value = get_reg_value(operand_size(operand),
                                  operand_index(operand), 0,
                                  regs);
            /* send the request and wait for the value */
            send_mmio_req(IOREQ_TYPE_XCHG, gpa, 1,
                          op_size, value, IOREQ_WRITE, df, 0);
        }
        break;

    default:
        printk("Unhandled MMIO instruction\n");
        domain_crash_synchronous();
    }
}

DEFINE_PER_CPU(int, guest_handles_in_xen_space);

/* Note that copy_{to,from}_user_hvm don't set the A and D bits on
   PTEs, and require the PTE to be writable even when they're only
   trying to read from it.  The guest is expected to deal with
   this. */
unsigned long copy_to_user_hvm(void *to, const void *from, unsigned len)
{
    if ( this_cpu(guest_handles_in_xen_space) )
    {
        memcpy(to, from, len);
        return 0;
    }

    return hvm_copy_to_guest_virt((unsigned long)to, (void *)from, len);
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    if ( this_cpu(guest_handles_in_xen_space) )
    {
        memcpy(to, from, len);
        return 0;
    }

    return hvm_copy_from_guest_virt(to, (unsigned long)from, len);
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
