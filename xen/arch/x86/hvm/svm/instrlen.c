/*
 * instrlen.c - calculates the instruction length for all operating modes
 * 
 * Travis Betak, travis.betak@amd.com
 * Copyright (c) 2005 AMD
 *
 * Essentially a very, very stripped version of Keir Fraser's work in 
 * x86_emulate.c.  Used primarily for MMIO.
 */

/*
 * TODO: the way in which we use svm_instrlen is very inefficient as is now 
 * stands.  it will be worth while to return the actual instruction buffer
 * along with the instruction length since we are getting the instruction length
 * so we know how much of the buffer we need to fetch.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <asm/regs.h>
#define DPRINTF DPRINTK
#include <asm-x86/x86_emulate.h>

/*
 * Opcode effective-address decode tables.
 * Note that we only emulate instructions that have at least one memory
 * operand (excluding implicit stack references). We assume that stack
 * references and instruction fetches will never occur in special memory
 * areas that require emulation. So, for example, 'mov <imm>,<reg>' need
 * not be handled.
 */

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define BYTE_OP      (1<<0)  /* 8-bit operands. */
/* Destination operand type. */
#define IMPLICIT_OPS (1<<1)  /* Implicit in opcode. No generic decode. */
#define DST_REG      (2<<1)  /* Register operand. */
#define DST_MEM      (3<<1)  /* Memory operand. */
#define DST_MASK     (3<<1)
/* Source operand type. */
#define SRC_NONE     (0<<3)  /* No source operand. */
#define SRC_IMPLICIT (0<<3)  /* Source operand is implicit in the opcode. */
#define SRC_REG      (1<<3)  /* Register operand. */
#define SRC_MEM      (2<<3)  /* Memory operand. */
#define SRC_IMM      (3<<3)  /* Immediate operand. */
#define SRC_IMMBYTE  (4<<3)  /* 8-bit sign-extended immediate operand. */
#define SRC_MASK     (7<<3)
/* Generic MODRM decode. */
#define MODRM       (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)

static u8 opcode_table[256] = {
    /* 0x00 - 0x07 */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x08 - 0x0F */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x10 - 0x17 */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x18 - 0x1F */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x20 - 0x27 */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x28 - 0x2F */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x30 - 0x37 */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x38 - 0x3F */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, 0,
    /* 0x40 - 0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x87 */
    BYTE_OP | DST_MEM | SRC_IMM | MODRM, DST_MEM | SRC_IMM | MODRM,
    BYTE_OP | DST_MEM | SRC_IMM | MODRM, DST_MEM | SRC_IMMBYTE | MODRM,
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    /* 0x88 - 0x8F */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM,
    BYTE_OP | DST_REG | SRC_MEM | MODRM, DST_REG | SRC_MEM | MODRM,
    0, 0, 0, DST_MEM | SRC_NONE | MODRM | Mov,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    BYTE_OP | DST_REG | SRC_MEM | Mov, DST_REG | SRC_MEM | Mov,
    BYTE_OP | DST_MEM | SRC_REG | Mov, DST_MEM | SRC_REG | Mov,
    BYTE_OP | IMPLICIT_OPS | Mov, IMPLICIT_OPS | Mov,
    BYTE_OP | IMPLICIT_OPS, IMPLICIT_OPS,
    /* 0xA8 - 0xAF */
    0, 0, BYTE_OP | IMPLICIT_OPS | Mov, IMPLICIT_OPS | Mov,
    BYTE_OP | IMPLICIT_OPS | Mov, IMPLICIT_OPS | Mov,
    BYTE_OP | IMPLICIT_OPS, IMPLICIT_OPS,
    /* 0xB0 - 0xBF */
    SRC_IMMBYTE, SRC_IMMBYTE, SRC_IMMBYTE, SRC_IMMBYTE, 
    SRC_IMMBYTE, SRC_IMMBYTE, SRC_IMMBYTE, SRC_IMMBYTE,
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xC0 - 0xC7 */
    BYTE_OP | DST_MEM | SRC_IMM | MODRM, DST_MEM | SRC_IMMBYTE | MODRM, 0, 0,
    0, 0, BYTE_OP | DST_MEM | SRC_IMM | MODRM, DST_MEM | SRC_IMM | MODRM,
    /* 0xC8 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xD7 */
    BYTE_OP | DST_MEM | SRC_IMPLICIT | MODRM, DST_MEM | SRC_IMPLICIT | MODRM,
    BYTE_OP | DST_MEM | SRC_IMPLICIT | MODRM, DST_MEM | SRC_IMPLICIT | MODRM,
    0, 0, 0, 0,
    /* 0xD8 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xF7 */
    0, 0, 0, 0,
    0, 0, BYTE_OP | DST_MEM | SRC_NONE | MODRM, DST_MEM | SRC_NONE | MODRM,
    /* 0xF8 - 0xFF */
    0, 0, 0, 0,
    0, 0, BYTE_OP | DST_MEM | SRC_NONE | MODRM, DST_MEM | SRC_NONE | MODRM
};

static u8 twobyte_table[256] = {
    /* 0x00 - 0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IMPLICIT_OPS | MODRM, 0, 0,
    /* 0x10 - 0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, IMPLICIT_OPS | MODRM, 0, 0, 0, 0, 0, 0, 0,
    /* 0x20 - 0x2F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x30 - 0x3F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x40 - 0x47 */
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    /* 0x48 - 0x4F */
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    DST_REG | SRC_MEM | MODRM | Mov, DST_REG | SRC_MEM | MODRM | Mov,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x8F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    0, 0, 0, DST_MEM | SRC_REG | MODRM, 0, 0, 0, 0,
    /* 0xA8 - 0xAF */
    0, 0, 0, DST_MEM | SRC_REG | MODRM, 0, 0, 0, 0,
    /* 0xB0 - 0xB7 */
    BYTE_OP | DST_MEM | SRC_REG | MODRM, DST_MEM | SRC_REG | MODRM, 0,
    DST_MEM | SRC_REG | MODRM,
    0, 0,
    DST_REG | SRC_MEM | MODRM,
    DST_REG | SRC_REG | MODRM,

    /* 0xB8 - 0xBF */
    0, 0, DST_MEM | SRC_IMMBYTE | MODRM, DST_MEM | SRC_REG | MODRM, 0, 0, 0, 0,
    /* 0xC0 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, IMPLICIT_OPS | MODRM, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xFF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* read from guest memory */
extern int inst_copy_from_guest(unsigned char *buf, unsigned long eip,
        int length);
extern void svm_dump_inst(unsigned long eip);

/* 
 * insn_fetch - fetch the next 1 to 4 bytes from instruction stream 
 * 
 * @_type:   u8, u16, u32, s8, s16, or s32
 * @_size:   1, 2, or 4 bytes
 * @_eip:    address to fetch from guest memory
 * @_length: updated! increments the current instruction length counter by _size
 *
 * INTERNAL this is used internally by svm_instrlen to fetch the next byte,
 * word, or dword from guest memory at location _eip.  we currently use a local
 * unsigned long as the storage buffer since the most bytes we're gonna get
 * is limited to 4.
 */
#define insn_fetch(_type, _size, _eip, _length) \
({  unsigned long _x; \
        if ((rc = inst_copy_from_guest((unsigned char *)(&(_x)), \
                (unsigned long)(_eip), _size)) \
                    != _size) \
        goto done; \
    (_eip) += (_size); \
    (_length) += (_size); \
    (_type)_x; \
})

/**
 * get_instruction_length - returns the current instructions length
 *
 * @regs: guest register state
 * @cr2:  target address
 * @ops:  guest memory operations
 * @mode: guest operating mode
 *
 * EXTERNAL this routine calculates the length of the current instruction
 * pointed to by eip.  The guest state is _not_ changed by this routine.
 */
unsigned long svm_instrlen(struct cpu_user_regs *regs, int mode)
{
    u8 b, d, twobyte = 0;
    u8 modrm, modrm_mod = 0, modrm_reg = 0, modrm_rm = 0;
    unsigned int op_bytes = (mode == 8) ? 4 : mode, ad_bytes = mode;
    unsigned int i;
    int rc = 0;
    u32 length = 0;
    u8 tmp;

    /* Copy the registers so we don't alter the guest's present state */
    volatile struct cpu_user_regs _regs = *regs;

        /* Check for Real Mode */
    if (mode == 2)
        _regs.eip += (_regs.cs << 4); 

    /* Legacy prefix check */
    for (i = 0; i < 8; i++) {
        switch (b = insn_fetch(u8, 1, _regs.eip, length)) {
        case 0x66:  /* operand-size override */
            op_bytes ^= 6;  /* switch between 2/4 bytes */
            break;
        case 0x67:  /* address-size override */
            ad_bytes ^= (mode == 8) ? 12 : 6; /* 2/4/8 bytes */
            break;
        case 0x2e:  /* CS override */
        case 0x3e:  /* DS override */
        case 0x26:  /* ES override */
        case 0x64:  /* FS override */
        case 0x65:  /* GS override */
        case 0x36:  /* SS override */
        case 0xf0:  /* LOCK */
        case 0xf3:  /* REP/REPE/REPZ */
        case 0xf2:  /* REPNE/REPNZ */
            break;
        default:
            goto done_prefixes;
        }
    }

done_prefixes:

    /* REX prefix check */
    if ((mode == 8) && ((b & 0xf0) == 0x40))
    {
        if (b & 8)
            op_bytes = 8;   /* REX.W */
        modrm_reg = (b & 4) << 1;   /* REX.R */
        /* REX.B and REX.X do not need to be decoded. */
        b = insn_fetch(u8, 1, _regs.eip, length);
    }

    /* Opcode byte(s). */
    d = opcode_table[b];
    if (d == 0) 
    {
        /* Two-byte opcode? */
        if (b == 0x0f) {
            twobyte = 1;
            b = insn_fetch(u8, 1, _regs.eip, length);
            d = twobyte_table[b];
        }

        /* Unrecognised? */
        if (d == 0)
            goto cannot_emulate;
    }

    /* MODRM and SIB bytes. */
    if (d & MODRM) 
    {
        modrm = insn_fetch(u8, 1, _regs.eip, length);
        modrm_mod |= (modrm & 0xc0) >> 6;
        modrm_reg |= (modrm & 0x38) >> 3;
        modrm_rm |= (modrm & 0x07);
        switch (modrm_mod) 
        {
        case 0:
            if ((modrm_rm == 4) &&
                (((insn_fetch(u8, 1, _regs.eip,
                      length)) & 7) == 5)) 
            {
                length += 4;
                _regs.eip += 4; /* skip SIB.base disp32 */
            } 
            else if (modrm_rm == 5) 
            {
                length += 4;
                _regs.eip += 4; /* skip disp32 */
            }
            break;
        case 1:
            if (modrm_rm == 4) 
            {
                insn_fetch(u8, 1, _regs.eip, length);
            }
            length += 1;
            _regs.eip += 1; /* skip disp8 */
            break;
        case 2:
            if (modrm_rm == 4)
            {
                insn_fetch(u8, 1, _regs.eip, length);
            }
            length += 4;
            _regs.eip += 4; /* skip disp32 */
            break;
        case 3:
            DPRINTF("Cannot parse ModRM.mod == 3.\n");
            goto cannot_emulate;
        }
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch (d & DST_MASK) 
    {
    case IMPLICIT_OPS:
        /* Special instructions do their own operand decoding. */
        goto done;
    }

    /* Decode and fetch the source operand: register, memory or immediate */
    switch (d & SRC_MASK) 
    {
    case SRC_IMM:
        tmp = (d & BYTE_OP) ? 1 : op_bytes;
        if (tmp == 8)
            tmp = 4;
        /* NB. Immediates are sign-extended as necessary. */
        switch (tmp) {
        case 1:
            insn_fetch(s8, 1, _regs.eip, length);
            break;
        case 2:
            insn_fetch(s16, 2, _regs.eip, length);
            break;
        case 4:
            insn_fetch(s32, 4, _regs.eip, length);
            break;
        }
        break;
    case SRC_IMMBYTE:
        insn_fetch(s8, 1, _regs.eip, length);
        break;
    }

    if (twobyte)
        goto done;

    switch (b) 
    {
    case 0xa0:
    case 0xa1:      /* mov */
        length += ad_bytes;
        _regs.eip += ad_bytes;  /* skip src displacement */
        break;
    case 0xa2:
    case 0xa3:      /* mov */
        length += ad_bytes;
        _regs.eip += ad_bytes;  /* skip dst displacement */
        break;
    case 0xf6:
    case 0xf7:      /* Grp3 */
        switch (modrm_reg) 
        {
        case 0:
        case 1: /* test */
            /* 
             * Special case in Grp3: test has an 
             * immediate source operand. 
             */
            tmp = (d & BYTE_OP) ? 1 : op_bytes;
            if (tmp == 8)
                tmp = 4;
            switch (tmp) 
            {
            case 1:
                insn_fetch(s8, 1, _regs.eip, length);
                break;
            case 2:
                insn_fetch(s16, 2, _regs.eip, length);
                break;
            case 4:
                insn_fetch(s32, 4, _regs.eip, length);
                break;
            }
            goto done;
        }
        break;
    }

done:
    return length;

cannot_emulate:
    DPRINTF("Cannot emulate %02x at address %lx (eip %lx, mode %d)\n",
            b, (unsigned long)_regs.eip, (unsigned long)regs->eip, mode);
    svm_dump_inst(_regs.eip);
    return (unsigned long)-1;
}
