/*
 * instrlen.c - calculates the instruction length for all operating modes
 * 
 * Travis Betak, travis.betak@amd.com
 * Copyright (c) 2005,2006 AMD
 * Copyright (c) 2005 Keir Fraser
 *
 * Essentially a very, very stripped version of Keir Fraser's work in
 * x86_emulate.c.  Used for MMIO.
 */

/*
 * TODO: The way in which we use hvm_instruction_length is very inefficient as
 * it now stands. It will be worthwhile to return the actual instruction buffer
 * along with the instruction length since one of the reasons we are getting
 * the instruction length is to know how many instruction bytes we need to
 * fetch.
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <asm-x86/x86_emulate.h>

/* read from guest memory */
extern int inst_copy_from_guest(unsigned char *buf, unsigned long eip,
        int length);

/*
 * Opcode effective-address decode tables.
 * Note that we only emulate instructions that have at least one memory
 * operand (excluding implicit stack references). We assume that stack
 * references and instruction fetches will never occur in special memory
 * areas that require emulation. So, for example, 'mov <imm>,<reg>' need
 * not be handled.
 */

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define ImplicitOps (1<<1) /* Implicit in opcode. No generic decode. */
#define DstReg      (2<<1) /* Register operand. */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcNone     (0<<3) /* No source operand. */
#define SrcImplicit (0<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (1<<3) /* Register operand. */
#define SrcMem      (2<<3) /* Memory operand. */
#define SrcMem16    (3<<3) /* Memory operand (16-bit). */
#define SrcMem32    (4<<3) /* Memory operand (32-bit). */
#define SrcImm      (5<<3) /* Immediate operand. */
#define SrcImmByte  (6<<3) /* 8-bit sign-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)

static uint8_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, 0,
    /* 0x40 - 0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x50 - 0x5F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x60 - 0x6F */
    0, 0, 0, DstReg|SrcMem32|ModRM|Mov /* movsxd (x86/64) */,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x70 - 0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    0, 0, 0, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xA0 - 0xA7 */
    ByteOp|DstReg|SrcMem|Mov, DstReg|SrcMem|Mov,
    ByteOp|DstMem|SrcReg|Mov, DstMem|SrcReg|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xA8 - 0xAF */
    0, 0, ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xB0 - 0xBF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM, 0, 0,
    0, 0, ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    /* 0xC8 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM, 
    0, 0, 0, 0,
    /* 0xD8 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xF7 */
    0, 0, 0, 0,
    0, 0, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM,
    /* 0xF8 - 0xFF */
    0, 0, 0, 0,
    0, 0, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

static uint8_t twobyte_table[256] = {
    /* 0x00 - 0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0,
    /* 0x10 - 0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, 0, 0, 0, 0,
    /* 0x20 - 0x2F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x30 - 0x3F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0x40 - 0x47 */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    /* 0x48 - 0x4F */
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
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
    0, 0, 0, DstMem|SrcReg|ModRM, 0, 0, 0, 0, 
    /* 0xA8 - 0xAF */
    0, 0, 0, DstMem|SrcReg|ModRM, 0, 0, 0, 0,
    /* 0xB0 - 0xB7 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM, 0, DstMem|SrcReg|ModRM,
    0, 0, ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xB8 - 0xBF */
    0, 0, DstMem|SrcImmByte|ModRM, DstMem|SrcReg|ModRM,
    0, 0, ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem16|ModRM|Mov,
    /* 0xC0 - 0xCF */
    0, 0, 0, 0, 0, 0, 0, ImplicitOps|ModRM, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xD0 - 0xDF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xE0 - 0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 0xF0 - 0xFF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* 
 * insn_fetch - fetch the next byte from instruction stream
 */
#define insn_fetch()                                                    \
({ uint8_t _x;                                                          \
   if ( length >= 15 )                                                  \
       return -1;                                                       \
   if ( inst_copy_from_guest(&_x, pc, 1) != 1 ) {                       \
       gdprintk(XENLOG_WARNING,                                         \
                "Cannot read from address %lx (eip %lx, mode %d)\n",    \
                pc, org_pc, address_bytes);                             \
       return -1;                                                       \
   }                                                                    \
   pc += 1;                                                             \
   length += 1;                                                         \
   _x;                                                                  \
})

/**
 * hvm_instruction_length - returns the current instructions length
 *
 * @org_pc: guest instruction pointer
 * @mode: guest operating mode
 *
 * EXTERNAL this routine calculates the length of the current instruction
 * pointed to by org_pc.  The guest state is _not_ changed by this routine.
 */
int hvm_instruction_length(unsigned long org_pc, int address_bytes)
{
    uint8_t b, d, twobyte = 0, rex_prefix = 0, modrm_reg = 0;
    unsigned int op_default, op_bytes, ad_default, ad_bytes, tmp;
    int length = 0;
    unsigned long pc = org_pc;

    op_bytes = op_default = ad_bytes = ad_default = address_bytes;
    if ( op_bytes == 8 )
    {
        op_bytes = op_default = 4;
#ifndef __x86_64__
        return -1;
#endif
    }

    /* Legacy prefixes. */
    for ( ; ; )
    {
        switch ( b = insn_fetch() )
        {
        case 0x66: /* operand-size override */
            op_bytes = op_default ^ 6;      /* switch between 2/4 bytes */
            break;
        case 0x67: /* address-size override */
            if ( ad_default == 8 )
                ad_bytes = ad_default ^ 12; /* switch between 4/8 bytes */
            else
                ad_bytes = ad_default ^ 6;  /* switch between 2/4 bytes */
            break;
        case 0x2e: /* CS override */
        case 0x3e: /* DS override */
        case 0x26: /* ES override */
        case 0x64: /* FS override */
        case 0x65: /* GS override */
        case 0x36: /* SS override */
        case 0xf0: /* LOCK */
        case 0xf3: /* REP/REPE/REPZ */
        case 0xf2: /* REPNE/REPNZ */
            break;
#ifdef __x86_64__
        case 0x40 ... 0x4f:
            if ( ad_default == 8 )
            {
                rex_prefix = b;
                continue;
            }
            /* FALLTHRU */
#endif
        default:
            goto done_prefixes;
        }
        rex_prefix = 0;
    }
done_prefixes:

    /* REX prefix. */
    if ( rex_prefix & 8 )
        op_bytes = 8;                   /* REX.W */
    /* REX.B, REX.R, and REX.X do not need to be decoded. */

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 )
    {
        /* Two-byte opcode? */
        if ( b == 0x0f )
        {
            twobyte = 1;
            b = insn_fetch();
            d = twobyte_table[b];
        }

        /* Unrecognised? */
        if ( d == 0 )
            goto cannot_emulate;
    }

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        uint8_t modrm = insn_fetch();
        uint8_t modrm_mod = (modrm & 0xc0) >> 6;
        uint8_t modrm_rm  = (modrm & 0x07);

        modrm_reg = (modrm & 0x38) >> 3;
        if ( modrm_mod == 3 )
        {
            gdprintk(XENLOG_WARNING, "Cannot parse ModRM.mod == 3.\n");
            goto cannot_emulate;
        }

        if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 ) 
                {
                    length += 2;
                    pc += 2; /* skip disp16 */
                }
                break;
            case 1:
                length += 1;
                pc += 1; /* skip disp8 */
                break;
            case 2:
                length += 2;
                pc += 2; /* skip disp16 */
                break;
            }
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm == 4) && 
                     ((insn_fetch() & 7) == 5) )
                {
                    length += 4;
                    pc += 4; /* skip disp32 specified by SIB.base */
                }
                else if ( modrm_rm == 5 )
                {
                    length += 4;
                    pc += 4; /* skip disp32 */
                }
                break;
            case 1:
                if ( modrm_rm == 4 )
                {
                    length += 1;
                    pc += 1;
                }
                length += 1;
                pc += 1; /* skip disp8 */
                break;
            case 2:
                if ( modrm_rm == 4 )
                {
                    length += 1;
                    pc += 1;
                }
                length += 4;
                pc += 4; /* skip disp32 */
                break;
            }
        }
    }

    /* Decode and fetch the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case ImplicitOps:
        /* Special instructions do their own operand decoding. */
        goto done;
    }

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcImm:
        tmp = (d & ByteOp) ? 1 : op_bytes;
        if ( tmp == 8 ) tmp = 4;
        /* NB. Immediates are sign-extended as necessary. */
        length += tmp;
        pc += tmp;
        break;
    case SrcImmByte:
        length += 1;
        pc += 1;
        break;
    }

    if ( twobyte )
        goto done;

    switch ( b )
    {
    case 0xa0 ... 0xa3: /* mov */
        length += ad_bytes;
        pc += ad_bytes; /* skip src/dst displacement */
        break;
    case 0xf6 ... 0xf7: /* Grp3 */
        switch ( modrm_reg )
        {
        case 0 ... 1: /* test */
            /* Special case in Grp3: test has an immediate source operand. */
            tmp = (d & ByteOp) ? 1 : op_bytes;
            if ( tmp == 8 ) tmp = 4;
            length += tmp;
            pc += tmp;
            break;
        }
        break;
    }

done:
    return length < 16 ? length : -1;

cannot_emulate:
    gdprintk(XENLOG_WARNING,
            "Cannot emulate %02x at address %lx (%lx, addr_bytes %d)\n",
            b, pc - 1, org_pc, address_bytes);
    return -1;
}
