/******************************************************************************
 * x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0) /* 8-bit operands. */
/* Destination operand type. */
#define DstNone     (0<<1) /* No destination operand. */
#define DstImplicit (0<<1) /* Destination operand is implicit in the opcode. */
#define DstBitBase  (1<<1) /* Memory operand, bit string. */
#define DstReg      (2<<1) /* Register operand. */
#define DstEax      DstReg /* Register EAX (aka DstReg with no ModRM) */
#define DstMem      (3<<1) /* Memory operand. */
#define DstMask     (3<<1)
/* Source operand type. */
#define SrcNone     (0<<3) /* No source operand. */
#define SrcImplicit (0<<3) /* Source operand is implicit in the opcode. */
#define SrcReg      (1<<3) /* Register operand. */
#define SrcEax      SrcReg /* Register EAX (aka SrcReg with no ModRM) */
#define SrcMem      (2<<3) /* Memory operand. */
#define SrcMem16    (3<<3) /* Memory operand (16-bit). */
#define SrcImm      (4<<3) /* Immediate operand. */
#define SrcImmByte  (5<<3) /* 8-bit sign-extended immediate operand. */
#define SrcImm16    (6<<3) /* 16-bit zero-extended immediate operand. */
#define SrcMask     (7<<3)
/* Generic ModRM decode. */
#define ModRM       (1<<6)
/* vSIB addressing mode (0f38 extension opcodes only), aliasing ModRM. */
#define vSIB        (1<<6)
/* Destination is only written; never read. */
#define Mov         (1<<7)
/* VEX/EVEX (SIMD only): 2nd source operand unused (must be all ones) */
#define TwoOp       Mov
/* All operands are implicit in the opcode. */
#define ImplicitOps (DstImplicit|SrcImplicit)

typedef uint8_t opcode_desc_t;

static const opcode_desc_t opcode_table[256] = {
    /* 0x00 - 0x07 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x08 - 0x0F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, 0,
    /* 0x10 - 0x17 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x18 - 0x1F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x20 - 0x27 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x28 - 0x2F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x30 - 0x37 */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x38 - 0x3F */
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstEax|SrcImm, DstEax|SrcImm, 0, ImplicitOps,
    /* 0x40 - 0x4F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    /* 0x50 - 0x5F */
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x60 - 0x67 */
    ImplicitOps, ImplicitOps, DstReg|SrcMem|ModRM, DstReg|SrcNone|ModRM|Mov,
    0, 0, 0, 0,
    /* 0x68 - 0x6F */
    DstImplicit|SrcImm|Mov, DstReg|SrcImm|ModRM|Mov,
    DstImplicit|SrcImmByte|Mov, DstReg|SrcImmByte|ModRM|Mov,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps|Mov,
    /* 0x70 - 0x77 */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0x78 - 0x7F */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0x80 - 0x87 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImm|ModRM,
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
    ByteOp|DstMem|SrcReg|ModRM, DstMem|SrcReg|ModRM,
    /* 0x88 - 0x8F */
    ByteOp|DstMem|SrcReg|ModRM|Mov, DstMem|SrcReg|ModRM|Mov,
    ByteOp|DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    DstMem|SrcReg|ModRM|Mov, DstReg|SrcNone|ModRM,
    DstReg|SrcMem16|ModRM|Mov, DstMem|SrcNone|ModRM|Mov,
    /* 0x90 - 0x97 */
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    DstImplicit|SrcEax, DstImplicit|SrcEax,
    /* 0x98 - 0x9F */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps|Mov, ImplicitOps|Mov, ImplicitOps, ImplicitOps,
    /* 0xA0 - 0xA7 */
    ByteOp|DstEax|SrcMem|Mov, DstEax|SrcMem|Mov,
    ByteOp|DstMem|SrcEax|Mov, DstMem|SrcEax|Mov,
    ByteOp|ImplicitOps|Mov, ImplicitOps|Mov,
    ByteOp|ImplicitOps, ImplicitOps,
    /* 0xA8 - 0xAF */
    ByteOp|DstEax|SrcImm, DstEax|SrcImm,
    ByteOp|DstImplicit|SrcEax|Mov, DstImplicit|SrcEax|Mov,
    ByteOp|DstEax|SrcImplicit|Mov, DstEax|SrcImplicit|Mov,
    ByteOp|DstImplicit|SrcEax, DstImplicit|SrcEax,
    /* 0xB0 - 0xB7 */
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    ByteOp|DstReg|SrcImm|Mov, ByteOp|DstReg|SrcImm|Mov,
    /* 0xB8 - 0xBF */
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov, DstReg|SrcImm|Mov,
    /* 0xC0 - 0xC7 */
    ByteOp|DstMem|SrcImm|ModRM, DstMem|SrcImmByte|ModRM,
    DstImplicit|SrcImm16, ImplicitOps,
    DstReg|SrcMem|ModRM|Mov, DstReg|SrcMem|ModRM|Mov,
    ByteOp|DstMem|SrcImm|ModRM|Mov, DstMem|SrcImm|ModRM|Mov,
    /* 0xC8 - 0xCF */
    DstImplicit|SrcImm16, ImplicitOps, DstImplicit|SrcImm16, ImplicitOps,
    ImplicitOps, DstImplicit|SrcImmByte, ImplicitOps, ImplicitOps,
    /* 0xD0 - 0xD7 */
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    ByteOp|DstMem|SrcImplicit|ModRM, DstMem|SrcImplicit|ModRM,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte, ImplicitOps, ImplicitOps,
    /* 0xD8 - 0xDF */
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    ImplicitOps|ModRM, ImplicitOps|ModRM|Mov,
    DstImplicit|SrcMem16|ModRM, ImplicitOps|ModRM|Mov,
    /* 0xE0 - 0xE7 */
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    DstEax|SrcImmByte, DstEax|SrcImmByte,
    DstImplicit|SrcImmByte, DstImplicit|SrcImmByte,
    /* 0xE8 - 0xEF */
    DstImplicit|SrcImm|Mov, DstImplicit|SrcImm,
    ImplicitOps, DstImplicit|SrcImmByte,
    DstEax|SrcImplicit, DstEax|SrcImplicit, ImplicitOps, ImplicitOps,
    /* 0xF0 - 0xF7 */
    0, ImplicitOps, 0, 0,
    ImplicitOps, ImplicitOps, ByteOp|ModRM, ModRM,
    /* 0xF8 - 0xFF */
    ImplicitOps, ImplicitOps, ImplicitOps, ImplicitOps,
    ImplicitOps, ImplicitOps, ByteOp|DstMem|SrcNone|ModRM, DstMem|SrcNone|ModRM
};

enum simd_opsize {
    simd_none,

    /*
     * Ordinary packed integers:
     * - 64 bits without prefix 66 (MMX)
     * - 128 bits with prefix 66 (SSEn)
     * - 128/256 bits depending on VEX.L (AVX)
     */
    simd_packed_int,

    /*
     * Ordinary packed/scalar floating point:
     * - 128 bits without prefix or with prefix 66 (SSEn)
     * - 128/256 bits depending on VEX.L (AVX)
     * - 32 bits with prefix F3 (scalar single)
     * - 64 bits with prefix F2 (scalar doubgle)
     */
    simd_any_fp,

    /*
     * Packed floating point:
     * - 128 bits without prefix or with prefix 66 (SSEn)
     * - 128/256 bits depending on VEX.L (AVX)
     */
    simd_packed_fp,

    /*
     * Single precision packed/scalar floating point:
     * - 128 bits without prefix (SSEn)
     * - 128/256 bits depending on VEX.L, no prefix (AVX)
     * - 32 bits with prefix F3 (scalar)
     */
    simd_single_fp,

    /*
     * Scalar floating point:
     * - 32 bits with low opcode bit clear (scalar single)
     * - 64 bits with low opcode bit set (scalar double)
     */
    simd_scalar_fp,

    /*
     * 128 bits of integer or floating point data, with no further
     * formatting information.
     */
    simd_128,

    /* Operand size encoded in non-standard way. */
    simd_other
};
typedef uint8_t simd_opsize_t;

static const struct twobyte_table {
    opcode_desc_t desc;
    simd_opsize_t size;
} twobyte_table[256] = {
    [0x00] = { ModRM },
    [0x01] = { ImplicitOps|ModRM },
    [0x02] = { DstReg|SrcMem16|ModRM },
    [0x03] = { DstReg|SrcMem16|ModRM },
    [0x05] = { ImplicitOps },
    [0x06] = { ImplicitOps },
    [0x07] = { ImplicitOps },
    [0x08] = { ImplicitOps },
    [0x09] = { ImplicitOps },
    [0x0b] = { ImplicitOps },
    [0x0d] = { ImplicitOps|ModRM },
    [0x0e] = { ImplicitOps },
    [0x0f] = { ModRM|SrcImmByte },
    [0x10] = { DstImplicit|SrcMem|ModRM|Mov, simd_any_fp },
    [0x11] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp },
    [0x12] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x13] = { DstMem|SrcImplicit|ModRM|Mov, simd_other },
    [0x14 ... 0x15] = { DstImplicit|SrcMem|ModRM, simd_packed_fp },
    [0x16] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x17] = { DstMem|SrcImplicit|ModRM|Mov, simd_other },
    [0x18 ... 0x1f] = { ImplicitOps|ModRM },
    [0x20 ... 0x21] = { DstMem|SrcImplicit|ModRM },
    [0x22 ... 0x23] = { DstImplicit|SrcMem|ModRM },
    [0x28] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp },
    [0x29] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_fp },
    [0x2a] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x2b] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp },
    [0x2c ... 0x2d] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x2e ... 0x2f] = { ImplicitOps|ModRM|TwoOp },
    [0x30 ... 0x35] = { ImplicitOps },
    [0x37] = { ImplicitOps },
    [0x38] = { DstReg|SrcMem|ModRM },
    [0x3a] = { DstReg|SrcImmByte|ModRM },
    [0x40 ... 0x4f] = { DstReg|SrcMem|ModRM|Mov },
    [0x50] = { DstReg|SrcImplicit|ModRM|Mov },
    [0x51] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_any_fp },
    [0x52 ... 0x53] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_single_fp },
    [0x54 ... 0x57] = { DstImplicit|SrcMem|ModRM, simd_packed_fp },
    [0x58 ... 0x59] = { DstImplicit|SrcMem|ModRM, simd_any_fp },
    [0x5a ... 0x5b] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x5c ... 0x5f] = { DstImplicit|SrcMem|ModRM, simd_any_fp },
    [0x60 ... 0x62] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0x63 ... 0x67] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0x68 ... 0x6a] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0x6b ... 0x6d] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0x6e] = { DstImplicit|SrcMem|ModRM|Mov },
    [0x6f] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_int },
    [0x70] = { SrcImmByte|ModRM|TwoOp, simd_other },
    [0x71 ... 0x73] = { DstImplicit|SrcImmByte|ModRM },
    [0x74 ... 0x76] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0x77] = { DstImplicit|SrcNone },
    [0x78] = { ImplicitOps|ModRM },
    [0x79] = { DstReg|SrcMem|ModRM, simd_packed_int },
    [0x7c ... 0x7d] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0x7e] = { DstMem|SrcImplicit|ModRM|Mov },
    [0x7f] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int },
    [0x80 ... 0x8f] = { DstImplicit|SrcImm },
    [0x90 ... 0x9f] = { ByteOp|DstMem|SrcNone|ModRM|Mov },
    [0xa0 ... 0xa1] = { ImplicitOps|Mov },
    [0xa2] = { ImplicitOps },
    [0xa3] = { DstBitBase|SrcReg|ModRM },
    [0xa4] = { DstMem|SrcImmByte|ModRM },
    [0xa5] = { DstMem|SrcReg|ModRM },
    [0xa6 ... 0xa7] = { ModRM },
    [0xa8 ... 0xa9] = { ImplicitOps|Mov },
    [0xaa] = { ImplicitOps },
    [0xab] = { DstBitBase|SrcReg|ModRM },
    [0xac] = { DstMem|SrcImmByte|ModRM },
    [0xad] = { DstMem|SrcReg|ModRM },
    [0xae] = { ImplicitOps|ModRM },
    [0xaf] = { DstReg|SrcMem|ModRM },
    [0xb0] = { ByteOp|DstMem|SrcReg|ModRM },
    [0xb1] = { DstMem|SrcReg|ModRM },
    [0xb2] = { DstReg|SrcMem|ModRM|Mov },
    [0xb3] = { DstBitBase|SrcReg|ModRM },
    [0xb4 ... 0xb5] = { DstReg|SrcMem|ModRM|Mov },
    [0xb6] = { ByteOp|DstReg|SrcMem|ModRM|Mov },
    [0xb7] = { DstReg|SrcMem16|ModRM|Mov },
    [0xb8] = { DstReg|SrcMem|ModRM },
    [0xb9] = { ModRM },
    [0xba] = { DstBitBase|SrcImmByte|ModRM },
    [0xbb] = { DstBitBase|SrcReg|ModRM },
    [0xbc ... 0xbd] = { DstReg|SrcMem|ModRM },
    [0xbe] = { ByteOp|DstReg|SrcMem|ModRM|Mov },
    [0xbf] = { DstReg|SrcMem16|ModRM|Mov },
    [0xc0] = { ByteOp|DstMem|SrcReg|ModRM },
    [0xc1] = { DstMem|SrcReg|ModRM },
    [0xc2] = { DstImplicit|SrcImmByte|ModRM, simd_any_fp },
    [0xc3] = { DstMem|SrcReg|ModRM|Mov },
    [0xc4] = { DstReg|SrcImmByte|ModRM, simd_packed_int },
    [0xc5] = { DstReg|SrcImmByte|ModRM|Mov },
    [0xc6] = { DstImplicit|SrcImmByte|ModRM, simd_packed_fp },
    [0xc7] = { ImplicitOps|ModRM },
    [0xc8 ... 0xcf] = { ImplicitOps },
    [0xd0] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xd1 ... 0xd3] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xd4 ... 0xd5] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xd6] = { DstMem|SrcImplicit|ModRM|Mov, simd_other },
    [0xd7] = { DstReg|SrcImplicit|ModRM|Mov },
    [0xd8 ... 0xdf] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xe0] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xe1 ... 0xe2] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xe3 ... 0xe5] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xe6] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0xe7] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int },
    [0xe8 ... 0xef] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xf0] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0xf1 ... 0xf3] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xf4 ... 0xf6] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xf7] = { DstMem|SrcMem|ModRM|Mov, simd_packed_int },
    [0xf8 ... 0xfe] = { DstImplicit|SrcMem|ModRM, simd_packed_int },
    [0xff] = { ModRM }
};

/*
 * The next two tables are indexed by high opcode extension byte (the one
 * that's encoded like an immediate) nibble, with each table element then
 * bit-indexed by low opcode extension byte nibble.
 */
static const uint16_t _3dnow_table[16] = {
    [0x0] = (1 << 0xd) /* pi2fd */,
    [0x1] = (1 << 0xd) /* pf2id */,
    [0x9] = (1 << 0x0) /* pfcmpge */ |
            (1 << 0x4) /* pfmin */ |
            (1 << 0x6) /* pfrcp */ |
            (1 << 0x7) /* pfrsqrt */ |
            (1 << 0xa) /* pfsub */ |
            (1 << 0xe) /* pfadd */,
    [0xa] = (1 << 0x0) /* pfcmpgt */ |
            (1 << 0x4) /* pfmax */ |
            (1 << 0x6) /* pfrcpit1 */ |
            (1 << 0x7) /* pfrsqit1 */ |
            (1 << 0xa) /* pfsubr */ |
            (1 << 0xe) /* pfacc */,
    [0xb] = (1 << 0x0) /* pfcmpeq */ |
            (1 << 0x4) /* pfmul */ |
            (1 << 0x6) /* pfrcpit2 */ |
            (1 << 0x7) /* pmulhrw */ |
            (1 << 0xf) /* pavgusb */,
};

static const uint16_t _3dnow_ext_table[16] = {
    [0x0] = (1 << 0xc) /* pi2fw */,
    [0x1] = (1 << 0xc) /* pf2iw */,
    [0x8] = (1 << 0xa) /* pfnacc */ |
            (1 << 0xe) /* pfpnacc */,
    [0xb] = (1 << 0xb) /* pswapd */,
};

/*
 * "two_op" and "four_op" below refer to the number of register operands
 * (one of which possibly also allowing to be a memory one). The named
 * operand counts do not include any immediate operands.
 */
static const struct ext0f38_table {
    uint8_t simd_size:5;
    uint8_t to_mem:1;
    uint8_t two_op:1;
    uint8_t vsib:1;
} ext0f38_table[256] = {
    [0x00 ... 0x0b] = { .simd_size = simd_packed_int },
    [0x0c ... 0x0f] = { .simd_size = simd_packed_fp },
    [0x10] = { .simd_size = simd_packed_int },
    [0x13] = { .simd_size = simd_other, .two_op = 1 },
    [0x14 ... 0x16] = { .simd_size = simd_packed_fp },
    [0x17] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x18 ... 0x19] = { .simd_size = simd_scalar_fp, .two_op = 1 },
    [0x1a] = { .simd_size = simd_128, .two_op = 1 },
    [0x1c ... 0x1e] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x20 ... 0x25] = { .simd_size = simd_other, .two_op = 1 },
    [0x28 ... 0x29] = { .simd_size = simd_packed_int },
    [0x2a] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x2b] = { .simd_size = simd_packed_int },
    [0x2c ... 0x2d] = { .simd_size = simd_other },
    [0x2e ... 0x2f] = { .simd_size = simd_other, .to_mem = 1 },
    [0x30 ... 0x35] = { .simd_size = simd_other, .two_op = 1 },
    [0x36 ... 0x3f] = { .simd_size = simd_packed_int },
    [0x40] = { .simd_size = simd_packed_int },
    [0x41] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x45 ... 0x47] = { .simd_size = simd_packed_int },
    [0x58 ... 0x59] = { .simd_size = simd_other, .two_op = 1 },
    [0x5a] = { .simd_size = simd_128, .two_op = 1 },
    [0x78 ... 0x79] = { .simd_size = simd_other, .two_op = 1 },
    [0x8c] = { .simd_size = simd_other },
    [0x8e] = { .simd_size = simd_other, .to_mem = 1 },
    [0x90 ... 0x93] = { .simd_size = simd_other, .vsib = 1 },
    [0x96 ... 0x9f] = { .simd_size = simd_packed_fp },
    [0xa6 ... 0xaf] = { .simd_size = simd_packed_fp },
    [0xb6 ... 0xbf] = { .simd_size = simd_packed_fp },
    [0xc8 ... 0xcd] = { .simd_size = simd_other },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdc ... 0xdf] = { .simd_size = simd_packed_int },
    [0xf0] = { .two_op = 1 },
    [0xf1] = { .to_mem = 1, .two_op = 1 },
    [0xf2 ... 0xf3] = {},
    [0xf5 ... 0xf7] = {},
};

/* Shift values between src and dst sizes of pmov{s,z}x{b,w,d}{w,d,q}. */
static const uint8_t pmov_convert_delta[] = { 1, 2, 3, 1, 2, 1 };

static const struct ext0f3a_table {
    uint8_t simd_size:5;
    uint8_t to_mem:1;
    uint8_t two_op:1;
    uint8_t four_op:1;
} ext0f3a_table[256] = {
    [0x00] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x01] = { .simd_size = simd_packed_fp, .two_op = 1 },
    [0x02] = { .simd_size = simd_packed_int },
    [0x04 ... 0x05] = { .simd_size = simd_packed_fp, .two_op = 1 },
    [0x06] = { .simd_size = simd_packed_fp },
    [0x08 ... 0x09] = { .simd_size = simd_packed_fp, .two_op = 1 },
    [0x0a ... 0x0b] = { .simd_size = simd_scalar_fp },
    [0x0c ... 0x0d] = { .simd_size = simd_packed_fp },
    [0x0e ... 0x0f] = { .simd_size = simd_packed_int },
    [0x14 ... 0x17] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1 },
    [0x18] = { .simd_size = simd_128 },
    [0x19] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1 },
    [0x1d] = { .simd_size = simd_other, .to_mem = 1, .two_op = 1 },
    [0x20] = { .simd_size = simd_none },
    [0x21] = { .simd_size = simd_other },
    [0x22] = { .simd_size = simd_none },
    [0x38] = { .simd_size = simd_128 },
    [0x39] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1 },
    [0x40 ... 0x41] = { .simd_size = simd_packed_fp },
    [0x42] = { .simd_size = simd_packed_int },
    [0x44] = { .simd_size = simd_packed_int },
    [0x46] = { .simd_size = simd_packed_int },
    [0x48 ... 0x49] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4a ... 0x4b] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4c] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x5c ... 0x5f] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x60 ... 0x63] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x68 ... 0x69] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6a ... 0x6b] = { .simd_size = simd_scalar_fp, .four_op = 1 },
    [0x6c ... 0x6d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6e ... 0x6f] = { .simd_size = simd_scalar_fp, .four_op = 1 },
    [0x78 ... 0x79] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7a ... 0x7b] = { .simd_size = simd_scalar_fp, .four_op = 1 },
    [0x7c ... 0x7d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7e ... 0x7f] = { .simd_size = simd_scalar_fp, .four_op = 1 },
    [0xcc] = { .simd_size = simd_other },
    [0xdf] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xf0] = {},
};

static const opcode_desc_t xop_table[] = {
    DstReg|SrcImmByte|ModRM,
    DstReg|SrcMem|ModRM,
    DstReg|SrcImm|ModRM,
};

static const struct ext8f08_table {
    uint8_t simd_size:5;
    uint8_t two_op:1;
    uint8_t four_op:1;
} ext8f08_table[256] = {
    [0xa2] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x85 ... 0x87] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x8e ... 0x8f] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x95 ... 0x97] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x9e ... 0x9f] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xa3] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xa6] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xb6] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0xc0 ... 0xc3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xcc ... 0xcf] = { .simd_size = simd_packed_int },
    [0xec ... 0xef] = { .simd_size = simd_packed_int },
};

static const struct ext8f09_table {
    uint8_t simd_size:5;
    uint8_t two_op:1;
} ext8f09_table[256] = {
    [0x01 ... 0x02] = { .two_op = 1 },
    [0x80 ... 0x81] = { .simd_size = simd_packed_fp, .two_op = 1 },
    [0x82 ... 0x83] = { .simd_size = simd_scalar_fp, .two_op = 1 },
    [0x90 ... 0x9b] = { .simd_size = simd_packed_int },
    [0xc1 ... 0xc3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xc6 ... 0xc7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xcb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd1 ... 0xd3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd6 ... 0xd7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xe1 ... 0xe3] = { .simd_size = simd_packed_int, .two_op = 1 },
};

#define REX_PREFIX 0x40
#define REX_B 0x01
#define REX_X 0x02
#define REX_R 0x04
#define REX_W 0x08

#define vex_none 0

enum vex_opcx {
    vex_0f = vex_none + 1,
    vex_0f38,
    vex_0f3a,
};

enum vex_pfx {
    vex_66 = vex_none + 1,
    vex_f3,
    vex_f2
};

#define VEX_PREFIX_DOUBLE_MASK 0x1
#define VEX_PREFIX_SCALAR_MASK 0x2

static const uint8_t sse_prefix[] = { 0x66, 0xf3, 0xf2 };

union vex {
    uint8_t raw[2];
    struct {
        uint8_t opcx:5;
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t pfx:2;
        uint8_t l:1;
        uint8_t reg:4;
        uint8_t w:1;
    };
};

#ifdef __x86_64__
# define PFX2 REX_PREFIX
#else
# define PFX2 0x3e
#endif
#define PFX_BYTES 3
#define init_prefixes(stub) ({ \
    uint8_t *buf_ = get_stub(stub); \
    buf_[0] = 0x3e; \
    buf_[1] = PFX2; \
    buf_[2] = 0x0f; \
    buf_ + 3; \
})

#define copy_VEX(ptr, vex) ({ \
    if ( !mode_64bit() ) \
        (vex).reg |= 8; \
    (ptr)[0 - PFX_BYTES] = ext < ext_8f08 ? 0xc4 : 0x8f; \
    (ptr)[1 - PFX_BYTES] = (vex).raw[0]; \
    (ptr)[2 - PFX_BYTES] = (vex).raw[1]; \
    container_of((ptr) + 1 - PFX_BYTES, typeof(vex), raw[0]); \
})

#define copy_REX_VEX(ptr, rex, vex) do { \
    if ( (vex).opcx != vex_none ) \
        copy_VEX(ptr, vex); \
    else \
    { \
        if ( (vex).pfx ) \
            (ptr)[0 - PFX_BYTES] = sse_prefix[(vex).pfx - 1]; \
        /* \
         * "rex" is always zero for other than 64-bit mode, so OR-ing it \
         * into any prefix (and not just REX_PREFIX) is safe on 32-bit \
         * (test harness) builds. \
         */ \
        (ptr)[1 - PFX_BYTES] |= rex; \
    } \
} while (0)

union evex {
    uint8_t raw[3];
    struct {
        uint8_t opcx:2;
        uint8_t mbz:2;
        uint8_t R:1;
        uint8_t b:1;
        uint8_t x:1;
        uint8_t r:1;
        uint8_t pfx:2;
        uint8_t mbs:1;
        uint8_t reg:4;
        uint8_t w:1;
        uint8_t opmsk:3;
        uint8_t RX:1;
        uint8_t bcst:1;
        uint8_t lr:2;
        uint8_t z:1;
    };
};

#define rep_prefix()   (vex.pfx >= vex_f3)
#define repe_prefix()  (vex.pfx == vex_f3)
#define repne_prefix() (vex.pfx == vex_f2)

/* Type, address-of, and value of an instruction's operand. */
struct operand {
    enum { OP_REG, OP_MEM, OP_IMM, OP_NONE } type;
    unsigned int bytes;

    /* Operand value. */
    unsigned long val;

    /* Original operand value. */
    unsigned long orig_val;

    /* OP_REG: Pointer to register field. */
    unsigned long *reg;

    /* OP_MEM: Segment and offset. */
    struct {
        enum x86_segment seg;
        unsigned long    off;
    } mem;
};

struct x86_emulate_state {
    unsigned int op_bytes, ad_bytes;

    enum {
        ext_none = vex_none,
        ext_0f   = vex_0f,
        ext_0f38 = vex_0f38,
        ext_0f3a = vex_0f3a,
        /*
         * For XOP use values such that the respective instruction field
         * can be used without adjustment.
         */
        ext_8f08 = 8,
        ext_8f09,
        ext_8f0a,
    } ext;
    enum {
        rmw_NONE,
        rmw_adc,
        rmw_add,
        rmw_and,
        rmw_btc,
        rmw_btr,
        rmw_bts,
        rmw_dec,
        rmw_inc,
        rmw_neg,
        rmw_not,
        rmw_or,
        rmw_rcl,
        rmw_rcr,
        rmw_rol,
        rmw_ror,
        rmw_sar,
        rmw_sbb,
        rmw_shl,
        rmw_shld,
        rmw_shr,
        rmw_shrd,
        rmw_sub,
        rmw_xadd,
        rmw_xchg,
        rmw_xor,
    } rmw;
    uint8_t modrm, modrm_mod, modrm_reg, modrm_rm;
    uint8_t sib_index, sib_scale;
    uint8_t rex_prefix;
    bool lock_prefix;
    bool not_64bit; /* Instruction not available in 64bit. */
    bool fpu_ctrl;  /* Instruction is an FPU control one. */
    opcode_desc_t desc;
    union vex vex;
    union evex evex;
    enum simd_opsize simd_size;

    /*
     * Data operand effective address (usually computed from ModRM).
     * Default is a memory operand relative to segment DS.
     */
    struct operand ea;

    /* Immediate operand values, if any. Use otherwise unused fields. */
#define imm1 ea.val
#define imm2 ea.orig_val

    unsigned long ip;
    struct cpu_user_regs *regs;

#ifndef NDEBUG
    /*
     * Track caller of x86_decode_insn() to spot missing as well as
     * premature calls to x86_emulate_free_state().
     */
    void *caller;
#endif
};

#ifdef __x86_64__
#define PTR_POISON ((void *)0x8086000000008086UL) /* non-canonical */
#else
#define PTR_POISON NULL /* 32-bit builds are for user-space, so NULL is OK. */
#endif

typedef union {
    uint64_t mmx;
    uint64_t __attribute__ ((aligned(16))) xmm[2];
    uint64_t __attribute__ ((aligned(32))) ymm[4];
} mmval_t;

/*
 * While proper alignment gets specified above, this doesn't get honored by
 * the compiler for automatic variables. Use this helper to instantiate a
 * suitably aligned variable, producing a pointer to access it.
 */
#define DECLARE_ALIGNED(type, var)                                        \
    long __##var[(sizeof(type) + __alignof(type)) / __alignof(long) - 1]; \
    type *const var##p =                                                  \
        (void *)(((long)__##var + __alignof(type) - __alignof(__##var))   \
                 & -__alignof(type))

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define ASM_FLAG_OUT(yes, no) yes
#else
# define ASM_FLAG_OUT(yes, no) no
#endif

/* Floating point status word definitions. */
#define FSW_ES    (1U << 7)

/* MXCSR bit definitions. */
#define MXCSR_MM  (1U << 17)

/* Exception definitions. */
#define EXC_DE  0
#define EXC_DB  1
#define EXC_BP  3
#define EXC_OF  4
#define EXC_BR  5
#define EXC_UD  6
#define EXC_NM  7
#define EXC_DF  8
#define EXC_TS 10
#define EXC_NP 11
#define EXC_SS 12
#define EXC_GP 13
#define EXC_PF 14
#define EXC_MF 16
#define EXC_AC 17
#define EXC_XM 19

#define EXC_HAS_EC                                                      \
    ((1u << EXC_DF) | (1u << EXC_TS) | (1u << EXC_NP) |                 \
     (1u << EXC_SS) | (1u << EXC_GP) | (1u << EXC_PF) | (1u << EXC_AC))

/* Segment selector error code bits. */
#define ECODE_EXT (1 << 0)
#define ECODE_IDT (1 << 1)
#define ECODE_TI  (1 << 2)

/*
 * Instruction emulation:
 * Most instructions are emulated directly via a fragment of inline assembly
 * code. This allows us to save/restore EFLAGS and thus very easily pick up
 * any modified flags.
 */

#if defined(__x86_64__)
#define _LO32 "k"          /* force 32-bit operand */
#define _STK  "%%rsp"      /* stack pointer */
#define _BYTES_PER_LONG "8"
#elif defined(__i386__)
#define _LO32 ""           /* force 32-bit operand */
#define _STK  "%%esp"      /* stack pointer */
#define _BYTES_PER_LONG "4"
#endif

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF | \
                     X86_EFLAGS_AF | X86_EFLAGS_PF | X86_EFLAGS_CF)

/*
 * These EFLAGS bits are modifiable (by POPF and IRET), possibly subject
 * to further CPL and IOPL constraints.
 */
#define EFLAGS_MODIFIABLE (X86_EFLAGS_ID | X86_EFLAGS_AC | X86_EFLAGS_RF | \
                           X86_EFLAGS_NT | X86_EFLAGS_IOPL | X86_EFLAGS_DF | \
                           X86_EFLAGS_IF | X86_EFLAGS_TF | EFLAGS_MASK)

/* Before executing instruction: restore necessary bits in EFLAGS. */
#define _PRE_EFLAGS(_sav, _msk, _tmp)                           \
/* EFLAGS = (_sav & _msk) | (EFLAGS & ~_msk); _sav &= ~_msk; */ \
"movl %"_LO32 _sav",%"_LO32 _tmp"; "                            \
"push %"_tmp"; "                                                \
"push %"_tmp"; "                                                \
"movl %"_msk",%"_LO32 _tmp"; "                                  \
"andl %"_LO32 _tmp",("_STK"); "                                 \
"pushf; "                                                       \
"notl %"_LO32 _tmp"; "                                          \
"andl %"_LO32 _tmp",("_STK"); "                                 \
"andl %"_LO32 _tmp",2*"_BYTES_PER_LONG"("_STK"); "              \
"pop  %"_tmp"; "                                                \
"orl  %"_LO32 _tmp",("_STK"); "                                 \
"popf; "                                                        \
"pop  %"_tmp"; "                                                \
"movl %"_LO32 _tmp",%"_LO32 _sav"; "

/* After executing instruction: write-back necessary bits in EFLAGS. */
#define _POST_EFLAGS(_sav, _msk, _tmp)          \
/* _sav |= EFLAGS & _msk; */                    \
"pushf; "                                       \
"pop  %"_tmp"; "                                \
"andl %"_msk",%"_LO32 _tmp"; "                  \
"orl  %"_LO32 _tmp",%"_LO32 _sav"; "

/* Raw emulation: instruction has two explicit operands. */
#define __emulate_2op_nobyte(_op, src, dst, sz, eflags, wsx,wsy,wdx,wdy,   \
                             lsx,lsy,ldx,ldy, qsx,qsy,qdx,qdy, extra...)   \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"w %"wsx"3,%"wdx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+" wdy (*(dst)), "=&r" (_tmp)                \
            : wsy (src), "i" (EFLAGS_MASK), ## extra );                    \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"l %"lsx"3,%"ldx"1; "                                       \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+" ldy (*(dst)), "=&r" (_tmp)                \
            : lsy (src), "i" (EFLAGS_MASK), ## extra );                    \
        break;                                                             \
    case 8:                                                                \
        __emulate_2op_8byte(_op, src, dst, eflags, qsx, qsy, qdx, qdy,     \
                            ## extra);                                     \
        break;                                                             \
    }                                                                      \
} while (0)
#define __emulate_2op(_op, src, dst, sz, eflags, _bx, by, wx, wy,          \
                      lx, ly, qx, qy, extra...)                            \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","4","2")                                       \
            _op"b %"_bx"3,%1; "                                            \
            _POST_EFLAGS("0","4","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : by (src), "i" (EFLAGS_MASK), ##extra );                      \
        break;                                                             \
    default:                                                               \
        __emulate_2op_nobyte(_op, src, dst, sz, eflags, wx, wy, "", "m",   \
                             lx, ly, "", "m", qx, qy, "", "m", ##extra);   \
        break;                                                             \
    }                                                                      \
} while (0)
/* Source operand is byte-sized and may be restricted to just %cl. */
#define _emulate_2op_SrcB(op, src, dst, sz, eflags)                        \
    __emulate_2op(op, src, dst, sz, eflags,                                \
                  "b", "c", "b", "c", "b", "c", "b", "c")
#define emulate_2op_SrcB(op, src, dst, eflags)                             \
    _emulate_2op_SrcB(op, (src).val, &(dst).val, (dst).bytes, eflags)
/* Source operand is byte, word, long or quad sized. */
#define _emulate_2op_SrcV(op, src, dst, sz, eflags, extra...)              \
    __emulate_2op(op, src, dst, sz, eflags,                                \
                  "b", "q", "w", "r", _LO32, "r", "", "r", ##extra)
#define emulate_2op_SrcV(_op, _src, _dst, _eflags)                         \
    _emulate_2op_SrcV(_op, (_src).val, &(_dst).val, (_dst).bytes, _eflags)
/* Source operand is word, long or quad sized. */
#define _emulate_2op_SrcV_nobyte(op, src, dst, sz, eflags, extra...)       \
    __emulate_2op_nobyte(op, src, dst, sz, eflags, "w", "r", "", "m",      \
                         _LO32, "r", "", "m", "", "r", "", "m", ##extra)
#define emulate_2op_SrcV_nobyte(_op, _src, _dst, _eflags)                  \
    _emulate_2op_SrcV_nobyte(_op, (_src).val, &(_dst).val, (_dst).bytes,   \
                             _eflags)
/* Operands are word, long or quad sized and source may be in memory. */
#define emulate_2op_SrcV_srcmem(_op, _src, _dst, _eflags)                  \
    __emulate_2op_nobyte(_op, (_src).val, &(_dst).val, (_dst).bytes,       \
                         _eflags, "", "m", "w", "r",                       \
                         "", "m", _LO32, "r", "", "m", "", "r")

/* Instruction has only one explicit operand (no source operand). */
#define _emulate_1op(_op, dst, sz, eflags, extra...)                       \
do{ unsigned long _tmp;                                                    \
    switch ( sz )                                                          \
    {                                                                      \
    case 1:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"b %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 2:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"w %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 4:                                                                \
        asm volatile (                                                     \
            _PRE_EFLAGS("0","3","2")                                       \
            _op"l %1; "                                                    \
            _POST_EFLAGS("0","3","2")                                      \
            : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                   \
            : "i" (EFLAGS_MASK), ##extra );                                \
        break;                                                             \
    case 8:                                                                \
        __emulate_1op_8byte(_op, dst, eflags, ##extra);                    \
        break;                                                             \
    }                                                                      \
} while (0)
#define emulate_1op(op, dst, eflags)                                       \
    _emulate_1op(op, &(dst).val, (dst).bytes, eflags)

/* Emulate an instruction with quadword operands (x86/64 only). */
#if defined(__x86_64__)
#define __emulate_2op_8byte(_op, src, dst, eflags,                      \
                            qsx, qsy, qdx, qdy, extra...)               \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","4","2")                                        \
        _op"q %"qsx"3,%"qdx"1; "                                        \
        _POST_EFLAGS("0","4","2")                                       \
        : "+g" (eflags), "+" qdy (*(dst)), "=&r" (_tmp)                 \
        : qsy (src), "i" (EFLAGS_MASK), ##extra );                      \
} while (0)
#define __emulate_1op_8byte(_op, dst, eflags, extra...)                 \
do{ asm volatile (                                                      \
        _PRE_EFLAGS("0","3","2")                                        \
        _op"q %1; "                                                     \
        _POST_EFLAGS("0","3","2")                                       \
        : "+g" (eflags), "+m" (*(dst)), "=&r" (_tmp)                    \
        : "i" (EFLAGS_MASK), ##extra );                                 \
} while (0)
#elif defined(__i386__)
#define __emulate_2op_8byte(op, src, dst, eflags, qsx, qsy, qdx, qdy, extra...)
#define __emulate_1op_8byte(op, dst, eflags, extra...)
#endif /* __i386__ */

#define fail_if(p)                                      \
do {                                                    \
    rc = (p) ? X86EMUL_UNHANDLEABLE : X86EMUL_OKAY;     \
    if ( rc ) goto done;                                \
} while (0)

static inline int mkec(uint8_t e, int32_t ec, ...)
{
    return (e < 32 && ((1u << e) & EXC_HAS_EC)) ? ec : X86_EVENT_NO_EC;
}

#define generate_exception_if(p, e, ec...)                                \
({  if ( (p) ) {                                                          \
        x86_emul_hw_exception(e, mkec(e, ##ec, 0), ctxt);                 \
        rc = X86EMUL_EXCEPTION;                                           \
        goto done;                                                        \
    }                                                                     \
})

#define generate_exception(e, ec...) generate_exception_if(true, e, ##ec)

#ifdef __XEN__
# define invoke_stub(pre, post, constraints...) do {                    \
    stub_exn.info = (union stub_exception_token) { .raw = ~0 };         \
    stub_exn.line = __LINE__; /* Utility outweighs livepatching cost */ \
    asm volatile ( pre "\n\tINDIRECT_CALL %[stub]\n\t" post "\n"        \
                   ".Lret%=:\n\t"                                       \
                   ".pushsection .fixup,\"ax\"\n"                       \
                   ".Lfix%=:\n\t"                                       \
                   "pop %[exn]\n\t"                                     \
                   "jmp .Lret%=\n\t"                                    \
                   ".popsection\n\t"                                    \
                   _ASM_EXTABLE(.Lret%=, .Lfix%=)                       \
                   : [exn] "+g" (stub_exn.info), constraints,           \
                     [stub] "r" (stub.func),                            \
                     "m" (*(uint8_t(*)[MAX_INST_LEN + 1])stub.ptr) );   \
    if ( unlikely(~stub_exn.info.raw) )                                 \
        goto emulation_stub_failure;                                    \
} while (0)
#else
# define invoke_stub(pre, post, constraints...)                         \
    asm volatile ( pre "\n\tcall *%[stub]\n\t" post                     \
                   : constraints, [stub] "rm" (stub.func),              \
                     "m" (*(typeof(stub.buf) *)stub.addr) )
#endif

#define emulate_stub(dst, src...) do {                                  \
    unsigned long tmp;                                                  \
    invoke_stub(_PRE_EFLAGS("[efl]", "[msk]", "[tmp]"),                 \
                _POST_EFLAGS("[efl]", "[msk]", "[tmp]"),                \
                dst, [tmp] "=&r" (tmp), [efl] "+g" (_regs.eflags)       \
                : [msk] "i" (EFLAGS_MASK), ## src);                     \
} while (0)

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size)                                         \
({ unsigned long _x = 0, _ip = state->ip;                               \
   state->ip += (_size); /* real hardware doesn't truncate */           \
   generate_exception_if((uint8_t)(state->ip -                          \
                                   ctxt->regs->r(ip)) > MAX_INST_LEN,   \
                         EXC_GP, 0);                                    \
   rc = ops->insn_fetch(x86_seg_cs, _ip, &_x, (_size), ctxt);           \
   if ( rc ) goto done;                                                 \
   _x;                                                                  \
})
#define insn_fetch_type(_type) ((_type)insn_fetch_bytes(sizeof(_type)))

#define truncate_word(ea, byte_width)           \
({  unsigned long __ea = (ea);                  \
    unsigned int _width = (byte_width);         \
    ((_width == sizeof(unsigned long)) ? __ea : \
     (__ea & ((1UL << (_width << 3)) - 1)));    \
})
#define truncate_ea(ea) truncate_word((ea), ad_bytes)

#ifdef __x86_64__
# define mode_64bit() (ctxt->addr_size == 64)
#else
# define mode_64bit() false
#endif

/*
 * Given byte has even parity (even number of 1s)? SDM Vol. 1 Sec. 3.4.3.1,
 * "Status Flags": EFLAGS.PF reflects parity of least-sig. byte of result only.
 */
static bool even_parity(uint8_t v)
{
    asm ( "test %1,%1" ASM_FLAG_OUT(, "; setp %0")
          : ASM_FLAG_OUT("=@ccp", "=qm") (v) : "q" (v) );

    return v;
}

/* Update address held in a register, based on addressing mode. */
#define _register_address_increment(reg, inc, byte_width)               \
do {                                                                    \
    int _inc = (inc); /* signed type ensures sign extension to long */  \
    unsigned int _width = (byte_width);                                 \
    if ( _width == sizeof(unsigned long) )                              \
        (reg) += _inc;                                                  \
    else if ( mode_64bit() )                                            \
        (reg) = ((reg) + _inc) & ((1UL << (_width << 3)) - 1);          \
    else                                                                \
        (reg) = ((reg) & ~((1UL << (_width << 3)) - 1)) |               \
                (((reg) + _inc) & ((1UL << (_width << 3)) - 1));        \
} while (0)
#define register_address_adjust(reg, adj)                               \
    _register_address_increment(reg,                                    \
                                _regs.eflags & X86_EFLAGS_DF ?          \
                                -(adj) : (adj),                         \
                                ad_bytes)

#define sp_pre_dec(dec) ({                                              \
    _register_address_increment(_regs.r(sp), -(dec), ctxt->sp_size/8);  \
    truncate_word(_regs.r(sp), ctxt->sp_size/8);                        \
})
#define sp_post_inc(inc) ({                                             \
    unsigned long sp = truncate_word(_regs.r(sp), ctxt->sp_size/8);     \
    _register_address_increment(_regs.r(sp), (inc), ctxt->sp_size/8);   \
    sp;                                                                 \
})

#define jmp_rel(rel)                                                    \
do {                                                                    \
    unsigned long ip = _regs.r(ip) + (int)(rel);                        \
    if ( op_bytes == 2 )                                                \
        ip = (uint16_t)ip;                                              \
    else if ( !mode_64bit() )                                           \
        ip = (uint32_t)ip;                                              \
    rc = ops->insn_fetch(x86_seg_cs, ip, NULL, 0, ctxt);                \
    if ( rc ) goto done;                                                \
    _regs.r(ip) = ip;                                                   \
    singlestep = _regs.eflags & X86_EFLAGS_TF;                          \
} while (0)

#define validate_far_branch(cs, ip) ({                                  \
    if ( sizeof(ip) <= 4 ) {                                            \
        ASSERT(!ctxt->lma);                                             \
        generate_exception_if((ip) > (cs)->limit, EXC_GP, 0);           \
    } else                                                              \
        generate_exception_if(ctxt->lma && (cs)->l                      \
                              ? !is_canonical_address(ip)               \
                              : (ip) > (cs)->limit, EXC_GP, 0);         \
})

#define commit_far_branch(cs, newip) ({                                 \
    validate_far_branch(cs, newip);                                     \
    _regs.r(ip) = (newip);                                              \
    singlestep = _regs.eflags & X86_EFLAGS_TF;                          \
    ops->write_segment(x86_seg_cs, cs, ctxt);                           \
})

static int _get_fpu(
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    uint64_t xcr0;
    int rc;

    fail_if(!ops->get_fpu);
    ASSERT(type != X86EMUL_FPU_none);

    if ( type < X86EMUL_FPU_ymm || !ops->read_xcr ||
         ops->read_xcr(0, &xcr0, ctxt) != X86EMUL_OKAY )
    {
        ASSERT(!ctxt->event_pending);
        xcr0 = 0;
    }

    switch ( type )
    {
    case X86EMUL_FPU_ymm:
        if ( !(xcr0 & X86_XCR0_SSE) || !(xcr0 & X86_XCR0_YMM) )
            return X86EMUL_UNHANDLEABLE;
        break;

    default:
        break;
    }

    rc = ops->get_fpu(type, ctxt);

    if ( rc == X86EMUL_OKAY )
    {
        unsigned long cr0;

        fail_if(type == X86EMUL_FPU_fpu && !ops->put_fpu);

        fail_if(!ops->read_cr);
        if ( type >= X86EMUL_FPU_xmm )
        {
            unsigned long cr4;

            rc = ops->read_cr(4, &cr4, ctxt);
            if ( rc != X86EMUL_OKAY )
                return rc;
            generate_exception_if(!(cr4 & ((type == X86EMUL_FPU_xmm)
                                           ? X86_CR4_OSFXSR : X86_CR4_OSXSAVE)),
                                  EXC_UD);
        }

        rc = ops->read_cr(0, &cr0, ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
        if ( type >= X86EMUL_FPU_ymm )
        {
            /* Should be unreachable if VEX decoding is working correctly. */
            ASSERT((cr0 & X86_CR0_PE) && !(ctxt->regs->eflags & X86_EFLAGS_VM));
        }
        if ( cr0 & X86_CR0_EM )
        {
            generate_exception_if(type == X86EMUL_FPU_fpu, EXC_NM);
            generate_exception_if(type == X86EMUL_FPU_mmx, EXC_UD);
            generate_exception_if(type == X86EMUL_FPU_xmm, EXC_UD);
        }
        generate_exception_if((cr0 & X86_CR0_TS) &&
                              (type != X86EMUL_FPU_wait || (cr0 & X86_CR0_MP)),
                              EXC_NM);
    }

 done:
    return rc;
}

#define get_fpu(type)                                           \
do {                                                            \
    rc = _get_fpu(fpu_type = (type), ctxt, ops);                \
    if ( rc ) goto done;                                        \
} while (0)

static void put_fpu(
    enum x86_emulate_fpu_type type,
    bool failed_late,
    const struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    if ( unlikely(failed_late) && type == X86EMUL_FPU_fpu )
        ops->put_fpu(ctxt, X86EMUL_FPU_fpu, NULL);
    else if ( unlikely(type == X86EMUL_FPU_fpu) && !state->fpu_ctrl )
    {
        struct x86_emul_fpu_aux aux = {
            .ip = ctxt->regs->r(ip),
            .cs = ctxt->regs->cs,
            .op = ((ctxt->opcode & 7) << 8) | state->modrm,
        };
        struct segment_register sreg;

        if ( ops->read_segment &&
             ops->read_segment(x86_seg_cs, &sreg, ctxt) == X86EMUL_OKAY )
            aux.cs = sreg.sel;
        if ( state->ea.type == OP_MEM )
        {
            aux.dp = state->ea.mem.off;
            if ( ops->read_segment &&
                 ops->read_segment(state->ea.mem.seg, &sreg,
                                   ctxt) == X86EMUL_OKAY )
                aux.ds = sreg.sel;
            else
                switch ( state->ea.mem.seg )
                {
                case x86_seg_cs: aux.ds = ctxt->regs->cs; break;
                case x86_seg_ds: aux.ds = ctxt->regs->ds; break;
                case x86_seg_es: aux.ds = ctxt->regs->es; break;
                case x86_seg_fs: aux.ds = ctxt->regs->fs; break;
                case x86_seg_gs: aux.ds = ctxt->regs->gs; break;
                case x86_seg_ss: aux.ds = ctxt->regs->ss; break;
                default:         ASSERT_UNREACHABLE();    break;
                }
            aux.dval = true;
        }
        ops->put_fpu(ctxt, X86EMUL_FPU_none, &aux);
    }
    else if ( type != X86EMUL_FPU_none && ops->put_fpu )
        ops->put_fpu(ctxt, X86EMUL_FPU_none, NULL);
}

static inline bool fpu_check_write(void)
{
    uint16_t fsw;

    asm ( "fnstsw %0" : "=am" (fsw) );

    return !(fsw & FSW_ES);
}

#define emulate_fpu_insn_memdst(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    insn_bytes = 2;                                                     \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "+m" (arg) : "a" (&(arg)));                     \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_memsrc(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "=m" (dummy) : "m" (arg), "a" (&(arg)));        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub(bytes...)                                 \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub("", "", "=m" (dummy) : "i" (0));                        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub_eflags(bytes...)                          \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    unsigned long tmp_;                                                 \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),             \
                _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),            \
                [eflags] "+g" (_regs.eflags), [tmp] "=&r" (tmp_)        \
                : [mask] "i" (X86_EFLAGS_ZF|X86_EFLAGS_PF|X86_EFLAGS_CF)); \
    put_stub(stub);                                                     \
} while (0)

static inline unsigned long get_loop_count(
    const struct cpu_user_regs *regs,
    int ad_bytes)
{
    return (ad_bytes > 4) ? regs->r(cx)
                          : (ad_bytes < 4) ? regs->cx : regs->ecx;
}

static inline void put_loop_count(
    struct cpu_user_regs *regs,
    int ad_bytes,
    unsigned long count)
{
    if ( ad_bytes == 2 )
        regs->cx = count;
    else
        regs->r(cx) = ad_bytes == 4 ? (uint32_t)count : count;
}

#define get_rep_prefix(using_si, using_di) ({                           \
    unsigned long max_reps = 1;                                         \
    if ( rep_prefix() )                                                 \
        max_reps = get_loop_count(&_regs, ad_bytes);                    \
    if ( max_reps == 0 )                                                \
    {                                                                   \
        /*                                                              \
         * Skip the instruction if no repetitions are required, but     \
         * zero extend involved registers first when using 32-bit       \
         * addressing in 64-bit mode.                                   \
         */                                                             \
        if ( mode_64bit() && ad_bytes == 4 )                            \
        {                                                               \
            _regs.r(cx) = 0;                                            \
            if ( using_si ) _regs.r(si) = _regs.esi;                    \
            if ( using_di ) _regs.r(di) = _regs.edi;                    \
        }                                                               \
        goto complete_insn;                                             \
    }                                                                   \
    if ( max_reps > 1 && (_regs.eflags & X86_EFLAGS_TF) &&              \
         !is_branch_step(ctxt, ops) )                                   \
        max_reps = 1;                                                   \
    max_reps;                                                           \
})

static void __put_rep_prefix(
    struct cpu_user_regs *int_regs,
    struct cpu_user_regs *ext_regs,
    int ad_bytes,
    unsigned long reps_completed)
{
    unsigned long ecx = get_loop_count(int_regs, ad_bytes);

    /* Reduce counter appropriately, and repeat instruction if non-zero. */
    ecx -= reps_completed;
    if ( ecx != 0 )
        int_regs->r(ip) = ext_regs->r(ip);

    put_loop_count(int_regs, ad_bytes, ecx);
}

#define put_rep_prefix(reps_completed) ({                               \
    if ( rep_prefix() )                                                 \
    {                                                                   \
        __put_rep_prefix(&_regs, ctxt->regs, ad_bytes, reps_completed); \
        if ( unlikely(rc == X86EMUL_EXCEPTION) )                        \
            goto complete_insn;                                         \
    }                                                                   \
})

/* Clip maximum repetitions so that the index register at most just wraps. */
#define truncate_ea_and_reps(ea, reps, bytes_per_rep) ({                  \
    unsigned long todo__, ea__ = truncate_ea(ea);                         \
    if ( !(_regs.eflags & X86_EFLAGS_DF) )                                \
        todo__ = truncate_ea(-ea__) / (bytes_per_rep);                    \
    else if ( truncate_ea(ea__ + (bytes_per_rep) - 1) < ea__ )            \
        todo__ = 1;                                                       \
    else                                                                  \
        todo__ = ea__ / (bytes_per_rep) + 1;                              \
    if ( !todo__ )                                                        \
        (reps) = 1;                                                       \
    else if ( todo__ < (reps) )                                           \
        (reps) = todo__;                                                  \
    ea__;                                                                 \
})

/* Compatibility function: read guest memory, zero-extend result to a ulong. */
static int read_ulong(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt,
        const struct x86_emulate_ops *ops)
{
    *val = 0;
    return ops->read(seg, offset, val, bytes, ctxt);
}

/*
 * Unsigned multiplication with double-word result.
 * IN:  Multiplicand=m[0], Multiplier=m[1]
 * OUT: Return CF/OF (overflow status); Result=m[1]:m[0]
 */
static bool mul_dbl(unsigned long m[2])
{
    bool rc;

    asm ( "mul %1" ASM_FLAG_OUT(, "; seto %2")
          : "+a" (m[0]), "+d" (m[1]), ASM_FLAG_OUT("=@cco", "=qm") (rc) );

    return rc;
}

/*
 * Signed multiplication with double-word result.
 * IN:  Multiplicand=m[0], Multiplier=m[1]
 * OUT: Return CF/OF (overflow status); Result=m[1]:m[0]
 */
static bool imul_dbl(unsigned long m[2])
{
    bool rc;

    asm ( "imul %1" ASM_FLAG_OUT(, "; seto %2")
          : "+a" (m[0]), "+d" (m[1]), ASM_FLAG_OUT("=@cco", "=qm") (rc) );

    return rc;
}

/*
 * Unsigned division of double-word dividend.
 * IN:  Dividend=u[1]:u[0], Divisor=v
 * OUT: Return 1: #DE
 *      Return 0: Quotient=u[0], Remainder=u[1]
 */
static bool div_dbl(unsigned long u[2], unsigned long v)
{
    if ( (v == 0) || (u[1] >= v) )
        return 1;
    asm ( "div"__OS" %2" : "+a" (u[0]), "+d" (u[1]) : "rm" (v) );
    return 0;
}

/*
 * Signed division of double-word dividend.
 * IN:  Dividend=u[1]:u[0], Divisor=v
 * OUT: Return 1: #DE
 *      Return 0: Quotient=u[0], Remainder=u[1]
 * NB. We don't use idiv directly as it's moderately hard to work out
 *     ahead of time whether it will #DE, which we cannot allow to happen.
 */
static bool idiv_dbl(unsigned long u[2], long v)
{
    bool negu = (long)u[1] < 0, negv = v < 0;

    /* u = abs(u) */
    if ( negu )
    {
        u[1] = ~u[1];
        if ( (u[0] = -u[0]) == 0 )
            u[1]++;
    }

    /* abs(u) / abs(v) */
    if ( div_dbl(u, negv ? -v : v) )
        return 1;

    /* Remainder has same sign as dividend. It cannot overflow. */
    if ( negu )
        u[1] = -u[1];

    /* Quotient is overflowed if sign bit is set. */
    if ( negu ^ negv )
    {
        if ( (long)u[0] >= 0 )
            u[0] = -u[0];
        else if ( (u[0] << 1) != 0 ) /* == 0x80...0 is okay */
            return 1;
    }
    else if ( (long)u[0] < 0 )
        return 1;

    return 0;
}

static bool
test_cc(
    unsigned int condition, unsigned int flags)
{
    int rc = 0;

    switch ( (condition & 15) >> 1 )
    {
    case 0: /* o */
        rc |= (flags & X86_EFLAGS_OF);
        break;
    case 1: /* b/c/nae */
        rc |= (flags & X86_EFLAGS_CF);
        break;
    case 2: /* z/e */
        rc |= (flags & X86_EFLAGS_ZF);
        break;
    case 3: /* be/na */
        rc |= (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF));
        break;
    case 4: /* s */
        rc |= (flags & X86_EFLAGS_SF);
        break;
    case 5: /* p/pe */
        rc |= (flags & X86_EFLAGS_PF);
        break;
    case 7: /* le/ng */
        rc |= (flags & X86_EFLAGS_ZF);
        /* fall through */
    case 6: /* l/nge */
        rc |= (!(flags & X86_EFLAGS_SF) != !(flags & X86_EFLAGS_OF));
        break;
    }

    /* Odd condition identifiers (lsb == 1) have inverted sense. */
    return (!!rc ^ (condition & 1));
}

static int
get_cpl(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    struct segment_register reg;

    if ( ctxt->regs->eflags & X86_EFLAGS_VM )
        return 3;

    if ( (ops->read_segment == NULL) ||
         ops->read_segment(x86_seg_ss, &reg, ctxt) )
        return -1;

    return reg.dpl;
}

static int
_mode_iopl(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    int cpl = get_cpl(ctxt, ops);
    if ( cpl == -1 )
        return -1;
    return cpl <= MASK_EXTR(ctxt->regs->eflags, X86_EFLAGS_IOPL);
}

#define mode_ring0() ({                         \
    int _cpl = get_cpl(ctxt, ops);              \
    fail_if(_cpl < 0);                          \
    (_cpl == 0);                                \
})
#define mode_iopl() ({                          \
    int _iopl = _mode_iopl(ctxt, ops);          \
    fail_if(_iopl < 0);                         \
    _iopl;                                      \
})
#define mode_vif() ({                                        \
    cr4 = 0;                                                 \
    if ( ops->read_cr && get_cpl(ctxt, ops) == 3 )           \
    {                                                        \
        rc = ops->read_cr(4, &cr4, ctxt);                    \
        if ( rc != X86EMUL_OKAY ) goto done;                 \
    }                                                        \
    !!(cr4 & (_regs.eflags & X86_EFLAGS_VM ? X86_CR4_VME : X86_CR4_PVI)); \
})

static int ioport_access_check(
    unsigned int first_port,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned long iobmp;
    struct segment_register tr;
    int rc = X86EMUL_OKAY;

    if ( !(ctxt->regs->eflags & X86_EFLAGS_VM) && mode_iopl() )
        return X86EMUL_OKAY;

    fail_if(ops->read_segment == NULL);
    /*
     * X86EMUL_DONE coming back here may be used to defer the port
     * permission check to the respective ioport hook.
     */
    if ( (rc = ops->read_segment(x86_seg_tr, &tr, ctxt)) != 0 )
        return rc == X86EMUL_DONE ? X86EMUL_OKAY : rc;

    /* Ensure the TSS has an io-bitmap-offset field. */
    generate_exception_if(tr.type != 0xb, EXC_GP, 0);

    switch ( rc = read_ulong(x86_seg_tr, 0x66, &iobmp, 2, ctxt, ops) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        generate_exception_if(!ctxt->event_pending, EXC_GP, 0);
        /* fallthrough */

    default:
        return rc;
    }

    /* Read two bytes including byte containing first port. */
    switch ( rc = read_ulong(x86_seg_tr, iobmp + first_port / 8,
                             &iobmp, 2, ctxt, ops) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        generate_exception_if(!ctxt->event_pending, EXC_GP, 0);
        /* fallthrough */

    default:
        return rc;
    }

    generate_exception_if(iobmp & (((1 << bytes) - 1) << (first_port & 7)),
                          EXC_GP, 0);

 done:
    return rc;
}

static bool
in_realmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    unsigned long cr0;
    int rc;

    if ( ops->read_cr == NULL )
        return 0;

    rc = ops->read_cr(0, &cr0, ctxt);
    return (!rc && !(cr0 & X86_CR0_PE));
}

static bool
in_protmode(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    return !(in_realmode(ctxt, ops) || (ctxt->regs->eflags & X86_EFLAGS_VM));
}

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3

static bool vcpu_has(
    unsigned int eax,
    unsigned int reg,
    unsigned int bit,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    struct cpuid_leaf res;
    int rc = X86EMUL_OKAY;

    fail_if(!ops->cpuid);
    rc = ops->cpuid(eax, 0, &res, ctxt);
    if ( rc == X86EMUL_OKAY )
    {
        switch ( reg )
        {
        case EAX: reg = res.a; break;
        case EBX: reg = res.b; break;
        case ECX: reg = res.c; break;
        case EDX: reg = res.d; break;
        default: BUG();
        }
        if ( !(reg & (1U << bit)) )
            rc = ~X86EMUL_OKAY;
    }

 done:
    return rc == X86EMUL_OKAY;
}

#define vcpu_has_fpu()         vcpu_has(         1, EDX,  0, ctxt, ops)
#define vcpu_has_sep()         vcpu_has(         1, EDX, 11, ctxt, ops)
#define vcpu_has_cx8()         vcpu_has(         1, EDX,  8, ctxt, ops)
#define vcpu_has_cmov()        vcpu_has(         1, EDX, 15, ctxt, ops)
#define vcpu_has_clflush()     vcpu_has(         1, EDX, 19, ctxt, ops)
#define vcpu_has_mmx()         vcpu_has(         1, EDX, 23, ctxt, ops)
#define vcpu_has_sse()         vcpu_has(         1, EDX, 25, ctxt, ops)
#define vcpu_has_sse2()        vcpu_has(         1, EDX, 26, ctxt, ops)
#define vcpu_has_sse3()        vcpu_has(         1, ECX,  0, ctxt, ops)
#define vcpu_has_pclmulqdq()   vcpu_has(         1, ECX,  1, ctxt, ops)
#define vcpu_has_ssse3()       vcpu_has(         1, ECX,  9, ctxt, ops)
#define vcpu_has_fma()         vcpu_has(         1, ECX, 12, ctxt, ops)
#define vcpu_has_cx16()        vcpu_has(         1, ECX, 13, ctxt, ops)
#define vcpu_has_sse4_1()      vcpu_has(         1, ECX, 19, ctxt, ops)
#define vcpu_has_sse4_2()      vcpu_has(         1, ECX, 20, ctxt, ops)
#define vcpu_has_movbe()       vcpu_has(         1, ECX, 22, ctxt, ops)
#define vcpu_has_popcnt()      vcpu_has(         1, ECX, 23, ctxt, ops)
#define vcpu_has_aesni()       vcpu_has(         1, ECX, 25, ctxt, ops)
#define vcpu_has_avx()         vcpu_has(         1, ECX, 28, ctxt, ops)
#define vcpu_has_f16c()        vcpu_has(         1, ECX, 29, ctxt, ops)
#define vcpu_has_rdrand()      vcpu_has(         1, ECX, 30, ctxt, ops)
#define vcpu_has_mmxext()     (vcpu_has(0x80000001, EDX, 22, ctxt, ops) || \
                               vcpu_has_sse())
#define vcpu_has_3dnow_ext()   vcpu_has(0x80000001, EDX, 30, ctxt, ops)
#define vcpu_has_3dnow()       vcpu_has(0x80000001, EDX, 31, ctxt, ops)
#define vcpu_has_lahf_lm()     vcpu_has(0x80000001, ECX,  0, ctxt, ops)
#define vcpu_has_cr8_legacy()  vcpu_has(0x80000001, ECX,  4, ctxt, ops)
#define vcpu_has_lzcnt()       vcpu_has(0x80000001, ECX,  5, ctxt, ops)
#define vcpu_has_sse4a()       vcpu_has(0x80000001, ECX,  6, ctxt, ops)
#define vcpu_has_misalignsse() vcpu_has(0x80000001, ECX,  7, ctxt, ops)
#define vcpu_has_xop()         vcpu_has(0x80000001, ECX, 12, ctxt, ops)
#define vcpu_has_fma4()        vcpu_has(0x80000001, ECX, 16, ctxt, ops)
#define vcpu_has_tbm()         vcpu_has(0x80000001, ECX, 21, ctxt, ops)
#define vcpu_has_bmi1()        vcpu_has(         7, EBX,  3, ctxt, ops)
#define vcpu_has_hle()         vcpu_has(         7, EBX,  4, ctxt, ops)
#define vcpu_has_avx2()        vcpu_has(         7, EBX,  5, ctxt, ops)
#define vcpu_has_bmi2()        vcpu_has(         7, EBX,  8, ctxt, ops)
#define vcpu_has_rtm()         vcpu_has(         7, EBX, 11, ctxt, ops)
#define vcpu_has_mpx()         vcpu_has(         7, EBX, 14, ctxt, ops)
#define vcpu_has_rdseed()      vcpu_has(         7, EBX, 18, ctxt, ops)
#define vcpu_has_adx()         vcpu_has(         7, EBX, 19, ctxt, ops)
#define vcpu_has_smap()        vcpu_has(         7, EBX, 20, ctxt, ops)
#define vcpu_has_clflushopt()  vcpu_has(         7, EBX, 23, ctxt, ops)
#define vcpu_has_clwb()        vcpu_has(         7, EBX, 24, ctxt, ops)
#define vcpu_has_sha()         vcpu_has(         7, EBX, 29, ctxt, ops)
#define vcpu_has_rdpid()       vcpu_has(         7, ECX, 22, ctxt, ops)
#define vcpu_has_clzero()      vcpu_has(0x80000008, EBX,  0, ctxt, ops)

#define vcpu_must_have(feat) \
    generate_exception_if(!vcpu_has_##feat(), EXC_UD)

#ifdef __XEN__
/*
 * Note the difference between vcpu_must_have(<feature>) and
 * host_and_vcpu_must_have(<feature>): The latter needs to be used when
 * emulation code is using the same instruction class for carrying out
 * the actual operation.
 */
#define host_and_vcpu_must_have(feat) ({ \
    generate_exception_if(!cpu_has_##feat, EXC_UD); \
    vcpu_must_have(feat); \
})
#else
/*
 * For the test harness both are fine to be used interchangeably, i.e.
 * features known to always be available (e.g. SSE/SSE2) to (64-bit) Xen
 * may be checked for by just vcpu_must_have().
 */
#define host_and_vcpu_must_have(feat) vcpu_must_have(feat)
#endif

static int
realmode_load_seg(
    enum x86_segment seg,
    uint16_t sel,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc;

    if ( !ops->read_segment )
        return X86EMUL_UNHANDLEABLE;

    if ( (rc = ops->read_segment(seg, sreg, ctxt)) == X86EMUL_OKAY )
    {
        sreg->sel  = sel;
        sreg->base = (uint32_t)sel << 4;
    }

    return rc;
}

/*
 * Passing in x86_seg_none means
 * - suppress any exceptions other than #PF,
 * - don't commit any state.
 */
static int
protmode_load_seg(
    enum x86_segment seg,
    uint16_t sel, bool is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    enum x86_segment sel_seg = (sel & 4) ? x86_seg_ldtr : x86_seg_gdtr;
    struct { uint32_t a, b; } desc, desc_hi = {};
    uint8_t dpl, rpl;
    int cpl = get_cpl(ctxt, ops);
    uint32_t a_flag = 0x100;
    int rc, fault_type = EXC_GP;

    if ( cpl < 0 )
        return X86EMUL_UNHANDLEABLE;

    /* NULL selector? */
    if ( (sel & 0xfffc) == 0 )
    {
        switch ( seg )
        {
        case x86_seg_ss:
            if ( mode_64bit() && (cpl != 3) && (cpl == sel) )
        default:
                break;
            /* fall through */
        case x86_seg_cs:
        case x86_seg_tr:
            goto raise_exn;
        }
        if ( ctxt->vendor != X86_VENDOR_AMD || !ops->read_segment ||
             ops->read_segment(seg, sreg, ctxt) != X86EMUL_OKAY )
            memset(sreg, 0, sizeof(*sreg));
        else
            sreg->attr = 0;
        sreg->sel = sel;

        /* Since CPL == SS.DPL, we need to put back DPL. */
        if ( seg == x86_seg_ss )
            sreg->dpl = sel;

        return X86EMUL_OKAY;
    }

    /* System segment descriptors must reside in the GDT. */
    if ( is_x86_system_segment(seg) && (sel & 4) )
        goto raise_exn;

    switch ( rc = ops->read(sel_seg, sel & 0xfff8, &desc, sizeof(desc), ctxt) )
    {
    case X86EMUL_OKAY:
        break;

    case X86EMUL_EXCEPTION:
        if ( !ctxt->event_pending )
            goto raise_exn;
        /* fallthrough */

    default:
        return rc;
    }

    /* System segments must have S flag == 0. */
    if ( is_x86_system_segment(seg) && (desc.b & (1u << 12)) )
        goto raise_exn;
    /* User segments must have S flag == 1. */
    if ( is_x86_user_segment(seg) && !(desc.b & (1u << 12)) )
        goto raise_exn;

    dpl = (desc.b >> 13) & 3;
    rpl = sel & 3;

    switch ( seg )
    {
    case x86_seg_cs:
        /* Code segment? */
        if ( !(desc.b & (1u<<11)) )
            goto raise_exn;
        if ( is_ret
             ? /*
                * Really rpl < cpl, but our sole caller doesn't handle
                * privilege level changes.
                */
               rpl != cpl || (desc.b & (1 << 10) ? dpl > rpl : dpl != rpl)
             : desc.b & (1 << 10)
               /* Conforming segment: check DPL against CPL. */
               ? dpl > cpl
               /* Non-conforming segment: check RPL and DPL against CPL. */
               : rpl > cpl || dpl != cpl )
            goto raise_exn;
        /*
         * 64-bit code segments (L bit set) must have D bit clear.
         * Experimentally in long mode, the L and D bits are checked before
         * the Present bit.
         */
        if ( ctxt->lma && (desc.b & (1 << 21)) && (desc.b & (1 << 22)) )
            goto raise_exn;
        sel = (sel ^ rpl) | cpl;
        break;
    case x86_seg_ss:
        /* Writable data segment? */
        if ( (desc.b & (5u<<9)) != (1u<<9) )
            goto raise_exn;
        if ( (dpl != cpl) || (dpl != rpl) )
            goto raise_exn;
        break;
    case x86_seg_ldtr:
        /* LDT system segment? */
        if ( (desc.b & (15u<<8)) != (2u<<8) )
            goto raise_exn;
        a_flag = 0;
        break;
    case x86_seg_tr:
        /* Available TSS system segment? */
        if ( (desc.b & (15u<<8)) != (9u<<8) )
            goto raise_exn;
        a_flag = 0x200; /* busy flag */
        break;
    default:
        /* Readable code or data segment? */
        if ( (desc.b & (5u<<9)) == (4u<<9) )
            goto raise_exn;
        /* Non-conforming segment: check DPL against RPL and CPL. */
        if ( ((desc.b & (6u<<9)) != (6u<<9)) &&
             ((dpl < cpl) || (dpl < rpl)) )
            goto raise_exn;
        break;
    case x86_seg_none:
        /* Non-conforming segment: check DPL against RPL and CPL. */
        if ( ((desc.b & (0x1c << 8)) != (0x1c << 8)) &&
             ((dpl < cpl) || (dpl < rpl)) )
            return X86EMUL_EXCEPTION;
        a_flag = 0;
        break;
    }

    /* Segment present in memory? */
    if ( !(desc.b & (1 << 15)) && seg != x86_seg_none )
    {
        fault_type = seg != x86_seg_ss ? EXC_NP : EXC_SS;
        goto raise_exn;
    }

    if ( !is_x86_user_segment(seg) )
    {
        /*
         * Whether to use an 8- or 16-byte descriptor in long mode depends
         * on sub-mode, descriptor type, and vendor:
         * - non-system descriptors are always 8-byte ones,
         * - system descriptors are always 16-byte ones in 64-bit mode,
         * - (call) gates are always 16-byte ones,
         * - other system descriptors in compatibility mode have
         *   - only their low 8-byte bytes read on Intel,
         *   - all 16 bytes read with the high 8 bytes ignored on AMD.
         */
        bool wide = desc.b & 0x1000
                    ? false : (desc.b & 0xf00) != 0xc00 &&
                               ctxt->vendor != X86_VENDOR_AMD
                               ? mode_64bit() : ctxt->lma;

        if ( wide )
        {
            switch ( rc = ops->read(sel_seg, (sel & 0xfff8) + 8,
                                    &desc_hi, sizeof(desc_hi), ctxt) )
            {
            case X86EMUL_OKAY:
                break;

            case X86EMUL_EXCEPTION:
                if ( !ctxt->event_pending )
                    goto raise_exn;
                /* fall through */
            default:
                return rc;
            }
            if ( !mode_64bit() && ctxt->vendor == X86_VENDOR_AMD &&
                 (desc.b & 0xf00) != 0xc00 )
                desc_hi.b = desc_hi.a = 0;
            if ( (desc_hi.b & 0x00001f00) ||
                 (seg != x86_seg_none &&
                  !is_canonical_address((uint64_t)desc_hi.a << 32)) )
                goto raise_exn;
        }
    }

    /* Ensure Accessed flag is set. */
    if ( a_flag && !(desc.b & a_flag) )
    {
        uint32_t new_desc_b = desc.b | a_flag;

        fail_if(!ops->cmpxchg);
        switch ( (rc = ops->cmpxchg(sel_seg, (sel & 0xfff8) + 4, &desc.b,
                                    &new_desc_b, sizeof(desc.b), true, ctxt)) )
        {
        case X86EMUL_OKAY:
            break;

        case X86EMUL_EXCEPTION:
            if ( !ctxt->event_pending )
                goto raise_exn;
            /* fallthrough */

        default:
            return rc;

        case X86EMUL_CMPXCHG_FAILED:
            return X86EMUL_RETRY;
        }

        /* Force the Accessed flag in our local copy. */
        desc.b = new_desc_b;
    }

    sreg->base = (((uint64_t)desc_hi.a << 32) |
                  ((desc.b <<  0) & 0xff000000u) |
                  ((desc.b << 16) & 0x00ff0000u) |
                  ((desc.a >> 16) & 0x0000ffffu));
    sreg->attr = (((desc.b >>  8) & 0x00ffu) |
                  ((desc.b >> 12) & 0x0f00u));
    sreg->limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( sreg->g )
        sreg->limit = (sreg->limit << 12) | 0xfffu;
    sreg->sel = sel;
    return X86EMUL_OKAY;

 raise_exn:
    generate_exception_if(seg != x86_seg_none, fault_type, sel & 0xfffc);
    rc = X86EMUL_EXCEPTION;
 done:
    return rc;
}

static int
load_seg(
    enum x86_segment seg,
    uint16_t sel, bool is_ret,
    struct segment_register *sreg,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    struct segment_register reg;
    int rc;

    if ( !ops->write_segment )
        return X86EMUL_UNHANDLEABLE;

    if ( !sreg )
        sreg = &reg;

    if ( in_protmode(ctxt, ops) )
        rc = protmode_load_seg(seg, sel, is_ret, sreg, ctxt, ops);
    else
        rc = realmode_load_seg(seg, sel, sreg, ctxt, ops);

    if ( !rc && sreg == &reg )
        rc = ops->write_segment(seg, sreg, ctxt);

    return rc;
}

/* Map GPRs by ModRM encoding to their offset within struct cpu_user_regs. */
const uint8_t cpu_user_regs_gpr_offsets[] = {
    offsetof(struct cpu_user_regs, r(ax)),
    offsetof(struct cpu_user_regs, r(cx)),
    offsetof(struct cpu_user_regs, r(dx)),
    offsetof(struct cpu_user_regs, r(bx)),
    offsetof(struct cpu_user_regs, r(sp)),
    offsetof(struct cpu_user_regs, r(bp)),
    offsetof(struct cpu_user_regs, r(si)),
    offsetof(struct cpu_user_regs, r(di)),
#ifdef __x86_64__
    offsetof(struct cpu_user_regs, r8),
    offsetof(struct cpu_user_regs, r9),
    offsetof(struct cpu_user_regs, r10),
    offsetof(struct cpu_user_regs, r11),
    offsetof(struct cpu_user_regs, r12),
    offsetof(struct cpu_user_regs, r13),
    offsetof(struct cpu_user_regs, r14),
    offsetof(struct cpu_user_regs, r15),
#endif
};

static void *_decode_gpr(
    struct cpu_user_regs *regs, unsigned int modrm_reg, bool legacy)
{
    static const uint8_t byte_reg_offsets[] = {
        offsetof(struct cpu_user_regs, al),
        offsetof(struct cpu_user_regs, cl),
        offsetof(struct cpu_user_regs, dl),
        offsetof(struct cpu_user_regs, bl),
        offsetof(struct cpu_user_regs, ah),
        offsetof(struct cpu_user_regs, ch),
        offsetof(struct cpu_user_regs, dh),
        offsetof(struct cpu_user_regs, bh),
    };

    if ( !legacy )
        return decode_gpr(regs, modrm_reg);

    /* Check that the array is a power of two. */
    BUILD_BUG_ON(ARRAY_SIZE(byte_reg_offsets) &
                 (ARRAY_SIZE(byte_reg_offsets) - 1));

    ASSERT(modrm_reg < ARRAY_SIZE(byte_reg_offsets));

    /* For safety in release builds.  Debug builds will hit the ASSERT() */
    modrm_reg &= ARRAY_SIZE(byte_reg_offsets) - 1;

    return (void *)regs + byte_reg_offsets[modrm_reg];
}

static unsigned long *decode_vex_gpr(
    unsigned int vex_reg, struct cpu_user_regs *regs,
    const struct x86_emulate_ctxt *ctxt)
{
    return decode_gpr(regs, ~vex_reg & (mode_64bit() ? 0xf : 7));
}

static bool is_aligned(enum x86_segment seg, unsigned long offs,
                       unsigned int size, struct x86_emulate_ctxt *ctxt,
                       const struct x86_emulate_ops *ops)
{
    struct segment_register reg;

    /* Expecting powers of two only. */
    ASSERT(!(size & (size - 1)));

    if ( mode_64bit() && seg < x86_seg_fs )
        memset(&reg, 0, sizeof(reg));
    else
    {
        /* No alignment checking when we have no way to read segment data. */
        if ( !ops->read_segment )
            return true;

        if ( ops->read_segment(seg, &reg, ctxt) != X86EMUL_OKAY )
            return false;
    }

    return !((reg.base + offs) & (size - 1));
}

static bool is_branch_step(struct x86_emulate_ctxt *ctxt,
                           const struct x86_emulate_ops *ops)
{
    uint64_t debugctl;

    return ops->read_msr &&
           ops->read_msr(MSR_IA32_DEBUGCTLMSR, &debugctl, ctxt) == X86EMUL_OKAY &&
           (debugctl & IA32_DEBUGCTLMSR_BTF);
}

static bool umip_active(struct x86_emulate_ctxt *ctxt,
                        const struct x86_emulate_ops *ops)
{
    unsigned long cr4;

    /* Intentionally not using mode_ring0() here to avoid its fail_if(). */
    return get_cpl(ctxt, ops) > 0 &&
           ops->read_cr && ops->read_cr(4, &cr4, ctxt) == X86EMUL_OKAY &&
           (cr4 & X86_CR4_UMIP);
}

static void adjust_bnd(struct x86_emulate_ctxt *ctxt,
                       const struct x86_emulate_ops *ops, enum vex_pfx pfx)
{
    uint64_t xcr0, bndcfg;
    int rc;

    if ( pfx == vex_f2 || !cpu_has_mpx || !vcpu_has_mpx() )
        return;

    if ( !ops->read_xcr || ops->read_xcr(0, &xcr0, ctxt) != X86EMUL_OKAY ||
         !(xcr0 & X86_XCR0_BNDREGS) || !(xcr0 & X86_XCR0_BNDCSR) )
        return;

    if ( !mode_ring0() )
        bndcfg = read_bndcfgu();
    else if ( !ops->read_msr ||
              ops->read_msr(MSR_IA32_BNDCFGS, &bndcfg, ctxt) != X86EMUL_OKAY )
        return;
    if ( (bndcfg & IA32_BNDCFGS_ENABLE) && !(bndcfg & IA32_BNDCFGS_PRESERVE) )
    {
        /*
         * Using BNDMK or any other MPX instruction here is pointless, as
         * we run with MPX disabled ourselves, and hence they're all no-ops.
         * Therefore we have two ways to clear BNDn: Enable MPX temporarily
         * (in which case executing any suitable non-prefixed branch
         * instruction would do), or use XRSTOR.
         */
        xstate_set_init(X86_XCR0_BNDREGS);
    }
 done:;
}

int x86emul_unhandleable_rw(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_UNHANDLEABLE;
}

/* Helper definitions. */
#define op_bytes (state->op_bytes)
#define ad_bytes (state->ad_bytes)
#define ext (state->ext)
#define modrm (state->modrm)
#define modrm_mod (state->modrm_mod)
#define modrm_reg (state->modrm_reg)
#define modrm_rm (state->modrm_rm)
#define rex_prefix (state->rex_prefix)
#define lock_prefix (state->lock_prefix)
#define vex (state->vex)
#define evex (state->evex)
#define ea (state->ea)

static int
x86_decode_onebyte(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc = X86EMUL_OKAY;

    switch ( ctxt->opcode )
    {
    case 0x06: /* push %%es */
    case 0x07: /* pop %%es */
    case 0x0e: /* push %%cs */
    case 0x16: /* push %%ss */
    case 0x17: /* pop %%ss */
    case 0x1e: /* push %%ds */
    case 0x1f: /* pop %%ds */
    case 0x27: /* daa */
    case 0x2f: /* das */
    case 0x37: /* aaa */
    case 0x3f: /* aas */
    case 0x60: /* pusha */
    case 0x61: /* popa */
    case 0x62: /* bound */
    case 0x82: /* Grp1 (x86/32 only) */
    case 0xc4: /* les */
    case 0xc5: /* lds */
    case 0xce: /* into */
    case 0xd4: /* aam */
    case 0xd5: /* aad */
    case 0xd6: /* salc */
        state->not_64bit = true;
        break;

    case 0x90: /* nop / pause */
        if ( repe_prefix() )
            ctxt->opcode |= X86EMUL_OPC_F3(0, 0);
        break;

    case 0x9a: /* call (far, absolute) */
    case 0xea: /* jmp (far, absolute) */
        generate_exception_if(mode_64bit(), EXC_UD);

        imm1 = insn_fetch_bytes(op_bytes);
        imm2 = insn_fetch_type(uint16_t);
        break;

    case 0xa0: case 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2: case 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Source EA is not encoded via ModRM. */
        ea.type = OP_MEM;
        ea.mem.off = insn_fetch_bytes(ad_bytes);
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        if ( op_bytes == 8 ) /* Fetch more bytes to obtain imm64. */
            imm1 = ((uint32_t)imm1 |
                    ((uint64_t)insn_fetch_type(uint32_t) << 32));
        break;

    case 0xc8: /* enter imm16,imm8 */
        imm2 = insn_fetch_type(uint8_t);
        break;

    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* call (near) */
        case 4: /* jmp (near) */
        case 6: /* push */
            if ( mode_64bit() && op_bytes == 4 )
                op_bytes = 8;
            /* fall through */
        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            state->desc = DstNone | SrcMem | Mov;
            break;
        }
        break;
    }

 done:
    return rc;
}

static int
x86_decode_twobyte(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    int rc = X86EMUL_OKAY;

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x00: /* Grp6 */
        switch ( modrm_reg & 6 )
        {
        case 0:
            state->desc |= DstMem | SrcImplicit | Mov;
            break;
        case 2: case 4:
            state->desc |= SrcMem16;
            break;
        }
        break;

    case 0x78:
        switch ( vex.pfx )
        {
        case vex_66: /* extrq $imm8, $imm8, xmm */
        case vex_f2: /* insertq $imm8, $imm8, xmm, xmm */
            imm1 = insn_fetch_type(uint8_t);
            imm2 = insn_fetch_type(uint8_t);
            break;
        }
        /* fall through */
    case 0x10 ... 0x18:
    case 0x28 ... 0x2f:
    case 0x50 ... 0x77:
    case 0x79 ... 0x7d:
    case 0x7f:
    case 0xc2 ... 0xc3:
    case 0xc5 ... 0xc6:
    case 0xd0 ... 0xef:
    case 0xf1 ... 0xfe:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0x20: case 0x22: /* mov to/from cr */
        if ( lock_prefix && vcpu_has_cr8_legacy() )
        {
            modrm_reg += 8;
            lock_prefix = false;
        }
        /* fall through */
    case 0x21: case 0x23: /* mov to/from dr */
        ASSERT(ea.type == OP_REG); /* Early operand adjustment ensures this. */
        generate_exception_if(lock_prefix, EXC_UD);
        op_bytes = mode_64bit() ? 8 : 4;
        break;

    case 0x7e:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( vex.pfx == vex_f3 ) /* movq xmm/m64,xmm */
        {
    case X86EMUL_OPC_VEX_F3(0, 0x7e): /* vmovq xmm/m64,xmm */
            state->desc = DstImplicit | SrcMem | TwoOp;
            state->simd_size = simd_other;
            /* Avoid the state->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;

    case 0xae:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX(0, 0xae):
        switch ( modrm_reg & 7 )
        {
        case 2: /* {,v}ldmxcsr */
            state->desc = DstImplicit | SrcMem | Mov;
            op_bytes = 4;
            break;

        case 3: /* {,v}stmxcsr */
            state->desc = DstMem | SrcImplicit | Mov;
            op_bytes = 4;
            break;
        }
        break;

    case 0xb8: /* jmpe / popcnt */
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

        /* Intentionally not handling here despite being modified by F3:
    case 0xbc: bsf / tzcnt
    case 0xbd: bsr / lzcnt
         * They're being dealt with in the execution phase (if at all).
         */

    case 0xc4: /* pinsrw */
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0, 0xc4): /* vpinsrw */
        state->desc = DstReg | SrcMem16;
        break;

    case 0xf0:
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( vex.pfx == vex_f2 ) /* lddqu mem,xmm */
        {
        /* fall through */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* vlddqu mem,{x,y}mm */
            state->desc = DstImplicit | SrcMem | TwoOp;
            state->simd_size = simd_other;
            /* Avoid the state->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;
    }

    /*
     * Scalar forms of most VEX-encoded TwoOp instructions have
     * three operands.  Those which do really have two operands
     * should have exited earlier.
     */
    if ( state->simd_size && vex.opcx &&
         (vex.pfx & VEX_PREFIX_SCALAR_MASK) )
        state->desc &= ~TwoOp;

 done:
    return rc;
}

static int
x86_decode_0f38(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x00 ... 0xef:
    case 0xf2 ... 0xf5:
    case 0xf7 ... 0xff:
        op_bytes = 0;
        /* fall through */
    case 0xf6: /* adcx / adox */
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0xf0: /* movbe / crc32 */
        state->desc |= repne_prefix() ? ByteOp : Mov;
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0xf1: /* movbe / crc32 */
        if ( repne_prefix() )
            state->desc = DstReg | SrcMem;
        if ( rep_prefix() )
            ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case X86EMUL_OPC_VEX(0, 0xf2):    /* andn */
    case X86EMUL_OPC_VEX(0, 0xf3):    /* Grp 17 */
    case X86EMUL_OPC_VEX(0, 0xf5):    /* bzhi */
    case X86EMUL_OPC_VEX_F3(0, 0xf5): /* pext */
    case X86EMUL_OPC_VEX_F2(0, 0xf5): /* pdep */
    case X86EMUL_OPC_VEX_F2(0, 0xf6): /* mulx */
    case X86EMUL_OPC_VEX(0, 0xf7):    /* bextr */
    case X86EMUL_OPC_VEX_66(0, 0xf7): /* shlx */
    case X86EMUL_OPC_VEX_F3(0, 0xf7): /* sarx */
    case X86EMUL_OPC_VEX_F2(0, 0xf7): /* shrx */
        break;

    default:
        op_bytes = 0;
        break;
    }

    return X86EMUL_OKAY;
}

static int
x86_decode_0f3a(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    if ( !vex.opcx )
        ctxt->opcode |= MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case X86EMUL_OPC_66(0, 0x14)
     ... X86EMUL_OPC_66(0, 0x17):     /* pextr*, extractps */
    case X86EMUL_OPC_VEX_66(0, 0x14)
     ... X86EMUL_OPC_VEX_66(0, 0x17): /* vpextr*, vextractps */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* rorx */
        break;

    case X86EMUL_OPC_66(0, 0x20):     /* pinsrb */
    case X86EMUL_OPC_VEX_66(0, 0x20): /* vpinsrb */
        state->desc = DstImplicit | SrcMem;
        if ( modrm_mod != 3 )
            state->desc |= ByteOp;
        break;

    case X86EMUL_OPC_66(0, 0x22):     /* pinsr{d,q} */
    case X86EMUL_OPC_VEX_66(0, 0x22): /* vpinsr{d,q} */
        state->desc = DstImplicit | SrcMem;
        break;

    default:
        op_bytes = 0;
        break;
    }

    return X86EMUL_OKAY;
}

static int
x86_decode(
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops  *ops)
{
    uint8_t b, d;
    unsigned int def_op_bytes, def_ad_bytes, opcode;
    enum x86_segment override_seg = x86_seg_none;
    bool pc_rel = false;
    int rc = X86EMUL_OKAY;

    ASSERT(ops->insn_fetch);

    memset(state, 0, sizeof(*state));
    ea.type = OP_NONE;
    ea.mem.seg = x86_seg_ds;
    ea.reg = PTR_POISON;
    state->regs = ctxt->regs;
    state->ip = ctxt->regs->r(ip);

    /* Initialise output state in x86_emulate_ctxt */
    ctxt->retire.raw = 0;
    x86_emul_reset_event(ctxt);

    op_bytes = def_op_bytes = ad_bytes = def_ad_bytes = ctxt->addr_size/8;
    if ( op_bytes == 8 )
    {
        op_bytes = def_op_bytes = 4;
#ifndef __x86_64__
        return X86EMUL_UNHANDLEABLE;
#endif
    }

    /* Prefix bytes. */
    for ( ; ; )
    {
        switch ( b = insn_fetch_type(uint8_t) )
        {
        case 0x66: /* operand-size override */
            op_bytes = def_op_bytes ^ 6;
            if ( !vex.pfx )
                vex.pfx = vex_66;
            break;
        case 0x67: /* address-size override */
            ad_bytes = def_ad_bytes ^ (mode_64bit() ? 12 : 6);
            break;
        case 0x2e: /* CS override */
            override_seg = x86_seg_cs;
            break;
        case 0x3e: /* DS override */
            override_seg = x86_seg_ds;
            break;
        case 0x26: /* ES override */
            override_seg = x86_seg_es;
            break;
        case 0x64: /* FS override */
            override_seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            override_seg = x86_seg_gs;
            break;
        case 0x36: /* SS override */
            override_seg = x86_seg_ss;
            break;
        case 0xf0: /* LOCK */
            lock_prefix = 1;
            break;
        case 0xf2: /* REPNE/REPNZ */
            vex.pfx = vex_f2;
            break;
        case 0xf3: /* REP/REPE/REPZ */
            vex.pfx = vex_f3;
            break;
        case 0x40 ... 0x4f: /* REX */
            if ( !mode_64bit() )
                goto done_prefixes;
            rex_prefix = b;
            continue;
        default:
            goto done_prefixes;
        }

        /* Any legacy prefix after a REX prefix nullifies its effect. */
        rex_prefix = 0;
    }
 done_prefixes:

    /* %{e,c,s,d}s overrides are ignored in 64bit mode. */
    if ( mode_64bit() && override_seg < x86_seg_fs )
        override_seg = x86_seg_none;

    if ( rex_prefix & REX_W )
        op_bytes = 8;

    /* Opcode byte(s). */
    d = opcode_table[b];
    if ( d == 0 && b == 0x0f )
    {
        /* Two-byte opcode. */
        b = insn_fetch_type(uint8_t);
        d = twobyte_table[b].desc;
        switch ( b )
        {
        default:
            opcode = b | MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f;
            state->simd_size = twobyte_table[b].size;
            break;
        case 0x38:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f38;
            break;
        case 0x3a:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
            ext = ext_0f3a;
            break;
        }
    }
    else
        opcode = b;

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        modrm = insn_fetch_type(uint8_t);
        modrm_mod = (modrm & 0xc0) >> 6;

        if ( !ext && ((b & ~1) == 0xc4 || (b == 0x8f && (modrm & 0x18)) ||
                      b == 0x62) )
            switch ( def_ad_bytes )
            {
            default:
                BUG(); /* Shouldn't be possible. */
            case 2:
                if ( state->regs->eflags & X86_EFLAGS_VM )
                    break;
                /* fall through */
            case 4:
                if ( modrm_mod != 3 || in_realmode(ctxt, ops) )
                    break;
                /* fall through */
            case 8:
                /* VEX / XOP / EVEX */
                generate_exception_if(rex_prefix || vex.pfx, EXC_UD);
                /*
                 * With operand size override disallowed (see above), op_bytes
                 * should not have changed from its default.
                 */
                ASSERT(op_bytes == def_op_bytes);

                vex.raw[0] = modrm;
                if ( b == 0xc5 )
                {
                    opcode = X86EMUL_OPC_VEX_;
                    vex.raw[1] = modrm;
                    vex.opcx = vex_0f;
                    vex.x = 1;
                    vex.b = 1;
                    vex.w = 0;
                }
                else
                {
                    vex.raw[1] = insn_fetch_type(uint8_t);
                    if ( mode_64bit() )
                    {
                        if ( !vex.b )
                            rex_prefix |= REX_B;
                        if ( !vex.x )
                            rex_prefix |= REX_X;
                        if ( vex.w )
                        {
                            rex_prefix |= REX_W;
                            op_bytes = 8;
                        }
                    }
                    else
                    {
                        /* Operand size fixed at 4 (no override via W bit). */
                        op_bytes = 4;
                        vex.b = 1;
                    }
                    switch ( b )
                    {
                    case 0x62:
                        opcode = X86EMUL_OPC_EVEX_;
                        evex.raw[0] = vex.raw[0];
                        evex.raw[1] = vex.raw[1];
                        evex.raw[2] = insn_fetch_type(uint8_t);

                        generate_exception_if(evex.mbs || !evex.mbz, EXC_UD);

                        if ( !mode_64bit() )
                        {
                            generate_exception_if(!evex.RX, EXC_UD);
                            evex.R = 1;
                        }

                        vex.opcx = evex.opcx;
                        break;
                    case 0xc4:
                        opcode = X86EMUL_OPC_VEX_;
                        break;
                    default:
                        opcode = 0;
                        break;
                    }
                }
                if ( !vex.r )
                    rex_prefix |= REX_R;

                ext = vex.opcx;
                if ( b != 0x8f )
                {
                    b = insn_fetch_type(uint8_t);
                    switch ( ext )
                    {
                    case vex_0f:
                        opcode |= MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[b].desc;
                        state->simd_size = twobyte_table[b].size;
                        break;
                    case vex_0f38:
                        opcode |= MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x38].desc;
                        break;
                    case vex_0f3a:
                        opcode |= MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x3a].desc;
                        break;
                    default:
                        rc = X86EMUL_UNRECOGNIZED;
                        goto done;
                    }
                }
                else if ( ext < ext_8f08 + ARRAY_SIZE(xop_table) )
                {
                    b = insn_fetch_type(uint8_t);
                    opcode |= MASK_INSR(0x8f08 + ext - ext_8f08,
                                        X86EMUL_OPC_EXT_MASK);
                    d = xop_table[ext - ext_8f08];
                }
                else
                {
                    rc = X86EMUL_UNRECOGNIZED;
                    goto done;
                }

                opcode |= b | MASK_INSR(vex.pfx, X86EMUL_OPC_PFX_MASK);

                if ( !(d & ModRM) )
                    break;

                modrm = insn_fetch_type(uint8_t);
                modrm_mod = (modrm & 0xc0) >> 6;

                break;
            }
    }

    if ( d & ModRM )
    {
        d &= ~ModRM;
#undef ModRM /* Only its aliases are valid to use from here on. */
        modrm_reg = ((rex_prefix & 4) << 1) | ((modrm & 0x38) >> 3);
        modrm_rm  = modrm & 0x07;

        /*
         * Early operand adjustments. Only ones affecting further processing
         * prior to the x86_decode_*() calls really belong here. That would
         * normally be only addition/removal of SrcImm/SrcImm16, so their
         * fetching can be taken care of by the common code below.
         */
        switch ( ext )
        {
        case ext_none:
            switch ( b )
            {
            case 0xf6 ... 0xf7: /* Grp3 */
                switch ( modrm_reg & 7 )
                {
                case 0 ... 1: /* test */
                    d |= DstMem | SrcImm;
                    break;
                case 2: /* not */
                case 3: /* neg */
                    d |= DstMem;
                    break;
                case 4: /* mul */
                case 5: /* imul */
                case 6: /* div */
                case 7: /* idiv */
                    /*
                     * DstEax isn't really precise for all cases; updates to
                     * rDX get handled in an open coded manner.
                     */
                    d |= DstEax | SrcMem;
                    break;
                }
                break;
            }
            break;

        case ext_0f:
            switch ( b )
            {
            case 0x20: /* mov cr,reg */
            case 0x21: /* mov dr,reg */
            case 0x22: /* mov reg,cr */
            case 0x23: /* mov reg,dr */
                /*
                 * Mov to/from cr/dr ignore the encoding of Mod, and behave as
                 * if they were encoded as reg/reg instructions.  No futher
                 * disp/SIB bytes are fetched.
                 */
                modrm_mod = 3;
                break;
            }
            break;

        case ext_0f38:
            d = ext0f38_table[b].to_mem ? DstMem | SrcReg
                                        : DstReg | SrcMem;
            if ( ext0f38_table[b].two_op )
                d |= TwoOp;
            if ( ext0f38_table[b].vsib )
                d |= vSIB;
            state->simd_size = ext0f38_table[b].simd_size;
            break;

        case ext_8f09:
            if ( ext8f09_table[b].two_op )
                d |= TwoOp;
            state->simd_size = ext8f09_table[b].simd_size;
            break;

        case ext_0f3a:
        case ext_8f08:
            /*
             * Cannot update d here yet, as the immediate operand still
             * needs fetching.
             */
        default:
            break;
        }

        if ( modrm_mod == 3 )
        {
            generate_exception_if(d & vSIB, EXC_UD);
            modrm_rm |= (rex_prefix & 1) << 3;
            ea.type = OP_REG;
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            generate_exception_if(d & vSIB, EXC_UD);
            ea.type = OP_MEM;
            switch ( modrm_rm )
            {
            case 0:
                ea.mem.off = state->regs->bx + state->regs->si;
                break;
            case 1:
                ea.mem.off = state->regs->bx + state->regs->di;
                break;
            case 2:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp + state->regs->si;
                break;
            case 3:
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp + state->regs->di;
                break;
            case 4:
                ea.mem.off = state->regs->si;
                break;
            case 5:
                ea.mem.off = state->regs->di;
                break;
            case 6:
                if ( modrm_mod == 0 )
                    break;
                ea.mem.seg = x86_seg_ss;
                ea.mem.off = state->regs->bp;
                break;
            case 7:
                ea.mem.off = state->regs->bx;
                break;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( modrm_rm == 6 )
                    ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            ea.type = OP_MEM;
            if ( modrm_rm == 4 )
            {
                uint8_t sib = insn_fetch_type(uint8_t);
                uint8_t sib_base = (sib & 7) | ((rex_prefix << 3) & 8);

                state->sib_index = ((sib >> 3) & 7) | ((rex_prefix << 2) & 8);
                state->sib_scale = (sib >> 6) & 3;
                if ( state->sib_index != 4 && !(d & vSIB) )
                {
                    ea.mem.off = *decode_gpr(state->regs, state->sib_index);
                    ea.mem.off <<= state->sib_scale;
                }
                if ( (modrm_mod == 0) && ((sib_base & 7) == 5) )
                    ea.mem.off += insn_fetch_type(int32_t);
                else if ( sib_base == 4 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->r(sp);
                    if ( !ext && (b == 0x8f) )
                        /* POP <rm> computes its EA post increment. */
                        ea.mem.off += ((mode_64bit() && (op_bytes == 4))
                                       ? 8 : op_bytes);
                }
                else if ( sib_base == 5 )
                {
                    ea.mem.seg  = x86_seg_ss;
                    ea.mem.off += state->regs->r(bp);
                }
                else
                    ea.mem.off += *decode_gpr(state->regs, sib_base);
            }
            else
            {
                generate_exception_if(d & vSIB, EXC_UD);
                modrm_rm |= (rex_prefix & 1) << 3;
                ea.mem.off = *decode_gpr(state->regs, modrm_rm);
                if ( (modrm_rm == 5) && (modrm_mod != 0) )
                    ea.mem.seg = x86_seg_ss;
            }
            switch ( modrm_mod )
            {
            case 0:
                if ( (modrm_rm & 7) != 5 )
                    break;
                ea.mem.off = insn_fetch_type(int32_t);
                pc_rel = mode_64bit();
                break;
            case 1:
                ea.mem.off += insn_fetch_type(int8_t);
                break;
            case 2:
                ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
        }
    }
    else
    {
        modrm_mod = 0xff;
        modrm_reg = modrm_rm = modrm = 0;
    }

    if ( override_seg != x86_seg_none )
        ea.mem.seg = override_seg;

    /* Fetch the immediate operand, if present. */
    switch ( d & SrcMask )
    {
        unsigned int bytes;

    case SrcImm:
        if ( !(d & ByteOp) )
            bytes = op_bytes != 8 ? op_bytes : 4;
        else
        {
    case SrcImmByte:
            bytes = 1;
        }
        /* NB. Immediates are sign-extended as necessary. */
        switch ( bytes )
        {
        case 1: imm1 = insn_fetch_type(int8_t);  break;
        case 2: imm1 = insn_fetch_type(int16_t); break;
        case 4: imm1 = insn_fetch_type(int32_t); break;
        }
        break;
    case SrcImm16:
        imm1 = insn_fetch_type(uint16_t);
        break;
    }

    ctxt->opcode = opcode;
    state->desc = d;

    switch ( ext )
    {
    case ext_none:
        rc = x86_decode_onebyte(state, ctxt, ops);
        break;

    case ext_0f:
        rc = x86_decode_twobyte(state, ctxt, ops);
        break;

    case ext_0f38:
        rc = x86_decode_0f38(state, ctxt, ops);
        break;

    case ext_0f3a:
        d = ext0f3a_table[b].to_mem ? DstMem | SrcReg : DstReg | SrcMem;
        if ( ext0f3a_table[b].two_op )
            d |= TwoOp;
        else if ( ext0f3a_table[b].four_op && !mode_64bit() && vex.opcx )
            imm1 &= 0x7f;
        state->desc = d;
        state->simd_size = ext0f3a_table[b].simd_size;
        rc = x86_decode_0f3a(state, ctxt, ops);
        break;

    case ext_8f08:
        d = DstReg | SrcMem;
        if ( ext8f08_table[b].two_op )
            d |= TwoOp;
        else if ( ext8f08_table[b].four_op && !mode_64bit() )
            imm1 &= 0x7f;
        state->desc = d;
        state->simd_size = ext8f08_table[b].simd_size;
        break;

    case ext_8f09:
    case ext_8f0a:
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNIMPLEMENTED;
    }

    if ( ea.type == OP_MEM )
    {
        if ( pc_rel )
            ea.mem.off += state->ip;

        ea.mem.off = truncate_ea(ea.mem.off);
    }

    /*
     * Simple op_bytes calculations. More complicated cases produce 0
     * and are further handled during execute.
     */
    switch ( state->simd_size )
    {
    case simd_none:
        /*
         * When prefix 66 has a meaning different from operand-size override,
         * operand size defaults to 4 and can't be overridden to 2.
         */
        if ( op_bytes == 2 &&
             (ctxt->opcode & X86EMUL_OPC_PFX_MASK) == X86EMUL_OPC_66(0, 0) )
            op_bytes = 4;
        break;

    case simd_packed_int:
        switch ( vex.pfx )
        {
        case vex_none:
            if ( !vex.opcx )
            {
                op_bytes = 8;
                break;
            }
            /* fall through */
        case vex_66:
            op_bytes = 16 << vex.l;
            break;
        default:
            op_bytes = 0;
            break;
        }
        break;

    case simd_single_fp:
        if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
        {
            op_bytes = 0;
            break;
    case simd_packed_fp:
            if ( vex.pfx & VEX_PREFIX_SCALAR_MASK )
            {
                op_bytes = 0;
                break;
            }
        }
        /* fall through */
    case simd_any_fp:
        switch ( vex.pfx )
        {
        default:     op_bytes = 16 << vex.l; break;
        case vex_f3: op_bytes = 4;           break;
        case vex_f2: op_bytes = 8;           break;
        }
        break;

    case simd_scalar_fp:
        op_bytes = 4 << (ctxt->opcode & 1);
        break;

    case simd_128:
        op_bytes = 16;
        break;

    default:
        op_bytes = 0;
        break;
    }

 done:
    return rc;
}

/* No insn fetching past this point. */
#undef insn_fetch_bytes
#undef insn_fetch_type

/* Undo DEBUG wrapper. */
#undef x86_emulate

int
x86_emulate(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    /* Shadow copy of register state. Committed on successful emulation. */
    struct cpu_user_regs _regs = *ctxt->regs;
    struct x86_emulate_state state;
    int rc;
    uint8_t b, d, *opc = NULL;
    unsigned int first_byte = 0, insn_bytes = 0;
    bool singlestep = (_regs.eflags & X86_EFLAGS_TF) &&
	    !is_branch_step(ctxt, ops);
    bool sfence = false;
    struct operand src = { .reg = PTR_POISON };
    struct operand dst = { .reg = PTR_POISON };
    unsigned long cr4;
    enum x86_emulate_fpu_type fpu_type = X86EMUL_FPU_none;
    struct x86_emulate_stub stub = {};
    DECLARE_ALIGNED(mmval_t, mmval);
#ifdef __XEN__
    struct {
        union stub_exception_token info;
        unsigned int line;
    } stub_exn;
#endif

    ASSERT(ops->read);

    rc = x86_decode(&state, ctxt, ops);
    if ( rc != X86EMUL_OKAY )
        return rc;

    /* Sync rIP to post decode value. */
    _regs.r(ip) = state.ip;

    if ( ops->validate )
    {
#ifndef NDEBUG
        state.caller = __builtin_return_address(0);
#endif
        rc = ops->validate(&state, ctxt);
#ifndef NDEBUG
        state.caller = NULL;
#endif
        if ( rc == X86EMUL_DONE )
            goto complete_insn;
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    b = ctxt->opcode;
    d = state.desc;
#define state (&state)

    generate_exception_if(state->not_64bit && mode_64bit(), EXC_UD);

    if ( ea.type == OP_REG )
        ea.reg = _decode_gpr(&_regs, modrm_rm, (d & ByteOp) && !rex_prefix);

    memset(mmvalp, 0xaa /* arbitrary */, sizeof(*mmvalp));

    /* Decode and fetch the source operand: register, memory or immediate. */
    switch ( d & SrcMask )
    {
    case SrcNone: /* case SrcImplicit: */
        src.type = OP_NONE;
        break;
    case SrcReg:
        src.type = OP_REG;
        if ( d & ByteOp )
        {
            src.reg = _decode_gpr(&_regs, modrm_reg, !rex_prefix);
            src.val = *(uint8_t *)src.reg;
            src.bytes = 1;
        }
        else
        {
            src.reg = decode_gpr(&_regs, modrm_reg);
            switch ( (src.bytes = op_bytes) )
            {
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        break;
    case SrcMem16:
        ea.bytes = 2;
        goto srcmem_common;
    case SrcMem:
        if ( state->simd_size )
            break;
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
    srcmem_common:
        src = ea;
        if ( src.type == OP_REG )
        {
            switch ( src.bytes )
            {
            case 1: src.val = *(uint8_t  *)src.reg; break;
            case 2: src.val = *(uint16_t *)src.reg; break;
            case 4: src.val = *(uint32_t *)src.reg; break;
            case 8: src.val = *(uint64_t *)src.reg; break;
            }
        }
        else if ( (rc = read_ulong(src.mem.seg, src.mem.off,
                                   &src.val, src.bytes, ctxt, ops)) )
            goto done;
        break;
    case SrcImm:
        if ( !(d & ByteOp) )
            src.bytes = op_bytes != 8 ? op_bytes : 4;
        else
        {
    case SrcImmByte:
            src.bytes = 1;
        }
        src.type  = OP_IMM;
        src.val   = imm1;
        break;
    case SrcImm16:
        src.type  = OP_IMM;
        src.bytes = 2;
        src.val   = imm1;
        break;
    }

    /* Decode (but don't fetch) the destination operand: register or memory. */
    switch ( d & DstMask )
    {
    case DstNone: /* case DstImplicit: */
        /*
         * The only implicit-operands instructions allowed a LOCK prefix are
         * CMPXCHG{8,16}B (MOV CRn is being handled elsewhere).
         */
        generate_exception_if(lock_prefix &&
                              (vex.opcx || ext != ext_0f || b != 0xc7 ||
                               (modrm_reg & 7) != 1 || ea.type != OP_MEM),
                              EXC_UD);
        dst.type = OP_NONE;
        break;

    case DstReg:
        generate_exception_if(lock_prefix, EXC_UD);
        dst.type = OP_REG;
        if ( d & ByteOp )
        {
            dst.reg = _decode_gpr(&_regs, modrm_reg, !rex_prefix);
            dst.val = *(uint8_t *)dst.reg;
            dst.bytes = 1;
        }
        else
        {
            dst.reg = decode_gpr(&_regs, modrm_reg);
            switch ( (dst.bytes = op_bytes) )
            {
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        break;
    case DstBitBase:
        if ( ea.type == OP_MEM )
        {
            /*
             * Instructions such as bt can reference an arbitrary offset from
             * their memory operand, but the instruction doing the actual
             * emulation needs the appropriate op_bytes read from memory.
             * Adjust both the source register and memory operand to make an
             * equivalent instruction.
             *
             * EA       += BitOffset DIV op_bytes*8
             * BitOffset = BitOffset MOD op_bytes*8
             * DIV truncates towards negative infinity.
             * MOD always produces a positive result.
             */
            if ( op_bytes == 2 )
                src.val = (int16_t)src.val;
            else if ( op_bytes == 4 )
                src.val = (int32_t)src.val;
            if ( (long)src.val < 0 )
                ea.mem.off -=
                    op_bytes + (((-src.val - 1) >> 3) & ~(op_bytes - 1L));
            else
                ea.mem.off += (src.val >> 3) & ~(op_bytes - 1L);
            ea.mem.off = truncate_ea(ea.mem.off);
        }

        /* Bit index always truncated to within range. */
        src.val &= (op_bytes << 3) - 1;

        d = (d & ~DstMask) | DstMem;
        /* Becomes a normal DstMem operation from here on. */
    case DstMem:
        if ( state->simd_size )
        {
            generate_exception_if(lock_prefix, EXC_UD);
            break;
        }
        ea.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst = ea;
        if ( dst.type == OP_REG )
        {
            generate_exception_if(lock_prefix, EXC_UD);
            switch ( dst.bytes )
            {
            case 1: dst.val = *(uint8_t  *)dst.reg; break;
            case 2: dst.val = *(uint16_t *)dst.reg; break;
            case 4: dst.val = *(uint32_t *)dst.reg; break;
            case 8: dst.val = *(uint64_t *)dst.reg; break;
            }
        }
        else if ( d & Mov ) /* optimisation - avoid slow emulated read */
        {
            /* Lock prefix is allowed only on RMW instructions. */
            generate_exception_if(lock_prefix, EXC_UD);
            fail_if(!ops->write);
        }
        else if ( !ops->rmw )
        {
            fail_if(lock_prefix ? !ops->cmpxchg : !ops->write);
            if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) )
                goto done;
            dst.orig_val = dst.val;
        }
        break;
    }

    switch ( ctxt->opcode )
    {
        enum x86_segment seg;
        struct segment_register cs, sreg;
        struct cpuid_leaf cpuid_leaf;
        uint64_t msr_val;
        unsigned int i, n;
        unsigned long dummy;

    case 0x00: case 0x01: add: /* add reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_add;
        else
        {
    case 0x02 ... 0x05: /* add */
            emulate_2op_SrcV("add", src, dst, _regs.eflags);
        }
        break;

    case 0x08: case 0x09: or: /* or reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_or;
        else
        {
    case 0x0a ... 0x0d: /* or */
            emulate_2op_SrcV("or", src, dst, _regs.eflags);
        }
        break;

    case 0x10: case 0x11: adc: /* adc reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_adc;
        else
        {
    case 0x12 ... 0x15: /* adc */
            emulate_2op_SrcV("adc", src, dst, _regs.eflags);
        }
        break;

    case 0x18: case 0x19: sbb: /* sbb reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_sbb;
        else
        {
    case 0x1a ... 0x1d: /* sbb */
            emulate_2op_SrcV("sbb", src, dst, _regs.eflags);
        }
        break;

    case 0x20: case 0x21: and: /* and reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_and;
        else
        {
    case 0x22 ... 0x25: /* and */
            emulate_2op_SrcV("and", src, dst, _regs.eflags);
        }
        break;

    case 0x28: case 0x29: sub: /* sub reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_sub;
        else
        {
    case 0x2a ... 0x2d: /* sub */
            emulate_2op_SrcV("sub", src, dst, _regs.eflags);
        }
        break;

    case 0x30: case 0x31: xor: /* xor reg,mem */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_xor;
        else
        {
    case 0x32 ... 0x35: /* xor */
            emulate_2op_SrcV("xor", src, dst, _regs.eflags);
        }
        break;

    case 0x38: case 0x39: cmp: /* cmp reg,mem */
        if ( ops->rmw && dst.type == OP_MEM &&
             (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                              dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        /* fall through */
    case 0x3a ... 0x3d: /* cmp */
        generate_exception_if(lock_prefix, EXC_UD);
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x06: /* push %%es */
    case 0x0e: /* push %%cs */
    case 0x16: /* push %%ss */
    case 0x1e: /* push %%ds */
    case X86EMUL_OPC(0x0f, 0xa0): /* push %%fs */
    case X86EMUL_OPC(0x0f, 0xa8): /* push %%gs */
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment((b >> 3) & 7, &sreg,
                                     ctxt)) != X86EMUL_OKAY )
            goto done;
        src.val = sreg.sel;
        goto push;

    case 0x07: /* pop %%es */
    case 0x17: /* pop %%ss */
    case 0x1f: /* pop %%ds */
    case X86EMUL_OPC(0x0f, 0xa1): /* pop %%fs */
    case X86EMUL_OPC(0x0f, 0xa9): /* pop %%gs */
        fail_if(ops->write_segment == NULL);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        seg = (b >> 3) & 7;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes), &dst.val,
                              op_bytes, ctxt, ops)) != X86EMUL_OKAY ||
             (rc = load_seg(seg, dst.val, 0, NULL, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        if ( seg == x86_seg_ss )
            ctxt->retire.mov_ss = true;
        break;

    case 0x27: /* daa */
    case 0x2f: /* das */ {
        uint8_t al = _regs.al;
        unsigned int eflags = _regs.eflags;

        _regs.eflags &= ~(X86_EFLAGS_CF | X86_EFLAGS_AF | X86_EFLAGS_SF |
                          X86_EFLAGS_ZF | X86_EFLAGS_PF);
        if ( ((al & 0x0f) > 9) || (eflags & X86_EFLAGS_AF) )
        {
            _regs.eflags |= X86_EFLAGS_AF;
            if ( b == 0x2f && (al < 6 || (eflags & X86_EFLAGS_CF)) )
                _regs.eflags |= X86_EFLAGS_CF;
            _regs.al += (b == 0x27) ? 6 : -6;
        }
        if ( (al > 0x99) || (eflags & X86_EFLAGS_CF) )
        {
            _regs.al += (b == 0x27) ? 0x60 : -0x60;
            _regs.eflags |= X86_EFLAGS_CF;
        }
        _regs.eflags |= !_regs.al ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= ((int8_t)_regs.al < 0) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= even_parity(_regs.al) ? X86_EFLAGS_PF : 0;
        break;
    }

    case 0x37: /* aaa */
    case 0x3f: /* aas */
        _regs.eflags &= ~X86_EFLAGS_CF;
        if ( (_regs.al > 9) || (_regs.eflags & X86_EFLAGS_AF) )
        {
            _regs.al += (b == 0x37) ? 6 : -6;
            _regs.ah += (b == 0x37) ? 1 : -1;
            _regs.eflags |= X86_EFLAGS_CF | X86_EFLAGS_AF;
        }
        _regs.al &= 0x0f;
        break;

    case 0x40 ... 0x4f: /* inc/dec reg */
        dst.type  = OP_REG;
        dst.reg   = decode_gpr(&_regs, b & 7);
        dst.bytes = op_bytes;
        dst.val   = *dst.reg;
        if ( b & 8 )
            emulate_1op("dec", dst, _regs.eflags);
        else
            emulate_1op("inc", dst, _regs.eflags);
        break;

    case 0x50 ... 0x57: /* push reg */
        src.val = *decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        goto push;

    case 0x58 ... 0x5f: /* pop reg */
        dst.type  = OP_REG;
        dst.reg   = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.bytes = op_bytes;
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x60: /* pusha */
        fail_if(!ops->write);
        ea.val = _regs.esp;
        for ( i = 0; i < 8; i++ )
        {
            void *reg = decode_gpr(&_regs, i);

            if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                                  reg != &_regs.esp ? reg : &ea.val,
                                  op_bytes, ctxt)) != 0 )
                goto done;
        }
        break;

    case 0x61: /* popa */
        for ( i = 0; i < 8; i++ )
        {
            void *reg = decode_gpr(&_regs, 7 - i);

            if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                                  &dst.val, op_bytes, ctxt, ops)) != 0 )
                goto done;
            if ( reg == &_regs.r(sp) )
                continue;
            if ( op_bytes == 2 )
                *(uint16_t *)reg = dst.val;
            else
                *(unsigned long *)reg = dst.val;
        }
        break;

    case 0x62: /* bound */ {
        int lb, ub, idx;

        generate_exception_if(src.type != OP_MEM, EXC_UD);
        if ( (rc = read_ulong(src.mem.seg, truncate_ea(src.mem.off + op_bytes),
                              &ea.val, op_bytes, ctxt, ops)) )
            goto done;
        ub  = (op_bytes == 2) ? (int16_t)ea.val   : (int32_t)ea.val;
        lb  = (op_bytes == 2) ? (int16_t)src.val  : (int32_t)src.val;
        idx = (op_bytes == 2) ? (int16_t)dst.val  : (int32_t)dst.val;
        generate_exception_if((idx < lb) || (idx > ub), EXC_BR);
        dst.type = OP_NONE;
        break;
    }

    case 0x63: /* movsxd (x86/64) / arpl (x86/32) */
        if ( mode_64bit() )
        {
            /* movsxd */
            if ( ea.type == OP_REG )
                src.val = *ea.reg;
            else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                       &src.val, 4, ctxt, ops)) )
                goto done;
            dst.val = (int32_t)src.val;
        }
        else
        {
            /* arpl */
            unsigned int src_rpl = dst.val & 3;

            dst = ea;
            dst.bytes = 2;
            if ( dst.type == OP_REG )
                dst.val = *dst.reg;
            else if ( (rc = read_ulong(dst.mem.seg, dst.mem.off,
                                       &dst.val, 2, ctxt, ops)) )
                goto done;
            if ( src_rpl > (dst.val & 3) )
            {
                _regs.eflags |= X86_EFLAGS_ZF;
                dst.val = (dst.val & ~3) | src_rpl;
            }
            else
            {
                _regs.eflags &= ~X86_EFLAGS_ZF;
                dst.type = OP_NONE;
            }
            generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        }
        break;

    case 0x68: /* push imm{16,32,64} */
    case 0x6a: /* push imm8 */
    push:
        ASSERT(d & Mov); /* writeback needed */
        dst.type  = OP_MEM;
        dst.bytes = mode_64bit() && (op_bytes == 4) ? 8 : op_bytes;
        dst.val = src.val;
        dst.mem.seg = x86_seg_ss;
        dst.mem.off = sp_pre_dec(dst.bytes);
        break;

    case 0x69: /* imul imm16/32 */
    case 0x6b: /* imul imm8 */
        if ( ea.type == OP_REG )
            dst.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                   &dst.val, op_bytes, ctxt, ops)) )
            goto done;
        goto imul;

    case 0x6c ... 0x6d: /* ins %dx,%es:%edi */ {
        unsigned long nr_reps = get_rep_prefix(false, true);
        unsigned int port = _regs.dx;

        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.r(di), nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        /* Try the presumably most efficient approach first. */
        if ( !ops->rep_ins )
            nr_reps = 1;
        rc = X86EMUL_UNHANDLEABLE;
        if ( nr_reps == 1 && ops->read_io && ops->write )
        {
            rc = ops->read_io(port, dst.bytes, &dst.val, ctxt);
            if ( rc != X86EMUL_UNHANDLEABLE )
                nr_reps = 0;
        }
        if ( (nr_reps > 1 || rc == X86EMUL_UNHANDLEABLE) && ops->rep_ins )
            rc = ops->rep_ins(port, dst.mem.seg, dst.mem.off, dst.bytes,
                              &nr_reps, ctxt);
        if ( nr_reps >= 1 && rc == X86EMUL_UNHANDLEABLE )
        {
            fail_if(!ops->read_io || !ops->write);
            if ( (rc = ops->read_io(port, dst.bytes, &dst.val, ctxt)) != 0 )
                goto done;
            nr_reps = 0;
        }
        if ( !nr_reps && rc == X86EMUL_OKAY )
        {
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0x6e ... 0x6f: /* outs %esi,%dx */ {
        unsigned long nr_reps = get_rep_prefix(true, false);
        unsigned int port = _regs.dx;

        dst.bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        ea.mem.off = truncate_ea_and_reps(_regs.r(si), nr_reps, dst.bytes);
        if ( (rc = ioport_access_check(port, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        /* Try the presumably most efficient approach first. */
        if ( !ops->rep_outs )
            nr_reps = 1;
        rc = X86EMUL_UNHANDLEABLE;
        if ( nr_reps == 1 && ops->write_io )
        {
            rc = read_ulong(ea.mem.seg, ea.mem.off, &dst.val, dst.bytes,
                            ctxt, ops);
            if ( rc != X86EMUL_UNHANDLEABLE )
                nr_reps = 0;
        }
        if ( (nr_reps > 1 || rc == X86EMUL_UNHANDLEABLE) && ops->rep_outs )
            rc = ops->rep_outs(ea.mem.seg, ea.mem.off, port, dst.bytes,
                               &nr_reps, ctxt);
        if ( nr_reps >= 1 && rc == X86EMUL_UNHANDLEABLE )
        {
            if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &dst.val,
                                  dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
                goto done;
            fail_if(ops->write_io == NULL);
            nr_reps = 0;
        }
        if ( !nr_reps && rc == X86EMUL_OKAY )
        {
            if ( (rc = ops->write_io(port, dst.bytes, dst.val, ctxt)) != 0 )
                goto done;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(si), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0x70 ... 0x7f: /* jcc (short) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0x80: case 0x81: case 0x82: case 0x83: /* Grp1 */
        switch ( modrm_reg & 7 )
        {
        case 0: goto add;
        case 1: goto or;
        case 2: goto adc;
        case 3: goto sbb;
        case 4: goto and;
        case 5: goto sub;
        case 6: goto xor;
        case 7: goto cmp;
        }
        break;

    case 0xa8 ... 0xa9: /* test imm,%%eax */
    case 0x84 ... 0x85: test: /* test */
        emulate_2op_SrcV("test", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case 0x86 ... 0x87: xchg: /* xchg */
        /*
         * The lock prefix is implied for this insn (and setting it for the
         * register operands case here is benign to subsequent code).
         */
        lock_prefix = 1;
        if ( ops->rmw && dst.type == OP_MEM )
        {
            state->rmw = rmw_xchg;
            break;
        }
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        /* Arrange for write back of the memory destination. */
        dst.val = src.val;
        break;

    case 0xc6: /* Grp11: mov / xabort */
    case 0xc7: /* Grp11: mov / xbegin */
        if ( modrm == 0xf8 && vcpu_has_rtm() )
        {
            /*
             * xbegin unconditionally aborts, xabort is unconditionally
             * a nop.
             */
            if ( b & 1 )
            {
                jmp_rel((int32_t)src.val);
                _regs.r(ax) = 0;
            }
            dst.type = OP_NONE;
            break;
        }
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD);
    case 0x88 ... 0x8b: /* mov */
    case 0xa0 ... 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2 ... 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        dst.val = src.val;
        break;

    case 0x8c: /* mov Sreg,r/m */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg), EXC_UD);
    store_selector:
        fail_if(ops->read_segment == NULL);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != 0 )
            goto done;
        dst.val = sreg.sel;
        if ( dst.type == OP_MEM )
            dst.bytes = 2;
        break;

    case 0x8d: /* lea */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        dst.val = ea.mem.off;
        break;

    case 0x8e: /* mov r/m,Sreg */
        seg = modrm_reg & 7; /* REX.R is ignored. */
        generate_exception_if(!is_x86_user_segment(seg) ||
                              seg == x86_seg_cs, EXC_UD);
        if ( (rc = load_seg(seg, src.val, 0, NULL, ctxt, ops)) != 0 )
            goto done;
        if ( seg == x86_seg_ss )
            ctxt->retire.mov_ss = true;
        dst.type = OP_NONE;
        break;

    case 0x8f: /* pop (sole member of Grp1a) */
        generate_exception_if((modrm_reg & 7) != 0, EXC_UD);
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (dst.bytes == 4) )
            dst.bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        break;

    case 0x90: /* nop / xchg %%r8,%%rax */
    case X86EMUL_OPC_F3(0, 0x90): /* pause / xchg %%r8,%%rax */
        if ( !(rex_prefix & REX_B) )
            break; /* nop / pause */
        /* fall through */

    case 0x91 ... 0x97: /* xchg reg,%%rax */
        dst.type = OP_REG;
        dst.bytes = op_bytes;
        dst.reg  = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.val  = *dst.reg;
        goto xchg;

    case 0x98: /* cbw/cwde/cdqe */
        switch ( op_bytes )
        {
        case 2: _regs.ax = (int8_t)_regs.al; break; /* cbw */
        case 4: _regs.r(ax) = (uint32_t)(int16_t)_regs.ax; break; /* cwde */
        case 8: _regs.r(ax) = (int32_t)_regs.eax; break; /* cdqe */
        }
        break;

    case 0x99: /* cwd/cdq/cqo */
        switch ( op_bytes )
        {
        case 2: _regs.dx = -((int16_t)_regs.ax < 0); break;
        case 4: _regs.r(dx) = (uint32_t)-((int32_t)_regs.eax < 0); break;
#ifdef __x86_64__
        case 8: _regs.rdx = -((int64_t)_regs.rax < 0); break;
#endif
        }
        break;

    case 0x9a: /* call (far, absolute) */
        ASSERT(!mode_64bit());
    far_call:
        fail_if(!ops->read_segment || !ops->write);

        if ( (rc = ops->read_segment(x86_seg_cs, &sreg, ctxt)) ||
             (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (validate_far_branch(&cs, imm1),
              src.val = sreg.sel,
              rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &src.val, op_bytes, ctxt)) ||
             (rc = ops->write(x86_seg_ss, sp_pre_dec(op_bytes),
                              &_regs.r(ip), op_bytes, ctxt)) ||
             (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) )
            goto done;

        _regs.r(ip) = imm1;
        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case 0x9b:  /* wait/fwait */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_wait);
        emulate_fpu_insn_stub(b);
        break;

    case 0x9c: /* pushf */
        if ( (_regs.eflags & X86_EFLAGS_VM) &&
             MASK_EXTR(_regs.eflags, X86_EFLAGS_IOPL) != 3 )
        {
            cr4 = 0;
            if ( op_bytes == 2 && ops->read_cr )
            {
                rc = ops->read_cr(4, &cr4, ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
            }
            generate_exception_if(!(cr4 & X86_CR4_VME), EXC_GP, 0);
            src.val = (_regs.flags & ~X86_EFLAGS_IF) | X86_EFLAGS_IOPL;
            if ( _regs.eflags & X86_EFLAGS_VIF )
                src.val |= X86_EFLAGS_IF;
        }
        else
            src.val = _regs.r(flags) & ~(X86_EFLAGS_VM | X86_EFLAGS_RF);
        goto push;

    case 0x9d: /* popf */ {
        uint32_t mask = X86_EFLAGS_VIP | X86_EFLAGS_VIF | X86_EFLAGS_VM;

        cr4 = 0;
        if ( !mode_ring0() )
        {
            if ( _regs.eflags & X86_EFLAGS_VM )
            {
                if ( op_bytes == 2 && ops->read_cr )
                {
                    rc = ops->read_cr(4, &cr4, ctxt);
                    if ( rc != X86EMUL_OKAY )
                        goto done;
                }
                generate_exception_if(!(cr4 & X86_CR4_VME) &&
                                      MASK_EXTR(_regs.eflags, X86_EFLAGS_IOPL) != 3,
                                      EXC_GP, 0);
            }
            mask |= X86_EFLAGS_IOPL;
            if ( !mode_iopl() )
                mask |= X86_EFLAGS_IF;
        }
        /* 64-bit mode: POP defaults to a 64-bit operand. */
        if ( mode_64bit() && (op_bytes == 4) )
            op_bytes = 8;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) != 0 )
            goto done;
        if ( op_bytes == 2 )
        {
            dst.val = (uint16_t)dst.val | (_regs.eflags & 0xffff0000u);
            if ( cr4 & X86_CR4_VME )
            {
                if ( dst.val & X86_EFLAGS_IF )
                {
                    generate_exception_if(_regs.eflags & X86_EFLAGS_VIP,
                                          EXC_GP, 0);
                    dst.val |= X86_EFLAGS_VIF;
                }
                else
                    dst.val &= ~X86_EFLAGS_VIF;
                mask &= ~X86_EFLAGS_VIF;
            }
        }
        dst.val &= EFLAGS_MODIFIABLE;
        _regs.eflags &= mask;
        _regs.eflags |= (dst.val & ~mask) | X86_EFLAGS_MBS;
        break;
    }

    case 0x9e: /* sahf */
        if ( mode_64bit() )
            vcpu_must_have(lahf_lm);
        *(uint8_t *)&_regs.eflags = (_regs.ah & EFLAGS_MASK) | X86_EFLAGS_MBS;
        break;

    case 0x9f: /* lahf */
        if ( mode_64bit() )
            vcpu_must_have(lahf_lm);
        _regs.ah = (_regs.eflags & EFLAGS_MASK) | X86_EFLAGS_MBS;
        break;

    case 0xa4 ... 0xa5: /* movs */ {
        unsigned long nr_reps = get_rep_prefix(true, true);

        dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea_and_reps(_regs.r(di), nr_reps, dst.bytes);
        src.mem.off = truncate_ea_and_reps(_regs.r(si), nr_reps, dst.bytes);
        if ( (nr_reps == 1) || !ops->rep_movs ||
             ((rc = ops->rep_movs(ea.mem.seg, src.mem.off,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) == X86EMUL_UNHANDLEABLE) )
        {
            if ( (rc = read_ulong(ea.mem.seg, src.mem.off,
                                  &dst.val, dst.bytes, ctxt, ops)) != 0 )
                goto done;
            dst.type = OP_MEM;
            nr_reps = 1;
        }
        register_address_adjust(_regs.r(si), nr_reps * dst.bytes);
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0xa6 ... 0xa7: /* cmps */ {
        unsigned long next_eip = _regs.r(ip);

        get_rep_prefix(true, true);
        src.bytes = dst.bytes = (d & ByteOp) ? 1 : op_bytes;
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(si)),
                              &dst.val, dst.bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_es, truncate_ea(_regs.r(di)),
                              &src.val, src.bytes, ctxt, ops)) )
            goto done;
        register_address_adjust(_regs.r(si), dst.bytes);
        register_address_adjust(_regs.r(di), src.bytes);
        put_rep_prefix(1);
        /* cmp: dst - src ==> src=*%%edi,dst=*%%esi ==> *%%esi - *%%edi */
        emulate_2op_SrcV("cmp", src, dst, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & X86_EFLAGS_ZF)) ||
             (repne_prefix() && (_regs.eflags & X86_EFLAGS_ZF)) )
            _regs.r(ip) = next_eip;
        break;
    }

    case 0xaa ... 0xab: /* stos */ {
        unsigned long nr_reps = get_rep_prefix(false, true);

        dst.bytes = src.bytes;
        dst.mem.seg = x86_seg_es;
        dst.mem.off = truncate_ea(_regs.r(di));
        if ( (nr_reps == 1) || !ops->rep_stos ||
             ((rc = ops->rep_stos(&src.val,
                                  dst.mem.seg, dst.mem.off, dst.bytes,
                                  &nr_reps, ctxt)) == X86EMUL_UNHANDLEABLE) )
        {
            dst.val = src.val;
            dst.type = OP_MEM;
            nr_reps = 1;
            rc = X86EMUL_OKAY;
        }
        register_address_adjust(_regs.r(di), nr_reps * dst.bytes);
        put_rep_prefix(nr_reps);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;
    }

    case 0xac ... 0xad: /* lods */
        get_rep_prefix(true, false);
        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(si)),
                              &dst.val, dst.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_adjust(_regs.r(si), dst.bytes);
        put_rep_prefix(1);
        break;

    case 0xae ... 0xaf: /* scas */ {
        unsigned long next_eip = _regs.r(ip);

        get_rep_prefix(false, true);
        if ( (rc = read_ulong(x86_seg_es, truncate_ea(_regs.r(di)),
                              &dst.val, src.bytes, ctxt, ops)) != 0 )
            goto done;
        register_address_adjust(_regs.r(di), src.bytes);
        put_rep_prefix(1);
        /* cmp: %%eax - *%%edi ==> src=%%eax,dst=*%%edi ==> src - dst */
        dst.bytes = src.bytes;
        emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
        if ( (repe_prefix() && !(_regs.eflags & X86_EFLAGS_ZF)) ||
             (repne_prefix() && (_regs.eflags & X86_EFLAGS_ZF)) )
            _regs.r(ip) = next_eip;
        break;
    }

    case 0xb0 ... 0xb7: /* mov imm8,r8 */
        dst.reg = _decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3),
                              !rex_prefix);
        dst.val = src.val;
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        dst.reg = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        dst.val = src.val;
        break;

    case 0xc0 ... 0xc1: grp2: /* Grp2 */
        generate_exception_if(lock_prefix, EXC_UD);

        switch ( modrm_reg & 7 )
        {
#define GRP2(name, ext) \
        case ext: \
            if ( ops->rmw && dst.type == OP_MEM ) \
                state->rmw = rmw_##name; \
            else \
                emulate_2op_SrcB(#name, src, dst, _regs.eflags); \
            break

        GRP2(rol, 0);
        GRP2(ror, 1);
        GRP2(rcl, 2);
        GRP2(rcr, 3);
        case 6: /* sal/shl alias */
        GRP2(shl, 4);
        GRP2(shr, 5);
        GRP2(sar, 7);
#undef GRP2
        }
        break;

    case 0xc2: /* ret imm16 (near) */
    case 0xc3: /* ret (near) */
        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + src.val),
                              &dst.val, op_bytes, ctxt, ops)) != 0 ||
             (rc = ops->insn_fetch(x86_seg_cs, dst.val, NULL, 0, ctxt)) )
            goto done;
        _regs.r(ip) = dst.val;
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0xc4: /* les */
    case 0xc5: /* lds */
        seg = (b & 1) * 3; /* es = 0, ds = 3 */
    les:
        generate_exception_if(src.type != OP_MEM, EXC_UD);
        if ( (rc = read_ulong(src.mem.seg, truncate_ea(src.mem.off + src.bytes),
                              &dst.val, 2, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        ASSERT(is_x86_user_segment(seg));
        if ( (rc = load_seg(seg, dst.val, 0, NULL, ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        dst.val = src.val;
        break;

    case 0xc8: /* enter imm16,imm8 */
        dst.type = OP_REG;
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        dst.reg = (unsigned long *)&_regs.r(bp);
        fail_if(!ops->write);
        if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                              &_regs.r(bp), dst.bytes, ctxt)) )
            goto done;
        dst.val = _regs.r(sp);

        n = imm2 & 31;
        if ( n )
        {
            for ( i = 1; i < n; i++ )
            {
                unsigned long ebp, temp_data;
                ebp = truncate_word(_regs.r(bp) - i*dst.bytes, ctxt->sp_size/8);
                if ( (rc = read_ulong(x86_seg_ss, ebp,
                                      &temp_data, dst.bytes, ctxt, ops)) ||
                     (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                                      &temp_data, dst.bytes, ctxt)) )
                    goto done;
            }
            if ( (rc = ops->write(x86_seg_ss, sp_pre_dec(dst.bytes),
                                  &dst.val, dst.bytes, ctxt)) )
                goto done;
        }

        sp_pre_dec(src.val);
        break;

    case 0xc9: /* leave */
        /* First writeback, to %%esp. */
        dst.bytes = (mode_64bit() && (op_bytes == 4)) ? 8 : op_bytes;
        if ( dst.bytes == 2 )
            _regs.sp = _regs.bp;
        else
            _regs.r(sp) = dst.bytes == 4 ? _regs.ebp : _regs.r(bp);

        /* Second writeback, to %%ebp. */
        dst.type = OP_REG;
        dst.reg = (unsigned long *)&_regs.r(bp);
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(dst.bytes),
                              &dst.val, dst.bytes, ctxt, ops)) )
            goto done;
        break;

    case 0xca: /* ret imm16 (far) */
    case 0xcb: /* ret (far) */
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &dst.val, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes + src.val),
                              &src.val, op_bytes, ctxt, ops)) ||
             (rc = load_seg(x86_seg_cs, src.val, 1, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, dst.val)) )
            goto done;
        break;

    case 0xce: /* into */
        if ( !(_regs.eflags & X86_EFLAGS_OF) )
            break;
        /* Fallthrough */
    case 0xcc: /* int3 */
    case 0xcd: /* int imm8 */
    case 0xf1: /* int1 (icebp) */
        ASSERT(!ctxt->event_pending);
        switch ( ctxt->opcode )
        {
        case 0xcc: /* int3 */
            ctxt->event.vector = EXC_BP;
            ctxt->event.type = X86_EVENTTYPE_SW_EXCEPTION;
            break;
        case 0xcd: /* int imm8 */
            ctxt->event.vector = imm1;
            ctxt->event.type = X86_EVENTTYPE_SW_INTERRUPT;
            break;
        case 0xce: /* into */
            ctxt->event.vector = EXC_OF;
            ctxt->event.type = X86_EVENTTYPE_SW_EXCEPTION;
            break;
        case 0xf1: /* icebp */
            ctxt->event.vector = EXC_DB;
            ctxt->event.type = X86_EVENTTYPE_PRI_SW_EXCEPTION;
            break;
        }
        ctxt->event.error_code = X86_EVENT_NO_EC;
        ctxt->event.insn_len = _regs.r(ip) - ctxt->regs->r(ip);
        ctxt->event_pending = true;
        rc = X86EMUL_EXCEPTION;
        goto done;

    case 0xcf: /* iret */ {
        unsigned long sel, eip, eflags;
        uint32_t mask = X86_EFLAGS_VIP | X86_EFLAGS_VIF | X86_EFLAGS_VM;

        fail_if(!in_realmode(ctxt, ops));
        ctxt->retire.unblock_nmi = true;
        if ( (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eip, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &sel, op_bytes, ctxt, ops)) ||
             (rc = read_ulong(x86_seg_ss, sp_post_inc(op_bytes),
                              &eflags, op_bytes, ctxt, ops)) )
            goto done;
        if ( op_bytes == 2 )
            eflags = (uint16_t)eflags | (_regs.eflags & 0xffff0000u);
        eflags &= EFLAGS_MODIFIABLE;
        _regs.eflags &= mask;
        _regs.eflags |= (eflags & ~mask) | X86_EFLAGS_MBS;
        if ( (rc = load_seg(x86_seg_cs, sel, 1, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, (uint32_t)eip)) )
            goto done;
        break;
    }

    case 0xd0 ... 0xd1: /* Grp2 */
        src.val = 1;
        goto grp2;

    case 0xd2 ... 0xd3: /* Grp2 */
        src.val = _regs.cl;
        goto grp2;

    case 0xd4: /* aam */
    case 0xd5: /* aad */
        n = (uint8_t)src.val;
        if ( b & 0x01 )
            _regs.ax = (uint8_t)(_regs.al + (_regs.ah * n));
        else
        {
            generate_exception_if(!n, EXC_DE);
            _regs.al = _regs.al % n;
            _regs.ah = _regs.al / n;
        }
        _regs.eflags &= ~(X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_PF);
        _regs.eflags |= !_regs.al ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= ((int8_t)_regs.al < 0) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= even_parity(_regs.al) ? X86_EFLAGS_PF : 0;
        break;

    case 0xd6: /* salc */
        _regs.al = (_regs.eflags & X86_EFLAGS_CF) ? 0xff : 0x00;
        break;

    case 0xd7: /* xlat */ {
        unsigned long al;

        if ( (rc = read_ulong(ea.mem.seg, truncate_ea(_regs.r(bx) + _regs.al),
                              &al, 1, ctxt, ops)) != 0 )
            goto done;
        _regs.al = al;
        break;
    }

    case 0xd8: /* FPU 0xd8 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %stN,%st */
        case 0xc8 ... 0xcf: /* fmul %stN,%st */
        case 0xd0 ... 0xd7: /* fcom %stN,%st */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st */
        case 0xe0 ... 0xe7: /* fsub %stN,%st */
        case 0xe8 ... 0xef: /* fsubr %stN,%st */
        case 0xf0 ... 0xf7: /* fdiv %stN,%st */
        case 0xf8 ... 0xff: /* fdivr %stN,%st */
            emulate_fpu_insn_stub(0xd8, modrm);
            break;
        default:
        fpu_memsrc32:
            ASSERT(ea.type == OP_MEM);
            if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                 4, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xd9: /* FPU 0xd9 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xfb: /* fsincos */
            fail_if(cpu_has_amd_erratum(573));
            /* fall through */
        case 0xc0 ... 0xc7: /* fld %stN */
        case 0xc8 ... 0xcf: /* fxch %stN */
        case 0xd0: /* fnop */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
        case 0xe0: /* fchs */
        case 0xe1: /* fabs */
        case 0xe4: /* ftst */
        case 0xe5: /* fxam */
        case 0xe8: /* fld1 */
        case 0xe9: /* fldl2t */
        case 0xea: /* fldl2e */
        case 0xeb: /* fldpi */
        case 0xec: /* fldlg2 */
        case 0xed: /* fldln2 */
        case 0xee: /* fldz */
        case 0xf0: /* f2xm1 */
        case 0xf1: /* fyl2x */
        case 0xf2: /* fptan */
        case 0xf3: /* fpatan */
        case 0xf4: /* fxtract */
        case 0xf5: /* fprem1 */
        case 0xf6: /* fdecstp */
        case 0xf7: /* fincstp */
        case 0xf8: /* fprem */
        case 0xf9: /* fyl2xp1 */
        case 0xfa: /* fsqrt */
        case 0xfc: /* frndint */
        case 0xfd: /* fscale */
        case 0xfe: /* fsin */
        case 0xff: /* fcos */
            emulate_fpu_insn_stub(0xd9, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m32fp */
                goto fpu_memsrc32;
            case 2: /* fst m32fp */
            case 3: /* fstp m32fp */
            fpu_memdst32:
                dst = ea;
                dst.bytes = 4;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            case 4: /* fldenv - TODO */
                state->fpu_ctrl = true;
                goto unimplemented_insn;
            case 5: /* fldcw m2byte */
                state->fpu_ctrl = true;
            fpu_memsrc16:
                if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                     2, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
                break;
            case 6: /* fnstenv - TODO */
                state->fpu_ctrl = true;
                goto unimplemented_insn;
            case 7: /* fnstcw m2byte */
                state->fpu_ctrl = true;
            fpu_memdst16:
                dst = ea;
                dst.bytes = 2;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            default:
                generate_exception(EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst.type == OP_MEM && !state->fpu_ctrl && !fpu_check_write() )
                dst.type = OP_NONE;
        }
        break;

    case 0xda: /* FPU 0xda */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovb %stN */
        case 0xc8 ... 0xcf: /* fcmove %stN */
        case 0xd0 ... 0xd7: /* fcmovbe %stN */
        case 0xd8 ... 0xdf: /* fcmovu %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xda, modrm);
            break;
        case 0xe9:          /* fucompp */
            emulate_fpu_insn_stub(0xda, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            goto fpu_memsrc32;
        }
        break;

    case 0xdb: /* FPU 0xdb */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovnb %stN */
        case 0xc8 ... 0xcf: /* fcmovne %stN */
        case 0xd0 ... 0xd7: /* fcmovnbe %stN */
        case 0xd8 ... 0xdf: /* fcmovnu %stN */
        case 0xe8 ... 0xef: /* fucomi %stN */
        case 0xf0 ... 0xf7: /* fcomi %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdb, modrm);
            break;
        case 0xe0: /* fneni - 8087 only, ignored by 287 */
        case 0xe1: /* fndisi - 8087 only, ignored by 287 */
        case 0xe2: /* fnclex */
        case 0xe3: /* fninit */
        case 0xe4: /* fnsetpm - 287 only, ignored by 387 */
        /* case 0xe5: frstpm - 287 only, #UD on 387 */
            state->fpu_ctrl = true;
            emulate_fpu_insn_stub(0xdb, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m32i */
                goto fpu_memsrc32;
            case 1: /* fisttp m32i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m32i */
            case 3: /* fistp m32i */
                goto fpu_memdst32;
            case 5: /* fld m80fp */
            fpu_memsrc80:
                if ( (rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp,
                                     10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, modrm_reg & 7, *mmvalp);
                break;
            case 7: /* fstp m80fp */
            fpu_memdst80:
                fail_if(!ops->write);
                emulate_fpu_insn_memdst(b, modrm_reg & 7, *mmvalp);
                if ( fpu_check_write() &&
                     (rc = ops->write(ea.mem.seg, ea.mem.off, mmvalp,
                                      10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                break;
            default:
                generate_exception(EXC_UD);
            }
        }
        break;

    case 0xdc: /* FPU 0xdc */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %st,%stN */
        case 0xc8 ... 0xcf: /* fmul %st,%stN */
        case 0xd0 ... 0xd7: /* fcom %stN,%st (alternative encoding) */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st (alternative encoding) */
        case 0xe0 ... 0xe7: /* fsubr %st,%stN */
        case 0xe8 ... 0xef: /* fsub %st,%stN */
        case 0xf0 ... 0xf7: /* fdivr %st,%stN */
        case 0xf8 ... 0xff: /* fdiv %st,%stN */
            emulate_fpu_insn_stub(0xdc, modrm);
            break;
        default:
        fpu_memsrc64:
            ASSERT(ea.type == OP_MEM);
            if ( (rc = ops->read(ea.mem.seg, ea.mem.off, &src.val,
                                 8, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xdd: /* FPU 0xdd */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* ffree %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fst %stN */
        case 0xd8 ... 0xdf: /* fstp %stN */
        case 0xe0 ... 0xe7: /* fucom %stN */
        case 0xe8 ... 0xef: /* fucomp %stN */
            emulate_fpu_insn_stub(0xdd, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fld m64fp */;
                goto fpu_memsrc64;
            case 1: /* fisttp m64i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fst m64fp */
            case 3: /* fstp m64fp */
            fpu_memdst64:
                dst = ea;
                dst.bytes = 8;
                emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
                break;
            case 4: /* frstor - TODO */
            case 6: /* fnsave - TODO */
                state->fpu_ctrl = true;
                goto unimplemented_insn;
            case 7: /* fnstsw m2byte */
                state->fpu_ctrl = true;
                goto fpu_memdst16;
            default:
                generate_exception(EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst.type == OP_MEM && !state->fpu_ctrl && !fpu_check_write() )
                dst.type = OP_NONE;
        }
        break;

    case 0xde: /* FPU 0xde */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xc0 ... 0xc7: /* faddp %stN */
        case 0xc8 ... 0xcf: /* fmulp %stN */
        case 0xd0 ... 0xd7: /* fcomp %stN (alternative encoding) */
        case 0xd9: /* fcompp */
        case 0xe0 ... 0xe7: /* fsubrp %stN */
        case 0xe8 ... 0xef: /* fsubp %stN */
        case 0xf0 ... 0xf7: /* fdivrp %stN */
        case 0xf8 ... 0xff: /* fdivp %stN */
            emulate_fpu_insn_stub(0xde, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            emulate_fpu_insn_memsrc(b, modrm_reg & 7, src.val);
            break;
        }
        break;

    case 0xdf: /* FPU 0xdf */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( modrm )
        {
        case 0xe0:
            /* fnstsw %ax */
            state->fpu_ctrl = true;
            dst.bytes = 2;
            dst.type = OP_REG;
            dst.reg = (void *)&_regs.ax;
            emulate_fpu_insn_memdst(b, modrm_reg & 7, dst.val);
            break;
        case 0xe8 ... 0xef: /* fucomip %stN */
        case 0xf0 ... 0xf7: /* fcomip %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdf, modrm);
            break;
        case 0xc0 ... 0xc7: /* ffreep %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fstp %stN (alternative encoding) */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
            emulate_fpu_insn_stub(0xdf, modrm);
            break;
        default:
            generate_exception_if(ea.type != OP_MEM, EXC_UD);
            switch ( modrm_reg & 7 )
            {
            case 0: /* fild m16i */
                goto fpu_memsrc16;
            case 1: /* fisttp m16i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m16i */
            case 3: /* fistp m16i */
                goto fpu_memdst16;
            case 4: /* fbld m80dec */
                goto fpu_memsrc80;
            case 5: /* fild m64i */
                dst.type = OP_NONE;
                goto fpu_memsrc64;
            case 6: /* fbstp packed bcd */
                goto fpu_memdst80;
            case 7: /* fistp m64i */
                goto fpu_memdst64;
            }
        }
        break;

    case 0xe0 ... 0xe2: /* loop{,z,nz} */ {
        unsigned long count = get_loop_count(&_regs, ad_bytes);
        int do_jmp = !(_regs.eflags & X86_EFLAGS_ZF); /* loopnz */

        if ( b == 0xe1 )
            do_jmp = !do_jmp; /* loopz */
        else if ( b == 0xe2 )
            do_jmp = 1; /* loop */
        if ( count != 1 && do_jmp )
            jmp_rel((int32_t)src.val);
        put_loop_count(&_regs, ad_bytes, count - 1);
        break;
    }

    case 0xe3: /* jcxz/jecxz (short) */
        if ( !get_loop_count(&_regs, ad_bytes) )
            jmp_rel((int32_t)src.val);
        break;

    case 0xe4: /* in imm8,%al */
    case 0xe5: /* in imm8,%eax */
    case 0xe6: /* out %al,imm8 */
    case 0xe7: /* out %eax,imm8 */
    case 0xec: /* in %dx,%al */
    case 0xed: /* in %dx,%eax */
    case 0xee: /* out %al,%dx */
    case 0xef: /* out %eax,%dx */ {
        unsigned int port = ((b < 0xe8) ? (uint8_t)src.val : _regs.dx);

        op_bytes = !(b & 1) ? 1 : (op_bytes == 8) ? 4 : op_bytes;
        if ( (rc = ioport_access_check(port, op_bytes, ctxt, ops)) != 0 )
            goto done;
        if ( b & 2 )
        {
            /* out */
            fail_if(ops->write_io == NULL);
            rc = ops->write_io(port, op_bytes, _regs.eax, ctxt);
        }
        else
        {
            /* in */
            dst.bytes = op_bytes;
            fail_if(ops->read_io == NULL);
            rc = ops->read_io(port, dst.bytes, &dst.val, ctxt);
        }
        if ( rc != 0 )
        {
            if ( rc == X86EMUL_DONE )
                goto complete_insn;
            goto done;
        }
        break;
    }

    case 0xe8: /* call (near) */ {
        int32_t rel = src.val;

        op_bytes = ((op_bytes == 4) && mode_64bit()) ? 8 : op_bytes;
        src.val = _regs.r(ip);
        jmp_rel(rel);
        adjust_bnd(ctxt, ops, vex.pfx);
        goto push;
    }

    case 0xe9: /* jmp (near) */
    case 0xeb: /* jmp (short) */
        jmp_rel((int32_t)src.val);
        if ( !(b & 2) )
            adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case 0xea: /* jmp (far, absolute) */
        ASSERT(!mode_64bit());
    far_jmp:
        if ( (rc = load_seg(x86_seg_cs, imm2, 0, &cs, ctxt, ops)) ||
             (rc = commit_far_branch(&cs, imm1)) )
            goto done;
        break;

    case 0xf4: /* hlt */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        ctxt->retire.hlt = true;
        break;

    case 0xf5: /* cmc */
        _regs.eflags ^= X86_EFLAGS_CF;
        break;

    case 0xf6 ... 0xf7: /* Grp3 */
        if ( (d & DstMask) == DstEax )
            dst.reg = (unsigned long *)&_regs.r(ax);
        switch ( modrm_reg & 7 )
        {
            unsigned long u[2], v;

        case 0 ... 1: /* test */
            generate_exception_if(lock_prefix, EXC_UD);
            if ( ops->rmw && dst.type == OP_MEM &&
                 (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                                  dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
                goto done;
            goto test;
        case 2: /* not */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_not;
            else
                dst.val = ~dst.val;
            break;
        case 3: /* neg */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_neg;
            else
                emulate_1op("neg", dst, _regs.eflags);
            break;
        case 4: /* mul */
            _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = _regs.al;
                dst.val *= src.val;
                if ( (uint8_t)dst.val != (uint16_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                dst.bytes = 2;
                break;
            case 2:
                dst.val = _regs.ax;
                dst.val *= src.val;
                if ( (uint16_t)dst.val != (uint32_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.dx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = _regs.eax;
                dst.val *= src.val;
                if ( (uint32_t)dst.val != dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.rdx = dst.val >> 32;
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = _regs.r(ax);
                if ( mul_dbl(u) )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                _regs.r(dx) = u[1];
                dst.val = u[0];
                break;
            }
            break;
        case 5: /* imul */
        imul:
            _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_CF);
            switch ( dst.bytes )
            {
            case 1:
                dst.val = (int8_t)src.val * (int8_t)_regs.al;
                if ( (int8_t)dst.val != (int16_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                ASSERT(b > 0x6b);
                dst.bytes = 2;
                break;
            case 2:
                dst.val = ((uint32_t)(int16_t)src.val *
                           (uint32_t)(int16_t)_regs.ax);
                if ( (int16_t)dst.val != (int32_t)dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.dx = dst.val >> 16;
                break;
#ifdef __x86_64__
            case 4:
                dst.val = ((uint64_t)(int32_t)src.val *
                           (uint64_t)(int32_t)_regs.eax);
                if ( (int32_t)dst.val != dst.val )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.rdx = dst.val >> 32;
                break;
#endif
            default:
                u[0] = src.val;
                u[1] = _regs.r(ax);
                if ( imul_dbl(u) )
                    _regs.eflags |= X86_EFLAGS_OF | X86_EFLAGS_CF;
                if ( b > 0x6b )
                    _regs.r(dx) = u[1];
                dst.val = u[0];
                break;
            }
            break;
        case 6: /* div */
            switch ( src.bytes )
            {
            case 1:
                u[0] = _regs.ax;
                u[1] = 0;
                v    = (uint8_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint8_t)u[0] != (uint16_t)u[0]),
                    EXC_DE);
                dst.val = (uint8_t)u[0];
                _regs.ah = u[1];
                break;
            case 2:
                u[0] = (_regs.edx << 16) | _regs.ax;
                u[1] = 0;
                v    = (uint16_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint16_t)u[0] != (uint32_t)u[0]),
                    EXC_DE);
                dst.val = (uint16_t)u[0];
                _regs.dx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.rdx << 32) | _regs.eax;
                u[1] = 0;
                v    = (uint32_t)src.val;
                generate_exception_if(
                    div_dbl(u, v) || ((uint32_t)u[0] != u[0]),
                    EXC_DE);
                dst.val   = (uint32_t)u[0];
                _regs.rdx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.r(ax);
                u[1] = _regs.r(dx);
                v    = src.val;
                generate_exception_if(div_dbl(u, v), EXC_DE);
                dst.val     = u[0];
                _regs.r(dx) = u[1];
                break;
            }
            break;
        case 7: /* idiv */
            switch ( src.bytes )
            {
            case 1:
                u[0] = (int16_t)_regs.ax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int8_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int8_t)u[0] != (int16_t)u[0]),
                    EXC_DE);
                dst.val = (int8_t)u[0];
                _regs.ah = u[1];
                break;
            case 2:
                u[0] = (int32_t)((_regs.edx << 16) | _regs.ax);
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int16_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int16_t)u[0] != (int32_t)u[0]),
                    EXC_DE);
                dst.val = (int16_t)u[0];
                _regs.dx = u[1];
                break;
#ifdef __x86_64__
            case 4:
                u[0] = (_regs.rdx << 32) | _regs.eax;
                u[1] = ((long)u[0] < 0) ? ~0UL : 0UL;
                v    = (int32_t)src.val;
                generate_exception_if(
                    idiv_dbl(u, v) || ((int32_t)u[0] != u[0]),
                    EXC_DE);
                dst.val   = (int32_t)u[0];
                _regs.rdx = (uint32_t)u[1];
                break;
#endif
            default:
                u[0] = _regs.r(ax);
                u[1] = _regs.r(dx);
                v    = src.val;
                generate_exception_if(idiv_dbl(u, v), EXC_DE);
                dst.val     = u[0];
                _regs.r(dx) = u[1];
                break;
            }
            break;
        }
        break;

    case 0xf8: /* clc */
        _regs.eflags &= ~X86_EFLAGS_CF;
        break;

    case 0xf9: /* stc */
        _regs.eflags |= X86_EFLAGS_CF;
        break;

    case 0xfa: /* cli */
        if ( mode_iopl() )
            _regs.eflags &= ~X86_EFLAGS_IF;
        else
        {
            generate_exception_if(!mode_vif(), EXC_GP, 0);
            _regs.eflags &= ~X86_EFLAGS_VIF;
        }
        break;

    case 0xfb: /* sti */
        if ( mode_iopl() )
        {
            if ( !(_regs.eflags & X86_EFLAGS_IF) )
                ctxt->retire.sti = true;
            _regs.eflags |= X86_EFLAGS_IF;
        }
        else
        {
            generate_exception_if((_regs.eflags & X86_EFLAGS_VIP) ||
				  !mode_vif(),
                                  EXC_GP, 0);
            if ( !(_regs.eflags & X86_EFLAGS_VIF) )
                ctxt->retire.sti = true;
            _regs.eflags |= X86_EFLAGS_VIF;
        }
        break;

    case 0xfc: /* cld */
        _regs.eflags &= ~X86_EFLAGS_DF;
        break;

    case 0xfd: /* std */
        _regs.eflags |= X86_EFLAGS_DF;
        break;

    case 0xfe: /* Grp4 */
        generate_exception_if((modrm_reg & 7) >= 2, EXC_UD);
        /* Fallthrough. */
    case 0xff: /* Grp5 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* inc */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_inc;
            else
                emulate_1op("inc", dst, _regs.eflags);
            break;
        case 1: /* dec */
            if ( ops->rmw && dst.type == OP_MEM )
                state->rmw = rmw_dec;
            else
                emulate_1op("dec", dst, _regs.eflags);
            break;
        case 2: /* call (near) */
            dst.val = _regs.r(ip);
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.r(ip) = src.val;
            src.val = dst.val;
            adjust_bnd(ctxt, ops, vex.pfx);
            goto push;
        case 4: /* jmp (near) */
            if ( (rc = ops->insn_fetch(x86_seg_cs, src.val, NULL, 0, ctxt)) )
                goto done;
            _regs.r(ip) = src.val;
            dst.type = OP_NONE;
            adjust_bnd(ctxt, ops, vex.pfx);
            break;
        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            generate_exception_if(src.type != OP_MEM, EXC_UD);

            if ( (rc = read_ulong(src.mem.seg,
                                  truncate_ea(src.mem.off + op_bytes),
                                  &imm2, 2, ctxt, ops)) )
                goto done;
            imm1 = src.val;
            if ( !(modrm_reg & 4) )
                goto far_call;
            goto far_jmp;
        case 6: /* push */
            goto push;
        case 7:
            generate_exception(EXC_UD);
        }
        break;

    case X86EMUL_OPC(0x0f, 0x00): /* Grp6 */
        seg = (modrm_reg & 1) ? x86_seg_tr : x86_seg_ldtr;
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        switch ( modrm_reg & 6 )
        {
        case 0: /* sldt / str */
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            goto store_selector;
        case 2: /* lldt / ltr */
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            if ( (rc = load_seg(seg, src.val, 0, NULL, ctxt, ops)) != 0 )
                goto done;
            break;
        case 4: /* verr / verw */
            _regs.eflags &= ~X86_EFLAGS_ZF;
            switch ( rc = protmode_load_seg(x86_seg_none, src.val, false,
                                            &sreg, ctxt, ops) )
            {
            case X86EMUL_OKAY:
                if ( sreg.s &&
                     ((modrm_reg & 1) ? ((sreg.type & 0xa) == 0x2)
                                      : ((sreg.type & 0xa) != 0x8)) )
                    _regs.eflags |= X86_EFLAGS_ZF;
                break;
            case X86EMUL_EXCEPTION:
                if ( ctxt->event_pending )
                {
                    ASSERT(ctxt->event.vector == EXC_PF);
            default:
                    goto done;
                }
                /* Instead of the exception, ZF remains cleared. */
                rc = X86EMUL_OKAY;
                break;
            }
            break;
        default:
            generate_exception_if(true, EXC_UD);
            break;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01): /* Grp7 */
    {
        unsigned long base, limit, cr0, cr0w;

        seg = (modrm_reg & 1) ? x86_seg_idtr : x86_seg_gdtr;

        switch( modrm )
        {
        case 0xca: /* clac */
        case 0xcb: /* stac */
            vcpu_must_have(smap);
            generate_exception_if(vex.pfx || !mode_ring0(), EXC_UD);

            _regs.eflags &= ~X86_EFLAGS_AC;
            if ( modrm == 0xcb )
                _regs.eflags |= X86_EFLAGS_AC;
            break;

        case 0xd0: /* xgetbv */
            generate_exception_if(vex.pfx, EXC_UD);
            if ( !ops->read_cr || !ops->read_xcr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), EXC_UD);
            rc = ops->read_xcr(_regs.ecx, &msr_val, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
            _regs.r(ax) = (uint32_t)msr_val;
            _regs.r(dx) = msr_val >> 32;
            break;

        case 0xd1: /* xsetbv */
            generate_exception_if(vex.pfx, EXC_UD);
            if ( !ops->read_cr || !ops->write_xcr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            rc = ops->write_xcr(_regs.ecx,
                                _regs.eax | ((uint64_t)_regs.edx << 32), ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
            break;

        case 0xd4: /* vmfunc */
            generate_exception_if(vex.pfx, EXC_UD);
            fail_if(!ops->vmfunc);
            if ( (rc = ops->vmfunc(ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

        case 0xd5: /* xend */
            generate_exception_if(vex.pfx, EXC_UD);
            generate_exception_if(!vcpu_has_rtm(), EXC_UD);
            generate_exception_if(vcpu_has_rtm(), EXC_GP, 0);
            break;

        case 0xd6: /* xtest */
            generate_exception_if(vex.pfx, EXC_UD);
            generate_exception_if(!vcpu_has_rtm() && !vcpu_has_hle(),
                                  EXC_UD);
            /* Neither HLE nor RTM can be active when we get here. */
            _regs.eflags |= X86_EFLAGS_ZF;
            break;

        case 0xdf: /* invlpga */
            fail_if(!ops->read_msr);
            if ( (rc = ops->read_msr(MSR_EFER,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            /* Finding SVME set implies vcpu_has_svm(). */
            generate_exception_if(!(msr_val & EFER_SVME) ||
                                  !in_protmode(ctxt, ops), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            generate_exception_if(_regs.ecx, EXC_UD); /* TODO: Support ASIDs. */
            fail_if(ops->invlpg == NULL);
            if ( (rc = ops->invlpg(x86_seg_none, truncate_ea(_regs.r(ax)),
                                   ctxt)) )
                goto done;
            break;

        case 0xf8: /* swapgs */
            generate_exception_if(!mode_64bit(), EXC_UD);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(!ops->read_segment || !ops->read_msr ||
                    !ops->write_segment || !ops->write_msr);
            if ( (rc = ops->read_segment(x86_seg_gs, &sreg,
                                         ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->read_msr(MSR_SHADOW_GS_BASE, &msr_val,
                                     ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->write_msr(MSR_SHADOW_GS_BASE, sreg.base,
                                      ctxt)) != X86EMUL_OKAY )
                goto done;
            sreg.base = msr_val;
            if ( (rc = ops->write_segment(x86_seg_gs, &sreg,
                                          ctxt)) != X86EMUL_OKAY )
            {
                /* Best effort unwind (i.e. no error checking). */
                ops->write_msr(MSR_SHADOW_GS_BASE, msr_val, ctxt);
                goto done;
            }
            break;

        case 0xf9: /* rdtscp */
            fail_if(ops->read_msr == NULL);
            if ( (rc = ops->read_msr(MSR_TSC_AUX,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.r(cx) = (uint32_t)msr_val;
            goto rdtsc;

        case 0xfc: /* clzero */
        {
            unsigned long zero = 0;

            vcpu_must_have(clzero);

            base = ad_bytes == 8 ? _regs.r(ax) :
                   ad_bytes == 4 ? _regs.eax : _regs.ax;
            limit = 0;
            if ( vcpu_has_clflush() &&
                 ops->cpuid(1, 0, &cpuid_leaf, ctxt) == X86EMUL_OKAY )
                limit = ((cpuid_leaf.b >> 8) & 0xff) * 8;
            generate_exception_if(limit < sizeof(long) ||
                                  (limit & (limit - 1)), EXC_UD);
            base &= ~(limit - 1);
            if ( ops->rep_stos )
            {
                unsigned long nr_reps = limit / sizeof(zero);

                rc = ops->rep_stos(&zero, ea.mem.seg, base, sizeof(zero),
                                   &nr_reps, ctxt);
                if ( rc == X86EMUL_OKAY )
                {
                    base += nr_reps * sizeof(zero);
                    limit -= nr_reps * sizeof(zero);
                }
                else if ( rc != X86EMUL_UNHANDLEABLE )
                    goto done;
            }
            fail_if(limit && !ops->write);
            while ( limit )
            {
                rc = ops->write(ea.mem.seg, base, &zero, sizeof(zero), ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
                base += sizeof(zero);
                limit -= sizeof(zero);
            }
            break;
        }

#define _GRP7(mod, reg) \
            (((mod) << 6) | ((reg) << 3)) ... (((mod) << 6) | ((reg) << 3) | 7)
#define GRP7_MEM(reg) _GRP7(0, reg): case _GRP7(1, reg): case _GRP7(2, reg)
#define GRP7_ALL(reg) GRP7_MEM(reg): case _GRP7(3, reg)

        case GRP7_MEM(0): /* sgdt */
        case GRP7_MEM(1): /* sidt */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            fail_if(!ops->read_segment || !ops->write);
            if ( (rc = ops->read_segment(seg, &sreg, ctxt)) )
                goto done;
            if ( mode_64bit() )
                op_bytes = 8;
            else if ( op_bytes == 2 )
            {
                sreg.base &= 0xffffff;
                op_bytes = 4;
            }
            if ( (rc = ops->write(ea.mem.seg, ea.mem.off, &sreg.limit,
                                  2, ctxt)) != X86EMUL_OKAY ||
                 (rc = ops->write(ea.mem.seg, truncate_ea(ea.mem.off + 2),
                                  &sreg.base, op_bytes, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;

        case GRP7_MEM(2): /* lgdt */
        case GRP7_MEM(3): /* lidt */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(ops->write_segment == NULL);
            memset(&sreg, 0, sizeof(sreg));
            if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                  &limit, 2, ctxt, ops)) ||
                 (rc = read_ulong(ea.mem.seg, truncate_ea(ea.mem.off + 2),
                                  &base, mode_64bit() ? 8 : 4, ctxt, ops)) )
                goto done;
            generate_exception_if(!is_canonical_address(base), EXC_GP, 0);
            sreg.base = base;
            sreg.limit = limit;
            if ( !mode_64bit() && op_bytes == 2 )
                sreg.base &= 0xffffff;
            if ( (rc = ops->write_segment(seg, &sreg, ctxt)) )
                goto done;
            break;

        case GRP7_ALL(4): /* smsw */
            generate_exception_if(umip_active(ctxt, ops), EXC_GP, 0);
            if ( ea.type == OP_MEM )
            {
                fail_if(!ops->write);
                d |= Mov; /* force writeback */
                ea.bytes = 2;
            }
            else
                ea.bytes = op_bytes;
            dst = ea;
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(0, &dst.val, ctxt)) )
                goto done;
            break;

        case GRP7_ALL(6): /* lmsw */
            fail_if(ops->read_cr == NULL);
            fail_if(ops->write_cr == NULL);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            if ( (rc = ops->read_cr(0, &cr0, ctxt)) )
                goto done;
            if ( ea.type == OP_REG )
                cr0w = *ea.reg;
            else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off,
                                       &cr0w, 2, ctxt, ops)) )
                goto done;
            /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
            cr0 = (cr0 & ~0xe) | (cr0w & 0xf);
            if ( (rc = ops->write_cr(0, cr0, ctxt)) )
                goto done;
            break;

        case GRP7_MEM(7): /* invlpg */
            ASSERT(ea.type == OP_MEM);
            generate_exception_if(!mode_ring0(), EXC_GP, 0);
            fail_if(ops->invlpg == NULL);
            if ( (rc = ops->invlpg(ea.mem.seg, ea.mem.off, ctxt)) )
                goto done;
            break;

#undef GRP7_ALL
#undef GRP7_MEM
#undef _GRP7

        default:
            goto unimplemented_insn;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0x02): /* lar */
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        _regs.eflags &= ~X86_EFLAGS_ZF;
        switch ( rc = protmode_load_seg(x86_seg_none, src.val, false, &sreg,
                                        ctxt, ops) )
        {
        case X86EMUL_OKAY:
            if ( !sreg.s )
            {
                switch ( sreg.type )
                {
                case 0x01: /* available 16-bit TSS */
                case 0x03: /* busy 16-bit TSS */
                case 0x04: /* 16-bit call gate */
                case 0x05: /* 16/32-bit task gate */
                    if ( ctxt->lma )
                        break;
                    /* fall through */
                case 0x02: /* LDT */
                case 0x09: /* available 32/64-bit TSS */
                case 0x0b: /* busy 32/64-bit TSS */
                case 0x0c: /* 32/64-bit call gate */
                    _regs.eflags |= X86_EFLAGS_ZF;
                    break;
                }
            }
            else
                _regs.eflags |= X86_EFLAGS_ZF;
            break;
        case X86EMUL_EXCEPTION:
            if ( ctxt->event_pending )
            {
                ASSERT(ctxt->event.vector == EXC_PF);
        default:
                goto done;
            }
            /* Instead of the exception, ZF remains cleared. */
            rc = X86EMUL_OKAY;
            break;
        }
        if ( _regs.eflags & X86_EFLAGS_ZF )
            dst.val = ((sreg.attr & 0xff) << 8) |
                      ((sreg.limit >> (sreg.g ? 12 : 0)) & 0xf0000) |
                      ((sreg.attr & 0xf00) << 12);
        else
            dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0x03): /* lsl */
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);
        _regs.eflags &= ~X86_EFLAGS_ZF;
        switch ( rc = protmode_load_seg(x86_seg_none, src.val, false, &sreg,
                                        ctxt, ops) )
        {
        case X86EMUL_OKAY:
            if ( !sreg.s )
            {
                switch ( sreg.type )
                {
                case 0x01: /* available 16-bit TSS */
                case 0x03: /* busy 16-bit TSS */
                    if ( ctxt->lma )
                        break;
                    /* fall through */
                case 0x02: /* LDT */
                case 0x09: /* available 32/64-bit TSS */
                case 0x0b: /* busy 32/64-bit TSS */
                    _regs.eflags |= X86_EFLAGS_ZF;
                    break;
                }
            }
            else
                _regs.eflags |= X86_EFLAGS_ZF;
            break;
        case X86EMUL_EXCEPTION:
            if ( ctxt->event_pending )
            {
                ASSERT(ctxt->event.vector == EXC_PF);
        default:
                goto done;
            }
            /* Instead of the exception, ZF remains cleared. */
            rc = X86EMUL_OKAY;
            break;
        }
        if ( _regs.eflags & X86_EFLAGS_ZF )
            dst.val = sreg.limit;
        else
            dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0x05): /* syscall */
        generate_exception_if(!in_protmode(ctxt, ops), EXC_UD);

        /* Inject #UD if syscall/sysret are disabled. */
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_EFER, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if((msr_val & EFER_SCE) == 0, EXC_UD);

        if ( (rc = ops->read_msr(MSR_STAR, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        cs.sel = (msr_val >> 32) & ~3; /* SELECTOR_RPL_MASK */
        sreg.sel = cs.sel + 8;

        cs.base = sreg.base = 0; /* flat segment */
        cs.limit = sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xc93; /* G+DB+P+S+Data */

#ifdef __x86_64__
        if ( ctxt->lma )
        {
            cs.attr = 0xa9b; /* L+DB+P+S+Code */

            _regs.rcx = _regs.rip;
            _regs.r11 = _regs.eflags & ~X86_EFLAGS_RF;

            if ( (rc = ops->read_msr(mode_64bit() ? MSR_LSTAR : MSR_CSTAR,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.rip = msr_val;

            if ( (rc = ops->read_msr(MSR_SYSCALL_MASK,
                                     &msr_val, ctxt)) != X86EMUL_OKAY )
                goto done;
            _regs.eflags &= ~(msr_val | X86_EFLAGS_RF);
        }
        else
#endif
        {
            cs.attr = 0xc9b; /* G+DB+P+S+Code */

            _regs.r(cx) = _regs.eip;
            _regs.eip = msr_val;
            _regs.eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF | X86_EFLAGS_RF);
        }

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) )
            goto done;

        /*
         * SYSCALL (unlike most instructions) evaluates its singlestep action
         * based on the resulting EFLAGS.TF, not the starting EFLAGS.TF.
         *
         * As the #DB is raised after the CPL change and before the OS can
         * switch stack, it is a large risk for privilege escalation.
         *
         * 64bit kernels should mask EFLAGS.TF in MSR_SYSCALL_MASK to avoid any
         * vulnerability.  Running the #DB handler on an IST stack is also a
         * mitigation.
         *
         * 32bit kernels have no ability to mask EFLAGS.TF at all.
         * Their only mitigation is to use a task gate for handling
         * #DB (or to not use enable EFER.SCE to start with).
         */
        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x06): /* clts */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if((ops->read_cr == NULL) || (ops->write_cr == NULL));
        if ( (rc = ops->read_cr(0, &dst.val, ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write_cr(0, dst.val & ~X86_CR0_TS, ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x08): /* invd */
    case X86EMUL_OPC(0x0f, 0x09): /* wbinvd */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->wbinvd == NULL);
        if ( (rc = ops->wbinvd(ctxt)) != 0 )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x0b): /* ud2 */
    case X86EMUL_OPC(0x0f, 0xb9): /* ud1 */
    case X86EMUL_OPC(0x0f, 0xff): /* ud0 */
        generate_exception(EXC_UD);

    case X86EMUL_OPC(0x0f, 0x0d): /* GrpP (prefetch) */
    case X86EMUL_OPC(0x0f, 0x18): /* Grp16 (prefetch/nop) */
    case X86EMUL_OPC(0x0f, 0x19) ... X86EMUL_OPC(0x0f, 0x1f): /* nop */
        break;

    case X86EMUL_OPC(0x0f, 0x0e): /* femms */
        host_and_vcpu_must_have(3dnow);
        asm volatile ( "femms" );
        break;

    case X86EMUL_OPC(0x0f, 0x0f): /* 3DNow! */
        if ( _3dnow_table[(imm1 >> 4) & 0xf] & (1 << (imm1 & 0xf)) )
            host_and_vcpu_must_have(3dnow);
        else if ( _3dnow_ext_table[(imm1 >> 4) & 0xf] & (1 << (imm1 & 0xf)) )
            host_and_vcpu_must_have(3dnow_ext);
        else
            generate_exception(EXC_UD);

        get_fpu(X86EMUL_FPU_mmx);

        d = DstReg | SrcMem;
        op_bytes = 8;
        state->simd_size = simd_other;
        goto simd_0f_imm8;

#define CASE_SIMD_PACKED_INT(pfx, opc)       \
    case X86EMUL_OPC(pfx, opc):              \
    case X86EMUL_OPC_66(pfx, opc)
#define CASE_SIMD_SINGLE_FP(kind, pfx, opc)  \
    case X86EMUL_OPC##kind(pfx, opc):        \
    case X86EMUL_OPC##kind##_F3(pfx, opc)
#define CASE_SIMD_DOUBLE_FP(kind, pfx, opc)  \
    case X86EMUL_OPC##kind##_66(pfx, opc):   \
    case X86EMUL_OPC##kind##_F2(pfx, opc)
#define CASE_SIMD_ALL_FP(kind, pfx, opc)     \
    CASE_SIMD_SINGLE_FP(kind, pfx, opc):     \
    CASE_SIMD_DOUBLE_FP(kind, pfx, opc)
#define CASE_SIMD_PACKED_FP(kind, pfx, opc)  \
    case X86EMUL_OPC##kind(pfx, opc):        \
    case X86EMUL_OPC##kind##_66(pfx, opc)
#define CASE_SIMD_SCALAR_FP(kind, pfx, opc)  \
    case X86EMUL_OPC##kind##_F3(pfx, opc):   \
    case X86EMUL_OPC##kind##_F2(pfx, opc)

    CASE_SIMD_SCALAR_FP(, 0x0f, 0x2b):     /* movnts{s,d} xmm,mem */
        host_and_vcpu_must_have(sse4a);
        /* fall through */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2b):     /* movntp{s,d} xmm,m128 */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x2b): /* vmovntp{s,d} {x,y}mm,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    CASE_SIMD_ALL_FP(, 0x0f, 0x10):        /* mov{up,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x10): /* vmovup{s,d} {x,y}mm/mem,{x,y}mm */
    CASE_SIMD_SCALAR_FP(_VEX, 0x0f, 0x10): /* vmovs{s,d} mem,xmm */
                                           /* vmovs{s,d} xmm,xmm,xmm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x11):        /* mov{up,s}{s,d} xmm,xmm/mem */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x11): /* vmovup{s,d} {x,y}mm,{x,y}mm/mem */
    CASE_SIMD_SCALAR_FP(_VEX, 0x0f, 0x11): /* vmovs{s,d} xmm,mem */
                                           /* vmovs{s,d} xmm,xmm,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x14):     /* unpcklp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x14): /* vunpcklp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x15):     /* unpckhp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x15): /* vunpckhp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x28):     /* movap{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x28): /* vmovap{s,d} {x,y}mm/mem,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x29):     /* movap{s,d} xmm,xmm/m128 */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x29): /* vmovap{s,d} {x,y}mm,{x,y}mm/mem */
    CASE_SIMD_ALL_FP(, 0x0f, 0x51):        /* sqrt{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x51):    /* vsqrtp{s,d} {x,y}mm/mem,{x,y}mm */
                                           /* vsqrts{s,d} xmm/m32,xmm,xmm */
    CASE_SIMD_SINGLE_FP(, 0x0f, 0x52):     /* rsqrt{p,s}s xmm/mem,xmm */
    CASE_SIMD_SINGLE_FP(_VEX, 0x0f, 0x52): /* vrsqrtps {x,y}mm/mem,{x,y}mm */
                                           /* vrsqrtss xmm/m32,xmm,xmm */
    CASE_SIMD_SINGLE_FP(, 0x0f, 0x53):     /* rcp{p,s}s xmm/mem,xmm */
    CASE_SIMD_SINGLE_FP(_VEX, 0x0f, 0x53): /* vrcpps {x,y}mm/mem,{x,y}mm */
                                           /* vrcpss xmm/m32,xmm,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x54):     /* andp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x54): /* vandp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x55):     /* andnp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x55): /* vandnp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x56):     /* orp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x56): /* vorp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x57):     /* xorp{s,d} xmm/m128,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x57): /* vxorp{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x58):        /* add{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x58):    /* vadd{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x59):        /* mul{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x59):    /* vmul{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x5c):        /* sub{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x5c):    /* vsub{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x5d):        /* min{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x5d):    /* vmin{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x5e):        /* div{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x5e):    /* vdiv{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_ALL_FP(, 0x0f, 0x5f):        /* max{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x5f):    /* vmax{p,s}{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_fp:
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
            {
    simd_0f_sse2:
                vcpu_must_have(sse2);
            }
            else
                vcpu_must_have(sse);
    simd_0f_xmm:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            /* vmovs{s,d} to/from memory have only two operands. */
            if ( (b & ~1) == 0x10 && ea.type == OP_MEM )
                d |= TwoOp;
    simd_0f_avx:
            host_and_vcpu_must_have(avx);
    simd_0f_ymm:
            get_fpu(X86EMUL_FPU_ymm);
        }
    simd_0f_common:
        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* convert memory operand to (%rAX) */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        break;

    case X86EMUL_OPC_66(0x0f, 0x12):       /* movlpd m64,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x12):   /* vmovlpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x13):     /* movlp{s,d} xmm,m64 */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x13): /* vmovlp{s,d} xmm,m64 */
    case X86EMUL_OPC_66(0x0f, 0x16):       /* movhpd m64,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x16):   /* vmovhpd m64,xmm,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x17):     /* movhp{s,d} xmm,m64 */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x17): /* vmovhp{s,d} xmm,m64 */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC(0x0f, 0x12):          /* movlps m64,xmm */
                                           /* movhlps xmm,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x12):      /* vmovlps m64,xmm,xmm */
                                           /* vmovhlps xmm,xmm,xmm */
    case X86EMUL_OPC(0x0f, 0x16):          /* movhps m64,xmm */
                                           /* movlhps xmm,xmm */
    case X86EMUL_OPC_VEX(0x0f, 0x16):      /* vmovhps m64,xmm,xmm */
                                           /* vmovlhps xmm,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        if ( (d & DstMask) != DstMem )
            d &= ~TwoOp;
        op_bytes = 8;
        goto simd_0f_fp;

    case X86EMUL_OPC_F3(0x0f, 0x12):       /* movsldup xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x12):   /* vmovsldup {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0x12):       /* movddup xmm/m64,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x12):   /* vmovddup {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x16):       /* movshdup xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x16):   /* vmovshdup {x,y}mm/mem,{x,y}mm */
        d |= TwoOp;
        op_bytes = !(vex.pfx & VEX_PREFIX_DOUBLE_MASK) || vex.l
                   ? 16 << vex.l : 8;
    simd_0f_sse3_avx:
        if ( vex.opcx != vex_none )
            goto simd_0f_avx;
        host_and_vcpu_must_have(sse3);
        goto simd_0f_xmm;

    case X86EMUL_OPC(0x0f, 0x20): /* mov cr,reg */
    case X86EMUL_OPC(0x0f, 0x21): /* mov dr,reg */
    case X86EMUL_OPC(0x0f, 0x22): /* mov reg,cr */
    case X86EMUL_OPC(0x0f, 0x23): /* mov reg,dr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        if ( b & 2 )
        {
            /* Write to CR/DR. */
            typeof(ops->write_cr) write = (b & 1) ? ops->write_dr
                                                  : ops->write_cr;

            fail_if(!write);
            rc = write(modrm_reg, src.val, ctxt);
        }
        else
        {
            /* Read from CR/DR. */
            typeof(ops->read_cr) read = (b & 1) ? ops->read_dr : ops->read_cr;

            fail_if(!read);
            rc = read(modrm_reg, &dst.val, ctxt);
        }
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;

    case X86EMUL_OPC_66(0x0f, 0x2a):       /* cvtpi2pd mm/m64,xmm */
        if ( ea.type == OP_REG )
        {
    case X86EMUL_OPC(0x0f, 0x2a):          /* cvtpi2ps mm/m64,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2c):     /* cvttp{s,d}2pi xmm/mem,mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2d):     /* cvtp{s,d}2pi xmm/mem,mm */
            host_and_vcpu_must_have(mmx);
        }
        op_bytes = (b & 4) && (vex.pfx & VEX_PREFIX_DOUBLE_MASK) ? 16 : 8;
        goto simd_0f_fp;

    CASE_SIMD_SCALAR_FP(, 0x0f, 0x2a):     /* cvtsi2s{s,d} r/m,xmm */
    CASE_SIMD_SCALAR_FP(_VEX, 0x0f, 0x2a): /* vcvtsi2s{s,d} r/m,xmm,xmm */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        if ( ea.type == OP_MEM )
        {
            rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val,
                            rex_prefix & REX_W ? 8 : 4, ctxt, ops);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        else
            src.val = rex_prefix & REX_W ? *ea.reg : (uint32_t)*ea.reg;

        state->simd_size = simd_none;
        goto simd_0f_rm;

    CASE_SIMD_SCALAR_FP(, 0x0f, 0x2c):     /* cvtts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(_VEX, 0x0f, 0x2c): /* vcvtts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(, 0x0f, 0x2d):     /* cvts{s,d}2si xmm/mem,reg */
    CASE_SIMD_SCALAR_FP(_VEX, 0x0f, 0x2d): /* vcvts{s,d}2si xmm/mem,reg */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            vex.l = 0;
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX and memory operand to (%rCX). */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( ea.type == OP_MEM )
        {
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] = 0x01;

            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp,
                           vex.pfx & VEX_PREFIX_DOUBLE_MASK ? 8 : 4, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        else
            opc[1] = modrm & 0xc7;
        if ( !mode_64bit() )
            vex.w = 0;
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        ea.reg = decode_gpr(&_regs, modrm_reg);
        invoke_stub("", "", "=a" (*ea.reg) : "c" (mmvalp), "m" (*mmvalp));

        put_stub(stub);
        state->simd_size = simd_none;
        break;

    CASE_SIMD_PACKED_FP(, 0x0f, 0x2e):     /* ucomis{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x2e): /* vucomis{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0x2f):     /* comis{s,d} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x2f): /* vcomis{s,d} xmm/mem,xmm */
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx )
                vcpu_must_have(sse2);
            else
                vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, vex.pfx ? 8 : 4,
                           ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;

            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),
                    [eflags] "+g" (_regs.eflags),
                    [tmp] "=&r" (dummy), "+m" (*mmvalp)
                    : "a" (mmvalp), [mask] "i" (EFLAGS_MASK));

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

    case X86EMUL_OPC(0x0f, 0x30): /* wrmsr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->write_msr == NULL);
        if ( (rc = ops->write_msr(_regs.ecx,
                                  ((uint64_t)_regs.r(dx) << 32) | _regs.eax,
                                  ctxt)) != 0 )
            goto done;
        break;

    case X86EMUL_OPC(0x0f, 0x31): rdtsc: /* rdtsc */
        if ( !mode_ring0() )
        {
            fail_if(ops->read_cr == NULL);
            if ( (rc = ops->read_cr(4, &cr4, ctxt)) )
                goto done;
            generate_exception_if(cr4 & X86_CR4_TSD, EXC_GP, 0);
        }
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_TSC,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(dx) = msr_val >> 32;
        _regs.r(ax) = (uint32_t)msr_val;
        break;

    case X86EMUL_OPC(0x0f, 0x32): /* rdmsr */
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(_regs.ecx, &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(dx) = msr_val >> 32;
        _regs.r(ax) = (uint32_t)msr_val;
        break;

    case X86EMUL_OPC(0x0f, 0x34): /* sysenter */
        vcpu_must_have(sep);
        generate_exception_if(mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_CS,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        generate_exception_if(!(msr_val & 0xfffc), EXC_GP, 0);

        _regs.eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF | X86_EFLAGS_RF);

        cs.sel = msr_val & ~3; /* SELECTOR_RPL_MASK */
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr = ctxt->lma ? 0xa9b  /* G+L+P+S+Code */
                            : 0xc9b; /* G+DB+P+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xc93; /* G+DB+P+S+Data */

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != 0 ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) != 0 )
            goto done;

        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_EIP,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(ip) = ctxt->lma ? msr_val : (uint32_t)msr_val;

        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_ESP,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        _regs.r(sp) = ctxt->lma ? msr_val : (uint32_t)msr_val;

        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x35): /* sysexit */
        vcpu_must_have(sep);
        generate_exception_if(!mode_ring0(), EXC_GP, 0);
        generate_exception_if(!in_protmode(ctxt, ops), EXC_GP, 0);

        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_IA32_SYSENTER_CS,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;

        generate_exception_if(!(msr_val & 0xfffc), EXC_GP, 0);
        generate_exception_if(op_bytes == 8 &&
                              (!is_canonical_address(_regs.r(dx)) ||
                               !is_canonical_address(_regs.r(cx))),
                              EXC_GP, 0);

        cs.sel = (msr_val | 3) + /* SELECTOR_RPL_MASK */
                 (op_bytes == 8 ? 32 : 16);
        cs.base = 0;   /* flat segment */
        cs.limit = ~0u;  /* 4GB limit */
        cs.attr = op_bytes == 8 ? 0xafb  /* L+DB+P+DPL3+S+Code */
                                : 0xcfb; /* G+DB+P+DPL3+S+Code */

        sreg.sel = cs.sel + 8;
        sreg.base = 0;   /* flat segment */
        sreg.limit = ~0u;  /* 4GB limit */
        sreg.attr = 0xcf3; /* G+DB+P+DPL3+S+Data */

        fail_if(ops->write_segment == NULL);
        if ( (rc = ops->write_segment(x86_seg_cs, &cs, ctxt)) != 0 ||
             (rc = ops->write_segment(x86_seg_ss, &sreg, ctxt)) != 0 )
            goto done;

        _regs.r(ip) = op_bytes == 8 ? _regs.r(dx) : _regs.edx;
        _regs.r(sp) = op_bytes == 8 ? _regs.r(cx) : _regs.ecx;

        singlestep = _regs.eflags & X86_EFLAGS_TF;
        break;

    case X86EMUL_OPC(0x0f, 0x40) ... X86EMUL_OPC(0x0f, 0x4f): /* cmovcc */
        vcpu_must_have(cmov);
        if ( test_cc(b, _regs.eflags) )
            dst.val = src.val;
        break;

    CASE_SIMD_PACKED_FP(, 0x0f, 0x50):     /* movmskp{s,d} xmm,reg */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x50): /* vmovmskp{s,d} {x,y}mm,reg */
    CASE_SIMD_PACKED_INT(0x0f, 0xd7):      /* pmovmskb {,x}mm,reg */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd7):   /* vpmovmskb {x,y}mm,reg */
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        insn_bytes = PFX_BYTES + 2;
    simd_0f_to_gpr:
        opc[insn_bytes - PFX_BYTES] = 0xc3;

        generate_exception_if(ea.type != OP_REG, EXC_UD);

        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                vcpu_must_have(sse2);
            else
            {
                if ( b != 0x50 )
                {
                    host_and_vcpu_must_have(mmx);
                    vcpu_must_have(mmxext);
                }
                else
                    vcpu_must_have(sse);
            }
            if ( b == 0x50 || (vex.pfx & VEX_PREFIX_DOUBLE_MASK) )
                get_fpu(X86EMUL_FPU_xmm);
            else
                get_fpu(X86EMUL_FPU_mmx);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            if ( b == 0x50 || !vex.l )
                host_and_vcpu_must_have(avx);
            else
                host_and_vcpu_must_have(avx2);
            get_fpu(X86EMUL_FPU_ymm);
        }

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=a" (dst.val) : [dummy] "i" (0));

        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.bytes = 4;
        break;

    CASE_SIMD_ALL_FP(, 0x0f, 0x5a):        /* cvt{p,s}{s,d}2{p,s}{s,d} xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0x5a):    /* vcvtp{s,d}2p{s,d} xmm/mem,xmm */
                                           /* vcvts{s,d}2s{s,d} xmm/mem,xmm,xmm */
        op_bytes = 4 << (((vex.pfx & VEX_PREFIX_SCALAR_MASK) ? 0 : 1 + vex.l) +
                         !!(vex.pfx & VEX_PREFIX_DOUBLE_MASK));
    simd_0f_cvt:
        if ( vex.opcx == vex_none )
            goto simd_0f_sse2;
        goto simd_0f_avx;

    CASE_SIMD_PACKED_FP(, 0x0f, 0x5b):     /* cvt{ps,dq}2{dq,ps} xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0x5b): /* vcvt{ps,dq}2{dq,ps} {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x5b):       /* cvttps2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x5b):   /* vcvttps2dq {x,y}mm/mem,{x,y}mm */
        d |= TwoOp;
        op_bytes = 16 << vex.l;
        goto simd_0f_cvt;

    CASE_SIMD_PACKED_INT(0x0f, 0x60):    /* punpcklbw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x60): /* vpunpcklbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x61):    /* punpcklwd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x61): /* vpunpcklwd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x62):    /* punpckldq {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x62): /* vpunpckldq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x68):    /* punpckhbw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x68): /* vpunpckhbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x69):    /* punpckhwd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x69): /* vpunpckhwd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x6a):    /* punpckhdq {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6a): /* vpunpckhdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
        op_bytes = vex.pfx ? 16 << vex.l : b & 8 ? 8 : 4;
        /* fall through */
    CASE_SIMD_PACKED_INT(0x0f, 0x63):    /* packssbw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x63): /* vpackssbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x64):    /* pcmpgtb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x64): /* vpcmpgtb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x65):    /* pcmpgtw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x65): /* vpcmpgtw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x66):    /* pcmpgtd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x66): /* vpcmpgtd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x67):    /* packusbw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x67): /* vpackusbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x6b):    /* packsswd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6b): /* vpacksswd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x6c):     /* punpcklqdq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6c): /* vpunpcklqdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x6d):     /* punpckhqdq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6d): /* vpunpckhqdq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x74):    /* pcmpeqb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x74): /* vpcmpeqb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x75):    /* pcmpeqw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x75): /* vpcmpeqw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0x76):    /* pcmpeqd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x76): /* vpcmpeqd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xd4):     /* paddq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd4): /* vpaddq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xd5):    /* pmullw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd5): /* vpmullw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xd8):    /* psubusb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd8): /* vpsubusb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xd9):    /* psubusw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd9): /* vpsubusw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xda):     /* pminub xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xda): /* vpminub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xdb):    /* pand {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xdb): /* vpand {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xdc):    /* paddusb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xdc): /* vpaddusb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xdd):    /* paddusw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xdd): /* vpaddusw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xde):     /* pmaxub xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xde): /* vpmaxub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xdf):    /* pandn {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xdf): /* vpandn {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe0):     /* pavgb xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe0): /* vpavgb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe3):     /* pavgw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe3): /* vpavgw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xe4):     /* pmulhuw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe4): /* vpmulhuw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xe5):    /* pmulhw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe5): /* vpmulhw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xe8):    /* psubsb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe8): /* vpsubsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xe9):    /* psubsw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe9): /* vpsubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xea):     /* pminsw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xea): /* vpminsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xeb):    /* por {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xeb): /* vpor {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xec):    /* paddsb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xec): /* vpaddsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xed):    /* paddsw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xed): /* vpaddsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xee):     /* pmaxsw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xee): /* vpmaxsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xef):    /* pxor {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xef): /* vpxor {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xf4):     /* pmuludq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf4): /* vpmuludq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xf6):     /* psadbw xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf6): /* vpsadbw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xf8):    /* psubb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf8): /* vpsubb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xf9):    /* psubw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf9): /* vpsubw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xfa):    /* psubd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfa): /* vpsubd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xfb):     /* psubq xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfb): /* vpsubq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xfc):    /* paddb {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfc): /* vpaddb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xfd):    /* paddw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfd): /* vpaddw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xfe):    /* paddd {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xfe): /* vpaddd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_int:
        if ( vex.opcx != vex_none )
        {
    case X86EMUL_OPC_VEX_66(0x0f38, 0x00): /* vpshufb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x01): /* vphaddw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x02): /* vphaddd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x03): /* vphaddsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x04): /* vpmaddubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x05): /* vphsubw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x06): /* vphsubd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x07): /* vphsubsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x08): /* vpsignb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x09): /* vpsignw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0a): /* vpsignd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0b): /* vpmulhrsw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1c): /* vpabsb {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1d): /* vpabsw {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1e): /* vpabsd {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x28): /* vpmuldq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x29): /* vpcmpeqq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2b): /* vpackusdw {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x37): /* vpcmpgtq {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x38): /* vpminsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x39): /* vpminsd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3a): /* vpminub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3b): /* vpminud {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3c): /* vpmaxsb {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3d): /* vpmaxsd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3e): /* vpmaxub {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x3f): /* vpmaxud {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x40): /* vpmulld {x,y}mm/mem,{x,y}mm,{x,y}mm */
            if ( !vex.l )
                goto simd_0f_avx;
            /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x45): /* vpsrlv{d,q} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x47): /* vpsllv{d,q} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_avx2:
            host_and_vcpu_must_have(avx2);
            goto simd_0f_ymm;
        }
        if ( vex.pfx )
            goto simd_0f_sse2;
    simd_0f_mmx:
        host_and_vcpu_must_have(mmx);
        get_fpu(X86EMUL_FPU_mmx);
        goto simd_0f_common;

    CASE_SIMD_PACKED_INT(0x0f, 0x6e):    /* mov{d,q} r/m,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6e): /* vmov{d,q} r/m,xmm */
    CASE_SIMD_PACKED_INT(0x0f, 0x7e):    /* mov{d,q} {,x}mm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7e): /* vmov{d,q} xmm,r/m */
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

    simd_0f_rm:
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert memory/GPR operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0x38;
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "+m" (src.val) : "a" (&src.val));
        dst.val = src.val;

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

    case X86EMUL_OPC_66(0x0f, 0xe7):     /* movntdq xmm,m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe7): /* vmovntdq {x,y}mm,mem */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0x6f):     /* movdqa xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x6f): /* vmovdqa {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x6f):     /* movdqu xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x6f): /* vmovdqu {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x7f):     /* movdqa xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7f): /* vmovdqa {x,y}mm,{x,y}mm/mem */
    case X86EMUL_OPC_F3(0x0f, 0x7f):     /* movdqu xmm,xmm/m128 */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x7f): /* vmovdqu {x,y}mm,{x,y}mm/mem */
    movdqa:
        d |= TwoOp;
        op_bytes = 16 << vex.l;
        if ( vex.opcx != vex_none )
            goto simd_0f_avx;
        goto simd_0f_sse2;

    case X86EMUL_OPC_VEX_66(0x0f, 0xd6): /* vmovq xmm,xmm/m64 */
        generate_exception_if(vex.l, EXC_UD);
        d |= TwoOp;
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0xd6):     /* movq xmm,xmm/m64 */
    case X86EMUL_OPC(0x0f, 0x6f):        /* movq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0x7f):        /* movq mm,mm/m64 */
        op_bytes = 8;
        goto simd_0f_int;

    CASE_SIMD_PACKED_INT(0x0f, 0x70):    /* pshuf{w,d} $imm8,{,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x70): /* vpshufd $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F3(0x0f, 0x70):     /* pshufhw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x70): /* vpshufhw $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0x70):     /* pshuflw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x70): /* vpshuflw $imm8,{x,y}mm/mem,{x,y}mm */
        d = (d & ~SrcMask) | SrcMem | TwoOp;
        op_bytes = vex.pfx ? 16 << vex.l : 8;
    simd_0f_int_imm8:
        if ( vex.opcx != vex_none )
        {
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0e): /* vpblendw $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0f): /* vpalignr $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x42): /* vmpsadbw $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
            if ( vex.l )
            {
    simd_0f_imm8_avx2:
                host_and_vcpu_must_have(avx2);
            }
            else
            {
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x08): /* vroundps $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x09): /* vroundpd $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0a): /* vroundss $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0b): /* vroundsd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0c): /* vblendps $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x0d): /* vblendpd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x40): /* vdpps $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    simd_0f_imm8_avx:
                host_and_vcpu_must_have(avx);
            }
    simd_0f_imm8_ymm:
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
    simd_0f_imm8_sse2:
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            vcpu_must_have(mmxext);
            get_fpu(X86EMUL_FPU_mmx);
        }
    simd_0f_imm8:
        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        break;

    CASE_SIMD_PACKED_INT(0x0f, 0x71):    /* Grp12 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x71):
    CASE_SIMD_PACKED_INT(0x0f, 0x72):    /* Grp13 */
    case X86EMUL_OPC_VEX_66(0x0f, 0x72):
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrl{w,d} $imm8,{,x}mm */
                /* vpsrl{w,d} $imm8,{x,y}mm,{x,y}mm */
        case 4: /* psra{w,d} $imm8,{,x}mm */
                /* vpsra{w,d} $imm8,{x,y}mm,{x,y}mm */
        case 6: /* psll{w,d} $imm8,{,x}mm */
                /* vpsll{w,d} $imm8,{x,y}mm,{x,y}mm */
            break;
        default:
            goto unrecognized_insn;
        }
    simd_0f_shift_imm:
        generate_exception_if(ea.type != OP_REG, EXC_UD);

        if ( vex.opcx != vex_none )
        {
            if ( vex.l )
                host_and_vcpu_must_have(avx2);
            else
                host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
    simd_0f_reg_only:
        opc[insn_bytes - PFX_BYTES] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", [dummy_out] "=g" (dummy) : [dummy_in] "i" (0) );

        put_stub(stub);
        ASSERT(!state->simd_size);
        break;

    case X86EMUL_OPC(0x0f, 0x73):        /* Grp14 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrlq $imm8,mm */
        case 6: /* psllq $imm8,mm */
            goto simd_0f_shift_imm;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_66(0x0f, 0x73):
    case X86EMUL_OPC_VEX_66(0x0f, 0x73):
        switch ( modrm_reg & 7 )
        {
        case 2: /* psrlq $imm8,xmm */
                /* vpsrlq $imm8,{x,y}mm,{x,y}mm */
        case 3: /* psrldq $imm8,xmm */
                /* vpsrldq $imm8,{x,y}mm,{x,y}mm */
        case 6: /* psllq $imm8,xmm */
                /* vpsllq $imm8,{x,y}mm,{x,y}mm */
        case 7: /* pslldq $imm8,xmm */
                /* vpslldq $imm8,{x,y}mm,{x,y}mm */
            goto simd_0f_shift_imm;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC(0x0f, 0x77):        /* emms */
    case X86EMUL_OPC_VEX(0x0f, 0x77):    /* vzero{all,upper} */
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);

#ifdef __x86_64__
            if ( !mode_64bit() )
            {
                /*
                 * Can't use the actual instructions here, as we must not
                 * touch YMM8...YMM15.
                 */
                if ( vex.l )
                {
                    /* vpxor %xmmN, %xmmN, %xmmN */
                    asm volatile ( ".byte 0xc5,0xf9,0xef,0xc0" );
                    asm volatile ( ".byte 0xc5,0xf1,0xef,0xc9" );
                    asm volatile ( ".byte 0xc5,0xe9,0xef,0xd2" );
                    asm volatile ( ".byte 0xc5,0xe1,0xef,0xdb" );
                    asm volatile ( ".byte 0xc5,0xd9,0xef,0xe4" );
                    asm volatile ( ".byte 0xc5,0xd1,0xef,0xed" );
                    asm volatile ( ".byte 0xc5,0xc9,0xef,0xf6" );
                    asm volatile ( ".byte 0xc5,0xc1,0xef,0xff" );
                }
                else
                {
                    /* vpor %xmmN, %xmmN, %xmmN */
                    asm volatile ( ".byte 0xc5,0xf9,0xeb,0xc0" );
                    asm volatile ( ".byte 0xc5,0xf1,0xeb,0xc9" );
                    asm volatile ( ".byte 0xc5,0xe9,0xeb,0xd2" );
                    asm volatile ( ".byte 0xc5,0xe1,0xeb,0xdb" );
                    asm volatile ( ".byte 0xc5,0xd9,0xeb,0xe4" );
                    asm volatile ( ".byte 0xc5,0xd1,0xeb,0xed" );
                    asm volatile ( ".byte 0xc5,0xc9,0xeb,0xf6" );
                    asm volatile ( ".byte 0xc5,0xc1,0xeb,0xff" );
                }

                ASSERT(!state->simd_size);
                break;
            }
#endif
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }

        opc = init_prefixes(stub);
        opc[0] = b;
        insn_bytes = PFX_BYTES + 1;
        goto simd_0f_reg_only;

    case X86EMUL_OPC_66(0x0f, 0x78):     /* Grp17 */
        switch ( modrm_reg & 7 )
        {
        case 0: /* extrq $imm8,$imm8,xmm */
            break;
        default:
            goto unrecognized_insn;
        }
        /* fall through */
    case X86EMUL_OPC_F2(0x0f, 0x78):     /* insertq $imm8,$imm8,xmm,xmm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);

        host_and_vcpu_must_have(sse4a);
        get_fpu(X86EMUL_FPU_xmm);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        opc[2] = imm1;
        opc[3] = imm2;
        insn_bytes = PFX_BYTES + 4;
        goto simd_0f_reg_only;

    case X86EMUL_OPC_66(0x0f, 0x79):     /* extrq xmm,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x79):     /* insertq xmm,xmm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        host_and_vcpu_must_have(sse4a);
        op_bytes = 8;
        goto simd_0f_xmm;

    case X86EMUL_OPC_F2(0x0f, 0xf0):     /* lddqu m128,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xf0): /* vlddqu mem,{x,y}mm */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_66(0x0f, 0x7c):     /* haddpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x7c):     /* haddps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7c): /* vhaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x7c): /* vhaddps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0x7d):     /* hsubpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0x7d):     /* hsubps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0x7d): /* vhsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0x7d): /* vhsubps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_66(0x0f, 0xd0):     /* addsubpd xmm/m128,xmm */
    case X86EMUL_OPC_F2(0x0f, 0xd0):     /* addsubps xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd0): /* vaddsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xd0): /* vaddsubps {x,y}mm/mem,{x,y}mm,{x,y}mm */
        op_bytes = 16 << vex.l;
        goto simd_0f_sse3_avx;

    case X86EMUL_OPC_F3(0x0f, 0x7e):     /* movq xmm/m64,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0x7e): /* vmovq xmm/m64,xmm */
        generate_exception_if(vex.l, EXC_UD);
        op_bytes = 8;
        goto simd_0f_int;

    case X86EMUL_OPC(0x0f, 0x80) ... X86EMUL_OPC(0x0f, 0x8f): /* jcc (near) */
        if ( test_cc(b, _regs.eflags) )
            jmp_rel((int32_t)src.val);
        adjust_bnd(ctxt, ops, vex.pfx);
        break;

    case X86EMUL_OPC(0x0f, 0x90) ... X86EMUL_OPC(0x0f, 0x9f): /* setcc */
        dst.val = test_cc(b, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xa2): /* cpuid */
        msr_val = 0;
        fail_if(ops->cpuid == NULL);

        /* Speculatively read MSR_INTEL_MISC_FEATURES_ENABLES. */
        if ( ops->read_msr && !mode_ring0() &&
             (rc = ops->read_msr(MSR_INTEL_MISC_FEATURES_ENABLES,
                                 &msr_val, ctxt)) == X86EMUL_EXCEPTION )
        {
            /* Not implemented.  Squash the exception and proceed normally. */
            x86_emul_reset_event(ctxt);
            rc = X86EMUL_OKAY;
        }
        if ( rc != X86EMUL_OKAY )
            goto done;

        generate_exception_if((msr_val & MSR_MISC_FEATURES_CPUID_FAULTING),
                              EXC_GP, 0); /* Faulting active? (Inc. CPL test) */

        rc = ops->cpuid(_regs.eax, _regs.ecx, &cpuid_leaf, ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;
        _regs.r(ax) = cpuid_leaf.a;
        _regs.r(bx) = cpuid_leaf.b;
        _regs.r(cx) = cpuid_leaf.c;
        _regs.r(dx) = cpuid_leaf.d;
        break;

    case X86EMUL_OPC(0x0f, 0xa3): bt: /* bt */
        generate_exception_if(lock_prefix, EXC_UD);

        if ( ops->rmw && dst.type == OP_MEM &&
             (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                              dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        emulate_2op_SrcV_nobyte("bt", src, dst, _regs.eflags);
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f, 0xa4): /* shld imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xa5): /* shld %%cl,r,r/m */
    case X86EMUL_OPC(0x0f, 0xac): /* shrd imm8,r,r/m */
    case X86EMUL_OPC(0x0f, 0xad): /* shrd %%cl,r,r/m */ {
        uint8_t shift, width = dst.bytes << 3;

        generate_exception_if(lock_prefix, EXC_UD);

        if ( b & 1 )
            shift = _regs.cl;
        else
        {
            shift = src.val;
            src.reg = decode_gpr(&_regs, modrm_reg);
            src.val = truncate_word(*src.reg, dst.bytes);
        }

        if ( ops->rmw && dst.type == OP_MEM )
        {
            ea.orig_val = shift;
            state->rmw = b & 8 ? rmw_shrd : rmw_shld;
            break;
        }

        if ( (shift &= width - 1) == 0 )
            break;
        dst.orig_val = dst.val;
        dst.val = (b & 8) ?
                  /* shrd */
                  ((dst.orig_val >> shift) |
                   truncate_word(src.val << (width - shift), dst.bytes)) :
                  /* shld */
                  (truncate_word(dst.orig_val << shift, dst.bytes) |
                   (src.val >> (width - shift)));
        _regs.eflags &= ~(X86_EFLAGS_OF | X86_EFLAGS_SF | X86_EFLAGS_ZF |
                          X86_EFLAGS_PF | X86_EFLAGS_CF);
        if ( (dst.orig_val >> ((b & 8) ? (shift - 1) : (width - shift))) & 1 )
            _regs.eflags |= X86_EFLAGS_CF;
        if ( ((dst.val ^ dst.orig_val) >> (width - 1)) & 1 )
            _regs.eflags |= X86_EFLAGS_OF;
        _regs.eflags |= ((dst.val >> (width - 1)) & 1) ? X86_EFLAGS_SF : 0;
        _regs.eflags |= (dst.val == 0) ? X86_EFLAGS_ZF : 0;
        _regs.eflags |= even_parity(dst.val) ? X86_EFLAGS_PF : 0;
        break;
    }

    case X86EMUL_OPC(0x0f, 0xab): bts: /* bts */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_bts;
        else
            emulate_2op_SrcV_nobyte("bts", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xae): case X86EMUL_OPC_66(0x0f, 0xae): /* Grp15 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* ldmxcsr */
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse);
        ldmxcsr:
            generate_exception_if(src.type != OP_MEM, EXC_UD);
            get_fpu(vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            generate_exception_if(src.val & ~mxcsr_mask, EXC_GP, 0);
            asm volatile ( "ldmxcsr %0" :: "m" (src.val) );
            break;

        case 3: /* stmxcsr */
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse);
        stmxcsr:
            generate_exception_if(dst.type != OP_MEM, EXC_UD);
            get_fpu(vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            asm volatile ( "stmxcsr %0" : "=m" (dst.val) );
            break;

        case 5: /* lfence */
            fail_if(modrm_mod != 3);
            generate_exception_if(vex.pfx, EXC_UD);
            vcpu_must_have(sse2);
            asm volatile ( "lfence" ::: "memory" );
            break;
        case 6:
            if ( modrm_mod == 3 ) /* mfence */
            {
                generate_exception_if(vex.pfx, EXC_UD);
                vcpu_must_have(sse2);
                asm volatile ( "mfence" ::: "memory" );
                break;
            }
            /* else clwb */
            fail_if(!vex.pfx);
            vcpu_must_have(clwb);
            fail_if(!ops->wbinvd);
            if ( (rc = ops->wbinvd(ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        case 7:
            if ( modrm_mod == 3 ) /* sfence */
            {
                generate_exception_if(vex.pfx, EXC_UD);
                vcpu_must_have(mmxext);
                asm volatile ( "sfence" ::: "memory" );
                break;
            }
            /* else clflush{,opt} */
            if ( !vex.pfx )
                vcpu_must_have(clflush);
            else
                vcpu_must_have(clflushopt);
            fail_if(ops->wbinvd == NULL);
            if ( (rc = ops->wbinvd(ctxt)) != 0 )
                goto done;
            break;
        default:
            goto unimplemented_insn;
        }
        break;

    case X86EMUL_OPC_VEX(0x0f, 0xae): /* Grp15 */
        switch ( modrm_reg & 7 )
        {
        case 2: /* vldmxcsr */
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            vcpu_must_have(avx);
            goto ldmxcsr;
        case 3: /* vstmxcsr */
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            vcpu_must_have(avx);
            goto stmxcsr;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_F3(0x0f, 0xae): /* Grp15 */
        fail_if(modrm_mod != 3);
        generate_exception_if((modrm_reg & 4) || !mode_64bit(), EXC_UD);
        fail_if(!ops->read_cr);
        if ( (rc = ops->read_cr(4, &cr4, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if(!(cr4 & X86_CR4_FSGSBASE), EXC_UD);
        seg = modrm_reg & 1 ? x86_seg_gs : x86_seg_fs;
        fail_if(!ops->read_segment);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
            goto done;
        dst.reg = decode_gpr(&_regs, modrm_rm);
        if ( !(modrm_reg & 2) )
        {
            /* rd{f,g}sbase */
            dst.type = OP_REG;
            dst.bytes = (op_bytes == 8) ? 8 : 4;
            dst.val = sreg.base;
        }
        else
        {
            /* wr{f,g}sbase */
            if ( op_bytes == 8 )
            {
                sreg.base = *dst.reg;
                generate_exception_if(!is_canonical_address(sreg.base),
                                      EXC_GP, 0);
            }
            else
                sreg.base = (uint32_t)*dst.reg;
            fail_if(!ops->write_segment);
            if ( (rc = ops->write_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
                goto done;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xaf): /* imul */
        emulate_2op_SrcV_srcmem("imul", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb0): case X86EMUL_OPC(0x0f, 0xb1): /* cmpxchg */
        fail_if(!ops->cmpxchg);

        if ( ops->rmw && dst.type == OP_MEM &&
             (rc = read_ulong(dst.mem.seg, dst.mem.off, &dst.val,
                              dst.bytes, ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        _regs.eflags &= ~EFLAGS_MASK;
        if ( !((dst.val ^ _regs.r(ax)) &
               (~0UL >> (8 * (sizeof(long) - dst.bytes)))) )
        {
            /* Success: write back to memory. */
            if ( dst.type == OP_MEM )
            {
                dst.val = _regs.r(ax);
                switch ( rc = ops->cmpxchg(dst.mem.seg, dst.mem.off, &dst.val,
                                           &src.val, dst.bytes, lock_prefix,
                                           ctxt) )
                {
                case X86EMUL_OKAY:
                    dst.type = OP_NONE;
                    _regs.eflags |= X86_EFLAGS_ZF | X86_EFLAGS_PF;
                    break;
                case X86EMUL_CMPXCHG_FAILED:
                    rc = X86EMUL_OKAY;
                    break;
                default:
                    goto done;
                }
            }
            else
            {
                dst.val = src.val;
                _regs.eflags |= X86_EFLAGS_ZF | X86_EFLAGS_PF;
            }
        }
        if ( !(_regs.eflags & X86_EFLAGS_ZF) )
        {
            /* Failure: write the value we saw to EAX. */
            dst.type = OP_REG;
            dst.reg  = (unsigned long *)&_regs.r(ax);
            /* cmp: %%eax - dst ==> dst and src swapped for macro invocation */
            src.val = _regs.r(ax);
            emulate_2op_SrcV("cmp", dst, src, _regs.eflags);
            ASSERT(!(_regs.eflags & X86_EFLAGS_ZF));
        }
        break;

    case X86EMUL_OPC(0x0f, 0xb2): /* lss */
    case X86EMUL_OPC(0x0f, 0xb4): /* lfs */
    case X86EMUL_OPC(0x0f, 0xb5): /* lgs */
        seg = b & 7;
        goto les;

    case X86EMUL_OPC(0x0f, 0xb3): btr: /* btr */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_btr;
        else
            emulate_2op_SrcV_nobyte("btr", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xb6): /* movzx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_gpr(&_regs, modrm_reg);
        dst.bytes = op_bytes;
        dst.val   = (uint8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xb7): /* movzx rm16,r{16,32,64} */
        dst.val = (uint16_t)src.val;
        break;

    case X86EMUL_OPC_F3(0x0f, 0xb8): /* popcnt r/m,r */
        host_and_vcpu_must_have(popcnt);
        asm ( "popcnt %1,%0" : "=r" (dst.val) : "rm" (src.val) );
        _regs.eflags &= ~EFLAGS_MASK;
        if ( !dst.val )
            _regs.eflags |= X86_EFLAGS_ZF;
        break;

    case X86EMUL_OPC(0x0f, 0xba): /* Grp8 */
        switch ( modrm_reg & 7 )
        {
        case 4: goto bt;
        case 5: goto bts;
        case 6: goto btr;
        case 7: goto btc;
        default: generate_exception(EXC_UD);
        }
        break;

    case X86EMUL_OPC(0x0f, 0xbb): btc: /* btc */
        if ( ops->rmw && dst.type == OP_MEM )
            state->rmw = rmw_btc;
        else
            emulate_2op_SrcV_nobyte("btc", src, dst, _regs.eflags);
        break;

    case X86EMUL_OPC(0x0f, 0xbc): /* bsf or tzcnt */
    {
        bool zf;

        asm ( "bsf %2,%0" ASM_FLAG_OUT(, "; setz %1")
              : "=r" (dst.val), ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "rm" (src.val) );
        _regs.eflags &= ~X86_EFLAGS_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_bmi1() )
        {
            _regs.eflags &= ~X86_EFLAGS_CF;
            if ( zf )
            {
                _regs.eflags |= X86_EFLAGS_CF;
                dst.val = op_bytes * 8;
            }
            else if ( !dst.val )
                _regs.eflags |= X86_EFLAGS_ZF;
        }
        else if ( zf )
        {
            _regs.eflags |= X86_EFLAGS_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbd): /* bsr or lzcnt */
    {
        bool zf;

        asm ( "bsr %2,%0" ASM_FLAG_OUT(, "; setz %1")
              : "=r" (dst.val), ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "rm" (src.val) );
        _regs.eflags &= ~X86_EFLAGS_ZF;
        if ( (vex.pfx == vex_f3) && vcpu_has_lzcnt() )
        {
            _regs.eflags &= ~X86_EFLAGS_CF;
            if ( zf )
            {
                _regs.eflags |= X86_EFLAGS_CF;
                dst.val = op_bytes * 8;
            }
            else
            {
                dst.val = op_bytes * 8 - 1 - dst.val;
                if ( !dst.val )
                    _regs.eflags |= X86_EFLAGS_ZF;
            }
        }
        else if ( zf )
        {
            _regs.eflags |= X86_EFLAGS_ZF;
            dst.type = OP_NONE;
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xbe): /* movsx rm8,r{16,32,64} */
        /* Recompute DstReg as we may have decoded AH/BH/CH/DH. */
        dst.reg   = decode_gpr(&_regs, modrm_reg);
        dst.bytes = op_bytes;
        dst.val   = (int8_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xbf): /* movsx rm16,r{16,32,64} */
        dst.val = (int16_t)src.val;
        break;

    case X86EMUL_OPC(0x0f, 0xc0): case X86EMUL_OPC(0x0f, 0xc1): /* xadd */
        if ( ops->rmw && dst.type == OP_MEM )
        {
            state->rmw = rmw_xadd;
            break;
        }
        /* Write back the register source. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)src.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)src.reg = (uint16_t)dst.val; break;
        case 4: *src.reg = (uint32_t)dst.val; break; /* 64b reg: zero-extend */
        case 8: *src.reg = dst.val; break;
        }
        goto add;

    CASE_SIMD_ALL_FP(, 0x0f, 0xc2):        /* cmp{p,s}{s,d} $imm8,xmm/mem,xmm */
    CASE_SIMD_ALL_FP(_VEX, 0x0f, 0xc2):    /* vcmp{p,s}{s,d} $imm8,{x,y}mm/mem,{x,y}mm */
    CASE_SIMD_PACKED_FP(, 0x0f, 0xc6):     /* shufp{s,d} $imm8,xmm/mem,xmm */
    CASE_SIMD_PACKED_FP(_VEX, 0x0f, 0xc6): /* vshufp{s,d} $imm8,{x,y}mm/mem,{x,y}mm */
        d = (d & ~SrcMask) | SrcMem;
        if ( vex.opcx == vex_none )
        {
            if ( vex.pfx & VEX_PREFIX_DOUBLE_MASK )
                goto simd_0f_imm8_sse2;
            vcpu_must_have(sse);
            get_fpu(X86EMUL_FPU_xmm);
            goto simd_0f_imm8;
        }
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC(0x0f, 0xc3): /* movnti */
        /* Ignore the non-temporal hint for now. */
        vcpu_must_have(sse2);
        dst.val = src.val;
        sfence = true;
        break;

    CASE_SIMD_PACKED_INT(0x0f, 0xc4):      /* pinsrw $imm8,r32/m16,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xc4):   /* vpinsrw $imm8,r32/m16,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        memcpy(mmvalp, &src.val, 2);
        ea.type = OP_MEM;
        goto simd_0f_int_imm8;

    CASE_SIMD_PACKED_INT(0x0f, 0xc5):      /* pextrw $imm8,{,x}mm,reg */
    case X86EMUL_OPC_VEX_66(0x0f, 0xc5):   /* vpextrw $imm8,xmm,reg */
        generate_exception_if(vex.l, EXC_UD);
        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        goto simd_0f_to_gpr;

    case X86EMUL_OPC(0x0f, 0xc7): /* Grp9 */
    {
        union {
            uint32_t u32[2];
            uint64_t u64[2];
        } *old, *aux;

        if ( ea.type == OP_REG )
        {
            bool __maybe_unused carry;

            switch ( modrm_reg & 7 )
            {
            default:
                goto unrecognized_insn;

            case 6: /* rdrand */
#ifdef HAVE_AS_RDRAND
                generate_exception_if(rep_prefix(), EXC_UD);
                host_and_vcpu_must_have(rdrand);
                dst = ea;
                switch ( op_bytes )
                {
                case 2:
                    asm ( "rdrand %w0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                default:
# ifdef __x86_64__
                    asm ( "rdrand %k0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                case 8:
# endif
                    asm ( "rdrand %0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                }
                _regs.eflags &= ~EFLAGS_MASK;
                if ( carry )
                    _regs.eflags |= X86_EFLAGS_CF;
                break;
#else
                goto unimplemented_insn;
#endif

            case 7: /* rdseed / rdpid */
                if ( repe_prefix() ) /* rdpid */
                {
                    generate_exception_if(ea.type != OP_REG, EXC_UD);
                    vcpu_must_have(rdpid);
                    fail_if(!ops->read_msr);
                    if ( (rc = ops->read_msr(MSR_TSC_AUX, &msr_val,
                                             ctxt)) != X86EMUL_OKAY )
                        goto done;
                    dst = ea;
                    dst.val = msr_val;
                    dst.bytes = 4;
                    break;
                }
#ifdef HAVE_AS_RDSEED
                generate_exception_if(rep_prefix(), EXC_UD);
                host_and_vcpu_must_have(rdseed);
                dst = ea;
                switch ( op_bytes )
                {
                case 2:
                    asm ( "rdseed %w0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                default:
# ifdef __x86_64__
                    asm ( "rdseed %k0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                case 8:
# endif
                    asm ( "rdseed %0" ASM_FLAG_OUT(, "; setc %1")
                          : "=r" (dst.val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                    break;
                }
                _regs.eflags &= ~EFLAGS_MASK;
                if ( carry )
                    _regs.eflags |= X86_EFLAGS_CF;
                break;
#endif
            }
            break;
        }

        /* cmpxchg8b/cmpxchg16b */
        generate_exception_if((modrm_reg & 7) != 1, EXC_UD);
        fail_if(!ops->cmpxchg);
        if ( rex_prefix & REX_W )
        {
            host_and_vcpu_must_have(cx16);
            generate_exception_if(!is_aligned(ea.mem.seg, ea.mem.off, 16,
                                              ctxt, ops),
                                  EXC_GP, 0);
            op_bytes = 16;
        }
        else
        {
            vcpu_must_have(cx8);
            op_bytes = 8;
        }

        old = container_of(&mmvalp->ymm[0], typeof(*old), u64[0]);
        aux = container_of(&mmvalp->ymm[2], typeof(*aux), u64[0]);

        /* Get actual old value. */
        if ( (rc = ops->read(ea.mem.seg, ea.mem.off, old, op_bytes,
                             ctxt)) != X86EMUL_OKAY )
            goto done;

        /* Get expected value. */
        if ( !(rex_prefix & REX_W) )
        {
            aux->u32[0] = _regs.eax;
            aux->u32[1] = _regs.edx;
        }
        else
        {
            aux->u64[0] = _regs.r(ax);
            aux->u64[1] = _regs.r(dx);
        }

        if ( memcmp(old, aux, op_bytes) )
        {
        cmpxchgNb_failed:
            /* Expected != actual: store actual to rDX:rAX and clear ZF. */
            _regs.r(ax) = !(rex_prefix & REX_W) ? old->u32[0] : old->u64[0];
            _regs.r(dx) = !(rex_prefix & REX_W) ? old->u32[1] : old->u64[1];
            _regs.eflags &= ~X86_EFLAGS_ZF;
        }
        else
        {
            /*
             * Expected == actual: Get proposed value, attempt atomic cmpxchg
             * and set ZF if successful.
             */
            if ( !(rex_prefix & REX_W) )
            {
                aux->u32[0] = _regs.ebx;
                aux->u32[1] = _regs.ecx;
            }
            else
            {
                aux->u64[0] = _regs.r(bx);
                aux->u64[1] = _regs.r(cx);
            }

            switch ( rc = ops->cmpxchg(ea.mem.seg, ea.mem.off, old, aux,
                                       op_bytes, lock_prefix, ctxt) )
            {
            case X86EMUL_OKAY:
                _regs.eflags |= X86_EFLAGS_ZF;
                break;

            case X86EMUL_CMPXCHG_FAILED:
                rc = X86EMUL_OKAY;
                goto cmpxchgNb_failed;

            default:
                goto done;
            }
        }
        break;
    }

    case X86EMUL_OPC(0x0f, 0xc8) ... X86EMUL_OPC(0x0f, 0xcf): /* bswap */
        dst.type = OP_REG;
        dst.reg  = decode_gpr(&_regs, (b & 7) | ((rex_prefix & 1) << 3));
        switch ( dst.bytes = op_bytes )
        {
        default: /* case 2: */
            /* Undefined behaviour. Writes zero on all tested CPUs. */
            dst.val = 0;
            break;
        case 4:
#ifdef __x86_64__
            asm ( "bswap %k0" : "=r" (dst.val) : "0" (*(uint32_t *)dst.reg) );
            break;
        case 8:
#endif
            asm ( "bswap %0" : "=r" (dst.val) : "0" (*dst.reg) );
            break;
        }
        break;

    CASE_SIMD_PACKED_INT(0x0f, 0xd1):    /* psrlw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd1): /* vpsrlw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xd2):    /* psrld {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd2): /* vpsrld xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xd3):    /* psrlq {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xd3): /* vpsrlq xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xe1):    /* psraw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe1): /* vpsraw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xe2):    /* psrad {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe2): /* vpsrad xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xf1):    /* psllw {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf1): /* vpsllw xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xf2):    /* pslld {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf2): /* vpslld xmm/m128,{x,y}mm,{x,y}mm */
    CASE_SIMD_PACKED_INT(0x0f, 0xf3):    /* psllq {,x}mm/mem,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf3): /* vpsllq xmm/m128,{x,y}mm,{x,y}mm */
        op_bytes = vex.pfx ? 16 : 8;
        goto simd_0f_int;

    case X86EMUL_OPC(0x0f, 0xd4):        /* paddq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xf4):        /* pmuludq mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xfb):        /* psubq mm/m64,mm */
        vcpu_must_have(sse2);
        goto simd_0f_mmx;

    case X86EMUL_OPC_F3(0x0f, 0xd6):     /* movq2dq mm,xmm */
    case X86EMUL_OPC_F2(0x0f, 0xd6):     /* movdq2q xmm,mm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        op_bytes = 8;
        host_and_vcpu_must_have(mmx);
        goto simd_0f_int;

    case X86EMUL_OPC(0x0f, 0xe7):        /* movntq mm,m64 */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        sfence = true;
        /* fall through */
    case X86EMUL_OPC(0x0f, 0xda):        /* pminub mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xde):        /* pmaxub mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xea):        /* pminsw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xee):        /* pmaxsw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe0):        /* pavgb mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe3):        /* pavgw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xe4):        /* pmulhuw mm/m64,mm */
    case X86EMUL_OPC(0x0f, 0xf6):        /* psadbw mm/m64,mm */
        vcpu_must_have(mmxext);
        goto simd_0f_mmx;

    case X86EMUL_OPC_66(0x0f, 0xe6):       /* cvttpd2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xe6):   /* vcvttpd2dq {x,y}mm/mem,xmm */
    case X86EMUL_OPC_F3(0x0f, 0xe6):       /* cvtdq2pd xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F3(0x0f, 0xe6):   /* vcvtdq2pd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_F2(0x0f, 0xe6):       /* cvtpd2dq xmm/mem,xmm */
    case X86EMUL_OPC_VEX_F2(0x0f, 0xe6):   /* vcvtpd2dq {x,y}mm/mem,xmm */
        d |= TwoOp;
        op_bytes = 8 << (!!(vex.pfx & VEX_PREFIX_DOUBLE_MASK) + vex.l);
        goto simd_0f_cvt;

    CASE_SIMD_PACKED_INT(0x0f, 0xf7):    /* maskmov{q,dqu} {,x}mm,{,x}mm */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf7): /* vmaskmovdqu xmm,xmm */
        generate_exception_if(ea.type != OP_REG, EXC_UD);
        if ( vex.opcx != vex_none )
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            d |= TwoOp;
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }
        else if ( vex.pfx )
        {
            vcpu_must_have(sse2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            vcpu_must_have(mmxext);
            get_fpu(X86EMUL_FPU_mmx);
        }

        /*
         * While we can't reasonably provide fully correct behavior here
         * (in particular avoiding the memory read in anticipation of all
         * bytes in the range eventually being written), we can (and should)
         * still suppress the memory access if all mask bits are clear. Read
         * the mask bits via {,v}pmovmskb for that purpose.
         */
        opc = init_prefixes(stub);
        opc[0] = 0xd7; /* {,v}pmovmskb */
        /* (Ab)use "sfence" for latching the original REX.R / VEX.R. */
        sfence = rex_prefix & REX_R;
        /* Convert GPR destination to %rAX. */
        rex_prefix &= ~REX_R;
        vex.r = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0xc7;
        opc[2] = 0xc3;

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=a" (ea.val) : [dummy] "i" (0));

        put_stub(stub);
        if ( !ea.val )
            goto complete_insn;

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        insn_bytes = PFX_BYTES + 2;
        /* Restore high bit of XMM destination. */
        if ( sfence )
        {
            rex_prefix |= REX_R;
            vex.r = 0;
        }

        ea.type = OP_MEM;
        ea.mem.off = truncate_ea(_regs.r(di));
        sfence = true;
        break;

    case X86EMUL_OPC(0x0f38, 0x00):    /* pshufb mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x00): /* pshufb xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x01):    /* phaddw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x01): /* phaddw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x02):    /* phaddd mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x02): /* phaddd xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x03):    /* phaddsw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x03): /* phaddsw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x04):    /* pmaddubsw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x04): /* pmaddubsw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x05):    /* phsubw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x05): /* phsubw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x06):    /* phsubd mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x06): /* phsubd xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x07):    /* phsubsw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x07): /* phsubsw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x08):    /* psignb mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x08): /* psignb xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x09):    /* psignw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x09): /* psignw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x0a):    /* psignd mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x0a): /* psignd xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x0b):    /* pmulhrsw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x0b): /* pmulhrsw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x1c):    /* pabsb mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x1c): /* pabsb xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x1d):    /* pabsw mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x1d): /* pabsw xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0x1e):    /* pabsd mm/m64,mm */
    case X86EMUL_OPC_66(0x0f38, 0x1e): /* pabsd xmm/m128,xmm */
        host_and_vcpu_must_have(ssse3);
        if ( vex.pfx )
        {
    simd_0f38_common:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }
        opc = init_prefixes(stub);
        opc[0] = 0x38;
        opc[1] = b;
        opc[2] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[2] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 3;
        break;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x19): /* vbroadcastsd xmm/m64,ymm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x1a): /* vbroadcastf128 m128,ymm */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x18): /* vbroadcastss xmm/m32,{x,y}mm */
        if ( ea.type != OP_MEM )
        {
            generate_exception_if(b & 2, EXC_UD);
            host_and_vcpu_must_have(avx2);
        }
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0c): /* vpermilps {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0d): /* vpermilpd {x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_avx;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x0e): /* vtestps {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x0f): /* vtestpd {x,y}mm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_66(0x0f38, 0x17):     /* ptest xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x17): /* vptest {x,y}mm/mem,{x,y}mm */
        if ( vex.opcx == vex_none )
        {
            host_and_vcpu_must_have(sse4_1);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        if ( vex.opcx == vex_none )
            opc++[0] = 0x38;
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 16 << vex.l, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;

            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x38;
        }
        insn_bytes = PFX_BYTES + 2;
        opc[2] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
            ++insn_bytes;
        }

        copy_REX_VEX(opc, rex_prefix, vex);
        emulate_stub("+m" (*mmvalp), "a" (mmvalp));

        put_stub(stub);
        state->simd_size = simd_none;
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC_66(0x0f38, 0x20): /* pmovsxbw xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x21): /* pmovsxbd xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x22): /* pmovsxbq xmm/m16,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x23): /* pmovsxwd xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x24): /* pmovsxwq xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x25): /* pmovsxdq xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x30): /* pmovzxbw xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x31): /* pmovzxbd xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x32): /* pmovzxbq xmm/m16,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x33): /* pmovzxwd xmm/m64,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x34): /* pmovzxwq xmm/m32,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x35): /* pmovzxdq xmm/m64,xmm */
        op_bytes = 16 >> pmov_convert_delta[b & 7];
        /* fall through */
    case X86EMUL_OPC_66(0x0f38, 0x10): /* pblendvb XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x14): /* blendvps XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x15): /* blendvpd XMM0,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x28): /* pmuldq xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x29): /* pcmpeqq xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x2b): /* packusdw xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x38): /* pminsb xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x39): /* pminsd xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3a): /* pminub xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3b): /* pminud xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3c): /* pmaxsb xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3d): /* pmaxsd xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3e): /* pmaxub xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x3f): /* pmaxud xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x40): /* pmulld xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0x41): /* phminposuw xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_1);
        goto simd_0f38_common;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x13): /* vcvtph2ps xmm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        host_and_vcpu_must_have(f16c);
        op_bytes = 8 << vex.l;
        goto simd_0f_ymm;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x16): /* vpermps ymm/m256,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x36): /* vpermd ymm/m256,ymm,ymm */
        generate_exception_if(!vex.l || vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x20): /* vpmovsxbw xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x21): /* vpmovsxbd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x22): /* vpmovsxbq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x23): /* vpmovsxwd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x24): /* vpmovsxwq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x25): /* vpmovsxdq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x30): /* vpmovzxbw xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x31): /* vpmovzxbd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x32): /* vpmovzxbq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x33): /* vpmovzxwd xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x34): /* vpmovzxwq xmm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x35): /* vpmovzxdq xmm/mem,{x,y}mm */
        op_bytes = 16 >> (pmov_convert_delta[b & 7] - vex.l);
        goto simd_0f_int;

    case X86EMUL_OPC_66(0x0f38, 0x2a):     /* movntdqa m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2a): /* vmovntdqa mem,{x,y}mm */
        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        /* Ignore the non-temporal hint for now, using movdqa instead. */
        asm volatile ( "mfence" ::: "memory" );
        b = 0x6f;
        if ( vex.opcx == vex_none )
            vcpu_must_have(sse4_1);
        else
        {
            vex.opcx = vex_0f;
            if ( vex.l )
                vcpu_must_have(avx2);
        }
        goto movdqa;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x2c): /* vmaskmovps mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2d): /* vmaskmovpd mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2e): /* vmaskmovps {x,y}mm,{x,y}mm,mem */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x2f): /* vmaskmovpd {x,y}mm,{x,y}mm,mem */
    {
        typeof(vex) *pvex;

        generate_exception_if(ea.type != OP_MEM || vex.w, EXC_UD);
        host_and_vcpu_must_have(avx);
        get_fpu(X86EMUL_FPU_ymm);

        /*
         * While we can't reasonably provide fully correct behavior here
         * (in particular, for writes, avoiding the memory read in anticipation
         * of all elements in the range eventually being written), we can (and
         * should) still limit the memory access to the smallest possible range
         * (suppressing it altogether if all mask bits are clear), to provide
         * correct faulting behavior. Read the mask bits via vmovmskp{s,d}
         * for that purpose.
         */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        if ( !(b & 1) )
            pvex->pfx = vex_none;
        opc[0] = 0x50; /* vmovmskp{s,d} */
        /* Use %rax as GPR destination and VEX.vvvv as source. */
        pvex->r = 1;
        pvex->b = !mode_64bit() || (vex.reg >> 3);
        opc[1] = 0xc0 | (~vex.reg & 7);
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "=a" (ea.val) : [dummy] "i" (0));
        put_stub(stub);

        if ( !ea.val )
            goto complete_insn;

        op_bytes = 4 << (b & 1);
        first_byte = __builtin_ctz(ea.val);
        ea.val >>= first_byte;
        first_byte *= op_bytes;
        op_bytes *= 32 - __builtin_clz(ea.val);

        /*
         * Even for the memory write variant a memory read is needed, unless
         * all set mask bits are contiguous.
         */
        if ( ea.val & (ea.val + 1) )
            d = (d & ~SrcMask) | SrcMem;

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert memory operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        opc[1] = modrm & 0x38;
        insn_bytes = PFX_BYTES + 2;

        break;
    }

    case X86EMUL_OPC_66(0x0f38, 0x37): /* pcmpgtq xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_2);
        goto simd_0f38_common;

    case X86EMUL_OPC_66(0x0f38, 0xdb):     /* aesimc xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdb): /* vaesimc xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdc):     /* aesenc xmm/m128,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdc): /* vaesenc xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdd):     /* aesenclast xmm/m128,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdd): /* vaesenclast xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xde):     /* aesdec xmm/m128,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xde): /* vaesdec xmm/m128,xmm,xmm */
    case X86EMUL_OPC_66(0x0f38, 0xdf):     /* aesdeclast xmm/m128,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xdf): /* vaesdeclast xmm/m128,xmm,xmm */
        host_and_vcpu_must_have(aesni);
        if ( vex.opcx == vex_none )
            goto simd_0f38_common;
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x41): /* vphminposuw xmm/m128,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_avx;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x58): /* vpbroadcastd xmm/m32,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x59): /* vpbroadcastq xmm/m64,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x78): /* vpbroadcastb xmm/m8,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x79): /* vpbroadcastw xmm/m16,{x,y}mm */
        op_bytes = 1 << ((!(b & 0x20) * 2) + (b & 1));
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x46): /* vpsravd {x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x5a): /* vbroadcasti128 m128,ymm */
        generate_exception_if(ea.type != OP_MEM || !vex.l || vex.w, EXC_UD);
        goto simd_0f_avx2;

    case X86EMUL_OPC_VEX_66(0x0f38, 0x8c): /* vpmaskmov{d,q} mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x8e): /* vpmaskmov{d,q} {x,y}mm,{x,y}mm,mem */
    {
        typeof(vex) *pvex;
        unsigned int mask = vex.w ? 0x80808080U : 0x88888888U;

        generate_exception_if(ea.type != OP_MEM, EXC_UD);
        host_and_vcpu_must_have(avx2);
        get_fpu(X86EMUL_FPU_ymm);

        /*
         * While we can't reasonably provide fully correct behavior here
         * (in particular, for writes, avoiding the memory read in anticipation
         * of all elements in the range eventually being written), we can (and
         * should) still limit the memory access to the smallest possible range
         * (suppressing it altogether if all mask bits are clear), to provide
         * correct faulting behavior. Read the mask bits via vmovmskp{s,d}
         * for that purpose.
         */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        opc[0] = 0xd7; /* vpmovmskb */
        /* Use %rax as GPR destination and VEX.vvvv as source. */
        pvex->r = 1;
        pvex->b = !mode_64bit() || (vex.reg >> 3);
        opc[1] = 0xc0 | (~vex.reg & 7);
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "=a" (ea.val) : [dummy] "i" (0));
        put_stub(stub);

        /* Convert byte granular result to dword/qword granularity. */
        ea.val &= mask;
        if ( !ea.val )
            goto complete_insn;

        first_byte = __builtin_ctz(ea.val) & ~((4 << vex.w) - 1);
        ea.val >>= first_byte;
        op_bytes = 32 - __builtin_clz(ea.val);

        /*
         * Even for the memory write variant a memory read is needed, unless
         * all set mask bits are contiguous.
         */
        if ( ea.val & (ea.val + ~mask + 1) )
            d = (d & ~SrcMask) | SrcMem;

        opc = init_prefixes(stub);
        opc[0] = b;
        /* Convert memory operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        opc[1] = modrm & 0x38;
        insn_bytes = PFX_BYTES + 2;

        break;
    }

    case X86EMUL_OPC_VEX_66(0x0f38, 0x90): /* vpgatherd{d,q} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x91): /* vpgatherq{d,q} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x92): /* vgatherdp{s,d} {x,y}mm,mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x93): /* vgatherqp{s,d} {x,y}mm,mem,{x,y}mm */
    {
        unsigned int mask_reg = ~vex.reg & (mode_64bit() ? 0xf : 7);
        typeof(vex) *pvex;
        union {
            int32_t dw[8];
            int64_t qw[4];
        } index, mask;

        ASSERT(ea.type == OP_MEM);
        generate_exception_if(modrm_reg == state->sib_index ||
                              modrm_reg == mask_reg ||
                              state->sib_index == mask_reg, EXC_UD);
        generate_exception_if(!cpu_has_avx, EXC_UD);
        vcpu_must_have(avx2);
        get_fpu(X86EMUL_FPU_ymm);

        /* Read destination, index, and mask registers. */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        opc[0] = 0x7f; /* vmovdqa */
        /* Use (%rax) as destination and modrm_reg as source. */
        pvex->r = !mode_64bit() || !(modrm_reg & 8);
        pvex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "=m" (*mmvalp) : "a" (mmvalp));

        pvex->pfx = vex_f3; /* vmovdqu */
        /* Switch to sib_index as source. */
        pvex->r = !mode_64bit() || !(state->sib_index & 8);
        opc[1] = (state->sib_index & 7) << 3;

        invoke_stub("", "", "=m" (index) : "a" (&index));

        /* Switch to mask_reg as source. */
        pvex->r = !mode_64bit() || !(mask_reg & 8);
        opc[1] = (mask_reg & 7) << 3;

        invoke_stub("", "", "=m" (mask) : "a" (&mask));
        put_stub(stub);

        /* Clear untouched parts of the destination and mask values. */
        n = 1 << (2 + vex.l - ((b & 1) | vex.w));
        op_bytes = 4 << vex.w;
        memset((void *)mmvalp + n * op_bytes, 0, 32 - n * op_bytes);
        memset((void *)&mask + n * op_bytes, 0, 32 - n * op_bytes);

        for ( i = 0; i < n && rc == X86EMUL_OKAY; ++i )
        {
            if ( (vex.w ? mask.qw[i] : mask.dw[i]) < 0 )
            {
                signed long idx = b & 1 ? index.qw[i] : index.dw[i];

                rc = ops->read(ea.mem.seg,
                               ea.mem.off + (idx << state->sib_scale),
                               (void *)mmvalp + i * op_bytes, op_bytes, ctxt);
                if ( rc != X86EMUL_OKAY )
                    break;

#ifdef __XEN__
                if ( i + 1 < n && local_events_need_delivery() )
                    rc = X86EMUL_RETRY;
#endif
            }

            if ( vex.w )
                mask.qw[i] = 0;
            else
                mask.dw[i] = 0;
        }

        /* Write destination and mask registers. */
        opc = init_prefixes(stub);
        pvex = copy_VEX(opc, vex);
        pvex->opcx = vex_0f;
        opc[0] = 0x6f; /* vmovdqa */
        /* Use modrm_reg as destination and (%rax) as source. */
        pvex->r = !mode_64bit() || !(modrm_reg & 8);
        pvex->b = 1;
        opc[1] = (modrm_reg & 7) << 3;
        pvex->reg = 0xf;
        opc[2] = 0xc3;

        invoke_stub("", "", "+m" (*mmvalp) : "a" (mmvalp));

        pvex->pfx = vex_f3; /* vmovdqu */
        /* Switch to mask_reg as destination. */
        pvex->r = !mode_64bit() || !(mask_reg & 8);
        opc[1] = (mask_reg & 7) << 3;

        invoke_stub("", "", "+m" (mask) : "a" (&mask));
        put_stub(stub);

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_VEX_66(0x0f38, 0x96): /* vfmaddsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x97): /* vfmsubadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x98): /* vfmadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x99): /* vfmadd132s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9a): /* vfmsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9b): /* vfmsub132s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9c): /* vfnmadd132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9d): /* vfnmadd132s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9e): /* vfnmsub132p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0x9f): /* vfnmsub132s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa6): /* vfmaddsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa7): /* vfmsubadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa8): /* vfmadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xa9): /* vfmadd213s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xaa): /* vfmsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xab): /* vfmsub213s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xac): /* vfnmadd213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xad): /* vfnmadd213s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xae): /* vfnmsub213p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xaf): /* vfnmsub213s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb6): /* vfmaddsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb7): /* vfmsubadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb8): /* vfmadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xb9): /* vfmadd231s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xba): /* vfmsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbb): /* vfmsub231s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbc): /* vfnmadd231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbd): /* vfnmadd231s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbe): /* vfnmsub231p{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xbf): /* vfnmsub231s{s,d} {x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(fma);
        goto simd_0f_ymm;

    case X86EMUL_OPC(0x0f38, 0xc8):     /* sha1nexte xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xc9):     /* sha1msg1 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xca):     /* sha1msg2 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcb):     /* sha256rnds2 XMM0,xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcc):     /* sha256msg1 xmm/m128,xmm */
    case X86EMUL_OPC(0x0f38, 0xcd):     /* sha256msg2 xmm/m128,xmm */
        host_and_vcpu_must_have(sha);
        op_bytes = 16;
        goto simd_0f38_common;

    case X86EMUL_OPC(0x0f38, 0xf0): /* movbe m,r */
    case X86EMUL_OPC(0x0f38, 0xf1): /* movbe r,m */
        vcpu_must_have(movbe);
        switch ( op_bytes )
        {
        case 2:
            asm ( "xchg %h0,%b0" : "=Q" (dst.val)
                                 : "0" (*(uint32_t *)&src.val) );
            break;
        case 4:
#ifdef __x86_64__
            asm ( "bswap %k0" : "=r" (dst.val)
                              : "0" (*(uint32_t *)&src.val) );
            break;
        case 8:
#endif
            asm ( "bswap %0" : "=r" (dst.val) : "0" (src.val) );
            break;
        default:
            ASSERT_UNREACHABLE();
        }
        break;
#ifdef HAVE_AS_SSE4_2
    case X86EMUL_OPC_F2(0x0f38, 0xf0): /* crc32 r/m8, r{32,64} */
    case X86EMUL_OPC_F2(0x0f38, 0xf1): /* crc32 r/m{16,32,64}, r{32,64} */
        host_and_vcpu_must_have(sse4_2);
        dst.bytes = rex_prefix & REX_W ? 8 : 4;
        switch ( op_bytes )
        {
        case 1:
            asm ( "crc32b %1,%k0" : "+r" (dst.val)
                                  : "qm" (*(uint8_t *)&src.val) );
            break;
        case 2:
            asm ( "crc32w %1,%k0" : "+r" (dst.val)
                                  : "rm" (*(uint16_t *)&src.val) );
            break;
        case 4:
            asm ( "crc32l %1,%k0" : "+r" (dst.val)
                                  : "rm" (*(uint32_t *)&src.val) );
            break;
# ifdef __x86_64__
        case 8:
            asm ( "crc32q %1,%0" : "+r" (dst.val) : "rm" (src.val) );
            break;
# endif
        default:
            ASSERT_UNREACHABLE();
        }
        break;
#endif

    case X86EMUL_OPC_VEX(0x0f38, 0xf2):    /* andn r/m,r,r */
    case X86EMUL_OPC_VEX(0x0f38, 0xf5):    /* bzhi r,r/m,r */
    case X86EMUL_OPC_VEX_F3(0x0f38, 0xf5): /* pext r/m,r,r */
    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf5): /* pdep r/m,r,r */
    case X86EMUL_OPC_VEX(0x0f38, 0xf7):    /* bextr r,r/m,r */
    case X86EMUL_OPC_VEX_66(0x0f38, 0xf7): /* shlx r,r/m,r */
    case X86EMUL_OPC_VEX_F3(0x0f38, 0xf7): /* sarx r,r/m,r */
    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf7): /* shrx r,r/m,r */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pvex = container_of(buf + 1, typeof(vex), raw[0]);

        if ( b == 0xf5 || vex.pfx )
            host_and_vcpu_must_have(bmi2);
        else
            host_and_vcpu_must_have(bmi1);
        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0xc4;
        *pvex = vex;
        pvex->b = 1;
        pvex->r = 1;
        pvex->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = 0x09; /* reg=rCX r/m=(%rCX) */
        buf[5] = 0xc3;

        src.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub([dst] "=&c" (dst.val), "[dst]" (&src.val), "a" (*src.reg));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_VEX(0x0f38, 0xf3): /* Grp 17 */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pvex = container_of(buf + 1, typeof(vex), raw[0]);

        switch ( modrm_reg & 7 )
        {
        case 1: /* blsr r,r/m */
        case 2: /* blsmsk r,r/m */
        case 3: /* blsi r,r/m */
            host_and_vcpu_must_have(bmi1);
            break;
        default:
            goto unrecognized_insn;
        }

        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0xc4;
        *pvex = vex;
        pvex->b = 1;
        pvex->r = 1;
        pvex->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = (modrm & 0x38) | 0x01; /* r/m=(%rCX) */
        buf[5] = 0xc3;

        dst.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub("=&a" (dst.val), "c" (&src.val));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_66(0x0f38, 0xf6): /* adcx r/m,r */
    case X86EMUL_OPC_F3(0x0f38, 0xf6): /* adox r/m,r */
    {
        unsigned int mask = rep_prefix() ? X86_EFLAGS_OF : X86_EFLAGS_CF;
        unsigned int aux = _regs.eflags & mask ? ~0 : 0;
        bool carry;

        vcpu_must_have(adx);
#ifdef __x86_64__
        if ( op_bytes == 8 )
            asm ( "add %[aux],%[aux]\n\t"
                  "adc %[src],%[dst]\n\t"
                  ASM_FLAG_OUT(, "setc %[carry]")
                  : [dst] "+r" (dst.val),
                    [carry] ASM_FLAG_OUT("=@ccc", "=qm") (carry),
                    [aux] "+r" (aux)
                  : [src] "rm" (src.val) );
        else
#endif
            asm ( "add %[aux],%[aux]\n\t"
                  "adc %k[src],%k[dst]\n\t"
                  ASM_FLAG_OUT(, "setc %[carry]")
                  : [dst] "+r" (dst.val),
                    [carry] ASM_FLAG_OUT("=@ccc", "=qm") (carry),
                    [aux] "+r" (aux)
                  : [src] "rm" (src.val) );
        if ( carry )
            _regs.eflags |= mask;
        else
            _regs.eflags &= ~mask;
        break;
    }

    case X86EMUL_OPC_VEX_F2(0x0f38, 0xf6): /* mulx r/m,r,r */
        vcpu_must_have(bmi2);
        generate_exception_if(vex.l, EXC_UD);
        ea.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        if ( mode_64bit() && vex.w )
            asm ( "mulq %3" : "=a" (*ea.reg), "=d" (dst.val)
                            : "0" (src.val), "rm" (_regs.r(dx)) );
        else
            asm ( "mull %3" : "=a" (*ea.reg), "=d" (dst.val)
                            : "0" ((uint32_t)src.val), "rm" (_regs.edx) );
        break;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x00): /* vpermq $imm8,ymm/m256,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x01): /* vpermpd $imm8,ymm/m256,ymm */
        generate_exception_if(!vex.l || !vex.w, EXC_UD);
        goto simd_0f_imm8_avx2;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x38): /* vinserti128 $imm8,xmm/m128,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x39): /* vextracti128 $imm8,ymm,xmm/m128 */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x46): /* vperm2i128 $imm8,ymm/m256,ymm,ymm */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x02): /* vpblendd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx2;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x06): /* vperm2f128 $imm8,ymm/m256,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x18): /* vinsertf128 $imm8,xmm/m128,ymm,ymm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x19): /* vextractf128 $imm8,ymm,xmm/m128 */
        generate_exception_if(!vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x04): /* vpermilps $imm8,{x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x05): /* vpermilpd $imm8,{x,y}mm/mem,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_66(0x0f3a, 0x08): /* roundps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x09): /* roundpd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0a): /* roundss $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0b): /* roundsd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0c): /* blendps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0d): /* blendpd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x0e): /* pblendw $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x40): /* dpps $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x41): /* dppd $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x42): /* mpsadbw $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(sse4_1);
        goto simd_0f3a_common;

    case X86EMUL_OPC(0x0f3a, 0x0f):    /* palignr $imm8,mm/m64,mm */
    case X86EMUL_OPC_66(0x0f3a, 0x0f): /* palignr $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(ssse3);
        if ( vex.pfx )
        {
    simd_0f3a_common:
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            host_and_vcpu_must_have(mmx);
            get_fpu(X86EMUL_FPU_mmx);
        }
        opc = init_prefixes(stub);
        opc[0] = 0x3a;
        opc[1] = b;
        opc[2] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[2] &= 0x38;
        }
        opc[3] = imm1;
        insn_bytes = PFX_BYTES + 4;
        break;

    case X86EMUL_OPC_66(0x0f3a, 0x14): /* pextrb $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x15): /* pextrw $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x16): /* pextr{d,q} $imm8,xmm,r/m */
    case X86EMUL_OPC_66(0x0f3a, 0x17): /* extractps $imm8,xmm,r/m */
        host_and_vcpu_must_have(sse4_1);
        get_fpu(X86EMUL_FPU_xmm);

        opc = init_prefixes(stub);
        opc++[0] = 0x3a;
    pextr:
        opc[0] = b;
        /* Convert memory/GPR operand to (%rAX). */
        rex_prefix &= ~REX_B;
        vex.b = 1;
        if ( !mode_64bit() )
            vex.w = 0;
        opc[1] = modrm & 0x38;
        opc[2] = imm1;
        opc[3] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
        }

        copy_REX_VEX(opc, rex_prefix, vex);
        invoke_stub("", "", "=m" (dst.val) : "a" (&dst.val));
        put_stub(stub);

        ASSERT(!state->simd_size);
        dst.bytes = dst.type == OP_REG || b == 0x17 ? 4 : 1 << (b & 3);
        if ( b == 0x16 && (rex_prefix & REX_W) )
            dst.bytes = 8;
        break;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x14): /* vpextrb $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x15): /* vpextrw $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x16): /* vpextr{d,q} $imm8,xmm,r/m */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x17): /* vextractps $imm8,xmm,r/m */
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
        host_and_vcpu_must_have(avx);
        get_fpu(X86EMUL_FPU_ymm);
        opc = init_prefixes(stub);
        goto pextr;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x1d): /* vcvtps2ph $imm8,{x,y}mm,xmm/mem */
    {
        uint32_t mxcsr;

        generate_exception_if(vex.w || vex.reg != 0xf, EXC_UD);
        host_and_vcpu_must_have(f16c);
        fail_if(!ops->write);

        opc = init_prefixes(stub);
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rAX). */
            vex.b = 1;
            opc[1] &= 0x38;
        }
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        opc[3] = 0xc3;

        copy_VEX(opc, vex);
        /* Latch MXCSR - we may need to restore it below. */
        invoke_stub("stmxcsr %[mxcsr]", "",
                    "=m" (*mmvalp), [mxcsr] "=m" (mxcsr) : "a" (mmvalp));

        put_stub(stub);

        if ( ea.type == OP_MEM )
        {
            rc = ops->write(ea.mem.seg, ea.mem.off, mmvalp, 8 << vex.l, ctxt);
            if ( rc != X86EMUL_OKAY )
            {
                asm volatile ( "ldmxcsr %0" :: "m" (mxcsr) );
                goto done;
            }
        }

        state->simd_size = simd_none;
        break;
    }

    case X86EMUL_OPC_66(0x0f3a, 0x20): /* pinsrb $imm8,r32/m8,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x22): /* pinsr{d,q} $imm8,r/m,xmm */
        host_and_vcpu_must_have(sse4_1);
        get_fpu(X86EMUL_FPU_xmm);
        memcpy(mmvalp, &src.val, op_bytes);
        ea.type = OP_MEM;
        op_bytes = src.bytes;
        d = SrcMem16; /* Fake for the common SIMD code below. */
        state->simd_size = simd_other;
        goto simd_0f3a_common;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x20): /* vpinsrb $imm8,r32/m8,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x22): /* vpinsr{d,q} $imm8,r/m,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        if ( !mode_64bit() )
            vex.w = 0;
        memcpy(mmvalp, &src.val, op_bytes);
        ea.type = OP_MEM;
        op_bytes = src.bytes;
        d = SrcMem16; /* Fake for the common SIMD code below. */
        state->simd_size = simd_other;
        goto simd_0f_int_imm8;

    case X86EMUL_OPC_66(0x0f3a, 0x21): /* insertps $imm8,xmm/m32,xmm */
        host_and_vcpu_must_have(sse4_1);
        op_bytes = 4;
        goto simd_0f3a_common;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x21): /* vinsertps $imm8,xmm/m128,xmm,xmm */
        op_bytes = 4;
        /* fall through */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x41): /* vdppd $imm8,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_66(0x0f3a, 0x44):     /* pclmulqdq $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x44): /* vpclmulqdq $imm8,xmm/m128,xmm,xmm */
        host_and_vcpu_must_have(pclmulqdq);
        if ( vex.opcx == vex_none )
            goto simd_0f3a_common;
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4a): /* vblendvps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4b): /* vblendvpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x48): /* vpermil2ps $imm,{x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                           /* vpermil2ps $imm,{x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x49): /* vpermil2pd $imm,{x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                           /* vpermil2pd $imm,{x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(xop);
        goto simd_0f_imm8_ymm;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x4c): /* vpblendvb {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_int_imm8;

    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5c): /* vfmaddsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5d): /* vfmaddsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5e): /* vfmsubaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x5f): /* vfmsubaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x68): /* vfmaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x69): /* vfmaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6a): /* vfmaddss xmm,xmm/m32,xmm,xmm */
                                           /* vfmaddss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6b): /* vfmaddsd xmm,xmm/m64,xmm,xmm */
                                           /* vfmaddsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6c): /* vfmsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6d): /* vfmsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfmsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6e): /* vfmsubss xmm,xmm/m32,xmm,xmm */
                                           /* vfmsubss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x6f): /* vfmsubsd xmm,xmm/m64,xmm,xmm */
                                           /* vfmsubsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x78): /* vfnmaddps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmaddps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x79): /* vfnmaddpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmaddpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7a): /* vfnmaddss xmm,xmm/m32,xmm,xmm */
                                           /* vfnmaddss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7b): /* vfnmaddsd xmm,xmm/m64,xmm,xmm */
                                           /* vfnmaddsd xmm/m64,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7c): /* vfnmsubps {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmsubps {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7d): /* vfnmsubpd {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
                                           /* vfnmsubpd {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7e): /* vfnmsubss xmm,xmm/m32,xmm,xmm */
                                           /* vfnmsubss xmm/m32,xmm,xmm,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x7f): /* vfnmsubsd xmm,xmm/m64,xmm,xmm */
                                           /* vfnmsubsd xmm/m64,xmm,xmm,xmm */
        host_and_vcpu_must_have(fma4);
        goto simd_0f_imm8_ymm;

    case X86EMUL_OPC_66(0x0f3a, 0x60):     /* pcmpestrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x60): /* vpcmpestrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x61):     /* pcmpestri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x61): /* vpcmpestri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x62):     /* pcmpistrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x62): /* vpcmpistrm $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_66(0x0f3a, 0x63):     /* pcmpistri $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0x63): /* vpcmpistri $imm8,xmm/m128,xmm */
        if ( vex.opcx == vex_none )
        {
            host_and_vcpu_must_have(sse4_2);
            get_fpu(X86EMUL_FPU_xmm);
        }
        else
        {
            generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
            host_and_vcpu_must_have(avx);
            get_fpu(X86EMUL_FPU_ymm);
        }

        opc = init_prefixes(stub);
        if ( vex.opcx == vex_none )
            opc++[0] = 0x3a;
        opc[0] = b;
        opc[1] = modrm;
        if ( ea.type == OP_MEM )
        {
            /* Convert memory operand to (%rDI). */
            rex_prefix &= ~REX_B;
            vex.b = 1;
            opc[1] &= 0x3f;
            opc[1] |= 0x07;

            rc = ops->read(ea.mem.seg, ea.mem.off, mmvalp, 16, ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
        }
        opc[2] = imm1;
        insn_bytes = PFX_BYTES + 3;
        opc[3] = 0xc3;
        if ( vex.opcx == vex_none )
        {
            /* Cover for extra prefix byte. */
            --opc;
            ++insn_bytes;
        }

        copy_REX_VEX(opc, rex_prefix, vex);
#ifdef __x86_64__
        if ( rex_prefix & REX_W )
            emulate_stub("=c" (dst.val), "m" (*mmvalp), "D" (mmvalp),
                         "a" (_regs.rax), "d" (_regs.rdx));
        else
#endif
            emulate_stub("=c" (dst.val), "m" (*mmvalp), "D" (mmvalp),
                         "a" (_regs.eax), "d" (_regs.edx));

        state->simd_size = simd_none;
        if ( b & 1 )
            _regs.r(cx) = (uint32_t)dst.val;
        dst.type = OP_NONE;
        break;

    case X86EMUL_OPC(0x0f3a, 0xcc):     /* sha1rnds4 $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(sha);
        op_bytes = 16;
        goto simd_0f3a_common;

    case X86EMUL_OPC_66(0x0f3a, 0xdf):     /* aeskeygenassist $imm8,xmm/m128,xmm */
    case X86EMUL_OPC_VEX_66(0x0f3a, 0xdf): /* vaeskeygenassist $imm8,xmm/m128,xmm */
        host_and_vcpu_must_have(aesni);
        if ( vex.opcx == vex_none )
            goto simd_0f3a_common;
        generate_exception_if(vex.l, EXC_UD);
        goto simd_0f_imm8_avx;

    case X86EMUL_OPC_VEX_F2(0x0f3a, 0xf0): /* rorx imm,r/m,r */
        vcpu_must_have(bmi2);
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);
        if ( ea.type == OP_REG )
            src.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val, op_bytes,
                                   ctxt, ops)) != X86EMUL_OKAY )
            goto done;
        if ( mode_64bit() && vex.w )
            asm ( "rorq %b1,%0" : "=g" (dst.val) : "c" (imm1), "0" (src.val) );
        else
            asm ( "rorl %b1,%k0" : "=g" (dst.val) : "c" (imm1), "0" (src.val) );
        break;

    case X86EMUL_OPC_XOP(08, 0x85): /* vpmacssww xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x86): /* vpmacsswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x87): /* vpmacssdql xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x8e): /* vpmacssdd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x8f): /* vpmacssdqh xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x95): /* vpmacsww xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x96): /* vpmacswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x97): /* vpmacsdql xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x9e): /* vpmacsdd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0x9f): /* vpmacsdqh xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xa6): /* vpmadcsswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xb6): /* vpmadcswd xmm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xc0): /* vprotb $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc1): /* vprotw $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc2): /* vprotd $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xc3): /* vprotq $imm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(08, 0xcc): /* vpcomb $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xcd): /* vpcomw $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xce): /* vpcomd $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xcf): /* vpcomq $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xec): /* vpcomub $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xed): /* vpcomuw $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xee): /* vpcomud $imm,xmm/m128,xmm,xmm */
    case X86EMUL_OPC_XOP(08, 0xef): /* vpcomuq $imm,xmm/m128,xmm,xmm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(08, 0xa3): /* vpperm xmm/m128,xmm,xmm,xmm */
                                    /* vpperm xmm,xmm/m128,xmm,xmm */
        generate_exception_if(vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(08, 0xa2): /* vpcmov {x,y}mm/mem,{x,y}mm,{x,y}mm,{x,y}mm */
                                    /* vpcmov {x,y}mm,{x,y}mm/mem,{x,y}mm,{x,y}mm */
        host_and_vcpu_must_have(xop);
        goto simd_0f_imm8_ymm;

    case X86EMUL_OPC_XOP(09, 0x01): /* XOP Grp1 */
        switch ( modrm_reg & 7 )
        {
        case 1: /* blcfill r/m,r */
        case 2: /* blsfill r/m,r */
        case 3: /* blcs r/m,r */
        case 4: /* tzmsk r/m,r */
        case 5: /* blcic r/m,r */
        case 6: /* blsic r/m,r */
        case 7: /* t1mskc r/m,r */
            host_and_vcpu_must_have(tbm);
            break;
        default:
            goto unrecognized_insn;
        }

    xop_09_rm_rv:
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pxop = container_of(buf + 1, typeof(vex), raw[0]);

        generate_exception_if(vex.l, EXC_UD);

        buf[0] = 0x8f;
        *pxop = vex;
        pxop->b = 1;
        pxop->r = 1;
        pxop->reg = 0xf; /* rAX */
        buf[3] = b;
        buf[4] = (modrm & 0x38) | 0x01; /* r/m=(%rCX) */
        buf[5] = 0xc3;

        dst.reg = decode_vex_gpr(vex.reg, &_regs, ctxt);
        emulate_stub([dst] "=&a" (dst.val), "c" (&src.val));

        put_stub(stub);
        break;
    }

    case X86EMUL_OPC_XOP(09, 0x02): /* XOP Grp2 */
        switch ( modrm_reg & 7 )
        {
        case 1: /* blcmsk r/m,r */
        case 6: /* blci r/m,r */
            host_and_vcpu_must_have(tbm);
            goto xop_09_rm_rv;
        }
        goto unrecognized_insn;

    case X86EMUL_OPC_XOP(09, 0x82): /* vfrczss xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x83): /* vfrczsd xmm/m128,xmm */
        generate_exception_if(vex.l, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(09, 0x80): /* vfrczps {x,y}mm/mem,{x,y}mm */
    case X86EMUL_OPC_XOP(09, 0x81): /* vfrczpd {x,y}mm/mem,{x,y}mm */
        host_and_vcpu_must_have(xop);
        generate_exception_if(vex.w, EXC_UD);
        goto simd_0f_ymm;

    case X86EMUL_OPC_XOP(09, 0xc1): /* vphaddbw xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc2): /* vphaddbd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc3): /* vphaddbq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc6): /* vphaddwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xc7): /* vphaddwq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xcb): /* vphadddq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd1): /* vphaddubw xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd2): /* vphaddubd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd3): /* vphaddubq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd6): /* vphadduwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xd7): /* vphadduwq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xdb): /* vphaddudq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe2): /* vphsubwd xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe3): /* vphsubdq xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0xe1): /* vphsubbw xmm/m128,xmm */
        generate_exception_if(vex.w, EXC_UD);
        /* fall through */
    case X86EMUL_OPC_XOP(09, 0x90): /* vprotb xmm/m128,xmm,xmm */
                                    /* vprotb xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x91): /* vprotw xmm/m128,xmm,xmm */
                                    /* vprotw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x92): /* vprotd xmm/m128,xmm,xmm */
                                    /* vprotd xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x93): /* vprotq xmm/m128,xmm,xmm */
                                    /* vprotq xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x94): /* vpshlb xmm/m128,xmm,xmm */
                                    /* vpshlb xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x95): /* vpshlw xmm/m128,xmm,xmm */
                                    /* vpshlw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x96): /* vpshld xmm/m128,xmm,xmm */
                                    /* vpshld xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x97): /* vpshlq xmm/m128,xmm,xmm */
                                    /* vpshlq xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x98): /* vpshab xmm/m128,xmm,xmm */
                                    /* vpshab xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x99): /* vpshaw xmm/m128,xmm,xmm */
                                    /* vpshaw xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x9a): /* vpshad xmm/m128,xmm,xmm */
                                    /* vpshad xmm,xmm/m128,xmm */
    case X86EMUL_OPC_XOP(09, 0x9b): /* vpshaq xmm/m128,xmm,xmm */
                                    /* vpshaq xmm,xmm/m128,xmm */
        generate_exception_if(vex.l, EXC_UD);
        host_and_vcpu_must_have(xop);
        goto simd_0f_ymm;

    case X86EMUL_OPC_XOP(0a, 0x10): /* bextr imm,r/m,r */
    {
        uint8_t *buf = get_stub(stub);
        typeof(vex) *pxop = container_of(buf + 1, typeof(vex), raw[0]);

        host_and_vcpu_must_have(tbm);
        generate_exception_if(vex.l || vex.reg != 0xf, EXC_UD);

        if ( ea.type == OP_REG )
            src.val = *ea.reg;
        else if ( (rc = read_ulong(ea.mem.seg, ea.mem.off, &src.val, op_bytes,
                                   ctxt, ops)) != X86EMUL_OKAY )
            goto done;

        buf[0] = 0x8f;
        *pxop = vex;
        pxop->b = 1;
        pxop->r = 1;
        buf[3] = b;
        buf[4] = 0x09; /* reg=rCX r/m=(%rCX) */
        *(uint32_t *)(buf + 5) = imm1;
        buf[9] = 0xc3;

        emulate_stub([dst] "=&c" (dst.val), "[dst]" (&src.val));

        put_stub(stub);
        break;
    }

    default:
    unimplemented_insn:
        rc = X86EMUL_UNIMPLEMENTED;
        goto done;
    unrecognized_insn:
        rc = X86EMUL_UNRECOGNIZED;
        goto done;
    }

    if ( state->rmw )
    {
        ea.val = src.val;
        op_bytes = dst.bytes;
        rc = ops->rmw(dst.mem.seg, dst.mem.off, dst.bytes, &_regs.eflags,
                      state, ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;

        /* Some operations require a register to be written. */
        switch ( state->rmw )
        {
        case rmw_xchg:
        case rmw_xadd:
            switch ( dst.bytes )
            {
            case 1: *(uint8_t  *)src.reg = (uint8_t)ea.val; break;
            case 2: *(uint16_t *)src.reg = (uint16_t)ea.val; break;
            case 4: *src.reg = (uint32_t)ea.val; break; /* 64b reg: zero-extend */
            case 8: *src.reg = ea.val; break;
            }
            break;

        default:
            break;
        }

        dst.type = OP_NONE;
    }
    else if ( state->simd_size )
    {
        generate_exception_if(!op_bytes, EXC_UD);
        generate_exception_if(vex.opcx && (d & TwoOp) && vex.reg != 0xf,
                              EXC_UD);

        if ( !opc )
            BUG();
        opc[insn_bytes - PFX_BYTES] = 0xc3;
        copy_REX_VEX(opc, rex_prefix, vex);

        if ( ea.type == OP_MEM )
        {
            uint32_t mxcsr = 0;

            if ( op_bytes < 16 ||
                 (vex.opcx
                  ? /* vmov{{a,nt}p{s,d},dqa,ntdq} are exceptions. */
                    ext != ext_0f ||
                    ((b | 1) != 0x29 && b != 0x2b &&
                     ((b | 0x10) != 0x7f || vex.pfx != vex_66) &&
                     b != 0xe7)
                  : /* movup{s,d}, {,mask}movdqu, and lddqu are exceptions. */
                    ext == ext_0f &&
                    ((b | 1) == 0x11 ||
                     ((b | 0x10) == 0x7f && vex.pfx == vex_f3) ||
                     b == 0xf7 || b == 0xf0)) )
                mxcsr = MXCSR_MM;
            else if ( vcpu_has_misalignsse() )
                asm ( "stmxcsr %0" : "=m" (mxcsr) );
            generate_exception_if(!(mxcsr & MXCSR_MM) &&
                                  !is_aligned(ea.mem.seg, ea.mem.off, op_bytes,
                                              ctxt, ops),
                                  EXC_GP, 0);
            switch ( d & SrcMask )
            {
            case SrcMem:
                rc = ops->read(ea.mem.seg, truncate_ea(ea.mem.off + first_byte),
                               (void *)mmvalp + first_byte, op_bytes,
                               ctxt);
                if ( rc != X86EMUL_OKAY )
                    goto done;
                /* fall through */
            case SrcMem16:
                dst.type = OP_NONE;
                break;
            default:
                if ( (d & DstMask) != DstMem )
                {
                    ASSERT_UNREACHABLE();
                    rc = X86EMUL_UNHANDLEABLE;
                    goto done;
                }
                break;
            }
            if ( (d & DstMask) == DstMem )
            {
                fail_if(!ops->write); /* Check before running the stub. */
                if ( (d & SrcMask) == SrcMem )
                    d |= Mov; /* Force memory write to occur below. */

                switch ( ctxt->opcode )
                {
                case X86EMUL_OPC_VEX_66(0x0f38, 0x2e): /* vmaskmovps */
                case X86EMUL_OPC_VEX_66(0x0f38, 0x2f): /* vmaskmovpd */
                case X86EMUL_OPC_VEX_66(0x0f38, 0x8e): /* vpmaskmov{d,q} */
                    /* These have merge semantics; force write to occur. */
                    d |= Mov;
                    break;
                default:
                    ASSERT(d & Mov);
                    break;
                }

                dst.type = OP_MEM;
                dst.bytes = op_bytes;
                dst.mem = ea.mem;
            }
        }
        else
            dst.type = OP_NONE;

        /* {,v}maskmov{q,dqu}, as an exception, uses rDI. */
        if ( likely((ctxt->opcode & ~(X86EMUL_OPC_PFX_MASK |
                                      X86EMUL_OPC_ENCODING_MASK)) !=
                    X86EMUL_OPC(0x0f, 0xf7)) )
            invoke_stub("", "", "+m" (*mmvalp) : "a" (mmvalp));
        else
            invoke_stub("", "", "+m" (*mmvalp) : "D" (mmvalp));

        put_stub(stub);
    }

    switch ( dst.type )
    {
    case OP_REG:
        /* The 4-byte case *is* correct: in 64-bit mode we zero-extend. */
        switch ( dst.bytes )
        {
        case 1: *(uint8_t  *)dst.reg = (uint8_t)dst.val; break;
        case 2: *(uint16_t *)dst.reg = (uint16_t)dst.val; break;
        case 4: *dst.reg = (uint32_t)dst.val; break; /* 64b: zero-ext */
        case 8: *dst.reg = dst.val; break;
        }
        break;
    case OP_MEM:
        if ( !(d & Mov) && (dst.orig_val == dst.val) &&
             !ctxt->force_writeback )
            /* nothing to do */;
        else if ( lock_prefix )
        {
            fail_if(!ops->cmpxchg);
            rc = ops->cmpxchg(
                dst.mem.seg, dst.mem.off, &dst.orig_val,
                &dst.val, dst.bytes, true, ctxt);
            if ( rc == X86EMUL_CMPXCHG_FAILED )
                rc = X86EMUL_RETRY;
        }
        else
        {
            fail_if(!ops->write);
            rc = ops->write(dst.mem.seg, truncate_ea(dst.mem.off + first_byte),
                            !state->simd_size ? &dst.val
                                              : (void *)mmvalp + first_byte,
                            dst.bytes, ctxt);
            if ( sfence )
                asm volatile ( "sfence" ::: "memory" );
        }
        if ( rc != 0 )
            goto done;
    default:
        break;
    }

 complete_insn: /* Commit shadow register state. */
    put_fpu(fpu_type, false, state, ctxt, ops);
    fpu_type = X86EMUL_FPU_none;

    /* Zero the upper 32 bits of %rip if not in 64-bit mode. */
    if ( !mode_64bit() )
        _regs.r(ip) = _regs.eip;

    /* Should a singlestep #DB be raised? */
    if ( rc == X86EMUL_OKAY && singlestep && !ctxt->retire.mov_ss )
    {
        ctxt->retire.singlestep = true;
        ctxt->retire.sti = false;
    }

    if ( rc != X86EMUL_DONE )
        *ctxt->regs = _regs;
    else
    {
        ctxt->regs->r(ip) = _regs.r(ip);
        rc = X86EMUL_OKAY;
    }

    ctxt->regs->eflags &= ~X86_EFLAGS_RF;

 done:
    put_fpu(fpu_type, insn_bytes > 0 && dst.type == OP_MEM, state, ctxt, ops);
    put_stub(stub);
    return rc;
#undef state

#ifdef __XEN__
 emulation_stub_failure:
    generate_exception_if(stub_exn.info.fields.trapnr == EXC_MF, EXC_MF);
    if ( stub_exn.info.fields.trapnr == EXC_XM )
    {
        unsigned long cr4;

        if ( !ops->read_cr || ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
            cr4 = X86_CR4_OSXMMEXCPT;
        generate_exception(cr4 & X86_CR4_OSXMMEXCPT ? EXC_XM : EXC_UD);
    }
    gprintk(XENLOG_WARNING,
            "exception %u (ec=%04x) in emulation stub (line %u)\n",
            stub_exn.info.fields.trapnr, stub_exn.info.fields.ec,
            stub_exn.line);
    gprintk(XENLOG_INFO, "  stub: %"__stringify(MAX_INST_LEN)"ph\n",
            stub.func);
    generate_exception_if(stub_exn.info.fields.trapnr == EXC_UD, EXC_UD);
    domain_crash(current->domain);
    rc = X86EMUL_UNHANDLEABLE;
    goto done;
#endif
}

#undef op_bytes
#undef ad_bytes
#undef ext
#undef modrm
#undef modrm_mod
#undef modrm_reg
#undef modrm_rm
#undef rex_prefix
#undef lock_prefix
#undef vex
#undef ea

int x86_emul_rmw(
    void *ptr,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long *dst = ptr;

    ASSERT(bytes == state->op_bytes);

/*
 * We cannot use Jcc below, as this code executes with the guest status flags
 * loaded into the EFLAGS register. Hence our only choice is J{E,R}CXZ.
 */
#ifdef __x86_64__
# define JCXZ "jrcxz"
#else
# define JCXZ "jecxz"
#endif

#define COND_LOCK(op) \
    JCXZ " .L" #op "%=\n\t" \
    "lock\n" \
    ".L" #op "%=:\n\t" \
    #op

    switch ( state->rmw )
    {
#define UNOP(op) \
    case rmw_##op: \
        _emulate_1op(COND_LOCK(op), dst, bytes, *eflags, \
                     "c" ((long)state->lock_prefix) ); \
        break
#define BINOP(op, sfx) \
    case rmw_##op: \
        _emulate_2op_SrcV##sfx(COND_LOCK(op), \
                               state->ea.val, dst, bytes, *eflags, \
                               "c" ((long)state->lock_prefix) ); \
        break
#define SHIFT(op) \
    case rmw_##op: \
        ASSERT(!state->lock_prefix); \
        _emulate_2op_SrcB(#op, state->ea.val, dst, bytes, *eflags); \
        break

    BINOP(adc, );
    BINOP(add, );
    BINOP(and, );
    BINOP(btc, _nobyte);
    BINOP(bts, _nobyte);
    BINOP(btr, _nobyte);
     UNOP(dec);
     UNOP(inc);
     UNOP(neg);
    BINOP(or, );
    SHIFT(rcl);
    SHIFT(rcr);
    SHIFT(rol);
    SHIFT(ror);
    SHIFT(sar);
    BINOP(sbb, );
    SHIFT(shl);
    SHIFT(shr);
    BINOP(sub, );
    BINOP(xor, );

#undef UNOP
#undef BINOP
#undef SHIFT

    case rmw_not:
        switch ( state->op_bytes )
        {
        case 1:
            asm ( COND_LOCK(notb) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
        case 2:
            asm ( COND_LOCK(notw) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
        case 4:
            asm ( COND_LOCK(notl) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
#ifdef __x86_64__
        case 8:
            asm ( COND_LOCK(notq) " %0"
                  : "+m" (*dst) : "c" ((long)state->lock_prefix) );
            break;
#endif
        }
        break;

    case rmw_shld:
        ASSERT(!state->lock_prefix);
        _emulate_2op_SrcV_nobyte("shld",
                                 state->ea.val, dst, bytes, *eflags,
                                 "c" (state->ea.orig_val) );
        break;

    case rmw_shrd:
        ASSERT(!state->lock_prefix);
        _emulate_2op_SrcV_nobyte("shrd",
                                 state->ea.val, dst, bytes, *eflags,
                                 "c" (state->ea.orig_val) );
        break;

    case rmw_xadd:
        switch ( state->op_bytes )
        {
            unsigned long dummy;

#define XADD(sz, cst, mod) \
        case sz: \
            asm ( _PRE_EFLAGS("[efl]", "[msk]", "[tmp]") \
                  COND_LOCK(xadd) " %"#mod"[reg], %[mem]; " \
                  _POST_EFLAGS("[efl]", "[msk]", "[tmp]") \
                  : [reg] "+" #cst (state->ea.val), \
                    [mem] "+m" (*dst), \
                    [efl] "+g" (*eflags), \
                    [tmp] "=&r" (dummy) \
                  : "c" ((long)state->lock_prefix), \
                    [msk] "i" (EFLAGS_MASK) ); \
            break
        XADD(1, q, b);
        XADD(2, r, w);
        XADD(4, r, k);
#ifdef __x86_64__
        XADD(8, r, );
#endif
#undef XADD
        }
        break;

    case rmw_xchg:
        switch ( state->op_bytes )
        {
        case 1:
            asm ( "xchg %b0, %b1" : "+q" (state->ea.val), "+m" (*dst) );
            break;
        case 2:
            asm ( "xchg %w0, %w1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        case 4:
#ifdef __x86_64__
            asm ( "xchg %k0, %k1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        case 8:
#endif
            asm ( "xchg %0, %1" : "+r" (state->ea.val), "+m" (*dst) );
            break;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

#undef COND_LOCK
#undef JCXZ

    return X86EMUL_OKAY;
}

static void __init __maybe_unused build_assertions(void)
{
    /* Check the values against SReg3 encoding in opcode/ModRM bytes. */
    BUILD_BUG_ON(x86_seg_es != 0);
    BUILD_BUG_ON(x86_seg_cs != 1);
    BUILD_BUG_ON(x86_seg_ss != 2);
    BUILD_BUG_ON(x86_seg_ds != 3);
    BUILD_BUG_ON(x86_seg_fs != 4);
    BUILD_BUG_ON(x86_seg_gs != 5);

    /*
     * Check X86_EVENTTYPE_* against VMCB EVENTINJ and VMCS INTR_INFO type
     * fields.
     */
    BUILD_BUG_ON(X86_EVENTTYPE_EXT_INTR != 0);
    BUILD_BUG_ON(X86_EVENTTYPE_NMI != 2);
    BUILD_BUG_ON(X86_EVENTTYPE_HW_EXCEPTION != 3);
    BUILD_BUG_ON(X86_EVENTTYPE_SW_INTERRUPT != 4);
    BUILD_BUG_ON(X86_EVENTTYPE_PRI_SW_EXCEPTION != 5);
    BUILD_BUG_ON(X86_EVENTTYPE_SW_EXCEPTION != 6);
}

#ifndef NDEBUG
/*
 * In debug builds, wrap x86_emulate() with some assertions about its expected
 * behaviour.
 */
int x86_emulate_wrapper(
    struct x86_emulate_ctxt *ctxt,
    const struct x86_emulate_ops *ops)
{
    unsigned long orig_ip = ctxt->regs->r(ip);
    int rc;

    if ( mode_64bit() )
        ASSERT(ctxt->lma);

    rc = x86_emulate(ctxt, ops);

    /*
     * Most retire flags should only be set for successful instruction
     * emulation.
     */
    if ( rc != X86EMUL_OKAY )
    {
        typeof(ctxt->retire) retire = ctxt->retire;

        retire.unblock_nmi = false;
        ASSERT(!retire.raw);
    }

    /* All cases returning X86EMUL_EXCEPTION should have fault semantics. */
    if ( rc == X86EMUL_EXCEPTION )
        ASSERT(ctxt->regs->r(ip) == orig_ip);

    /*
     * An event being pending should exactly match returning
     * X86EMUL_EXCEPTION.  (If this trips, the chances are a codepath has
     * called hvm_inject_hw_exception() rather than using
     * x86_emul_hw_exception().)
     */
    ASSERT(ctxt->event_pending == (rc == X86EMUL_EXCEPTION));

    return rc;
}
#endif

#ifdef __XEN__

#include <xen/err.h>

struct x86_emulate_state *
x86_decode_insn(
    struct x86_emulate_ctxt *ctxt,
    int (*insn_fetch)(
        enum x86_segment seg, unsigned long offset,
        void *p_data, unsigned int bytes,
        struct x86_emulate_ctxt *ctxt))
{
    static DEFINE_PER_CPU(struct x86_emulate_state, state);
    struct x86_emulate_state *state = &this_cpu(state);
    const struct x86_emulate_ops ops = {
        .insn_fetch = insn_fetch,
        .read       = x86emul_unhandleable_rw,
    };
    int rc = x86_decode(state, ctxt, &ops);

    if ( unlikely(rc != X86EMUL_OKAY) )
        return ERR_PTR(-rc);

#ifndef NDEBUG
    /*
     * While we avoid memory allocation (by use of per-CPU data) above,
     * nevertheless make sure callers properly release the state structure
     * for forward compatibility.
     */
    if ( state->caller )
    {
        printk(XENLOG_ERR "Unreleased emulation state acquired by %ps\n",
               state->caller);
        dump_execution_state();
    }
    state->caller = __builtin_return_address(0);
#endif

    return state;
}

static inline void check_state(const struct x86_emulate_state *state)
{
#ifndef NDEBUG
    ASSERT(state->caller);
#endif
}

#ifndef NDEBUG
void x86_emulate_free_state(struct x86_emulate_state *state)
{
    check_state(state);
    state->caller = NULL;
}
#endif

unsigned int
x86_insn_opsize(const struct x86_emulate_state *state)
{
    check_state(state);

    return state->op_bytes << 3;
}

int
x86_insn_modrm(const struct x86_emulate_state *state,
               unsigned int *rm, unsigned int *reg)
{
    check_state(state);

    if ( unlikely(state->modrm_mod > 3) )
    {
        if ( rm )
            *rm = ~0U;
        if ( reg )
            *reg = ~0U;
        return -EINVAL;
    }

    if ( rm )
        *rm = state->modrm_rm;
    if ( reg )
        *reg = state->modrm_reg;

    return state->modrm_mod;
}

unsigned long
x86_insn_operand_ea(const struct x86_emulate_state *state,
                    enum x86_segment *seg)
{
    *seg = state->ea.type == OP_MEM ? state->ea.mem.seg : x86_seg_none;

    check_state(state);

    return state->ea.mem.off;
}

bool
x86_insn_is_mem_access(const struct x86_emulate_state *state,
                       const struct x86_emulate_ctxt *ctxt)
{
    if ( state->ea.type == OP_MEM )
        return ctxt->opcode != 0x8d /* LEA */ &&
               (ctxt->opcode != X86EMUL_OPC(0x0f, 0x01) ||
                (state->modrm_reg & 7) != 7) /* INVLPG */;

    switch ( ctxt->opcode )
    {
    case 0x6c ... 0x6f: /* INS / OUTS */
    case 0xa4 ... 0xa7: /* MOVS / CMPS */
    case 0xaa ... 0xaf: /* STOS / LODS / SCAS */
    case 0xd7:          /* XLAT */
    CASE_SIMD_PACKED_INT(0x0f, 0xf7):    /* MASKMOV{Q,DQU} */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf7): /* VMASKMOVDQU */
        return true;

    case X86EMUL_OPC(0x0f, 0x01):
        /* Cover CLZERO. */
        return (state->modrm_rm & 7) == 4 && (state->modrm_reg & 7) == 7;
    }

    return false;
}

bool
x86_insn_is_mem_write(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt)
{
    switch ( state->desc & DstMask )
    {
    case DstMem:
        /* The SrcMem check is to cover {,V}MASKMOV{Q,DQU}. */
        return state->modrm_mod != 3 || (state->desc & SrcMask) == SrcMem;

    case DstBitBase:
    case DstImplicit:
        break;

    default:
        return false;
    }

    if ( state->modrm_mod == 3 )
        /* CLZERO is the odd one. */
        return ctxt->opcode == X86EMUL_OPC(0x0f, 0x01) &&
               (state->modrm_rm & 7) == 4 && (state->modrm_reg & 7) == 7;

    switch ( ctxt->opcode )
    {
    case 0x6c: case 0x6d:                /* INS */
    case 0xa4: case 0xa5:                /* MOVS */
    case 0xaa: case 0xab:                /* STOS */
    case X86EMUL_OPC(0x0f, 0xab):        /* BTS */
    case X86EMUL_OPC(0x0f, 0xb3):        /* BTR */
    case X86EMUL_OPC(0x0f, 0xbb):        /* BTC */
        return true;

    case 0xd9:
        switch ( state->modrm_reg & 7 )
        {
        case 2: /* FST m32fp */
        case 3: /* FSTP m32fp */
        case 6: /* FNSTENV */
        case 7: /* FNSTCW */
            return true;
        }
        break;

    case 0xdb:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m32i */
        case 2: /* FIST m32i */
        case 3: /* FISTP m32i */
        case 7: /* FSTP m80fp */
            return true;
        }
        break;

    case 0xdd:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m64i */
        case 2: /* FST m64fp */
        case 3: /* FSTP m64fp */
        case 6: /* FNSAVE */
        case 7: /* FNSTSW */
            return true;
        }
        break;

    case 0xdf:
        switch ( state->modrm_reg & 7 )
        {
        case 1: /* FISTTP m16i */
        case 2: /* FIST m16i */
        case 3: /* FISTP m16i */
        case 6: /* FBSTP */
        case 7: /* FISTP m64i */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        return !(state->modrm_reg & 6); /* SGDT / SIDT */

    case X86EMUL_OPC(0x0f, 0xba):
        return (state->modrm_reg & 7) > 4; /* BTS / BTR / BTC */

    case X86EMUL_OPC(0x0f, 0xc7):
        return (state->modrm_reg & 7) == 1; /* CMPXCHG{8,16}B */
    }

    return false;
}

bool
x86_insn_is_portio(const struct x86_emulate_state *state,
                   const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
    case 0x6c ... 0x6f: /* INS / OUTS */
    case 0xe4 ... 0xe7: /* IN / OUT imm8 */
    case 0xec ... 0xef: /* IN / OUT %dx */
        return true;
    }

    return false;
}

bool
x86_insn_is_cr_access(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
        unsigned int ext;

    case X86EMUL_OPC(0x0f, 0x01):
        if ( x86_insn_modrm(state, NULL, &ext) >= 0
             && (ext & 5) == 4 ) /* SMSW / LMSW */
            return true;
        break;

    case X86EMUL_OPC(0x0f, 0x06): /* CLTS */
    case X86EMUL_OPC(0x0f, 0x20): /* MOV from CRn */
    case X86EMUL_OPC(0x0f, 0x22): /* MOV to CRn */
        return true;
    }

    return false;
}

unsigned long
x86_insn_immediate(const struct x86_emulate_state *state, unsigned int nr)
{
    check_state(state);

    switch ( nr )
    {
    case 0:
        return state->imm1;
    case 1:
        return state->imm2;
    }

    return 0;
}

unsigned int
x86_insn_length(const struct x86_emulate_state *state,
                const struct x86_emulate_ctxt *ctxt)
{
    check_state(state);

    return state->ip - ctxt->regs->r(ip);
}

#endif
