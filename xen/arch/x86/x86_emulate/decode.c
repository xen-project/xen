/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * decode.c - helper for x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 */

#include "private.h"

#ifdef __XEN__
# include <xen/err.h>
#else
# define ERR_PTR(val) NULL
#endif

#define evex_encoded() (s->evex.mbs)

struct x86_emulate_state *
x86_decode_insn(
    struct x86_emulate_ctxt *ctxt,
    int (*insn_fetch)(
        unsigned long offset, void *p_data, unsigned int bytes,
        struct x86_emulate_ctxt *ctxt))
{
    static DEFINE_PER_CPU(struct x86_emulate_state, state);
    struct x86_emulate_state *s = &this_cpu(state);
    const struct x86_emulate_ops ops = {
        .insn_fetch = insn_fetch,
        .read       = x86emul_unhandleable_rw,
    };
    int rc;

    init_context(ctxt);

    rc = x86emul_decode(s, ctxt, &ops);
    if ( unlikely(rc != X86EMUL_OKAY) )
        return ERR_PTR(-rc);

#if defined(__XEN__) && !defined(NDEBUG)
    /*
     * While we avoid memory allocation (by use of per-CPU data) above,
     * nevertheless make sure callers properly release the state structure
     * for forward compatibility.
     */
    if ( s->caller )
    {
        printk(XENLOG_ERR "Unreleased emulation state acquired by %ps\n",
               s->caller);
        dump_execution_state();
    }
    s->caller = __builtin_return_address(0);
#endif

    return s;
}

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
    ByteOp|DstReg|SrcMem|ModRM, DstReg|SrcMem|ModRM,
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

static const struct twobyte_table {
    opcode_desc_t desc;
    simd_opsize_t size:4;
    disp8scale_t d8s:4;
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
    [0x10] = { DstImplicit|SrcMem|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x11] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x12] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, 3 },
    [0x13] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0x14 ... 0x15] = { DstImplicit|SrcMem|ModRM, simd_packed_fp, d8s_vl },
    [0x16] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, 3 },
    [0x17] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0x18 ... 0x1c] = { ImplicitOps|ModRM },
    [0x1d] = { ImplicitOps|ModRM, simd_none, d8s_vl },
    [0x1e ... 0x1f] = { ImplicitOps|ModRM },
    [0x20 ... 0x21] = { DstMem|SrcImplicit|ModRM },
    [0x22 ... 0x23] = { DstImplicit|SrcMem|ModRM },
    [0x28] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x29] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x2a] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_dq64 },
    [0x2b] = { DstMem|SrcImplicit|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x2c ... 0x2d] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0x2e ... 0x2f] = { ImplicitOps|ModRM|TwoOp, simd_none, d8s_dq },
    [0x30 ... 0x35] = { ImplicitOps },
    [0x37] = { ImplicitOps },
    [0x38] = { DstReg|SrcMem|ModRM },
    [0x3a] = { DstReg|SrcImmByte|ModRM },
    [0x40 ... 0x4f] = { DstReg|SrcMem|ModRM|Mov },
    [0x50] = { DstReg|SrcImplicit|ModRM|Mov },
    [0x51] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_any_fp, d8s_vl },
    [0x52 ... 0x53] = { DstImplicit|SrcMem|ModRM|TwoOp, simd_single_fp },
    [0x54 ... 0x57] = { DstImplicit|SrcMem|ModRM, simd_packed_fp, d8s_vl },
    [0x58 ... 0x59] = { DstImplicit|SrcMem|ModRM, simd_any_fp, d8s_vl },
    [0x5a] = { DstImplicit|SrcMem|ModRM|Mov, simd_any_fp, d8s_vl },
    [0x5b] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x5c ... 0x5f] = { DstImplicit|SrcMem|ModRM, simd_any_fp, d8s_vl },
    [0x60 ... 0x62] = { DstImplicit|SrcMem|ModRM, simd_other, d8s_vl },
    [0x63 ... 0x67] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x68 ... 0x6a] = { DstImplicit|SrcMem|ModRM, simd_other, d8s_vl },
    [0x6b ... 0x6d] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x6e] = { DstImplicit|SrcMem|ModRM|Mov, simd_none, d8s_dq64 },
    [0x6f] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_int, d8s_vl },
    [0x70] = { SrcImmByte|ModRM|TwoOp, simd_other, d8s_vl },
    [0x71 ... 0x73] = { DstImplicit|SrcImmByte|ModRM, simd_none, d8s_vl },
    [0x74 ... 0x76] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0x77] = { DstImplicit|SrcNone },
    [0x78 ... 0x79] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_vl },
    [0x7a] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0x7b] = { DstImplicit|SrcMem|ModRM|Mov, simd_other, d8s_dq64 },
    [0x7c ... 0x7d] = { DstImplicit|SrcMem|ModRM, simd_other, d8s_vl },
    [0x7e] = { DstMem|SrcImplicit|ModRM|Mov, simd_none, d8s_dq64 },
    [0x7f] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int, d8s_vl },
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
    [0xc2] = { DstImplicit|SrcImmByte|ModRM, simd_any_fp, d8s_vl },
    [0xc3] = { DstMem|SrcReg|ModRM|Mov },
    [0xc4] = { DstImplicit|SrcImmByte|ModRM, simd_none, 1 },
    [0xc5] = { DstReg|SrcImmByte|ModRM|Mov },
    [0xc6] = { DstImplicit|SrcImmByte|ModRM, simd_packed_fp, d8s_vl },
    [0xc7] = { ImplicitOps|ModRM },
    [0xc8 ... 0xcf] = { ImplicitOps },
    [0xd0] = { DstImplicit|SrcMem|ModRM, simd_other },
    [0xd1 ... 0xd3] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xd4 ... 0xd5] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xd6] = { DstMem|SrcImplicit|ModRM|Mov, simd_other, 3 },
    [0xd7] = { DstReg|SrcImplicit|ModRM|Mov },
    [0xd8 ... 0xdf] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe0] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe1 ... 0xe2] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xe3 ... 0xe5] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xe6] = { DstImplicit|SrcMem|ModRM|Mov, simd_packed_fp, d8s_vl },
    [0xe7] = { DstMem|SrcImplicit|ModRM|Mov, simd_packed_int, d8s_vl },
    [0xe8 ... 0xef] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xf0] = { DstImplicit|SrcMem|ModRM|Mov, simd_other },
    [0xf1 ... 0xf3] = { DstImplicit|SrcMem|ModRM, simd_128, 4 },
    [0xf4 ... 0xf6] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xf7] = { DstMem|SrcMem|ModRM|Mov, simd_packed_int },
    [0xf8 ... 0xfe] = { DstImplicit|SrcMem|ModRM, simd_packed_int, d8s_vl },
    [0xff] = { ModRM }
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
    disp8scale_t d8s:4;
} ext0f38_table[256] = {
    [0x00] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x01 ... 0x03] = { .simd_size = simd_packed_int },
    [0x04] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x05 ... 0x0a] = { .simd_size = simd_packed_int },
    [0x0b] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x0c ... 0x0d] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x0e ... 0x0f] = { .simd_size = simd_packed_fp },
    [0x10 ... 0x12] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x13] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x14 ... 0x16] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x17] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x18] = { .simd_size = simd_scalar_opc, .two_op = 1, .d8s = 2 },
    [0x19] = { .simd_size = simd_scalar_opc, .two_op = 1, .d8s = 3 },
    [0x1a] = { .simd_size = simd_128, .two_op = 1, .d8s = 4 },
    [0x1b] = { .simd_size = simd_256, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1c ... 0x1f] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x20] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x21] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x22] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_8 },
    [0x23] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x24] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x25] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x26 ... 0x29] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x2a] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x2b] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x2c] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x2d] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x2e ... 0x2f] = { .simd_size = simd_packed_fp, .to_mem = 1 },
    [0x30] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x31] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x32] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_8 },
    [0x33] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x34] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_4 },
    [0x35] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x36 ... 0x3f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x40] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x41] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x42] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x43] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x44] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x45 ... 0x47] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x4c] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x4d] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x4e] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x4f] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x50 ... 0x53] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x54 ... 0x55] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x56] = { .simd_size = simd_other, .d8s = d8s_vl },
    [0x57] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x58] = { .simd_size = simd_other, .two_op = 1, .d8s = 2 },
    [0x59] = { .simd_size = simd_other, .two_op = 1, .d8s = 3 },
    [0x5a] = { .simd_size = simd_128, .two_op = 1, .d8s = 4 },
    [0x5b] = { .simd_size = simd_256, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x62] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_bw },
    [0x63] = { .simd_size = simd_packed_int, .to_mem = 1, .two_op = 1, .d8s = d8s_bw },
    [0x64 ... 0x66] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x68] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x70 ... 0x73] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x75 ... 0x76] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x77] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x78] = { .simd_size = simd_other, .two_op = 1 },
    [0x79] = { .simd_size = simd_other, .two_op = 1, .d8s = 1 },
    [0x7a ... 0x7c] = { .simd_size = simd_none, .two_op = 1 },
    [0x7d ... 0x7e] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x7f] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x82] = { .simd_size = simd_other },
    [0x83] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x88] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_dq },
    [0x89] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_dq },
    [0x8a] = { .simd_size = simd_packed_fp, .to_mem = 1, .two_op = 1, .d8s = d8s_dq },
    [0x8b] = { .simd_size = simd_packed_int, .to_mem = 1, .two_op = 1, .d8s = d8s_dq },
    [0x8c] = { .simd_size = simd_packed_int },
    [0x8d] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x8e] = { .simd_size = simd_packed_int, .to_mem = 1 },
    [0x8f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x90 ... 0x93] = { .simd_size = simd_other, .vsib = 1, .d8s = d8s_dq },
    [0x96 ... 0x98] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x99] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9a] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9b] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9c] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9d] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x9e] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x9f] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xa0 ... 0xa3] = { .simd_size = simd_other, .to_mem = 1, .vsib = 1, .d8s = d8s_dq },
    [0xa6 ... 0xa8] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xa9] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xaa] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xab] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xac] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xad] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xae] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xaf] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xb0] = { .simd_size = simd_other, .two_op = 1 },
    [0xb1] = { .simd_size = simd_other, .two_op = 1 },
    [0xb4 ... 0xb5] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xb6 ... 0xb8] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xb9] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xba] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbb] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xbc] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbd] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xbe] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0xbf] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xc4] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0xc8] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0xc9] = { .simd_size = simd_other },
    [0xca] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0xcb] = { .simd_size = simd_other, .d8s = d8s_vl },
    [0xcc ... 0xcd] = { .simd_size = simd_other, .two_op = 1, .d8s = d8s_vl },
    [0xcf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xd2] = { .simd_size = simd_other },
    [0xd3] = { .simd_size = simd_other },
    [0xd6] = { .simd_size = simd_other, .d8s = d8s_vl },
    [0xd7] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0xda] = { .simd_size = simd_other },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdc ... 0xdf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xe0 ... 0xef] = { .to_mem = 1 },
    [0xf0] = { .two_op = 1 },
    [0xf1] = { .to_mem = 1, .two_op = 1 },
    [0xf2 ... 0xf3] = {},
    [0xf5 ... 0xf7] = {},
    [0xf8] = { .simd_size = simd_other },
    [0xf9] = { .to_mem = 1, .two_op = 1 /* Mov */ },
};

static const struct ext0f3a_table {
    uint8_t simd_size:5;
    uint8_t to_mem:1;
    uint8_t two_op:1;
    uint8_t four_op:1;
    disp8scale_t d8s:4;
} ext0f3a_table[256] = {
    [0x00] = { .simd_size = simd_packed_int, .two_op = 1, .d8s = d8s_vl },
    [0x01] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x02] = { .simd_size = simd_packed_int },
    [0x03] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x04 ... 0x05] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x06] = { .simd_size = simd_packed_fp },
    [0x08 ... 0x09] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x0a ... 0x0b] = { .simd_size = simd_scalar_opc, .d8s = d8s_dq },
    [0x0c ... 0x0d] = { .simd_size = simd_packed_fp },
    [0x0e] = { .simd_size = simd_packed_int },
    [0x0f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x14] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 0 },
    [0x15] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 1 },
    [0x16] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = d8s_dq64 },
    [0x17] = { .simd_size = simd_none, .to_mem = 1, .two_op = 1, .d8s = 2 },
    [0x18] = { .simd_size = simd_128, .d8s = 4 },
    [0x19] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1, .d8s = 4 },
    [0x1a] = { .simd_size = simd_256, .d8s = d8s_vl_by_2 },
    [0x1b] = { .simd_size = simd_256, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1d] = { .simd_size = simd_other, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x1e ... 0x1f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x20] = { .simd_size = simd_none, .d8s = 0 },
    [0x21] = { .simd_size = simd_other, .d8s = 2 },
    [0x22] = { .simd_size = simd_none, .d8s = d8s_dq64 },
    [0x23] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x25] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x26] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x27] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x30 ... 0x33] = { .simd_size = simd_other, .two_op = 1 },
    [0x38] = { .simd_size = simd_128, .d8s = 4 },
    [0x3a] = { .simd_size = simd_256, .d8s = d8s_vl_by_2 },
    [0x39] = { .simd_size = simd_128, .to_mem = 1, .two_op = 1, .d8s = 4 },
    [0x3b] = { .simd_size = simd_256, .to_mem = 1, .two_op = 1, .d8s = d8s_vl_by_2 },
    [0x3e ... 0x3f] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x40 ... 0x41] = { .simd_size = simd_packed_fp },
    [0x42 ... 0x43] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x44] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x46] = { .simd_size = simd_packed_int },
    [0x48 ... 0x49] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4a ... 0x4b] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x4c] = { .simd_size = simd_packed_int, .four_op = 1 },
    [0x50] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x51] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x54] = { .simd_size = simd_packed_fp, .d8s = d8s_vl },
    [0x55] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x56] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x57] = { .simd_size = simd_scalar_vexw, .d8s = d8s_dq },
    [0x5c ... 0x5f] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x60 ... 0x63] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0x66] = { .simd_size = simd_packed_fp, .two_op = 1, .d8s = d8s_vl },
    [0x67] = { .simd_size = simd_scalar_vexw, .two_op = 1, .d8s = d8s_dq },
    [0x68 ... 0x69] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6a ... 0x6b] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x6c ... 0x6d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x6e ... 0x6f] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x70 ... 0x73] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0x78 ... 0x79] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7a ... 0x7b] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0x7c ... 0x7d] = { .simd_size = simd_packed_fp, .four_op = 1 },
    [0x7e ... 0x7f] = { .simd_size = simd_scalar_opc, .four_op = 1 },
    [0xc2] = { .simd_size = simd_any_fp, .d8s = d8s_vl },
    [0xcc] = { .simd_size = simd_other },
    [0xce ... 0xcf] = { .simd_size = simd_packed_int, .d8s = d8s_vl },
    [0xde] = { .simd_size = simd_other },
    [0xdf] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xf0] = { .two_op = 1 /* Mov */ },
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
    [0x82 ... 0x83] = { .simd_size = simd_scalar_opc, .two_op = 1 },
    [0x90 ... 0x9b] = { .simd_size = simd_packed_int },
    [0xc1 ... 0xc3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xc6 ... 0xc7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xcb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd1 ... 0xd3] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xd6 ... 0xd7] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xdb] = { .simd_size = simd_packed_int, .two_op = 1 },
    [0xe1 ... 0xe3] = { .simd_size = simd_packed_int, .two_op = 1 },
};

static unsigned int decode_disp8scale(enum disp8scale scale,
                                      const struct x86_emulate_state *s)
{
    switch ( scale )
    {
    case d8s_bw:
        return s->evex.w;

    default:
        if ( scale < d8s_vl )
            return scale;
        if ( s->evex.brs )
        {
    case d8s_dq:
            return 1 + !s->fp16 + s->evex.w;
        }
        break;

    case d8s_dq64:
        return 1 + !s->fp16 + (s->op_bytes == 8);
    }

    switch ( s->simd_size )
    {
    case simd_any_fp:
    case simd_single_fp:
        if ( !(s->evex.pfx & VEX_PREFIX_SCALAR_MASK) )
            break;
        /* fall through */
    case simd_scalar_opc:
    case simd_scalar_vexw:
        return 1 + !s->fp16 + s->evex.w;

    case simd_128:
        /* These should have an explicit size specified. */
        ASSERT_UNREACHABLE();
        return 4;

    default:
        break;
    }

    return 4 + s->evex.lr - (scale - d8s_vl);
}

/* Fetch next part of the instruction being emulated. */
#define insn_fetch_bytes(_size) ({                                    \
   unsigned long _x = 0, _ip = s->ip;                                 \
   s->ip += (_size); /* real hardware doesn't truncate */             \
   generate_exception_if((uint8_t)(s->ip -                            \
                                   ctxt->regs->r(ip)) > MAX_INST_LEN, \
                         X86_EXC_GP, 0);                              \
   rc = ops->insn_fetch(_ip, &_x, _size, ctxt);                       \
   if ( rc ) goto done;                                               \
   _x;                                                                \
})
#define insn_fetch_type(type) ((type)insn_fetch_bytes(sizeof(type)))

static int
decode_onebyte(struct x86_emulate_state *s,
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
    case 0xc4: /* les */
    case 0xc5: /* lds */
    case 0xce: /* into */
    case 0xd4: /* aam */
    case 0xd5: /* aad */
    case 0xd6: /* salc */
        s->not_64bit = true;
        break;

    case 0x82: /* Grp1 (x86/32 only) */
        s->not_64bit = true;
        /* fall through */
    case 0x80: case 0x81: case 0x83: /* Grp1 */
        if ( (s->modrm_reg & 7) == 7 ) /* cmp */
            s->desc = (s->desc & ByteOp) | DstNone | SrcMem;
        break;

    case 0x90: /* nop / pause */
        if ( s->vex.pfx == vex_f3 )
            ctxt->opcode |= X86EMUL_OPC_F3(0, 0);
        break;

    case 0x9a: /* call (far, absolute) */
    case 0xea: /* jmp (far, absolute) */
        generate_exception_if(mode_64bit(), X86_EXC_UD);

        s->imm1 = insn_fetch_bytes(s->op_bytes);
        s->imm2 = insn_fetch_type(uint16_t);
        break;

    case 0xa0: case 0xa1: /* mov mem.offs,{%al,%ax,%eax,%rax} */
    case 0xa2: case 0xa3: /* mov {%al,%ax,%eax,%rax},mem.offs */
        /* Source EA is not encoded via ModRM. */
        s->ea.type = OP_MEM;
        s->ea.mem.off = insn_fetch_bytes(s->ad_bytes);
        break;

    case 0xb8 ... 0xbf: /* mov imm{16,32,64},r{16,32,64} */
        if ( s->op_bytes == 8 ) /* Fetch more bytes to obtain imm64. */
            s->imm1 = ((uint32_t)s->imm1 |
                       ((uint64_t)insn_fetch_type(uint32_t) << 32));
        break;

    case 0xc8: /* enter imm16,imm8 */
        s->imm2 = insn_fetch_type(uint8_t);
        break;

    case 0xf6: case 0xf7: /* Grp3 */
        if ( !(s->modrm_reg & 6) ) /* test */
            s->desc = (s->desc & ByteOp) | DstNone | SrcMem;
        break;

    case 0xff: /* Grp5 */
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* call (near) */
        case 4: /* jmp (near) */
            if ( mode_64bit() && (s->op_bytes == 4 || !amd_like(ctxt)) )
                s->op_bytes = 8;
            s->desc = DstNone | SrcMem | Mov;
            break;

        case 3: /* call (far, absolute indirect) */
        case 5: /* jmp (far, absolute indirect) */
            /* REX.W ignored on a vendor-dependent basis. */
            if ( s->op_bytes == 8 && amd_like(ctxt) )
                s->op_bytes = 4;
            s->desc = DstNone | SrcMem | Mov;
            break;

        case 6: /* push */
            if ( mode_64bit() && s->op_bytes == 4 )
                s->op_bytes = 8;
            s->desc = DstNone | SrcMem | Mov;
            break;
        }
        break;
    }

 done:
    return rc;
}

static int
decode_twobyte(struct x86_emulate_state *s,
               struct x86_emulate_ctxt *ctxt,
               const struct x86_emulate_ops *ops)
{
    int rc = X86EMUL_OKAY;

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x00: /* Grp6 */
        switch ( s->modrm_reg & 6 )
        {
        case 0:
            s->desc |= DstMem | SrcImplicit | Mov;
            break;
        case 2: case 4:
            s->desc |= SrcMem16;
            break;
        }
        break;

    case 0x78:
        s->desc = ImplicitOps;
        s->simd_size = simd_none;
        switch ( s->vex.pfx )
        {
        case vex_66: /* extrq $imm8, $imm8, xmm */
        case vex_f2: /* insertq $imm8, $imm8, xmm, xmm */
            s->imm1 = insn_fetch_type(uint8_t);
            s->imm2 = insn_fetch_type(uint8_t);
            break;
        }
        /* fall through */
    case 0x10 ... 0x18:
    case 0x28 ... 0x2f:
    case 0x50 ... 0x77:
    case 0x7a ... 0x7d:
    case 0x7f:
    case 0xc2 ... 0xc3:
    case 0xc5 ... 0xc6:
    case 0xd0 ... 0xef:
    case 0xf1 ... 0xfe:
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0x20: case 0x22: /* mov to/from cr */
        if ( s->lock_prefix && vcpu_has_cr8_legacy() )
        {
            s->modrm_reg += 8;
            s->lock_prefix = false;
        }
        /* fall through */
    case 0x21: case 0x23: /* mov to/from dr */
        ASSERT(s->ea.type == OP_REG); /* Early operand adjustment ensures this. */
        generate_exception_if(s->lock_prefix, X86_EXC_UD);
        s->op_bytes = mode_64bit() ? 8 : 4;
        break;

    case 0x79:
        s->desc = DstReg | SrcMem;
        s->simd_size = simd_packed_int;
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0x7e:
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( s->vex.pfx == vex_f3 ) /* movq xmm/m64,xmm */
        {
    case X86EMUL_OPC_VEX_F3(0, 0x7e): /* vmovq xmm/m64,xmm */
    case X86EMUL_OPC_EVEX_F3(0, 0x7e): /* vmovq xmm/m64,xmm */
            s->desc = DstImplicit | SrcMem | TwoOp;
            s->simd_size = simd_other;
            /* Avoid the s->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;

    case X86EMUL_OPC_VEX(0, 0x90):    /* kmov{w,q} */
    case X86EMUL_OPC_VEX_66(0, 0x90): /* kmov{b,d} */
        s->desc = DstReg | SrcMem | Mov;
        s->simd_size = simd_other;
        break;

    case X86EMUL_OPC_VEX(0, 0x91):    /* kmov{w,q} */
    case X86EMUL_OPC_VEX_66(0, 0x91): /* kmov{b,d} */
        s->desc = DstMem | SrcReg | Mov;
        s->simd_size = simd_other;
        break;

    case 0xae:
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX(0, 0xae):
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* {,v}ldmxcsr */
            s->desc = DstImplicit | SrcMem | Mov;
            s->op_bytes = 4;
            break;

        case 3: /* {,v}stmxcsr */
            s->desc = DstMem | SrcImplicit | Mov;
            s->op_bytes = 4;
            break;
        }
        break;

    case 0xb2: /* lss */
    case 0xb4: /* lfs */
    case 0xb5: /* lgs */
        /* REX.W ignored on a vendor-dependent basis. */
        if ( s->op_bytes == 8 && amd_like(ctxt) )
            s->op_bytes = 4;
        break;

    case 0xb8: /* jmpe / popcnt */
        if ( s->vex.pfx >= vex_f3 )
            ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

        /* Intentionally not handling here despite being modified by F3:
    case 0xbc: bsf / tzcnt
    case 0xbd: bsr / lzcnt
         * They're being dealt with in the execution phase (if at all).
         */

    case 0xc4: /* pinsrw */
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        /* fall through */
    case X86EMUL_OPC_VEX_66(0, 0xc4): /* vpinsrw */
    case X86EMUL_OPC_EVEX_66(0, 0xc4): /* vpinsrw */
        s->desc = DstImplicit | SrcMem16;
        break;

    case 0xf0:
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        if ( s->vex.pfx == vex_f2 ) /* lddqu mem,xmm */
        {
        /* fall through */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* vlddqu mem,{x,y}mm */
            s->desc = DstImplicit | SrcMem | TwoOp;
            s->simd_size = simd_other;
            /* Avoid the s->desc clobbering of TwoOp below. */
            return X86EMUL_OKAY;
        }
        break;
    }

    /*
     * Scalar forms of most VEX-/EVEX-encoded TwoOp instructions have
     * three operands.  Those which do really have two operands
     * should have exited earlier.
     */
    if ( s->simd_size && s->vex.opcx &&
         (s->vex.pfx & VEX_PREFIX_SCALAR_MASK) )
        s->desc &= ~TwoOp;

 done:
    return rc;
}

static int
decode_0f38(struct x86_emulate_state *s,
            struct x86_emulate_ctxt *ctxt,
            const struct x86_emulate_ops *ops)
{
    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case 0x00 ... 0xef:
    case 0xf2 ... 0xf5:
    case 0xf7 ... 0xf8:
    case 0xfa ... 0xff:
        s->op_bytes = 0;
        /* fall through */
    case 0xf6: /* adcx / adox */
    case 0xf9: /* movdiri */
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case X86EMUL_OPC_VEX_66(0, 0x2d): /* vmaskmovpd */
        s->simd_size = simd_packed_fp;
        break;

    case X86EMUL_OPC_EVEX_66(0, 0x7a): /* vpbroadcastb */
    case X86EMUL_OPC_EVEX_66(0, 0x7b): /* vpbroadcastw */
    case X86EMUL_OPC_EVEX_66(0, 0x7c): /* vpbroadcast{d,q} */
        break;

    case 0xf0: /* movbe / crc32 */
        s->desc |= s->vex.pfx == vex_f2 ? ByteOp : Mov;
        if ( s->vex.pfx >= vex_f3 )
            ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case 0xf1: /* movbe / crc32 */
        if ( s->vex.pfx == vex_f2 )
            s->desc = DstReg | SrcMem;
        if ( s->vex.pfx >= vex_f3 )
            ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);
        break;

    case X86EMUL_OPC_VEX_66(0, 0xe0) ...
         X86EMUL_OPC_VEX_66(0, 0xef): /* cmp<cc>xadd */
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
        s->op_bytes = 0;
        break;
    }

    return X86EMUL_OKAY;
}

static int
decode_0f3a(struct x86_emulate_state *s,
            struct x86_emulate_ctxt *ctxt,
            const struct x86_emulate_ops *ops)
{
    if ( !s->vex.opcx )
        ctxt->opcode |= MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);

    switch ( ctxt->opcode & X86EMUL_OPC_MASK )
    {
    case X86EMUL_OPC_66(0, 0x14)
     ... X86EMUL_OPC_66(0, 0x17):     /* pextr*, extractps */
    case X86EMUL_OPC_VEX_66(0, 0x14)
     ... X86EMUL_OPC_VEX_66(0, 0x17): /* vpextr*, vextractps */
    case X86EMUL_OPC_EVEX_66(0, 0x14)
     ... X86EMUL_OPC_EVEX_66(0, 0x17): /* vpextr*, vextractps */
    case X86EMUL_OPC_VEX_F2(0, 0xf0): /* rorx */
        break;

    case X86EMUL_OPC_66(0, 0x20):     /* pinsrb */
    case X86EMUL_OPC_VEX_66(0, 0x20): /* vpinsrb */
    case X86EMUL_OPC_EVEX_66(0, 0x20): /* vpinsrb */
        s->desc = DstImplicit | SrcMem;
        if ( s->modrm_mod != 3 )
            s->desc |= ByteOp;
        break;

    case X86EMUL_OPC_66(0, 0x22):     /* pinsr{d,q} */
    case X86EMUL_OPC_VEX_66(0, 0x22): /* vpinsr{d,q} */
    case X86EMUL_OPC_EVEX_66(0, 0x22): /* vpinsr{d,q} */
        s->desc = DstImplicit | SrcMem;
        break;

    default:
        s->op_bytes = 0;
        break;
    }

    return X86EMUL_OKAY;
}

#define ad_bytes (s->ad_bytes) /* for truncate_ea() */

int x86emul_decode(struct x86_emulate_state *s,
                   struct x86_emulate_ctxt *ctxt,
                   const struct x86_emulate_ops *ops)
{
    uint8_t b, d;
    unsigned int def_op_bytes, def_ad_bytes, opcode;
    enum x86_segment override_seg = x86_seg_none;
    bool pc_rel = false;
    int rc = X86EMUL_OKAY;

    ASSERT(ops->insn_fetch);

    memset(s, 0, sizeof(*s));
    s->ea.type = OP_NONE;
    s->ea.mem.seg = x86_seg_ds;
    s->ea.reg = PTR_POISON;
    s->ip = ctxt->regs->r(ip);

    s->op_bytes = def_op_bytes = ad_bytes = def_ad_bytes =
        ctxt->addr_size / 8;
    if ( s->op_bytes == 8 )
    {
        s->op_bytes = def_op_bytes = 4;
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
            s->op_bytes = def_op_bytes ^ 6;
            if ( !s->vex.pfx )
                s->vex.pfx = vex_66;
            break;
        case 0x67: /* address-size override */
            ad_bytes = def_ad_bytes ^ (mode_64bit() ? 12 : 6);
            break;
        case 0x26: /* ES override */
        case 0x2e: /* CS override */
        case 0x36: /* SS override */
        case 0x3e: /* DS override, all ignored in 64-bit mode */
            if ( !mode_64bit() )
                override_seg = (b >> 3) & 3;
            break;
        case 0x64: /* FS override */
            override_seg = x86_seg_fs;
            break;
        case 0x65: /* GS override */
            override_seg = x86_seg_gs;
            break;
        case 0xf0: /* LOCK */
            s->lock_prefix = true;
            break;
        case 0xf2: /* REPNE/REPNZ */
            s->vex.pfx = vex_f2;
            break;
        case 0xf3: /* REP/REPE/REPZ */
            s->vex.pfx = vex_f3;
            break;
        case 0x40 ... 0x4f: /* REX */
            if ( !mode_64bit() )
                goto done_prefixes;
            s->rex_prefix = b;
            continue;
        default:
            goto done_prefixes;
        }

        /* Any legacy prefix after a REX prefix nullifies its effect. */
        s->rex_prefix = 0;
    }
 done_prefixes:

    if ( s->rex_prefix & REX_W )
        s->op_bytes = 8;

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
            s->ext = ext_0f;
            s->simd_size = twobyte_table[b].size;
            break;
        case 0x38:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
            s->ext = ext_0f38;
            break;
        case 0x3a:
            b = insn_fetch_type(uint8_t);
            opcode = b | MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
            s->ext = ext_0f3a;
            break;
        }
    }
    else
        opcode = b;

    /* ModRM and SIB bytes. */
    if ( d & ModRM )
    {
        s->modrm = insn_fetch_type(uint8_t);
        s->modrm_mod = (s->modrm & 0xc0) >> 6;

        if ( !s->ext && ((b & ~1) == 0xc4 || (b == 0x8f && (s->modrm & 0x18)) ||
                         b == 0x62) )
            switch ( def_ad_bytes )
            {
            default:
                ASSERT_UNREACHABLE(); /* Shouldn't be possible. */
                return X86EMUL_UNHANDLEABLE;

            case 2:
                if ( ctxt->regs->eflags & X86_EFLAGS_VM )
                    break;
                /* fall through */
            case 4:
                if ( s->modrm_mod != 3 || in_realmode(ctxt, ops) )
                    break;
                /* fall through */
            case 8:
                /* VEX / XOP / EVEX */
                generate_exception_if(s->rex_prefix || s->vex.pfx, X86_EXC_UD);
                /*
                 * With operand size override disallowed (see above), op_bytes
                 * should not have changed from its default.
                 */
                ASSERT(s->op_bytes == def_op_bytes);

                s->vex.raw[0] = s->modrm;
                if ( b == 0xc5 )
                {
                    opcode = X86EMUL_OPC_VEX_;
                    s->vex.raw[1] = s->modrm;
                    s->vex.opcx = vex_0f;
                    s->vex.x = 1;
                    s->vex.b = 1;
                    s->vex.w = 0;
                }
                else
                {
                    s->vex.raw[1] = insn_fetch_type(uint8_t);
                    if ( mode_64bit() )
                    {
                        if ( !s->vex.b )
                            s->rex_prefix |= REX_B;
                        if ( !s->vex.x )
                            s->rex_prefix |= REX_X;
                        if ( s->vex.w )
                        {
                            s->rex_prefix |= REX_W;
                            s->op_bytes = 8;
                        }
                    }
                    else
                    {
                        /* Operand size fixed at 4 (no override via W bit). */
                        s->op_bytes = 4;
                        s->vex.b = 1;
                    }
                    switch ( b )
                    {
                    case 0x62:
                        opcode = X86EMUL_OPC_EVEX_;
                        s->evex.raw[0] = s->vex.raw[0];
                        s->evex.raw[1] = s->vex.raw[1];
                        s->evex.raw[2] = insn_fetch_type(uint8_t);

                        generate_exception_if(!s->evex.mbs || s->evex.mbz, X86_EXC_UD);
                        generate_exception_if(!s->evex.opmsk && s->evex.z, X86_EXC_UD);

                        if ( !mode_64bit() )
                            s->evex.R = 1;

                        s->vex.opcx = s->evex.opcx;
                        break;
                    case 0xc4:
                        opcode = X86EMUL_OPC_VEX_;
                        break;
                    default:
                        opcode = 0;
                        break;
                    }
                }
                if ( !s->vex.r )
                    s->rex_prefix |= REX_R;

                s->ext = s->vex.opcx;
                if ( b != 0x8f )
                {
                    b = insn_fetch_type(uint8_t);
                    switch ( s->ext )
                    {
                    case vex_0f:
                        opcode |= MASK_INSR(0x0f, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[b].desc;
                        s->simd_size = twobyte_table[b].size;
                        break;
                    case vex_0f38:
                        opcode |= MASK_INSR(0x0f38, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x38].desc;
                        break;
                    case vex_0f3a:
                        opcode |= MASK_INSR(0x0f3a, X86EMUL_OPC_EXT_MASK);
                        d = twobyte_table[0x3a].desc;
                        break;

                    case evex_map5:
                        if ( !evex_encoded() )
                        {
                    default:
                            rc = X86EMUL_UNRECOGNIZED;
                            goto done;
                        }
                        opcode |= MASK_INSR(5, X86EMUL_OPC_EXT_MASK);
                        /*
                         * Re-use twobyte_table[] here, for the similarity of
                         * the entries valid in map 5.
                         */
                        d = twobyte_table[b].desc;
                        s->simd_size = twobyte_table[b].size ?: simd_other;
                        break;

                    case evex_map6:
                        if ( !evex_encoded() )
                        {
                            rc = X86EMUL_UNRECOGNIZED;
                            goto done;
                        }
                        opcode |= MASK_INSR(6, X86EMUL_OPC_EXT_MASK);
                        /*
                         * Re-use twobyte_table[]'s 0x38 entry here, for the
                         * similarity of the 0F38 entries with map 6.
                         */
                        d = twobyte_table[0x38].desc;
                        break;
                    }
                }
                else if ( s->ext < ext_8f08 + ARRAY_SIZE(xop_table) )
                {
                    b = insn_fetch_type(uint8_t);
                    opcode |= MASK_INSR(0x8f08 + s->ext - ext_8f08,
                                        X86EMUL_OPC_EXT_MASK);
                    d = array_access_nospec(xop_table, s->ext - ext_8f08);
                }
                else
                {
                    rc = X86EMUL_UNRECOGNIZED;
                    goto done;
                }

                opcode |= b | MASK_INSR(s->vex.pfx, X86EMUL_OPC_PFX_MASK);

                if ( !evex_encoded() )
                    s->evex.lr = s->vex.l;

                if ( !(d & ModRM) )
                    break;

                s->modrm = insn_fetch_type(uint8_t);
                s->modrm_mod = (s->modrm & 0xc0) >> 6;

                break;
            }
    }

    if ( d & ModRM )
    {
        unsigned int disp8scale = 0;

        d &= ~ModRM;
#undef ModRM /* Only its aliases are valid to use from here on. */
        s->modrm_reg = ((s->rex_prefix & 4) << 1) | ((s->modrm & 0x38) >> 3) |
                       ((evex_encoded() && !s->evex.R) << 4);
        s->modrm_rm  = s->modrm & 0x07;

        /*
         * Early operand adjustments. Only ones affecting further processing
         * prior to the x86_decode_*() calls really belong here. That would
         * normally be only addition/removal of SrcImm/SrcImm16, so their
         * fetching can be taken care of by the common code below.
         */
        switch ( s->ext )
        {
        case ext_none:
            switch ( b )
            {
            case 0xf6 ... 0xf7: /* Grp3 */
                switch ( s->modrm_reg & 7 )
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
            if ( evex_encoded() )
                disp8scale = decode_disp8scale(twobyte_table[b].d8s, s);

            switch ( b )
            {
            case 0x12: /* vmovsldup / vmovddup */
                if ( s->evex.pfx == vex_f2 )
                    disp8scale = s->evex.lr ? 4 + s->evex.lr : 3;
                /* fall through */
            case 0x16: /* vmovshdup */
                if ( s->evex.pfx == vex_f3 )
                    disp8scale = 4 + s->evex.lr;
                break;

            case 0x20: /* mov cr,reg */
            case 0x21: /* mov dr,reg */
            case 0x22: /* mov reg,cr */
            case 0x23: /* mov reg,dr */
                /*
                 * Mov to/from cr/dr ignore the encoding of Mod, and behave as
                 * if they were encoded as reg/reg instructions.  No further
                 * disp/SIB bytes are fetched.
                 */
                s->modrm_mod = 3;
                break;

            case 0x78:
            case 0x79:
                if ( !s->evex.pfx )
                    break;
                /* vcvt{,t}ps2uqq need special casing */
                if ( s->evex.pfx == vex_66 )
                {
                    if ( !s->evex.w && !s->evex.brs )
                        --disp8scale;
                    break;
                }
                /* vcvt{,t}s{s,d}2usi need special casing. */
                fallthrough;
            case 0x2c: /* vcvtts{s,d}2si need special casing */
            case 0x2d: /* vcvts{s,d}2si need special casing */
                if ( evex_encoded() )
                    disp8scale = 2 + (s->evex.pfx & VEX_PREFIX_DOUBLE_MASK);
                break;

            case 0x5a: /* vcvtps2pd needs special casing */
                if ( disp8scale && !s->evex.pfx && !s->evex.brs )
                    --disp8scale;
                break;

            case 0x7a: /* vcvttps2qq and vcvtudq2pd need special casing */
                if ( disp8scale && s->evex.pfx != vex_f2 && !s->evex.w && !s->evex.brs )
                    --disp8scale;
                break;

            case 0x7b: /* vcvtp{s,d}2qq need special casing */
                if ( disp8scale && s->evex.pfx == vex_66 )
                    disp8scale = (s->evex.brs ? 2 : 3 + s->evex.lr) + s->evex.w;
                break;

            case 0x7e: /* vmovq xmm/m64,xmm needs special casing */
                if ( disp8scale == 2 && s->evex.pfx == vex_f3 )
                    disp8scale = 3;
                break;

            case 0xe6: /* vcvtdq2pd needs special casing */
                if ( disp8scale && s->evex.pfx == vex_f3 && !s->evex.w && !s->evex.brs )
                    --disp8scale;
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
            s->simd_size = ext0f38_table[b].simd_size;
            if ( evex_encoded() )
            {
                /*
                 * VPMOVUS* are identical to VPMOVS* Disp8-scaling-wise, but
                 * their attributes don't match those of the vex_66 encoded
                 * insns with the same base opcodes. Rather than adding new
                 * columns to the table, handle this here for now.
                 */
                if ( s->evex.pfx != vex_f3 || (b & 0xf8) != 0x10 )
                    disp8scale = decode_disp8scale(ext0f38_table[b].d8s, s);
                else
                {
                    disp8scale = decode_disp8scale(ext0f38_table[b ^ 0x30].d8s,
                                                   s);
                    s->simd_size = simd_other;
                }
            }
            break;

        case ext_0f3a:
            /*
             * Cannot update d here yet, as the immediate operand still
             * needs fetching.
             */
            s->simd_size = ext0f3a_table[b].simd_size;
            if ( evex_encoded() )
            {
                switch ( b )
                {
                case 0x08: /* vrndscaleph */
                case 0x0a: /* vrndscalesh */
                case 0x26: /* vfpclassph */
                case 0x27: /* vfpclasssh */
                case 0x56: /* vgetmantph */
                case 0x57: /* vgetmantsh */
                case 0x66: /* vreduceph */
                case 0x67: /* vreducesh */
                    if ( !s->evex.pfx )
                        s->fp16 = true;
                    break;

                case 0xc2: /* vpcmp{p,s}h */
                    if ( !(s->evex.pfx & VEX_PREFIX_DOUBLE_MASK) )
                        s->fp16 = true;
                    break;
                }

                disp8scale = decode_disp8scale(ext0f3a_table[b].d8s, s);
            }
            break;

        case ext_map5:
            switch ( b )
            {
            default:
                if ( !(s->evex.pfx & VEX_PREFIX_DOUBLE_MASK) )
                    s->fp16 = true;
                break;

            case 0x1d: /* vcvtps2phx / vcvtss2sh */
                if ( s->evex.pfx & VEX_PREFIX_SCALAR_MASK )
                    break;
                d = DstReg | SrcMem;
                if ( s->evex.pfx & VEX_PREFIX_DOUBLE_MASK )
                {
                    s->simd_size = simd_packed_fp;
                    d |= TwoOp;
                }
                else
                    s->simd_size = simd_scalar_vexw;
                break;

            case 0x2a: /* vcvtsi2sh */
                break;

            case 0x2c: case 0x2d: /* vcvt{,t}sh2si */
                if ( s->evex.pfx == vex_f3 )
                    s->fp16 = true;
                break;

            case 0x2e: case 0x2f: /* v{,u}comish */
                if ( !s->evex.pfx )
                    s->fp16 = true;
                s->simd_size = simd_none;
                break;

            case 0x5b: /* vcvt{d,q}q2ph, vcvt{,t}ph2dq */
                if ( s->evex.pfx && s->evex.pfx != vex_f2 )
                    s->fp16 = true;
                break;

            case 0x6e: /* vmovw r/m16, xmm */
                d = (d & ~SrcMask) | SrcMem16;
                /* fall through */
            case 0x7e: /* vmovw xmm, r/m16 */
                if ( s->evex.pfx == vex_66 )
                    s->fp16 = true;
                s->simd_size = simd_none;
                break;

            case 0x78: case 0x79: /* vcvt{,t}ph2u{d,q}q, vcvt{,t}sh2usi */
                if ( s->evex.pfx != vex_f2 )
                    s->fp16 = true;
                break;

            case 0x7a: /* vcvttph2qq, vcvtu{d,q}q2ph */
            case 0x7b: /* vcvtph2qq, vcvtusi2sh */
                if ( s->evex.pfx == vex_66 )
                    s->fp16 = true;
                break;

            case 0x7c: /* vcvttph2{,u}w */
            case 0x7d: /* vcvtph2{,u}w / vcvt{,u}w2ph */
                d = DstReg | SrcMem | TwoOp;
                s->fp16 = true;
                break;
            }

            /* Like above re-use twobyte_table[] here. */
            disp8scale = decode_disp8scale(twobyte_table[b].d8s, s);

            switch ( b )
            {
            case 0x78:
            case 0x79:
                /* vcvt{,t}ph2u{d,q}q need special casing */
                if ( s->evex.pfx <= vex_66 )
                {
                    if ( !s->evex.brs )
                        disp8scale -= 1 + (s->evex.pfx == vex_66);
                    break;
                }
                /* vcvt{,t}sh2usi needs special casing. */
                fallthrough;
            case 0x2c: case 0x2d: /* vcvt{,t}sh2si need special casing */
                disp8scale = 1;
                break;

            case 0x5a: /* vcvtph2pd needs special casing */
                if ( !s->evex.pfx && !s->evex.brs )
                    disp8scale -= 2;
                break;

            case 0x5b: /* vcvt{,t}ph2dq need special casing */
                if ( s->evex.pfx && !s->evex.brs )
                    --disp8scale;
                break;

            case 0x7a: case 0x7b: /* vcvt{,t}ph2qq need special casing */
                if ( s->evex.pfx == vex_66 && !s->evex.brs )
                    disp8scale = s->evex.brs ? 1 : 2 + s->evex.lr;
                break;
            }

            break;

        case ext_map6:
            /*
             * Re-use ext0f38_table[] here, for the similarity of the entries
             * valid in map 6.
             */
            d = ext0f38_table[b].to_mem ? DstMem | SrcReg
                                        : DstReg | SrcMem;
            if ( ext0f38_table[b].two_op )
                d |= TwoOp;
            s->simd_size = ext0f38_table[b].simd_size ?: simd_other;

            switch ( b )
            {
            default:
                if ( s->evex.pfx == vex_66 )
                    s->fp16 = true;
                break;

            case 0x13: /* vcvtph2psx / vcvtsh2ss */
                if ( s->evex.pfx & VEX_PREFIX_SCALAR_MASK )
                    break;
                s->fp16 = true;
                if ( !(s->evex.pfx & VEX_PREFIX_DOUBLE_MASK) )
                {
                    s->simd_size = simd_scalar_vexw;
                    d &= ~TwoOp;
                }
                break;

            case 0x56: case 0x57: /* vf{,c}maddc{p,s}h */
            case 0xd6: case 0xd7: /* vf{,c}mulc{p,s}h */
                break;
            }

            disp8scale = decode_disp8scale(ext0f38_table[b].d8s, s);
            break;

        case ext_8f09:
            if ( ext8f09_table[b].two_op )
                d |= TwoOp;
            s->simd_size = ext8f09_table[b].simd_size;
            break;

        case ext_8f08:
        case ext_8f0a:
            /*
             * Cannot update d here yet, as the immediate operand still
             * needs fetching.
             */
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNIMPLEMENTED;
        }

        if ( s->modrm_mod == 3 )
        {
            generate_exception_if(d & vSIB, X86_EXC_UD);
            s->modrm_rm |= ((s->rex_prefix & 1) << 3) |
                           ((evex_encoded() && !s->evex.x) << 4);
            s->ea.type = OP_REG;
        }
        else if ( ad_bytes == 2 )
        {
            /* 16-bit ModR/M decode. */
            generate_exception_if(d & vSIB, X86_EXC_UD);
            s->ea.type = OP_MEM;
            switch ( s->modrm_rm )
            {
            case 0:
                s->ea.mem.off = ctxt->regs->bx + ctxt->regs->si;
                break;
            case 1:
                s->ea.mem.off = ctxt->regs->bx + ctxt->regs->di;
                break;
            case 2:
                s->ea.mem.seg = x86_seg_ss;
                s->ea.mem.off = ctxt->regs->bp + ctxt->regs->si;
                break;
            case 3:
                s->ea.mem.seg = x86_seg_ss;
                s->ea.mem.off = ctxt->regs->bp + ctxt->regs->di;
                break;
            case 4:
                s->ea.mem.off = ctxt->regs->si;
                break;
            case 5:
                s->ea.mem.off = ctxt->regs->di;
                break;
            case 6:
                if ( s->modrm_mod == 0 )
                    break;
                s->ea.mem.seg = x86_seg_ss;
                s->ea.mem.off = ctxt->regs->bp;
                break;
            case 7:
                s->ea.mem.off = ctxt->regs->bx;
                break;
            }
            switch ( s->modrm_mod )
            {
            case 0:
                if ( s->modrm_rm == 6 )
                    s->ea.mem.off = insn_fetch_type(int16_t);
                break;
            case 1:
                s->ea.mem.off += insn_fetch_type(int8_t) * (1 << disp8scale);
                break;
            case 2:
                s->ea.mem.off += insn_fetch_type(int16_t);
                break;
            }
        }
        else
        {
            /* 32/64-bit ModR/M decode. */
            s->ea.type = OP_MEM;
            if ( s->modrm_rm == 4 )
            {
                uint8_t sib = insn_fetch_type(uint8_t);
                uint8_t sib_base = (sib & 7) | ((s->rex_prefix << 3) & 8);

                s->sib_index = ((sib >> 3) & 7) | ((s->rex_prefix << 2) & 8);
                s->sib_scale = (sib >> 6) & 3;
                if ( unlikely(d & vSIB) )
                    s->sib_index |= (mode_64bit() && evex_encoded() &&
                                     !s->evex.RX) << 4;
                else if ( s->sib_index != 4 )
                {
                    s->ea.mem.off = *decode_gpr(ctxt->regs, s->sib_index);
                    s->ea.mem.off <<= s->sib_scale;
                }
                if ( (s->modrm_mod == 0) && ((sib_base & 7) == 5) )
                    s->ea.mem.off += insn_fetch_type(int32_t);
                else if ( sib_base == 4 )
                {
                    s->ea.mem.seg  = x86_seg_ss;
                    s->ea.mem.off += ctxt->regs->r(sp);
                    if ( !s->ext && (b == 0x8f) )
                        /* POP <rm> computes its EA post increment. */
                        s->ea.mem.off += ((mode_64bit() && (s->op_bytes == 4))
                                       ? 8 : s->op_bytes);
                }
                else if ( sib_base == 5 )
                {
                    s->ea.mem.seg  = x86_seg_ss;
                    s->ea.mem.off += ctxt->regs->r(bp);
                }
                else
                    s->ea.mem.off += *decode_gpr(ctxt->regs, sib_base);
            }
            else
            {
                generate_exception_if(d & vSIB, X86_EXC_UD);
                s->modrm_rm |= (s->rex_prefix & 1) << 3;
                s->ea.mem.off = *decode_gpr(ctxt->regs, s->modrm_rm);
                if ( (s->modrm_rm == 5) && (s->modrm_mod != 0) )
                    s->ea.mem.seg = x86_seg_ss;
            }
            switch ( s->modrm_mod )
            {
            case 0:
                if ( (s->modrm_rm & 7) != 5 )
                    break;
                s->ea.mem.off = insn_fetch_type(int32_t);
                pc_rel = mode_64bit();
                break;
            case 1:
                s->ea.mem.off += insn_fetch_type(int8_t) * (1 << disp8scale);
                break;
            case 2:
                s->ea.mem.off += insn_fetch_type(int32_t);
                break;
            }
        }
    }
    else
    {
        s->modrm_mod = 0xff;
        s->modrm_reg = s->modrm_rm = s->modrm = 0;
    }

    if ( override_seg != x86_seg_none )
        s->ea.mem.seg = override_seg;

    /* Fetch the immediate operand, if present. */
    switch ( d & SrcMask )
    {
        unsigned int bytes;

    case SrcImm:
        if ( !(d & ByteOp) )
        {
            if ( mode_64bit() && !amd_like(ctxt) &&
                 ((s->ext == ext_none && (b | 1) == 0xe9) /* call / jmp */ ||
                  (s->ext == ext_0f && (b | 0xf) == 0x8f) /* jcc */ ) )
                s->op_bytes = 4;
            bytes = s->op_bytes != 8 ? s->op_bytes : 4;
        }
        else
        {
    case SrcImmByte:
            bytes = 1;
        }
        /* NB. Immediates are sign-extended as necessary. */
        switch ( bytes )
        {
        case 1: s->imm1 = insn_fetch_type(int8_t);  break;
        case 2: s->imm1 = insn_fetch_type(int16_t); break;
        case 4: s->imm1 = insn_fetch_type(int32_t); break;
        }
        break;
    case SrcImm16:
        s->imm1 = insn_fetch_type(uint16_t);
        break;
    }

    ctxt->opcode = opcode;
    s->desc = d;

    switch ( s->ext )
    {
    case ext_none:
        rc = decode_onebyte(s, ctxt, ops);
        break;

    case ext_0f:
        rc = decode_twobyte(s, ctxt, ops);
        break;

    case ext_0f38:
        rc = decode_0f38(s, ctxt, ops);
        break;

    case ext_0f3a:
        d = ext0f3a_table[b].to_mem ? DstMem | SrcReg : DstReg | SrcMem;
        if ( ext0f3a_table[b].two_op )
            d |= TwoOp;
        else if ( ext0f3a_table[b].four_op && !mode_64bit() && s->vex.opcx )
            s->imm1 &= 0x7f;
        s->desc = d;
        rc = decode_0f3a(s, ctxt, ops);
        break;

    case ext_8f08:
        d = DstReg | SrcMem;
        if ( ext8f08_table[b].two_op )
            d |= TwoOp;
        else if ( ext8f08_table[b].four_op && !mode_64bit() )
            s->imm1 &= 0x7f;
        s->desc = d;
        s->simd_size = ext8f08_table[b].simd_size;
        break;

    case ext_map5:
    case ext_map6:
    case ext_8f09:
    case ext_8f0a:
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNIMPLEMENTED;
    }

    if ( s->ea.type == OP_MEM )
    {
        if ( pc_rel )
            s->ea.mem.off += s->ip;

        s->ea.mem.off = truncate_ea(s->ea.mem.off);
    }

    /*
     * Simple op_bytes calculations. More complicated cases produce 0
     * and are further handled during execute.
     */
    switch ( s->simd_size )
    {
    case simd_none:
        /*
         * When prefix 66 has a meaning different from operand-size override,
         * operand size defaults to 4 and can't be overridden to 2.
         */
        if ( s->op_bytes == 2 &&
             (ctxt->opcode & X86EMUL_OPC_PFX_MASK) == X86EMUL_OPC_66(0, 0) )
            s->op_bytes = 4;
        break;

#ifndef X86EMUL_NO_SIMD
    case simd_packed_int:
        switch ( s->vex.pfx )
        {
        case vex_none:
            if ( !s->vex.opcx )
            {
                s->op_bytes = 8;
                break;
            }
            /* fall through */
        case vex_66:
            s->op_bytes = 16 << s->evex.lr;
            break;
        default:
            s->op_bytes = 0;
            break;
        }
        break;

    case simd_single_fp:
        if ( s->vex.pfx & VEX_PREFIX_DOUBLE_MASK )
        {
            s->op_bytes = 0;
            break;
    case simd_packed_fp:
            if ( s->vex.pfx & VEX_PREFIX_SCALAR_MASK )
            {
                s->op_bytes = 0;
                break;
            }
        }
        /* fall through */
    case simd_any_fp:
        switch ( s->vex.pfx )
        {
        default:
            s->op_bytes = 16 << s->evex.lr;
            break;
        case vex_f3:
            generate_exception_if(evex_encoded() && s->evex.w, X86_EXC_UD);
            s->op_bytes = 4 >> s->fp16;
            break;
        case vex_f2:
            generate_exception_if(evex_encoded() && !s->evex.w, X86_EXC_UD);
            s->op_bytes = 8;
            break;
        }
        break;

    case simd_scalar_opc:
        s->op_bytes = 2 << (!s->fp16 + (ctxt->opcode & 1));
        break;

    case simd_scalar_vexw:
        s->op_bytes = 2 << (!s->fp16 + s->vex.w);
        break;

    case simd_128:
        /* The special cases here are MMX shift insns. */
        s->op_bytes = s->vex.opcx || s->vex.pfx ? 16 : 8;
        break;

    case simd_256:
        s->op_bytes = 32;
        break;
#endif /* !X86EMUL_NO_SIMD */

    default:
        s->op_bytes = 0;
        break;
    }

 done:
    return rc;
}
