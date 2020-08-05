#include "x86-emulate.h"

#include <stdio.h>

enum mem_access { mem_none, mem_read, mem_write };
enum pfx { pfx_no, pfx_66, pfx_f3, pfx_f2 };
static const uint8_t prefixes[] = { 0x66, 0xf3, 0xf2 };

#define F false
#define T true

#define N mem_none
#define R mem_read
#define W mem_write

/*
 * ModR/M bytes and immediates don't need spelling out in the opcodes,
 * unless the implied zeros aren't good enough.
 */
static const struct {
    uint8_t opc[8];
    uint8_t len[2]; /* 32- and 64-bit mode */
    bool modrm:1; /* Should register form (also) be tested? */
    uint8_t mem:2;
    uint8_t pfx:2;
#define REG(opc, more...) \
    { { (opc) | 0 }, more }, /* %?ax */ \
    { { (opc) | 1 }, more }, /* %?cx */ \
    { { (opc) | 2 }, more }, /* %?dx */ \
    { { (opc) | 3 }, more }, /* %?bx */ \
    { { (opc) | 4 }, more }, /* %?sp */ \
    { { (opc) | 5 }, more }, /* %?bp */ \
    { { (opc) | 6 }, more }, /* %?si */ \
    { { (opc) | 7 }, more }  /* %?di */
#define CND(opc, more...) \
    { { (opc) | 0x0 }, more }, /* ..o */ \
    { { (opc) | 0x1 }, more }, /* ..no */ \
    { { (opc) | 0x2 }, more }, /* ..c / ..b */ \
    { { (opc) | 0x3 }, more }, /* ..nc / ..nb */ \
    { { (opc) | 0x4 }, more }, /* ..z / ..e */ \
    { { (opc) | 0x5 }, more }, /* ..nz / ..ne */ \
    { { (opc) | 0x6 }, more }, /* ..be / ..na */ \
    { { (opc) | 0x7 }, more }, /* ..a / ..nbe */ \
    { { (opc) | 0x8 }, more }, /* ..s */ \
    { { (opc) | 0x9 }, more }, /* ..ns */ \
    { { (opc) | 0xa }, more }, /* ..pe / ..p */ \
    { { (opc) | 0xb }, more }, /* ..po / ..np */ \
    { { (opc) | 0xc }, more }, /* ..l / ..nge */ \
    { { (opc) | 0xd }, more }, /* ..ge / ..nl */ \
    { { (opc) | 0xe }, more }, /* ..le / ..ng */ \
    { { (opc) | 0xf }, more }  /* ..g / .. nle */
} legacy[] = {
    { { 0x00 }, { 2, 2 }, T, W }, /* add */
    { { 0x01 }, { 2, 2 }, T, W }, /* add */
    { { 0x02 }, { 2, 2 }, T, R }, /* add */
    { { 0x03 }, { 2, 2 }, T, R }, /* add */
    { { 0x04 }, { 2, 2 }, F, N }, /* add */
    { { 0x05 }, { 5, 5 }, F, N }, /* add */
    { { 0x06 }, { 1, 0 }, F, W }, /* push %es */
    { { 0x07 }, { 1, 0 }, F, R }, /* pop %es */
    { { 0x08 }, { 2, 2 }, T, W }, /* or */
    { { 0x09 }, { 2, 2 }, T, W }, /* or */
    { { 0x0a }, { 2, 2 }, T, R }, /* or */
    { { 0x0b }, { 2, 2 }, T, R }, /* or */
    { { 0x0c }, { 2, 2 }, F, N }, /* or */
    { { 0x0d }, { 5, 5 }, F, N }, /* or */
    { { 0x0e }, { 1, 0 }, F, W }, /* push %cs */
    { { 0x10 }, { 2, 2 }, T, W }, /* adc */
    { { 0x11 }, { 2, 2 }, T, W }, /* adc */
    { { 0x12 }, { 2, 2 }, T, R }, /* adc */
    { { 0x13 }, { 2, 2 }, T, R }, /* adc */
    { { 0x14 }, { 2, 2 }, F, N }, /* adc */
    { { 0x15 }, { 5, 5 }, F, N }, /* adc */
    { { 0x16 }, { 1, 0 }, F, W }, /* push %ss */
    { { 0x17 }, { 1, 0 }, F, R }, /* pop %ss */
    { { 0x18 }, { 2, 2 }, T, W }, /* adc */
    { { 0x19 }, { 2, 2 }, T, W }, /* adc */
    { { 0x1a }, { 2, 2 }, T, R }, /* adc */
    { { 0x1b }, { 2, 2 }, T, R }, /* adc */
    { { 0x1c }, { 2, 2 }, F, N }, /* adc */
    { { 0x1d }, { 5, 5 }, F, N }, /* adc */
    { { 0x1e }, { 1, 0 }, F, W }, /* push %ds */
    { { 0x1f }, { 1, 0 }, F, R }, /* pop %ds */
    { { 0x20 }, { 2, 2 }, T, W }, /* and */
    { { 0x21 }, { 2, 2 }, T, W }, /* and */
    { { 0x22 }, { 2, 2 }, T, R }, /* and */
    { { 0x23 }, { 2, 2 }, T, R }, /* and */
    { { 0x24 }, { 2, 2 }, F, N }, /* and */
    { { 0x25 }, { 5, 5 }, F, N }, /* and */
    { { 0x27 }, { 1, 0 }, F, N }, /* daa */
    { { 0x28 }, { 2, 2 }, T, W }, /* sub */
    { { 0x29 }, { 2, 2 }, T, W }, /* sub */
    { { 0x2a }, { 2, 2 }, T, R }, /* sub */
    { { 0x2b }, { 2, 2 }, T, R }, /* sub */
    { { 0x2c }, { 2, 2 }, F, N }, /* sub */
    { { 0x2d }, { 5, 5 }, F, N }, /* sub */
    { { 0x2f }, { 1, 0 }, F, N }, /* das */
    { { 0x30 }, { 2, 2 }, T, W }, /* xor */
    { { 0x31 }, { 2, 2 }, T, W }, /* xor */
    { { 0x32 }, { 2, 2 }, T, R }, /* xor */
    { { 0x33 }, { 2, 2 }, T, R }, /* xor */
    { { 0x34 }, { 2, 2 }, F, N }, /* xor */
    { { 0x35 }, { 5, 5 }, F, N }, /* xor */
    { { 0x37 }, { 1, 0 }, F, N }, /* aaa */
    { { 0x38 }, { 2, 2 }, T, R }, /* cmp */
    { { 0x39 }, { 2, 2 }, T, R }, /* cmp */
    { { 0x3a }, { 2, 2 }, T, R }, /* cmp */
    { { 0x3b }, { 2, 2 }, T, R }, /* cmp */
    { { 0x3c }, { 2, 2 }, F, N }, /* cmp */
    { { 0x3d }, { 5, 5 }, F, N }, /* cmp */
    { { 0x3f }, { 1, 0 }, F, N }, /* aas */
    REG(0x40,   { 1, 0 }, F, N ), /* inc */
    REG(0x48,   { 1, 0 }, F, N ), /* dec */
    REG(0x50,   { 1, 0 }, F, W ), /* push */
    REG(0x58,   { 1, 0 }, F, R ), /* pop */
    { { 0x60 }, { 1, 0 }, F, W }, /* pusha */
    { { 0x61 }, { 1, 0 }, F, R }, /* popa */
    { { 0x62 }, { 2, 0 }, F, R }, /* bound */
    { { 0x63 }, { 2, 0 }, F, W }, /* arpl */
    { { 0x63 }, { 0, 2 }, F, R }, /* movsxd */
    { { 0x68 }, { 5, 5 }, F, W }, /* push */
    { { 0x69 }, { 6, 6 }, T, R }, /* imul */
    { { 0x6a }, { 2, 2 }, F, W }, /* push */
    { { 0x6b }, { 3, 3 }, T, R }, /* imul */
    { { 0x6c }, { 1, 1 }, F, W }, /* ins */
    { { 0x6d }, { 1, 1 }, F, W }, /* ins */
    { { 0x6e }, { 1, 1 }, F, R }, /* outs */
    { { 0x6f }, { 1, 1 }, F, R }, /* outs */
    CND(0x70,   { 2, 2 }, F, N ), /* j<cc> */
    { { 0x80, 0x00 }, { 3, 3 }, T, W }, /* add */
    { { 0x80, 0x08 }, { 3, 3 }, T, W }, /* or */
    { { 0x80, 0x10 }, { 3, 3 }, T, W }, /* adc */
    { { 0x80, 0x18 }, { 3, 3 }, T, W }, /* sbb */
    { { 0x80, 0x20 }, { 3, 3 }, T, W }, /* and */
    { { 0x80, 0x28 }, { 3, 3 }, T, W }, /* sub */
    { { 0x80, 0x30 }, { 3, 3 }, T, W }, /* xor */
    { { 0x80, 0x38 }, { 3, 3 }, T, R }, /* cmp */
    { { 0x81, 0x00 }, { 6, 6 }, T, W }, /* add */
    { { 0x81, 0x08 }, { 6, 6 }, T, W }, /* or */
    { { 0x81, 0x10 }, { 6, 6 }, T, W }, /* adc */
    { { 0x81, 0x18 }, { 6, 6 }, T, W }, /* sbb */
    { { 0x81, 0x20 }, { 6, 6 }, T, W }, /* and */
    { { 0x81, 0x28 }, { 6, 6 }, T, W }, /* sub */
    { { 0x81, 0x30 }, { 6, 6 }, T, W }, /* add */
    { { 0x81, 0x38 }, { 6, 6 }, T, R }, /* cmp */
    { { 0x82, 0x00 }, { 3, 0 }, T, W }, /* xor */
    { { 0x82, 0x08 }, { 3, 0 }, T, W }, /* or */
    { { 0x82, 0x10 }, { 3, 0 }, T, W }, /* adc */
    { { 0x82, 0x18 }, { 3, 0 }, T, W }, /* sbb */
    { { 0x82, 0x20 }, { 3, 0 }, T, W }, /* and */
    { { 0x82, 0x28 }, { 3, 0 }, T, W }, /* sub */
    { { 0x82, 0x30 }, { 3, 0 }, T, W }, /* xor */
    { { 0x82, 0x38 }, { 3, 0 }, T, R }, /* cmp */
    { { 0x83, 0x00 }, { 3, 3 }, T, W }, /* add */
    { { 0x83, 0x08 }, { 3, 3 }, T, W }, /* or */
    { { 0x83, 0x10 }, { 3, 3 }, T, W }, /* adc */
    { { 0x83, 0x18 }, { 3, 3 }, T, W }, /* sbb */
    { { 0x83, 0x20 }, { 3, 3 }, T, W }, /* and */
    { { 0x83, 0x28 }, { 3, 3 }, T, W }, /* sub */
    { { 0x83, 0x30 }, { 3, 3 }, T, W }, /* xor */
    { { 0x83, 0x38 }, { 3, 3 }, T, R }, /* cmp */
    { { 0x84 }, { 2, 2 }, T, R }, /* test */
    { { 0x85 }, { 2, 2 }, T, R }, /* test */
    { { 0x86 }, { 2, 2 }, T, W }, /* xchg */
    { { 0x87 }, { 2, 2 }, T, W }, /* xchg */
    { { 0x88 }, { 2, 2 }, T, W }, /* mov */
    { { 0x89 }, { 2, 2 }, T, W }, /* mov */
    { { 0x8a }, { 2, 2 }, T, R }, /* mov */
    { { 0x8b }, { 2, 2 }, T, R }, /* mov */
    { { 0x8c }, { 2, 2 }, T, W }, /* mov */
    { { 0x8d }, { 2, 2 }, F, N }, /* lea */
    { { 0x8e }, { 2, 2 }, T, R }, /* mov */
    { { 0x8f, 0x00 }, { 2, 2 }, F, W }, /* pop */
    { { 0x8f, 0xc0 }, { 2, 2 }, F, R }, /* pop */
    REG(0x90,   { 1, 0 }, F, N ), /* xchg */
    { { 0x98 }, { 1, 1 }, F, N }, /* cbw */
    { { 0x99 }, { 1, 1 }, F, N }, /* cwd */
    { { 0x9a }, { 7, 0 }, F, W }, /* lcall */
    { { 0x9b }, { 1, 1 }, F, N }, /* wait */
    { { 0x9c }, { 1, 1 }, F, W }, /* pushf */
    { { 0x9d }, { 1, 1 }, F, R }, /* popf */
    { { 0x9e }, { 1, 1 }, F, N }, /* sahf */
    { { 0x9f }, { 1, 1 }, F, N }, /* lahf */
    { { 0xa0 }, { 5, 9 }, F, R }, /* mov */
    { { 0xa1 }, { 5, 9 }, F, R }, /* mov */
    { { 0xa2 }, { 5, 9 }, F, W }, /* mov */
    { { 0xa3 }, { 5, 9 }, F, W }, /* mov */
    { { 0xa4 }, { 1, 1 }, F, W }, /* movs */
    { { 0xa5 }, { 1, 1 }, F, W }, /* movs */
    { { 0xa6 }, { 1, 1 }, F, R }, /* cmps */
    { { 0xa7 }, { 1, 1 }, F, R }, /* cmps */
    { { 0xa8 }, { 2, 2 }, F, N }, /* test */
    { { 0xa9 }, { 5, 5 }, F, N }, /* test */
    { { 0xaa }, { 1, 1 }, F, W }, /* stos */
    { { 0xab }, { 1, 1 }, F, W }, /* stos */
    { { 0xac }, { 1, 1 }, F, R }, /* lods */
    { { 0xad }, { 1, 1 }, F, R }, /* lods */
    { { 0xae }, { 1, 1 }, F, R }, /* scas */
    { { 0xaf }, { 1, 1 }, F, R }, /* scas */
    REG(0xb0,   { 2, 2 }, F, N ), /* mov */
    REG(0xb8,   { 5, 5 }, F, N ), /* mov */
    { { 0xc0, 0x00 }, { 3, 3 }, T, W }, /* rol */
    { { 0xc0, 0x08 }, { 3, 3 }, T, W }, /* ror */
    { { 0xc0, 0x10 }, { 3, 3 }, T, W }, /* rcl */
    { { 0xc0, 0x18 }, { 3, 3 }, T, W }, /* rcr */
    { { 0xc0, 0x20 }, { 3, 3 }, T, W }, /* shl */
    { { 0xc0, 0x28 }, { 3, 3 }, T, W }, /* shr */
    { { 0xc0, 0x30 }, { 3, 3 }, T, W }, /* sal */
    { { 0xc0, 0x38 }, { 3, 3 }, T, W }, /* sar */
    { { 0xc1, 0x00 }, { 3, 3 }, T, W }, /* rol */
    { { 0xc1, 0x08 }, { 3, 3 }, T, W }, /* ror */
    { { 0xc1, 0x10 }, { 3, 3 }, T, W }, /* rcl */
    { { 0xc1, 0x18 }, { 3, 3 }, T, W }, /* rcr */
    { { 0xc1, 0x20 }, { 3, 3 }, T, W }, /* shl */
    { { 0xc1, 0x28 }, { 3, 3 }, T, W }, /* shr */
    { { 0xc1, 0x30 }, { 3, 3 }, T, W }, /* sal */
    { { 0xc1, 0x38 }, { 3, 3 }, T, W }, /* sar */
    { { 0xc2 }, { 3, 3 }, F, R }, /* ret */
    { { 0xc3 }, { 1, 1 }, F, R }, /* ret */
    { { 0xc4 }, { 2, 0 }, F, R }, /* les */
    { { 0xc5 }, { 2, 0 }, F, R }, /* lds */
    { { 0xc6, 0x00 }, { 3, 3 }, T, W }, /* mov */
    { { 0xc6, 0xf8 }, { 3, 3 }, F, N }, /* xabort */
    { { 0xc7, 0x00 }, { 6, 6 }, T, W }, /* mov */
    { { 0xc7, 0xf8 }, { 6, 6 }, F, N }, /* xbegin */
    { { 0xc8 }, { 4, 4 }, F, W }, /* enter */
    { { 0xc9 }, { 1, 1 }, F, R }, /* leave */
    { { 0xca }, { 3, 3 }, F, R }, /* lret */
    { { 0xcb }, { 1, 1 }, F, R }, /* lret */
    { { 0xcc }, { 1, 1 }, F, N }, /* int3 */
    { { 0xcd }, { 2, 2 }, F, N }, /* int */
    { { 0xce }, { 1, 0 }, F, N }, /* into */
    { { 0xcf }, { 1, 1 }, F, N }, /* iret */
    { { 0xd0, 0x00 }, { 2, 2 }, T, W }, /* rol */
    { { 0xd0, 0x08 }, { 2, 2 }, T, W }, /* ror */
    { { 0xd0, 0x10 }, { 2, 2 }, T, W }, /* rcl */
    { { 0xd0, 0x18 }, { 2, 2 }, T, W }, /* rcr */
    { { 0xd0, 0x20 }, { 2, 2 }, T, W }, /* shl */
    { { 0xd0, 0x28 }, { 2, 2 }, T, W }, /* shr */
    { { 0xd0, 0x30 }, { 2, 2 }, T, W }, /* sal */
    { { 0xd0, 0x38 }, { 2, 2 }, T, W }, /* sar */
    { { 0xd1, 0x00 }, { 2, 2 }, T, W }, /* rol */
    { { 0xd1, 0x08 }, { 2, 2 }, T, W }, /* ror */
    { { 0xd1, 0x10 }, { 2, 2 }, T, W }, /* rcl */
    { { 0xd1, 0x18 }, { 2, 2 }, T, W }, /* rcr */
    { { 0xd1, 0x20 }, { 2, 2 }, T, W }, /* shl */
    { { 0xd1, 0x28 }, { 2, 2 }, T, W }, /* shr */
    { { 0xd1, 0x30 }, { 2, 2 }, T, W }, /* sal */
    { { 0xd1, 0x38 }, { 2, 2 }, T, W }, /* sar */
    { { 0xd2, 0x00 }, { 2, 2 }, T, W }, /* rol */
    { { 0xd2, 0x08 }, { 2, 2 }, T, W }, /* ror */
    { { 0xd2, 0x10 }, { 2, 2 }, T, W }, /* rcl */
    { { 0xd2, 0x18 }, { 2, 2 }, T, W }, /* rcr */
    { { 0xd2, 0x20 }, { 2, 2 }, T, W }, /* shl */
    { { 0xd2, 0x28 }, { 2, 2 }, T, W }, /* shr */
    { { 0xd2, 0x30 }, { 2, 2 }, T, W }, /* sal */
    { { 0xd2, 0x38 }, { 2, 2 }, T, W }, /* sar */
    { { 0xd3, 0x00 }, { 2, 2 }, T, W }, /* rol */
    { { 0xd3, 0x08 }, { 2, 2 }, T, W }, /* ror */
    { { 0xd3, 0x10 }, { 2, 2 }, T, W }, /* rcl */
    { { 0xd3, 0x18 }, { 2, 2 }, T, W }, /* rcr */
    { { 0xd3, 0x20 }, { 2, 2 }, T, W }, /* shl */
    { { 0xd3, 0x28 }, { 2, 2 }, T, W }, /* shr */
    { { 0xd3, 0x30 }, { 2, 2 }, T, W }, /* sal */
    { { 0xd3, 0x38 }, { 2, 2 }, T, W }, /* sar */
    { { 0xd4 }, { 2, 0 }, F, N }, /* aam */
    { { 0xd5 }, { 2, 0 }, F, N }, /* aad */
    { { 0xd6 }, { 1, 0 }, F, N }, /* salc */
    { { 0xd7 }, { 1, 1 }, F, R }, /* xlat */
    { { 0xe0 }, { 2, 2 }, F, N }, /* loopne */
    { { 0xe1 }, { 2, 2 }, F, N }, /* loope */
    { { 0xe2 }, { 2, 2 }, F, N }, /* loop */
    { { 0xe3 }, { 2, 2 }, F, N }, /* j?cxz */
    { { 0xe4 }, { 2, 2 }, F, N }, /* in */
    { { 0xe5 }, { 2, 2 }, F, N }, /* in */
    { { 0xe6 }, { 2, 2 }, F, N }, /* out */
    { { 0xe7 }, { 2, 2 }, F, N }, /* out */
    { { 0xe8 }, { 5, 5 }, F, W }, /* call */
    { { 0xe9 }, { 5, 5 }, F, N }, /* jmp */
    { { 0xea }, { 7, 0 }, F, N }, /* ljmp */
    { { 0xeb }, { 2, 2 }, F, N }, /* jmp */
    { { 0xec }, { 1, 1 }, F, N }, /* in */
    { { 0xed }, { 1, 1 }, F, N }, /* in */
    { { 0xee }, { 1, 1 }, F, N }, /* out */
    { { 0xef }, { 1, 1 }, F, N }, /* out */
    { { 0xf1 }, { 1, 1 }, F, N }, /* icebp */
    { { 0xf4 }, { 1, 1 }, F, N }, /* hlt */
    { { 0xf5 }, { 1, 1 }, F, N }, /* cmc */
    { { 0xf6, 0x00 }, { 3, 3 }, T, R }, /* test */
    { { 0xf6, 0x08 }, { 3, 3 }, T, R }, /* test */
    { { 0xf6, 0x10 }, { 2, 2 }, T, W }, /* not */
    { { 0xf6, 0x18 }, { 2, 2 }, T, W }, /* neg */
    { { 0xf6, 0x20 }, { 2, 2 }, T, R }, /* mul */
    { { 0xf6, 0x28 }, { 2, 2 }, T, R }, /* imul */
    { { 0xf6, 0x30 }, { 2, 2 }, T, R }, /* div */
    { { 0xf6, 0x38 }, { 2, 2 }, T, R }, /* idiv */
    { { 0xf7, 0x00 }, { 6, 6 }, T, R }, /* test */
    { { 0xf7, 0x08 }, { 6, 6 }, T, R }, /* test */
    { { 0xf7, 0x10 }, { 2, 2 }, T, W }, /* not */
    { { 0xf7, 0x18 }, { 2, 2 }, T, W }, /* neg */
    { { 0xf7, 0x20 }, { 2, 2 }, T, R }, /* mul */
    { { 0xf7, 0x28 }, { 2, 2 }, T, R }, /* imul */
    { { 0xf7, 0x30 }, { 2, 2 }, T, R }, /* div */
    { { 0xf7, 0x38 }, { 2, 2 }, T, R }, /* idiv */
    { { 0xf8 }, { 1, 1 }, F, N }, /* clc */
    { { 0xf9 }, { 1, 1 }, F, N }, /* stc */
    { { 0xfa }, { 1, 1 }, F, N }, /* cli */
    { { 0xfb }, { 1, 1 }, F, N }, /* sti */
    { { 0xfc }, { 1, 1 }, F, N }, /* cld */
    { { 0xfd }, { 1, 1 }, F, N }, /* std */
    { { 0xfe, 0x00 }, { 2, 2 }, T, W }, /* inc */
    { { 0xfe, 0x08 }, { 2, 2 }, T, W }, /* dec */
    { { 0xff, 0x00 }, { 2, 2 }, T, W }, /* inc */
    { { 0xff, 0x08 }, { 2, 2 }, T, W }, /* dec */
    { { 0xff, 0x10 }, { 2, 2 }, F, W }, /* call */
    { { 0xff, 0x18 }, { 2, 2 }, F, W }, /* lcall */
    { { 0xff, 0x20 }, { 2, 2 }, T, R }, /* jmp */
    { { 0xff, 0x28 }, { 2, 2 }, F, R }, /* ljmp */
    { { 0xff, 0x30 }, { 2, 2 }, F, W }, /* push */
    { { 0xff, 0xd0 }, { 2, 2 }, F, W }, /* call */
    { { 0xff, 0xf0 }, { 2, 2 }, F, W }, /* push */
}, legacy_0f[] = {
    { { 0x00, 0x00 }, { 2, 2 }, T, W }, /* sldt */
    { { 0x00, 0x08 }, { 2, 2 }, T, W }, /* str */
    { { 0x00, 0x10 }, { 2, 2 }, T, R }, /* lldt */
    { { 0x00, 0x18 }, { 2, 2 }, T, R }, /* ltr */
    { { 0x00, 0x20 }, { 2, 2 }, T, R }, /* verr */
    { { 0x00, 0x28 }, { 2, 2 }, T, R }, /* verw */
    { { 0x01, 0x00 }, { 2, 2 }, F, W }, /* sgdt */
    { { 0x01, 0x08 }, { 2, 2 }, F, W }, /* sidt */
    { { 0x01, 0x10 }, { 2, 2 }, F, R }, /* lgdt */
    { { 0x01, 0x18 }, { 2, 2 }, F, R }, /* lidt */
    { { 0x01, 0x20 }, { 2, 2 }, T, W }, /* smsw */
    /*{ 0x01, 0x28 }, { 2, 2 }, F, W, pfx_f3 }, rstorssp */
    { { 0x01, 0x30 }, { 2, 2 }, T, R }, /* lmsw */
    { { 0x01, 0x38 }, { 2, 2 }, F, N }, /* invlpg */
    { { 0x01, 0xc0 }, { 2, 2 }, F, N }, /* enclv */
    { { 0x01, 0xc1 }, { 2, 2 }, F, N }, /* vmcall */
    /*{ 0x01, 0xc2 }, { 2, 2 }, F, R }, vmlaunch */
    /*{ 0x01, 0xc3 }, { 2, 2 }, F, R }, vmresume */
    { { 0x01, 0xc4 }, { 2, 2 }, F, N }, /* vmxoff */
    { { 0x01, 0xc5 }, { 2, 2 }, F, N }, /* pconfig */
    { { 0x01, 0xc8 }, { 2, 2 }, F, N }, /* monitor */
    { { 0x01, 0xc9 }, { 2, 2 }, F, N }, /* mwait */
    { { 0x01, 0xca }, { 2, 2 }, F, N }, /* clac */
    { { 0x01, 0xcb }, { 2, 2 }, F, N }, /* stac */
    { { 0x01, 0xcf }, { 2, 2 }, F, N }, /* encls */
    { { 0x01, 0xd0 }, { 2, 2 }, F, N }, /* xgetbv */
    { { 0x01, 0xd1 }, { 2, 2 }, F, N }, /* xsetbv */
    { { 0x01, 0xd4 }, { 2, 2 }, F, N }, /* vmfunc */
    { { 0x01, 0xd5 }, { 2, 2 }, F, N }, /* xend */
    { { 0x01, 0xd6 }, { 2, 2 }, F, N }, /* xtest */
    { { 0x01, 0xd7 }, { 2, 2 }, F, N }, /* enclu */
    /*{ 0x01, 0xd8 }, { 2, 2 }, F, R }, vmrun */
    { { 0x01, 0xd9 }, { 2, 2 }, F, N }, /* vmcall */
    { { 0x01, 0xd9 }, { 2, 2 }, F, N, pfx_f3 }, /* vmgexit */
    { { 0x01, 0xd9 }, { 2, 2 }, F, N, pfx_f2 }, /* vmgexit */
    /*{ 0x01, 0xda }, { 2, 2 }, F, R }, vmload */
    /*{ 0x01, 0xdb }, { 2, 2 }, F, W }, vmsave */
    { { 0x01, 0xdc }, { 2, 2 }, F, N }, /* stgi */
    { { 0x01, 0xdd }, { 2, 2 }, F, N }, /* clgi */
    /*{ 0x01, 0xde }, { 2, 2 }, F, R }, skinit */
    { { 0x01, 0xdf }, { 2, 2 }, F, N }, /* invlpga */
    { { 0x01, 0xe8 }, { 2, 2 }, F, N }, /* serialize */
    /*{ 0x01, 0xe8 }, { 2, 2 }, F, W, pfx_f3 }, setssbsy */
    { { 0x01, 0xe8 }, { 2, 2 }, F, N, pfx_f2 }, /* xsusldtrk */
    { { 0x01, 0xe9 }, { 2, 2 }, F, N, pfx_f2 }, /* xresldtrk */
    /*{ 0x01, 0xea }, { 2, 2 }, F, W, pfx_f3 }, saveprevssp */
    { { 0x01, 0xee }, { 2, 2 }, F, N }, /* rdpkru */
    { { 0x01, 0xef }, { 2, 2 }, F, N }, /* wrpkru */
    { { 0x01, 0xf8 }, { 0, 2 }, F, N }, /* swapgs */
    { { 0x01, 0xf9 }, { 2, 2 }, F, N }, /* rdtscp */
    { { 0x01, 0xfa }, { 2, 2 }, F, N }, /* monitorx */
    { { 0x01, 0xfa }, { 2, 2 }, F, N, pfx_f3 }, /* mcommit */
    { { 0x01, 0xfb }, { 2, 2 }, F, N }, /* mwaitx */
    { { 0x01, 0xfc }, { 2, 2 }, F, W }, /* clzero */
    { { 0x01, 0xfd }, { 2, 2 }, F, N }, /* rdpru */
    { { 0x01, 0xfe }, { 2, 2 }, F, N }, /* invlpgb */
    { { 0x01, 0xfe }, { 0, 2 }, F, N, pfx_f3 }, /* rmpadjust */
    { { 0x01, 0xfe }, { 0, 2 }, F, N, pfx_f2 }, /* rmpupdate */
    { { 0x01, 0xff }, { 2, 2 }, F, N }, /* tlbsync */
    { { 0x01, 0xff }, { 0, 2 }, F, N, pfx_f3 }, /* psmash */
    { { 0x01, 0xff }, { 0, 2 }, F, N, pfx_f2 }, /* pvalidate */
    { { 0x02 }, { 2, 2 }, T, R }, /* lar */
    { { 0x03 }, { 2, 2 }, T, R }, /* lsl */
    { { 0x05 }, { 1, 1 }, F, N }, /* syscall */
    { { 0x06 }, { 1, 1 }, F, N }, /* clts */
    { { 0x07 }, { 1, 1 }, F, N }, /* sysret */
    { { 0x08 }, { 1, 1 }, F, N }, /* invd */
    { { 0x09 }, { 1, 1 }, F, N }, /* wbinvd */
    { { 0x09 }, { 1, 1 }, F, N, pfx_f3 }, /* wbnoinvd */
    { { 0x0b }, { 1, 1 }, F, N }, /* ud2 */
    { { 0x0d, 0x00 }, { 2, 2 }, F, N }, /* prefetch */
    { { 0x0d, 0x08 }, { 2, 2 }, F, N }, /* prefetchw */
    { { 0x0e }, { 1, 1 }, F, N }, /* femms */
    { { 0x0f, 0x00, 0x9e }, { 3, 3 }, T, R }, /* pfadd */
    { { 0x10 }, { 2, 2 }, T, R, pfx_no }, /* movups */
    { { 0x10 }, { 2, 2 }, T, R, pfx_66 }, /* movupd */
    { { 0x10 }, { 2, 2 }, T, R, pfx_f3 }, /* movss */
    { { 0x10 }, { 2, 2 }, T, R, pfx_f2 }, /* movsd */
    { { 0x11 }, { 2, 2 }, T, W, pfx_no }, /* movups */
    { { 0x11 }, { 2, 2 }, T, W, pfx_66 }, /* movupd */
    { { 0x11 }, { 2, 2 }, T, W, pfx_f3 }, /* movss */
    { { 0x11 }, { 2, 2 }, T, W, pfx_f2 }, /* movsd */
    { { 0x12 }, { 2, 2 }, T, R, pfx_no }, /* movlps / movhlps */
    { { 0x12 }, { 2, 2 }, F, R, pfx_66 }, /* movlpd */
    { { 0x12 }, { 2, 2 }, T, R, pfx_f3 }, /* movsldup */
    { { 0x12 }, { 2, 2 }, T, R, pfx_f2 }, /* movddup */
    { { 0x13 }, { 2, 2 }, F, W, pfx_no }, /* movlps */
    { { 0x13 }, { 2, 2 }, F, W, pfx_66 }, /* movlpd */
    { { 0x14 }, { 2, 2 }, T, R, pfx_no }, /* unpcklps */
    { { 0x14 }, { 2, 2 }, T, R, pfx_66 }, /* unpcklpd */
    { { 0x15 }, { 2, 2 }, T, R, pfx_no }, /* unpckhps */
    { { 0x15 }, { 2, 2 }, T, R, pfx_66 }, /* unpckhpd */
    { { 0x16 }, { 2, 2 }, T, R, pfx_no }, /* movhps / movlhps */
    { { 0x16 }, { 2, 2 }, F, R, pfx_66 }, /* movhpd */
    { { 0x16 }, { 2, 2 }, T, R, pfx_f3 }, /* movshdup */
    { { 0x17 }, { 2, 2 }, F, W, pfx_no }, /* movhps */
    { { 0x17 }, { 2, 2 }, F, W, pfx_66 }, /* movhpd */
    { { 0x18, 0x00 }, { 2, 2 }, F, N }, /* prefetchnta */
    { { 0x18, 0x08 }, { 2, 2 }, F, N }, /* prefetch0 */
    { { 0x18, 0x10 }, { 2, 2 }, F, N }, /* prefetch1 */
    { { 0x18, 0x18 }, { 2, 2 }, F, N }, /* prefetch2 */
    /*{ 0x1a }, { 2, 2 }, F, R }, bndldx */
    /*{ 0x1a }, { 2, 2 }, T, R, pfx_66 }, bndmov */
    { { 0x1a }, { 2, 2 }, T, N, pfx_f3 }, /* bndcl */
    { { 0x1a }, { 2, 2 }, T, N, pfx_f2 }, /* bndcu */
    /*{ 0x1b }, { 2, 2 }, F, W }, bndstx */
    /*{ 0x1b }, { 2, 2 }, T, W, pfx_66 }, bndmov */
    { { 0x1b }, { 2, 2 }, F, N, pfx_f3 }, /* bndmk */
    { { 0x1b }, { 2, 2 }, T, N, pfx_f2 }, /* bndcn */
    { { 0x1c, 0x00 }, { 2, 2 }, F, N }, /* cldemote */
    { { 0x1e, 0xc8 }, { 2, 2 }, F, N, pfx_f3 }, /* rdssp */
    { { 0x1e, 0xfa }, { 2, 2 }, F, N, pfx_f3 }, /* endbr64 */
    { { 0x1e, 0xfb }, { 2, 2 }, F, N, pfx_f3 }, /* endbr32 */
    { { 0x1f, 0x00 }, { 2, 2 }, T, N }, /* nop */
    { { 0x20 }, { 2, 2 }, T, N }, /* mov */
    { { 0x21 }, { 2, 2 }, T, N }, /* mov */
    { { 0x22 }, { 2, 2 }, T, N }, /* mov */
    { { 0x23 }, { 2, 2 }, T, N }, /* mov */
    { { 0x28 }, { 2, 2 }, T, R, pfx_no }, /* movaps */
    { { 0x28 }, { 2, 2 }, T, R, pfx_66 }, /* movapd */
    { { 0x29 }, { 2, 2 }, T, W, pfx_no }, /* movaps */
    { { 0x29 }, { 2, 2 }, T, W, pfx_66 }, /* movapd */
    { { 0x2a }, { 2, 2 }, T, R, pfx_no }, /* cvtpi2ps */
    { { 0x2a }, { 2, 2 }, T, R, pfx_66 }, /* cvtpi2pd */
    { { 0x2a }, { 2, 2 }, T, R, pfx_f3 }, /* cvtsi2ss */
    { { 0x2a }, { 2, 2 }, T, R, pfx_f2 }, /* cvtsi2sd */
    { { 0x2b }, { 2, 2 }, T, W, pfx_no }, /* movntps */
    { { 0x2b }, { 2, 2 }, T, W, pfx_66 }, /* movntpd */
    { { 0x2b }, { 2, 2 }, T, W, pfx_f3 }, /* movntss */
    { { 0x2b }, { 2, 2 }, T, W, pfx_f2 }, /* movntsd */
    { { 0x2c }, { 2, 2 }, T, R, pfx_no }, /* cvttps2pi */
    { { 0x2c }, { 2, 2 }, T, R, pfx_66 }, /* cvttpd2pi */
    { { 0x2c }, { 2, 2 }, T, R, pfx_f3 }, /* cvttss2si */
    { { 0x2c }, { 2, 2 }, T, R, pfx_f2 }, /* cvttsd2si */
    { { 0x2d }, { 2, 2 }, T, R, pfx_no }, /* cvtps2pi */
    { { 0x2d }, { 2, 2 }, T, R, pfx_66 }, /* cvtpd2pi */
    { { 0x2d }, { 2, 2 }, T, R, pfx_f3 }, /* cvtss2si */
    { { 0x2d }, { 2, 2 }, T, R, pfx_f2 }, /* cvtsd2si */
    { { 0x2e }, { 2, 2 }, T, R, pfx_no }, /* ucomiss */
    { { 0x2e }, { 2, 2 }, T, R, pfx_66 }, /* ucomisd */
    { { 0x2f }, { 2, 2 }, T, R, pfx_no }, /* comiss */
    { { 0x2f }, { 2, 2 }, T, R, pfx_66 }, /* comisd */
    { { 0x30 }, { 1, 1 }, F, N }, /* wrmsr */
    { { 0x31 }, { 1, 1 }, F, N }, /* rdtsc */
    { { 0x32 }, { 1, 1 }, F, N }, /* rdmsr */
    { { 0x33 }, { 1, 1 }, F, N }, /* rdpmc */
    { { 0x34 }, { 1, 1 }, F, N }, /* sysenter */
    { { 0x35 }, { 1, 1 }, F, N }, /* sysexit */
    CND(0x40,   { 2, 2 }, T, R ), /* cmov<cc> */
    { { 0x50, 0xc0 }, { 2, 2 }, F, N, pfx_no }, /* movmskps */
    { { 0x50, 0xc0 }, { 2, 2 }, F, N, pfx_66 }, /* movmskpd */
    { { 0x51 }, { 2, 2 }, T, R, pfx_no }, /* sqrtps */
    { { 0x51 }, { 2, 2 }, T, R, pfx_66 }, /* sqrtpd */
    { { 0x51 }, { 2, 2 }, T, R, pfx_f3 }, /* sqrtss */
    { { 0x51 }, { 2, 2 }, T, R, pfx_f2 }, /* sqrtsd */
    { { 0x52 }, { 2, 2 }, T, R, pfx_no }, /* rsqrtps */
    { { 0x52 }, { 2, 2 }, T, R, pfx_f3 }, /* rsqrtss */
    { { 0x53 }, { 2, 2 }, T, R, pfx_no }, /* rcpps */
    { { 0x53 }, { 2, 2 }, T, R, pfx_f3 }, /* rcpss */
    { { 0x54 }, { 2, 2 }, T, R, pfx_no }, /* andps */
    { { 0x54 }, { 2, 2 }, T, R, pfx_66 }, /* andpd */
    { { 0x55 }, { 2, 2 }, T, R, pfx_no }, /* andnps */
    { { 0x55 }, { 2, 2 }, T, R, pfx_66 }, /* andnpd */
    { { 0x56 }, { 2, 2 }, T, R, pfx_no }, /* orps */
    { { 0x56 }, { 2, 2 }, T, R, pfx_66 }, /* orpd */
    { { 0x57 }, { 2, 2 }, T, R, pfx_no }, /* xorps */
    { { 0x57 }, { 2, 2 }, T, R, pfx_66 }, /* xorpd */
    { { 0x58 }, { 2, 2 }, T, R, pfx_no }, /* addps */
    { { 0x58 }, { 2, 2 }, T, R, pfx_66 }, /* addpd */
    { { 0x58 }, { 2, 2 }, T, R, pfx_f3 }, /* addss */
    { { 0x58 }, { 2, 2 }, T, R, pfx_f2 }, /* addsd */
    { { 0x59 }, { 2, 2 }, T, R, pfx_no }, /* mulps */
    { { 0x59 }, { 2, 2 }, T, R, pfx_66 }, /* mulpd */
    { { 0x59 }, { 2, 2 }, T, R, pfx_f3 }, /* mulss */
    { { 0x59 }, { 2, 2 }, T, R, pfx_f2 }, /* mulsd */
    { { 0x5a }, { 2, 2 }, T, R, pfx_no }, /* cvtps2pd */
    { { 0x5a }, { 2, 2 }, T, R, pfx_66 }, /* cvtpd2ps */
    { { 0x5a }, { 2, 2 }, T, R, pfx_f3 }, /* cvtss2sd */
    { { 0x5a }, { 2, 2 }, T, R, pfx_f2 }, /* cvtsd2ss */
    { { 0x5b }, { 2, 2 }, T, R, pfx_no }, /* cvtdq2ps */
    { { 0x5b }, { 2, 2 }, T, R, pfx_66 }, /* cvtps2dq */
    { { 0x5b }, { 2, 2 }, T, R, pfx_f3 }, /* cvttps2dq */
    { { 0x5c }, { 2, 2 }, T, R, pfx_no }, /* subps */
    { { 0x5c }, { 2, 2 }, T, R, pfx_66 }, /* subpd */
    { { 0x5c }, { 2, 2 }, T, R, pfx_f3 }, /* subss */
    { { 0x5c }, { 2, 2 }, T, R, pfx_f2 }, /* subsd */
    { { 0x5d }, { 2, 2 }, T, R, pfx_no }, /* minps */
    { { 0x5d }, { 2, 2 }, T, R, pfx_66 }, /* minpd */
    { { 0x5d }, { 2, 2 }, T, R, pfx_f3 }, /* minss */
    { { 0x5d }, { 2, 2 }, T, R, pfx_f2 }, /* minsd */
    { { 0x5e }, { 2, 2 }, T, R, pfx_no }, /* divps */
    { { 0x5e }, { 2, 2 }, T, R, pfx_66 }, /* divpd */
    { { 0x5e }, { 2, 2 }, T, R, pfx_f3 }, /* divss */
    { { 0x5e }, { 2, 2 }, T, R, pfx_f2 }, /* divsd */
    { { 0x5f }, { 2, 2 }, T, R, pfx_no }, /* maxps */
    { { 0x5f }, { 2, 2 }, T, R, pfx_66 }, /* maxpd */
    { { 0x5f }, { 2, 2 }, T, R, pfx_f3 }, /* maxss */
    { { 0x5f }, { 2, 2 }, T, R, pfx_f2 }, /* maxsd */
    { { 0x60 }, { 2, 2 }, T, R, pfx_no }, /* punpcklbw */
    { { 0x60 }, { 2, 2 }, T, R, pfx_66 }, /* punpcklbw */
    { { 0x61 }, { 2, 2 }, T, R, pfx_no }, /* punpcklwd */
    { { 0x61 }, { 2, 2 }, T, R, pfx_66 }, /* punpcklwd */
    { { 0x62 }, { 2, 2 }, T, R, pfx_no }, /* punpckldq */
    { { 0x62 }, { 2, 2 }, T, R, pfx_66 }, /* punpckldq */
    { { 0x63 }, { 2, 2 }, T, R, pfx_no }, /* packsswb */
    { { 0x63 }, { 2, 2 }, T, R, pfx_66 }, /* packsswb */
    { { 0x64 }, { 2, 2 }, T, R, pfx_no }, /* pcmpgtb */
    { { 0x64 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpgtb */
    { { 0x65 }, { 2, 2 }, T, R, pfx_no }, /* pcmpgtw */
    { { 0x65 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpgtw */
    { { 0x66 }, { 2, 2 }, T, R, pfx_no }, /* pcmpgtd */
    { { 0x66 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpgtd */
    { { 0x67 }, { 2, 2 }, T, R, pfx_no }, /* packuswb */
    { { 0x67 }, { 2, 2 }, T, R, pfx_66 }, /* packuswb */
    { { 0x68 }, { 2, 2 }, T, R, pfx_no }, /* punpckhbw */
    { { 0x68 }, { 2, 2 }, T, R, pfx_66 }, /* punpckhbw */
    { { 0x69 }, { 2, 2 }, T, R, pfx_no }, /* punpckhwd */
    { { 0x69 }, { 2, 2 }, T, R, pfx_66 }, /* punpckhwd */
    { { 0x6a }, { 2, 2 }, T, R, pfx_no }, /* punpckhdq */
    { { 0x6a }, { 2, 2 }, T, R, pfx_66 }, /* punpckhdq */
    { { 0x6b }, { 2, 2 }, T, R, pfx_no }, /* packssdw */
    { { 0x6b }, { 2, 2 }, T, R, pfx_66 }, /* packssdw */
    { { 0x6c }, { 2, 2 }, T, R, pfx_66 }, /* punpcklqdq */
    { { 0x6d }, { 2, 2 }, T, R, pfx_66 }, /* punpckhqdq */
    { { 0x6e }, { 2, 2 }, T, R, pfx_no }, /* movd */
    { { 0x6e }, { 2, 2 }, T, R, pfx_66 }, /* movd */
    { { 0x6f }, { 2, 2 }, T, R, pfx_no }, /* movq */
    { { 0x6f }, { 2, 2 }, T, R, pfx_66 }, /* movdqa */
    { { 0x6f }, { 2, 2 }, T, R, pfx_f3 }, /* movdqu */
    { { 0x70 }, { 3, 3 }, T, R, pfx_no }, /* pshufw */
    { { 0x70 }, { 3, 3 }, T, R, pfx_66 }, /* pshufd */
    { { 0x70 }, { 3, 3 }, T, R, pfx_f3 }, /* pshuflw */
    { { 0x70 }, { 3, 3 }, T, R, pfx_f2 }, /* pshufhw */
    { { 0x71, 0xd0 }, { 3, 3 }, F, N, pfx_no }, /* psrlw */
    { { 0x71, 0xd0 }, { 3, 3 }, F, N, pfx_66 }, /* psrlw */
    { { 0x71, 0xe0 }, { 3, 3 }, F, N, pfx_no }, /* psraw */
    { { 0x71, 0xe0 }, { 3, 3 }, F, N, pfx_66 }, /* psraw */
    { { 0x71, 0xf0 }, { 3, 3 }, F, N, pfx_no }, /* psllw */
    { { 0x71, 0xf0 }, { 3, 3 }, F, N, pfx_66 }, /* psllw */
    { { 0x72, 0xd0 }, { 3, 3 }, F, N, pfx_no }, /* psrld */
    { { 0x72, 0xd0 }, { 3, 3 }, F, N, pfx_66 }, /* psrld */
    { { 0x72, 0xe0 }, { 3, 3 }, F, N, pfx_no }, /* psrad */
    { { 0x72, 0xe0 }, { 3, 3 }, F, N, pfx_66 }, /* psrad */
    { { 0x72, 0xf0 }, { 3, 3 }, F, N, pfx_no }, /* pslld */
    { { 0x72, 0xf0 }, { 3, 3 }, F, N, pfx_66 }, /* pslld */
    { { 0x73, 0xd0 }, { 3, 3 }, F, N, pfx_no }, /* psrlq */
    { { 0x73, 0xd0 }, { 3, 3 }, F, N, pfx_66 }, /* psrlq */
    { { 0x73, 0xd8 }, { 3, 3 }, F, N, pfx_66 }, /* psrldq */
    { { 0x73, 0xf0 }, { 3, 3 }, F, N, pfx_no }, /* psllq */
    { { 0x73, 0xf0 }, { 3, 3 }, F, N, pfx_66 }, /* psllq */
    { { 0x73, 0xf8 }, { 3, 3 }, F, N, pfx_66 }, /* pslldq */
    { { 0x74 }, { 2, 2 }, T, R, pfx_no }, /* pcmpeqb */
    { { 0x74 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpeqb */
    { { 0x75 }, { 2, 2 }, T, R, pfx_no }, /* pcmpeqw */
    { { 0x75 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpeqw */
    { { 0x76 }, { 2, 2 }, T, R, pfx_no }, /* pcmpeqd */
    { { 0x76 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpeqd */
    { { 0x77 }, { 1, 1 }, F, N }, /* emms */
    /*{ 0x78 }, { 2, 2 }, T, W }, vmread */
    { { 0x78, 0xc0 }, { 4, 4 }, F, N, pfx_66 }, /* extrq */
    { { 0x78, 0xc0 }, { 4, 4 }, F, N, pfx_f2 }, /* insertq */
    { { 0x79 }, { 2, 2 }, T, R }, /* vmwrite */
    { { 0x79, 0xc0 }, { 2, 2 }, F, N, pfx_66 }, /* extrq */
    { { 0x79, 0xc0 }, { 2, 2 }, F, N, pfx_f2 }, /* insertq */
    { { 0x7c }, { 2, 2 }, T, R, pfx_66 }, /* haddpd */
    { { 0x7c }, { 2, 2 }, T, R, pfx_f2 }, /* haddps */
    { { 0x7d }, { 2, 2 }, T, R, pfx_66 }, /* hsubpd */
    { { 0x7d }, { 2, 2 }, T, R, pfx_f2 }, /* hsubps */
    { { 0x7e }, { 2, 2 }, T, W, pfx_no }, /* movd */
    { { 0x7e }, { 2, 2 }, T, W, pfx_66 }, /* movd */
    { { 0x7e }, { 2, 2 }, T, R, pfx_f3 }, /* movq */
    { { 0x7f }, { 2, 2 }, T, W, pfx_no }, /* movq */
    { { 0x7f }, { 2, 2 }, T, W, pfx_66 }, /* movdqa */
    { { 0x7f }, { 2, 2 }, T, W, pfx_f3 }, /* movdqu */
    CND(0x80,   { 5, 5 }, F, N ), /* j<cc> */
    CND(0x90,   { 2, 2 }, T, W ), /* set<cc> */
    { { 0xa0 }, { 1, 1 }, F, W }, /* push %fs */
    { { 0xa1 }, { 1, 1 }, F, R }, /* pop %fs */
    { { 0xa2 }, { 1, 1 }, F, N }, /* cpuid */
    { { 0xa3 }, { 2, 2 }, T, R }, /* bt */
    { { 0xa4 }, { 3, 3 }, T, W }, /* shld */
    { { 0xa5 }, { 2, 2 }, T, W }, /* shld */
    { { 0xa8 }, { 1, 1 }, F, W }, /* push %gs */
    { { 0xa9 }, { 1, 1 }, F, R }, /* pop %gs */
    { { 0xaa }, { 1, 1 }, F, N }, /* rsm */
    { { 0xab }, { 2, 2 }, T, W }, /* bts */
    { { 0xac }, { 3, 3 }, T, W }, /* shrd */
    { { 0xad }, { 2, 2 }, T, W }, /* shrd */
    { { 0xae, 0x00 }, { 2, 2 }, F, W }, /* fxsave */
    { { 0xae, 0x08 }, { 2, 2 }, F, R }, /* fxrstor */
    { { 0xae, 0x10 }, { 2, 2 }, F, R }, /* ldmxcsr */
    { { 0xae, 0x18 }, { 2, 2 }, F, W }, /* stmxcsr */
    { { 0xae, 0x20 }, { 2, 2 }, F, W }, /* xsave */
    { { 0xae, 0x20 }, { 2, 2 }, F, R, pfx_f3 }, /* ptwrite */
    { { 0xae, 0x28 }, { 2, 2 }, F, R }, /* xrstor */
    { { 0xae, 0x30 }, { 2, 2 }, F, W }, /* xsaveopt */
    { { 0xae, 0x30 }, { 2, 2 }, F, N, pfx_66 }, /* clwb */
    /*{ 0xae, 0x30 }, { 2, 2 }, F, W, pfx_f3 }, clrssbsy */
    { { 0xae, 0x38 }, { 2, 2 }, F, N }, /* clflush */
    { { 0xae, 0x38 }, { 2, 2 }, F, N, pfx_66 }, /* clflushopt */
    { { 0xae, 0xc0 }, { 0, 2 }, F, N, pfx_f3 }, /* rdfsbase */
    { { 0xae, 0xc8 }, { 0, 2 }, F, N, pfx_f3 }, /* rdgsbase */
    { { 0xae, 0xd0 }, { 0, 2 }, F, N, pfx_f3 }, /* wrfsbase */
    { { 0xae, 0xd8 }, { 0, 2 }, F, N, pfx_f3 }, /* wrgsbase */
    { { 0xae, 0xe8 }, { 2, 2 }, F, N }, /* lfence */
    /*{ 0xae, 0xe8 }, { 2, 2 }, F, R, pfx_f3 }, incssp */
    { { 0xae, 0xf0 }, { 2, 2 }, F, N }, /* mfence */
    { { 0xae, 0xf0 }, { 2, 2 }, F, N, pfx_66 }, /* tpause */
    { { 0xae, 0xf0 }, { 2, 2 }, F, N, pfx_f3 }, /* umonitor */
    { { 0xae, 0xf0 }, { 2, 2 }, F, N, pfx_f2 }, /* umwait */
    { { 0xae, 0xf8 }, { 2, 2 }, F, N }, /* sfence */
    { { 0xaf }, { 2, 2 }, T, R }, /* imul */
    { { 0xb0 }, { 2, 2 }, F, W }, /* cmpxchg */
    { { 0xb1 }, { 2, 2 }, F, W }, /* cmpxchg */
    { { 0xb2 }, { 2, 2 }, F, R }, /* lss */
    { { 0xb3 }, { 2, 2 }, T, W }, /* btr */
    { { 0xb4 }, { 2, 2 }, F, R }, /* lfs */
    { { 0xb5 }, { 2, 2 }, F, R }, /* lgs */
    { { 0xb6 }, { 2, 2 }, F, R }, /* movzx */
    { { 0xb7 }, { 2, 2 }, F, R }, /* movzx */
    { { 0xb8 }, { 2, 2 }, F, R }, /* popcnt */
    { { 0xb9 }, { 2, 2 }, F, N }, /* ud1 */
    { { 0xba, 0x20 }, { 3, 3 }, T, R }, /* bt */
    { { 0xba, 0x28 }, { 3, 3 }, T, W }, /* bts */
    { { 0xba, 0x30 }, { 3, 3 }, T, W }, /* btr */
    { { 0xba, 0x38 }, { 3, 3 }, T, W }, /* btc */
    { { 0xbb }, { 2, 2 }, T, W }, /* btc */
    { { 0xbc }, { 2, 2 }, T, R }, /* bsf */
    { { 0xbc }, { 2, 2 }, T, R, pfx_f3 }, /* tzcnt */
    { { 0xbd }, { 2, 2 }, T, R }, /* bsr */
    { { 0xbd }, { 2, 2 }, T, R, pfx_f3 }, /* lzcnt */
    { { 0xbe }, { 2, 2 }, F, R }, /* movsx */
    { { 0xbf }, { 2, 2 }, F, R }, /* movsx */
    { { 0xc0 }, { 2, 2 }, F, W }, /* xadd */
    { { 0xc1 }, { 2, 2 }, F, W }, /* xadd */
    { { 0xc2 }, { 3, 3 }, T, R, pfx_no }, /* cmpps */
    { { 0xc2 }, { 3, 3 }, T, R, pfx_66 }, /* cmppd */
    { { 0xc2 }, { 3, 3 }, T, R, pfx_f3 }, /* cmpss */
    { { 0xc2 }, { 3, 3 }, T, R, pfx_f2 }, /* cmpsd */
    { { 0xc3 }, { 2, 2 }, F, W }, /* movnti */
    { { 0xc4 }, { 3, 3 }, T, R, pfx_no }, /* pinsrw */
    { { 0xc4 }, { 3, 3 }, T, R, pfx_66 }, /* pinsrw */
    { { 0xc5, 0xc0 }, { 3, 3 }, F, N, pfx_no }, /* pextrw */
    { { 0xc5, 0xc0 }, { 3, 3 }, F, N, pfx_66 }, /* pextrw */
    { { 0xc6 }, { 3, 3 }, T, R, pfx_no }, /* shufps */
    { { 0xc6 }, { 3, 3 }, T, R, pfx_66 }, /* shufpd */
    { { 0xc7, 0x08 }, { 2, 2 }, F, W }, /* cmpxchg8b */
    { { 0xc7, 0x18 }, { 2, 2 }, F, R }, /* xrstors */
    { { 0xc7, 0x20 }, { 2, 2 }, F, W }, /* xsavec */
    { { 0xc7, 0x28 }, { 2, 2 }, F, W }, /* xsaves */
    { { 0xc7, 0x30 }, { 2, 2 }, F, R }, /* vmptrld */
    { { 0xc7, 0x30 }, { 2, 2 }, F, R, pfx_66 }, /* vmclear */
    { { 0xc7, 0x30 }, { 2, 2 }, F, R, pfx_f3 }, /* vmxon */
    { { 0xc7, 0x38 }, { 2, 2 }, F, R }, /* vmptrst */
    { { 0xc7, 0xf0 }, { 2, 2 }, F, N }, /* rdrand */
    { { 0xc7, 0xf8 }, { 2, 2 }, F, N }, /* rdseed */
    { { 0xc7, 0xf8 }, { 2, 2 }, F, N, pfx_f3 }, /* rdpid */
    REG(0xc8,   { 1, 1 }, F, N ), /* bswap */
    { { 0xd0 }, { 2, 2 }, T, R, pfx_66 }, /* addsubpd */
    { { 0xd0 }, { 2, 2 }, T, R, pfx_f2 }, /* addsubps */
    { { 0xd1 }, { 2, 2 }, T, R, pfx_no }, /* psrlw */
    { { 0xd1 }, { 2, 2 }, T, R, pfx_66 }, /* psrlw */
    { { 0xd2 }, { 2, 2 }, T, R, pfx_no }, /* psrld */
    { { 0xd2 }, { 2, 2 }, T, R, pfx_66 }, /* psrld */
    { { 0xd3 }, { 2, 2 }, T, R, pfx_no }, /* psrlq */
    { { 0xd3 }, { 2, 2 }, T, R, pfx_66 }, /* psrlq */
    { { 0xd4 }, { 2, 2 }, T, R, pfx_no }, /* paddq */
    { { 0xd4 }, { 2, 2 }, T, R, pfx_66 }, /* paddq */
    { { 0xd5 }, { 2, 2 }, T, R, pfx_no }, /* pmullw */
    { { 0xd5 }, { 2, 2 }, T, R, pfx_66 }, /* pmullw */
    { { 0xd6 }, { 2, 2 }, T, W, pfx_66 }, /* movq */
    { { 0xd6, 0xc0 }, { 2, 2 }, F, N, pfx_f3 }, /* movq2dq */
    { { 0xd6, 0xc0 }, { 2, 2 }, F, N, pfx_f2 }, /* movdq2q */
    { { 0xd7, 0xc0 }, { 2, 2 }, F, N, pfx_no }, /* pmovmskb */
    { { 0xd7, 0xc0 }, { 2, 2 }, F, N, pfx_66 }, /* pmovmskb */
    { { 0xd8 }, { 2, 2 }, T, R, pfx_no }, /* psubusb */
    { { 0xd8 }, { 2, 2 }, T, R, pfx_66 }, /* psubusb */
    { { 0xd9 }, { 2, 2 }, T, R, pfx_no }, /* psubusw */
    { { 0xd9 }, { 2, 2 }, T, R, pfx_66 }, /* psubusw */
    { { 0xda }, { 2, 2 }, T, R, pfx_no }, /* pminub */
    { { 0xda }, { 2, 2 }, T, R, pfx_66 }, /* pminub */
    { { 0xdb }, { 2, 2 }, T, R, pfx_no }, /* pand */
    { { 0xdb }, { 2, 2 }, T, R, pfx_66 }, /* pand */
    { { 0xdc }, { 2, 2 }, T, R, pfx_no }, /* paddusb */
    { { 0xdc }, { 2, 2 }, T, R, pfx_66 }, /* paddusb */
    { { 0xdd }, { 2, 2 }, T, R, pfx_no }, /* paddusw */
    { { 0xdd }, { 2, 2 }, T, R, pfx_66 }, /* paddusw */
    { { 0xde }, { 2, 2 }, T, R, pfx_no }, /* pmaxub */
    { { 0xde }, { 2, 2 }, T, R, pfx_66 }, /* pmaxub */
    { { 0xdf }, { 2, 2 }, T, R, pfx_no }, /* pandn */
    { { 0xdf }, { 2, 2 }, T, R, pfx_66 }, /* pandn */
    { { 0xe0 }, { 2, 2 }, T, R, pfx_no }, /* pavgb */
    { { 0xe0 }, { 2, 2 }, T, R, pfx_66 }, /* pavgb */
    { { 0xe1 }, { 2, 2 }, T, R, pfx_no }, /* psraw */
    { { 0xe1 }, { 2, 2 }, T, R, pfx_66 }, /* psraw */
    { { 0xe2 }, { 2, 2 }, T, R, pfx_no }, /* psrad */
    { { 0xe2 }, { 2, 2 }, T, R, pfx_66 }, /* psrad */
    { { 0xe3 }, { 2, 2 }, T, R, pfx_no }, /* pavgw */
    { { 0xe3 }, { 2, 2 }, T, R, pfx_66 }, /* pavgw */
    { { 0xe4 }, { 2, 2 }, T, R, pfx_no }, /* pmulhuw */
    { { 0xe4 }, { 2, 2 }, T, R, pfx_66 }, /* pmulhuw */
    { { 0xe5 }, { 2, 2 }, T, R, pfx_no }, /* pmulhw */
    { { 0xe5 }, { 2, 2 }, T, R, pfx_66 }, /* pmulhw */
    { { 0xe6 }, { 2, 2 }, T, R, pfx_66 }, /* cvttpd2dq */
    { { 0xe6 }, { 2, 2 }, T, R, pfx_f3 }, /* cvtdq2pd */
    { { 0xe6 }, { 2, 2 }, T, R, pfx_f2 }, /* cvtpd2dq */
    { { 0xe7 }, { 2, 2 }, F, W, pfx_no }, /* movntq */
    { { 0xe7 }, { 2, 2 }, F, W, pfx_66 }, /* movntdq */
    { { 0xe8 }, { 2, 2 }, T, R, pfx_no }, /* psubsb */
    { { 0xe8 }, { 2, 2 }, T, R, pfx_66 }, /* psubsb */
    { { 0xe9 }, { 2, 2 }, T, R, pfx_no }, /* psubsw */
    { { 0xe9 }, { 2, 2 }, T, R, pfx_66 }, /* psubsw */
    { { 0xea }, { 2, 2 }, T, R, pfx_no }, /* pminsw */
    { { 0xea }, { 2, 2 }, T, R, pfx_66 }, /* pminsw */
    { { 0xeb }, { 2, 2 }, T, R, pfx_no }, /* por */
    { { 0xeb }, { 2, 2 }, T, R, pfx_66 }, /* por */
    { { 0xec }, { 2, 2 }, T, R, pfx_no }, /* paddsb */
    { { 0xec }, { 2, 2 }, T, R, pfx_66 }, /* paddsb */
    { { 0xed }, { 2, 2 }, T, R, pfx_no }, /* paddsw */
    { { 0xed }, { 2, 2 }, T, R, pfx_66 }, /* paddsw */
    { { 0xee }, { 2, 2 }, T, R, pfx_no }, /* pmaxsw */
    { { 0xee }, { 2, 2 }, T, R, pfx_66 }, /* pmaxsw */
    { { 0xef }, { 2, 2 }, T, R, pfx_no }, /* pxor */
    { { 0xef }, { 2, 2 }, T, R, pfx_66 }, /* pxor */
    { { 0xf0 }, { 2, 2 }, T, R, pfx_f2 }, /* lddqu */
    { { 0xf1 }, { 2, 2 }, T, R, pfx_no }, /* psllw */
    { { 0xf1 }, { 2, 2 }, T, R, pfx_66 }, /* psllw */
    { { 0xf2 }, { 2, 2 }, T, R, pfx_no }, /* pslld */
    { { 0xf2 }, { 2, 2 }, T, R, pfx_66 }, /* pslld */
    { { 0xf3 }, { 2, 2 }, T, R, pfx_no }, /* psllq */
    { { 0xf3 }, { 2, 2 }, T, R, pfx_66 }, /* psllq */
    { { 0xf4 }, { 2, 2 }, T, R, pfx_no }, /* pmuludq */
    { { 0xf4 }, { 2, 2 }, T, R, pfx_66 }, /* pmuludq */
    { { 0xf5 }, { 2, 2 }, T, R, pfx_no }, /* pmaddwd */
    { { 0xf5 }, { 2, 2 }, T, R, pfx_66 }, /* pmaddwd */
    { { 0xf6 }, { 2, 2 }, T, R, pfx_no }, /* psadbw */
    { { 0xf6 }, { 2, 2 }, T, R, pfx_66 }, /* psadbw */
    { { 0xf7, 0xc0 }, { 2, 2 }, F, W, pfx_no }, /* maskmovq */
    { { 0xf7, 0xc0 }, { 2, 2 }, F, W, pfx_66 }, /* maskmovdqu */
    { { 0xf8 }, { 2, 2 }, T, R, pfx_no }, /* psubb */
    { { 0xf8 }, { 2, 2 }, T, R, pfx_66 }, /* psubb */
    { { 0xf9 }, { 2, 2 }, T, R, pfx_no }, /* psubw */
    { { 0xf9 }, { 2, 2 }, T, R, pfx_66 }, /* psubw */
    { { 0xfa }, { 2, 2 }, T, R, pfx_no }, /* psubd */
    { { 0xfa }, { 2, 2 }, T, R, pfx_66 }, /* psubd */
    { { 0xfb }, { 2, 2 }, T, R, pfx_no }, /* psubq */
    { { 0xfb }, { 2, 2 }, T, R, pfx_66 }, /* psubq */
    { { 0xfc }, { 2, 2 }, T, R, pfx_no }, /* paddb */
    { { 0xfc }, { 2, 2 }, T, R, pfx_66 }, /* paddb */
    { { 0xfd }, { 2, 2 }, T, R, pfx_no }, /* paddw */
    { { 0xfd }, { 2, 2 }, T, R, pfx_66 }, /* paddw */
    { { 0xfe }, { 2, 2 }, T, R, pfx_no }, /* paddd */
    { { 0xfe }, { 2, 2 }, T, R, pfx_66 }, /* paddd */
    { { 0xff }, { 2, 2 }, F, N }, /* ud0 */
}, legacy_0f38[] = {
    { { 0x00 }, { 2, 2 }, T, R, pfx_no }, /* pshufb */
    { { 0x00 }, { 2, 2 }, T, R, pfx_66 }, /* pshufb */
    { { 0x01 }, { 2, 2 }, T, R, pfx_no }, /* phaddw */
    { { 0x01 }, { 2, 2 }, T, R, pfx_66 }, /* phaddw */
    { { 0x02 }, { 2, 2 }, T, R, pfx_no }, /* phaddd */
    { { 0x02 }, { 2, 2 }, T, R, pfx_66 }, /* phaddd */
    { { 0x03 }, { 2, 2 }, T, R, pfx_no }, /* phaddsw */
    { { 0x03 }, { 2, 2 }, T, R, pfx_66 }, /* phaddsw */
    { { 0x04 }, { 2, 2 }, T, R, pfx_no }, /* pmaddubsw */
    { { 0x04 }, { 2, 2 }, T, R, pfx_66 }, /* pmaddubsw */
    { { 0x05 }, { 2, 2 }, T, R, pfx_no }, /* phsubw */
    { { 0x05 }, { 2, 2 }, T, R, pfx_66 }, /* phsubw */
    { { 0x06 }, { 2, 2 }, T, R, pfx_no }, /* phsubd */
    { { 0x06 }, { 2, 2 }, T, R, pfx_66 }, /* phsubd */
    { { 0x07 }, { 2, 2 }, T, R, pfx_no }, /* phsubsw */
    { { 0x07 }, { 2, 2 }, T, R, pfx_66 }, /* phsubsw */
    { { 0x08 }, { 2, 2 }, T, R, pfx_no }, /* psignb */
    { { 0x08 }, { 2, 2 }, T, R, pfx_66 }, /* psignb */
    { { 0x09 }, { 2, 2 }, T, R, pfx_no }, /* psignw */
    { { 0x09 }, { 2, 2 }, T, R, pfx_66 }, /* psignw */
    { { 0x0a }, { 2, 2 }, T, R, pfx_no }, /* psignd */
    { { 0x0a }, { 2, 2 }, T, R, pfx_66 }, /* psignd */
    { { 0x0b }, { 2, 2 }, T, R, pfx_no }, /* pmulhrsw */
    { { 0x0b }, { 2, 2 }, T, R, pfx_66 }, /* pmulhrsw */
    { { 0x10 }, { 2, 2 }, T, R, pfx_66 }, /* pblendvb */
    { { 0x14 }, { 2, 2 }, T, R, pfx_66 }, /* blendvps */
    { { 0x15 }, { 2, 2 }, T, R, pfx_66 }, /* blendvpd */
    { { 0x17 }, { 2, 2 }, T, R, pfx_66 }, /* ptest */
    { { 0x1c }, { 2, 2 }, T, R, pfx_no }, /* pabsb */
    { { 0x1c }, { 2, 2 }, T, R, pfx_66 }, /* pabsb */
    { { 0x1d }, { 2, 2 }, T, R, pfx_no }, /* pabsw */
    { { 0x1d }, { 2, 2 }, T, R, pfx_66 }, /* pabsw */
    { { 0x1e }, { 2, 2 }, T, R, pfx_no }, /* pabsd */
    { { 0x1e }, { 2, 2 }, T, R, pfx_66 }, /* pabsd */
    { { 0x20 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxbw */
    { { 0x21 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxbd */
    { { 0x22 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxbq */
    { { 0x23 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxwd */
    { { 0x24 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxwq */
    { { 0x25 }, { 2, 2 }, T, R, pfx_66 }, /* pmovsxdq */
    { { 0x28 }, { 2, 2 }, T, R, pfx_66 }, /* pmuldq */
    { { 0x29 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpeqq */
    { { 0x2a }, { 2, 2 }, F, R, pfx_66 }, /* movntdqa */
    { { 0x2b }, { 2, 2 }, T, R, pfx_66 }, /* packusdw */
    { { 0x30 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxbw */
    { { 0x31 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxbd */
    { { 0x32 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxbq */
    { { 0x33 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxwd */
    { { 0x34 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxwq */
    { { 0x35 }, { 2, 2 }, T, R, pfx_66 }, /* pmovzxdq */
    { { 0x37 }, { 2, 2 }, T, R, pfx_66 }, /* pcmpgtq */
    { { 0x38 }, { 2, 2 }, T, R, pfx_66 }, /* pminsb */
    { { 0x39 }, { 2, 2 }, T, R, pfx_66 }, /* pminsd */
    { { 0x3a }, { 2, 2 }, T, R, pfx_66 }, /* pminuw */
    { { 0x3b }, { 2, 2 }, T, R, pfx_66 }, /* pminud */
    { { 0x3c }, { 2, 2 }, T, R, pfx_66 }, /* pmaxsb */
    { { 0x3d }, { 2, 2 }, T, R, pfx_66 }, /* pmaxsd */
    { { 0x3e }, { 2, 2 }, T, R, pfx_66 }, /* pmaxuw */
    { { 0x3f }, { 2, 2 }, T, R, pfx_66 }, /* pmaxud */
    { { 0x40 }, { 2, 2 }, T, R, pfx_66 }, /* pmulld */
    { { 0x41 }, { 2, 2 }, T, R, pfx_66 }, /* phminposuw */
    { { 0x80 }, { 2, 2 }, T, R, pfx_66 }, /* invept */
    { { 0x81 }, { 2, 2 }, T, R, pfx_66 }, /* invvpid */
    { { 0x82 }, { 2, 2 }, T, R, pfx_66 }, /* invpcid */
    { { 0xc8 }, { 2, 2 }, T, R, pfx_no }, /* sha1nexte */
    { { 0xc9 }, { 2, 2 }, T, R, pfx_no }, /* sha1msg1 */
    { { 0xca }, { 2, 2 }, T, R, pfx_no }, /* sha1msg2 */
    { { 0xcb }, { 2, 2 }, T, R, pfx_no }, /* sha256rnds2 */
    { { 0xcc }, { 2, 2 }, T, R, pfx_no }, /* sha256msg1 */
    { { 0xcd }, { 2, 2 }, T, R, pfx_no }, /* sha256msg2 */
    { { 0xcf }, { 2, 2 }, T, R, pfx_66 }, /* gf2p8mulb */
    { { 0xdb }, { 2, 2 }, T, R, pfx_66 }, /* aesimc */
    { { 0xdc }, { 2, 2 }, T, R, pfx_66 }, /* aesenc */
    { { 0xdd }, { 2, 2 }, T, R, pfx_66 }, /* aesenclast */
    { { 0xde }, { 2, 2 }, T, R, pfx_66 }, /* aesdec */
    { { 0xdf }, { 2, 2 }, T, R, pfx_66 }, /* aesdeclast */
    { { 0xf0 }, { 2, 2 }, T, R }, /* movbe */
    { { 0xf0 }, { 2, 2 }, T, R, pfx_f2 }, /* crc32 */
    { { 0xf1 }, { 2, 2 }, T, W }, /* movbe */
    { { 0xf1 }, { 2, 2 }, T, R, pfx_f2 }, /* crc32 */
    /*{ 0xf5 }, { 2, 2 }, F, W, pfx_66 }, wruss */
    /*{ 0xf6 }, { 2, 2 }, F, W }, wrss */
    { { 0xf6 }, { 2, 2 }, T, R, pfx_66 }, /* adcx */
    { { 0xf6 }, { 2, 2 }, T, R, pfx_f3 }, /* adox */
    { { 0xf8 }, { 2, 2 }, F, W, pfx_66 }, /* movdir64b */
    { { 0xf8 }, { 2, 2 }, F, W, pfx_f3 }, /* enqcmds */
    { { 0xf8 }, { 2, 2 }, F, W, pfx_f2 }, /* enqcmd */
    { { 0xf9 }, { 2, 2 }, F, W }, /* movdiri */
};
#undef CND
#undef REG

static const struct {
    uint8_t opc;
    uint8_t mem:2;
    uint8_t pfx:2;
} legacy_0f3a[] = {
    { 0x08, R, pfx_66 }, /* roundps */
    { 0x09, R, pfx_66 }, /* roundpd */
    { 0x0a, R, pfx_66 }, /* roundss */
    { 0x0b, R, pfx_66 }, /* roundsd */
    { 0x0c, R, pfx_66 }, /* blendps */
    { 0x0d, R, pfx_66 }, /* blendpd */
    { 0x0e, R, pfx_66 }, /* pblendw */
    { 0x0f, R, pfx_no }, /* palignr */
    { 0x0f, R, pfx_66 }, /* palignr */
    { 0x14, W, pfx_66 }, /* pextrb */
    { 0x15, W, pfx_66 }, /* pextrw */
    { 0x16, W, pfx_66 }, /* pextrd */
    { 0x17, W, pfx_66 }, /* extractps */
    { 0x20, R, pfx_66 }, /* pinsrb */
    { 0x21, R, pfx_66 }, /* insertps */
    { 0x22, R, pfx_66 }, /* pinsrd */
    { 0x40, R, pfx_66 }, /* dpps */
    { 0x41, R, pfx_66 }, /* dppd */
    { 0x42, R, pfx_66 }, /* mpsadbw */
    { 0x44, R, pfx_66 }, /* pclmulqdq */
    { 0x60, R, pfx_66 }, /* pcmpestrm */
    { 0x61, R, pfx_66 }, /* pcmpestri */
    { 0x62, R, pfx_66 }, /* pcmpistrm */
    { 0x63, R, pfx_66 }, /* pcmpistri */
    { 0xcc, R, pfx_no }, /* sha1rnds4 */
    { 0xce, R, pfx_66 }, /* gf2p8affineqb */
    { 0xcf, R, pfx_66 }, /* gf2p8affineinvqb */
    { 0xdf, R, pfx_66 }, /* aeskeygenassist */
};

static const struct {
    uint8_t opc[2];
    bool modrm:1; /* Should register form (also) be tested? */
    uint8_t mem:2;
} fpu[] = {
    { { 0xd8, 0x00 }, T, R }, /* fadd */
    { { 0xd8, 0x08 }, T, R }, /* fmul */
    { { 0xd8, 0x10 }, T, R }, /* fcom */
    { { 0xd8, 0x18 }, T, R }, /* fcomp */
    { { 0xd8, 0x20 }, T, R }, /* fsub */
    { { 0xd8, 0x28 }, T, R }, /* fsubr */
    { { 0xd8, 0x30 }, T, R }, /* fdiv */
    { { 0xd8, 0x38 }, T, R }, /* fdivr */
    { { 0xd9, 0x00 }, T, R }, /* fld */
    { { 0xd9, 0x10 }, F, W }, /* fst */
    { { 0xd9, 0x18 }, T, W }, /* fstp */
    { { 0xd9, 0x20 }, F, R }, /* fldenv */
    { { 0xd9, 0x28 }, F, R }, /* fldcw */
    { { 0xd9, 0x30 }, F, W }, /* fnstenv */
    { { 0xd9, 0x38 }, F, W }, /* fnstcw */
    { { 0xd9, 0xc8 }, F, N }, /* fxch */
    { { 0xd9, 0xd0 }, F, N }, /* fnop */
    { { 0xd9, 0xe0 }, F, N }, /* fchs */
    { { 0xd9, 0xe1 }, F, N }, /* fabs */
    { { 0xd9, 0xe4 }, F, N }, /* ftst */
    { { 0xd9, 0xe5 }, F, N }, /* fxam */
    { { 0xd9, 0xe6 }, F, N }, /* ftstp */
    { { 0xd9, 0xe8 }, F, N }, /* fld1 */
    { { 0xd9, 0xe9 }, F, N }, /* fldl2t */
    { { 0xd9, 0xea }, F, N }, /* fldl2e */
    { { 0xd9, 0xeb }, F, N }, /* fldpi */
    { { 0xd9, 0xec }, F, N }, /* fldlg2 */
    { { 0xd9, 0xed }, F, N }, /* fldln2 */
    { { 0xd9, 0xee }, F, N }, /* fldz */
    { { 0xd9, 0xf0 }, F, N }, /* f2xm1 */
    { { 0xd9, 0xf1 }, F, N }, /* fyl2x */
    { { 0xd9, 0xf2 }, F, N }, /* fptan */
    { { 0xd9, 0xf3 }, F, N }, /* fpatan */
    { { 0xd9, 0xf4 }, F, N }, /* fxtract */
    { { 0xd9, 0xf5 }, F, N }, /* fprem1 */
    { { 0xd9, 0xf6 }, F, N }, /* fdecstp */
    { { 0xd9, 0xf7 }, F, N }, /* fincstp */
    { { 0xd9, 0xf8 }, F, N }, /* fprem */
    { { 0xd9, 0xf9 }, F, N }, /* fyl2xp1 */
    { { 0xd9, 0xfa }, F, N }, /* fsqrt */
    { { 0xd9, 0xfb }, F, N }, /* fsincos */
    { { 0xd9, 0xfc }, F, N }, /* frndint */
    { { 0xd9, 0xfd }, F, N }, /* fscale */
    { { 0xd9, 0xfe }, F, N }, /* fsin */
    { { 0xd9, 0xff }, F, N }, /* fcos */
    { { 0xda, 0x00 }, F, R }, /* fiadd */
    { { 0xda, 0x08 }, F, R }, /* fimul */
    { { 0xda, 0x10 }, F, R }, /* ficom */
    { { 0xda, 0x18 }, F, R }, /* ficomp */
    { { 0xda, 0x20 }, F, R }, /* fisub */
    { { 0xda, 0x28 }, F, R }, /* fisubr */
    { { 0xda, 0x30 }, F, R }, /* fidiv */
    { { 0xda, 0x38 }, F, R }, /* fidivr */
    { { 0xda, 0xc0 }, F, N }, /* fcmovb */
    { { 0xda, 0xc8 }, F, N }, /* fcmove */
    { { 0xda, 0xd0 }, F, N }, /* fcmovbe */
    { { 0xda, 0xd8 }, F, N }, /* fcmovu */
    { { 0xda, 0xe9 }, F, N }, /* fucompp */
    { { 0xdb, 0x00 }, F, R }, /* fild */
    { { 0xdb, 0x08 }, F, W }, /* fisttp */
    { { 0xdb, 0x10 }, F, W }, /* fist */
    { { 0xdb, 0x18 }, F, W }, /* fistp */
    { { 0xdb, 0x28 }, F, R }, /* fld */
    { { 0xdb, 0x38 }, F, W }, /* fstp */
    { { 0xdb, 0xc0 }, F, N }, /* fcmovnb */
    { { 0xdb, 0xc8 }, F, N }, /* fcmovne */
    { { 0xdb, 0xd0 }, F, N }, /* fcmovnbe */
    { { 0xdb, 0xd8 }, F, N }, /* fcmovnu */
    { { 0xdb, 0xe0 }, F, N }, /* fneni */
    { { 0xdb, 0xe1 }, F, N }, /* fndisi */
    { { 0xdb, 0xe2 }, F, N }, /* fnclex */
    { { 0xdb, 0xe3 }, F, N }, /* fninit */
    { { 0xdb, 0xe4 }, F, N }, /* fsetpm */
    { { 0xdb, 0xe5 }, F, N }, /* frstpm */
    { { 0xdb, 0xe8 }, F, N }, /* fucomi */
    { { 0xdb, 0xf0 }, F, N }, /* fcomi */
    { { 0xdc, 0x00 }, T, R }, /* fadd */
    { { 0xdc, 0x08 }, T, R }, /* fmul */
    { { 0xdc, 0x10 }, T, R }, /* fcom */
    { { 0xdc, 0x18 }, T, R }, /* fcomp */
    { { 0xdc, 0x20 }, T, R }, /* fsub */
    { { 0xdc, 0x28 }, T, R }, /* fsubr */
    { { 0xdc, 0x30 }, T, R }, /* fdiv */
    { { 0xdc, 0x38 }, T, R }, /* fdivr */
    { { 0xdd, 0x00 }, F, R }, /* fld */
    { { 0xdd, 0x08 }, F, W }, /* fisttp */
    { { 0xdd, 0x10 }, T, W }, /* fst */
    { { 0xdd, 0x18 }, T, W }, /* fstp */
    { { 0xdd, 0x20 }, F, R }, /* frstor */
    { { 0xdd, 0x30 }, F, W }, /* fnsave */
    { { 0xdd, 0x38 }, F, W }, /* fnstsw */
    { { 0xdd, 0xc0 }, F, N }, /* ffree */
    { { 0xdd, 0xc8 }, F, N }, /* fxch */
    { { 0xdd, 0xe0 }, F, N }, /* fucom */
    { { 0xdd, 0xe8 }, F, N }, /* fucomp */
    { { 0xde, 0x00 }, F, R }, /* fiadd */
    { { 0xde, 0x08 }, F, R }, /* fimul */
    { { 0xde, 0x10 }, F, R }, /* ficom */
    { { 0xde, 0x18 }, F, R }, /* ficomp */
    { { 0xde, 0x20 }, F, R }, /* fisub */
    { { 0xde, 0x28 }, F, R }, /* fisubr */
    { { 0xde, 0x30 }, F, R }, /* fidiv */
    { { 0xde, 0x38 }, F, R }, /* fidivr */
    { { 0xde, 0xc0 }, F, N }, /* faddp */
    { { 0xde, 0xc8 }, F, N }, /* fmulp */
    { { 0xde, 0xd0 }, F, N }, /* fcomp */
    { { 0xde, 0xd9 }, F, N }, /* fcompp */
    { { 0xde, 0xe0 }, F, N }, /* fsubrp */
    { { 0xde, 0xe8 }, F, N }, /* fsubp */
    { { 0xde, 0xf0 }, F, N }, /* fdivrp */
    { { 0xde, 0xf8 }, F, N }, /* fdivp */
    { { 0xdf, 0x00 }, F, R }, /* fild */
    { { 0xdf, 0x08 }, F, W }, /* fisttp */
    { { 0xdf, 0x10 }, F, W }, /* fist */
    { { 0xdf, 0x18 }, F, W }, /* fistp */
    { { 0xdf, 0x20 }, F, R }, /* fbld */
    { { 0xdf, 0x28 }, F, R }, /* fild */
    { { 0xdf, 0x30 }, F, W }, /* fbstp */
    { { 0xdf, 0x38 }, F, W }, /* fistp */
    { { 0xdf, 0xc0 }, F, N }, /* ffreep */
    { { 0xdf, 0xc8 }, F, N }, /* fxch */
    { { 0xdf, 0xd0 }, F, N }, /* fstp */
    { { 0xdf, 0xd8 }, F, N }, /* fstp */
    { { 0xdf, 0xe0 }, F, N }, /* fnstsw */
    { { 0xdf, 0xe8 }, F, N }, /* fucomip */
    { { 0xdf, 0xf0 }, F, N }, /* fcomip */
};
#undef F
#undef N
#undef R
#undef T
#undef W

static unsigned int errors;

static void print_insn(const uint8_t *instr, unsigned int len)
{
    if ( !errors++ )
        puts("");
    while ( len--)
        printf("%02x%c", *instr++, len ? ' ' : ':');
}

void do_test(uint8_t *instr, unsigned int len, unsigned int modrm,
             enum mem_access mem, struct x86_emulate_ctxt *ctxt,
             int (*fetch)(enum x86_segment seg,
                          unsigned long offset,
                          void *p_data,
                          unsigned int bytes,
                          struct x86_emulate_ctxt *ctxt))
{
    struct x86_emulate_state *s;

    if ( !modrm || mem != mem_none )
    {
        s = x86_decode_insn(ctxt, fetch);

        if ( x86_insn_length(s, ctxt) != len )
        {
            print_insn(instr, len);
            printf(" length %u (expected %u)\n", x86_insn_length(s, ctxt), len);
        }

        if ( x86_insn_is_mem_access(s, ctxt) != (mem != mem_none) )
        {
            print_insn(instr, len);
            printf(" mem access %d (expected %d)\n",
                   x86_insn_is_mem_access(s, ctxt), mem != mem_none);
        }

        if ( x86_insn_is_mem_write(s, ctxt) != (mem == mem_write) )
        {
            print_insn(instr, len);
            printf(" mem write %d (expected %d)\n",
                   x86_insn_is_mem_write(s, ctxt), mem == mem_write);
        }

        x86_emulate_free_state(s);
    }

    if ( modrm )
    {
        instr[modrm] |= 0xc0;

        s = x86_decode_insn(ctxt, fetch);

        if ( x86_insn_length(s, ctxt) != len )
        {
            print_insn(instr, len);
            printf(" length %u (expected %u)\n", x86_insn_length(s, ctxt), len);
        }

        if ( x86_insn_is_mem_access(s, ctxt) ||
             x86_insn_is_mem_write(s, ctxt) )
        {
            print_insn(instr, len);
            printf(" mem access %d / write %d unexpected\n",
                   x86_insn_is_mem_access(s, ctxt),
                   x86_insn_is_mem_write(s, ctxt));
        }

        x86_emulate_free_state(s);
    }
}

void predicates_test(void *instr, struct x86_emulate_ctxt *ctxt,
                     int (*fetch)(enum x86_segment seg,
                                  unsigned long offset,
                                  void *p_data,
                                  unsigned int bytes,
                                  struct x86_emulate_ctxt *ctxt))
{
    unsigned int m;

    ctxt->regs->eip = (unsigned long)instr;

    for ( m = 0; m < sizeof(long) / sizeof(int); ++m )
    {
        unsigned int t;

        ctxt->addr_size = 32 << m;
        ctxt->sp_size = 32 << m;
        ctxt->lma = ctxt->sp_size == 64;

        printf("Testing %u-bit decoding / predicates...", ctxt->sp_size);

        for ( t = 0; t < ARRAY_SIZE(legacy); ++t )
        {
            if ( !legacy[t].len[m] )
                continue;

            assert(!legacy[t].pfx);

            memset(instr + 1, 0xcc, 14);
            memcpy(instr, legacy[t].opc, legacy[t].len[m]);

            do_test(instr, legacy[t].len[m], legacy[t].modrm, legacy[t].mem,
                    ctxt, fetch);
        }

        for ( t = 0; t < ARRAY_SIZE(legacy_0f); ++t )
        {
            uint8_t *ptr = instr;

            if ( !legacy_0f[t].len[m] )
                continue;

            memset(instr + 2, 0xcc, 13);
            if ( legacy_0f[t].pfx )
                *ptr++ = prefixes[legacy_0f[t].pfx - 1];
            *ptr++ = 0x0f;
            memcpy(ptr, legacy_0f[t].opc, legacy_0f[t].len[m]);

            do_test(instr, legacy_0f[t].len[m] + ((void *)ptr - instr),
                    legacy_0f[t].modrm ? (void *)ptr - instr + 1 : 0,
                    legacy_0f[t].mem, ctxt, fetch);
        }

        for ( t = 0; t < ARRAY_SIZE(legacy_0f38); ++t )
        {
            uint8_t *ptr = instr;

            if ( !legacy_0f38[t].len[m] )
                continue;

            memset(instr + 3, 0xcc, 12);
            if ( legacy_0f38[t].pfx )
                *ptr++ = prefixes[legacy_0f38[t].pfx - 1];
            *ptr++ = 0x0f;
            *ptr++ = 0x38;
            memcpy(ptr, legacy_0f38[t].opc, legacy_0f38[t].len[m]);

            do_test(instr, legacy_0f38[t].len[m] + ((void *)ptr - instr),
                    legacy_0f38[t].modrm ? (void *)ptr - instr + 1 : 0,
                    legacy_0f38[t].mem, ctxt, fetch);
        }

        for ( t = 0; t < ARRAY_SIZE(legacy_0f3a); ++t )
        {
            uint8_t *ptr = instr;

            memset(instr + 5, 0xcc, 10);
            if ( legacy_0f3a[t].pfx )
                *ptr++ = prefixes[legacy_0f3a[t].pfx - 1];
            *ptr++ = 0x0f;
            *ptr++ = 0x3a;
            *ptr++ = legacy_0f3a[t].opc;
            *ptr++ = 0x00; /* ModR/M */
            *ptr++ = 0x00; /* imm8 */

            do_test(instr, (void *)ptr - instr, (void *)ptr - instr - 2,
                    legacy_0f3a[t].mem, ctxt, fetch);
        }

        memset(instr + ARRAY_SIZE(fpu[t].opc), 0xcc, 13);

        for ( t = 0; t < ARRAY_SIZE(fpu); ++t )
        {
            memcpy(instr, fpu[t].opc, ARRAY_SIZE(fpu[t].opc));

            do_test(instr, ARRAY_SIZE(fpu[t].opc), fpu[t].modrm, fpu[t].mem,
                    ctxt, fetch);
        }

        if ( errors )
            exit(1);

        puts(" okay");
    }
}
