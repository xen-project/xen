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
    { { 0x01, 0xc6 }, { 2, 2 }, F, N }, /* wrmsrns */
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

#define VSIB(n) 0x04 | ((n) << 3), 0x38 /* reg: %xmm<n>, mem: (%eax,%xmm7) */

static const struct vex {
    uint8_t opc[3];
    uint8_t len:3;
    bool modrm:1; /* Should register form (also) be tested? */
    uint8_t mem:2;
    uint8_t pfx:2;
    uint8_t w:2;
#define WIG 0
#define W0 1
#define W1 2
#define Wn (W0 | W1)
    uint8_t l:2;
#define LIG 0
#define L0 1
#define L1 2
#define Ln (L0 | L1)
} vex_0f[] = {
    { { 0x10 }, 2, T, R, pfx_no, WIG, Ln }, /* vmovups */
    { { 0x10 }, 2, T, R, pfx_66, WIG, Ln }, /* vmovupd */
    { { 0x10 }, 2, T, R, pfx_f3, WIG, LIG }, /* vmovss */
    { { 0x10 }, 2, T, R, pfx_f2, WIG, LIG }, /* vmovsd */
    { { 0x11 }, 2, T, W, pfx_no, WIG, Ln }, /* vmovups */
    { { 0x11 }, 2, T, W, pfx_66, WIG, Ln }, /* vmovupd */
    { { 0x11 }, 2, T, W, pfx_f3, WIG, LIG }, /* vmovss */
    { { 0x11 }, 2, T, W, pfx_f2, WIG, LIG }, /* vmovsd */
    { { 0x12 }, 2, T, R, pfx_no, WIG, L0 }, /* vmovlps / vmovhlps */
    { { 0x12 }, 2, F, R, pfx_66, WIG, L0 }, /* vmovlpd */
    { { 0x12 }, 2, T, R, pfx_f3, WIG, Ln }, /* vmovsldup */
    { { 0x12 }, 2, T, R, pfx_f2, WIG, Ln }, /* vmovddup */
    { { 0x13 }, 2, F, W, pfx_no, WIG, L0 }, /* vmovlps */
    { { 0x13 }, 2, F, W, pfx_66, WIG, L0 }, /* vmovlpd */
    { { 0x14 }, 2, T, R, pfx_no, WIG, Ln }, /* vunpcklps */
    { { 0x14 }, 2, T, R, pfx_66, WIG, Ln }, /* vunpcklpd */
    { { 0x15 }, 2, T, R, pfx_no, WIG, Ln }, /* vunpckhps */
    { { 0x15 }, 2, T, R, pfx_66, WIG, Ln }, /* vunpckhpd */
    { { 0x16 }, 2, T, R, pfx_no, WIG, L0 }, /* vmovhps / vmovlhps */
    { { 0x16 }, 2, F, R, pfx_66, WIG, L0 }, /* vmovhpd */
    { { 0x16 }, 2, T, R, pfx_f3, WIG, Ln }, /* vmovshdup */
    { { 0x17 }, 2, F, W, pfx_no, WIG, L0 }, /* vmovhps */
    { { 0x17 }, 2, F, W, pfx_66, WIG, L0 }, /* vmovhpd */
    { { 0x28 }, 2, T, R, pfx_no, WIG, Ln }, /* vmovaps */
    { { 0x28 }, 2, T, R, pfx_66, WIG, Ln }, /* vmovapd */
    { { 0x29 }, 2, T, W, pfx_no, WIG, Ln }, /* vmovaps */
    { { 0x29 }, 2, T, W, pfx_66, WIG, Ln }, /* vmovapd */
    { { 0x2a }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtsi2ss */
    { { 0x2a }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvtsi2sd */
    { { 0x2b }, 2, T, W, pfx_no, WIG, Ln }, /* vmovntps */
    { { 0x2b }, 2, T, W, pfx_66, WIG, Ln }, /* vmovntpd */
    { { 0x2c }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvttss2si */
    { { 0x2c }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvttsd2si */
    { { 0x2d }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtss2si */
    { { 0x2d }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvtsd2si */
    { { 0x2e }, 2, T, R, pfx_no, WIG, LIG }, /* vucomiss */
    { { 0x2e }, 2, T, R, pfx_66, WIG, LIG }, /* vucomisd */
    { { 0x2f }, 2, T, R, pfx_no, WIG, LIG }, /* vcomiss */
    { { 0x2f }, 2, T, R, pfx_66, WIG, LIG }, /* vcomisd */
    { { 0x41, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kand{w,q} */
    { { 0x41, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kand{b,d} */
    { { 0x42, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kandn{w,q} */
    { { 0x42, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kandn{b,d} */
    { { 0x44, 0xc0 }, 2, F, N, pfx_no, Wn, L0 }, /* knot{w,q} */
    { { 0x44, 0xc0 }, 2, F, N, pfx_66, Wn, L0 }, /* knot{b,d} */
    { { 0x45, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kor{w,q} */
    { { 0x45, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kor{b,d} */
    { { 0x46, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kxnor{w,q} */
    { { 0x46, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kxnor{b,d} */
    { { 0x47, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kxor{w,q} */
    { { 0x47, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kxor{b,d} */
    { { 0x4a, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kadd{w,q} */
    { { 0x4a, 0xc0 }, 2, F, N, pfx_66, Wn, L1 }, /* kadd{b,d} */
    { { 0x4b, 0xc0 }, 2, F, N, pfx_no, Wn, L1 }, /* kunpck{wd,dq} */
    { { 0x4b, 0xc0 }, 2, F, N, pfx_66, W0, L1 }, /* kunpckbw */
    { { 0x50, 0xc0 }, 2, F, N, pfx_no, WIG, Ln }, /* vmovmskps */
    { { 0x50, 0xc0 }, 2, F, N, pfx_66, WIG, Ln }, /* vmovmskpd */
    { { 0x51 }, 2, T, R, pfx_no, WIG, Ln }, /* vsqrtps */
    { { 0x51 }, 2, T, R, pfx_66, WIG, Ln }, /* vsqrtpd */
    { { 0x51 }, 2, T, R, pfx_f3, WIG, LIG }, /* vsqrtss */
    { { 0x51 }, 2, T, R, pfx_f2, WIG, LIG }, /* vsqrtsd */
    { { 0x52 }, 2, T, R, pfx_no, WIG, Ln }, /* vrsqrtps */
    { { 0x52 }, 2, T, R, pfx_f3, WIG, LIG }, /* vrsqrtss */
    { { 0x53 }, 2, T, R, pfx_no, WIG, Ln }, /* vrcpps */
    { { 0x53 }, 2, T, R, pfx_f3, WIG, LIG }, /* vrcpss */
    { { 0x54 }, 2, T, R, pfx_no, WIG, Ln }, /* vandps */
    { { 0x54 }, 2, T, R, pfx_66, WIG, Ln }, /* vandpd */
    { { 0x55 }, 2, T, R, pfx_no, WIG, Ln }, /* vandnps */
    { { 0x55 }, 2, T, R, pfx_66, WIG, Ln }, /* vandnpd */
    { { 0x56 }, 2, T, R, pfx_no, WIG, Ln }, /* vorps */
    { { 0x56 }, 2, T, R, pfx_66, WIG, Ln }, /* vorpd */
    { { 0x57 }, 2, T, R, pfx_no, WIG, Ln }, /* vxorps */
    { { 0x57 }, 2, T, R, pfx_66, WIG, Ln }, /* vxorpd */
    { { 0x58 }, 2, T, R, pfx_no, WIG, Ln }, /* vaddps */
    { { 0x58 }, 2, T, R, pfx_66, WIG, Ln }, /* vaddpd */
    { { 0x58 }, 2, T, R, pfx_f3, WIG, LIG }, /* vaddss */
    { { 0x58 }, 2, T, R, pfx_f2, WIG, LIG }, /* vaddsd */
    { { 0x59 }, 2, T, R, pfx_no, WIG, Ln }, /* vmulps */
    { { 0x59 }, 2, T, R, pfx_66, WIG, Ln }, /* vmulpd */
    { { 0x59 }, 2, T, R, pfx_f3, WIG, LIG }, /* vmulss */
    { { 0x59 }, 2, T, R, pfx_f2, WIG, LIG }, /* vmulsd */
    { { 0x5a }, 2, T, R, pfx_no, WIG, Ln }, /* vcvtps2pd */
    { { 0x5a }, 2, T, R, pfx_66, WIG, Ln }, /* vcvtpd2ps */
    { { 0x5a }, 2, T, R, pfx_f3, WIG, LIG }, /* vcvtss2sd */
    { { 0x5a }, 2, T, R, pfx_f2, WIG, LIG }, /* vcvtsd2ss */
    { { 0x5b }, 2, T, R, pfx_no, WIG, Ln }, /* vcvtdq2ps */
    { { 0x5b }, 2, T, R, pfx_66, WIG, Ln }, /* vcvtps2dq */
    { { 0x5b }, 2, T, R, pfx_f3, WIG, Ln }, /* vcvttps2dq */
    { { 0x5c }, 2, T, R, pfx_no, WIG, Ln }, /* vsubps */
    { { 0x5c }, 2, T, R, pfx_66, WIG, Ln }, /* vsubpd */
    { { 0x5c }, 2, T, R, pfx_f3, WIG, LIG }, /* vsubss */
    { { 0x5c }, 2, T, R, pfx_f2, WIG, LIG }, /* vsubsd */
    { { 0x5d }, 2, T, R, pfx_no, WIG, Ln }, /* vminps */
    { { 0x5d }, 2, T, R, pfx_66, WIG, Ln }, /* vminpd */
    { { 0x5d }, 2, T, R, pfx_f3, WIG, LIG }, /* vminss */
    { { 0x5d }, 2, T, R, pfx_f2, WIG, LIG }, /* vminsd */
    { { 0x5e }, 2, T, R, pfx_no, WIG, Ln }, /* vdivps */
    { { 0x5e }, 2, T, R, pfx_66, WIG, Ln }, /* vdivpd */
    { { 0x5e }, 2, T, R, pfx_f3, WIG, LIG }, /* vdivss */
    { { 0x5e }, 2, T, R, pfx_f2, WIG, LIG }, /* vdivsd */
    { { 0x5f }, 2, T, R, pfx_no, WIG, Ln }, /* vmaxps */
    { { 0x5f }, 2, T, R, pfx_66, WIG, Ln }, /* vmaxpd */
    { { 0x5f }, 2, T, R, pfx_f3, WIG, LIG }, /* vmaxss */
    { { 0x5f }, 2, T, R, pfx_f2, WIG, LIG }, /* vmaxsd */
    { { 0x60 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpcklbw */
    { { 0x61 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpcklwd */
    { { 0x62 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckldq */
    { { 0x63 }, 2, T, R, pfx_66, WIG, Ln }, /* vpacksswb */
    { { 0x64 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtb */
    { { 0x65 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtw */
    { { 0x66 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtd */
    { { 0x67 }, 2, T, R, pfx_66, WIG, Ln }, /* vpackuswb */
    { { 0x68 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhbw */
    { { 0x69 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhwd */
    { { 0x6a }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhdq */
    { { 0x6b }, 2, T, R, pfx_66, WIG, Ln }, /* vpackssdw */
    { { 0x6c }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpcklqdq */
    { { 0x6d }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhqdq */
    { { 0x6e }, 2, T, R, pfx_66, Wn, L0 }, /* vmov{d,q} */
    { { 0x6f }, 2, T, R, pfx_66, WIG, Ln }, /* vmovdqa */
    { { 0x6f }, 2, T, R, pfx_f3, WIG, Ln }, /* vmovdqu */
    { { 0x70 }, 3, T, R, pfx_66, WIG, Ln }, /* vpshufd */
    { { 0x70 }, 3, T, R, pfx_f3, WIG, Ln }, /* vpshuflw */
    { { 0x70 }, 3, T, R, pfx_f2, WIG, Ln }, /* vpshufhw */
    { { 0x71, 0xd0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrlw */
    { { 0x71, 0xe0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsraw */
    { { 0x71, 0xf0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsllw */
    { { 0x72, 0xd0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrld */
    { { 0x72, 0xe0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrad */
    { { 0x72, 0xf0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpslld */
    { { 0x73, 0xd0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrlq */
    { { 0x73, 0xd8 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrldq */
    { { 0x73, 0xf0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsllq */
    { { 0x73, 0xf8 }, 3, F, N, pfx_66, WIG, Ln }, /* vpslldq */
    { { 0x74 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqb */
    { { 0x75 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqw */
    { { 0x76 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqd */
    { { 0x77 }, 1, F, N, pfx_no, WIG, Ln }, /* vzero{upper,all} */
    { { 0x7c }, 2, T, R, pfx_66, WIG, Ln }, /* vhaddpd */
    { { 0x7c }, 2, T, R, pfx_f2, WIG, Ln }, /* vhaddps */
    { { 0x7d }, 2, T, R, pfx_66, WIG, Ln }, /* vhsubpd */
    { { 0x7d }, 2, T, R, pfx_f2, WIG, Ln }, /* vhsubps */
    { { 0x7e }, 2, T, W, pfx_66, Wn, L0 }, /* vmov{d,q} */
    { { 0x7e }, 2, T, R, pfx_f3, WIG, L0 }, /* vmovq */
    { { 0x7f }, 2, T, W, pfx_66, WIG, Ln }, /* vmovdqa */
    { { 0x7f }, 2, T, W, pfx_f3, WIG, Ln }, /* vmovdqu */
    { { 0x90 }, 2, T, R, pfx_no, Wn, L0 }, /* kmov{w,q} */
    { { 0x90 }, 2, T, R, pfx_66, Wn, L0 }, /* kmov{b,d} */
    { { 0x91 }, 2, N, W, pfx_no, Wn, L0 }, /* kmov{w,q} */
    { { 0x91 }, 2, N, W, pfx_66, Wn, L0 }, /* kmov{b,d} */
    { { 0x92, 0xc0 }, 2, F, N, pfx_no, W0, L0 }, /* kmovw */
    { { 0x92, 0xc0 }, 2, F, N, pfx_66, W0, L0 }, /* kmovb */
    { { 0x92, 0xc0 }, 2, F, N, pfx_f2, Wn, L0 }, /* kmov{d,q} */
    { { 0x93, 0xc0 }, 2, F, N, pfx_no, W0, L0 }, /* kmovw */
    { { 0x93, 0xc0 }, 2, F, N, pfx_66, W0, L0 }, /* kmovb */
    { { 0x93, 0xc0 }, 2, F, N, pfx_f2, Wn, L0 }, /* kmov{d,q} */
    { { 0x98, 0xc0 }, 2, F, N, pfx_no, Wn, L0 }, /* kortest{w,q} */
    { { 0x98, 0xc0 }, 2, F, N, pfx_66, Wn, L0 }, /* kortest{b,d} */
    { { 0x99, 0xc0 }, 2, F, N, pfx_no, Wn, L0 }, /* ktest{w,q} */
    { { 0x99, 0xc0 }, 2, F, N, pfx_66, Wn, L0 }, /* ktest{b,d} */
    { { 0xae, 0x10 }, 2, F, R, pfx_no, WIG, L0 }, /* vldmxcsr */
    { { 0xae, 0x18 }, 2, F, W, pfx_no, WIG, L0 }, /* vstmxcsr */
    { { 0xc2 }, 3, T, R, pfx_no, WIG, Ln }, /* vcmpps */
    { { 0xc2 }, 3, T, R, pfx_66, WIG, Ln }, /* vcmppd */
    { { 0xc2 }, 3, T, R, pfx_f3, WIG, LIG }, /* vcmpss */
    { { 0xc2 }, 3, T, R, pfx_f2, WIG, LIG }, /* vcmpsd */
    { { 0xc4 }, 3, T, R, pfx_66, WIG, L0 }, /* vpinsrw */
    { { 0xc5, 0xc0 }, 3, F, N, pfx_66, WIG, L0 }, /* vpextrw */
    { { 0xc6 }, 3, T, R, pfx_no, WIG, Ln }, /* vshufps */
    { { 0xc6 }, 3, T, R, pfx_66, WIG, Ln }, /* vshufpd */
    { { 0xd0 }, 2, T, R, pfx_66, WIG, Ln }, /* vaddsubpd */
    { { 0xd0 }, 2, T, R, pfx_f2, WIG, Ln }, /* vaddsubps */
    { { 0xd1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsrlw */
    { { 0xd2 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsrld */
    { { 0xd3 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsrlq */
    { { 0xd4 }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddq */
    { { 0xd5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmullw */
    { { 0xd6 }, 2, T, W, pfx_66, WIG, L0 }, /* vmovq */
    { { 0xd7, 0xc0 }, 2, F, N, pfx_66, WIG, Ln }, /* vpmovmskb */
    { { 0xd8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubusb */
    { { 0xd9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubusw */
    { { 0xda }, 2, T, R, pfx_66, WIG, Ln }, /* vpminub */
    { { 0xdb }, 2, T, R, pfx_66, WIG, Ln }, /* vpand */
    { { 0xdc }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddusb */
    { { 0xdd }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddusw */
    { { 0xde }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxub */
    { { 0xdf }, 2, T, R, pfx_66, WIG, Ln }, /* vpandn */
    { { 0xe0 }, 2, T, R, pfx_66, WIG, Ln }, /* vpavgb */
    { { 0xe1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsraw */
    { { 0xe2 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsrad */
    { { 0xe3 }, 2, T, R, pfx_66, WIG, Ln }, /* vpavgw */
    { { 0xe4 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhuw */
    { { 0xe5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhw */
    { { 0xe6 }, 2, T, R, pfx_66, WIG, Ln }, /* vcvttpd2dq */
    { { 0xe6 }, 2, T, R, pfx_f3, WIG, Ln }, /* vcvtdq2pd */
    { { 0xe6 }, 2, T, R, pfx_f2, WIG, Ln }, /* vcvtpd2dq */
    { { 0xe7 }, 2, F, W, pfx_66, WIG, Ln }, /* vmovntdq */
    { { 0xe8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubsb */
    { { 0xe9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubsw */
    { { 0xea }, 2, T, R, pfx_66, WIG, Ln }, /* vpminsw */
    { { 0xeb }, 2, T, R, pfx_66, WIG, Ln }, /* vpor */
    { { 0xec }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddsb */
    { { 0xed }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddsw */
    { { 0xee }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxsw */
    { { 0xef }, 2, T, R, pfx_66, WIG, Ln }, /* vpxor */
    { { 0xf0 }, 2, T, R, pfx_f2, WIG, Ln }, /* vlddqu */
    { { 0xf1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsllw */
    { { 0xf2 }, 2, T, R, pfx_66, WIG, Ln }, /* vpslld */
    { { 0xf3 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsllq */
    { { 0xf4 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmuludq */
    { { 0xf5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaddwd */
    { { 0xf6 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsadbw */
    { { 0xf7, 0xc0 }, 2, F, W, pfx_66, WIG, L0 }, /* vmaskmovdqu */
    { { 0xf8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubb */
    { { 0xf9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubw */
    { { 0xfa }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubd */
    { { 0xfb }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubq */
    { { 0xfc }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddb */
    { { 0xfd }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddw */
    { { 0xfe }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddd */
}, vex_0f38[] = {
    { { 0x00 }, 2, T, R, pfx_66, WIG, Ln }, /* vpshufb */
    { { 0x01 }, 2, T, R, pfx_66, WIG, Ln }, /* vphaddw */
    { { 0x02 }, 2, T, R, pfx_66, WIG, Ln }, /* vphaddd */
    { { 0x03 }, 2, T, R, pfx_66, WIG, Ln }, /* vphaddsw */
    { { 0x04 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaddubsw */
    { { 0x05 }, 2, T, R, pfx_66, WIG, Ln }, /* vphsubw */
    { { 0x06 }, 2, T, R, pfx_66, WIG, Ln }, /* vphsubd */
    { { 0x07 }, 2, T, R, pfx_66, WIG, Ln }, /* vphsubsw */
    { { 0x08 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsignb */
    { { 0x09 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsignw */
    { { 0x0a }, 2, T, R, pfx_66, WIG, Ln }, /* vpsignd */
    { { 0x0b }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhrsw */
    { { 0x0c }, 2, T, R, pfx_66, W0, Ln }, /* vpermilps */
    { { 0x0d }, 2, T, R, pfx_66, W0, Ln }, /* vpermilpd */
    { { 0x0e }, 2, T, R, pfx_66, W0, Ln }, /* vtestps */
    { { 0x0f }, 2, T, R, pfx_66, W0, Ln }, /* vtestpd */
    { { 0x13 }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2ps */
    { { 0x16 }, 2, T, R, pfx_66, W0, L1 }, /* vpermps */
    { { 0x17 }, 2, T, R, pfx_66, WIG, Ln }, /* vptest */
    { { 0x18 }, 2, T, R, pfx_66, W0, Ln }, /* vbroadcastss */
    { { 0x19 }, 2, T, R, pfx_66, W0, L1 }, /* vbroadcastsd */
    { { 0x1a }, 2, F, R, pfx_66, W0, L1 }, /* vbroadcastf128 */
    { { 0x1c }, 2, T, R, pfx_66, WIG, Ln }, /* vpabsb */
    { { 0x1d }, 2, T, R, pfx_66, WIG, Ln }, /* vpabsw */
    { { 0x1e }, 2, T, R, pfx_66, WIG, Ln }, /* vpabsd */
    { { 0x20 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbw */
    { { 0x21 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbd */
    { { 0x22 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbq */
    { { 0x23 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxwd */
    { { 0x24 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxwq */
    { { 0x25 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxdq */
    { { 0x28 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmuldq */
    { { 0x29 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqq */
    { { 0x2a }, 2, F, R, pfx_66, WIG, Ln }, /* vmovntdqa */
    { { 0x2b }, 2, T, R, pfx_66, WIG, Ln }, /* vpackusdw */
    { { 0x2c }, 2, F, R, pfx_66, W0, Ln }, /* vmaskmovps */
    { { 0x2d }, 2, F, R, pfx_66, W0, Ln }, /* vmaskmovpd */
    { { 0x2e }, 2, F, W, pfx_66, W0, Ln }, /* vmaskmovps */
    { { 0x2f }, 2, F, W, pfx_66, W0, Ln }, /* vmaskmovpd */
    { { 0x30 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbw */
    { { 0x31 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbd */
    { { 0x32 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbq */
    { { 0x33 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxwd */
    { { 0x34 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxwq */
    { { 0x35 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxdq */
    { { 0x36 }, 2, T, R, pfx_66, W0, L1 }, /* vpermd */
    { { 0x37 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtq */
    { { 0x38 }, 2, T, R, pfx_66, WIG, Ln }, /* vpminsb */
    { { 0x39 }, 2, T, R, pfx_66, WIG, Ln }, /* vpminsd */
    { { 0x3a }, 2, T, R, pfx_66, WIG, Ln }, /* vpminuw */
    { { 0x3b }, 2, T, R, pfx_66, WIG, Ln }, /* vpminud */
    { { 0x3c }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxsb */
    { { 0x3d }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxsd */
    { { 0x3e }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxuw */
    { { 0x3f }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxud */
    { { 0x40 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulld */
    { { 0x41 }, 2, T, R, pfx_66, WIG, L0 }, /* vphminposuw */
    { { 0x45 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsrlv{d,q} */
    { { 0x46 }, 2, T, R, pfx_66, W0, Ln }, /* vpsravd */
    { { 0x47 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsllv{d,q} */
    { { 0x50 }, 2, T, R, pfx_no, W0, Ln }, /* vpdpbuud */
    { { 0x50 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpbusd */
    { { 0x50 }, 2, T, R, pfx_f3, W0, Ln }, /* vpdpbsud */
    { { 0x50 }, 2, T, R, pfx_f2, W0, Ln }, /* vpdpbssd */
    { { 0x51 }, 2, T, R, pfx_no, W0, Ln }, /* vpdpbuuds */
    { { 0x51 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpbusds */
    { { 0x51 }, 2, T, R, pfx_f3, W0, Ln }, /* vpdpbsuds */
    { { 0x51 }, 2, T, R, pfx_f2, W0, Ln }, /* vpdpbssds */
    { { 0x52 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwssd */
    { { 0x53 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwssds */
    { { 0x58 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastd */
    { { 0x59 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastq */
    { { 0x5a }, 2, F, R, pfx_66, W0, L1 }, /* vbroadcasti128 */
    { { 0x72 }, 2, T, R, pfx_f3, W0, Ln }, /* vcvtneps2bf16 */
    { { 0x78 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastb */
    { { 0x79 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastw */
    { { 0x8c }, 2, F, R, pfx_66, Wn, Ln }, /* vpmaskmov{d,q} */
    { { 0x8e }, 2, F, W, pfx_66, Wn, Ln }, /* vpmaskmov{d,q} */
    { { 0x90, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln }, /* vpgatherd{d,q} */
    { { 0x91, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln }, /* vpgatherq{d,q} */
    { { 0x92, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln }, /* vgatherdp{s,d} */
    { { 0x93, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln }, /* vgatherqp{s,d} */
    { { 0x96 }, 2, T, R, pfx_66, Wn, Ln }, /* vmaddsub132p{s,d} */
    { { 0x97 }, 2, T, R, pfx_66, Wn, Ln }, /* vmsubadd132p{s,d} */
    { { 0x98 }, 2, T, R, pfx_66, Wn, Ln }, /* vmadd132p{s,d} */
    { { 0x99 }, 2, T, R, pfx_66, Wn, LIG }, /* vmadd132s{s,d} */
    { { 0x9a }, 2, T, R, pfx_66, Wn, Ln }, /* vmsub132p{s,d} */
    { { 0x9b }, 2, T, R, pfx_66, Wn, LIG }, /* vmsub132s{s,d} */
    { { 0x9c }, 2, T, R, pfx_66, Wn, Ln }, /* vnmadd132p{s,d} */
    { { 0x9d }, 2, T, R, pfx_66, Wn, LIG }, /* vnmadd132s{s,d} */
    { { 0x9e }, 2, T, R, pfx_66, Wn, Ln }, /* vnmsub132p{s,d} */
    { { 0x9f }, 2, T, R, pfx_66, Wn, LIG }, /* vnmsub132s{s,d} */
    { { 0xa6 }, 2, T, R, pfx_66, Wn, Ln }, /* vmaddsub213p{s,d} */
    { { 0xa7 }, 2, T, R, pfx_66, Wn, Ln }, /* vmsubadd213p{s,d} */
    { { 0xa8 }, 2, T, R, pfx_66, Wn, Ln }, /* vmadd213p{s,d} */
    { { 0xa9 }, 2, T, R, pfx_66, Wn, LIG }, /* vmadd213s{s,d} */
    { { 0xaa }, 2, T, R, pfx_66, Wn, Ln }, /* vmsub213p{s,d} */
    { { 0xab }, 2, T, R, pfx_66, Wn, LIG }, /* vmsub213s{s,d} */
    { { 0xac }, 2, T, R, pfx_66, Wn, Ln }, /* vnmadd213p{s,d} */
    { { 0xad }, 2, T, R, pfx_66, Wn, LIG }, /* vnmadd213s{s,d} */
    { { 0xae }, 2, T, R, pfx_66, Wn, Ln }, /* vnmsub213p{s,d} */
    { { 0xaf }, 2, T, R, pfx_66, Wn, LIG }, /* vnmsub213s{s,d} */
    { { 0xb0 }, 2, F, R, pfx_no, W0, Ln }, /* vcvtneoph2ps */
    { { 0xb0 }, 2, F, R, pfx_66, W0, Ln }, /* vcvtneeph2ps */
    { { 0xb0 }, 2, F, R, pfx_f3, W0, Ln }, /* vcvtneebf162ps */
    { { 0xb0 }, 2, F, R, pfx_f2, W0, Ln }, /* vcvtneobf162ps */
    { { 0xb1 }, 2, F, R, pfx_66, W0, Ln }, /* vbcstnesh2ps */
    { { 0xb1 }, 2, F, R, pfx_f3, W0, Ln }, /* vbcstnebf162ps */
    { { 0xb4 }, 2, T, R, pfx_66, W1, Ln }, /* vpmadd52luq */
    { { 0xb5 }, 2, T, R, pfx_66, W1, Ln }, /* vpmadd52huq */
    { { 0xb6 }, 2, T, R, pfx_66, Wn, Ln }, /* vmaddsub231p{s,d} */
    { { 0xb7 }, 2, T, R, pfx_66, Wn, Ln }, /* vmsubadd231p{s,d} */
    { { 0xb8 }, 2, T, R, pfx_66, Wn, Ln }, /* vmadd231p{s,d} */
    { { 0xb9 }, 2, T, R, pfx_66, Wn, LIG }, /* vmadd231s{s,d} */
    { { 0xba }, 2, T, R, pfx_66, Wn, Ln }, /* vmsub231p{s,d} */
    { { 0xbb }, 2, T, R, pfx_66, Wn, LIG }, /* vmsub231s{s,d} */
    { { 0xbc }, 2, T, R, pfx_66, Wn, Ln }, /* vnmadd231p{s,d} */
    { { 0xbd }, 2, T, R, pfx_66, Wn, LIG }, /* vnmadd231s{s,d} */
    { { 0xbe }, 2, T, R, pfx_66, Wn, Ln }, /* vnmsub231p{s,d} */
    { { 0xbf }, 2, T, R, pfx_66, Wn, LIG }, /* vnmsub231s{s,d} */
    { { 0xcb, 0xc0 }, 2, F, N, pfx_f2, W0, L1 }, /* vsha512rnds2 */
    { { 0xcc, 0xc0 }, 2, F, N, pfx_f2, W0, L1 }, /* vsha512msg1 */
    { { 0xcd, 0xc0 }, 2, F, N, pfx_f2, W0, L1 }, /* vsha512msg2 */
    { { 0xcf }, 2, T, R, pfx_66, W0, Ln }, /* vgf2p8mulb */
    { { 0xd2 }, 2, T, R, pfx_no, W0, Ln }, /* vpdpwuud */
    { { 0xd2 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwusd */
    { { 0xd2 }, 2, T, R, pfx_f3, W0, Ln }, /* vpdpwsud */
    { { 0xd3 }, 2, T, R, pfx_no, W0, Ln }, /* vpdpwuuds */
    { { 0xd3 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwusds */
    { { 0xd3 }, 2, T, R, pfx_f3, W0, Ln }, /* vpdpwsuds */
    { { 0xda }, 2, T, R, pfx_no, W0, L0 }, /* vsm3msg1 */
    { { 0xda }, 2, T, R, pfx_66, W0, L0 }, /* vsm3msg2 */
    { { 0xda }, 2, T, R, pfx_f3, W0, Ln }, /* vsm4key4 */
    { { 0xda }, 2, T, R, pfx_f2, W0, Ln }, /* vsm4rnds4 */
    { { 0xdb }, 2, T, R, pfx_66, WIG, L0 }, /* vaesimc */
    { { 0xdc }, 2, T, R, pfx_66, WIG, Ln }, /* vaesenc */
    { { 0xdd }, 2, T, R, pfx_66, WIG, Ln }, /* vaesenclast */
    { { 0xde }, 2, T, R, pfx_66, WIG, Ln }, /* vaesdec */
    { { 0xdf }, 2, T, R, pfx_66, WIG, Ln }, /* vaesdeclast */
    { { 0xe0 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpoxadd */
    { { 0xe1 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpnoxadd */
    { { 0xe2 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpbxadd */
    { { 0xe3 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpnbxadd */
    { { 0xe4 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpexadd */
    { { 0xe5 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpnexadd */
    { { 0xe6 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpbexadd */
    { { 0xe7 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpaxadd */
    { { 0xe8 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpsxadd */
    { { 0xe9 }, 2, F, W, pfx_66, Wn, L0 }, /* cmpnsxadd */
    { { 0xea }, 2, F, W, pfx_66, Wn, L0 }, /* cmppxadd */
    { { 0xeb }, 2, F, W, pfx_66, Wn, L0 }, /* cmpnpxadd */
    { { 0xec }, 2, F, W, pfx_66, Wn, L0 }, /* cmplxadd */
    { { 0xed }, 2, F, W, pfx_66, Wn, L0 }, /* cmpgexadd */
    { { 0xee }, 2, F, W, pfx_66, Wn, L0 }, /* cmplexadd */
    { { 0xef }, 2, F, W, pfx_66, Wn, L0 }, /* cmpgxadd */
    { { 0xf2 }, 2, T, R, pfx_no, Wn, L0 }, /* andn */
    { { 0xf3, 0x08 }, 2, T, R, pfx_no, Wn, L0 }, /* blsr */
    { { 0xf3, 0x10 }, 2, T, R, pfx_no, Wn, L0 }, /* blsmsk */
    { { 0xf3, 0x18 }, 2, T, R, pfx_no, Wn, L0 }, /* blsi */
    { { 0xf5 }, 2, T, R, pfx_no, Wn, L0 }, /* bzhi */
    { { 0xf5 }, 2, T, R, pfx_f3, Wn, L0 }, /* pext */
    { { 0xf5 }, 2, T, R, pfx_f2, Wn, L0 }, /* pdep */
    { { 0xf6 }, 2, T, R, pfx_f2, Wn, L0 }, /* mulx */
    { { 0xf7 }, 2, T, R, pfx_no, Wn, L0 }, /* bextr */
    { { 0xf7 }, 2, T, R, pfx_66, Wn, L0 }, /* shlx */
    { { 0xf7 }, 2, T, R, pfx_f3, Wn, L0 }, /* sarx */
    { { 0xf7 }, 2, T, R, pfx_f2, Wn, L0 }, /* shrx */
}, vex_0f3a[] = {
    { { 0x00 }, 3, T, R, pfx_66, W1, L1 }, /* vpermq */
    { { 0x01 }, 3, T, R, pfx_66, W1, L1 }, /* vpermpd */
    { { 0x02 }, 3, T, R, pfx_66, W0, Ln }, /* vpblendd */
    { { 0x04 }, 3, T, R, pfx_66, W0, Ln }, /* vpermilps */
    { { 0x05 }, 3, T, R, pfx_66, W0, Ln }, /* vpermilpd */
    { { 0x06 }, 3, T, R, pfx_66, W0, L1 }, /* vperm2f128 */
    { { 0x08 }, 3, T, R, pfx_66, WIG, Ln }, /* vroundps */
    { { 0x09 }, 3, T, R, pfx_66, WIG, Ln }, /* vroundpd */
    { { 0x0a }, 3, T, R, pfx_66, WIG, LIG }, /* vroundss */
    { { 0x0b }, 3, T, R, pfx_66, WIG, LIG }, /* vroundsd */
    { { 0x0c }, 3, T, R, pfx_66, WIG, Ln }, /* vblendps */
    { { 0x0d }, 3, T, R, pfx_66, WIG, Ln }, /* vblendpd */
    { { 0x0e }, 3, T, R, pfx_66, WIG, Ln }, /* vpblendw */
    { { 0x0f }, 3, T, R, pfx_66, WIG, Ln }, /* vpalignr */
    { { 0x14 }, 3, T, W, pfx_66, WIG, L0 }, /* vpextrb */
    { { 0x15 }, 3, T, W, pfx_66, WIG, L0 }, /* vpextrw */
    { { 0x16 }, 3, T, W, pfx_66, Wn, L0 }, /* vpextr{d,q} */
    { { 0x17 }, 3, T, W, pfx_66, WIG, L0 }, /* vextractps */
    { { 0x18 }, 3, T, R, pfx_66, W0, L1 }, /* vinsertf128 */
    { { 0x19 }, 3, T, W, pfx_66, W0, L1 }, /* vextractf128 */
    { { 0x1d }, 3, T, W, pfx_66, W0, Ln }, /* vcvtps2ph */
    { { 0x20 }, 3, T, R, pfx_66, WIG, L0 }, /* vpinsrb */
    { { 0x21 }, 3, T, R, pfx_66, WIG, L0 }, /* vinsertps */
    { { 0x22 }, 3, T, R, pfx_66, Wn, L0 }, /* vpinsr{d,q} */
    { { 0x30, 0xc0 }, 3, F, N, pfx_66, Wn, L0 }, /* kshiftr{b,w} */
    { { 0x31, 0xc0 }, 3, F, N, pfx_66, Wn, L0 }, /* kshiftr{d,q} */
    { { 0x32, 0xc0 }, 3, F, N, pfx_66, Wn, L0 }, /* kshiftl{b,w} */
    { { 0x33, 0xc0 }, 3, F, N, pfx_66, Wn, L0 }, /* kshiftl{d,q} */
    { { 0x38 }, 3, T, R, pfx_66, W0, L1 }, /* vinserti128 */
    { { 0x39 }, 3, T, W, pfx_66, W0, L1 }, /* vextracti128 */
    { { 0x40 }, 3, T, R, pfx_66, WIG, Ln }, /* vdpps */
    { { 0x41 }, 3, T, R, pfx_66, WIG, Ln }, /* vdppd */
    { { 0x42 }, 3, T, R, pfx_66, WIG, Ln }, /* vmpsadbw */
    { { 0x44 }, 3, T, R, pfx_66, WIG, Ln }, /* vpclmulqdq */
    { { 0x46 }, 3, T, R, pfx_66, W0, L1 }, /* vperm2i128 */
    { { 0x48 }, 3, T, R, pfx_66, Wn, Ln }, /* vpermil2ps */
    { { 0x49 }, 3, T, R, pfx_66, Wn, Ln }, /* vpermil2pd */
    { { 0x4a }, 3, T, R, pfx_66, W0, Ln }, /* vblendvps */
    { { 0x4b }, 3, T, R, pfx_66, W0, Ln }, /* vblendvpd */
    { { 0x4c }, 3, T, R, pfx_66, W0, Ln }, /* vpblendvb */
    { { 0x5c }, 3, T, R, pfx_66, Wn, Ln }, /* vfmaddsubps */
    { { 0x5d }, 3, T, R, pfx_66, Wn, Ln }, /* vfmaddsubpd */
    { { 0x5e }, 3, T, R, pfx_66, Wn, Ln }, /* vfmsubaddps */
    { { 0x5f }, 3, T, R, pfx_66, Wn, Ln }, /* vfmsubaddpd */
    { { 0x60 }, 3, T, R, pfx_66, WIG, L0 }, /* vpcmpestrm */
    { { 0x61 }, 3, T, R, pfx_66, WIG, L0 }, /* vpcmpestri */
    { { 0x62 }, 3, T, R, pfx_66, WIG, L0 }, /* vpcmpistrm */
    { { 0x63 }, 3, T, R, pfx_66, WIG, L0 }, /* vpcmpistri */
    { { 0x68 }, 3, T, R, pfx_66, Wn, Ln }, /* vfmaddps */
    { { 0x69 }, 3, T, R, pfx_66, Wn, Ln }, /* vfmaddpd */
    { { 0x6a }, 3, T, R, pfx_66, Wn, LIG }, /* vfmaddss */
    { { 0x6b }, 3, T, R, pfx_66, Wn, LIG }, /* vfmaddsd */
    { { 0x6c }, 3, T, R, pfx_66, Wn, Ln }, /* vfmsubps */
    { { 0x6d }, 3, T, R, pfx_66, Wn, Ln }, /* vfmsubpd */
    { { 0x6e }, 3, T, R, pfx_66, Wn, LIG }, /* vfmsubss */
    { { 0x6f }, 3, T, R, pfx_66, Wn, LIG }, /* vfmsubsd */
    { { 0x78 }, 3, T, R, pfx_66, Wn, Ln }, /* vfnmaddps */
    { { 0x79 }, 3, T, R, pfx_66, Wn, Ln }, /* vfnmaddpd */
    { { 0x7a }, 3, T, R, pfx_66, Wn, LIG }, /* vfnmaddss */
    { { 0x7b }, 3, T, R, pfx_66, Wn, LIG }, /* vfnmaddsd */
    { { 0x7c }, 3, T, R, pfx_66, Wn, Ln }, /* vfnmsubps */
    { { 0x7d }, 3, T, R, pfx_66, Wn, Ln }, /* vfnmsubpd */
    { { 0x7e }, 3, T, R, pfx_66, Wn, LIG }, /* vfnmsubss */
    { { 0x7f }, 3, T, R, pfx_66, Wn, LIG }, /* vfnmsubsd */
    { { 0xce }, 3, T, R, pfx_66, W1, Ln }, /* vgf2p8affineqb */
    { { 0xcf }, 3, T, R, pfx_66, W1, Ln }, /* vgf2p8affineinvqb */
    { { 0xde }, 3, T, R, pfx_66, W0, L0 }, /* vsm3rnds2 */
    { { 0xdf }, 3, T, R, pfx_66, WIG, Ln }, /* vaeskeygenassist */
    { { 0xf0 }, 3, T, R, pfx_f2, Wn, L0 }, /* rorx */
};

static const struct {
    const struct vex *tbl;
    unsigned int num;
} vex[] = {
    { vex_0f,   ARRAY_SIZE(vex_0f) },
    { vex_0f38, ARRAY_SIZE(vex_0f38) },
    { vex_0f3a, ARRAY_SIZE(vex_0f3a) },
};

static const struct xop {
    uint8_t opc[2];
    uint8_t w:2;
    uint8_t l:2;
} xop_08[] = {
    { { 0x85 }, W0, L0 }, /* vpmacssww */
    { { 0x86 }, W0, L0 }, /* vpmacsswd */
    { { 0x87 }, W0, L0 }, /* vpmacssdql */
    { { 0x8e }, W0, L0 }, /* vpmacssdd */
    { { 0x8f }, W0, L0 }, /* vpmacssdqh */
    { { 0x95 }, W0, L0 }, /* vpmacsww */
    { { 0x96 }, W0, L0 }, /* vpmacswd */
    { { 0x97 }, W0, L0 }, /* vpmacsdql */
    { { 0x9e }, W0, L0 }, /* vpmacsdd */
    { { 0x9f }, W0, L0 }, /* vpmacsdqh */
    { { 0xa2 }, Wn, Ln }, /* vpcmov */
    { { 0xa3 }, Wn, L0 }, /* vpperm */
    { { 0xa6 }, W0, L0 }, /* vpmadcsswd */
    { { 0xb6 }, W0, L0 }, /* vpmadcswd */
    { { 0xc0 }, W0, L0 }, /* vprotb */
    { { 0xc1 }, W0, L0 }, /* vprotw */
    { { 0xc2 }, W0, L0 }, /* vprotd */
    { { 0xc3 }, W0, L0 }, /* vprotq */
    { { 0xcc }, W0, L0 }, /* vpcomb */
    { { 0xcd }, W0, L0 }, /* vpcomw */
    { { 0xce }, W0, L0 }, /* vpcomd */
    { { 0xcf }, W0, L0 }, /* vpcomq */
    { { 0xec }, W0, L0 }, /* vpcomub */
    { { 0xed }, W0, L0 }, /* vpcomuw */
    { { 0xee }, W0, L0 }, /* vpcomud */
    { { 0xef }, W0, L0 }, /* vpcomuq */
}, xop_09[] = {
    { { 0x01, 0x08 }, Wn, L0 }, /* blcfill */
    { { 0x01, 0x10 }, Wn, L0 }, /* blsfill */
    { { 0x01, 0x18 }, Wn, L0 }, /* blcs */
    { { 0x01, 0x20 }, Wn, L0 }, /* tzmsk */
    { { 0x01, 0x28 }, Wn, L0 }, /* blcic */
    { { 0x01, 0x30 }, Wn, L0 }, /* blsic */
    { { 0x01, 0x38 }, Wn, L0 }, /* t1mskc */
    { { 0x02, 0x08 }, Wn, L0 }, /* blcmsk */
    { { 0x02, 0x30 }, Wn, L0 }, /* blci */
    { { 0x02, 0xc0 }, Wn, L0 }, /* llwpcb */
    { { 0x02, 0xc8 }, Wn, L0 }, /* slwpcb */
    { { 0x80 }, W0, Ln }, /* vfrczps */
    { { 0x81 }, W0, Ln }, /* vfrczpd */
    { { 0x82 }, W0, L0 }, /* vfrczss */
    { { 0x83 }, W0, L0 }, /* vfrczsd */
    { { 0x90 }, Wn, L0 }, /* vprotb */
    { { 0x91 }, Wn, L0 }, /* vprotw */
    { { 0x92 }, Wn, L0 }, /* vprotd */
    { { 0x93 }, Wn, L0 }, /* vprotq */
    { { 0x94 }, Wn, L0 }, /* vpshlb */
    { { 0x95 }, Wn, L0 }, /* vpshlw */
    { { 0x96 }, Wn, L0 }, /* vpshld */
    { { 0x97 }, Wn, L0 }, /* vpshlq */
    { { 0x9c }, Wn, L0 }, /* vpshab */
    { { 0x9d }, Wn, L0 }, /* vpshaw */
    { { 0x9e }, Wn, L0 }, /* vpshad */
    { { 0x9f }, Wn, L0 }, /* vpshaq */
    { { 0xc1 }, W0, L0 }, /* vphaddbw */
    { { 0xc2 }, W0, L0 }, /* vphaddbd */
    { { 0xc3 }, W0, L0 }, /* vphaddbq */
    { { 0xc6 }, W0, L0 }, /* vphaddwd */
    { { 0xc7 }, W0, L0 }, /* vphaddwq */
    { { 0xcb }, W0, L0 }, /* vphadddq */
    { { 0xd1 }, W0, L0 }, /* vphaddubw */
    { { 0xd2 }, W0, L0 }, /* vphaddubd */
    { { 0xd3 }, W0, L0 }, /* vphaddubq */
    { { 0xd6 }, W0, L0 }, /* vphadduwd */
    { { 0xd7 }, W0, L0 }, /* vphadduwq */
    { { 0xdb }, W0, L0 }, /* vphaddudq */
    { { 0xe1 }, W0, L0 }, /* vphsubbw */
    { { 0xe2 }, W0, L0 }, /* vphsubwd */
    { { 0xe3 }, W0, L0 }, /* vphsubdq */
}, xop_0a[] = {
    { { 0x10 }, Wn, L0 }, /* bextr */
    { { 0x12, 0x00 }, Wn, L0 }, /* lwpins */
    { { 0x12, 0x08 }, Wn, L0 }, /* lwpval */
};

static const struct {
    const struct xop *tbl;
    unsigned int num;
    unsigned int imm;
} xop[] = {
    { xop_08, ARRAY_SIZE(xop_08), 1 },
    { xop_09, ARRAY_SIZE(xop_09), 0 },
    { xop_0a, ARRAY_SIZE(xop_0a), 4 },
};

#undef Ln

static const struct evex {
    uint8_t opc[3];
    uint8_t len:3;
    bool modrm:1; /* Should register form (also) be tested? */
    uint8_t mem:2;
    uint8_t pfx:2;
    uint8_t w:2;
    uint8_t l:3;
    bool mask:1;
#define L2 4
#define Ln (L0 | L1 | L2)
} evex_0f[] = {
    { { 0x10 }, 2, T, R, pfx_no, W0, Ln }, /* vmovups */
    { { 0x10 }, 2, T, R, pfx_66, W1, Ln }, /* vmovupd */
    { { 0x10 }, 2, T, R, pfx_f3, W0, LIG }, /* vmovss */
    { { 0x10 }, 2, T, R, pfx_f2, W1, LIG }, /* vmovsd */
    { { 0x11 }, 2, T, W, pfx_no, W0, Ln }, /* vmovups */
    { { 0x11 }, 2, T, W, pfx_66, W1, Ln }, /* vmovupd */
    { { 0x11 }, 2, T, W, pfx_f3, W0, LIG }, /* vmovss */
    { { 0x11 }, 2, T, W, pfx_f2, W1, LIG }, /* vmovsd */
    { { 0x12 }, 2, T, R, pfx_no, W0, L0 }, /* vmovlps / vmovhlps */
    { { 0x12 }, 2, F, R, pfx_66, W1, L0 }, /* vmovlpd */
    { { 0x12 }, 2, T, R, pfx_f3, W0, Ln }, /* vmovsldup */
    { { 0x12 }, 2, T, R, pfx_f2, W1, Ln }, /* vmovddup */
    { { 0x13 }, 2, F, W, pfx_no, W0, L0 }, /* vmovlps */
    { { 0x13 }, 2, F, W, pfx_66, W1, L0 }, /* vmovlpd */
    { { 0x14 }, 2, T, R, pfx_no, W0, Ln }, /* vunpcklps */
    { { 0x14 }, 2, T, R, pfx_66, W1, Ln }, /* vunpcklpd */
    { { 0x15 }, 2, T, R, pfx_no, W0, Ln }, /* vunpckhps */
    { { 0x15 }, 2, T, R, pfx_66, W1, Ln }, /* vunpckhpd */
    { { 0x16 }, 2, T, R, pfx_no, W0, L0 }, /* vmovhps / vmovlhps */
    { { 0x16 }, 2, F, R, pfx_66, W1, L0 }, /* vmovhpd */
    { { 0x16 }, 2, T, R, pfx_f3, W0, Ln }, /* vmovshdup */
    { { 0x17 }, 2, F, W, pfx_no, W0, L0 }, /* vmovhps */
    { { 0x17 }, 2, F, W, pfx_66, W1, L0 }, /* vmovhpd */
    { { 0x28 }, 2, T, R, pfx_no, W0, Ln }, /* vmovaps */
    { { 0x28 }, 2, T, R, pfx_66, W1, Ln }, /* vmovapd */
    { { 0x29 }, 2, T, W, pfx_no, W0, Ln }, /* vmovaps */
    { { 0x29 }, 2, T, W, pfx_66, W1, Ln }, /* vmovapd */
    { { 0x2a }, 2, T, R, pfx_f3, W0, LIG }, /* vcvtsi2ss */
    { { 0x2a }, 2, T, R, pfx_f2, W1, LIG }, /* vcvtsi2sd */
    { { 0x2b }, 2, T, W, pfx_no, W0, Ln }, /* vmovntps */
    { { 0x2b }, 2, T, W, pfx_66, W1, Ln }, /* vmovntpd */
    { { 0x2c }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvttss2si */
    { { 0x2c }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvttsd2si */
    { { 0x2d }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtss2si */
    { { 0x2d }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvtsd2si */
    { { 0x2e }, 2, T, R, pfx_no, W0, LIG }, /* vucomiss */
    { { 0x2e }, 2, T, R, pfx_66, W1, LIG }, /* vucomisd */
    { { 0x2f }, 2, T, R, pfx_no, W0, LIG }, /* vcomiss */
    { { 0x2f }, 2, T, R, pfx_66, W1, LIG }, /* vcomisd */
    { { 0x51 }, 2, T, R, pfx_no, W0, Ln }, /* vsqrtps */
    { { 0x51 }, 2, T, R, pfx_66, W1, Ln }, /* vsqrtpd */
    { { 0x51 }, 2, T, R, pfx_f3, W0, LIG }, /* vsqrtss */
    { { 0x51 }, 2, T, R, pfx_f2, W1, LIG }, /* vsqrtsd */
    { { 0x54 }, 2, T, R, pfx_no, W0, Ln }, /* vandps */
    { { 0x54 }, 2, T, R, pfx_66, W1, Ln }, /* vandpd */
    { { 0x55 }, 2, T, R, pfx_no, W0, Ln }, /* vandnps */
    { { 0x55 }, 2, T, R, pfx_66, W1, Ln }, /* vandnpd */
    { { 0x56 }, 2, T, R, pfx_no, W0, Ln }, /* vorps */
    { { 0x56 }, 2, T, R, pfx_66, W1, Ln }, /* vorpd */
    { { 0x57 }, 2, T, R, pfx_no, W0, Ln }, /* vxorps */
    { { 0x57 }, 2, T, R, pfx_66, W1, Ln }, /* vxorpd */
    { { 0x58 }, 2, T, R, pfx_no, W0, Ln }, /* vaddps */
    { { 0x58 }, 2, T, R, pfx_66, W1, Ln }, /* vaddpd */
    { { 0x58 }, 2, T, R, pfx_f3, W0, LIG }, /* vaddss */
    { { 0x58 }, 2, T, R, pfx_f2, W1, LIG }, /* vaddsd */
    { { 0x59 }, 2, T, R, pfx_no, W0, Ln }, /* vmulps */
    { { 0x59 }, 2, T, R, pfx_66, W1, Ln }, /* vmulpd */
    { { 0x59 }, 2, T, R, pfx_f3, W0, LIG }, /* vmulss */
    { { 0x59 }, 2, T, R, pfx_f2, W1, LIG }, /* vmulsd */
    { { 0x5a }, 2, T, R, pfx_no, W0, Ln }, /* vcvtps2pd */
    { { 0x5a }, 2, T, R, pfx_66, W1, Ln }, /* vcvtpd2ps */
    { { 0x5a }, 2, T, R, pfx_f3, W0, LIG }, /* vcvtss2sd */
    { { 0x5a }, 2, T, R, pfx_f2, W1, LIG }, /* vcvtsd2ss */
    { { 0x5b }, 2, T, R, pfx_no, Wn, Ln }, /* vcvt{d,q}q2ps */
    { { 0x5b }, 2, T, R, pfx_66, W0, Ln }, /* vcvtps2dq */
    { { 0x5b }, 2, T, R, pfx_f3, W0, Ln }, /* vcvttps2dq */
    { { 0x5c }, 2, T, R, pfx_no, W0, Ln }, /* vsubps */
    { { 0x5c }, 2, T, R, pfx_66, W1, Ln }, /* vsubpd */
    { { 0x5c }, 2, T, R, pfx_f3, W0, LIG }, /* vsubss */
    { { 0x5c }, 2, T, R, pfx_f2, W1, LIG }, /* vsubsd */
    { { 0x5d }, 2, T, R, pfx_no, W0, Ln }, /* vminps */
    { { 0x5d }, 2, T, R, pfx_66, W1, Ln }, /* vminpd */
    { { 0x5d }, 2, T, R, pfx_f3, W0, LIG }, /* vminss */
    { { 0x5d }, 2, T, R, pfx_f2, W1, LIG }, /* vminsd */
    { { 0x5e }, 2, T, R, pfx_no, W0, Ln }, /* vdivps */
    { { 0x5e }, 2, T, R, pfx_66, W1, Ln }, /* vdivpd */
    { { 0x5e }, 2, T, R, pfx_f3, W0, LIG }, /* vdivss */
    { { 0x5e }, 2, T, R, pfx_f2, W1, LIG }, /* vdivsd */
    { { 0x5f }, 2, T, R, pfx_no, W0, Ln }, /* vmaxps */
    { { 0x5f }, 2, T, R, pfx_66, W1, Ln }, /* vmaxpd */
    { { 0x5f }, 2, T, R, pfx_f3, W0, LIG }, /* vmaxss */
    { { 0x5f }, 2, T, R, pfx_f2, W1, LIG }, /* vmaxsd */
    { { 0x60 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpcklbw */
    { { 0x61 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpcklwd */
    { { 0x62 }, 2, T, R, pfx_66, W0, Ln }, /* vpunpckldq */
    { { 0x63 }, 2, T, R, pfx_66, WIG, Ln }, /* vpacksswb */
    { { 0x64 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtb */
    { { 0x65 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpgtw */
    { { 0x66 }, 2, T, R, pfx_66, W0, Ln }, /* vpcmpgtd */
    { { 0x67 }, 2, T, R, pfx_66, WIG, Ln }, /* vpackuswb */
    { { 0x68 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhbw */
    { { 0x69 }, 2, T, R, pfx_66, WIG, Ln }, /* vpunpckhwd */
    { { 0x6a }, 2, T, R, pfx_66, W0, Ln }, /* vpunpckhdq */
    { { 0x6b }, 2, T, R, pfx_66, W0, Ln }, /* vpackssdw */
    { { 0x6c }, 2, T, R, pfx_66, W1, Ln }, /* vpunpcklqdq */
    { { 0x6d }, 2, T, R, pfx_66, W1, Ln }, /* vpunpckhqdq */
    { { 0x6e }, 2, T, R, pfx_66, Wn, L0 }, /* vmov{d,q} */
    { { 0x6f }, 2, T, R, pfx_66, Wn, Ln }, /* vmovdqa{32,64} */
    { { 0x6f }, 2, T, R, pfx_f3, Wn, Ln }, /* vmovdqu{32,64} */
    { { 0x6f }, 2, T, R, pfx_f2, Wn, Ln }, /* vmovdqu{8,16} */
    { { 0x70 }, 3, T, R, pfx_66, W0, Ln }, /* vpshufd */
    { { 0x70 }, 3, T, R, pfx_f3, WIG, Ln }, /* vpshuflw */
    { { 0x70 }, 3, T, R, pfx_f2, WIG, Ln }, /* vpshufhw */
    { { 0x71, 0xd0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrlw */
    { { 0x71, 0xe0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsraw */
    { { 0x71, 0xf0 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsllw */
    { { 0x72, 0xc0 }, 3, F, N, pfx_66, Wn, Ln }, /* vpror{d,q} */
    { { 0x72, 0xc8 }, 3, F, N, pfx_66, Wn, Ln }, /* vprol{d,q} */
    { { 0x72, 0xd0 }, 3, F, N, pfx_66, W0, Ln }, /* vpsrld */
    { { 0x72, 0xe0 }, 3, F, N, pfx_66, Wn, Ln }, /* vpsra{d,q} */
    { { 0x72, 0xf0 }, 3, F, N, pfx_66, W0, Ln }, /* vpslld */
    { { 0x73, 0xd0 }, 3, F, N, pfx_66, W1, Ln }, /* vpsrlq */
    { { 0x73, 0xd8 }, 3, F, N, pfx_66, WIG, Ln }, /* vpsrldq */
    { { 0x73, 0xf0 }, 3, F, N, pfx_66, W0, Ln }, /* vpsllq */
    { { 0x73, 0xf8 }, 3, F, N, pfx_66, WIG, Ln }, /* vpslldq */
    { { 0x74 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqb */
    { { 0x75 }, 2, T, R, pfx_66, WIG, Ln }, /* vpcmpeqw */
    { { 0x76 }, 2, T, R, pfx_66, W0, Ln }, /* vpcmpeqd */
    { { 0x78 }, 2, T, R, pfx_no, Wn, Ln }, /* vcvttp{s,d}2udq */
    { { 0x78 }, 2, T, R, pfx_66, Wn, Ln }, /* vcvttp{s,d}2uqq */
    { { 0x78 }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvttss2usi */
    { { 0x78 }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvttsd2usi */
    { { 0x79 }, 2, T, R, pfx_no, Wn, Ln }, /* vcvtp{s,d}2udq */
    { { 0x79 }, 2, T, R, pfx_66, Wn, Ln }, /* vcvtp{s,d}2uqq */
    { { 0x79 }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtss2usi */
    { { 0x79 }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvtsd2usi */
    { { 0x7a }, 2, T, R, pfx_66, Wn, Ln }, /* vcvttp{s,d}2qq */
    { { 0x7a }, 2, T, R, pfx_f3, Wn, Ln }, /* vcvtu{d,q}2pd */
    { { 0x7a }, 2, T, R, pfx_f2, Wn, Ln }, /* vcvtu{d,q}2ps */
    { { 0x7b }, 2, T, R, pfx_66, Wn, Ln }, /* vcvtp{s,d}2qq */
    { { 0x7b }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtusi2ss */
    { { 0x7b }, 2, T, R, pfx_f2, Wn, LIG }, /* vcvtusi2sd */
    { { 0x7e }, 2, T, W, pfx_66, Wn, L0 }, /* vmov{d,q} */
    { { 0x7e }, 2, T, R, pfx_f3, W1, L0 }, /* vmovq */
    { { 0x7f }, 2, T, W, pfx_66, Wn, Ln }, /* vmovdqa{32,64} */
    { { 0x7f }, 2, T, W, pfx_f3, Wn, Ln }, /* vmovdqu{32,64} */
    { { 0x7f }, 2, T, W, pfx_f2, Wn, Ln }, /* vmovdqu{8,16} */
    { { 0xc2 }, 3, T, R, pfx_no, W0, Ln }, /* vcmpps */
    { { 0xc2 }, 3, T, R, pfx_66, W1, Ln }, /* vcmppd */
    { { 0xc2 }, 3, T, R, pfx_f3, W0, LIG }, /* vcmpss */
    { { 0xc2 }, 3, T, R, pfx_f2, W1, LIG }, /* vcmpsd */
    { { 0xc4 }, 3, T, R, pfx_66, WIG, L0 }, /* vpinsrw */
    { { 0xc5, 0xc0 }, 3, F, N, pfx_66, WIG, L0 }, /* vpextrw */
    { { 0xc6 }, 3, T, R, pfx_no, W0, Ln }, /* vshufps */
    { { 0xc6 }, 3, T, R, pfx_66, W1, Ln }, /* vshufpd */
    { { 0xd1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsrlw */
    { { 0xd2 }, 2, T, R, pfx_66, W0, Ln }, /* vpsrld */
    { { 0xd3 }, 2, T, R, pfx_66, W1, Ln }, /* vpsrlq */
    { { 0xd4 }, 2, T, R, pfx_66, W1, Ln }, /* vpaddq */
    { { 0xd5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmullw */
    { { 0xd6 }, 2, T, W, pfx_66, W1, L0 }, /* vmovq */
    { { 0xd8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubusb */
    { { 0xd9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubusw */
    { { 0xda }, 2, T, R, pfx_66, WIG, Ln }, /* vpminub */
    { { 0xdb }, 2, T, R, pfx_66, Wn, Ln }, /* vpand{d,q} */
    { { 0xdc }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddusb */
    { { 0xdd }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddusw */
    { { 0xde }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxub */
    { { 0xdf }, 2, T, R, pfx_66, Wn, Ln }, /* vpandn{d,q} */
    { { 0xe0 }, 2, T, R, pfx_66, WIG, Ln }, /* vpavgb */
    { { 0xe1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsraw */
    { { 0xe2 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsra{d,q} */
    { { 0xe3 }, 2, T, R, pfx_66, WIG, Ln }, /* vpavgw */
    { { 0xe4 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhuw */
    { { 0xe5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhw */
    { { 0xe6 }, 2, T, R, pfx_66, WIG, Ln }, /* vcvttpd2dq */
    { { 0xe6 }, 2, T, R, pfx_f3, Wn, Ln }, /* vcvt{d,q}q2pd */
    { { 0xe6 }, 2, T, R, pfx_f2, WIG, Ln }, /* vcvtpd2dq */
    { { 0xe7 }, 2, F, W, pfx_66, W0, Ln }, /* vmovntdq */
    { { 0xe8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubsb */
    { { 0xe9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubsw */
    { { 0xea }, 2, T, R, pfx_66, WIG, Ln }, /* vpminsw */
    { { 0xeb }, 2, T, R, pfx_66, Wn, Ln }, /* vpor{d,q} */
    { { 0xec }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddsb */
    { { 0xed }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddsw */
    { { 0xee }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxsw */
    { { 0xef }, 2, T, R, pfx_66, Wn, Ln }, /* vpxor{d,q} */
    { { 0xf1 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsllw */
    { { 0xf2 }, 2, T, R, pfx_66, W0, Ln }, /* vpslld */
    { { 0xf3 }, 2, T, R, pfx_66, W1, Ln }, /* vpsllq */
    { { 0xf4 }, 2, T, R, pfx_66, W1, Ln }, /* vpmuludq */
    { { 0xf5 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaddwd */
    { { 0xf6 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsadbw */
    { { 0xf8 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubb */
    { { 0xf9 }, 2, T, R, pfx_66, WIG, Ln }, /* vpsubw */
    { { 0xfa }, 2, T, R, pfx_66, W0, Ln }, /* vpsubd */
    { { 0xfb }, 2, T, R, pfx_66, W1, Ln }, /* vpsubq */
    { { 0xfc }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddb */
    { { 0xfd }, 2, T, R, pfx_66, WIG, Ln }, /* vpaddw */
    { { 0xfe }, 2, T, R, pfx_66, W0, Ln }, /* vpaddd */
}, evex_0f38[] = {
    { { 0x00 }, 2, T, R, pfx_66, WIG, Ln }, /* vpshufb */
    { { 0x04 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaddubsw */
    { { 0x0b }, 2, T, R, pfx_66, WIG, Ln }, /* vpmulhrsw */
    { { 0x0c }, 2, T, R, pfx_66, W0, Ln }, /* vpermilps */
    { { 0x0d }, 2, T, R, pfx_66, W1, Ln }, /* vpermilpd */
    { { 0x10 }, 2, T, R, pfx_66, W1, Ln }, /* vpsrlvw */
    { { 0x10 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovuswb */
    { { 0x11 }, 2, T, R, pfx_66, W1, Ln }, /* vpsravw */
    { { 0x11 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovusdb */
    { { 0x12 }, 2, T, R, pfx_66, W1, Ln }, /* vpsllvw */
    { { 0x12 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovusqb */
    { { 0x13 }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2ps */
    { { 0x13 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovusdw */
    { { 0x14 }, 2, T, R, pfx_66, Wn, Ln }, /* vprorv{d,q} */
    { { 0x14 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovusqw */
    { { 0x15 }, 2, T, R, pfx_66, Wn, Ln }, /* vprolv{d,q} */
    { { 0x15 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovusqd */
    { { 0x16 }, 2, T, R, pfx_66, Wn, L1|L2 }, /* vpermp{s,d} */
    { { 0x18 }, 2, T, R, pfx_66, W0, Ln }, /* vbroadcastss */
    { { 0x19 }, 2, T, R, pfx_66, Wn, L1|L2 }, /* vbroadcast{32x2,sd} */
    { { 0x1a }, 2, F, R, pfx_66, Wn, L1|L2 }, /* vbroadcastf{32x4,64x2} */
    { { 0x1b }, 2, F, R, pfx_66, Wn, L2 }, /* vbroadcastf{32x8,64x4} */
    { { 0x1c }, 2, T, R, pfx_66, WIG, Ln }, /* vpabsb */
    { { 0x1d }, 2, T, R, pfx_66, WIG, Ln }, /* vpabsw */
    { { 0x1e }, 2, T, R, pfx_66, W0, Ln }, /* vpabsd */
    { { 0x1f }, 2, T, R, pfx_66, W1, Ln }, /* vpabsq */
    { { 0x20 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbw */
    { { 0x20 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovswb */
    { { 0x21 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbd */
    { { 0x21 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovsdb */
    { { 0x22 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxbq */
    { { 0x22 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovsqb */
    { { 0x23 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxwd */
    { { 0x23 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovsdw */
    { { 0x24 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovsxwq */
    { { 0x24 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovsqw */
    { { 0x25 }, 2, T, R, pfx_66, W0, Ln }, /* vpmovsxdq */
    { { 0x25 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovsqd */
    { { 0x26 }, 2, T, R, pfx_66, Wn, Ln }, /* vptestm{b,w} */
    { { 0x26 }, 2, T, R, pfx_f3, Wn, Ln }, /* vptestnm{b,w} */
    { { 0x27 }, 2, T, R, pfx_66, Wn, Ln }, /* vptestm{d,q} */
    { { 0x27 }, 2, T, R, pfx_f3, Wn, Ln }, /* vptestnm{d,q} */
    { { 0x28 }, 2, T, R, pfx_66, W1, Ln }, /* vpmuldq */
    { { 0x28, 0xc0 }, 2, F, N, pfx_f3, Wn, Ln }, /* vpmovm2{b,w} */
    { { 0x29 }, 2, T, R, pfx_66, W1, Ln }, /* vpcmpeqq */
    { { 0x29, 0xc0 }, 2, F, N, pfx_f3, Wn, Ln }, /* vpmov{b,w}2m */
    { { 0x2a }, 2, F, R, pfx_66, W0, Ln }, /* vmovntdqa */
    { { 0x2a, 0xc0 }, 2, F, N, pfx_f3, W1, Ln }, /* vpbroadcastmb2q */
    { { 0x2b }, 2, T, R, pfx_66, W0, Ln }, /* vpackusdw */
    { { 0x2c }, 2, T, R, pfx_66, Wn, Ln }, /* vscalefp{s,d} */
    { { 0x2d }, 2, T, R, pfx_66, Wn, LIG }, /* vscalefs{s,d} */
    { { 0x30 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbw */
    { { 0x30 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovwb */
    { { 0x31 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbd */
    { { 0x31 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovdb */
    { { 0x32 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxbq */
    { { 0x32 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovqb */
    { { 0x33 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxwd */
    { { 0x33 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovdw */
    { { 0x34 }, 2, T, R, pfx_66, WIG, Ln }, /* vpmovzxwq */
    { { 0x34 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovqw */
    { { 0x35 }, 2, T, R, pfx_66, W0, Ln }, /* vpmovzxdq */
    { { 0x35 }, 2, T, W, pfx_f3, W0, Ln }, /* vpmovqd */
    { { 0x36 }, 2, T, R, pfx_66, Wn, L1|L2 }, /* vperm{d,q} */
    { { 0x37 }, 2, T, R, pfx_66, W1, Ln }, /* vpcmpgtq */
    { { 0x38 }, 2, T, R, pfx_66, WIG, Ln }, /* vpminsb */
    { { 0x38, 0xc0 }, 2, F, N, pfx_f3, Wn, Ln }, /* vpmovm2{d,q} */
    { { 0x39 }, 2, T, R, pfx_66, Wn, Ln }, /* vpmins{d,q} */
    { { 0x39, 0xc0 }, 2, F, N, pfx_f3, Wn, Ln }, /* vpmov{d,q}2m */
    { { 0x3a }, 2, T, R, pfx_66, WIG, Ln }, /* vpminuw */
    { { 0x3a, 0xc0 }, 2, F, N, pfx_f3, W0, Ln }, /* vpbroadcastmw2d */
    { { 0x3b }, 2, T, R, pfx_66, Wn, Ln }, /* vpminu{d,q} */
    { { 0x3c }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxsb */
    { { 0x3d }, 2, T, R, pfx_66, Wn, Ln }, /* vpmaxs{d,q} */
    { { 0x3e }, 2, T, R, pfx_66, WIG, Ln }, /* vpmaxuw */
    { { 0x3f }, 2, T, R, pfx_66, Wn, Ln }, /* vpmaxu{d,q} */
    { { 0x40 }, 2, T, R, pfx_66, Wn, Ln }, /* vpmull{d,q} */
    { { 0x42 }, 2, T, R, pfx_66, Wn, Ln }, /* vgetexpp{s,d} */
    { { 0x43 }, 2, T, R, pfx_66, Wn, LIG }, /* vgetexps{s,d} */
    { { 0x44 }, 2, T, R, pfx_66, Wn, Ln }, /* vlzcnt{d,q} */
    { { 0x45 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsrlv{d,q} */
    { { 0x46 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsrav{d,q} */
    { { 0x47 }, 2, T, R, pfx_66, Wn, Ln }, /* vpsllv{d,q} */
    { { 0x4c }, 2, T, R, pfx_66, Wn, Ln }, /* vrcp14p{s,d} */
    { { 0x4d }, 2, T, R, pfx_66, Wn, LIG }, /* vrcp14s{s,d} */
    { { 0x4e }, 2, T, R, pfx_66, Wn, Ln }, /* vrsqrt14p{s,d} */
    { { 0x4f }, 2, T, R, pfx_66, Wn, LIG }, /* vrsqrt14s{s,d} */
    { { 0x50 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpbusd */
    { { 0x51 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpbusds */
    { { 0x52 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwssd */
    { { 0x52 }, 2, T, R, pfx_f3, W0, Ln }, /* vdpbf16ps */
    { { 0x52 }, 2, T, R, pfx_f2, W0, L2 }, /* vp4dpwssd */
    { { 0x53 }, 2, T, R, pfx_66, W0, Ln }, /* vpdpwssds */
    { { 0x53 }, 2, T, R, pfx_f2, W0, L2 }, /* vp4dpwssds */
    { { 0x54 }, 2, T, R, pfx_66, Wn, Ln }, /* vpopcnt{b,w} */
    { { 0x55 }, 2, T, R, pfx_66, Wn, Ln }, /* vpopcnt{d,q} */
    { { 0x58 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastd */
    { { 0x59 }, 2, T, R, pfx_66, Wn, Ln }, /* vbroadcast32x2 / vpbroadcastq */
    { { 0x5a }, 2, F, R, pfx_66, Wn, L1|L2 }, /* vbroadcasti{32x4,64x2} */
    { { 0x5b }, 2, F, R, pfx_66, Wn, L2 }, /* vbroadcasti{32x8,64x4} */
    { { 0x62 }, 2, T, R, pfx_66, Wn, Ln }, /* vpexpand{b,w} */
    { { 0x63 }, 2, T, W, pfx_66, Wn, Ln }, /* vpcompress{b,w} */
    { { 0x64 }, 2, T, R, pfx_66, Wn, Ln }, /* vpblendm{d,q} */
    { { 0x65 }, 2, T, R, pfx_66, Wn, Ln }, /* vblendmp{s,d} */
    { { 0x66 }, 2, T, R, pfx_66, Wn, Ln }, /* vpblendm{b,w} */
    { { 0x68 }, 2, T, R, pfx_f2, Wn, Ln }, /* vp2intersect{d,q} */
    { { 0x70 }, 2, T, R, pfx_66, W1, Ln }, /* vpshldvw */
    { { 0x71 }, 2, T, R, pfx_66, Wn, Ln }, /* vpshldv{d,q} */
    { { 0x72 }, 2, T, R, pfx_66, W1, Ln }, /* vpshrdvw */
    { { 0x72 }, 2, T, R, pfx_f3, W1, Ln }, /* vcvtneps2bf16 */
    { { 0x72 }, 2, T, R, pfx_f2, W1, Ln }, /* vcvtne2ps2bf16 */
    { { 0x73 }, 2, T, R, pfx_66, Wn, Ln }, /* vpshrdv{d,q} */
    { { 0x75 }, 2, T, R, pfx_66, Wn, Ln }, /* vpermi2{b,w} */
    { { 0x76 }, 2, T, R, pfx_66, Wn, Ln }, /* vpermi2{d,q} */
    { { 0x77 }, 2, T, R, pfx_66, Wn, Ln }, /* vpermi2p{s,d} */
    { { 0x78 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastb */
    { { 0x79 }, 2, T, R, pfx_66, W0, Ln }, /* vpbroadcastw */
    { { 0x7a, 0xc0 }, 2, F, N, pfx_66, W0, Ln }, /* vpbroadcastb */
    { { 0x7b, 0xc0 }, 2, F, N, pfx_66, W0, Ln }, /* vpbroadcastw */
    { { 0x7c, 0xc0 }, 2, F, N, pfx_66, W0, Ln }, /* vpbroadcast{d,q} */
    { { 0x7d }, 2, T, R, pfx_66, Wn, Ln }, /* vpermt2{b,w} */
    { { 0x7e }, 2, T, R, pfx_66, Wn, Ln }, /* vpermt2{d,q} */
    { { 0x7f }, 2, T, R, pfx_66, Wn, Ln }, /* vpermt2p{s,d} */
    { { 0x83 }, 2, T, R, pfx_66, W1, Ln }, /* vpmultishiftqb */
    { { 0x88 }, 2, T, R, pfx_66, Wn, Ln }, /* vpexpandp{s,d} */
    { { 0x89 }, 2, T, R, pfx_66, Wn, Ln }, /* vpexpand{d,q} */
    { { 0x8a }, 2, T, W, pfx_66, Wn, Ln }, /* vpcompressp{s,d} */
    { { 0x8b }, 2, T, W, pfx_66, Wn, Ln }, /* vpcompress{d,q} */
    { { 0x8d }, 2, F, R, pfx_66, Wn, Ln }, /* vperm{b,w} */
    { { 0x8f }, 2, F, R, pfx_66, W0, Ln }, /* vpshufbitqmb */
    { { 0x90, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln, T }, /* vpgatherd{d,q} */
    { { 0x91, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln, T }, /* vpgatherq{d,q} */
    { { 0x92, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln, T }, /* vgatherdp{s,d} */
    { { 0x93, VSIB(1) }, 3, F, R, pfx_66, Wn, Ln, T }, /* vgatherqp{s,d} */
    { { 0x96 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmaddsub132p{s,d} */
    { { 0x97 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsubadd132p{s,d} */
    { { 0x98 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmadd132p{s,d} */
    { { 0x99 }, 2, T, R, pfx_66, Wn, LIG }, /* vfmadd132s{s,d} */
    { { 0x9a }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsub132p{s,d} */
    { { 0x9a }, 2, T, R, pfx_f2, W0, L2 }, /* v4fmaddps */
    { { 0x9b }, 2, T, R, pfx_66, Wn, LIG }, /* vfmsub132s{s,d} */
    { { 0x9b }, 2, T, R, pfx_f2, W0, LIG }, /* v4fmaddss */
    { { 0x9c }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmadd132p{s,d} */
    { { 0x9d }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmadd132s{s,d} */
    { { 0x9e }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmsub132p{s,d} */
    { { 0x9f }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmsub132s{s,d} */
    { { 0xa0, VSIB(1) }, 3, F, W, pfx_66, Wn, Ln, T }, /* vpscatterd{d,q} */
    { { 0xa1, VSIB(1) }, 3, F, W, pfx_66, Wn, Ln, T }, /* vpscatterq{d,q} */
    { { 0xa2, VSIB(1) }, 3, F, W, pfx_66, Wn, Ln, T }, /* vscatterdp{s,d} */
    { { 0xa3, VSIB(1) }, 3, F, W, pfx_66, Wn, Ln, T }, /* vscatterqp{s,d} */
    { { 0xa6 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmaddsub213p{s,d} */
    { { 0xa7 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsubadd213p{s,d} */
    { { 0xa8 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmadd213p{s,d} */
    { { 0xa9 }, 2, T, R, pfx_66, Wn, LIG }, /* vfmadd213s{s,d} */
    { { 0x9a }, 2, T, R, pfx_f2, W0, L2 }, /* v4fnmaddps */
    { { 0xaa }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsub213p{s,d} */
    { { 0xab }, 2, T, R, pfx_66, Wn, LIG }, /* vfmsub213s{s,d} */
    { { 0x9b }, 2, T, R, pfx_f2, W0, LIG }, /* v4fnmaddss */
    { { 0xac }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmadd213p{s,d} */
    { { 0xad }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmadd213s{s,d} */
    { { 0xae }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmsub213p{s,d} */
    { { 0xaf }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmsub213s{s,d} */
    { { 0xb4 }, 2, T, R, pfx_66, W1, Ln }, /* vpmadd52luq */
    { { 0xb5 }, 2, T, R, pfx_66, W1, Ln }, /* vpmadd52huq */
    { { 0xb6 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmaddsub231p{s,d} */
    { { 0xb7 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsubadd231p{s,d} */
    { { 0xb8 }, 2, T, R, pfx_66, Wn, Ln }, /* vfmadd231p{s,d} */
    { { 0xb9 }, 2, T, R, pfx_66, Wn, LIG }, /* vfmadd231s{s,d} */
    { { 0xba }, 2, T, R, pfx_66, Wn, Ln }, /* vfmsub231p{s,d} */
    { { 0xbb }, 2, T, R, pfx_66, Wn, LIG }, /* vfmsub231s{s,d} */
    { { 0xbc }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmadd231p{s,d} */
    { { 0xbd }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmadd231s{s,d} */
    { { 0xbe }, 2, T, R, pfx_66, Wn, Ln }, /* vfnmsub231p{s,d} */
    { { 0xbf }, 2, T, R, pfx_66, Wn, LIG }, /* vfnmsub231s{s,d} */
    { { 0xc4 }, 2, T, R, pfx_66, Wn, Ln }, /* vpconflict{d,q} */
    { { 0xc6, VSIB(1) }, 3, F, N, pfx_66, Wn, L2, T }, /* vgatherpf0dp{s,d} */
    { { 0xc6, VSIB(2) }, 3, F, N, pfx_66, Wn, L2, T }, /* vgatherpf1dp{s,d} */
    { { 0xc6, VSIB(5) }, 3, F, N, pfx_66, Wn, L2, T }, /* vscatterpf0dp{s,d} */
    { { 0xc6, VSIB(6) }, 3, F, N, pfx_66, Wn, L2, T }, /* vscatterpf1dp{s,d} */
    { { 0xc7, VSIB(1) }, 3, F, N, pfx_66, Wn, L2, T }, /* vgatherpf0qp{s,d} */
    { { 0xc7, VSIB(2) }, 3, F, N, pfx_66, Wn, L2, T }, /* vgatherpf1qp{s,d} */
    { { 0xc7, VSIB(5) }, 3, F, N, pfx_66, Wn, L2, T }, /* vscatterpf0qp{s,d} */
    { { 0xc7, VSIB(6) }, 3, F, N, pfx_66, Wn, L2, T }, /* vscatterpf1qp{s,d} */
    { { 0xc8 }, 2, T, R, pfx_66, Wn, L2 }, /* vexp2p{s,d} */
    { { 0xca }, 2, T, R, pfx_66, Wn, L2 }, /* vrcp28p{s,d} */
    { { 0xcb }, 2, T, R, pfx_66, Wn, LIG }, /* vrcp28s{s,d} */
    { { 0xcc }, 2, T, R, pfx_66, Wn, L2 }, /* vrsqrt28p{s,d} */
    { { 0xcd }, 2, T, R, pfx_66, Wn, LIG }, /* vrsqrt28s{s,d} */
    { { 0xcf }, 2, T, R, pfx_66, W0, Ln }, /* vgf2p8mulb */
    { { 0xdc }, 2, T, R, pfx_66, WIG, Ln }, /* vaesenc */
    { { 0xdd }, 2, T, R, pfx_66, WIG, Ln }, /* vaesenclast */
    { { 0xde }, 2, T, R, pfx_66, WIG, Ln }, /* vaesdec */
    { { 0xdf }, 2, T, R, pfx_66, WIG, Ln }, /* vaesdeclast */
}, evex_0f3a[] = {
    { { 0x00 }, 3, T, R, pfx_66, W1, L1|L2 }, /* vpermq */
    { { 0x01 }, 3, T, R, pfx_66, W1, L1|L2 }, /* vpermpd */
    { { 0x03 }, 3, T, R, pfx_66, Wn, Ln }, /* valign{d,q} */
    { { 0x04 }, 3, T, R, pfx_66, W0, Ln }, /* vpermilps */
    { { 0x05 }, 3, T, R, pfx_66, W1, Ln }, /* vpermilpd */
    { { 0x08 }, 3, T, R, pfx_no, W0, Ln }, /* vrndscaleph */
    { { 0x08 }, 3, T, R, pfx_66, W0, Ln }, /* vrndscaleps */
    { { 0x09 }, 3, T, R, pfx_66, W1, Ln }, /* vrndscalepd */
    { { 0x0a }, 3, T, R, pfx_no, W0, LIG }, /* vrndscalesh */
    { { 0x0a }, 3, T, R, pfx_66, W0, LIG }, /* vrndscaless */
    { { 0x0b }, 3, T, R, pfx_66, W1, LIG }, /* vrndscalesd */
    { { 0x0f }, 3, T, R, pfx_66, WIG, Ln }, /* vpalignr */
    { { 0x14 }, 3, T, W, pfx_66, WIG, L0 }, /* vpextrb */
    { { 0x15 }, 3, T, W, pfx_66, WIG, L0 }, /* vpextrw */
    { { 0x16 }, 3, T, W, pfx_66, Wn, L0 }, /* vpextr{d,q} */
    { { 0x17 }, 3, T, W, pfx_66, WIG, L0 }, /* vextractps */
    { { 0x18 }, 3, T, R, pfx_66, Wn, L1|L2 }, /* vinsertf{32x4,64x2} */
    { { 0x19 }, 3, T, W, pfx_66, Wn, L1|L2 }, /* vextractf{32x4,64x2} */
    { { 0x1a }, 3, T, R, pfx_66, Wn, L2 }, /* vinsertf{32x8,64x4} */
    { { 0x1b }, 3, T, W, pfx_66, Wn, L2 }, /* vextractf{32x8,64x4} */
    { { 0x1d }, 3, T, W, pfx_66, W0, Ln }, /* vcvtps2ph */
    { { 0x1e }, 3, T, R, pfx_66, Wn, Ln }, /* vpcmpu{d,q} */
    { { 0x1f }, 3, T, R, pfx_66, Wn, Ln }, /* vpcmp{d,q} */
    { { 0x20 }, 3, T, R, pfx_66, WIG, L0 }, /* vpinsrb */
    { { 0x21 }, 3, T, R, pfx_66, WIG, L0 }, /* vinsertps */
    { { 0x22 }, 3, T, R, pfx_66, Wn, L0 }, /* vpinsr{d,q} */
    { { 0x23 }, 3, T, R, pfx_66, Wn, L1|L2 }, /* vshuff{32x4,64x2} */
    { { 0x25 }, 3, T, R, pfx_66, Wn, Ln }, /* vpternlog{d,q} */
    { { 0x26 }, 3, T, R, pfx_no, W0, Ln }, /* vgetmantph */
    { { 0x26 }, 3, T, R, pfx_66, Wn, Ln }, /* vgetmantp{s,d} */
    { { 0x27 }, 3, T, R, pfx_no, W0, LIG }, /* vgetmantsh */
    { { 0x27 }, 3, T, R, pfx_66, Wn, LIG }, /* vgetmants{s,d} */
    { { 0x38 }, 3, T, R, pfx_66, Wn, L1|L2 }, /* vinserti{32x4,64x2} */
    { { 0x39 }, 3, T, W, pfx_66, Wn, L1|L2 }, /* vextracti{32x4,64x2} */
    { { 0x3a }, 3, T, R, pfx_66, Wn, L2 }, /* vinserti{32x8,64x4} */
    { { 0x3b }, 3, T, W, pfx_66, Wn, L2 }, /* vextracti{32x8,64x4} */
    { { 0x3e }, 3, T, R, pfx_66, Wn, Ln }, /* vpcmpu{b,w} */
    { { 0x3f }, 3, T, R, pfx_66, Wn, Ln }, /* vpcmp{b,w} */
    { { 0x42 }, 3, T, R, pfx_66, W0, Ln }, /* vdbpsadbw */
    { { 0x43 }, 3, T, R, pfx_66, Wn, L1|L2 }, /* vshufi{32x4,64x2} */
    { { 0x44 }, 3, T, R, pfx_66, WIG, Ln }, /* vpclmulqdq */
    { { 0x50 }, 3, T, R, pfx_66, Wn, Ln }, /* vrangep{s,d} */
    { { 0x51 }, 3, T, R, pfx_66, Wn, LIG }, /* vranges{s,d} */
    { { 0x54 }, 3, T, R, pfx_66, Wn, Ln }, /* vfixupimmp{s,d} */
    { { 0x55 }, 3, T, R, pfx_66, Wn, LIG }, /* vfixumpimms{s,d} */
    { { 0x56 }, 3, T, R, pfx_no, W0, Ln }, /* vreduceph */
    { { 0x56 }, 3, T, R, pfx_66, Wn, Ln }, /* vreducep{s,d} */
    { { 0x57 }, 3, T, R, pfx_no, W0, LIG }, /* vreducesh */
    { { 0x57 }, 3, T, R, pfx_66, Wn, LIG }, /* vreduces{s,d} */
    { { 0x66 }, 3, T, R, pfx_no, W0, Ln }, /* vfpclassph */
    { { 0x66 }, 3, T, R, pfx_66, Wn, Ln }, /* vfpclassp{s,d} */
    { { 0x67 }, 3, T, R, pfx_no, W0, LIG }, /* vfpclasssh */
    { { 0x67 }, 3, T, R, pfx_66, Wn, LIG }, /* vfpclasss{s,d} */
    { { 0x70 }, 3, T, R, pfx_66, W1, Ln }, /* vshldw */
    { { 0x71 }, 3, T, R, pfx_66, Wn, Ln }, /* vshld{d,q} */
    { { 0x72 }, 3, T, R, pfx_66, W1, Ln }, /* vshrdw */
    { { 0x73 }, 3, T, R, pfx_66, Wn, Ln }, /* vshrd{d,q} */
    { { 0xc2 }, 3, T, R, pfx_no, W0, Ln }, /* vcmpph */
    { { 0xc2 }, 3, T, R, pfx_f3, W0, LIG }, /* vcmpsh */
    { { 0xce }, 3, T, R, pfx_66, W1, Ln }, /* vgf2p8affineqb */
    { { 0xcf }, 3, T, R, pfx_66, W1, Ln }, /* vgf2p8affineinvqb */
}, evex_map5[] = {
    { { 0x10 }, 2, T, R, pfx_f3, W0, LIG }, /* vmovsh */
    { { 0x11 }, 2, T, W, pfx_f3, W0, LIG }, /* vmovsh */
    { { 0x1d }, 2, T, R, pfx_66, W0, Ln }, /* vcvtps2phx */
    { { 0x1d }, 2, T, R, pfx_no, W0, LIG }, /* vcvtss2sh */
    { { 0x2a }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtsi2sh */
    { { 0x2c }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvttsh2si */
    { { 0x2d }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtsh2si */
    { { 0x2e }, 2, T, R, pfx_no, W0, LIG }, /* vucomish */
    { { 0x2f }, 2, T, R, pfx_no, W0, LIG }, /* vcomish */
    { { 0x51 }, 2, T, R, pfx_no, W0, Ln }, /* vsqrtph */
    { { 0x51 }, 2, T, R, pfx_f3, W0, LIG }, /* vsqrtsh */
    { { 0x58 }, 2, T, R, pfx_no, W0, Ln }, /* vaddph */
    { { 0x58 }, 2, T, R, pfx_f3, W0, LIG }, /* vaddsh */
    { { 0x59 }, 2, T, R, pfx_no, W0, Ln }, /* vmulph */
    { { 0x59 }, 2, T, R, pfx_f3, W0, LIG }, /* vmulsh */
    { { 0x5a }, 2, T, R, pfx_no, W0, Ln }, /* vcvtph2pd */
    { { 0x5a }, 2, T, R, pfx_66, W1, Ln }, /* vcvtpd2ph */
    { { 0x5a }, 2, T, R, pfx_f3, W0, LIG }, /* vcvtsh2sd */
    { { 0x5a }, 2, T, R, pfx_f2, W1, LIG }, /* vcvtsd2sh */
    { { 0x5b }, 2, T, R, pfx_no, W0, Ln }, /* vcvtdq2ph */
    { { 0x5b }, 2, T, R, pfx_no, W1, Ln }, /* vcvtqq2ph */
    { { 0x5b }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2dq */
    { { 0x5b }, 2, T, R, pfx_f3, W0, Ln }, /* vcvttph2dq */
    { { 0x5c }, 2, T, R, pfx_no, W0, Ln }, /* vsubph */
    { { 0x5c }, 2, T, R, pfx_f3, W0, LIG }, /* vsubsh */
    { { 0x5d }, 2, T, R, pfx_no, W0, Ln }, /* vminph */
    { { 0x5d }, 2, T, R, pfx_f3, W0, LIG }, /* vminsh */
    { { 0x5e }, 2, T, R, pfx_no, W0, Ln }, /* vdivph */
    { { 0x5e }, 2, T, R, pfx_f3, W0, LIG }, /* vdivsh */
    { { 0x5f }, 2, T, R, pfx_no, W0, Ln }, /* vmaxph */
    { { 0x5f }, 2, T, R, pfx_f3, W0, LIG }, /* vmaxsh */
    { { 0x6e }, 2, T, R, pfx_66, WIG, L0 }, /* vmovw */
    { { 0x78 }, 2, T, R, pfx_no, W0, Ln }, /* vcvttph2udq */
    { { 0x78 }, 2, T, R, pfx_66, W0, Ln }, /* vcvttph2uqq */
    { { 0x78 }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvttsh2usi */
    { { 0x79 }, 2, T, R, pfx_no, W0, Ln }, /* vcvtph2udq */
    { { 0x79 }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2uqq */
    { { 0x79 }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtsh2usi */
    { { 0x7a }, 2, T, R, pfx_66, W0, Ln }, /* vcvttph2qq */
    { { 0x7a }, 2, T, R, pfx_f2, W0, Ln }, /* vcvtudq2ph */
    { { 0x7a }, 2, T, R, pfx_f2, W1, Ln }, /* vcvtuqq2ph */
    { { 0x7b }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2qq */
    { { 0x7b }, 2, T, R, pfx_f3, Wn, LIG }, /* vcvtusi2sh */
    { { 0x7c }, 2, T, R, pfx_no, W0, Ln }, /* vcvttph2uw */
    { { 0x7c }, 2, T, R, pfx_66, W0, Ln }, /* vcvttph2w */
    { { 0x7d }, 2, T, R, pfx_no, W0, Ln }, /* vcvtph2uw */
    { { 0x7d }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2w */
    { { 0x7d }, 2, T, R, pfx_f3, W0, Ln }, /* vcvtw2ph */
    { { 0x7d }, 2, T, R, pfx_f2, W0, Ln }, /* vcvtuwph */
    { { 0x7e }, 2, T, W, pfx_66, WIG, L0 }, /* vmovw */
}, evex_map6[] = {
    { { 0x13 }, 2, T, R, pfx_66, W0, Ln }, /* vcvtph2psx */
    { { 0x13 }, 2, T, R, pfx_no, W0, LIG }, /* vcvtsh2ss */
    { { 0x2c }, 2, T, R, pfx_66, W0, Ln }, /* vscalefph */
    { { 0x2d }, 2, T, R, pfx_66, W0, LIG }, /* vscalefsh */
    { { 0x42 }, 2, T, R, pfx_66, W0, Ln }, /* vgetexpph */
    { { 0x43 }, 2, T, R, pfx_66, W0, LIG }, /* vgetexpsh */
    { { 0x4c }, 2, T, R, pfx_66, W0, Ln }, /* vrcpph */
    { { 0x4d }, 2, T, R, pfx_66, W0, LIG }, /* vrcpsh */
    { { 0x4e }, 2, T, R, pfx_66, W0, Ln }, /* vrsqrtph */
    { { 0x4f }, 2, T, R, pfx_66, W0, LIG }, /* vrsqrtsh */
    { { 0x56 }, 2, T, R, pfx_f3, W0, Ln }, /* vfmaddcph */
    { { 0x56 }, 2, T, R, pfx_f2, W0, Ln }, /* vfcmaddcph */
    { { 0x57 }, 2, T, R, pfx_f3, W0, LIG }, /* vfmaddcsh */
    { { 0x57 }, 2, T, R, pfx_f2, W0, LIG }, /* vfcmaddcsh */
    { { 0x96 }, 2, T, R, pfx_66, W0, Ln }, /* vfmaddsub132ph */
    { { 0x97 }, 2, T, R, pfx_66, W0, Ln }, /* vfmsubadd132ph */
    { { 0x98 }, 2, T, R, pfx_66, W0, Ln }, /* vfmadd132ph */
    { { 0x99 }, 2, T, R, pfx_66, W0, LIG }, /* vfmadd132sh */
    { { 0x9a }, 2, T, R, pfx_66, W0, Ln }, /* vfmsub132ph */
    { { 0x9b }, 2, T, R, pfx_66, W0, LIG }, /* vfmsub132sh */
    { { 0x9c }, 2, T, R, pfx_66, W0, Ln }, /* vfnmadd132ph */
    { { 0x9d }, 2, T, R, pfx_66, W0, LIG }, /* vfnmadd132sh */
    { { 0x9e }, 2, T, R, pfx_66, W0, Ln }, /* vfnmsub132ph */
    { { 0x9f }, 2, T, R, pfx_66, W0, LIG }, /* vfnmsub132sh */
    { { 0xa6 }, 2, T, R, pfx_66, W0, Ln }, /* vfmaddsub213ph */
    { { 0xa7 }, 2, T, R, pfx_66, W0, Ln }, /* vfmsubadd213ph */
    { { 0xa8 }, 2, T, R, pfx_66, W0, Ln }, /* vfmadd213ph */
    { { 0xa9 }, 2, T, R, pfx_66, W0, LIG }, /* vfmadd213sh */
    { { 0xaa }, 2, T, R, pfx_66, W0, Ln }, /* vfmsub213ph */
    { { 0xab }, 2, T, R, pfx_66, W0, LIG }, /* vfmsub213sh */
    { { 0xac }, 2, T, R, pfx_66, W0, Ln }, /* vfnmadd213ph */
    { { 0xad }, 2, T, R, pfx_66, W0, LIG }, /* vfnmadd213sh */
    { { 0xae }, 2, T, R, pfx_66, W0, Ln }, /* vfnmsub213ph */
    { { 0xaf }, 2, T, R, pfx_66, W0, LIG }, /* vfnmsub213sh */
    { { 0xb6 }, 2, T, R, pfx_66, W0, Ln }, /* vfmaddsub231ph */
    { { 0xb7 }, 2, T, R, pfx_66, W0, Ln }, /* vfmsubadd231ph */
    { { 0xb8 }, 2, T, R, pfx_66, W0, Ln }, /* vfmadd231ph */
    { { 0xb9 }, 2, T, R, pfx_66, W0, LIG }, /* vfmadd231sh */
    { { 0xba }, 2, T, R, pfx_66, W0, Ln }, /* vfmsub231ph */
    { { 0xbb }, 2, T, R, pfx_66, W0, LIG }, /* vfmsub231sh */
    { { 0xbc }, 2, T, R, pfx_66, W0, Ln }, /* vfnmadd231ph */
    { { 0xbd }, 2, T, R, pfx_66, W0, LIG }, /* vfnmadd231sh */
    { { 0xbe }, 2, T, R, pfx_66, W0, Ln }, /* vfnmsub231ph */
    { { 0xbf }, 2, T, R, pfx_66, W0, LIG }, /* vfnmsub231sh */
    { { 0xd6 }, 2, T, R, pfx_f3, W0, Ln }, /* vfmulcph */
    { { 0xd6 }, 2, T, R, pfx_f2, W0, Ln }, /* vfcmulcph */
    { { 0xd7 }, 2, T, R, pfx_f3, W0, LIG }, /* vfmulcsh */
    { { 0xd7 }, 2, T, R, pfx_f2, W0, LIG }, /* vfcmulcsh */
};

static const struct {
    const struct evex *tbl;
    unsigned int num;
} evex[] = {
    { evex_0f,   ARRAY_SIZE(evex_0f) },
    { evex_0f38, ARRAY_SIZE(evex_0f38) },
    { evex_0f3a, ARRAY_SIZE(evex_0f3a) },
    { NULL,      0 },
    { evex_map5, ARRAY_SIZE(evex_map5) },
    { evex_map6, ARRAY_SIZE(evex_map6) },
};

#undef Wn

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
             int (*fetch)(unsigned long offset,
                          void *p_data,
                          unsigned int bytes,
                          struct x86_emulate_ctxt *ctxt))
{
    struct x86_emulate_state *s = x86_decode_insn(ctxt, fetch);

    if ( !s )
    {
        print_insn(instr, len);
        printf(" failed to decode\n");
        return;
    }

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

    if ( modrm )
    {
        instr[modrm] |= 0xc0;

        s = x86_decode_insn(ctxt, fetch);

        if ( !s )
        {
            print_insn(instr, len);
            printf(" failed to decode\n");
            return;
        }

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
                     int (*fetch)(unsigned long offset,
                                  void *p_data,
                                  unsigned int bytes,
                                  struct x86_emulate_ctxt *ctxt))
{
    unsigned int m;

    ctxt->regs->eip = (unsigned long)instr;

    for ( m = 0; m < sizeof(long) / sizeof(int); ++m )
    {
        unsigned int t, x;

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

        for ( t = 0; t < ARRAY_SIZE(vex_0f); ++t )
        {
            if ( vex_0f[t].w == WIG || (vex_0f[t].w & W0) )
            {
                uint8_t *ptr = instr;

                memset(instr + 3, 0xcc, 12);

                *ptr++ = 0xc5;
                *ptr++ = 0xf8 | vex_0f[t].pfx;
                memcpy(ptr, vex_0f[t].opc, vex_0f[t].len);

                if ( vex_0f[t].l == LIG || (vex_0f[t].l & L0) )
                    do_test(instr, vex_0f[t].len + ((void *)ptr - instr),
                            vex_0f[t].modrm ? (void *)ptr - instr + 1 : 0,
                            vex_0f[t].mem, ctxt, fetch);

                if ( vex_0f[t].l == LIG || (vex_0f[t].l & L1) )
                {
                    ptr[-1] |= 4;
                    memcpy(ptr, vex_0f[t].opc, vex_0f[t].len);

                    do_test(instr, vex_0f[t].len + ((void *)ptr - instr),
                            vex_0f[t].modrm ? (void *)ptr - instr + 1 : 0,
                            vex_0f[t].mem, ctxt, fetch);
                }
            }
        }

        for ( x = 0; x < ARRAY_SIZE(vex); ++x )
        {
            for ( t = 0; t < vex[x].num; ++t )
            {
                uint8_t *ptr = instr;

                memset(instr + 4, 0xcc, 11);

                *ptr++ = 0xc4;
                *ptr++ = 0xe1 + x;
                *ptr++ = 0x78 | vex[x].tbl[t].pfx;

                if ( vex[x].tbl[t].w == WIG || (vex[x].tbl[t].w & W0) )
                {
                    memcpy(ptr, vex[x].tbl[t].opc, vex[x].tbl[t].len);

                    if ( vex[x].tbl[t].l == LIG || (vex[x].tbl[t].l & L0) )
                        do_test(instr, vex[x].tbl[t].len + ((void *)ptr - instr),
                                vex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                vex[x].tbl[t].mem, ctxt, fetch);

                    if ( vex[x].tbl[t].l == LIG || (vex[x].tbl[t].l & L1) )
                    {
                        ptr[-1] |= 4;
                        memcpy(ptr, vex[x].tbl[t].opc, vex[x].tbl[t].len);

                        do_test(instr, vex[x].tbl[t].len + ((void *)ptr - instr),
                                vex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                vex[x].tbl[t].mem, ctxt, fetch);
                    }
                }

                if ( vex[x].tbl[t].w == WIG || (vex[x].tbl[t].w & W1) )
                {
                    ptr[-1] = 0xf8 | vex[x].tbl[t].pfx;
                    memcpy(ptr, vex[x].tbl[t].opc, vex[x].tbl[t].len);

                    if ( vex[x].tbl[t].l == LIG || (vex[x].tbl[t].l & L0) )
                        do_test(instr, vex[x].tbl[t].len + ((void *)ptr - instr),
                                vex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                vex[x].tbl[t].mem, ctxt, fetch);

                    if ( vex[x].tbl[t].l == LIG || (vex[x].tbl[t].l & L1) )
                    {
                        ptr[-1] |= 4;
                        memcpy(ptr, vex[x].tbl[t].opc, vex[x].tbl[t].len);

                        do_test(instr, vex[x].tbl[t].len + ((void *)ptr - instr),
                                vex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                vex[x].tbl[t].mem, ctxt, fetch);
                    }
                }
            }
        }

        for ( x = 0; x < ARRAY_SIZE(xop); ++x )
        {
            for ( t = 0; t < xop[x].num; ++t )
            {
                uint8_t *ptr = instr;
                unsigned int modrm;
                enum mem_access mem;

                memset(instr + 5, 0xcc, 10);

                *ptr++ = 0x8f;
                *ptr++ = 0xe8 + x;
                *ptr++ = 0x78;
                memcpy(ptr, xop[x].tbl[t].opc, 2);
                memset(ptr + 2, 0, xop[x].imm);

                modrm = ptr[1] & 0xc0 ? 0 : 4;
                mem = ptr[1] & 0xc0 ? mem_none : mem_read;

                assert(xop[x].tbl[t].w != WIG);
                assert(xop[x].tbl[t].l != LIG);

                if ( xop[x].tbl[t].w & W0 )
                {
                    if ( xop[x].tbl[t].l & L0 )
                        do_test(instr, 5 + xop[x].imm, modrm, mem, ctxt, fetch);

                    if ( xop[x].tbl[t].l & L1 )
                    {
                        ptr[-1] = 0x7c;
                        ptr[1] = mem != mem_none ? 0x00 : 0xc0;

                        do_test(instr, 5 + xop[x].imm, modrm, mem, ctxt, fetch);
                    }
                }

                if ( xop[x].tbl[t].w & W1 )
                {
                    if ( xop[x].tbl[t].l & L0 )
                    {
                        ptr[-1] = 0xf8;
                        ptr[1] = mem != mem_none ? 0x00 : 0xc0;

                        do_test(instr, 5 + xop[x].imm, modrm, mem, ctxt, fetch);
                    }

                    if ( xop[x].tbl[t].l & L1 )
                    {
                        ptr[-1] = 0xfc;
                        ptr[1] = mem != mem_none ? 0x00 : 0xc0;

                        do_test(instr, 5 + xop[x].imm, modrm, mem, ctxt, fetch);
                    }
                }
            }
        }

        for ( x = 0; x < ARRAY_SIZE(evex); ++x )
        {
            for ( t = 0; t < evex[x].num; ++t )
            {
                uint8_t *ptr = instr;
                unsigned int l;

                memset(instr + 5, 0xcc, 10);

                *ptr++ = 0x62;
                *ptr++ = 0xf1 + x;
                *ptr++ = 0x7c | evex[x].tbl[t].pfx;
                *ptr++ = 0x08 | evex[x].tbl[t].mask;

                for ( l = 3; l--; )
                {
                    if ( evex[x].tbl[t].l != LIG && !(evex[x].tbl[t].l & (1u << l)) )
                        continue;

                    ptr[-1] &= ~0x60;
                    ptr[-1] |= l << 5;
                    memcpy(ptr, evex[x].tbl[t].opc, evex[x].tbl[t].len);

                    if ( evex[x].tbl[t].w == WIG || (evex[x].tbl[t].w & W0) )
                    {
                        ptr[-2] &= ~0x80;
                        do_test(instr, evex[x].tbl[t].len + ((void *)ptr - instr),
                                evex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                evex[x].tbl[t].mem, ctxt, fetch);
                    }

                    if ( evex[x].tbl[t].w == WIG || (evex[x].tbl[t].w & W1) )
                    {
                        ptr[-2] |= 0x80;
                        memcpy(ptr, evex[x].tbl[t].opc, evex[x].tbl[t].len);

                        do_test(instr, evex[x].tbl[t].len + ((void *)ptr - instr),
                                evex[x].tbl[t].modrm ? (void *)ptr - instr + 1 : 0,
                                evex[x].tbl[t].mem, ctxt, fetch);
                    }
                }
            }
        }

        if ( errors )
            exit(1);

        puts(" okay");
    }
}
