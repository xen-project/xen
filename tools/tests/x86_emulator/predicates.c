#include "x86-emulate.h"

#include <stdio.h>

enum mem_access { mem_none, mem_read, mem_write };
enum pfx { pfx_none, pfx_66, pfx_f3, pfx_f2 };
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
    unsigned int mem:2;
    unsigned int pfx:2;
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
    { { 0x01, 0xc0 }, { 2, 2 }, T, N }, /* enclv */
    { { 0x01, 0xc1 }, { 2, 2 }, T, N }, /* vmcall */
    /*{ 0x01, 0xc2 }, { 2, 2 }, F, R }, vmlaunch */
    /*{ 0x01, 0xc3 }, { 2, 2 }, F, R }, vmresume */
    { { 0x01, 0xc4 }, { 2, 2 }, T, N }, /* vmxoff */
    { { 0x01, 0xc5 }, { 2, 2 }, T, N }, /* pconfig */
    { { 0x01, 0xc8 }, { 2, 2 }, T, N }, /* monitor */
    { { 0x01, 0xc9 }, { 2, 2 }, T, N }, /* mwait */
    { { 0x01, 0xca }, { 2, 2 }, T, N }, /* clac */
    { { 0x01, 0xcb }, { 2, 2 }, T, N }, /* stac */
    { { 0x01, 0xcf }, { 2, 2 }, T, N }, /* encls */
    { { 0x01, 0xd0 }, { 2, 2 }, T, N }, /* xgetbv */
    { { 0x01, 0xd1 }, { 2, 2 }, T, N }, /* xsetbv */
    { { 0x01, 0xd4 }, { 2, 2 }, T, N }, /* vmfunc */
    { { 0x01, 0xd5 }, { 2, 2 }, T, N }, /* xend */
    { { 0x01, 0xd6 }, { 2, 2 }, T, N }, /* xtest */
    { { 0x01, 0xd7 }, { 2, 2 }, T, N }, /* enclu */
    /*{ 0x01, 0xd8 }, { 2, 2 }, F, R }, vmrun */
    { { 0x01, 0xd9 }, { 2, 2 }, T, N }, /* vmcall */
    { { 0x01, 0xd9 }, { 2, 2 }, T, N, pfx_f3 }, /* vmgexit */
    { { 0x01, 0xd9 }, { 2, 2 }, T, N, pfx_f2 }, /* vmgexit */
    /*{ 0x01, 0xda }, { 2, 2 }, F, R }, vmload */
    /*{ 0x01, 0xdb }, { 2, 2 }, F, W }, vmsave */
    { { 0x01, 0xdc }, { 2, 2 }, T, N }, /* stgi */
    { { 0x01, 0xdd }, { 2, 2 }, T, N }, /* clgi */
    /*{ 0x01, 0xde }, { 2, 2 }, F, R }, skinit */
    { { 0x01, 0xdf }, { 2, 2 }, T, N }, /* invlpga */
    { { 0x01, 0xe8 }, { 2, 2 }, T, N }, /* serialize */
    /*{ 0x01, 0xe8 }, { 2, 2 }, F, W, pfx_f3 }, setssbsy */
    { { 0x01, 0xe8 }, { 2, 2 }, T, N, pfx_f2 }, /* xsusldtrk */
    { { 0x01, 0xe9 }, { 2, 2 }, T, N, pfx_f2 }, /* xresldtrk */
    /*{ 0x01, 0xea }, { 2, 2 }, F, W, pfx_f3 }, saveprevssp */
    { { 0x01, 0xee }, { 2, 2 }, T, N }, /* rdpkru */
    { { 0x01, 0xef }, { 2, 2 }, T, N }, /* wrpkru */
    { { 0x01, 0xf8 }, { 0, 2 }, T, N }, /* swapgs */
    { { 0x01, 0xf9 }, { 2, 2 }, T, N }, /* rdtscp */
    { { 0x01, 0xfa }, { 2, 2 }, T, N }, /* monitorx */
    { { 0x01, 0xfa }, { 2, 2 }, T, N, pfx_f3 }, /* mcommit */
    { { 0x01, 0xfb }, { 2, 2 }, T, N }, /* mwaitx */
    { { 0x01, 0xfc }, { 2, 2 }, F, W }, /* clzero */
    { { 0x01, 0xfd }, { 2, 2 }, T, N }, /* rdpru */
    { { 0x01, 0xfe }, { 2, 2 }, T, N }, /* invlpgb */
    { { 0x01, 0xfe }, { 0, 2 }, T, N, pfx_f3 }, /* rmpadjust */
    { { 0x01, 0xfe }, { 0, 2 }, T, N, pfx_f2 }, /* rmpupdate */
    { { 0x01, 0xff }, { 2, 2 }, T, N }, /* tlbsync */
    { { 0x01, 0xff }, { 0, 2 }, T, N, pfx_f3 }, /* psmash */
    { { 0x01, 0xff }, { 0, 2 }, T, N, pfx_f2 }, /* pvalidate */
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
    { { 0x30 }, { 1, 1 }, F, N }, /* wrmsr */
    { { 0x31 }, { 1, 1 }, F, N }, /* rdtsc */
    { { 0x32 }, { 1, 1 }, F, N }, /* rdmsr */
    { { 0x33 }, { 1, 1 }, F, N }, /* rdpmc */
    { { 0x34 }, { 1, 1 }, F, N }, /* sysenter */
    { { 0x35 }, { 1, 1 }, F, N }, /* sysexit */
    CND(0x40,   { 2, 2 }, T, R ), /* cmov<cc> */
    /*{ 0x78 }, { 2, 2 }, T, W }, vmread */
    { { 0x79 }, { 2, 2 }, T, R }, /* vmwrite */
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
    { { 0xc3 }, { 2, 2 }, F, W }, /* movnti */
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
    { { 0xff }, { 2, 2 }, F, N }, /* ud0 */
}, legacy_0f38[] = {
    { { 0x80 }, { 2, 2 }, T, R, pfx_66 }, /* invept */
    { { 0x81 }, { 2, 2 }, T, R, pfx_66 }, /* invvpid */
    { { 0x82 }, { 2, 2 }, T, R, pfx_66 }, /* invpcid */
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

        if ( errors )
            exit(1);

        puts(" okay");
    }
}
