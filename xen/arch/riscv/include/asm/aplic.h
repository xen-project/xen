/* SPDX-License-Identifier: MIT */

/*
 * xen/arch/riscv/asm/include/aplic.h
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) Microchip.
 */

#ifndef ASM_RISCV_APLIC_H
#define ASM_RISCV_APLIC_H

#include <xen/types.h>

#include <asm/imsic.h>

#define APLIC_DOMAINCFG_IE      BIT(8, U)
#define APLIC_DOMAINCFG_DM      BIT(2, U)

#define APLIC_SOURCECFG_SM_INACTIVE     0x0
#define APLIC_SOURCECFG_SM_DETACH       0x1
#define APLIC_SOURCECFG_SM_EDGE_RISE    0x4
#define APLIC_SOURCECFG_SM_EDGE_FALL    0x5
#define APLIC_SOURCECFG_SM_LEVEL_HIGH   0x6
#define APLIC_SOURCECFG_SM_LEVEL_LOW    0x7

#define APLIC_TARGET_HART_IDX_SHIFT 18

struct aplic_regs {
    uint32_t domaincfg;         /* 0x0000 */
    uint32_t sourcecfg[1023];   /* 0x0004 */
    uint8_t _reserved1[3008];   /* 0x1000 */

    uint32_t mmsiaddrcfg;       /* 0x1BC0 */
    uint32_t mmsiaddrcfgh;      /* 0x1BC4 */
    uint32_t smsiaddrcfg;       /* 0x1BC8 */
    uint32_t smsiaddrcfgh;      /* 0x1BCC */
    uint8_t _reserved2[48];     /* 0x1BD0 */

    uint32_t setip[32];         /* 0x1C00 */
    uint8_t _reserved3[92];     /* 0x1C80 */

    uint32_t setipnum;          /* 0x1CDC */
    uint8_t _reserved4[32];     /* 0x1CE0 */

    uint32_t in_clrip[32];      /* 0x1D00 */
    uint8_t _reserved5[92];     /* 0x1D80 */

    uint32_t clripnum;          /* 0x1DDC */
    uint8_t _reserved6[32];     /* 0x1DE0 */

    uint32_t setie[32];         /* 0x1E00 */
    uint8_t _reserved7[92];     /* 0x1E80 */

    uint32_t setienum;          /* 0x1EDC */
    uint8_t _reserved8[32];     /* 0x1EE0 */

    uint32_t clrie[32];         /* 0x1F00 */
    uint8_t _reserved9[92];     /* 0x1F80 */

    uint32_t clrienum;          /* 0x1FDC */
    uint8_t _reserved10[32];    /* 0x1FF0 */

    uint32_t setipnum_le;       /* 0x2000 */
    uint32_t setipnum_be;       /* 0x2004 */
    uint8_t _reserved11[4088];  /* 0x2008 */

    uint32_t genmsi;            /* 0x3000 */
    uint32_t target[1023];      /* 0x3008 */
};

#endif /* ASM_RISCV_APLIC_H */
