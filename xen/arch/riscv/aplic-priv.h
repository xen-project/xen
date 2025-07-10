/* SPDX-License-Identifier: MIT */

/*
 * xen/arch/riscv/aplic-priv.h
 *
 * Private part of aplic.h header.
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) Microchip.
 * Copyright (c) Vates.
 */

#ifndef ASM_RISCV_APLIC_PRIV_H
#define ASM_RISCV_APLIC_PRIV_H

#include <xen/types.h>

#include <asm/aplic.h>

struct aplic_priv {
    /* Base physical address and size */
    paddr_t paddr_start;
    size_t  size;

    /* Registers */
    volatile struct aplic_regs __iomem *regs;

    /* IMSIC configuration */
    const struct imsic_config *imsic_cfg;
};

#endif /* ASM_RISCV_APLIC_PRIV_H */
