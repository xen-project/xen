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

#include <xen/spinlock.h>
#include <xen/types.h>

#include <asm/aplic.h>

struct aplic_priv {
    /* Base physical address and size */
    paddr_t paddr_start;
    size_t  size;

    /* Registers */
    volatile struct aplic_regs __iomem *regs;

    /* Lock to protect access to APLIC's registers */
    spinlock_t lock;

    /* IMSIC configuration */
    const struct imsic_config *imsic_cfg;
};

/*
 * Value is inspired by what QEMU is using for riscv,num-sources property for
 * APLIC node.
 */
#define GUEST_APLIC_MAX_SOURCES 96U

/*
 * Specifies the number of interrupt sources supported by guest APLIC domain.
 * Could be limited by host interrupt controller and is identical for every
 * domain for now.
 */
extern unsigned int guest_aplic_num_sources;

#endif /* ASM_RISCV_APLIC_PRIV_H */
