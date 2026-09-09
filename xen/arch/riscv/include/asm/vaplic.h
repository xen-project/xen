/* SPDX-License-Identifier: MIT */
/*
 * xen/arch/riscv/vaplic.c
 *
 * Virtual RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) Microchip.
 */

#ifndef ASM__RISCV__VAPLIC_H
#define ASM__RISCV__VAPLIC_H

#include <xen/kernel.h>
#include <xen/types.h>

#include <asm/intc.h>

struct domain;

#define to_vaplic(d) container_of((d)->arch.vintc, struct vaplic, vintc)

struct vaplic_regs {
    uint32_t domaincfg;
};

struct vaplic {
    struct vintc vintc;
    struct vaplic_regs regs;
};

int domain_vaplic_init(struct domain *d);
void domain_vaplic_deinit(struct domain *d);

#endif /* ASM__RISCV__VAPLIC_H */
