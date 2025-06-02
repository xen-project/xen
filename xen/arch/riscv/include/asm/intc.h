/* SPDX-License-Identifier: MIT */

/*
 * (c) 2023-2024 Microchip Technology Inc.
 * (c) 2024 Vates
 */

#ifndef ASM__RISCV__INTERRUPT_CONTOLLER_H
#define ASM__RISCV__INTERRUPT_CONTOLLER_H

struct dt_device_node;

enum intc_version {
    INTC_APLIC,
};

struct intc_info {
    enum intc_version hw_version;
    const struct dt_device_node *node;
};

void intc_preinit(void);

#endif /* ASM__RISCV__INTERRUPT_CONTOLLER_H */
