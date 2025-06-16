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

struct irq_desc;

struct intc_info {
    enum intc_version hw_version;
    const struct dt_device_node *node;
};

struct intc_hw_operations {
    /* Hold intc hw information */
    const struct intc_info *info;
    /* Initialize the intc and the boot CPU */
    int (*init)(void);

    /* hw_irq_controller to enable/disable/eoi host irq */
    const struct hw_interrupt_type *host_irq_type;

    /* Set IRQ type */
    void (*set_irq_type)(struct irq_desc *desc, unsigned int type);
    /* Set IRQ priority */
    void (*set_irq_priority)(struct irq_desc *desc, unsigned int priority);
};

void intc_preinit(void);

void register_intc_ops(const struct intc_hw_operations *ops);

#endif /* ASM__RISCV__INTERRUPT_CONTOLLER_H */
