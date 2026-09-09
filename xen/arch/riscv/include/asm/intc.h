/* SPDX-License-Identifier: MIT */

/*
 * (c) 2023-2024 Microchip Technology Inc.
 * (c) 2024 Vates
 */

#ifndef ASM__RISCV__INTERRUPT_CONTOLLER_H
#define ASM__RISCV__INTERRUPT_CONTOLLER_H

struct dt_device_node;

enum intc_variant {
    INTC_APLIC,
};

struct cpu_user_regs;
struct irq_desc;
struct kernel_info;
struct vcpu;

struct intc_info {
    enum intc_variant hw_variant;
    const struct dt_device_node *node;

    /* number of irqs */
    unsigned int num_irqs;
};

struct intc_hw_operations {
    /* Hold intc hw information */
    const struct intc_info *info;

    /* hw_irq_controller to enable/disable/eoi host irq */
    const struct hw_interrupt_type *host_irq_type;

    /* Set IRQ type */
    void (*set_irq_type)(struct irq_desc *desc, unsigned int type);
    /* Set IRQ priority */
    void (*set_irq_priority)(struct irq_desc *desc, unsigned int priority);

    /* handle external interrupt */
    void (*handle_interrupt)(struct cpu_user_regs *regs);
};

struct intc_hw_init_ops {
    const struct intc_hw_operations *ops;
    /* Initialize the intc and the boot CPU */
    int (*init)(void);
};

struct vintc_init_ops {
    /* Create interrupt controller node for domain */
    int (*make_domu_dt_node)(struct kernel_info *kinfo);
};

struct vintc_ops {
    /* Initialize some vINTC-related stuff for a vCPU */
    int (*vcpu_init)(struct vcpu *v);

    /* Deinitialize some vINTC-related stuff for a vCPU */
    void (*vcpu_deinit)(struct vcpu *v);
};

struct vintc {
    /* Callbacks invoked during domain construction only. */
    const struct vintc_init_ops *init_ops;
    /* Runtime callbacks used for the lifetime of the guest. */
    const struct vintc_ops *ops;
};

void intc_preinit(void);

void register_intc_ops(const struct intc_hw_init_ops *init_ops);

void intc_init(void);

void intc_route_irq_to_xen(struct irq_desc *desc, unsigned int priority);

void intc_handle_external_irqs(struct cpu_user_regs *regs);

#endif /* ASM__RISCV__INTERRUPT_CONTOLLER_H */
