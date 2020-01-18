/*
 * ARM Generic Interrupt Controller support
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_GIC_H__
#define __ASM_ARM_GIC_H__

#define NR_GIC_LOCAL_IRQS  NR_LOCAL_IRQS
#define NR_GIC_SGI         16

#define GICD_CTLR       (0x000)
#define GICD_TYPER      (0x004)
#define GICD_IIDR       (0x008)
#define GICD_IGROUPR    (0x080)
#define GICD_IGROUPRN   (0x0FC)
#define GICD_ISENABLER  (0x100)
#define GICD_ISENABLERN (0x17C)
#define GICD_ICENABLER  (0x180)
#define GICD_ICENABLERN (0x1fC)
#define GICD_ISPENDR    (0x200)
#define GICD_ISPENDRN   (0x27C)
#define GICD_ICPENDR    (0x280)
#define GICD_ICPENDRN   (0x2FC)
#define GICD_ISACTIVER  (0x300)
#define GICD_ISACTIVERN (0x37C)
#define GICD_ICACTIVER  (0x380)
#define GICD_ICACTIVERN (0x3FC)
#define GICD_IPRIORITYR (0x400)
#define GICD_IPRIORITYRN (0x7F8)
#define GICD_ITARGETSR  (0x800)
#define GICD_ITARGETSR7 (0x81C)
#define GICD_ITARGETSR8 (0x820)
#define GICD_ITARGETSRN (0xBF8)
#define GICD_ICFGR      (0xC00)
#define GICD_ICFGR1     (0xC04)
#define GICD_ICFGR2     (0xC08)
#define GICD_ICFGRN     (0xCFC)
#define GICD_NSACR      (0xE00)
#define GICD_NSACRN     (0xEFC)
#define GICD_SGIR       (0xF00)
#define GICD_CPENDSGIR  (0xF10)
#define GICD_CPENDSGIRN (0xF1C)
#define GICD_SPENDSGIR  (0xF20)
#define GICD_SPENDSGIRN (0xF2C)
#define GICD_ICPIDR2    (0xFE8)

#define GICD_SGI_TARGET_LIST_SHIFT   (24)
#define GICD_SGI_TARGET_LIST_MASK    (0x3UL << GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_LIST         (0UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_LIST_VAL     (0)
#define GICD_SGI_TARGET_OTHERS       (1UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_OTHERS_VAL   (1)
#define GICD_SGI_TARGET_SELF         (2UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_SELF_VAL     (2)
#define GICD_SGI_TARGET_SHIFT        (16)
#define GICD_SGI_TARGET_MASK         (0xFFUL<<GICD_SGI_TARGET_SHIFT)
#define GICD_SGI_GROUP1              (1UL<<15)
#define GICD_SGI_INTID_MASK          (0xFUL)

#define GICC_CTLR       (0x0000)
#define GICC_PMR        (0x0004)
#define GICC_BPR        (0x0008)
#define GICC_IAR        (0x000C)
#define GICC_EOIR       (0x0010)
#define GICC_RPR        (0x0014)
#define GICC_HPPIR      (0x0018)
#define GICC_APR        (0x00D0)
#define GICC_NSAPR      (0x00E0)
#define GICC_IIDR       (0x00FC)
#define GICC_DIR        (0x1000)

#define GICH_HCR        (0x00)
#define GICH_VTR        (0x04)
#define GICH_VMCR       (0x08)
#define GICH_MISR       (0x10)
#define GICH_EISR0      (0x20)
#define GICH_EISR1      (0x24)
#define GICH_ELSR0      (0x30)
#define GICH_ELSR1      (0x34)
#define GICH_APR        (0xF0)
#define GICH_LR         (0x100)

/* Register bits */
#define GICD_CTL_ENABLE 0x1

#define GICD_TYPE_LINES 0x01f
#define GICD_TYPE_CPUS_SHIFT 5
#define GICD_TYPE_CPUS  0x0e0
#define GICD_TYPE_SEC   0x400
#define GICD_TYPER_DVIS (1U << 18)

#define GICC_CTL_ENABLE 0x1
#define GICC_CTL_EOI    (0x1 << 9)

#define GICC_IA_IRQ       0x03ff
#define GICC_IA_CPU_MASK  0x1c00
#define GICC_IA_CPU_SHIFT 10

#define GICH_HCR_EN       (1 << 0)
#define GICH_HCR_UIE      (1 << 1)
#define GICH_HCR_LRENPIE  (1 << 2)
#define GICH_HCR_NPIE     (1 << 3)
#define GICH_HCR_VGRP0EIE (1 << 4)
#define GICH_HCR_VGRP0DIE (1 << 5)
#define GICH_HCR_VGRP1EIE (1 << 6)
#define GICH_HCR_VGRP1DIE (1 << 7)

#define GICH_MISR_EOI     (1 << 0)
#define GICH_MISR_U       (1 << 1)
#define GICH_MISR_LRENP   (1 << 2)
#define GICH_MISR_NP      (1 << 3)
#define GICH_MISR_VGRP0E  (1 << 4)
#define GICH_MISR_VGRP0D  (1 << 5)
#define GICH_MISR_VGRP1E  (1 << 6)
#define GICH_MISR_VGRP1D  (1 << 7)

/*
 * The minimum GICC_BPR is required to be in the range 0-3. We set
 * GICC_BPR to 0 but we must expect that it might be 3. This means we
 * can rely on premption between the following ranges:
 * 0xf0..0xff
 * 0xe0..0xdf
 * 0xc0..0xcf
 * 0xb0..0xbf
 * 0xa0..0xaf
 * 0x90..0x9f
 * 0x80..0x8f
 *
 * Priorities within a range will not preempt each other.
 *
 * A GIC must support a mimimum of 16 priority levels.
 */
#define GIC_PRI_LOWEST     0xf0
#define GIC_PRI_IRQ        0xa0
#define GIC_PRI_IPI        0x90 /* IPIs must preempt normal interrupts */
#define GIC_PRI_HIGHEST    0x80 /* Higher priorities belong to Secure-World */
#define GIC_PRI_TO_GUEST(pri) (pri >> 3) /* GICH_LR and GICH_VMCR only support
                                            5 bits for guest irq priority */

#define GICH_LR_PENDING         1
#define GICH_LR_ACTIVE          2

#ifndef __ASSEMBLY__
#include <xen/device_tree.h>
#include <xen/irq.h>

#define DT_COMPAT_GIC_CORTEX_A15 "arm,cortex-a15-gic"

#define DT_MATCH_GIC_V2                                             \
    DT_MATCH_COMPATIBLE(DT_COMPAT_GIC_CORTEX_A15),                  \
    DT_MATCH_COMPATIBLE("arm,cortex-a7-gic"),                       \
    DT_MATCH_COMPATIBLE("arm,gic-400")

#define DT_MATCH_GIC_V3 DT_MATCH_COMPATIBLE("arm,gic-v3")

#ifdef CONFIG_GICV3
/*
 * GICv3 registers that needs to be saved/restored
 */
struct gic_v3 {
    uint32_t hcr, vmcr, sre_el1;
    uint32_t apr0[4];
    uint32_t apr1[4];
    uint64_t lr[16];
};
#endif

/*
 * GICv2 register that needs to be saved/restored
 * on VCPU context switch
 */
struct gic_v2 {
    uint32_t hcr;
    uint32_t vmcr;
    uint32_t apr;
    uint32_t lr[64];
};

/*
 * Union to hold underlying hw version context information
 */
union gic_state_data {
    struct gic_v2 v2;
#ifdef CONFIG_GICV3
    struct gic_v3 v3;
#endif
};

/*
 * Decode LR register content.
 * The LR register format is different for GIC HW version
 */
struct gic_lr {
   /* Virtual IRQ */
   uint32_t virq;
   uint8_t priority;
   bool active;
   bool pending;
   bool hw_status;
   union
   {
       /* Only filled when there are a corresponding pIRQ (hw_state = true) */
       struct
       {
           uint32_t pirq;
       } hw;
       /* Only filled when there are no corresponding pIRQ (hw_state = false) */
       struct
       {
           bool eoi;
           uint8_t source;      /* GICv2 only */
       } virt;
   };
};

enum gic_version {
    GIC_INVALID = 0,    /* the default until explicitly set up */
    GIC_V2,
    GIC_V3,
};

DECLARE_PER_CPU(uint64_t, lr_mask);

extern enum gic_version gic_hw_version(void);

/* Program the IRQ type into the GIC */
void gic_set_irq_type(struct irq_desc *desc, unsigned int type);

/* Program the GIC to route an interrupt */
extern void gic_route_irq_to_xen(struct irq_desc *desc, unsigned int priority);
extern int gic_route_irq_to_guest(struct domain *, unsigned int virq,
                                  struct irq_desc *desc,
                                  unsigned int priority);

/* Remove an IRQ passthrough to a guest */
int gic_remove_irq_from_guest(struct domain *d, unsigned int virq,
                              struct irq_desc *desc);

extern void gic_clear_pending_irqs(struct vcpu *v);

extern void init_maintenance_interrupt(void);
extern void gic_raise_guest_irq(struct vcpu *v, unsigned int irq,
        unsigned int priority);
extern void gic_raise_inflight_irq(struct vcpu *v, unsigned int virtual_irq);

/* Accept an interrupt from the GIC and dispatch its handler */
extern void gic_interrupt(struct cpu_user_regs *regs, int is_fiq);
/* Find the interrupt controller and set up the callback to translate
 * device tree IRQ.
 */
extern void gic_preinit(void);
/* Bring up the interrupt controller, and report # cpus attached */
extern void gic_init(void);
/* Bring up a secondary CPU's per-CPU GIC interface */
extern void gic_init_secondary_cpu(void);
/* Take down a CPU's per-CPU GIC interface */
extern void gic_disable_cpu(void);
/* setup the gic virtual interface for a guest */
extern int gicv_setup(struct domain *d);

/* Context switch */
extern void gic_save_state(struct vcpu *v);
extern void gic_restore_state(struct vcpu *v);

/* SGI (AKA IPIs) */
enum gic_sgi {
    GIC_SGI_EVENT_CHECK,
    GIC_SGI_DUMP_STATE,
    GIC_SGI_CALL_FUNCTION,
    GIC_SGI_MAX,
};

/* SGI irq mode types */
enum gic_sgi_mode {
    SGI_TARGET_LIST,
    SGI_TARGET_OTHERS,
    SGI_TARGET_SELF,
};

extern void send_SGI_mask(const cpumask_t *cpumask, enum gic_sgi sgi);
extern void send_SGI_one(unsigned int cpu, enum gic_sgi sgi);
extern void send_SGI_self(enum gic_sgi sgi);
extern void send_SGI_allbutself(enum gic_sgi sgi);

/* print useful debug info */
extern void gic_dump_info(struct vcpu *v);
extern void gic_dump_vgic_info(struct vcpu *v);

/* Number of interrupt lines */
extern unsigned int gic_number_lines(void);

/* IRQ translation function for the device tree */
int gic_irq_xlate(const u32 *intspec, unsigned int intsize,
                  unsigned int *out_hwirq, unsigned int *out_type);

struct gic_info {
    /* GIC version */
    enum gic_version hw_version;
    /* Number of GIC lines supported */
    unsigned int nr_lines;
    /* Number of LR registers */
    uint8_t nr_lrs;
    /* Maintenance irq number */
    unsigned int maintenance_irq;
    /* Pointer to the device tree node representing the interrupt controller */
    const struct dt_device_node *node;
};

struct gic_hw_operations {
    /* Hold GIC HW information */
    const struct gic_info *info;
    /* Initialize the GIC and the boot CPU */
    int (*init)(void);
    /* Save GIC registers */
    void (*save_state)(struct vcpu *);
    /* Restore GIC registers */
    void (*restore_state)(const struct vcpu *);
    /* Dump GIC LR register information */
    void (*dump_state)(const struct vcpu *);

    /* hw_irq_controller to enable/disable/eoi host irq */
    hw_irq_controller *gic_host_irq_type;

    /* hw_irq_controller to enable/disable/eoi guest irq */
    hw_irq_controller *gic_guest_irq_type;

    /* End of Interrupt */
    void (*eoi_irq)(struct irq_desc *irqd);
    /* Deactivate/reduce priority of irq */
    void (*deactivate_irq)(struct irq_desc *irqd);
    /* Read IRQ id and Ack */
    unsigned int (*read_irq)(void);
    /* Force the active state of an IRQ by accessing the distributor */
    void (*set_active_state)(struct irq_desc *irqd, bool state);
    /* Force the pending state of an IRQ by accessing the distributor */
    void (*set_pending_state)(struct irq_desc *irqd, bool state);
    /* Set IRQ type */
    void (*set_irq_type)(struct irq_desc *desc, unsigned int type);
    /* Set IRQ priority */
    void (*set_irq_priority)(struct irq_desc *desc, unsigned int priority);
    /* Send SGI */
    void (*send_SGI)(enum gic_sgi sgi, enum gic_sgi_mode irqmode,
                     const cpumask_t *online_mask);
    /* Disable CPU physical and virtual interfaces */
    void (*disable_interface)(void);
    /* Update LR register with state and priority */
    void (*update_lr)(int lr, unsigned int virq, uint8_t priority,
                      unsigned int hw_irq, unsigned int state);
    /* Update HCR status register */
    void (*update_hcr_status)(uint32_t flag, bool set);
    /* Clear LR register */
    void (*clear_lr)(int lr);
    /* Read LR register and populate gic_lr structure */
    void (*read_lr)(int lr, struct gic_lr *);
    /* Write LR register from gic_lr structure */
    void (*write_lr)(int lr, const struct gic_lr *);
    /* Read VMCR priority */
    unsigned int (*read_vmcr_priority)(void);
    /* Read APRn register */
    unsigned int (*read_apr)(int apr_reg);
    /* Query the pending state of an interrupt at the distributor level. */
    bool (*read_pending_state)(struct irq_desc *irqd);
    /* Secondary CPU init */
    int (*secondary_init)(void);
    /* Create GIC node for the hardware domain */
    int (*make_hwdom_dt_node)(const struct domain *d,
                              const struct dt_device_node *gic, void *fdt);
    /* Create MADT table for the hardware domain */
    int (*make_hwdom_madt)(const struct domain *d, u32 offset);
    /* Map extra GIC MMIO, irqs and other hw stuffs to the hardware domain. */
    int (*map_hwdom_extra_mappings)(struct domain *d);
    /* Query the size of hardware domain madt table */
    unsigned long (*get_hwdom_extra_madt_size)(const struct domain *d);
    /* Deny access to GIC regions */
    int (*iomem_deny_access)(const struct domain *d);
    /* Handle LPIs, which require special handling */
    void (*do_LPI)(unsigned int lpi);
};

extern const struct gic_hw_operations *gic_hw_ops;

static inline unsigned int gic_get_nr_lrs(void)
{
    return gic_hw_ops->info->nr_lrs;
}

/*
 * Set the active state of an IRQ. This should be used with care, as this
 * directly forces the active bit, without considering the GIC state machine.
 * For private IRQs this only works for those of the current CPU.
 *
 * This function should only be called for interrupts routed to the
 * guest. The flow of interrupts routed to Xen is not able cope with
 * software changes to the active state.
 */
static inline void gic_set_active_state(struct irq_desc *irqd, bool state)
{
    ASSERT(test_bit(_IRQ_GUEST, &irqd->status));
    gic_hw_ops->set_active_state(irqd, state);
}

/*
 * Set the pending state of an IRQ. This should be used with care, as this
 * directly forces the pending bit, without considering the GIC state machine.
 * For private IRQs this only works for those of the current CPU.
 */
static inline void gic_set_pending_state(struct irq_desc *irqd, bool state)
{
    gic_hw_ops->set_pending_state(irqd, state);
}

/*
 * Read the pending state of an interrupt from the distributor.
 * For private IRQs this only works for those of the current CPU.
 */
static inline bool gic_read_pending_state(struct irq_desc *irqd)
{
    return gic_hw_ops->read_pending_state(irqd);
}

void register_gic_ops(const struct gic_hw_operations *ops);
int gic_make_hwdom_dt_node(const struct domain *d,
                           const struct dt_device_node *gic,
                           void *fdt);
int gic_make_hwdom_madt(const struct domain *d, u32 offset);
unsigned long gic_get_hwdom_madt_size(const struct domain *d);
int gic_map_hwdom_extra_mappings(struct domain *d);
int gic_iomem_deny_access(const struct domain *d);

#endif /* __ASSEMBLY__ */
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
