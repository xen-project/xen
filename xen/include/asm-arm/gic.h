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

#define GICD_CTLR       (0x000/4)
#define GICD_TYPER      (0x004/4)
#define GICD_IIDR       (0x008/4)
#define GICD_IGROUPR    (0x080/4)
#define GICD_IGROUPRN   (0x0FC/4)
#define GICD_ISENABLER  (0x100/4)
#define GICD_ISENABLERN (0x17C/4)
#define GICD_ICENABLER  (0x180/4)
#define GICD_ICENABLERN (0x1fC/4)
#define GICD_ISPENDR    (0x200/4)
#define GICD_ISPENDRN   (0x27C/4)
#define GICD_ICPENDR    (0x280/4)
#define GICD_ICPENDRN   (0x2FC/4)
#define GICD_ISACTIVER  (0x300/4)
#define GICD_ISACTIVERN (0x37C/4)
#define GICD_ICACTIVER  (0x380/4)
#define GICD_ICACTIVERN (0x3FC/4)
#define GICD_IPRIORITYR (0x400/4)
#define GICD_IPRIORITYRN (0x7F8/4)
#define GICD_ITARGETSR  (0x800/4)
#define GICD_ITARGETSRN (0xBF8/4)
#define GICD_ICFGR      (0xC00/4)
#define GICD_ICFGRN     (0xCFC/4)
#define GICD_NSACR      (0xE00/4)
#define GICD_NSACRN     (0xEFC/4)
#define GICD_SGIR       (0xF00/4)
#define GICD_CPENDSGIR  (0xF10/4)
#define GICD_CPENDSGIRN (0xF1C/4)
#define GICD_SPENDSGIR  (0xF20/4)
#define GICD_SPENDSGIRN (0xF2C/4)
#define GICD_ICPIDR2    (0xFE8/4)

#define GICD_SGI_TARGET_LIST_SHIFT   (24)
#define GICD_SGI_TARGET_LIST_MASK    (0x3UL << GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_LIST         (0UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_OTHERS       (1UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_SELF         (2UL<<GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_SHIFT        (16)
#define GICD_SGI_TARGET_MASK         (0xFFUL<<GICD_SGI_TARGET_SHIFT)
#define GICD_SGI_GROUP1              (1UL<<15)
#define GICD_SGI_INTID_MASK          (0xFUL)

#define GICC_CTLR       (0x0000/4)
#define GICC_PMR        (0x0004/4)
#define GICC_BPR        (0x0008/4)
#define GICC_IAR        (0x000C/4)
#define GICC_EOIR       (0x0010/4)
#define GICC_RPR        (0x0014/4)
#define GICC_HPPIR      (0x0018/4)
#define GICC_APR        (0x00D0/4)
#define GICC_NSAPR      (0x00E0/4)
#define GICC_DIR        (0x1000/4)

#define GICH_HCR        (0x00/4)
#define GICH_VTR        (0x04/4)
#define GICH_VMCR       (0x08/4)
#define GICH_MISR       (0x10/4)
#define GICH_EISR0      (0x20/4)
#define GICH_EISR1      (0x24/4)
#define GICH_ELSR0      (0x30/4)
#define GICH_ELSR1      (0x34/4)
#define GICH_APR        (0xF0/4)
#define GICH_LR         (0x100/4)

/* Register bits */
#define GICD_CTL_ENABLE 0x1

#define GICD_TYPE_LINES 0x01f
#define GICD_TYPE_CPUS  0x0e0
#define GICD_TYPE_SEC   0x400

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

#define GICH_LR_VIRTUAL_MASK    0x3ff
#define GICH_LR_VIRTUAL_SHIFT   0
#define GICH_LR_PHYSICAL_MASK   0x3ff
#define GICH_LR_PHYSICAL_SHIFT  10
#define GICH_LR_STATE_MASK      0x3
#define GICH_LR_STATE_SHIFT     28
#define GICH_LR_PRIORITY_SHIFT  23
#define GICH_LR_MAINTENANCE_IRQ (1<<19)
#define GICH_LR_PENDING         (1<<28)
#define GICH_LR_ACTIVE          (1<<29)
#define GICH_LR_GRP1            (1<<30)
#define GICH_LR_HW              (1<<31)
#define GICH_LR_CPUID_SHIFT     9
#define GICH_VTR_NRLRGS         0x3f

#ifndef __ASSEMBLY__
#include <xen/device_tree.h>

#define DT_MATCH_GIC    DT_MATCH_COMPATIBLE("arm,cortex-a15-gic"), \
                        DT_MATCH_COMPATIBLE("arm,cortex-a7-gic")

extern int domain_vgic_init(struct domain *d);
extern void domain_vgic_free(struct domain *d);

extern int vcpu_vgic_init(struct vcpu *v);

extern void vgic_vcpu_inject_irq(struct vcpu *v, unsigned int irq,int virtual);
extern void vgic_clear_pending_irqs(struct vcpu *v);
extern struct pending_irq *irq_to_pending(struct vcpu *v, unsigned int irq);

/* Program the GIC to route an interrupt with a dt_irq */
extern void gic_route_dt_irq(const struct dt_irq *irq,
                             const cpumask_t *cpu_mask,
                             unsigned int priority);
extern void gic_route_ppis(void);
extern void gic_route_spis(void);

extern void gic_inject(void);
extern void gic_clear_pending_irqs(struct vcpu *v);
extern int gic_events_need_delivery(void);

extern void __cpuinit init_maintenance_interrupt(void);
extern void gic_set_guest_irq(struct vcpu *v, unsigned int irq,
        unsigned int state, unsigned int priority);
extern void gic_remove_from_queues(struct vcpu *v, unsigned int virtual_irq);
extern int gic_route_irq_to_guest(struct domain *d,
                                  const struct dt_irq *irq,
                                  const char * devname);

/* Accept an interrupt from the GIC and dispatch its handler */
extern void gic_interrupt(struct cpu_user_regs *regs, int is_fiq);
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
    GIC_SGI_EVENT_CHECK = 0,
    GIC_SGI_DUMP_STATE  = 1,
    GIC_SGI_CALL_FUNCTION = 2,
};
extern void send_SGI_mask(const cpumask_t *cpumask, enum gic_sgi sgi);
extern void send_SGI_one(unsigned int cpu, enum gic_sgi sgi);
extern void send_SGI_self(enum gic_sgi sgi);
extern void send_SGI_allbutself(enum gic_sgi sgi);

/* print useful debug info */
extern void gic_dump_info(struct vcpu *v);

/* Number of interrupt lines */
extern unsigned int gic_number_lines(void);

/* IRQ translation function for the device tree */
int gic_irq_xlate(const u32 *intspec, unsigned int intsize,
                  unsigned int *out_hwirq, unsigned int *out_type);

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
