/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

PERFCOUNTER(invalid_hypercalls, "invalid hypercalls")

PERFCOUNTER(trap_wfi,      "trap: wfi")
PERFCOUNTER(trap_wfe,      "trap: wfe")
PERFCOUNTER(trap_cp15_32,  "trap: cp15 32-bit access")
PERFCOUNTER(trap_cp15_64,  "trap: cp15 64-bit access")
PERFCOUNTER(trap_cp14_32,  "trap: cp14 32-bit access")
PERFCOUNTER(trap_cp14_64,  "trap: cp14 64-bit access")
PERFCOUNTER(trap_cp14_dbg, "trap: cp14 dbg access")
PERFCOUNTER(trap_cp,       "trap: cp access")
PERFCOUNTER(trap_smc32,    "trap: 32-bit smc")
PERFCOUNTER(trap_hvc32,    "trap: 32-bit hvc")
#ifdef CONFIG_ARM_64
PERFCOUNTER(trap_smc64,    "trap: 64-bit smc")
PERFCOUNTER(trap_hvc64,    "trap: 64-bit hvc")
PERFCOUNTER(trap_sysreg,   "trap: sysreg access")
#endif
PERFCOUNTER(trap_iabt,     "trap: guest instr abort")
PERFCOUNTER(trap_dabt,     "trap: guest data abort")
PERFCOUNTER(trap_uncond,   "trap: condition failed")

PERFCOUNTER(vpsci_cpu_on,              "vpsci: cpu_on")
PERFCOUNTER(vpsci_cpu_off,             "vpsci: cpu_off")
PERFCOUNTER(vpsci_version,             "vpsci: version")
PERFCOUNTER(vpsci_migrate_info_type,   "vpsci: migrate_info_type")
PERFCOUNTER(vpsci_migrate_info_up_cpu, "vpsci: migrate_info_up_cpu")
PERFCOUNTER(vpsci_system_off,          "vpsci: system_off")
PERFCOUNTER(vpsci_system_reset,        "vpsci: system_reset")
PERFCOUNTER(vpsci_cpu_suspend,         "vpsci: cpu_suspend")
PERFCOUNTER(vpsci_cpu_affinity_info,   "vpsci: cpu_affinity_info")
PERFCOUNTER(vpsci_cpu_migrate,         "vpsci: cpu_migrate")

PERFCOUNTER(vgicd_reads,                "vgicd: read")
PERFCOUNTER(vgicd_writes,               "vgicd: write")
PERFCOUNTER(vgicr_reads,                "vgicr: read")
PERFCOUNTER(vgicr_writes,               "vgicr: write")
PERFCOUNTER(vgic_sysreg_reads,          "vgic: sysreg read")
PERFCOUNTER(vgic_sysreg_writes,         "vgic: sysreg write")
PERFCOUNTER(vgic_sgi_list  ,            "vgic: SGI send to list")
PERFCOUNTER(vgic_sgi_others,            "vgic: SGI send to others")
PERFCOUNTER(vgic_sgi_self,              "vgic: SGI send to self")
PERFCOUNTER(vgic_cross_cpu_intr_inject, "vgic: cross-CPU irq inject")
PERFCOUNTER(vgic_irq_migrates,          "vgic: irq migration")

PERFCOUNTER(vuart_reads,  "vuart: read")
PERFCOUNTER(vuart_writes, "vuart: write")

PERFCOUNTER(vtimer_cp32_reads,   "vtimer: cp32 read")
PERFCOUNTER(vtimer_cp32_writes,  "vtimer: cp32 write")

PERFCOUNTER(vtimer_cp64_reads,   "vtimer: cp64 read")
PERFCOUNTER(vtimer_cp64_writes,  "vtimer: cp64 write")

PERFCOUNTER(vtimer_sysreg_reads,  "vtimer: sysreg read")
PERFCOUNTER(vtimer_sysreg_writes, "vtimer: sysreg write")

PERFCOUNTER(vtimer_phys_inject,   "vtimer: phys expired, injected")
PERFCOUNTER(vtimer_phys_masked,   "vtimer: phys expired, masked")
PERFCOUNTER(vtimer_virt_inject,   "vtimer: virt expired, injected")

PERFCOUNTER(ppis,                 "#PPIs")
PERFCOUNTER(spis,                 "#SPIs")
PERFCOUNTER(guest_irqs,           "#GUEST-IRQS")

PERFCOUNTER(hyp_timer_irqs,   "Hypervisor timer interrupts")
PERFCOUNTER(phys_timer_irqs,  "Physical timer interrupts")
PERFCOUNTER(virt_timer_irqs,  "Virtual timer interrupts")
PERFCOUNTER(maintenance_irqs, "Maintenance interrupts")

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
