#ifndef __ASM_DOMAIN_BUILD_H__
#define __ASM_DOMAIN_BUILD_H__

#include <xen/fdt-kernel.h>
#include <xen/sched.h>

typedef __be32 gic_interrupt_t[3];
int make_psci_node(void *fdt);
void evtchn_allocate(struct domain *d);

/*
 * Helper to write an interrupts with the GIC format
 * This code is assuming the irq is an PPI.
 */
void set_interrupt(gic_interrupt_t interrupt, unsigned int irq,
                   unsigned int cpumask, unsigned int level);

#ifndef CONFIG_ACPI
static inline int prepare_acpi(struct domain *d, struct kernel_info *kinfo)
{
    /* Only booting with ACPI will hit here */
    BUG();
    return -EINVAL;
}
#else
int prepare_acpi(struct domain *d, struct kernel_info *kinfo);
#endif

int add_ext_regions(unsigned long s_gfn, unsigned long e_gfn, void *data);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
