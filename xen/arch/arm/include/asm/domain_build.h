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

int prepare_acpi(struct domain *d, struct kernel_info *kinfo);

int add_ext_regions(unsigned long s_gfn, unsigned long e_gfn, void *data);

#define ACPI_DOM0_FDT_MIN_SIZE 4096

paddr_t hwdom_get_fdt_alloc_size(void);

#if defined(CONFIG_MPU) && defined(CONFIG_ARM_64)
/* Utility function to determine if an Armv8-R processor supports VMSA. */
bool has_v8r_vmsa_support(void);
#else
static inline bool has_v8r_vmsa_support(void)
{
    return false;
}
#endif /* CONFIG_MPU */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
