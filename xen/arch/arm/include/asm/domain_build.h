#ifndef __ASM_DOMAIN_BUILD_H__
#define __ASM_DOMAIN_BUILD_H__

#include <xen/sched.h>
#include <asm/kernel.h>

typedef __be32 gic_interrupt_t[3];
typedef bool (*alloc_domheap_mem_cb)(struct domain *d, struct page_info *pg,
                                     unsigned int order, void *extra);
bool allocate_domheap_memory(struct domain *d, paddr_t tot_size,
                             alloc_domheap_mem_cb cb, void *extra);
bool allocate_bank_memory(struct kernel_info *kinfo, gfn_t sgfn,
                          paddr_t tot_size);
void allocate_memory(struct domain *d, struct kernel_info *kinfo);
int construct_domain(struct domain *d, struct kernel_info *kinfo);
int domain_fdt_begin_node(void *fdt, const char *name, uint64_t unit);
int make_chosen_node(const struct kernel_info *kinfo);
int make_cpus_node(const struct domain *d, void *fdt);
int make_hypervisor_node(struct domain *d, const struct kernel_info *kinfo,
                         int addrcells, int sizecells);
int make_memory_node(const struct kernel_info *kinfo, int addrcells,
                     int sizecells, const struct membanks *mem);
int make_psci_node(void *fdt);
int make_timer_node(const struct kernel_info *kinfo);
void evtchn_allocate(struct domain *d);

unsigned int get_allocation_size(paddr_t size);

/*
 * handle_device_interrupts retrieves the interrupts configuration from
 * a device tree node and maps those interrupts to the target domain.
 *
 * Returns:
 *   < 0 error
 *   0   success
 */
int handle_device_interrupts(struct domain *d, struct dt_device_node *dev,
                             bool need_mapping);

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
