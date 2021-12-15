#ifndef __ASM_DOMAIN_BUILD_H__
#define __ASM_DOMAIN_BUILD_H__

#include <xen/sched.h>
#include <asm/kernel.h>

int map_irq_to_domain(struct domain *d, unsigned int irq,
                      bool need_mapping, const char *devname);
int make_chosen_node(const struct kernel_info *kinfo);
void evtchn_allocate(struct domain *d);

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
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
