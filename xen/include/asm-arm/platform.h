#ifndef __ASM_ARM_PLATFORM_H
#define __ASM_ARM_PLATFORM_H

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/device_tree.h>

/* Describe specific operation for a board */
struct platform_desc {
    /* Platform name */
    const char *name;
    /* Array of device tree 'compatible' strings */
    const char *const *compatible;
    /* Platform initialization */
    int (*init)(void);
    int (*init_time)(void);
#ifdef CONFIG_ARM_32
    /* SMP */
    int (*smp_init)(void);
    int (*cpu_up)(int cpu);
#endif
    /* Specific mapping for dom0 */
    int (*specific_mapping)(struct domain *d);
    /* Platform reset */
    void (*reset)(void);
    /* Platform power-off */
    void (*poweroff)(void);
    /*
     * Platform quirks
     * Defined has a function because a platform can support multiple
     * board with different quirk on each
     */
    uint32_t (*quirks)(void);
    /*
     * Platform blacklist devices
     * List of devices which must not pass-through to a guest
     */
    const struct dt_device_match *blacklist_dev;
};

/*
 * Quirk for platforms where device tree incorrectly reports 4K GICC
 * size, but actually the two GICC register ranges are placed at 64K
 * stride.
 */
#define PLATFORM_QUIRK_GIC_64K_STRIDE (1 << 0)

void __init platform_init(void);
int __init platform_init_time(void);
int __init platform_specific_mapping(struct domain *d);
#ifdef CONFIG_ARM_32
int platform_smp_init(void);
int platform_cpu_up(int cpu);
#endif
void platform_reset(void);
void platform_poweroff(void);
bool_t platform_has_quirk(uint32_t quirk);
bool_t platform_device_is_blacklisted(const struct dt_device_node *node);

#define PLATFORM_START(_name, _namestr)                         \
static const struct platform_desc  __plat_desc_##_name __used   \
__section(".arch.info") = {                                     \
    .name = _namestr,

#define PLATFORM_END                                            \
};

#endif /* __ASM_ARM_PLATFORM_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
