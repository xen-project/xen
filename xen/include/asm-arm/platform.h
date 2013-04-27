#ifndef __ASM_ARM_PLATFORM_H
#define __ASM_ARM_PLATFORM_H

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/mm.h>

/* Describe specific operation for a board */
struct platform_desc {
    /* Platform name */
    const char *name;
    /* Array of device tree 'compatible' strings */
    const char *const *compatible;
    /* Platform initialization */
    int (*init)(void);
    int (*init_time)(void);
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
};

/*
 * Quirk to map dom0 memory in 1:1
 * Usefull on platform where System MMU is not yet implemented
 */
#define PLATFORM_QUIRK_DOM0_MAPPING_11 (1 << 0)

int __init platform_init(void);
int __init platform_init_time(void);
int __init platform_specific_mapping(struct domain *d);
void platform_reset(void);
void platform_poweroff(void);
bool_t platform_has_quirk(uint32_t quirk);

#define PLATFORM_START(_name, _namestr)                         \
static const struct platform_desc  __plat_desc_##_name __used   \
__attribute__((__section__(".arch.info"))) = {                  \
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
