#ifndef __ASM_ARM_DEVICE_H
#define __ASM_ARM_DEVICE_H

#include <xen/init.h>
#include <xen/device_tree.h>

enum device_type
{
    DEVICE_SERIAL
};

struct device_desc {
    /* Device name */
    const char *name;
    /* Device type */
    enum device_type type;
    /* Array of device tree 'compatible' strings */
    const char *const *compatible;
    /* Device initialization */
    int (*init)(struct dt_device_node *dev, const void *data);
};

/**
 *  device_init - Initialize a device
 *  @dev: device to initialize
 *  @type: type of the device (serial, network...)
 *  @data: specific data for initializing the device
 *
 *  Return 0 on success.
 */
int __init device_init(struct dt_device_node *dev, enum device_type type,
                       const void *data);

#define DT_DEVICE_START(_name, _namestr, _type)                     \
static const struct device_desc __dev_desc_##_name __used           \
__attribute__((__section__(".dev.info"))) = {                       \
    .name = _namestr,                                               \
    .type = _type,                                                  \

#define DT_DEVICE_END                                               \
};

#endif /* __ASM_ARM_DEVICE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
