/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_DEVICE_H__
#define __ASM_PPC_DEVICE_H__

enum device_type
{
    DEV_DT,
    DEV_PCI,
};

struct device {
    enum device_type type;
#ifdef CONFIG_HAS_DEVICE_TREE
    struct dt_device_node *of_node; /* Used by drivers imported from Linux */
#endif
};

enum device_class
{
    DEVICE_SERIAL,
    DEVICE_IOMMU,
    DEVICE_PCI_HOSTBRIDGE,
    /* Use for error */
    DEVICE_UNKNOWN,
};

struct device_desc {
    /* Device name */
    const char *name;
    /* Device class */
    enum device_class class;
    /* List of devices supported by this driver */
    const struct dt_device_match *dt_match;
    /*
     * Device initialization.
     *
     * -EAGAIN is used to indicate that device probing is deferred.
     */
    int (*init)(struct dt_device_node *dev, const void *data);
};

typedef struct device device_t;

#define DT_DEVICE_START(name_, namestr_, class_)                    \
static const struct device_desc __dev_desc_##name_ __used           \
__section(".dev.info") = {                                          \
    .name = namestr_,                                               \
    .class = class_,                                                \

#define DT_DEVICE_END                                               \
};

#endif /* __ASM_PPC_DEVICE_H__ */
