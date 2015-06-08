#ifndef __ASM_ARM_DEVICE_H
#define __ASM_ARM_DEVICE_H

#include <xen/init.h>

enum device_type
{
    DEV_DT,
};

struct dev_archdata {
    void *iommu;    /* IOMMU private data */
};

/* struct device - The basic device structure */
struct device
{
    enum device_type type;
#ifdef HAS_DEVICE_TREE
    struct dt_device_node *of_node; /* Used by drivers imported from Linux */
#endif
    struct dev_archdata archdata;
};

typedef struct device device_t;

#include <xen/device_tree.h>

/* TODO: Correctly implement dev_is_pci when PCI is supported on ARM */
#define dev_is_pci(dev) ((void)(dev), 0)
#define dev_is_dt(dev)  ((dev->type == DEV_DT)

enum device_class
{
    DEVICE_SERIAL,
    DEVICE_IOMMU,
    DEVICE_GIC,
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
    /* Device initialization */
    int (*init)(struct dt_device_node *dev, const void *data);
};

/**
 *  device_init - Initialize a device
 *  @dev: device to initialize
 *  @class: class of the device (serial, network...)
 *  @data: specific data for initializing the device
 *
 *  Return 0 on success.
 */
int __init device_init(struct dt_device_node *dev, enum device_class class,
                       const void *data);

/**
 * device_get_type - Get the type of the device
 * @dev: device to match
 *
 * Return the device type on success or DEVICE_ANY on failure
 */
enum device_class device_get_class(const struct dt_device_node *dev);

#define DT_DEVICE_START(_name, _namestr, _class)                    \
static const struct device_desc __dev_desc_##_name __used           \
__section(".dev.info") = {                                          \
    .name = _namestr,                                               \
    .class = _class,                                                \

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
