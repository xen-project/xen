#ifndef __ASM_ARM_DEVICE_H
#define __ASM_ARM_DEVICE_H

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
#ifdef CONFIG_HAS_DEVICE_TREE
    struct dt_device_node *of_node; /* Used by drivers imported from Linux */
#endif
    struct dev_archdata archdata;
    struct iommu_fwspec *iommu_fwspec; /* per-device IOMMU instance data */
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
    /*
     * Device initialization.
     *
     * -EAGAIN is used to indicate that device probing is deferred.
     */
    int (*init)(struct dt_device_node *dev, const void *data);
};

struct acpi_device_desc {
    /* Device name */
    const char *name;
    /* Device class */
    enum device_class class;
    /* type of device supported by the driver */
    const int class_type;
    /* Device initialization */
    int (*init)(const void *data);
};

/**
 *  acpi_device_init - Initialize a device
 *  @class: class of the device (serial, network...)
 *  @data: specific data for initializing the device
 *
 *  Return 0 on success.
 */
int acpi_device_init(enum device_class class,
                     const void *data, int class_type);

/**
 *  device_init - Initialize a device
 *  @dev: device to initialize
 *  @class: class of the device (serial, network...)
 *  @data: specific data for initializing the device
 *
 *  Return 0 on success.
 */
int device_init(struct dt_device_node *dev, enum device_class class,
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

#define ACPI_DEVICE_START(_name, _namestr, _class)                    \
static const struct acpi_device_desc __dev_desc_##_name __used           \
__section(".adev.info") = {                       \
    .name = _namestr,                                               \
    .class = _class,                                                \

#define ACPI_DEVICE_END                                               \
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
