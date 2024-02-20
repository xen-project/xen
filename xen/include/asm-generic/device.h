/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_DEVICE_H__
#define __ASM_GENERIC_DEVICE_H__

#include <xen/stdbool.h>

enum device_type
{
#ifdef CONFIG_HAS_DEVICE_TREE
    DEV_DT,
#endif
    DEV_PCI
};

enum device_class
{
    DEVICE_SERIAL,
    DEVICE_IOMMU,
    DEVICE_INTERRUPT_CONTROLLER,
    DEVICE_PCI_HOSTBRIDGE,
    /* Use for error */
    DEVICE_UNKNOWN,
};

/* struct device - The basic device structure */
struct device
{
    enum device_type type;
#ifdef CONFIG_HAS_DEVICE_TREE
    struct dt_device_node *of_node; /* Used by drivers imported from Linux */
#endif
#ifdef CONFIG_HAS_PASSTHROUGH
    void *iommu; /* IOMMU private data */;
    struct iommu_fwspec *iommu_fwspec; /* per-device IOMMU instance data */
#endif
};

typedef struct device device_t;

#ifdef CONFIG_HAS_DEVICE_TREE

#include <xen/device_tree.h>

#define dev_is_dt(dev)  ((dev)->type == DEV_DT)

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

#define DT_DEVICE_START(dev_name, ident, cls)                   \
static const struct device_desc __dev_desc_##dev_name __used    \
__section(".dev.info") = {                                      \
    .name = ident,                                              \
    .class = cls,

#define DT_DEVICE_END                                           \
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

#else /* !CONFIG_HAS_DEVICE_TREE */
#define dev_is_dt(dev) ((void)(dev), false)
#endif /* CONFIG_HAS_DEVICE_TREE */

#define dev_is_pci(dev) ((dev)->type == DEV_PCI)

#ifdef CONFIG_ACPI

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

#define ACPI_DEVICE_START(dev_name, ident, cls)                     \
static const struct acpi_device_desc __dev_desc_##dev_name __used   \
__section(".adev.info") = {                                         \
    .name = ident,                                                  \
    .class = cls,

#define ACPI_DEVICE_END                                             \
};

#endif /* CONFIG_ACPI */

#endif /* __ASM_GENERIC_DEVICE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
