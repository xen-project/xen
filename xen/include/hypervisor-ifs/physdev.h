/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (c) 2004 - Rolf Neugebauer - Intel Research Cambridge
 * (c) 2004 - Keir Fraser - University of Cambridge
 ****************************************************************************
 * Description: Interface for domains to access physical devices on the PCI bus
 */

#ifndef __HYPERVISOR_IFS_PHYSDEV_H__
#define __HYPERVISOR_IFS_PHYSDEV_H__

/* Commands to HYPERVISOR_physdev_op() */
#define PHYSDEVOP_PCI_CFGREG_READ       0
#define PHYSDEVOP_PCI_CFGREG_WRITE      1
#define PHYSDEVOP_PCI_INITIALISE_DEVICE 2
#define PHYSDEVOP_PCI_PROBE_ROOT_BUSES  3
#define PHYSDEVOP_UNMASK_IRQ            4

/* Read from PCI configuration space. */
typedef struct physdevop_pci_cfgreg_read_st
{
    int bus;        /* IN */
    int dev;        /* IN */
    int func;       /* IN */
    int reg;        /* IN */
    int len;        /* IN */
    u32 value;      /* OUT */
} physdevop_pci_cfgreg_read_t;

/* Write to PCI configuration space. */
typedef struct physdevop_pci_cfgreg_write_st
{
    int bus;        /* IN */
    int dev;        /* IN */
    int func;       /* IN */
    int reg;        /* IN */
    int len;        /* IN */
    u32 value;      /* IN */
} physdevop_pci_cfgreg_write_t;

/* Do final initialisation of a PCI device (e.g., last-moment IRQ routing). */
typedef struct physdevop_pci_initialise_device_st
{
    int bus;      /* IN */
    int dev;      /* IN */
    int func;     /* IN */
} physdevop_pci_initialise_device_t;

/* Find the root buses for subsequent scanning. */
typedef struct physdevop_pci_probe_root_buses_st
{
    u32 busmask[256/32]; /* OUT */
} physdevop_pci_probe_root_buses_t;

typedef struct _physdev_op_st 
{
    unsigned long cmd;
    union
    {
        physdevop_pci_cfgreg_read_t       pci_cfgreg_read;
        physdevop_pci_cfgreg_write_t      pci_cfgreg_write;
        physdevop_pci_initialise_device_t pci_initialise_device;
        physdevop_pci_probe_root_buses_t  pci_probe_root_buses;
    } u;
} physdev_op_t;

#endif /* __HYPERVISOR_IFS_PHYSDEV_H__ */
