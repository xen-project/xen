/*
 *	Low-Level PCI Support for PC
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 * Adjusted to use Xen's interface by Rolf Neugebauer, Intel Research Cambridge
 * Further modifications by Keir Fraser, University of Cambridge
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>

#include <asm/segment.h>
#include <asm/io.h>

#include <asm-xen/xen-public/xen.h>
#include <asm-xen/xen-public/physdev.h>

#include "pci-i386.h"

/*
 * NB. The following interface functions are not included here:
 *  1. void eisa_set_level_irq(unsigned int irq)
 *  2. irq_routing_table * __devinit pcibios_get_irq_routing_table(void)
 *  3. int pcibios_set_irq_routing(struct pci_dev *dev, int pin, int irq)
 * All are used by the ACPI driver. This should be ported to Xen if it is
 * ever required -- Xen is the ultimate source for IRQ-routing knowledge.
 */

struct pci_ops *pci_root_ops = NULL;

int (*pci_config_read)(int seg, int bus, int dev, int fn, 
                       int reg, int len, u32 *value) = NULL;
int (*pci_config_write)(int seg, int bus, int dev, int fn,
                        int reg, int len, u32 value) = NULL;

unsigned int pci_probe = PCI_PROBE_BIOS;

struct pci_fixup pcibios_fixups[] = { { 0 } };

static int pci_confx_read(int seg, int bus, int dev, int fn, int reg, 
                          int len, u32 *value)
{
    int ret;
    physdev_op_t op;

    if (bus > 255 || dev > 31 || fn > 7 || reg > 255)
        return -EINVAL;

    op.cmd = PHYSDEVOP_PCI_CFGREG_READ;
    op.u.pci_cfgreg_read.bus  = bus;
    op.u.pci_cfgreg_read.dev  = dev;
    op.u.pci_cfgreg_read.func = fn;
    op.u.pci_cfgreg_read.reg  = reg;
    op.u.pci_cfgreg_read.len  = len;

    if ( (ret = HYPERVISOR_physdev_op(&op)) != 0 )
        return ret;

    *value = op.u.pci_cfgreg_read.value;

    return 0;
}

static int pci_confx_write(int seg, int bus, int dev, int fn, int reg, 
                           int len, u32 value)
{
    int ret;
    physdev_op_t op;

    if ((bus > 255 || dev > 31 || fn > 7 || reg > 255)) 
        return -EINVAL;

    op.cmd = PHYSDEVOP_PCI_CFGREG_WRITE;
    op.u.pci_cfgreg_write.bus   = bus;
    op.u.pci_cfgreg_write.dev   = dev;
    op.u.pci_cfgreg_write.func  = fn;
    op.u.pci_cfgreg_write.reg   = reg;
    op.u.pci_cfgreg_write.len   = len;
    op.u.pci_cfgreg_write.value = value;

    if ( (ret = HYPERVISOR_physdev_op(&op)) != 0 )
        return ret;
    return 0;
}


static int pci_confx_read_config_byte(struct pci_dev *dev, 
                                      int where, u8 *value)
{
    int result; 
    u32 data;

    result = pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                            PCI_FUNC(dev->devfn), where, 1, &data);

    *value = (u8)data;

    return result;
}

static int pci_confx_read_config_word(struct pci_dev *dev, 
                                      int where, u16 *value)
{
    int result; 
    u32 data;

    result = pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                            PCI_FUNC(dev->devfn), where, 2, &data);

    *value = (u16)data;

    return result;
}

static int pci_confx_read_config_dword(struct pci_dev *dev, 
                                       int where, u32 *value)
{
    return pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                          PCI_FUNC(dev->devfn), where, 4, value);
}

static int pci_confx_write_config_byte(struct pci_dev *dev, 
                                       int where, u8 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 1, value);
}

static int pci_confx_write_config_word(struct pci_dev *dev, 
                                       int where, u16 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 2, value);
}

static int pci_confx_write_config_dword(struct pci_dev *dev, 
                                        int where, u32 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 4, value);
}

static struct pci_ops pci_conf_xen = {
    pci_confx_read_config_byte,
    pci_confx_read_config_word,
    pci_confx_read_config_dword,
    pci_confx_write_config_byte,
    pci_confx_write_config_word,
    pci_confx_write_config_dword
};

void pcibios_penalize_isa_irq(int irq)
{ 
    /* nothing */
}

void __devinit pcibios_fixup_bus(struct pci_bus *b)
{
    pci_read_bridge_bases(b);
}

struct pci_bus * __devinit pcibios_scan_root(int busnum)
{
    struct list_head *list;
    struct pci_bus *bus;

    list_for_each ( list, &pci_root_buses )
    {
        bus = pci_bus_b(list);
        if ( bus->number == busnum )
            return bus;
    }

    printk("PCI: Probing PCI hardware (bus %02x)\n", busnum);
    return pci_scan_bus(busnum, pci_root_ops, NULL);
}

void __init pcibios_init(void)
{
    int bus;
    physdev_op_t op;

    if ( !pci_probe )
        return;

    pci_root_ops     = &pci_conf_xen;
    pci_config_read  = pci_confx_read;
    pci_config_write = pci_confx_write;

    pcibios_set_cacheline_size();

    op.cmd = PHYSDEVOP_PCI_PROBE_ROOT_BUSES;
    if ( HYPERVISOR_physdev_op(&op) != 0 )
    {
        printk(KERN_WARNING "PCI: System does not support PCI\n");
        return;
    }

    printk(KERN_INFO "PCI: Probing PCI hardware\n");
    for ( bus = 0; bus < 256; bus++ )
        if ( test_bit(bus, &op.u.pci_probe_root_buses.busmask[0]) )
            (void)pcibios_scan_root(bus);

    pcibios_resource_survey();
}

char * __devinit pcibios_setup(char *str)
{
    if ( !strcmp(str, "off") )
        pci_probe = 0;
    return NULL;
}

unsigned int pcibios_assign_all_busses(void)
{
    return 0;
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
    int err;
    u8  pin;
    physdev_op_t op;

    /* Inform Xen that we are going to use this device. */
    op.cmd = PHYSDEVOP_PCI_INITIALISE_DEVICE;
    op.u.pci_initialise_device.bus  = dev->bus->number;
    op.u.pci_initialise_device.dev  = PCI_SLOT(dev->devfn);
    op.u.pci_initialise_device.func = PCI_FUNC(dev->devfn);
    if ( (err = HYPERVISOR_physdev_op(&op)) != 0 )
        return err;

    /* Now we can bind to the very final IRQ line. */
    pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &pin);
    dev->irq = pin;

    /* Turn on device I/O and memory access as necessary. */
    if ( (err = pcibios_enable_resources(dev, mask)) < 0 )
        return err;

    /* Sanity-check that an interrupt-producing device is routed to an IRQ. */
    pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
    if ( pin != 0 )
    {
        if ( dev->irq != 0 )
            printk(KERN_INFO "PCI: Obtained IRQ %d for device %s\n",
                   dev->irq, dev->slot_name);
        else
            printk(KERN_WARNING "PCI: No IRQ known for interrupt pin %c of "
                   "device %s.\n", 'A' + pin - 1, dev->slot_name);
    }

    return 0;
}
