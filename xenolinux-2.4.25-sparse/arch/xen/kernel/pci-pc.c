/*
 *	Low-Level PCI Support for PC
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 * adjusted to use Xen's interface by Rolf Neugebauer
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

#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/hypervisor-ifs/physdev.h>

#include "pci-i386.h"

int pcibios_last_bus = -1;
struct pci_bus *pci_root_bus = NULL;
struct pci_ops *pci_root_ops = NULL;

int (*pci_config_read)(int seg, int bus, int dev, int fn, int reg, int len, u32 *value) = NULL;
int (*pci_config_write)(int seg, int bus, int dev, int fn, int reg, int len, u32 value) = NULL;

static int pci_using_acpi_prt = 0;

/*
 * This interrupt-safe spinlock protects all accesses to PCI
 * configuration space.
 */
static spinlock_t pci_config_lock = SPIN_LOCK_UNLOCKED;

unsigned int pci_probe = PCI_PROBE_BIOS;

/*
 * Functions for accessing PCI configuration space with type 1 accesses
 */

static int pci_confx_read (int seg, int bus, int dev, int fn, int reg, 
                           int len, u32 *value)
{
    int ret;
    physdev_op_t op;

    if (bus > 255 || dev > 31 || fn > 7 || reg > 255)
        return -EINVAL;

    op.cmd = PHYSDEVOP_CFGREG_READ;
    op.u.cfg_read.seg  = seg;
    op.u.cfg_read.bus  = bus;
    op.u.cfg_read.dev  = dev;
    op.u.cfg_read.func = fn;
    op.u.cfg_read.reg  = reg;
    op.u.cfg_read.len  = len;

    if ( (ret = HYPERVISOR_physdev_op(&op)) != 0 )
    {
        //printk(KERN_ALERT "pci config read error\n");
        return ret;
    }

    *value = op.u.cfg_read.value;

    return 0;
}

static int pci_confx_write (int seg, int bus, int dev, int fn, int reg, 
                            int len, u32 value)
{
    int ret;
    physdev_op_t op;

    if ((bus > 255 || dev > 31 || fn > 7 || reg > 255)) 
        return -EINVAL;

    op.cmd = PHYSDEVOP_CFGREG_WRITE;
    op.u.cfg_write.seg   = seg;
    op.u.cfg_write.bus   = bus;
    op.u.cfg_write.dev   = dev;
    op.u.cfg_write.func  = fn;
    op.u.cfg_write.reg   = reg;
    op.u.cfg_write.len   = len;
    op.u.cfg_write.value = value;

    if ( (ret = HYPERVISOR_physdev_op(&op)) != 0 )
    {
        //printk(KERN_ALERT "pci config write error\n");
        return ret;
    }
    return 0;
}


static int pci_confx_read_config_byte(struct pci_dev *dev, int where, u8 *value)
{
    int result; 
    u32 data;

    result = pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                            PCI_FUNC(dev->devfn), where, 1, &data);

    *value = (u8)data;

    return result;
}

static int pci_confx_read_config_word(struct pci_dev *dev, int where, u16 *value)
{
    int result; 
    u32 data;

    result = pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                            PCI_FUNC(dev->devfn), where, 2, &data);

    *value = (u16)data;

    return result;
}

static int pci_confx_read_config_dword(struct pci_dev *dev, int where, u32 *value)
{
    return pci_confx_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                          PCI_FUNC(dev->devfn), where, 4, value);
}

static int pci_confx_write_config_byte(struct pci_dev *dev, int where, u8 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 1, value);
}

static int pci_confx_write_config_word(struct pci_dev *dev, int where, u16 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 2, value);
}

static int pci_confx_write_config_dword(struct pci_dev *dev, int where, u32 value)
{
    return pci_confx_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
                           PCI_FUNC(dev->devfn), where, 4, value);
}

static struct pci_ops pci_direct_confx = {
    pci_confx_read_config_byte,
    pci_confx_read_config_word,
    pci_confx_read_config_dword,
    pci_confx_write_config_byte,
    pci_confx_write_config_word,
    pci_confx_write_config_dword
};



static struct pci_ops * __devinit pci_check_xen(void)
{
    unsigned long flags;

    __save_flags(flags); __cli();

    printk(KERN_INFO "PCI: Using Xen interface\n");

    __restore_flags(flags);

    return &pci_direct_confx;
}

struct pci_fixup pcibios_fixups[] = { {0}};


struct irq_routing_table * __devinit pcibios_get_irq_routing_table(void)
{
    return NULL;
}

int pcibios_set_irq_routing(struct pci_dev *dev, int pin, int irq)
{
    return 0;
}

/*
 * Several buggy motherboards address only 16 devices and mirror
 * them to next 16 IDs. We try to detect this `feature' on all
 * primary buses (those containing host bridges as they are
 * expected to be unique) and remove the ghost devices.
 */

static void __devinit pcibios_fixup_ghosts(struct pci_bus *b)
{
    struct list_head *ln, *mn;
    struct pci_dev *d, *e;
    int mirror = PCI_DEVFN(16,0);
    int seen_host_bridge = 0;
    int i;

    DBG("PCI: Scanning for ghost devices on bus %d\n", b->number);
    for (ln=b->devices.next; ln != &b->devices; ln=ln->next) {
        d = pci_dev_b(ln);
        if ((d->class >> 8) == PCI_CLASS_BRIDGE_HOST)
            seen_host_bridge++;
        for (mn=ln->next; mn != &b->devices; mn=mn->next) {
            e = pci_dev_b(mn);
            if (e->devfn != d->devfn + mirror ||
                e->vendor != d->vendor ||
                e->device != d->device ||
                e->class != d->class)
                continue;
            for(i=0; i<PCI_NUM_RESOURCES; i++)
                if (e->resource[i].start != d->resource[i].start ||
                    e->resource[i].end != d->resource[i].end ||
                    e->resource[i].flags != d->resource[i].flags)
                    continue;
            break;
        }
        if (mn == &b->devices)
            return;
    }
    if (!seen_host_bridge)
        return;
    printk(KERN_WARNING "PCI: Ignoring ghost devices on bus %02x\n", b->number);

    ln = &b->devices;
    while (ln->next != &b->devices) {
        d = pci_dev_b(ln->next);
        if (d->devfn >= mirror) {
            list_del(&d->global_list);
            list_del(&d->bus_list);
            kfree(d);
        } else
            ln = ln->next;
    }
}

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void __devinit pcibios_fixup_peer_bridges(void)
{
    int n;
    struct pci_bus bus;
    struct pci_dev dev;
    u16 l;
    
    if (pcibios_last_bus <= 0 || pcibios_last_bus >= 0xff)
        return;
    DBG("PCI: Peer bridge fixup\n");
    for (n=0; n <= pcibios_last_bus; n++) {
        if (pci_bus_exists(&pci_root_buses, n))
            continue;
        bus.number = n;
        bus.ops = pci_root_ops;
        dev.bus = &bus;
        for(dev.devfn=0; dev.devfn<256; dev.devfn += 8)
            if (!pci_read_config_word(&dev, PCI_VENDOR_ID, &l) &&
                l != 0x0000 && l != 0xffff) {
                DBG("Found device at %02x:%02x [%04x]\n", n, dev.devfn, l);
                printk(KERN_INFO "PCI: Discovered peer bus %02x\n", n);
                pci_scan_bus(n, pci_root_ops, NULL);
                break;
            }
    }
}


/*
 *  Called after each bus is probed, but before its children
 *  are examined.
 */

void __devinit  pcibios_fixup_bus(struct pci_bus *b)
{
    pcibios_fixup_ghosts(b);
    pci_read_bridge_bases(b);
    return;
}

struct pci_bus * __devinit pcibios_scan_root(int busnum)
{
    struct list_head *list;
    struct pci_bus *bus;

    list_for_each(list, &pci_root_buses) {
        bus = pci_bus_b(list);
        if (bus->number == busnum) {
            /* Already scanned */
            return bus;
        }
    }

    printk("PCI: Probing PCI hardware (bus %02x)\n", busnum);

    return pci_scan_bus(busnum, pci_root_ops, NULL);
}

void __devinit pcibios_config_init(void)
{
    /*
     * Try all known PCI access methods. Note that we support using 
     * both PCI BIOS and direct access, with a preference for direct.
     */

    pci_root_ops = pci_check_xen();
    pci_config_read = pci_confx_read;
    pci_config_write = pci_confx_write;

    return;
}

void __init pcibios_init(void)
{
    if (!pci_root_ops)
        pcibios_config_init();
    if (!pci_root_ops) {
        printk(KERN_WARNING "PCI: System does not support PCI\n");
        return;
    }

    pcibios_set_cacheline_size();

    printk(KERN_INFO "PCI: Probing PCI hardware\n");

    if (!pci_using_acpi_prt) {
        pci_root_bus = pcibios_scan_root(0);
        pcibios_irq_init();
        pcibios_fixup_peer_bridges();
        pcibios_fixup_irqs();
    }

    pcibios_resource_survey();
}

char * __devinit  pcibios_setup(char *str)
{
    if (!strcmp(str, "off")) {
        pci_probe = 0;
        return NULL;
    }
    return NULL;
}

unsigned int pcibios_assign_all_busses(void)
{
    return (pci_probe & PCI_ASSIGN_ALL_BUSSES) ? 1 : 0;
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
    int err;

    if ((err = pcibios_enable_resources(dev, mask)) < 0)
        return err;

    pcibios_enable_irq(dev);

    return 0;
}
