/*
 * pci.c - Low-Level PCI Access in IA-64
 *
 * Derived from bios32.c of i386 tree.
 *
 * (c) Copyright 2002, 2005 Hewlett-Packard Development Company, L.P.
 *  David Mosberger-Tang <davidm@hpl.hp.com>
 * Bjorn Helgaas <bjorn.helgaas@hp.com>
 * Copyright (C) 2004 Silicon Graphics, Inc.
 *
 * Note: Above list of copyright holders is incomplete...
 */

#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/spinlock.h>

#include <asm/io.h>
#include <asm/sal.h>
#include <asm/hw_irq.h>

/*
 * Low-level SAL-based PCI configuration access functions. Note that SAL
 * calls are already serialized (via sal_lock), so we don't need another
 * synchronization mechanism here.
 */

#define PCI_SAL_ADDRESS(seg, bus, devfn, reg)       \
    (((u64) seg << 24) | (bus << 16) | (devfn << 8) | (reg))

/* SAL 3.2 adds support for extended config space. */

#define PCI_SAL_EXT_ADDRESS(seg, bus, devfn, reg)   \
    (((u64) seg << 28) | (bus << 20) | (devfn << 12) | (reg))

static int
pci_sal_read (unsigned int seg, unsigned int bus, unsigned int devfn,
        int reg, int len, u32 *value)
{
    u64 addr, data = 0;
    int mode, result;

    if (!value || (seg > 65535) || (bus > 255) || (devfn > 255) || (reg > 4095))
        return -EINVAL;

    if ((seg | reg) <= 255) {
        addr = PCI_SAL_ADDRESS(seg, bus, devfn, reg);
        mode = 0;
    } else {
        addr = PCI_SAL_EXT_ADDRESS(seg, bus, devfn, reg);
        mode = 1;
    }
    result = ia64_sal_pci_config_read(addr, mode, len, &data);
    if (result != 0)
        return -EINVAL;

    *value = (u32) data;
    return 0;
}

static int
pci_sal_write (unsigned int seg, unsigned int bus, unsigned int devfn,
        int reg, int len, u32 value)
{
    u64 addr;
    int mode, result;

    if ((seg > 65535) || (bus > 255) || (devfn > 255) || (reg > 4095))
        return -EINVAL;

    if ((seg | reg) <= 255) {
        addr = PCI_SAL_ADDRESS(seg, bus, devfn, reg);
        mode = 0;
    } else {
        addr = PCI_SAL_EXT_ADDRESS(seg, bus, devfn, reg);
        mode = 1;
    }
    result = ia64_sal_pci_config_write(addr, mode, len, value);
    if (result != 0)
        return -EINVAL;
    return 0;
}


uint8_t pci_conf_read8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    uint32_t value;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_read(0, bus, (dev<<3)|func, reg, 1, &value);
    return (uint8_t)value;
}

uint16_t pci_conf_read16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    uint32_t value;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_read(0, bus, (dev<<3)|func, reg, 2, &value);
    return (uint16_t)value;
}

uint32_t pci_conf_read32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg)
{
    uint32_t value;
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_read(0, bus, (dev<<3)|func, reg, 4, &value);
    return (uint32_t)value;
}

void pci_conf_write8(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint8_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_write(0, bus, (dev<<3)|func, reg, 1, data);
}

void pci_conf_write16(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint16_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_write(0, bus, (dev<<3)|func, reg, 2, data);
}

void pci_conf_write32(
    unsigned int bus, unsigned int dev, unsigned int func, unsigned int reg,
    uint32_t data)
{
    BUG_ON((bus > 255) || (dev > 31) || (func > 7) || (reg > 255));
    pci_sal_write(0, bus, (dev<<3)|func, reg, 4, data);
}

int pci_find_ext_capability(int seg, int bus, int devfn, int cap)
{
    return 0;
}
