/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * Author: Allen Kay <allen.m.kay@intel.com> - adapted from linux
 */

#ifndef X86_64_MMCONFIG_H
#define X86_64_MMCONFIG_H

#define PCI_DEVICE_ID_INTEL_E7520_MCH    0x3590
#define PCI_DEVICE_ID_INTEL_82945G_HB    0x2770

/* ioport ends */
#define PCI_PROBE_BIOS        0x0001
#define PCI_PROBE_CONF1        0x0002
#define PCI_PROBE_CONF2        0x0004
#define PCI_PROBE_MMCONF    0x0008
#define PCI_PROBE_MASK        0x000f
#define PCI_PROBE_NOEARLY    0x0010

#define PCI_CHECK_ENABLE_AMD_MMCONF     0x20000

extern unsigned int pci_probe;

/*
 * AMD Fam10h CPUs are buggy, and cannot access MMIO config space
 * on their northbrige except through the * %eax register. As such, you MUST
 * NOT use normal IOMEM accesses, you need to only use the magic mmio-config
 * accessor functions.
 * In fact just use pci_config_*, nothing else please.
 */
static inline unsigned char mmio_config_readb(void __iomem *pos)
{
    u8 val;
    asm volatile("movb (%1),%%al" : "=a" (val) : "r" (pos));
    return val;
}

static inline unsigned short mmio_config_readw(void __iomem *pos)
{
    u16 val;
    asm volatile("movw (%1),%%ax" : "=a" (val) : "r" (pos));
    return val;
}

static inline unsigned int mmio_config_readl(void __iomem *pos)
{
    u32 val;
    asm volatile("movl (%1),%%eax" : "=a" (val) : "r" (pos));
    return val;
}

static inline void mmio_config_writeb(void __iomem *pos, u8 val)
{
    asm volatile("movb %%al,(%1)" :: "a" (val), "r" (pos) : "memory");
}

static inline void mmio_config_writew(void __iomem *pos, u16 val)
{
    asm volatile("movw %%ax,(%1)" :: "a" (val), "r" (pos) : "memory");
}

static inline void mmio_config_writel(void __iomem *pos, u32 val)
{
    asm volatile("movl %%eax,(%1)" :: "a" (val), "r" (pos) : "memory");
}

/* function prototypes */
struct acpi_table_header;
int cf_check acpi_parse_mcfg(struct acpi_table_header *header);
int pci_mmcfg_reserved(uint64_t address, unsigned int segment,
                       unsigned int start_bus, unsigned int end_bus,
                       unsigned int flags);
int pci_mmcfg_arch_init(void);
int pci_mmcfg_arch_enable(unsigned int idx);
void pci_mmcfg_arch_disable(unsigned int idx);

#endif /* X86_64_MMCONFIG_H */
