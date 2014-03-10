/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Author: Allen Kay <allen.m.kay@intel.com> - adapted from linux
 */

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

/* external variable defines */
extern int pci_mmcfg_config_num;
extern struct acpi_mcfg_allocation *pci_mmcfg_config;

/* function prototypes */
int acpi_parse_mcfg(struct acpi_table_header *header);
int pci_mmcfg_reserved(uint64_t address, unsigned int segment,
                       unsigned int start_bus, unsigned int end_bus,
                       unsigned int flags);
int pci_mmcfg_arch_init(void);
int pci_mmcfg_arch_enable(unsigned int);
void pci_mmcfg_arch_disable(unsigned int);
