/*
 * mmconfig.c - Low-level direct PCI config space access via MMCONFIG
 *
 * This is an 64bit optimized version that always keeps the full mmconfig
 * space mapped. This allows lockless config space operation.
 *
 * copied from Linux
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/acpi.h>
#include <xen/xmalloc.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>

#include "mmconfig.h"

/* Static virtual mapping of the MMCONFIG aperture */
struct mmcfg_virt {
    struct acpi_mcfg_allocation *cfg;
    char __iomem *virt;
};
static struct mmcfg_virt *pci_mmcfg_virt;
static int __initdata mmcfg_pci_segment_shift;

static char __iomem *get_virt(unsigned int seg, unsigned bus)
{
    struct acpi_mcfg_allocation *cfg;
    int cfg_num;

    for (cfg_num = 0; cfg_num < pci_mmcfg_config_num; cfg_num++) {
        cfg = pci_mmcfg_virt[cfg_num].cfg;
        if (cfg->pci_segment == seg &&
            (cfg->start_bus_number <= bus) &&
            (cfg->end_bus_number >= bus))
            return pci_mmcfg_virt[cfg_num].virt;
    }

    /* Fall back to type 0 */
    return NULL;
}

static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus, unsigned int devfn)
{
    char __iomem *addr;

    addr = get_virt(seg, bus);
    if (!addr)
        return NULL;
     return addr + ((bus << 20) | (devfn << 12));
}

int pci_mmcfg_read(unsigned int seg, unsigned int bus,
              unsigned int devfn, int reg, int len, u32 *value)
{
    char __iomem *addr;

    /* Why do we have this when nobody checks it. How about a BUG()!? -AK */
    if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095))) {
err:        *value = -1;
        return -EINVAL;
    }

    addr = pci_dev_base(seg, bus, devfn);
    if (!addr)
        goto err;

    switch (len) {
    case 1:
        *value = mmio_config_readb(addr + reg);
        break;
    case 2:
        *value = mmio_config_readw(addr + reg);
        break;
    case 4:
        *value = mmio_config_readl(addr + reg);
        break;
    }

    return 0;
}

int pci_mmcfg_write(unsigned int seg, unsigned int bus,
               unsigned int devfn, int reg, int len, u32 value)
{
    char __iomem *addr;

    /* Why do we have this when nobody checks it. How about a BUG()!? -AK */
    if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095)))
        return -EINVAL;

    addr = pci_dev_base(seg, bus, devfn);
    if (!addr)
        return -EINVAL;

    switch (len) {
    case 1:
        mmio_config_writeb(addr + reg, value);
        break;
    case 2:
        mmio_config_writew(addr + reg, value);
        break;
    case 4:
        mmio_config_writel(addr + reg, value);
        break;
    }

    return 0;
}

static void __iomem * __init mcfg_ioremap(struct acpi_mcfg_allocation *cfg)
{
    unsigned long virt, size;

    virt = PCI_MCFG_VIRT_START +
           ((unsigned long)cfg->pci_segment << mmcfg_pci_segment_shift) +
           (cfg->start_bus_number << 20);
    size = (cfg->end_bus_number - cfg->start_bus_number + 1) << 20;
    if (virt + size < virt || virt + size > PCI_MCFG_VIRT_END)
        return NULL;

    map_pages_to_xen(virt, cfg->address >> PAGE_SHIFT,
                     size >> PAGE_SHIFT, PAGE_HYPERVISOR_NOCACHE);

    return (void __iomem *) virt;
}

int __init pci_mmcfg_arch_init(void)
{
    int i;

    pci_mmcfg_virt = xmalloc_array(struct mmcfg_virt, pci_mmcfg_config_num);
    if (pci_mmcfg_virt == NULL) {
        printk(KERN_ERR "PCI: Can not allocate memory for mmconfig structures\n");
        return 0;
    }
    memset(pci_mmcfg_virt, 0, sizeof(*pci_mmcfg_virt) * pci_mmcfg_config_num);

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        pci_mmcfg_virt[i].cfg = &pci_mmcfg_config[i];
        while (pci_mmcfg_config[i].end_bus_number >> mmcfg_pci_segment_shift)
            ++mmcfg_pci_segment_shift;
    }
    mmcfg_pci_segment_shift += 20;
    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        pci_mmcfg_virt[i].virt = mcfg_ioremap(&pci_mmcfg_config[i]);
        if (!pci_mmcfg_virt[i].virt) {
            printk(KERN_ERR "PCI: Cannot map mmconfig aperture for "
                    "segment %d\n",
                pci_mmcfg_config[i].pci_segment);
            pci_mmcfg_arch_free();
            return 0;
        }
    }
    return 1;
}

void __init pci_mmcfg_arch_free(void)
{
    int i;

    if (pci_mmcfg_virt == NULL)
        return;

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        if (pci_mmcfg_virt[i].virt) {
            iounmap(pci_mmcfg_virt[i].virt);
            pci_mmcfg_virt[i].virt = NULL;
            pci_mmcfg_virt[i].cfg = NULL;
        }
    }

    xfree(pci_mmcfg_virt);
    pci_mmcfg_virt = NULL;
}
