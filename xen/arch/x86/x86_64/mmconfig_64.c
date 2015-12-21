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
#include <xen/iommu.h>
#include <xen/rangeset.h>

#include "mmconfig.h"

/* Static virtual mapping of the MMCONFIG aperture */
struct mmcfg_virt {
    struct acpi_mcfg_allocation *cfg;
    char __iomem *virt;
};
static struct mmcfg_virt *pci_mmcfg_virt;
static unsigned int mmcfg_pci_segment_shift;

static char __iomem *get_virt(unsigned int seg, unsigned int *bus)
{
    struct acpi_mcfg_allocation *cfg;
    int cfg_num;

    for (cfg_num = 0; cfg_num < pci_mmcfg_config_num; cfg_num++) {
        cfg = pci_mmcfg_virt[cfg_num].cfg;
        if (cfg->pci_segment == seg &&
            (cfg->start_bus_number <= *bus) &&
            (cfg->end_bus_number >= *bus)) {
            *bus -= cfg->start_bus_number;
            return pci_mmcfg_virt[cfg_num].virt;
        }
    }

    /* Fall back to type 0 */
    return NULL;
}

static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus, unsigned int devfn)
{
    char __iomem *addr;

    addr = get_virt(seg, &bus);
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

static void __iomem *mcfg_ioremap(const struct acpi_mcfg_allocation *cfg,
                                  unsigned long idx, unsigned int prot)
{
    unsigned long virt, size;

    virt = PCI_MCFG_VIRT_START + (idx << mmcfg_pci_segment_shift) +
           (cfg->start_bus_number << 20);
    size = (cfg->end_bus_number - cfg->start_bus_number + 1) << 20;
    if (virt + size < virt || virt + size > PCI_MCFG_VIRT_END)
        return NULL;

    if (map_pages_to_xen(virt,
                         (cfg->address >> PAGE_SHIFT) +
                         (cfg->start_bus_number << (20 - PAGE_SHIFT)),
                         size >> PAGE_SHIFT, prot))
        return NULL;

    return (void __iomem *) virt;
}

int pci_mmcfg_arch_enable(unsigned int idx)
{
    const typeof(pci_mmcfg_config[0]) *cfg = pci_mmcfg_virt[idx].cfg;
    unsigned long start_mfn, end_mfn;

    if (pci_mmcfg_virt[idx].virt)
        return 0;
    pci_mmcfg_virt[idx].virt = mcfg_ioremap(cfg, idx, PAGE_HYPERVISOR_NOCACHE);
    if (!pci_mmcfg_virt[idx].virt) {
        printk(KERN_ERR "PCI: Cannot map MCFG aperture for segment %04x\n",
               cfg->pci_segment);
        return -ENOMEM;
    }
    printk(KERN_INFO "PCI: Using MCFG for segment %04x bus %02x-%02x\n",
           cfg->pci_segment, cfg->start_bus_number, cfg->end_bus_number);

    start_mfn = PFN_DOWN(cfg->address) + PCI_BDF(cfg->start_bus_number, 0, 0);
    end_mfn = PFN_DOWN(cfg->address) + PCI_BDF(cfg->end_bus_number, ~0, ~0);
    if ( rangeset_add_range(mmio_ro_ranges, start_mfn, end_mfn) )
        printk(XENLOG_ERR
               "%04x:%02x-%02x: could not mark MCFG (mfns %lx-%lx) read-only\n",
               cfg->pci_segment, cfg->start_bus_number, cfg->end_bus_number,
               start_mfn, end_mfn);

    return 0;
}

void pci_mmcfg_arch_disable(unsigned int idx)
{
    const typeof(pci_mmcfg_config[0]) *cfg = pci_mmcfg_virt[idx].cfg;

    pci_mmcfg_virt[idx].virt = NULL;
    /*
     * Don't use destroy_xen_mappings() here, or make sure that at least
     * the necessary L4 entries get populated (so that they get properly
     * propagated to guest domains' page tables).
     */
    mcfg_ioremap(cfg, idx, 0);
    printk(KERN_WARNING "PCI: Not using MCFG for segment %04x bus %02x-%02x\n",
           cfg->pci_segment, cfg->start_bus_number, cfg->end_bus_number);
}

bool_t pci_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                        unsigned int *bdf)
{
    unsigned int idx;

    for (idx = 0; idx < pci_mmcfg_config_num; ++idx) {
        const struct acpi_mcfg_allocation *cfg = pci_mmcfg_virt[idx].cfg;

        if (pci_mmcfg_virt[idx].virt &&
            mfn >= PFN_DOWN(cfg->address) + PCI_BDF(cfg->start_bus_number,
                                                    0, 0) &&
            mfn <= PFN_DOWN(cfg->address) + PCI_BDF(cfg->end_bus_number,
                                                    ~0, ~0)) {
            *seg = cfg->pci_segment;
            *bdf = mfn - PFN_DOWN(cfg->address);
            return 1;
        }
    }

    return 0;
}

bool_t pci_ro_mmcfg_decode(unsigned long mfn, unsigned int *seg,
                           unsigned int *bdf)
{
    const unsigned long *ro_map;

    return pci_mmcfg_decode(mfn, seg, bdf) &&
           ((ro_map = pci_get_ro_map(*seg)) == NULL ||
             !test_bit(*bdf, ro_map));
}

int __init pci_mmcfg_arch_init(void)
{
    int i;

    if (pci_mmcfg_virt)
        return 0;

    pci_mmcfg_virt = xzalloc_array(struct mmcfg_virt, pci_mmcfg_config_num);
    if (pci_mmcfg_virt == NULL) {
        printk(KERN_ERR "PCI: Can not allocate memory for mmconfig structures\n");
        pci_mmcfg_config_num = 0;
        return 0;
    }

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        pci_mmcfg_virt[i].cfg = &pci_mmcfg_config[i];
        while (pci_mmcfg_config[i].end_bus_number >> mmcfg_pci_segment_shift)
            ++mmcfg_pci_segment_shift;
    }
    mmcfg_pci_segment_shift += 20;
    return 1;
}
