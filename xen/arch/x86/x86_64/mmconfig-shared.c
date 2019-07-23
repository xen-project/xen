/*
 * mmconfig-shared.c - Low-level direct PCI config space access via
 *                     MMCONFIG - common code between i386 and x86-64.
 *
 * This code does:
 * - known chipset handling
 * - ACPI decoding and validation
 *
 * Per-architecture code takes care of the mappings and accesses
 * themselves.
 *
 * Author: Allen Kay <allen.m.kay@intel.com> -  adapted to xen from Linux
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/acpi.h>
#include <xen/xmalloc.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/pci_ids.h>
#include <asm/e820.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <public/physdev.h>

#include "mmconfig.h"

unsigned int pci_probe = PCI_PROBE_CONF1 | PCI_PROBE_MMCONF;

static int __init parse_mmcfg(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        switch ( parse_bool(s, ss) )
        {
        case 0:
            pci_probe &= ~PCI_PROBE_MMCONF;
            break;
        case 1:
            break;
        default:
            if ( !cmdline_strcmp(s, "amd_fam10") ||
                 !cmdline_strcmp(s, "amd-fam10") )
                pci_probe |= PCI_CHECK_ENABLE_AMD_MMCONF;
            else
                rc = -EINVAL;
            break;
        }

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("mmcfg", parse_mmcfg);

static const char __init *pci_mmcfg_e7520(void)
{
    u32 win;
    win = pci_conf_read16(PCI_SBDF(0, 0, 0, 0), 0xce);

    win = win & 0xf000;
    if(win == 0x0000 || win == 0xf000)
        pci_mmcfg_config_num = 0;
    else {
        pci_mmcfg_config_num = 1;
        pci_mmcfg_config = xzalloc(struct acpi_mcfg_allocation);
        if (!pci_mmcfg_config)
            return NULL;
        pci_mmcfg_config[0].address = win << 16;
        pci_mmcfg_config[0].pci_segment = 0;
        pci_mmcfg_config[0].start_bus_number = 0;
        pci_mmcfg_config[0].end_bus_number = 255;
    }

    return "Intel Corporation E7520 Memory Controller Hub";
}

static const char __init *pci_mmcfg_intel_945(void)
{
    u32 pciexbar, mask = 0, len = 0;

    pci_mmcfg_config_num = 1;

    pciexbar = pci_conf_read32(PCI_SBDF(0, 0, 0, 0), 0x48);

    /* Enable bit */
    if (!(pciexbar & 1))
        pci_mmcfg_config_num = 0;

    /* Size bits */
    switch ((pciexbar >> 1) & 3) {
    case 0:
        mask = 0xf0000000U;
        len  = 0x10000000U;
        break;
    case 1:
        mask = 0xf8000000U;
        len  = 0x08000000U;
        break;
    case 2:
        mask = 0xfc000000U;
        len  = 0x04000000U;
        break;
    default:
        pci_mmcfg_config_num = 0;
    }

    /* Errata #2, things break when not aligned on a 256Mb boundary */
    /* Can only happen in 64M/128M mode */

    if ((pciexbar & mask) & 0x0fffffffU)
        pci_mmcfg_config_num = 0;

    /* Don't hit the APIC registers and their friends */
    if ((pciexbar & mask) >= 0xf0000000U)
        pci_mmcfg_config_num = 0;

    if (pci_mmcfg_config_num) {
        pci_mmcfg_config = xzalloc(struct acpi_mcfg_allocation);
        if (!pci_mmcfg_config)
            return NULL;
        pci_mmcfg_config[0].address = pciexbar & mask;
        pci_mmcfg_config[0].pci_segment = 0;
        pci_mmcfg_config[0].start_bus_number = 0;
        pci_mmcfg_config[0].end_bus_number = (len >> 20) - 1;
    }

    return "Intel Corporation 945G/GZ/P/PL Express Memory Controller Hub";
}

static const char __init *pci_mmcfg_amd_fam10h(void)
{
    uint32_t address;
    uint64_t base, msr_content;
    int i;
    unsigned segnbits = 0, busnbits;

    if (!(pci_probe & PCI_CHECK_ENABLE_AMD_MMCONF))
        return NULL;

    address = MSR_FAM10H_MMIO_CONF_BASE;
    if (rdmsr_safe(address, msr_content))
        return NULL;

    /* mmconfig is not enable */
    if (!(msr_content & FAM10H_MMIO_CONF_ENABLE))
        return NULL;

    base = msr_content &
        (FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT);

    busnbits = (msr_content >> FAM10H_MMIO_CONF_BUSRANGE_SHIFT) &
                FAM10H_MMIO_CONF_BUSRANGE_MASK;

    /*
     * only handle bus 0 ?
     * need to skip it
     */
    if (!busnbits)
        return NULL;

    if (busnbits > 8) {
        segnbits = busnbits - 8;
        busnbits = 8;
    }

    pci_mmcfg_config_num = (1 << segnbits);
    pci_mmcfg_config = xmalloc_array(struct acpi_mcfg_allocation,
                                     pci_mmcfg_config_num);
    if (!pci_mmcfg_config)
        return NULL;

    for (i = 0; i < (1 << segnbits); i++) {
        pci_mmcfg_config[i].address = base + ((unsigned long)i << 28);
        pci_mmcfg_config[i].pci_segment = i;
        pci_mmcfg_config[i].start_bus_number = 0;
        pci_mmcfg_config[i].end_bus_number = (1 << busnbits) - 1;
        pci_add_segment(i);
    }

    return "AMD Family 10h NB";
}

static const char __init *pci_mmcfg_nvidia_mcp55(void)
{
    static bool_t __initdata mcp55_checked;
    int bus, i;

    static const u32 extcfg_regnum      = 0x90;
    static const u32 extcfg_enable_mask = 1u << 31;
    static const u32 extcfg_start_mask  = 0xffu << 16;
    static const int extcfg_start_shift = 16;
    static const u32 extcfg_size_mask   = 3u << 28;
    static const int extcfg_size_shift  = 28;
    static const int extcfg_sizebus[]   = {0xff, 0x7f, 0x3f, 0x1f};
    static const u32 extcfg_base_mask[] = {0x7ff8, 0x7ffc, 0x7ffe, 0x7fff};
    static const int extcfg_base_lshift = 25;

    /* check if amd fam10h already took over */
    if (!acpi_disabled || pci_mmcfg_config_num || mcp55_checked)
        return NULL;

    mcp55_checked = 1;
    for (i = bus = 0; bus < 256; bus++) {
        u32 l, extcfg;
        u16 vendor, device;

        l = pci_conf_read32(PCI_SBDF(0, bus, 0, 0), 0);
        vendor = l & 0xffff;
        device = (l >> 16) & 0xffff;

        if (PCI_VENDOR_ID_NVIDIA != vendor || 0x0369 != device)
            continue;

        extcfg = pci_conf_read32(PCI_SBDF(0, bus, 0, 0), extcfg_regnum);

        if (extcfg & extcfg_enable_mask)
            i++;
    }

    if (!i)
        return NULL;

    pci_mmcfg_config_num = i;
    pci_mmcfg_config = xmalloc_array(struct acpi_mcfg_allocation,
                                     pci_mmcfg_config_num);

    for (i = bus = 0; bus < 256; bus++) {
        u64 base;
        u32 l, extcfg;
        u16 vendor, device;
        int size_index;

        l = pci_conf_read32(PCI_SBDF(0, bus, 0, 0), 0);
        vendor = l & 0xffff;
        device = (l >> 16) & 0xffff;

        if (PCI_VENDOR_ID_NVIDIA != vendor || 0x0369 != device)
            continue;

        extcfg = pci_conf_read32(PCI_SBDF(0, bus, 0, 0), extcfg_regnum);

        if (!(extcfg & extcfg_enable_mask))
            continue;

        if (i >= pci_mmcfg_config_num)
            break;

        size_index = (extcfg & extcfg_size_mask) >> extcfg_size_shift;
        base = extcfg & extcfg_base_mask[size_index];
        /* base could be > 4G */
        pci_mmcfg_config[i].address = base << extcfg_base_lshift;
        pci_mmcfg_config[i].pci_segment = 0;
        pci_mmcfg_config[i].start_bus_number =
            (extcfg & extcfg_start_mask) >> extcfg_start_shift;
        pci_mmcfg_config[i].end_bus_number =
            pci_mmcfg_config[i].start_bus_number + extcfg_sizebus[size_index];
        i++;
    }

    if (bus == 256)
        return "nVidia MCP55";

    pci_mmcfg_config_num = 0;
    xfree(pci_mmcfg_config);
    pci_mmcfg_config = NULL;

    return NULL;
}

struct pci_mmcfg_hostbridge_probe {
    u32 bus;
    u32 devfn;
    u32 vendor;
    u32 device;
    const char *(*probe)(void);
};

static struct pci_mmcfg_hostbridge_probe pci_mmcfg_probes[] __initdata = {
    { 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
      PCI_DEVICE_ID_INTEL_E7520_MCH, pci_mmcfg_e7520 },
    { 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
      PCI_DEVICE_ID_INTEL_82945G_HB, pci_mmcfg_intel_945 },
    { 0, PCI_DEVFN(0x18, 0), PCI_VENDOR_ID_AMD,
      0x1200, pci_mmcfg_amd_fam10h },
    { 0xff, PCI_DEVFN(0, 0), PCI_VENDOR_ID_AMD,
      0x1200, pci_mmcfg_amd_fam10h },
    { 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_NVIDIA,
      0x0369, pci_mmcfg_nvidia_mcp55 },
};

static int __init pci_mmcfg_check_hostbridge(void)
{
    u32 l;
    u32 bus, devfn;
    u16 vendor, device;
    int i;
    const char *name;

    pci_mmcfg_config_num = 0;
    pci_mmcfg_config = NULL;
    name = NULL;

    for (i = 0; !name && i < ARRAY_SIZE(pci_mmcfg_probes); i++) {
        bus =  pci_mmcfg_probes[i].bus;
        devfn = pci_mmcfg_probes[i].devfn;
        l = pci_conf_read32(PCI_SBDF3(0, bus, devfn), 0);
        vendor = l & 0xffff;
        device = (l >> 16) & 0xffff;

        if (pci_mmcfg_probes[i].vendor == vendor &&
            pci_mmcfg_probes[i].device == device)
            name = pci_mmcfg_probes[i].probe();
    }

    if (name) {
        printk(KERN_INFO "PCI: Found %s %s MMCONFIG support.\n",
            name, pci_mmcfg_config_num ? "with" : "without");
    }

    return name != NULL;
}

static int __init is_mmconf_reserved(
    u64 addr, u64 size, int i,
    typeof(pci_mmcfg_config[0]) *cfg)
{
    u64 old_size = size;
    int valid = 0;

    while (!e820_all_mapped(addr, addr + size - 1, E820_RESERVED)) {
        size >>= 1;
        if (size < (16UL<<20))
            break;
    }

    if (size >= (16UL<<20) || size == old_size) {
        printk(KERN_NOTICE "PCI: MCFG area at %lx reserved in E820\n", addr);
        valid = 1;

        if (old_size != size) {
            /* update end_bus_number */
            cfg->end_bus_number = cfg->start_bus_number + ((size>>20) - 1);
            printk(KERN_NOTICE "PCI: updated MCFG configuration %d: base %lx "
                   "segment %hu buses %u - %u\n",
                   i, (unsigned long)cfg->address, cfg->pci_segment,
                   (unsigned int)cfg->start_bus_number,
                   (unsigned int)cfg->end_bus_number);
        }
    }

    return valid;
}

static bool_t __init pci_mmcfg_reject_broken(void)
{
    typeof(pci_mmcfg_config[0]) *cfg;
    int i;
    bool_t valid = 1;

    if ((pci_mmcfg_config_num == 0) ||
        (pci_mmcfg_config == NULL) ||
        (pci_mmcfg_config[0].address == 0))
        return 0;

    for (i = 0; i < pci_mmcfg_config_num; i++) {
        u64 addr, size;

        cfg = &pci_mmcfg_config[i];
        addr = cfg->start_bus_number;
        addr <<= 20;
        addr += cfg->address;
        size = cfg->end_bus_number + 1 - cfg->start_bus_number;
        size <<= 20;
        printk(KERN_NOTICE "PCI: MCFG configuration %d: base %lx "
               "segment %04x buses %02x - %02x\n",
               i, (unsigned long)cfg->address, cfg->pci_segment,
               (unsigned int)cfg->start_bus_number,
               (unsigned int)cfg->end_bus_number);

        if (!is_mmconf_reserved(addr, size, i, cfg) ||
            pci_mmcfg_arch_enable(i)) {
            pci_mmcfg_arch_disable(i);
            valid = 0;
        }
    }

    return valid;
}

void __init acpi_mmcfg_init(void)
{
    bool_t valid = 1;

    pci_segments_init();

    /* MMCONFIG disabled */
    if ((pci_probe & PCI_PROBE_MMCONF) == 0)
        return;

    /* MMCONFIG already enabled */
    if (!(pci_probe & PCI_PROBE_MASK & ~PCI_PROBE_MMCONF))
        return;

    if (pci_mmcfg_check_hostbridge()) {
        unsigned int i;

        pci_mmcfg_arch_init();
        for (i = 0; i < pci_mmcfg_config_num; ++i)
            if (pci_mmcfg_arch_enable(i))
                valid = 0;
    } else {
        acpi_table_parse(ACPI_SIG_MCFG, acpi_parse_mcfg);
        pci_mmcfg_arch_init();
        valid = pci_mmcfg_reject_broken();
    }

    if ((pci_mmcfg_config_num == 0) ||
        (pci_mmcfg_config == NULL) ||
        (pci_mmcfg_config[0].address == 0))
        return;

    if (valid)
        pci_probe = (pci_probe & ~PCI_PROBE_MASK) | PCI_PROBE_MMCONF;
}

int pci_mmcfg_reserved(uint64_t address, unsigned int segment,
                       unsigned int start_bus, unsigned int end_bus,
                       unsigned int flags)
{
    unsigned int i;

    if (flags & ~XEN_PCI_MMCFG_RESERVED)
        return -EINVAL;

    for (i = 0; i < pci_mmcfg_config_num; ++i) {
        const typeof(pci_mmcfg_config[0]) *cfg = &pci_mmcfg_config[i];

        if (cfg->pci_segment == segment &&
            cfg->start_bus_number == start_bus &&
            cfg->end_bus_number == end_bus) {
            if (cfg->address != address) {
                printk(KERN_WARNING
                       "Base address presented for segment %04x bus %02x-%02x"
                       " (%08" PRIx64 ") does not match previously obtained"
                       " one (%08" PRIx64 ")\n",
                       segment, start_bus, end_bus, address, cfg->address);
                return -EIO;
            }
            if (flags & XEN_PCI_MMCFG_RESERVED)
                return pci_mmcfg_arch_enable(i);
            pci_mmcfg_arch_disable(i);
            return 0;
        }
    }

    return -ENODEV;
}
