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

#include <xen/mm.h>
#include <xen/acpi.h>
#include <xen/xmalloc.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <asm/e820.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

#include "mmconfig.h"

static int __initdata known_bridge;
unsigned int pci_probe = PCI_PROBE_CONF1 | PCI_PROBE_MMCONF;

static const char __init *pci_mmcfg_e7520(void)
{
    u32 win;
    win = pci_conf_read16(0, 0, 0, 0xce);

    win = win & 0xf000;
    if(win == 0x0000 || win == 0xf000)
        pci_mmcfg_config_num = 0;
    else {
        pci_mmcfg_config_num = 1;
        pci_mmcfg_config = xmalloc_bytes(sizeof(pci_mmcfg_config[0]));
        if (!pci_mmcfg_config)
            return NULL;
        memset(pci_mmcfg_config, 0, sizeof(pci_mmcfg_config[0]));
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

        pciexbar = pci_conf_read32(0, 0, 0, 0x48);

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
        pci_mmcfg_config = xmalloc_bytes(sizeof(pci_mmcfg_config[0]));
        if (!pci_mmcfg_config)
            return NULL;
        memset(pci_mmcfg_config, 0, sizeof(pci_mmcfg_config[0]));
        pci_mmcfg_config[0].address = pciexbar & mask;
        pci_mmcfg_config[0].pci_segment = 0;
        pci_mmcfg_config[0].start_bus_number = 0;
        pci_mmcfg_config[0].end_bus_number = (len >> 20) - 1;
    }

    return "Intel Corporation 945G/GZ/P/PL Express Memory Controller Hub";
}

static const char __init *pci_mmcfg_amd_fam10h(void)
{
    u32 low, high, address;
    u64 base, msr;
    int i;
    unsigned segnbits = 0, busnbits;

    if (!(pci_probe & PCI_CHECK_ENABLE_AMD_MMCONF))
        return NULL;

    address = MSR_FAM10H_MMIO_CONF_BASE;
    if (rdmsr_safe(address, low, high))
        return NULL;

    msr = high;
    msr <<= 32;
    msr |= low;

    /* mmconfig is not enable */
    if (!(msr & FAM10H_MMIO_CONF_ENABLE))
        return NULL;

    base = msr & (FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT);

    busnbits = (msr >> FAM10H_MMIO_CONF_BUSRANGE_SHIFT) &
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
    pci_mmcfg_config = xmalloc_bytes(sizeof(pci_mmcfg_config[0]) *
                                     pci_mmcfg_config_num);
    if (!pci_mmcfg_config)
        return NULL;

    for (i = 0; i < (1 << segnbits); i++) {
        pci_mmcfg_config[i].address = base + (1<<28) * i;
        pci_mmcfg_config[i].pci_segment = i;
        pci_mmcfg_config[i].start_bus_number = 0;
        pci_mmcfg_config[i].end_bus_number = (1 << busnbits) - 1;
    }

    return "AMD Family 10h NB";
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
        l = pci_conf_read32(bus, PCI_SLOT(devfn), PCI_FUNC(devfn), 0);
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

typedef int (*check_reserved_t)(u64 start, u64 end, unsigned type);

static int __init is_mmconf_reserved(
    check_reserved_t is_reserved,
    u64 addr, u64 size, int i,
    typeof(pci_mmcfg_config[0]) *cfg, int with_e820)
{
    u64 old_size = size;
    int valid = 0;

    while (!is_reserved(addr, addr + size - 1, E820_RESERVED)) {
        size >>= 1;
        if (size < (16UL<<20))
            break;
    }

    if (size >= (16UL<<20) || size == old_size) {
        printk(KERN_NOTICE
               "PCI: MCFG area at %lx reserved in %s\n",
                addr, with_e820?"E820":"ACPI motherboard resources");
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

static void __init pci_mmcfg_reject_broken(int early)
{
    typeof(pci_mmcfg_config[0]) *cfg;
    int i;

    if ((pci_mmcfg_config_num == 0) ||
        (pci_mmcfg_config == NULL) ||
        (pci_mmcfg_config[0].address == 0))
        return;

    cfg = &pci_mmcfg_config[0];

    for (i = 0; i < pci_mmcfg_config_num; i++) {
        int valid = 0;
        u64 addr, size;

        cfg = &pci_mmcfg_config[i];
        addr = cfg->start_bus_number;
        addr <<= 20;
        addr += cfg->address;
        size = cfg->end_bus_number + 1 - cfg->start_bus_number;
        size <<= 20;
        printk(KERN_NOTICE "PCI: MCFG configuration %d: base %lx "
               "segment %hu buses %u - %u\n",
               i, (unsigned long)cfg->address, cfg->pci_segment,
               (unsigned int)cfg->start_bus_number,
               (unsigned int)cfg->end_bus_number);

        if (valid)
            continue;

        if (!early)
            printk(KERN_ERR "PCI: BIOS Bug: MCFG area at %lx is not"
                   " reserved in ACPI motherboard resources\n",
                   cfg->address);

        valid = is_mmconf_reserved(e820_all_mapped, addr, size, i, cfg, 1);

        if (!valid)
            goto reject;
    }

    return;

reject:
    printk(KERN_INFO "PCI: Not using MMCONFIG.\n");
    pci_mmcfg_arch_free();
    xfree(pci_mmcfg_config);
    pci_mmcfg_config = NULL;
    pci_mmcfg_config_num = 0;
}

void __init __pci_mmcfg_init(int early)
{
    /* MMCONFIG disabled */
    if ((pci_probe & PCI_PROBE_MMCONF) == 0)
        return;

    /* MMCONFIG already enabled */
    if (!early && !(pci_probe & PCI_PROBE_MASK & ~PCI_PROBE_MMCONF))
        return;

    /* for late to exit */
    if (known_bridge)
        return;

    if (early) {
        if (pci_mmcfg_check_hostbridge())
            known_bridge = 1;
    }

    if (!known_bridge) {
        acpi_table_parse(ACPI_SIG_MCFG, acpi_parse_mcfg);
        pci_mmcfg_reject_broken(early);
    }

    if ((pci_mmcfg_config_num == 0) ||
        (pci_mmcfg_config == NULL) ||
        (pci_mmcfg_config[0].address == 0))
        return;

    if (pci_mmcfg_arch_init()) {
        pci_probe = (pci_probe & ~PCI_PROBE_MASK) | PCI_PROBE_MMCONF;
    }
}

void acpi_mmcfg_init(void)
{
    __pci_mmcfg_init(1);
}

/**
 * pci_find_ext_capability - Find an extended capability
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.  Possible values for @cap:
 *
 *  %PCI_EXT_CAP_ID_ERR         Advanced Error Reporting
 *  %PCI_EXT_CAP_ID_VC          Virtual Channel
 *  %PCI_EXT_CAP_ID_DSN         Device Serial Number
 *  %PCI_EXT_CAP_ID_PWR         Power Budgeting
 */
int pci_find_ext_capability(int seg, int bus, int devfn, int cap)
{
    u32 header;
    int ttl = 480; /* 3840 bytes, minimum 8 bytes per capability */
    int pos = 0x100;

    header = pci_conf_read32(bus, PCI_SLOT(devfn), PCI_FUNC(devfn), pos);

    /*
     * If we have no capabilities, this is indicated by cap ID,
     * cap version and next pointer all being 0.
     */
    if ( (header == 0) || (header == -1) )
    {
        dprintk(XENLOG_INFO VTDPREFIX,
                "next cap:%x:%x.%x:  no extended config\n",
                bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        return 0;
    }

    while ( ttl-- > 0 ) {
        if ( PCI_EXT_CAP_ID(header) == cap )
            return pos;
        pos = PCI_EXT_CAP_NEXT(header);
        if ( pos < 0x100 )
            break;
        header = pci_conf_read32(bus, PCI_SLOT(devfn), PCI_FUNC(devfn), pos);
    }
    return 0;
}
