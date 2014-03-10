/*
 * AMD Family 10h mmconfig enablement (taken from Linux 2.6.36)
 */

#include <xen/lib.h>
#include <xen/acpi.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/pci_ids.h>
#include <xen/init.h>
#include <xen/dmi.h>
#include <asm/amd.h>
#include <asm/e820.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include "mmconfig.h"

struct pci_hostbridge_probe {
	u32 bus;
	u32 slot;
	u32 vendor;
	u32 device;
};

static u64 __cpuinitdata fam10h_pci_mmconf_base;

static struct pci_hostbridge_probe pci_probes[] __cpuinitdata = {
	{ 0, 0x18, PCI_VENDOR_ID_AMD, 0x1200 },
	{ 0xff, 0, PCI_VENDOR_ID_AMD, 0x1200 },
};

#define UNIT (1ULL << FAM10H_MMIO_CONF_BASE_SHIFT)
#define MASK (~(UNIT - 1))
#define SIZE (UNIT << 8)
/* need to avoid (0xfd<<32) and (0xfe<<32), ht used space */
#define FAM10H_PCI_MMCONF_BASE (0xfcULL<<32)
#define BASE_VALID(b) ((b) + SIZE <= (0xfdULL<<32) || (b) >= (1ULL<<40))
static void __init get_fam10h_pci_mmconf_base(void)
{
	unsigned int i, j, bus, slot, hi_mmio_num;
	u32 address;
	u64 val, tom2, start, end;
	struct range {
		u64 start, end;
	} range[8];

	for (i = 0; i < ARRAY_SIZE(pci_probes); i++) {
		u32 id;
		u16 device;
		u16 vendor;

		bus = pci_probes[i].bus;
		slot = pci_probes[i].slot;
		id = pci_conf_read32(0, bus, slot, 0, PCI_VENDOR_ID);

		vendor = id & 0xffff;
		device = (id>>16) & 0xffff;
		if (pci_probes[i].vendor == vendor &&
		    pci_probes[i].device == device)
			break;
	}

	if (i >= ARRAY_SIZE(pci_probes))
		return;

	/* SYS_CFG */
	address = MSR_K8_SYSCFG;
	rdmsrl(address, val);

	/* TOP_MEM2 is not enabled? */
	if (!(val & (1<<21))) {
		tom2 = 1ULL << 32;
	} else {
		/* TOP_MEM2 */
		address = MSR_K8_TOP_MEM2;
		rdmsrl(address, val);
		tom2 = max(val & 0xffffff800000ULL, 1ULL << 32);
	}

	/*
	 * need to check if the range is in the high mmio range that is
	 * above 4G
	 */
	for (hi_mmio_num = i = 0; i < 8; i++) {
		val = pci_conf_read32(0, bus, slot, 1, 0x80 + (i << 3));
		if (!(val & 3))
			continue;

		start = (val & 0xffffff00) << 8; /* 39:16 on 31:8*/
		val = pci_conf_read32(0, bus, slot, 1, 0x84 + (i << 3));
		end = ((val & 0xffffff00) << 8) | 0xffff; /* 39:16 on 31:8*/

		if (end < tom2)
			continue;

		for (j = hi_mmio_num; j; --j) {
			if (range[j - 1].start < start)
				break;
			range[j] = range[j - 1];
		}
		range[j].start = start;
		range[j].end = end;
		hi_mmio_num++;
	}

	start = FAM10H_PCI_MMCONF_BASE;
	if (start <= tom2)
		start = (tom2 + 2 * UNIT - 1) & MASK;

	if (!hi_mmio_num)
		goto out;

	if (range[hi_mmio_num - 1].end < start)
		goto out;
	if (range[0].start > start + SIZE)
		goto out;

	/* need to find one window */
	start = (range[0].start & MASK) - UNIT;
	if (start > tom2 && BASE_VALID(start))
		goto out;
	start = (range[hi_mmio_num - 1].end + UNIT) & MASK;
	if (BASE_VALID(start))
		goto out;
	/* need to find window between ranges */
	for (i = 1; i < hi_mmio_num; i++) {
		start = (range[i - 1].end + UNIT) & MASK;
		end = range[i].start & MASK;
		if (end >= start + SIZE && BASE_VALID(start))
			goto out;
	}
	return;

out:
	if (e820_add_range(&e820, start, start + SIZE, E820_RESERVED))
		fam10h_pci_mmconf_base = start;
}

void __cpuinit fam10h_check_enable_mmcfg(void)
{
	u64 val;
	bool_t print = opt_cpu_info;

	if (!(pci_probe & PCI_CHECK_ENABLE_AMD_MMCONF))
		return;

	rdmsrl(MSR_FAM10H_MMIO_CONF_BASE, val);

	/* try to make sure that AP's setting is identical to BSP setting */
	if (val & FAM10H_MMIO_CONF_ENABLE) {
		u64 base = val & MASK;

		if (!fam10h_pci_mmconf_base) {
			fam10h_pci_mmconf_base = base;
			return;
		}
		if (fam10h_pci_mmconf_base == base)
			return;
	}

	/*
	 * if it is not enabled, try to enable it and assume only one segment
	 * with 256 buses
	 */
	/* only try to get setting from BSP */
	if (!fam10h_pci_mmconf_base) {
		get_fam10h_pci_mmconf_base();
		print = 1;
	}
	if (!fam10h_pci_mmconf_base) {
		pci_probe &= ~PCI_CHECK_ENABLE_AMD_MMCONF;
		return;
	}

	if (print)
		printk(KERN_INFO "Enable MMCONFIG on AMD Fam10h at %"PRIx64"\n",
		       fam10h_pci_mmconf_base);
	val &= ~((FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT) |
	     (FAM10H_MMIO_CONF_BUSRANGE_MASK<<FAM10H_MMIO_CONF_BUSRANGE_SHIFT));
	val |= fam10h_pci_mmconf_base | (8 << FAM10H_MMIO_CONF_BUSRANGE_SHIFT) |
	       FAM10H_MMIO_CONF_ENABLE;
	wrmsrl(MSR_FAM10H_MMIO_CONF_BASE, val);
}

static int __init set_check_enable_amd_mmconf(struct dmi_system_id *d)
{
        pci_probe |= PCI_CHECK_ENABLE_AMD_MMCONF;
        return 0;
}

static struct dmi_system_id __initdata mmconf_dmi_table[] = {
	{
		.callback = set_check_enable_amd_mmconf,
		.ident = "Sun Microsystems Machine",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Sun Microsystems"),
		},
	},
	{}
};

void __init check_enable_amd_mmconf_dmi(void)
{
	dmi_check_system(mmconf_dmi_table);
}
