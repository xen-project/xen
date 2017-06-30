#include <xen/types.h>
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/init.h>
#include <xen/cache.h>
#include <xen/acpi.h>
#include <asm/io.h>
#include <asm/system.h>
#include <xen/dmi.h>
#include <xen/efi.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>

#define bt_ioremap(b,l)  ((void *)__acpi_map_table(b,l))
#define bt_iounmap(b,l)  ((void)0)
#define memcpy_fromio    memcpy
#define alloc_bootmem(l) xmalloc_bytes(l)

struct __packed dmi_eps {
	char anchor[5];			/* "_DMI_" */
	u8 checksum;
	u16 size;
	u32 address;
	u16 num_structures;
	u8 revision;
};

struct __packed smbios_eps {
	char anchor[4];			/* "_SM_" */
	u8 checksum;
	u8 length;
	u8 major, minor;
	u16 max_size;
	u8 revision;
	u8 _rsrvd_[5];
	struct dmi_eps dmi;
};

struct __packed smbios3_eps {
	char anchor[5];			/* "_SM3_" */
	u8 checksum;
	u8 length;
	u8 major, minor;
	u8 docrev;
	u8 revision;
	u8 _rsrvd_;
	u32 max_size;
	u64 address;
};

struct dmi_header
{
	u8	type;
	u8	length;
	u16	handle;
};

enum dmi_entry_type {
	DMI_ENTRY_BIOS = 0,
	DMI_ENTRY_SYSTEM,
	DMI_ENTRY_BASEBOARD,
	DMI_ENTRY_CHASSIS,
	DMI_ENTRY_PROCESSOR,
	DMI_ENTRY_MEM_CONTROLLER,
	DMI_ENTRY_MEM_MODULE,
	DMI_ENTRY_CACHE,
	DMI_ENTRY_PORT_CONNECTOR,
	DMI_ENTRY_SYSTEM_SLOT,
	DMI_ENTRY_ONBOARD_DEVICE,
	DMI_ENTRY_OEMSTRINGS,
	DMI_ENTRY_SYSCONF,
	DMI_ENTRY_BIOS_LANG,
	DMI_ENTRY_GROUP_ASSOC,
	DMI_ENTRY_SYSTEM_EVENT_LOG,
	DMI_ENTRY_PHYS_MEM_ARRAY,
	DMI_ENTRY_MEM_DEVICE,
	DMI_ENTRY_32_MEM_ERROR,
	DMI_ENTRY_MEM_ARRAY_MAPPED_ADDR,
	DMI_ENTRY_MEM_DEV_MAPPED_ADDR,
	DMI_ENTRY_BUILTIN_POINTING_DEV,
	DMI_ENTRY_PORTABLE_BATTERY,
	DMI_ENTRY_SYSTEM_RESET,
	DMI_ENTRY_HW_SECURITY,
	DMI_ENTRY_SYSTEM_POWER_CONTROLS,
	DMI_ENTRY_VOLTAGE_PROBE,
	DMI_ENTRY_COOLING_DEV,
	DMI_ENTRY_TEMP_PROBE,
	DMI_ENTRY_ELECTRICAL_CURRENT_PROBE,
	DMI_ENTRY_OOB_REMOTE_ACCESS,
	DMI_ENTRY_BIS_ENTRY,
	DMI_ENTRY_SYSTEM_BOOT,
	DMI_ENTRY_MGMT_DEV,
	DMI_ENTRY_MGMT_DEV_COMPONENT,
	DMI_ENTRY_MGMT_DEV_THRES,
	DMI_ENTRY_MEM_CHANNEL,
	DMI_ENTRY_IPMI_DEV,
	DMI_ENTRY_SYS_POWER_SUPPLY,
	DMI_ENTRY_ADDITIONAL,
	DMI_ENTRY_ONBOARD_DEV_EXT,
	DMI_ENTRY_MGMT_CONTROLLER_HOST,
	DMI_ENTRY_INACTIVE = 126,
	DMI_ENTRY_END_OF_TABLE = 127,
};

#undef DMI_DEBUG

#ifdef DMI_DEBUG
#define dmi_printk(x) printk x
#else
#define dmi_printk(x)
#endif

static char * __init dmi_string(struct dmi_header *dm, u8 s)
{
	char *bp=(char *)dm;
	bp+=dm->length;
	if(!s)
		return "";
	s--;
	while(s>0 && *bp)
	{
		bp+=strlen(bp);
		bp++;
		s--;
	}
	return bp;
}

/*
 *	We have to be cautious here. We have seen BIOSes with DMI pointers
 *	pointing to completely the wrong place for example
 */
 
static int __init dmi_table(paddr_t base, u32 len, int num,
			    void (*decode)(struct dmi_header *))
{
	u8 *buf;
	struct dmi_header *dm;
	u8 *data;
	int i=0;
		
	buf = bt_ioremap(base, len);
	if(buf==NULL)
		return -1;

	data = buf;

	/*
	 * Stop when we have seen all the items the table claimed to have
	 * (SMBIOS < 3.0 only) OR we reach an end-of-table marker (SMBIOS
	 * >= 3.0 only) OR we run off the end of the table (should never
	 * happen but sometimes does on bogus implementations.)
	 */
	while((num < 0 || i < num) && data-buf+sizeof(struct dmi_header)<=len)
	{
		dm=(struct dmi_header *)data;
		/*
		 *  We want to know the total length (formated area and strings)
		 *  before decoding to make sure we won't run off the table in
		 *  dmi_decode or dmi_string
		 */
		data+=dm->length;
		while(data-buf<len-1 && (data[0] || data[1]))
			data++;
		if(data-buf<len-1)
			decode(dm);
		/*
		 * 7.45 End-of-Table (Type 127) [SMBIOS reference spec v3.0.0]
		 * For tables behind a 64-bit entry point, we have no item
		 * count and no exact table length, so stop on end-of-table
		 * marker. For tables behind a 32-bit entry point, we have
		 * seen OEM structures behind the end-of-table marker on
		 * some systems, so don't trust it.
		 */
		if (num < 0 && dm->type == DMI_ENTRY_END_OF_TABLE)
			break;
		data+=2;
		i++;
	}
	bt_iounmap(buf, len);
	return 0;
}


static inline bool __init dmi_checksum(const void __iomem *buf,
                                       unsigned int len)
{
	u8 sum = 0;
	const u8 *p = buf;
	unsigned int a;
	
	for (a = 0; a < len; a++)
		sum += p[a];
	return sum == 0;
}

static u32 __initdata efi_dmi_address;
static u32 __initdata efi_dmi_size;
static u32 __initdata efi_smbios_address;
static u32 __initdata efi_smbios_size;
static u64 __initdata efi_smbios3_address;
static u32 __initdata efi_smbios3_size;

/*
 * Important: This function gets called while still in EFI
 * (pseudo-)physical mode.
 */
void __init dmi_efi_get_table(const void *smbios, const void *smbios3)
{
	const struct smbios_eps *eps = smbios;
	const struct smbios3_eps *eps3 = smbios3;

	if (eps3 && memcmp(eps3->anchor, "_SM3_", 5) == 0 &&
	    eps3->length >= sizeof(*eps3) &&
	    dmi_checksum(eps3, eps3->length)) {
		efi_smbios3_address = eps3->address;
		efi_smbios3_size = eps3->max_size;
		return;
	}

	if (eps && memcmp(eps->anchor, "_SM_", 4) == 0 &&
	    eps->length >= sizeof(*eps) &&
	    dmi_checksum(eps, eps->length)) {
		efi_smbios_address = (u32)(long)eps;
		efi_smbios_size = eps->length;

		if (memcmp(eps->dmi.anchor, "_DMI_", 5) == 0 &&
		    dmi_checksum(&eps->dmi, sizeof(eps->dmi))) {
			efi_dmi_address = eps->dmi.address;
			efi_dmi_size = eps->dmi.size;
		}
	}
}

const char *__init dmi_get_table(paddr_t *base, u32 *len)
{
	static unsigned int __initdata instance;

	if (efi_enabled(EFI_BOOT)) {
		if (efi_smbios3_size && !(instance & 1)) {
			*base = efi_smbios3_address;
			*len = efi_smbios3_size;
			instance |= 1;
			return "SMBIOSv3";
		}
		if (efi_dmi_size && !(instance & 2)) {
			*base = efi_dmi_address;
			*len = efi_dmi_size;
			instance |= 2;
			return "DMI";
		}
		if (efi_smbios_size && !(instance & 4)) {
			*base = efi_smbios_address;
			*len = efi_smbios_size;
			instance |= 4;
			return "SMBIOS";
		}
	} else {
		char __iomem *p = maddr_to_virt(0xF0000), *q;
		union {
			struct dmi_eps dmi;
			struct smbios3_eps smbios3;
		} eps;

		for (q = p; q <= p + 0x10000 - sizeof(eps.dmi); q += 16) {
			memcpy_fromio(&eps, q, sizeof(eps.dmi));
			if (!(instance & 1) &&
			    memcmp(eps.dmi.anchor, "_DMI_", 5) == 0 &&
			    dmi_checksum(&eps.dmi, sizeof(eps.dmi))) {
				*base = eps.dmi.address;
				*len = eps.dmi.size;
				instance |= 1;
				return "DMI";
			}

			BUILD_BUG_ON(sizeof(eps.smbios3) <= sizeof(eps.dmi));
			if ((instance & 2) ||
			    q > p + 0x10000 - sizeof(eps.smbios3))
				continue;
			memcpy_fromio(&eps.dmi + 1, q + sizeof(eps.dmi),
			              sizeof(eps.smbios3) - sizeof(eps.dmi));
			if (!memcmp(eps.smbios3.anchor, "_SM3_", 5) &&
			    eps.smbios3.length >= sizeof(eps.smbios3) &&
			    q <= p + 0x10000 - eps.smbios3.length &&
			    dmi_checksum(q, eps.smbios3.length)) {
				*base = eps.smbios3.address;
				*len = eps.smbios3.max_size;
				instance |= 2;
				return "SMBIOSv3";
			}
		}
	}
	return NULL;
}

typedef union {
	const struct smbios_eps __iomem *legacy;
	const struct smbios3_eps __iomem *v3;
} smbios_eps_u __attribute__((transparent_union));

static int __init _dmi_iterate(const struct dmi_eps *dmi,
			       const smbios_eps_u smbios,
			       void (*decode)(struct dmi_header *))
{
	int num;
	u32 len;
	paddr_t base;

	if (!dmi) {
		num = -1;
		len = smbios.v3->max_size;
		base = smbios.v3->address;
		printk(KERN_INFO "SMBIOS %d.%d present.\n",
		       smbios.v3->major, smbios.v3->minor);
		dmi_printk((KERN_INFO "SMBIOS v3 table at 0x%"PRIpaddr".\n", base));
	} else {
		num = dmi->num_structures;
		len = dmi->size;
		base = dmi->address;

		/*
		 * DMI version 0.0 means that the real version is taken from
		 * the SMBIOS version, which we may not know at this point.
		 */
		if (dmi->revision)
			printk(KERN_INFO "DMI %d.%d present.\n",
			       dmi->revision >> 4,  dmi->revision & 0x0f);
		else if (!smbios.legacy)
			printk(KERN_INFO "DMI present.\n");
		dmi_printk((KERN_INFO "%d structures occupying %u bytes.\n",
			    num, len));
		dmi_printk((KERN_INFO "DMI table at 0x%08X.\n", (u32)base));
	}
	return dmi_table(base, len, num, decode);
}

static int __init dmi_iterate(void (*decode)(struct dmi_header *))
{
	struct dmi_eps dmi;
	struct smbios3_eps smbios3;
	char __iomem *p, *q;

	dmi.size = 0;
	smbios3.length = 0;

	p = maddr_to_virt(0xF0000);
	for (q = p; q < p + 0x10000; q += 16) {
		if (!dmi.size) {
			memcpy_fromio(&dmi, q, sizeof(dmi));
			if (memcmp(dmi.anchor, "_DMI_", 5) ||
			    !dmi_checksum(&dmi, sizeof(dmi)))
				dmi.size = 0;
		}
		if (!smbios3.length &&
		    q <= p + 0x10000 - sizeof(smbios3)) {
			memcpy_fromio(&smbios3, q, sizeof(smbios3));
			if (memcmp(smbios3.anchor, "_SM3_", 5) ||
			    smbios3.length < sizeof(smbios3) ||
			    q < p + 0x10000 - smbios3.length ||
			    !dmi_checksum(q, smbios3.length))
				smbios3.length = 0;
		}
	}

	if (smbios3.length)
		return _dmi_iterate(NULL, &smbios3, decode);
	if (dmi.size)
		return _dmi_iterate(&dmi, NULL, decode);
	return -1;
}

static int __init dmi_efi_iterate(void (*decode)(struct dmi_header *))
{
	int ret = -1;

	while (efi.smbios3 != EFI_INVALID_TABLE_ADDR) {
		struct smbios3_eps eps;
		const struct smbios3_eps __iomem *p;

		p = bt_ioremap(efi.smbios3, sizeof(eps));
		if (!p)
			break;
		memcpy_fromio(&eps, p, sizeof(eps));
		bt_iounmap(p, sizeof(eps));

		if (memcmp(eps.anchor, "_SM3_", 5) ||
		    eps.length < sizeof(eps))
			break;

		p = bt_ioremap(efi.smbios3, eps.length);
		if (!p)
			break;
		if (dmi_checksum(p, eps.length))
			ret = _dmi_iterate(NULL, p, decode);
		bt_iounmap(p, eps.length);
		break;
	}

	if (ret != 0 && efi.smbios != EFI_INVALID_TABLE_ADDR) {
		struct smbios_eps eps;
		const struct smbios_eps __iomem *p;

		p = bt_ioremap(efi.smbios, sizeof(eps));
		if (!p)
			return -1;
		memcpy_fromio(&eps, p, sizeof(eps));
		bt_iounmap(p, sizeof(eps));

		if (memcmp(eps.anchor, "_SM_", 4) ||
		    eps.length < sizeof(eps))
			return -1;

		p = bt_ioremap(efi.smbios, eps.length);
		if (!p)
			return -1;
		if (dmi_checksum(p, eps.length) &&
		    memcmp(eps.dmi.anchor, "_DMI_", 5) == 0 &&
		    dmi_checksum(&eps.dmi, sizeof(eps.dmi))) {
			printk(KERN_INFO "SMBIOS %d.%d present.\n",
			       eps.major, eps.minor);
			ret = _dmi_iterate(&eps.dmi, p, decode);
		}
		bt_iounmap(p, eps.length);
	}

	return ret;
}

static char *__initdata dmi_ident[DMI_STRING_MAX];

/*
 *	Save a DMI string
 */
 
static void __init dmi_save_ident(struct dmi_header *dm, int slot, int string)
{
	char *d = (char*)dm;
	char *p = dmi_string(dm, d[string]);
	if(p==NULL || *p == 0)
		return;
	if (dmi_ident[slot])
		return;
	dmi_ident[slot] = alloc_bootmem(strlen(p)+1);
	if(dmi_ident[slot])
		strlcpy(dmi_ident[slot], p, strlen(p)+1);
	else
		printk(KERN_ERR "dmi_save_ident: out of memory.\n");
}

/*
 * Ugly compatibility crap.
 */
#define dmi_blacklist	dmi_system_id
#define NO_MATCH	{ DMI_NONE, NULL}
#define MATCH		DMI_MATCH

/*
 * Toshiba keyboard likes to repeat keys when they are not repeated.
 */

static __init int broken_toshiba_keyboard(struct dmi_blacklist *d)
{
	printk(KERN_WARNING "Toshiba with broken keyboard detected. If your keyboard sometimes generates 3 keypresses instead of one, see http://davyd.ucc.asn.au/projects/toshiba/README\n");
	return 0;
}

static int __init ich10_bios_quirk(struct dmi_system_id *d)
{
    u32 port, smictl;

    if ( pci_conf_read16(0, 0, 0x1f, 0, PCI_VENDOR_ID) != 0x8086 )
        return 0;

    switch ( pci_conf_read16(0, 0, 0x1f, 0, PCI_DEVICE_ID) ) {
    case 0x3a14:
    case 0x3a16:
    case 0x3a18:
    case 0x3a1a:
        port = (pci_conf_read16(0, 0, 0x1f, 0, 0x40) & 0xff80) + 0x30;
        smictl = inl(port);
        /* turn off LEGACY_USB{,2}_EN if enabled */
        if ( smictl & 0x20008 )
            outl(smictl & ~0x20008, port);
        break;
    }

    return 0;
}

#ifdef CONFIG_ACPI_SLEEP
static __init int reset_videomode_after_s3(struct dmi_blacklist *d)
{
	/* See acpi_wakeup.S */
	acpi_video_flags |= 2;
	return 0;
}
#endif

static __init int dmi_disable_acpi(struct dmi_blacklist *d) 
{ 
	if (!acpi_force) { 
		printk(KERN_NOTICE "%s detected: acpi off\n",d->ident);
		disable_acpi();
	} else { 
		printk(KERN_NOTICE 
		       "Warning: DMI blacklist says broken, but acpi forced\n");
	}
	return 0;
} 

/*
 * Limit ACPI to CPU enumeration for HT
 */
static __init int force_acpi_ht(struct dmi_blacklist *d) 
{ 
	if (!acpi_force) { 
		printk(KERN_NOTICE "%s detected: force use of acpi=ht\n", d->ident);
		disable_acpi();
		acpi_ht = 1;
	} else { 
		printk(KERN_NOTICE 
		       "Warning: acpi=force overrules DMI blacklist: acpi=ht\n");
	}
	return 0;
} 

/*
 *	Process the DMI blacklists
 */
 

/*
 *	This will be expanded over time to force things like the APM 
 *	interrupt mask settings according to the laptop
 */
 
static __initdata struct dmi_blacklist dmi_blacklist[]={

	{ broken_toshiba_keyboard, "Toshiba Satellite 4030cdt", { /* Keyboard generates spurious repeats */
			MATCH(DMI_PRODUCT_NAME, "S4030CDT/4.3"),
			NO_MATCH, NO_MATCH, NO_MATCH
			} },
#ifdef CONFIG_ACPI_SLEEP
	{ reset_videomode_after_s3, "Toshiba Satellite 4030cdt", { /* Reset video mode after returning from ACPI S3 sleep */
			MATCH(DMI_PRODUCT_NAME, "S4030CDT/4.3"),
			NO_MATCH, NO_MATCH, NO_MATCH
			} },
#endif

	{ ich10_bios_quirk, "Intel board & BIOS",
		/*
		 * BIOS leaves legacy USB emulation enabled while
		 * SMM can't properly handle it.
		 */
		{
			MATCH(DMI_BOARD_VENDOR, "Intel Corp"),
			MATCH(DMI_BIOS_VENDOR, "Intel Corp"),
			NO_MATCH, NO_MATCH
		}
	},

	/*
	 * If your system is blacklisted here, but you find that acpi=force
	 * works for you, please contact acpi-devel@sourceforge.net
	 */

	/*
	 *	Boxes that need ACPI disabled
	 */

	{ dmi_disable_acpi, "IBM Thinkpad", {
			MATCH(DMI_BOARD_VENDOR, "IBM"),
			MATCH(DMI_BOARD_NAME, "2629H1G"),
			NO_MATCH, NO_MATCH }},

	/*
	 *	Boxes that need acpi=ht 
	 */

	{ force_acpi_ht, "FSC Primergy T850", {
			MATCH(DMI_SYS_VENDOR, "FUJITSU SIEMENS"),
			MATCH(DMI_PRODUCT_NAME, "PRIMERGY T850"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "DELL GX240", {
			MATCH(DMI_BOARD_VENDOR, "Dell Computer Corporation"),
			MATCH(DMI_BOARD_NAME, "OptiPlex GX240"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "HP VISUALIZE NT Workstation", {
			MATCH(DMI_BOARD_VENDOR, "Hewlett-Packard"),
			MATCH(DMI_PRODUCT_NAME, "HP VISUALIZE NT Workstation"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "Compaq Workstation W8000", {
			MATCH(DMI_SYS_VENDOR, "Compaq"),
			MATCH(DMI_PRODUCT_NAME, "Workstation W8000"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "ASUS P4B266", {
			MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
			MATCH(DMI_BOARD_NAME, "P4B266"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "ASUS P2B-DS", {
			MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
			MATCH(DMI_BOARD_NAME, "P2B-DS"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "ASUS CUR-DLS", {
			MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
			MATCH(DMI_BOARD_NAME, "CUR-DLS"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "ABIT i440BX-W83977", {
			MATCH(DMI_BOARD_VENDOR, "ABIT <http://www.abit.com>"),
			MATCH(DMI_BOARD_NAME, "i440BX-W83977 (BP6)"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "IBM Bladecenter", {
			MATCH(DMI_BOARD_VENDOR, "IBM"),
			MATCH(DMI_BOARD_NAME, "IBM eServer BladeCenter HS20"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "IBM eServer xSeries 360", {
			MATCH(DMI_BOARD_VENDOR, "IBM"),
			MATCH(DMI_BOARD_NAME, "eServer xSeries 360"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "IBM eserver xSeries 330", {
			MATCH(DMI_BOARD_VENDOR, "IBM"),
			MATCH(DMI_BOARD_NAME, "eserver xSeries 330"),
			NO_MATCH, NO_MATCH }},

	{ force_acpi_ht, "IBM eserver xSeries 440", {
			MATCH(DMI_BOARD_VENDOR, "IBM"),
			MATCH(DMI_PRODUCT_NAME, "eserver xSeries 440"),
			NO_MATCH, NO_MATCH }},

	{ NULL, }
};

/*
 *	Process a DMI table entry. Right now all we care about are the BIOS
 *	and machine entries. For 2.5 we should pull the smbus controller info
 *	out of here.
 */

static void __init dmi_decode(struct dmi_header *dm)
{
#ifdef DMI_DEBUG
	u8 *data = (u8 *)dm;
#endif
	
	switch(dm->type)
	{
		case DMI_ENTRY_BIOS:
			dmi_printk(("BIOS Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_BIOS_VENDOR, 4);
			dmi_printk(("BIOS Version: %s\n", 
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_BIOS_VERSION, 5);
			dmi_printk(("BIOS Release: %s\n",
				dmi_string(dm, data[8])));
			dmi_save_ident(dm, DMI_BIOS_DATE, 8);
			break;
		case DMI_ENTRY_SYSTEM:
			dmi_printk(("System Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_SYS_VENDOR, 4);
			dmi_printk(("Product Name: %s\n",
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_PRODUCT_NAME, 5);
			dmi_printk(("Version: %s\n",
				dmi_string(dm, data[6])));
			dmi_save_ident(dm, DMI_PRODUCT_VERSION, 6);
			dmi_printk(("Serial Number: %s\n",
				dmi_string(dm, data[7])));
			break;
		case DMI_ENTRY_BASEBOARD:
			dmi_printk(("Board Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_BOARD_VENDOR, 4);
			dmi_printk(("Board Name: %s\n",
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_BOARD_NAME, 5);
			dmi_printk(("Board Version: %s\n",
				dmi_string(dm, data[6])));
			dmi_save_ident(dm, DMI_BOARD_VERSION, 6);
			break;
	}
}

void __init dmi_scan_machine(void)
{
	if ((!efi_enabled(EFI_BOOT) ? dmi_iterate(dmi_decode) :
	                    dmi_efi_iterate(dmi_decode)) == 0)
 		dmi_check_system(dmi_blacklist);
	else
		printk(KERN_INFO "DMI not present.\n");
}


/**
 *	dmi_check_system - check system DMI data
 *	@list: array of dmi_system_id structures to match against
 *
 *	Walk the blacklist table running matching functions until someone
 *	returns non zero or we hit the end. Callback function is called for
 *	each successfull match. Returns the number of matches.
 */
int __init dmi_check_system(struct dmi_system_id *list)
{
	int i, count = 0;
	struct dmi_system_id *d = list;

	while (d->ident) {
		for (i = 0; i < ARRAY_SIZE(d->matches); i++) {
			int s = d->matches[i].slot;
			if (s == DMI_NONE)
				continue;
			if (dmi_ident[s] && strstr(dmi_ident[s], d->matches[i].substr))
				continue;
			/* No match */
			goto fail;
		}
		if (d->callback && d->callback(d))
			break;
		count++;
fail:		d++;
	}

	return count;
}

/**
 *	dmi_get_date - parse a DMI date
 *	@field:	data index (see enum dmi_field)
 *	@yearp: optional out parameter for the year
 *	@monthp: optional out parameter for the month
 *	@dayp: optional out parameter for the day
 *
 *	The date field is assumed to be in the form resembling
 *	[mm[/dd]]/yy[yy] and the result is stored in the out
 *	parameters any or all of which can be omitted.
 *
 *	If the field doesn't exist, all out parameters are set to zero
 *	and false is returned.  Otherwise, true is returned with any
 *	invalid part of date set to zero.
 *
 *	On return, year, month and day are guaranteed to be in the
 *	range of [0,9999], [0,12] and [0,31] respectively.
 */
bool __init dmi_get_date(int field, int *yearp, int *monthp, int *dayp)
{
	int year = 0, month = 0, day = 0;
	bool exists;
	const char *s, *e, *y;

	s = field < DMI_STRING_MAX ? dmi_ident[field] : NULL;
	exists = !!s;
	if (!exists)
		goto out;

	/*
	 * Determine year first.  We assume the date string resembles
	 * mm/dd/yy[yy] but the original code extracted only the year
	 * from the end.  Keep the behavior in the spirit of no
	 * surprises.
	 */
	y = strrchr(s, '/');
	if (!y)
		goto out;

	y++;
	year = simple_strtoul(y, &e, 10);
	if (y != e && year < 100) {	/* 2-digit year */
		year += 1900;
		if (year < 1996)	/* no dates < spec 1.0 */
			year += 100;
	}
	if (year > 9999)		/* year should fit in %04d */
		year = 0;

	/* parse the mm and dd */
	month = simple_strtoul(s, &e, 10);
	if (s == e || *e != '/' || !month || month > 12) {
		month = 0;
		goto out;
	}

	s = e + 1;
	day = simple_strtoul(s, &e, 10);
	if (s == y || s == e || *e != '/' || day > 31)
		day = 0;
out:
	if (yearp)
		*yearp = year;
	if (monthp)
		*monthp = month;
	if (dayp)
		*dayp = day;
	return exists;
}

void __init dmi_end_boot(void)
{
    unsigned int i;

    for ( i = 0; i < DMI_STRING_MAX; ++i )
        xfree(dmi_ident[i]);
}
