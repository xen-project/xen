/*
 *	Intel Multiprocessor Specificiation 1.1 and 1.4
 *	compliant MP-table parsing routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998, 1999, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	Fixes
 *		Erich Boleyn	:	MP v1.4 and additional changes.
 *		Alan Cox	:	Added EBDA scanning
 *		Ingo Molnar	:	various cleanups and rewrites
 *	Maciej W. Rozycki	:	Bits for default MP configurations
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <asm/io.h>
#include <xeno/irq.h>
#include <xeno/smp.h>
#include <asm/apic.h>
#include <asm/mpspec.h>
#include <asm/pgalloc.h>
#include <asm/smpboot.h>
#include <xeno/kernel.h>

int numnodes = 1; /* XXX Xen */

/* Have we found an MP table */
int smp_found_config;

/*
 * Various Linux-internal data structures created from the
 * MP-table.
 */
int apic_version [MAX_APICS];
int quad_local_to_mp_bus_id [NR_CPUS/4][4];
int mp_current_pci_id;
int *mp_bus_id_to_type;
int *mp_bus_id_to_node;
int *mp_bus_id_to_local;
int *mp_bus_id_to_pci_bus;
int max_mp_busses;
int max_irq_sources;

/* I/O APIC entries */
struct mpc_config_ioapic mp_ioapics[MAX_IO_APICS];

/* # of MP IRQ source entries */
struct mpc_config_intsrc *mp_irqs;

/* MP IRQ source entries */
int mp_irq_entries;

int nr_ioapics;

int pic_mode;
unsigned long mp_lapic_addr;

/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;
unsigned int boot_cpu_logical_apicid = -1U;
/* Internal processor count */
static unsigned int num_processors;

/* Bitmask of physically existing CPUs */
unsigned long phys_cpu_present_map;
unsigned long logical_cpu_present_map;

#ifdef CONFIG_X86_CLUSTERED_APIC
unsigned char esr_disable = 0;
unsigned char clustered_apic_mode = CLUSTERED_APIC_NONE;
unsigned int apic_broadcast_id = APIC_BROADCAST_ID_APIC;
#endif
unsigned char raw_phys_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

/*
 * Intel MP BIOS table parsing routines:
 */

#ifndef CONFIG_X86_VISWS_APIC
/*
 * Checksum an MP configuration block.
 */

static int __init mpf_checksum(unsigned char *mp, int len)
{
	int sum = 0;

	while (len--)
		sum += *mp++;

	return sum & 0xFF;
}

/*
 * Processor encoding in an MP configuration block
 */

static char __init *mpc_family(int family,int model)
{
	static char n[32];
	static char *model_defs[]=
	{
		"80486DX","80486DX",
		"80486SX","80486DX/2 or 80487",
		"80486SL","80486SX/2",
		"Unknown","80486DX/2-WB",
		"80486DX/4","80486DX/4-WB"
	};

	switch (family) {
		case 0x04:
			if (model < 10)
				return model_defs[model];
			break;

		case 0x05:
			return("Pentium(tm)");

		case 0x06:
			return("Pentium(tm) Pro");

		case 0x0F:
			if (model == 0x00)
				return("Pentium 4(tm)");
			if (model == 0x02)
				return("Pentium 4(tm) XEON(tm)");
			if (model == 0x0F)
				return("Special controller");
	}
	sprintf(n,"Unknown CPU [%d:%d]",family, model);
	return n;
}

#ifdef CONFIG_X86_IO_APIC
// XXX Xen extern int have_acpi_tables;	/* set by acpitable.c */
#define have_acpi_tables (0)
#else
#define have_acpi_tables (0)
#endif

/* 
 * Have to match translation table entries to main table entries by counter
 * hence the mpc_record variable .... can't see a less disgusting way of
 * doing this ....
 */

static int mpc_record; 
static struct mpc_config_translation *translation_table[MAX_MPC_ENTRY] __initdata;

void __init MP_processor_info (struct mpc_config_processor *m)
{
 	int ver, quad, logical_apicid;
 	
	if (!(m->mpc_cpuflag & CPU_ENABLED))
		return;

	logical_apicid = m->mpc_apicid;
	if (clustered_apic_mode == CLUSTERED_APIC_NUMAQ) {
		quad = translation_table[mpc_record]->trans_quad;
		logical_apicid = (quad << 4) + 
			(m->mpc_apicid ? m->mpc_apicid << 1 : 1);
		printk("Processor #%d %s APIC version %d (quad %d, apic %d)\n",
			m->mpc_apicid,
			mpc_family((m->mpc_cpufeature & CPU_FAMILY_MASK)>>8 ,
				   (m->mpc_cpufeature & CPU_MODEL_MASK)>>4),
			m->mpc_apicver, quad, logical_apicid);
	} else {
		printk("Processor #%d %s APIC version %d\n",
			m->mpc_apicid,
			mpc_family((m->mpc_cpufeature & CPU_FAMILY_MASK)>>8 ,
				   (m->mpc_cpufeature & CPU_MODEL_MASK)>>4),
			m->mpc_apicver);
	}

	if (m->mpc_featureflag&(1<<0))
		Dprintk("    Floating point unit present.\n");
	if (m->mpc_featureflag&(1<<7))
		Dprintk("    Machine Exception supported.\n");
	if (m->mpc_featureflag&(1<<8))
		Dprintk("    64 bit compare & exchange supported.\n");
	if (m->mpc_featureflag&(1<<9))
		Dprintk("    Internal APIC present.\n");
	if (m->mpc_featureflag&(1<<11))
		Dprintk("    SEP present.\n");
	if (m->mpc_featureflag&(1<<12))
		Dprintk("    MTRR  present.\n");
	if (m->mpc_featureflag&(1<<13))
		Dprintk("    PGE  present.\n");
	if (m->mpc_featureflag&(1<<14))
		Dprintk("    MCA  present.\n");
	if (m->mpc_featureflag&(1<<15))
		Dprintk("    CMOV  present.\n");
	if (m->mpc_featureflag&(1<<16))
		Dprintk("    PAT  present.\n");
	if (m->mpc_featureflag&(1<<17))
		Dprintk("    PSE  present.\n");
	if (m->mpc_featureflag&(1<<18))
		Dprintk("    PSN  present.\n");
	if (m->mpc_featureflag&(1<<19))
		Dprintk("    Cache Line Flush Instruction present.\n");
	/* 20 Reserved */
	if (m->mpc_featureflag&(1<<21))
		Dprintk("    Debug Trace and EMON Store present.\n");
	if (m->mpc_featureflag&(1<<22))
		Dprintk("    ACPI Thermal Throttle Registers  present.\n");
	if (m->mpc_featureflag&(1<<23))
		Dprintk("    MMX  present.\n");
	if (m->mpc_featureflag&(1<<24))
		Dprintk("    FXSR  present.\n");
	if (m->mpc_featureflag&(1<<25))
		Dprintk("    XMM  present.\n");
	if (m->mpc_featureflag&(1<<26))
		Dprintk("    Willamette New Instructions  present.\n");
	if (m->mpc_featureflag&(1<<27))
		Dprintk("    Self Snoop  present.\n");
	if (m->mpc_featureflag&(1<<28))
		Dprintk("    HT  present.\n");
	if (m->mpc_featureflag&(1<<29))
		Dprintk("    Thermal Monitor present.\n");
	/* 30, 31 Reserved */


	if (m->mpc_cpuflag & CPU_BOOTPROCESSOR) {
		Dprintk("    Bootup CPU\n");
		boot_cpu_physical_apicid = m->mpc_apicid;
		boot_cpu_logical_apicid = logical_apicid;
	}

	num_processors++;

	if (m->mpc_apicid > MAX_APICS) {
		printk("Processor #%d INVALID. (Max ID: %d).\n",
			m->mpc_apicid, MAX_APICS);
		--num_processors;
		return;
	}
	ver = m->mpc_apicver;

	logical_cpu_present_map |= 1 << (num_processors-1);
 	phys_cpu_present_map |= apicid_to_phys_cpu_present(m->mpc_apicid);
 
	/*
	 * Validate version
	 */
	if (ver == 0x0) {
		printk("BIOS bug, APIC version is 0 for CPU#%d! fixing up to 0x10. (tell your hw vendor)\n", m->mpc_apicid);
		ver = 0x10;
	}
	apic_version[m->mpc_apicid] = ver;
	raw_phys_apicid[num_processors - 1] = m->mpc_apicid;
}

static void __init MP_bus_info (struct mpc_config_bus *m)
{
	char str[7];
	int quad;

	memcpy(str, m->mpc_bustype, 6);
	str[6] = 0;
	
	if (clustered_apic_mode == CLUSTERED_APIC_NUMAQ) {
		quad = translation_table[mpc_record]->trans_quad;
		mp_bus_id_to_node[m->mpc_busid] = quad;
		mp_bus_id_to_local[m->mpc_busid] = translation_table[mpc_record]->trans_local;
		quad_local_to_mp_bus_id[quad][translation_table[mpc_record]->trans_local] = m->mpc_busid;
		printk("Bus #%d is %s (node %d)\n", m->mpc_busid, str, quad);
	} else {
		Dprintk("Bus #%d is %s\n", m->mpc_busid, str);
	}

	if (strncmp(str, BUSTYPE_ISA, sizeof(BUSTYPE_ISA)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_ISA;
	} else if (strncmp(str, BUSTYPE_EISA, sizeof(BUSTYPE_EISA)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_EISA;
	} else if (strncmp(str, BUSTYPE_PCI, sizeof(BUSTYPE_PCI)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_PCI;
		mp_bus_id_to_pci_bus[m->mpc_busid] = mp_current_pci_id;
		mp_current_pci_id++;
	} else if (strncmp(str, BUSTYPE_MCA, sizeof(BUSTYPE_MCA)-1) == 0) {
		mp_bus_id_to_type[m->mpc_busid] = MP_BUS_MCA;
	} else {
		printk("Unknown bustype %s - ignoring\n", str);
	}
}

static void __init MP_ioapic_info (struct mpc_config_ioapic *m)
{
	if (!(m->mpc_flags & MPC_APIC_USABLE))
		return;

	printk("I/O APIC #%d Version %d at 0x%lX.\n",
		m->mpc_apicid, m->mpc_apicver, m->mpc_apicaddr);
	if (nr_ioapics >= MAX_IO_APICS) {
		printk("Max # of I/O APICs (%d) exceeded (found %d).\n",
			MAX_IO_APICS, nr_ioapics);
		panic("Recompile kernel with bigger MAX_IO_APICS!.\n");
	}
	if (!m->mpc_apicaddr) {
		printk(KERN_ERR "WARNING: bogus zero I/O APIC address"
			" found in MP table, skipping!\n");
		return;
	}
	mp_ioapics[nr_ioapics] = *m;
	nr_ioapics++;
}

static void __init MP_intsrc_info (struct mpc_config_intsrc *m)
{
	mp_irqs [mp_irq_entries] = *m;
	Dprintk("Int: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x, APIC ID %x, APIC INT %02x\n",
			m->mpc_irqtype, m->mpc_irqflag & 3,
			(m->mpc_irqflag >> 2) & 3, m->mpc_srcbus,
			m->mpc_srcbusirq, m->mpc_dstapic, m->mpc_dstirq);
	if (++mp_irq_entries == max_irq_sources)
		panic("Max # of irq sources exceeded!!\n");
}

static void __init MP_lintsrc_info (struct mpc_config_lintsrc *m)
{
	Dprintk("Lint: type %d, pol %d, trig %d, bus %d,"
		" IRQ %02x, APIC ID %x, APIC LINT %02x\n",
			m->mpc_irqtype, m->mpc_irqflag & 3,
			(m->mpc_irqflag >> 2) &3, m->mpc_srcbusid,
			m->mpc_srcbusirq, m->mpc_destapic, m->mpc_destapiclint);
	/*
	 * Well it seems all SMP boards in existence
	 * use ExtINT/LVT1 == LINT0 and
	 * NMI/LVT2 == LINT1 - the following check
	 * will show us if this assumptions is false.
	 * Until then we do not have to add baggage.
	 */
	if ((m->mpc_irqtype == mp_ExtINT) &&
		(m->mpc_destapiclint != 0))
			BUG();
	if ((m->mpc_irqtype == mp_NMI) &&
		(m->mpc_destapiclint != 1))
			BUG();
}

static void __init MP_translation_info (struct mpc_config_translation *m)
{
	printk("Translation: record %d, type %d, quad %d, global %d, local %d\n", mpc_record, m->trans_type, m->trans_quad, m->trans_global, m->trans_local);

	if (mpc_record >= MAX_MPC_ENTRY) 
		printk("MAX_MPC_ENTRY exceeded!\n");
	else
		translation_table[mpc_record] = m; /* stash this for later */
	if (m->trans_quad+1 > numnodes)
		numnodes = m->trans_quad+1;
}

/*
 * Read/parse the MPC oem tables
 */

static void __init smp_read_mpc_oem(struct mp_config_oemtable *oemtable, \
	unsigned short oemsize)
{
	int count = sizeof (*oemtable); /* the header size */
	unsigned char *oemptr = ((unsigned char *)oemtable)+count;
	
	printk("Found an OEM MPC table at %8p - parsing it ... \n", oemtable);
	if (memcmp(oemtable->oem_signature,MPC_OEM_SIGNATURE,4))
	{
		printk("SMP mpc oemtable: bad signature [%c%c%c%c]!\n",
			oemtable->oem_signature[0],
			oemtable->oem_signature[1],
			oemtable->oem_signature[2],
			oemtable->oem_signature[3]);
		return;
	}
	if (mpf_checksum((unsigned char *)oemtable,oemtable->oem_length))
	{
		printk("SMP oem mptable: checksum error!\n");
		return;
	}
	while (count < oemtable->oem_length) {
		switch (*oemptr) {
			case MP_TRANSLATION:
			{
				struct mpc_config_translation *m=
					(struct mpc_config_translation *)oemptr;
				MP_translation_info(m);
				oemptr += sizeof(*m);
				count += sizeof(*m);
				++mpc_record;
				break;
			}
			default:
			{
				printk("Unrecognised OEM table entry type! - %d\n", (int) *oemptr);
				return;
			}
		}
       }
}

/*
 * Read/parse the MPC
 */

static int __init smp_read_mpc(struct mp_config_table *mpc)
{
	char oem[16], prod[14];
	int count=sizeof(*mpc);
	unsigned char *mpt=((unsigned char *)mpc)+count;
	int num_bus = 0;
	int num_irq = 0;
	unsigned char *bus_data;

	if (memcmp(mpc->mpc_signature,MPC_SIGNATURE,4)) {
		panic("SMP mptable: bad signature [%c%c%c%c]!\n",
			mpc->mpc_signature[0],
			mpc->mpc_signature[1],
			mpc->mpc_signature[2],
			mpc->mpc_signature[3]);
		return 0;
	}
	if (mpf_checksum((unsigned char *)mpc,mpc->mpc_length)) {
		panic("SMP mptable: checksum error!\n");
		return 0;
	}
	if (mpc->mpc_spec!=0x01 && mpc->mpc_spec!=0x04) {
		printk(KERN_ERR "SMP mptable: bad table version (%d)!!\n",
			mpc->mpc_spec);
		return 0;
	}
	if (!mpc->mpc_lapic) {
		printk(KERN_ERR "SMP mptable: null local APIC address!\n");
		return 0;
	}
	memcpy(oem,mpc->mpc_oem,8);
	oem[8]=0;
	printk("OEM ID: %s ",oem);

	memcpy(prod,mpc->mpc_productid,12);
	prod[12]=0;
	printk("Product ID: %s ",prod);

	detect_clustered_apic(oem, prod);
	
	printk("APIC at: 0x%lX\n",mpc->mpc_lapic);

	/* save the local APIC address, it might be non-default,
	 * but only if we're not using the ACPI tables
	 */
	if (!have_acpi_tables)
		mp_lapic_addr = mpc->mpc_lapic;

	if ((clustered_apic_mode == CLUSTERED_APIC_NUMAQ) && mpc->mpc_oemptr) {
		/* We need to process the oem mpc tables to tell us which quad things are in ... */
		mpc_record = 0;
		smp_read_mpc_oem((struct mp_config_oemtable *) mpc->mpc_oemptr, mpc->mpc_oemsize);
		mpc_record = 0;
	}

	/* Pre-scan to determine the number of bus and 
	 * interrupts records we have
	 */
	while (count < mpc->mpc_length) {
		switch (*mpt) {
			case MP_PROCESSOR:
				mpt += sizeof(struct mpc_config_processor);
				count += sizeof(struct mpc_config_processor);
				break;
			case MP_BUS:
				++num_bus;
				mpt += sizeof(struct mpc_config_bus);
				count += sizeof(struct mpc_config_bus);
				break;
			case MP_INTSRC:
				++num_irq;
				mpt += sizeof(struct mpc_config_intsrc);
				count += sizeof(struct mpc_config_intsrc);
				break;
			case MP_IOAPIC:
				mpt += sizeof(struct mpc_config_ioapic);
				count += sizeof(struct mpc_config_ioapic);
				break;
			case MP_LINTSRC:
				mpt += sizeof(struct mpc_config_lintsrc);
				count += sizeof(struct mpc_config_lintsrc);
				break;
			default:
				count = mpc->mpc_length;
				break;
		}
	}
	/* 
	 * Paranoia: Allocate one extra of both the number of busses and number
	 * of irqs, and make sure that we have at least 4 interrupts per PCI
	 * slot.  But some machines do not report very many busses, so we need
	 * to fall back on the older defaults.
	 */
	++num_bus;
	max_mp_busses = max(num_bus, MAX_MP_BUSSES);
	if (num_irq < (4 * max_mp_busses))
		num_irq = 4 * num_bus;	/* 4 intr/PCI slot */
	++num_irq;
	max_irq_sources = max(num_irq, MAX_IRQ_SOURCES);
	
	count = (max_mp_busses * sizeof(int)) * 4;
	count += (max_irq_sources * sizeof(struct mpc_config_intsrc));
	
	{
	//bus_data = alloc_bootmem(count);  XXX Xen
	static char arr[4096];
	if(count > 4096) BUG();
	bus_data = (void*)arr;
	
	}
	if (!bus_data) {
		printk(KERN_ERR "SMP mptable: out of memory!\n");
		return 0;
	}
	mp_bus_id_to_type = (int *)&bus_data[0];
	mp_bus_id_to_node = (int *)&bus_data[(max_mp_busses * sizeof(int))];
	mp_bus_id_to_local = (int *)&bus_data[(max_mp_busses * sizeof(int)) * 2];
	mp_bus_id_to_pci_bus = (int *)&bus_data[(max_mp_busses * sizeof(int)) * 3];
	mp_irqs = (struct mpc_config_intsrc *)&bus_data[(max_mp_busses * sizeof(int)) * 4];
	memset(mp_bus_id_to_pci_bus, -1, max_mp_busses);

	/*
	 *	Now process the configuration blocks.
	 */
	count = sizeof(*mpc);
	mpt = ((unsigned char *)mpc)+count;
	while (count < mpc->mpc_length) {
		switch(*mpt) {
			case MP_PROCESSOR:
			{
				struct mpc_config_processor *m=
					(struct mpc_config_processor *)mpt;

				/* ACPI may already have provided this one for us */
				if (!have_acpi_tables)
					MP_processor_info(m);
				mpt += sizeof(*m);
				count += sizeof(*m);
				break;
			}
			case MP_BUS:
			{
				struct mpc_config_bus *m=
					(struct mpc_config_bus *)mpt;
				MP_bus_info(m);
				mpt += sizeof(*m);
				count += sizeof(*m);
				break;
			}
			case MP_IOAPIC:
			{
				struct mpc_config_ioapic *m=
					(struct mpc_config_ioapic *)mpt;
				MP_ioapic_info(m);
				mpt+=sizeof(*m);
				count+=sizeof(*m);
				break;
			}
			case MP_INTSRC:
			{
				struct mpc_config_intsrc *m=
					(struct mpc_config_intsrc *)mpt;

				MP_intsrc_info(m);
				mpt+=sizeof(*m);
				count+=sizeof(*m);
				break;
			}
			case MP_LINTSRC:
			{
				struct mpc_config_lintsrc *m=
					(struct mpc_config_lintsrc *)mpt;
				MP_lintsrc_info(m);
				mpt+=sizeof(*m);
				count+=sizeof(*m);
				break;
			}
			default:
			{
				count = mpc->mpc_length;
				break;
			}
		}
		++mpc_record;
	}

	if (clustered_apic_mode){
		phys_cpu_present_map = logical_cpu_present_map;
	}


	printk("Enabling APIC mode: ");
	if(clustered_apic_mode == CLUSTERED_APIC_NUMAQ)
		printk("Clustered Logical.	");
	else if(clustered_apic_mode == CLUSTERED_APIC_XAPIC)
		printk("Physical.	");
	else
		printk("Flat.	");
	printk("Using %d I/O APICs\n",nr_ioapics);

	if (!num_processors)
		printk(KERN_ERR "SMP mptable: no processors registered!\n");
	return num_processors;
}

static int __init ELCR_trigger(unsigned int irq)
{
	unsigned int port;

	port = 0x4d0 + (irq >> 3);
	return (inb(port) >> (irq & 7)) & 1;
}

static void __init construct_default_ioirq_mptable(int mpc_default_type)
{
	struct mpc_config_intsrc intsrc;
	int i;
	int ELCR_fallback = 0;

	intsrc.mpc_type = MP_INTSRC;
	intsrc.mpc_irqflag = 0;			/* conforming */
	intsrc.mpc_srcbus = 0;
	intsrc.mpc_dstapic = mp_ioapics[0].mpc_apicid;

	intsrc.mpc_irqtype = mp_INT;

	/*
	 *  If true, we have an ISA/PCI system with no IRQ entries
	 *  in the MP table. To prevent the PCI interrupts from being set up
	 *  incorrectly, we try to use the ELCR. The sanity check to see if
	 *  there is good ELCR data is very simple - IRQ0, 1, 2 and 13 can
	 *  never be level sensitive, so we simply see if the ELCR agrees.
	 *  If it does, we assume it's valid.
	 */
	if (mpc_default_type == 5) {
		printk("ISA/PCI bus type with no IRQ information... falling back to ELCR\n");

		if (ELCR_trigger(0) || ELCR_trigger(1) || ELCR_trigger(2) || ELCR_trigger(13))
			printk("ELCR contains invalid data... not using ELCR\n");
		else {
			printk("Using ELCR to identify PCI interrupts\n");
			ELCR_fallback = 1;
		}
	}

	for (i = 0; i < 16; i++) {
		switch (mpc_default_type) {
		case 2:
			if (i == 0 || i == 13)
				continue;	/* IRQ0 & IRQ13 not connected */
			/* fall through */
		default:
			if (i == 2)
				continue;	/* IRQ2 is never connected */
		}

		if (ELCR_fallback) {
			/*
			 *  If the ELCR indicates a level-sensitive interrupt, we
			 *  copy that information over to the MP table in the
			 *  irqflag field (level sensitive, active high polarity).
			 */
			if (ELCR_trigger(i))
				intsrc.mpc_irqflag = 13;
			else
				intsrc.mpc_irqflag = 0;
		}

		intsrc.mpc_srcbusirq = i;
		intsrc.mpc_dstirq = i ? i : 2;		/* IRQ0 to INTIN2 */
		MP_intsrc_info(&intsrc);
	}

	intsrc.mpc_irqtype = mp_ExtINT;
	intsrc.mpc_srcbusirq = 0;
	intsrc.mpc_dstirq = 0;				/* 8259A to INTIN0 */
	MP_intsrc_info(&intsrc);
}

static inline void __init construct_default_ISA_mptable(int mpc_default_type)
{
	struct mpc_config_processor processor;
	struct mpc_config_bus bus;
	struct mpc_config_ioapic ioapic;
	struct mpc_config_lintsrc lintsrc;
	int linttypes[2] = { mp_ExtINT, mp_NMI };
	int i;

	/*
	 * local APIC has default address
	 */
	mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;

	/*
	 * 2 CPUs, numbered 0 & 1.
	 */
	processor.mpc_type = MP_PROCESSOR;
	/* Either an integrated APIC or a discrete 82489DX. */
	processor.mpc_apicver = mpc_default_type > 4 ? 0x10 : 0x01;
	processor.mpc_cpuflag = CPU_ENABLED;
	processor.mpc_cpufeature = (boot_cpu_data.x86 << 8) |
				   (boot_cpu_data.x86_model << 4) |
				   boot_cpu_data.x86_mask;
	processor.mpc_featureflag = boot_cpu_data.x86_capability[0];
	processor.mpc_reserved[0] = 0;
	processor.mpc_reserved[1] = 0;
	for (i = 0; i < 2; i++) {
		processor.mpc_apicid = i;
		MP_processor_info(&processor);
	}

	bus.mpc_type = MP_BUS;
	bus.mpc_busid = 0;
	switch (mpc_default_type) {
		default:
			printk("???\nUnknown standard configuration %d\n",
				mpc_default_type);
			/* fall through */
		case 1:
		case 5:
			memcpy(bus.mpc_bustype, "ISA   ", 6);
			break;
		case 2:
		case 6:
		case 3:
			memcpy(bus.mpc_bustype, "EISA  ", 6);
			break;
		case 4:
		case 7:
			memcpy(bus.mpc_bustype, "MCA   ", 6);
	}
	MP_bus_info(&bus);
	if (mpc_default_type > 4) {
		bus.mpc_busid = 1;
		memcpy(bus.mpc_bustype, "PCI   ", 6);
		MP_bus_info(&bus);
	}

	ioapic.mpc_type = MP_IOAPIC;
	ioapic.mpc_apicid = 2;
	ioapic.mpc_apicver = mpc_default_type > 4 ? 0x10 : 0x01;
	ioapic.mpc_flags = MPC_APIC_USABLE;
	ioapic.mpc_apicaddr = 0xFEC00000;
	MP_ioapic_info(&ioapic);

	/*
	 * We set up most of the low 16 IO-APIC pins according to MPS rules.
	 */
	construct_default_ioirq_mptable(mpc_default_type);

	lintsrc.mpc_type = MP_LINTSRC;
	lintsrc.mpc_irqflag = 0;		/* conforming */
	lintsrc.mpc_srcbusid = 0;
	lintsrc.mpc_srcbusirq = 0;
	lintsrc.mpc_destapic = MP_APIC_ALL;
	for (i = 0; i < 2; i++) {
		lintsrc.mpc_irqtype = linttypes[i];
		lintsrc.mpc_destapiclint = i;
		MP_lintsrc_info(&lintsrc);
	}
}

static struct intel_mp_floating *mpf_found;
extern void 	config_acpi_tables(void);

/*
 * Scan the memory blocks for an SMP configuration block.
 */
void __init get_smp_config (void)
{
	struct intel_mp_floating *mpf = mpf_found;

#ifdef CONFIG_X86_IO_APIC
	/*
	 * Check if the ACPI tables are provided. Use them only to get
	 * the processor information, mainly because it provides
	 * the info on the logical processor(s), rather than the physical
	 * processor(s) that are provided by the MPS. We attempt to 
	 * check only if the user provided a commandline override
	 */
        config_acpi_tables();
#endif
	
	printk("Intel MultiProcessor Specification v1.%d\n", mpf->mpf_specification);
	if (mpf->mpf_feature2 & (1<<7)) {
		printk("    IMCR and PIC compatibility mode.\n");
		pic_mode = 1;
	} else {
		printk("    Virtual Wire compatibility mode.\n");
		pic_mode = 0;
	}

	/*
	 * Now see if we need to read further.
	 */
	if (mpf->mpf_feature1 != 0) {

		printk("Default MP configuration #%d\n", mpf->mpf_feature1);
		construct_default_ISA_mptable(mpf->mpf_feature1);

	} else if (mpf->mpf_physptr) {

		/*
		 * Read the physical hardware table.  Anything here will
		 * override the defaults.
		 */
		if (!smp_read_mpc((void *)mpf->mpf_physptr)) {
			smp_found_config = 0;
			printk(KERN_ERR "BIOS bug, MP table errors detected!...\n");
			printk(KERN_ERR "... disabling SMP support. (tell your hw vendor)\n");
			return;
		}
		/*
		 * If there are no explicit MP IRQ entries, then we are
		 * broken.  We set up most of the low 16 IO-APIC pins to
		 * ISA defaults and hope it will work.
		 */
		if (!mp_irq_entries) {
			struct mpc_config_bus bus;

			printk("BIOS bug, no explicit IRQ entries, using default mptable. (tell your hw vendor)\n");

			bus.mpc_type = MP_BUS;
			bus.mpc_busid = 0;
			memcpy(bus.mpc_bustype, "ISA   ", 6);
			MP_bus_info(&bus);

			construct_default_ioirq_mptable(0);
		}

	} else
		BUG();

	printk("Processors: %d\n", num_processors);
	/*
	 * Only use the first configuration found.
	 */
}

static int __init smp_scan_config (unsigned long base, unsigned long length)
{
	unsigned long *bp = phys_to_virt(base);
	struct intel_mp_floating *mpf;

	Dprintk("Scan SMP from %p for %ld bytes.\n", bp,length);
	if (sizeof(*mpf) != 16)
		printk("Error: MPF size\n");

	while (length > 0) {
		mpf = (struct intel_mp_floating *)bp;
		if ((*bp == SMP_MAGIC_IDENT) &&
			(mpf->mpf_length == 1) &&
			!mpf_checksum((unsigned char *)bp, 16) &&
			((mpf->mpf_specification == 1)
				|| (mpf->mpf_specification == 4)) ) {

			smp_found_config = 1;
			printk("found SMP MP-table at %08lx\n",
						virt_to_phys(mpf));
			reserve_bootmem(virt_to_phys(mpf), PAGE_SIZE);
			if (mpf->mpf_physptr)
				reserve_bootmem(mpf->mpf_physptr, PAGE_SIZE);
			mpf_found = mpf;
			return 1;
		}
		bp += 4;
		length -= 16;
	}
	return 0;
}

void __init find_intel_smp (void)
{
	unsigned int address;

	/*
	 * FIXME: Linux assumes you have 640K of base ram..
	 * this continues the error...
	 *
	 * 1) Scan the bottom 1K for a signature
	 * 2) Scan the top 1K of base RAM
	 * 3) Scan the 64K of bios
	 */
	if (smp_scan_config(0x0,0x400) ||
		smp_scan_config(639*0x400,0x400) ||
			smp_scan_config(0xF0000,0x10000))
		return;
	/*
	 * If it is an SMP machine we should know now, unless the
	 * configuration is in an EISA/MCA bus machine with an
	 * extended bios data area.
	 *
	 * there is a real-mode segmented pointer pointing to the
	 * 4K EBDA area at 0x40E, calculate and scan it here.
	 *
	 * NOTE! There were Linux loaders that will corrupt the EBDA
	 * area, and as such this kind of SMP config may be less
	 * trustworthy, simply because the SMP table may have been
	 * stomped on during early boot.  Thankfully the bootloaders
	 * now honour the EBDA.
	 */

	address = *(unsigned short *)phys_to_virt(0x40E);
	address <<= 4;
	smp_scan_config(address, 0x1000);
}

#else

/*
 * The Visual Workstation is Intel MP compliant in the hardware
 * sense, but it doesn't have a BIOS(-configuration table).
 * No problem for Linux.
 */
void __init find_visws_smp(void)
{
	smp_found_config = 1;

	phys_cpu_present_map |= 2; /* or in id 1 */
	apic_version[1] |= 0x10; /* integrated APIC */
	apic_version[0] |= 0x10;

	mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;
}

#endif

/*
 * - Intel MP Configuration Table
 * - or SGI Visual Workstation configuration
 */
void __init find_smp_config (void)
{
#ifdef CONFIG_X86_LOCAL_APIC
	find_intel_smp();
#endif
#ifdef CONFIG_VISWS
	find_visws_smp();
#endif
}

