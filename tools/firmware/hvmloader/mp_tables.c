/*
 * mp_tables.c: Dynamically writes MP table info into the ROMBIOS.
 *
 * In order to work with various VCPU counts, this code reads the VCPU count
 * for the HVM partition and creates the correct MP tables for the VCPU count
 * and places the information into a predetermined location set aside in the
 * ROMBIOS during build time.
 *
 * Please note that many of the values, such as the CPU's
 * family/model/stepping, are hard-coded based upon the values that were used
 * in the ROMBIOS and may need to be modified or calculated dynamically to
 * correspond with what an HVM guest's CPUID returns.
 *
 * Travis Betak, travis.betak@amd.com
 * Copyright (c) 2006, AMD.
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
 */


/* FIXME find a header that already has types defined!!! */
typedef unsigned char  uint8_t;
typedef   signed char  int8_t;
typedef unsigned short uint16_t;
typedef   signed short int16_t;
typedef unsigned int   uint32_t;
typedef   signed int   int32_t;
#ifdef __i386__
typedef unsigned long long uint64_t;
typedef   signed long long int64_t;
#else
typedef unsigned long uint64_t;
typedef   signed long int64_t;
#endif

#define ROMBIOS_SEG              0xF000
#define ROMBIOS_BEGIN            0x000F0000
#define ROMBIOS_SIZE             0x00010000 
#define ROMBIOS_MAXOFFSET        0x0000FFFF
#define ROMBIOS_END             (ROMBIOS_BEGIN + ROMBIOS_SIZE)

/* number of non-processor MP table entries */
#define NR_NONPROC_ENTRIES     18

#define ENTRY_TYPE_PROCESSOR   0
#define ENTRY_TYPE_BUS         1
#define ENTRY_TYPE_IOAPIC      2
#define ENTRY_TYPE_IO_INTR     3
#define ENTRY_TYPE_LOCAL_INTR  4

#define CPU_FLAG_ENABLED       0x01
#define CPU_FLAG_BSP           0x02

/* TODO change this to correspond with what the guest's see's from CPUID */
#define CPU_SIG_FAMILY         0x06
#define CPU_SIG_MODEL          0x00
#define CPU_SIG_STEPPING       0x00
#define CPU_SIGNATURE        ((CPU_SIG_FAMILY << 8)  \
                             | (CPU_SIG_MODEL << 4)  \
                             | (CPU_SIG_STEPPING))
#define CPU_FEATURE_FPU       (1U << 0)
#define CPU_FEATURE_MCE       (1U << 7)
#define CPU_FEATURE_CX8       (1U << 8)
#define CPU_FEATURE_APIC      (1U << 9)
#define CPU_FEATURES          (CPU_FEATURE_FPU | CPU_FEATURE_APIC)

#define BUS_TYPE_LENGTH        6
#define BUS_TYPE_STR_ISA       "ISA   "

#define LAPIC_BASE_ADDR        0xFEE00000

#define IOAPIC_VERSION         0x11
#define IOAPIC_BASE_ADDR       0xFEC00000
#define IOAPIC_FLAG_ENABLED   (1U << 0)

#define INTR_TYPE_INT          0
#define INTR_TYPE_NMI          1
#define INTR_TYPE_SMI          2
#define INTR_TYPE_EXTINT       3

#define INTR_FLAGS             0

#define INTR_MAX_NR            16

extern int puts(const char *); /* for printing */
extern int get_vcpu_nr(void);  /* for the guest's VCPU count */

/*
 * The following structures are defined in the MuliProcessor Specifiation v1.4
 */

/* MP Floating Pointer Structure */
struct mp_floating_pointer_struct {
	uint8_t signature[4];
	uint32_t mp_table;
	uint8_t length;
	uint8_t revision;
	uint8_t checksum;
	uint8_t feature[5];
};

/* MP Configuration Table */
struct mp_config_table {
	uint8_t signature[4];
	uint16_t length;
	uint8_t revision;
	uint8_t checksum;
	uint8_t oem_id[8];
	uint8_t vendor_id[12];
	uint32_t oem_table;
	uint16_t oem_table_sz;
	uint16_t nr_entries;
	uint32_t lapic;
	uint16_t extended_length;
	uint8_t extended_checksum;
	uint8_t reserved;
};

/* MP Processor Entry */
struct mp_proc_entry {
	uint8_t type;
	uint8_t lapic_id;
	uint8_t lapic_version;
	uint8_t cpu_flags;
	uint32_t cpu_signature;
	uint32_t feature_flags;
	uint8_t reserved[8];
};

/* MP Bus Entry */
struct mp_bus_entry {
	uint8_t type;
	uint8_t bus_id;
	uint8_t bus_type_str[6];
};

/* MP IOAPIC Entry */
struct mp_ioapic_entry {
	uint8_t type;
	uint8_t ioapic_id;
	uint8_t ioapic_version;
	uint8_t ioapic_flags;
	uint32_t ioapic_addr;
};

/* MP IO Interrupt Entry */
struct mp_io_intr_entry {
	uint8_t type;
	uint8_t intr_type;
	uint16_t io_intr_flags;
	uint8_t src_bus_id;
	uint8_t src_bus_irq;
	uint8_t dst_ioapic_id;
	uint8_t dst_ioapic_intin;
};

/* MP Local Interrupt Entry */
struct mp_local_intr_entry {
	uint8_t type;
	uint8_t intr_type;
	uint16_t local_intr_flags;
	uint8_t src_bus_id;
	uint8_t src_bus_irq;
	uint8_t dst_lapic_id;
	uint8_t dst_lapic_lintin;
};


/* 
 * fill_mp_config_table - fills in the information for the MP config table
 *    
 * When calculating the length and nr_entries fields, keep in mind that there
 * are always 18 non-processor entries and N processor entries
 * 
 *    N vcpu entries
 *    1 bus entry 
 *    1 IOAPIC entry 
 * + 16 IO intr. entries
 * ----------------------
 * 18 + N total entries
 */
void fill_mp_config_table(struct mp_config_table *mpct)
{
	int vcpu_nr;

	vcpu_nr = get_vcpu_nr();

	/* fill in the MP configuration table signature, "PCMP" */
	mpct->signature[0] = 'P';
	mpct->signature[1] = 'C';
	mpct->signature[2] = 'M';
	mpct->signature[3] = 'P';

	mpct->length =    sizeof(struct mp_config_table)
			+ vcpu_nr * sizeof(struct mp_proc_entry)
			+ sizeof(struct mp_ioapic_entry)
			+ sizeof(struct mp_bus_entry)
			+ 16 * sizeof(struct mp_local_intr_entry);

	mpct->revision = 4;

	/* 
	 * We'll fill in the checksum later after all of the 
	 * entries have been created
	 */
	mpct->checksum = 0;

	/* fill in the OEM ID string, "_HVMCPU_" */
	mpct->oem_id[0] = '_'; mpct->oem_id[3] = 'M'; mpct->oem_id[6] = 'U';
	mpct->oem_id[1] = 'H'; mpct->oem_id[4] = 'C'; mpct->oem_id[7] = '_';
	mpct->oem_id[2] = 'V'; mpct->oem_id[5] = 'P';

	/* fill in the Vendor ID string, "XEN         " */
	mpct->vendor_id[0] = 'X'; mpct->vendor_id[6] =  ' ';
	mpct->vendor_id[1] = 'E'; mpct->vendor_id[7] =  ' ';
	mpct->vendor_id[2] = 'N'; mpct->vendor_id[8] =  ' ';
	mpct->vendor_id[3] = ' '; mpct->vendor_id[9] =  ' ';
	mpct->vendor_id[4] = ' '; mpct->vendor_id[10] = ' ';
	mpct->vendor_id[5] = ' '; mpct->vendor_id[11] = ' ';

	mpct->oem_table = 0;
	mpct->oem_table_sz = 0;

	mpct->nr_entries = vcpu_nr + NR_NONPROC_ENTRIES;

	mpct->lapic = LAPIC_BASE_ADDR;
	mpct->extended_length = 0;
	mpct->extended_checksum = 0;
}


/* calculates the checksum for the MP configuration table */
void fill_mp_config_table_checksum(struct mp_config_table *mpct)
{
	int i;
	uint8_t checksum;

	checksum = 0;
	for (i = 0; i < mpct->length; ++i)
		checksum += ((uint8_t *)(mpct))[i];
	mpct->checksum = -checksum;
}


/* fills in an MP processor entry for VCPU 'vcpu_id' */
void fill_mp_proc_entry(struct mp_proc_entry *mppe, int vcpu_id)
{
	mppe->type = ENTRY_TYPE_PROCESSOR;
	mppe->lapic_id = vcpu_id;
	mppe->lapic_version = 0x11;
	mppe->cpu_flags = CPU_FLAG_ENABLED;
	if (vcpu_id == 0)
		mppe->cpu_flags |= CPU_FLAG_BSP;
	mppe->cpu_signature = CPU_SIGNATURE;
	mppe->feature_flags = CPU_FEATURES;
}


/* fills in an MP bus entry of type 'type' and bus ID 'bus_id' */
void fill_mp_bus_entry(struct mp_bus_entry *mpbe, int bus_id, const char *type)
{
	int i;

	mpbe->type = ENTRY_TYPE_BUS;
	mpbe->bus_id = bus_id;
	for (i = 0; i < BUS_TYPE_LENGTH; ++i)
		mpbe->bus_type_str[i] = type[i]; /* FIXME length check? */
}


/* fills in an MP IOAPIC entry for IOAPIC 'ioapic_id' */
void fill_mp_ioapic_entry(struct mp_ioapic_entry *mpie, int ioapic_id)
{
	mpie->type = ENTRY_TYPE_IOAPIC;
	mpie->ioapic_id = ioapic_id;
	mpie->ioapic_version = IOAPIC_VERSION;
	mpie->ioapic_flags = IOAPIC_FLAG_ENABLED;
	mpie->ioapic_addr = IOAPIC_BASE_ADDR;
}


/* fills in an IO interrupt entry for IOAPIC 'ioapic_id' */
void fill_mp_io_intr_entry(struct mp_io_intr_entry *mpiie,
		int src_bus_irq, int ioapic_id, int dst_ioapic_intin)
{
	mpiie->type = ENTRY_TYPE_IO_INTR;
	mpiie->intr_type = INTR_TYPE_INT;
	mpiie->io_intr_flags = INTR_FLAGS;
	mpiie->src_bus_id = 0;
	mpiie->src_bus_irq = src_bus_irq;
	mpiie->dst_ioapic_id = ioapic_id;
	mpiie->dst_ioapic_intin = dst_ioapic_intin;
}


/* fill in the mp floating processor structure */
void fill_mpfps(struct mp_floating_pointer_struct *mpfps, uint32_t mpct)
{
	int i;
	uint8_t checksum;


	mpfps->signature[0] = '_';
	mpfps->signature[1] = 'M';
	mpfps->signature[2] = 'P';
	mpfps->signature[3] = '_';

	mpfps->mp_table = mpct; 
	mpfps->length = 1;
	mpfps->revision = 4;
	mpfps->checksum = 0;
	for (i = 0; i < 5; ++i)
		mpfps->feature[i] = 0;

	/* compute the checksum for our new table */
	checksum = 0;
	for (i = 0; i < sizeof(struct mp_floating_pointer_struct); ++i)
		checksum += ((uint8_t *)(mpfps))[i];
	mpfps->checksum = -checksum;
}


/*
 * find_mp_table_start - searchs through BIOS memory for '___HVMMP' signature
 *
 * The '___HVMMP' signature is created by the ROMBIOS and designates a chunk
 * of space inside the ROMBIOS that is safe for us to write our MP table info
 */
void* get_mp_table_start(void)
{
	char *bios_mem;
	for (bios_mem = (char *)ROMBIOS_BEGIN; 
	     bios_mem != (char *)ROMBIOS_END; 
	     ++bios_mem)
		if (bios_mem[0] == '_' && bios_mem[1] == '_' &&
		    bios_mem[2] == '_' && bios_mem[3] == 'H' &&
		    bios_mem[4] == 'V' && bios_mem[5] == 'M' &&
		    bios_mem[6] == 'M' && bios_mem[7] == 'P')
			return bios_mem;

	return (void *)-1;
}


/* recalculate the new ROMBIOS checksum after adding MP tables */
void reset_bios_checksum(void)
{
	uint32_t i;
	uint8_t checksum;

	checksum = 0;
	for (i = 0; i < ROMBIOS_MAXOFFSET; ++i)
		checksum += ((uint8_t *)(ROMBIOS_BEGIN))[i];
	
	*((uint8_t *)(ROMBIOS_BEGIN + ROMBIOS_MAXOFFSET)) = -checksum;
}


/* create_mp_tables - creates MP tables for the guest based upon config data */
void create_mp_tables(void)
{
	void *mp_table_base;
	char *p;
	struct mp_config_table *mp_config_table;
	int vcpu_nr;
	int i;

	vcpu_nr = get_vcpu_nr();
	
	puts("Creating MP tables ...\n");

	/* find the 'safe' place in ROMBIOS for the MP tables */
	mp_table_base = get_mp_table_start();
	if (mp_table_base == (void *)-1) {
		puts("Couldn't find start point for MP tables\n");
		return;
	}
	p = mp_table_base;

	fill_mp_config_table((struct mp_config_table *)p);

 	/* save the location of the MP config table for a little later*/
	mp_config_table = (struct mp_config_table *)p;
	p += sizeof(struct mp_config_table);

	for (i = 0; i < vcpu_nr; ++i) {
		fill_mp_proc_entry((struct mp_proc_entry *)p, i);
		p += sizeof(struct mp_proc_entry);
	}

	fill_mp_bus_entry((struct mp_bus_entry *)p, 0, BUS_TYPE_STR_ISA);
	p += sizeof(struct mp_bus_entry);

	fill_mp_ioapic_entry((struct mp_ioapic_entry *)p, vcpu_nr);
	p += sizeof(struct mp_ioapic_entry);

	for (i = 0; i < INTR_MAX_NR; ++i) {
		fill_mp_io_intr_entry((struct mp_io_intr_entry *)p, 
				i, vcpu_nr, i);
		p += sizeof(struct mp_io_intr_entry);
	}

	/* find the next 16-byte boundary to place the mp floating pointer */
	while ((unsigned long)p & 0xF)
		++p;
	
	fill_mpfps((struct mp_floating_pointer_struct *)p, 
			(uint32_t)mp_table_base);

	/* calculate the MP configuration table's checksum */
	fill_mp_config_table_checksum(mp_config_table);

	/* finally, recalculate the ROMBIOS checksum */
	reset_bios_checksum();
}
