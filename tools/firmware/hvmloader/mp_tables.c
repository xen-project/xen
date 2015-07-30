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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include "config.h"

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
#define BUS_ID_ISA             0

#define INTR_TYPE_INT          0
#define INTR_TYPE_NMI          1
#define INTR_TYPE_SMI          2
#define INTR_TYPE_EXTINT       3

#define INTR_MAX_NR            16

#include "util.h"

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


static void fill_mp_config_table(struct mp_config_table *mpct, int length)
{
    int vcpu_nr, i;
    uint8_t checksum;

    vcpu_nr = hvm_info->nr_vcpus;

    /* fill in the MP configuration table signature, "PCMP" */
    mpct->signature[0] = 'P';
    mpct->signature[1] = 'C';
    mpct->signature[2] = 'M';
    mpct->signature[3] = 'P';

    mpct->length = length;

    mpct->revision = 4;

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

    mpct->lapic = LAPIC_BASE_ADDRESS;
    mpct->extended_length = 0;
    mpct->extended_checksum = 0;

    /* Finally, fill in the checksum. */
    mpct->checksum = checksum = 0;
    for ( i = 0; i < length; i++ )
        checksum += ((uint8_t *)(mpct))[i];
    mpct->checksum = -checksum;
}

/* fills in an MP processor entry for VCPU 'vcpu_id' */
static void fill_mp_proc_entry(struct mp_proc_entry *mppe, int vcpu_id)
{
    mppe->type = ENTRY_TYPE_PROCESSOR;
    mppe->lapic_id = LAPIC_ID(vcpu_id);
    mppe->lapic_version = 0x11;
    mppe->cpu_flags = CPU_FLAG_ENABLED;
    if ( vcpu_id == 0 )
        mppe->cpu_flags |= CPU_FLAG_BSP;
    mppe->cpu_signature = CPU_SIGNATURE;
    mppe->feature_flags = CPU_FEATURES;
}


/* fills in an MP bus entry of type 'type' and bus ID 'bus_id' */
static void fill_mp_bus_entry(
    struct mp_bus_entry *mpbe, int bus_id, const char *type)
{
    int i;

    mpbe->type = ENTRY_TYPE_BUS;
    mpbe->bus_id = bus_id;
    for ( i = 0; i < BUS_TYPE_LENGTH; i++ )
        mpbe->bus_type_str[i] = type[i]; /* FIXME length check? */
}


/* fills in an MP IOAPIC entry for IOAPIC 'ioapic_id' */
static void fill_mp_ioapic_entry(struct mp_ioapic_entry *mpie)
{
    mpie->type = ENTRY_TYPE_IOAPIC;
    mpie->ioapic_id = IOAPIC_ID;
    mpie->ioapic_version = IOAPIC_VERSION;
    mpie->ioapic_flags = 1; /* enabled */
    mpie->ioapic_addr = IOAPIC_BASE_ADDRESS;
}


/* fill in the mp floating processor structure */
static void fill_mpfps(struct mp_floating_pointer_struct *mpfps, uint32_t mpct)
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
    for ( i = 0; i < sizeof(struct mp_floating_pointer_struct); i++ )
        checksum += ((uint8_t *)(mpfps))[i];
    mpfps->checksum = -checksum;
}

/* create_mp_tables - creates MP tables for the guest based upon config data */
unsigned long create_mp_tables(void *_mpfps)
{
    char *p;
    int vcpu_nr, i, length;
    void *base;
    struct mp_io_intr_entry *mpiie;
    struct mp_floating_pointer_struct *mpfps;

    vcpu_nr = hvm_info->nr_vcpus;

    printf("Creating MP tables ...\n");

    if ( _mpfps == NULL )
    {
        int sz;

        sz  = sizeof(struct mp_floating_pointer_struct);
        sz += sizeof(struct mp_config_table);
        sz += sizeof(struct mp_proc_entry) * vcpu_nr;
        sz += sizeof(struct mp_bus_entry);
        sz += sizeof(struct mp_ioapic_entry);
        sz += sizeof(struct mp_io_intr_entry) * 16;

        _mpfps = mem_alloc(sz, 0);
    }

    mpfps = _mpfps;

    base = &mpfps[1];

    p = base + sizeof(struct mp_config_table);

    for ( i = 0; i < vcpu_nr; i++ )
    {
        fill_mp_proc_entry((struct mp_proc_entry *)p, i);
        p += sizeof(struct mp_proc_entry);
    }

    fill_mp_bus_entry((struct mp_bus_entry *)p, BUS_ID_ISA, BUS_TYPE_STR_ISA);
    p += sizeof(struct mp_bus_entry);

    fill_mp_ioapic_entry((struct mp_ioapic_entry *)p);
    p += sizeof(struct mp_ioapic_entry);

    /* I/O interrupt assignment: IOAPIC pin 0 is connected to 8259 ExtInt. */
    mpiie = (struct mp_io_intr_entry *)p;
    memset(mpiie, 0, sizeof(*mpiie));
    mpiie->type = ENTRY_TYPE_IO_INTR;
    mpiie->intr_type = INTR_TYPE_EXTINT;
    mpiie->dst_ioapic_id = IOAPIC_ID;
    p += sizeof(*mpiie);

    /* I/O interrupt assignment for every legacy 8259 interrupt source. */
    for ( i = 0; i < 16; i++ )
    {
        if ( i == 2 )
            continue; /* skip the slave PIC connection */
        mpiie = (struct mp_io_intr_entry *)p;
        mpiie->type = ENTRY_TYPE_IO_INTR;
        mpiie->intr_type = INTR_TYPE_INT;
        mpiie->io_intr_flags = (PCI_ISA_IRQ_MASK & (1U << i)) ? 0xf : 0x0;
        mpiie->src_bus_id = BUS_ID_ISA;
        mpiie->src_bus_irq = i;
        mpiie->dst_ioapic_id = IOAPIC_ID;
        mpiie->dst_ioapic_intin = (i == 0) ? 2 : i;
        p += sizeof(*mpiie);
    }

    length = p - (char *)base;

    fill_mp_config_table((struct mp_config_table *)base, length);

    fill_mpfps(mpfps, (uint32_t)base);

    return (unsigned long)mpfps;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
