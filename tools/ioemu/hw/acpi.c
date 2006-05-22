/*
 * ACPI emulation
 * 
 * Copyright (c) 2006 Virtual Iron Software
 *
 * This module provides the beginnings of some ACPI emulation.
 * Initially, this code handles writes to the sleep state
 * registers. This is done to detect requests to power-off
 * a guest domain.
 *
 * Later, and driven by empirical evidence, additional capabilities
 * and emulation might be added.
 *
 * Currently, the FADT specifies a small register set, of which
 * only PM1_CNTa is available.  In addition, the ASL code specifies
 * the proper values to write on an S5 (poweroff) request, which
 * this code understands.
 *
 */

#include "vl.h"
extern FILE* logfile;

// Define some basic offsets to ACPI registers

//#define DEBUG_ACPI
#define	PM1a_STS	0x0
#define	PM1a_EN		0x1
#define	PM1b_STS	0x2
#define	PM1b_EN		0x3
#define	PM1_CNTa	0x4
#define	PM1_CNTb	0x6

// Values within PM1_CNTa that we need for power handling

#define	SLP_TYP_MASK	0x1C00
#define	SLP_VAL		0x1C00
#define	SLP_EN		0x2000

// Base ACPI register address

static unsigned int acpi_base = 0;

/* acpi_write_byte - handle byte writes for ACPI I/O region
 *
 * Input:
 *	opaque	pointer to private data structure (currently NULL)
 *	addr	I/O space address to be written
 *	data	data to be written
 *
 * Output:
 *	none
 *
 * Returns:
 *	none
 */

static void acpi_write_byte(void *opaque, uint32_t addr, uint32_t data) {

#ifdef DEBUG_ACPI
    fprintf(logfile, "%s - addr 0x%x, data 0x%x\n", __FUNCTION__, addr, data);
#endif

    // All byte writes are currently ignored

    return;
}

/* acpi_write_word - handle word writes for ACPI I/O region
 *
 * Input:
 *	opaque	pointer to private data structure (currently NULL)
 *	addr	I/O space address to be written
 *	data	data to be written
 *
 * Output:
 *	none
 *
 * Returns:
 *	none
 */

static void acpi_write_word(void *opaque, uint32_t addr, uint32_t data) {

#ifdef DEBUG_ACPI
    fprintf(logfile, "%s - addr 0x%x, data 0x%x\n", __FUNCTION__, addr, data);
#endif

    // Only a write to PM1_CNTa for power operations is handled
    // All others are ignored

    if (addr == acpi_base + PM1_CNTa) {
        if ( ( (data & SLP_EN) != 0) &&
             ( (data & SLP_TYP_MASK) == SLP_VAL) ) {
            qemu_system_shutdown_request();
            fprintf(logfile, "%s - ACPI Power State 5 (poweroff) requested\n", __FUNCTION__);
        }
    }

    return;
}

/* acpi_read_byte - handle byte reads for ACPI I/O region
 *
 * Input:
 *	opaque	pointer to private data structure (currently NULL)
 *	addr	I/O space address to be written
 *
 * Output:
 *	none
 *
 * Returns:
 *	data read
 */

static uint32_t acpi_read_byte(void *opaque, uint32_t addr) {

#ifdef DEBUG_ACPI
    fprintf(logfile, "%s - addr 0x%x\n", __FUNCTION__, addr);
#endif

    // All reads return 0

    return 0;
}

/* acpi_read_word - handle word reads for ACPI I/O region
 *
 * Input:
 *	opaque	pointer to private data structure (currently NULL)
 *	addr	I/O space address to be written
 *
 * Output:
 *	none
 *
 * Returns:
 *	data read
 */

static uint32_t acpi_read_word(void *opaque, uint32_t addr) {

#ifdef DEBUG_ACPI
    fprintf(logfile, "%s - addr 0x%x\n", __FUNCTION__, addr);
#endif

    // All reads return 0

    return 0;
}

/* acpi_init - initialize for ACPI I/O space operation handling
 *
 * Input:
 *	base	base I/O address
 *
 * Output:
 *	none
 *
 * Returns:
 *	status
 */

int acpi_init(unsigned int base) {

    fprintf(logfile, "%s - registering ACPI addresses at 0x%x\n", __FUNCTION__, base);

    // Map 16 bytes of reads/writes for bytes/words

    register_ioport_write(base, 16, sizeof(unsigned char), acpi_write_byte, NULL);
    register_ioport_read(base,  16, sizeof(unsigned char), acpi_read_byte,  NULL);

    register_ioport_write(base, 16, sizeof(unsigned short), acpi_write_word, NULL);
    register_ioport_read(base,  16, sizeof(unsigned short), acpi_read_word,  NULL);

    acpi_base = base;

    return 0;
}
