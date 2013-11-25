/*
 *  Implementation of the TCG BIOS extension according to the specification
 *  described in
 *  https://www.trustedcomputinggroup.org/specs/PCClient/TCG_PCClientImplementationforBIOS_1-20_1-00.pdf
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#include "rombios_compat.h"
#include "tpm_drivers.h"

#include "util.h"
#include "tcgbios.h"

/* local structure and variables */
struct ptti_cust {
	uint16_t    ipblength;
	uint16_t    reserved;
	uint16_t    opblength;
	uint16_t    reserved2;
	uint8_t     tpmoperandin[18];
} __attribute__((packed));

struct ptti_cust CMD_TPM_Startup_0x01_IPB = {
    0x8+0xc, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x99, 0x00, 0x01 },
};

struct ptti_cust CMD_TSC_PhysicalPresence_0x20_IPB = {
    0x8+0xc, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x0a, 0x00, 0x20 },
};

struct ptti_cust CMD_TSC_PhysicalPresence_0x08_IPB = {
    0x8+0xc, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x0a, 0x00, 0x08 },
};

struct ptti_cust CMD_TSC_PhysicalPresence_0x100_IPB = {
    0x8+0xc, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x0a, 0x01, 0x00 },
};

struct ptti_cust CMD_TSC_PhysicalPresence_0x10_IPB = {
    0x8+0xc, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x0a, 0x00, 0x10 },
};

struct ptti_cust CMD_TPM_PhysicalEnable_IPB = {
    0x8+0xa, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x6f },
};

struct ptti_cust CMD_TPM_PhysicalSetDeactivated_0x00_IPB = {
    0x8+0xb, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x72, 0x00 }
};
struct ptti_cust CMD_TPM_SHA1Start_IPB = {
    0x8+0xa, 0x00, 4+10, 0x00,
    { 0x00, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xa0 },
};

struct ptti_cust CMD_TPM_GetCap_Version_IPB = {
    0x8+0x12, 0x00, 4+18, 0x00,
    {0x00, 0xc1, 0x00, 0x00, 0x00, 0x12,
     0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00 },
};

struct ptti_cust *TCG_CommandList[] = {
	&CMD_TPM_Startup_0x01_IPB,
	&CMD_TSC_PhysicalPresence_0x20_IPB,
	&CMD_TSC_PhysicalPresence_0x08_IPB,
	&CMD_TSC_PhysicalPresence_0x100_IPB,
	&CMD_TSC_PhysicalPresence_0x10_IPB,
	&CMD_TPM_PhysicalEnable_IPB,
	&CMD_TPM_PhysicalSetDeactivated_0x00_IPB,
	&CMD_TPM_SHA1Start_IPB,
};

/* local function prototypes */
static void sha1(const unsigned char *data, uint32_t length,
                 unsigned char *hash);
static uint32_t TCG_ShutdownPreBootInterface(uint32_t ebx);
static uint32_t HashAll32(struct hai *hai, unsigned char *hash,
                          uint32_t magic, uint32_t ecx, uint32_t edx);
static uint32_t HashLogExtendEvent32(struct hleei_short *hleei_s,
                                     struct hleeo *hleeo,
                                     uint32_t magic, uint32_t ecx,
                                     uint32_t edx);
static uint32_t HashLogEvent32(struct hlei *hlei, struct hleo *hleo,
                               uint32_t ebx, uint32_t ecx, uint32_t edx);
static uint32_t PassThroughToTPM32(struct pttti *pttti, struct pttto *pttto,
                                   uint32_t magic, uint32_t ecx, uint32_t edx);
static uint32_t MA_Transmit(unsigned char *cmdbuffer,
                            unsigned char *respbuffer,
                            uint32_t respbufferlen);

static unsigned char *tcpa_get_lasa_last_ptr(void);
static unsigned char *tcpa_get_lasa_base_ptr(void);
static void tcpa_reset_acpi_log(void);
static uint32_t tcpa_get_laml(void);


extern struct tpm_driver tpm_drivers[];

/* utility functions */

static inline uint32_t bswap(uint32_t a)
{
	return ( ( a >> 24 ) & 0x000000ff) |
	       ( ( a >> 8  ) & 0x0000ff00) |
	       ( ( a << 8  ) & 0x00ff0000) |
	       ( ( a << 24 ) & 0xff000000);
}

/********************************************************
  Extensions for TCG-enabled BIOS
 *******************************************************/

typedef struct {
	struct acpi_20_tcpa_clisrv *tcpa_ptr;
	unsigned char       *lasa_last_ptr;
	uint16_t            entry_count;
	uint16_t            flags;
} tcpa_acpi_t;

static tcpa_acpi_t tcpa_acpi;


/* low level driver implementation */
static int tpm_driver_to_use = TPM_INVALID_DRIVER;

static
uint32_t MA_IsTPMPresent(void)
{
	uint32_t rc = 0;
	unsigned int i;
	for (i = 0; i < TPM_NUM_DRIVERS; i++) {
		struct tpm_driver *td = &tpm_drivers[i];
		if (td->probe(td->baseaddr) != 0) {
			tpm_driver_to_use = i;
			rc = 1;
			break;
		}
	}
	return rc;
}

static
uint32_t MA_InitTPM(uint16_t startupcode)
{
	uint32_t rc = 0;
	/* low-level initialize the TPM */
	unsigned char command[sizeof(CMD_TPM_Startup_0x01_IPB.tpmoperandin)];
	unsigned char response[10];
	uint32_t response_size = sizeof(response);

	memcpy(command,
	       CMD_TPM_Startup_0x01_IPB.tpmoperandin,
	       sizeof(CMD_TPM_Startup_0x01_IPB.tpmoperandin));
	command[10] = (startupcode >> 8) & 0xff;
	command[11] = (startupcode >> 0) & 0xff;
	rc = MA_Transmit(command, response, response_size);

	return rc;
}

static
uint32_t MA_Transmit(unsigned char *cmdbuffer, unsigned char *respbuffer,
                     uint32_t respbufferlen)
{
	uint32_t rc = 0;
	uint32_t irc;
	struct tpm_driver *td;

	if (tpm_driver_to_use == TPM_INVALID_DRIVER)
		return TCG_FATAL_COM_ERROR;

	td = &tpm_drivers[tpm_driver_to_use];

	if (rc == 0) {
		irc = td->activate(td->baseaddr);
		if (irc == 0) {
			/* tpm could not be activated */
			rc = TCG_FATAL_COM_ERROR;
		}
	}

	if (rc == 0) {
		uint32_t *tmp = (uint32_t *)&cmdbuffer[2];
		uint32_t len = bswap(*tmp);
		irc = td->senddata(td->baseaddr,
		                   cmdbuffer,
		                   len);
		if (irc != 0) {
			rc = TCG_FATAL_COM_ERROR;
		}
	}

	if (rc == 0) {
		irc = td->waitdatavalid(td->baseaddr);
		if (irc != 0) {
			rc = TCG_FATAL_COM_ERROR;
		}
	}

	if (rc == 0) {
		irc = td->waitrespready(td->baseaddr, 2000);
		if (irc != 0) {
			rc = TCG_FATAL_COM_ERROR;
		}
	}

	if (rc == 0) {
		irc = td->readresp(td->baseaddr,
		                   respbuffer,
		                   respbufferlen);
		if (irc != 0) {
			rc = TCG_FATAL_COM_ERROR;
		}
	}

	if (rc == 0) {
		irc = td->ready(td->baseaddr);
	}

	return rc;
}


static
uint8_t acpi_validate_entry(struct acpi_header *hdr)
{
	uint8_t sum = 0;
	unsigned int length = hdr->length;
	unsigned int ctr;
	unsigned char *addr = (unsigned char *)hdr;

	for (ctr = 0; ctr < length; ctr++)
		sum += addr[ctr];

	return sum;
}


/*
   initialize the TCPA ACPI subsystem; find the ACPI tables and determine
   where the TCPA table is.
 */
void tcpa_acpi_init(void)
{
	struct acpi_20_rsdt *rsdt;
	struct acpi_20_tcpa_clisrv *tcpa = (void *)0;
	struct acpi_20_rsdp *rsdp;
	uint32_t length;
	uint16_t off;
	int found = 0;

	if (MA_IsTPMPresent() == 0)
		return;

	rsdp = find_rsdp();
	if (rsdp) {
		uint32_t ctr = 0;
		/* get RSDT from RSDP */
		rsdt   = (struct acpi_20_rsdt *)rsdp->rsdt_address;
		length = rsdt->header.length;
		off = 36;
		while ((off + 3) < length) {
			/* try all pointers to structures */
			tcpa = (struct acpi_20_tcpa_clisrv *)rsdt->entry[ctr];
			/* valid TCPA ACPI table ? */
			if (ACPI_2_0_TCPA_SIGNATURE == tcpa->header.signature
			    && acpi_validate_entry(&tcpa->header) == 0) {
				found = 1;
				break;
			}
			off += 4;
			ctr++;
		}
	}

	if (found == 0) {
		printf("TCPA ACPI was NOT found!\n");
		tcpa = 0;
	}

	tcpa_acpi.tcpa_ptr = tcpa;
	tcpa_acpi.lasa_last_ptr = 0;
	tcpa_acpi.entry_count = 0;
	tcpa_acpi.flags = 0;
	tcpa_reset_acpi_log();
}

/* clear the ACPI log */
static void tcpa_reset_acpi_log(void)
{
	unsigned char *lasa = tcpa_get_lasa_base_ptr();
	if (lasa)
		memset(lasa, 0x0, tcpa_get_laml());
}


/*
 * Extend the ACPI log with the given entry by copying the
 * entry data into the log.
 * Input
 *  Pointer to the structure to be copied into the log
 *
 * Output:
 *  lower 16 bits of return code contain entry number
 *  if entry number is '0', then upper 16 bits contain error code.
 */
uint32_t tcpa_extend_acpi_log(uint32_t entry_ptr)
{
	uint32_t res = 0;
	unsigned char *lasa_last = tcpa_get_lasa_last_ptr();
	unsigned char *lasa_base = tcpa_get_lasa_base_ptr();
	uint32_t size;
	uint16_t entry_count = tcpa_acpi.entry_count;
	struct pcpes *pcpes = (struct pcpes *)entry_ptr;

	if (lasa_last == 0) {
		lasa_last = lasa_base;
	} else {
		struct pcpes *pcpes = (struct pcpes *)lasa_last;
		/* skip the last entry in the log */
		size = pcpes->eventdatasize;
		size += 32;
		lasa_last += size;
	}

	if (lasa_last == 0) {
		res = ((uint32_t)TCG_PC_LOGOVERFLOW << 16);
	}

	if (res == 0) {
		uint32_t laml = tcpa_get_laml();
		size = pcpes->eventdatasize;
		size += 32;
		if ((lasa_last + size - lasa_base) > laml) {
			res = (TCG_PC_LOGOVERFLOW << 16);
		}
	}

	if (res == 0) {
		/* copy the log entry into the ACPI log */
		memcpy((char *)lasa_last, (char *)entry_ptr, size);
		/*
		 * update the pointers and entry counter that were modified
		 * due to the new entry in the log
		 */
		tcpa_acpi.lasa_last_ptr = lasa_last;
		entry_count++;
		tcpa_acpi.entry_count = entry_count;

		res = entry_count;
	}
	return res;
}

static
unsigned char *tcpa_get_lasa_last_ptr(void)
{
	return tcpa_acpi.lasa_last_ptr;
}

static
unsigned char *tcpa_get_lasa_base_ptr(void)
{
	unsigned char *lasa = 0;
	struct acpi_20_tcpa_clisrv *tcpa = tcpa_acpi.tcpa_ptr;
	if (tcpa != 0) {
		uint32_t class = tcpa->platform_class;
		if (class == TCPA_ACPI_CLASS_CLIENT) {
			/* client type */
			lasa = (unsigned char *)(long)tcpa->u.client.lasa;
		} else if (class == TCPA_ACPI_CLASS_SERVER) {
			/* server type */
			lasa = (unsigned char *)(long)tcpa->u.server.lasa;
		}
	}
	return lasa;
}

static
uint32_t tcpa_get_laml(void)
{
	uint32_t laml = 0;
	struct acpi_20_tcpa_clisrv *tcpa = tcpa_acpi.tcpa_ptr;
	if (tcpa != 0) {
		uint32_t class = tcpa->platform_class;
		if (class == TCPA_ACPI_CLASS_CLIENT) {
			/* client type */
			laml = tcpa->u.client.laml;
		} else if (class == TCPA_ACPI_CLASS_SERVER) {
			laml = tcpa->u.server.laml;
		}
	}
	return laml;
}



/*
 * Add a measurement to the log; the data at data_seg:data/length are
 * appended to the TCG_PCClientPCREventStruct
 *
 * Input parameters:
 *  pcrIndex   : which PCR to extend
 *  event_type : type of event; specs 10.4.1
 *  event_id   : (unused)
 *  data       : pointer to the data (i.e., string) to be added to the log
 *  length     : length of the data
 */
static uint32_t
tcpa_add_measurement_to_log(uint32_t pcrIndex,
                            uint32_t event_type,
                            uint32_t event_id,
                            const char *data_ptr,
                            uint32_t length)
{
	uint32_t rc = 0;
	struct hleei_short hleei;
	struct hleeo hleeo;
	uint8_t _pcpes[32+400];
	struct pcpes *pcpes = (struct pcpes *)_pcpes;
	uint8_t *data = (uint8_t *)data_ptr;

	if (length < sizeof(_pcpes)-32) {
		memset(pcpes, 0x0, 32);
		pcpes->pcrindex   = pcrIndex;
		pcpes->eventtype = event_type;
		pcpes->eventdatasize = length;
		memcpy(&_pcpes[32], data, length);

		hleei.ipblength = 0x18;
		hleei.reserved  = 0x0;
		hleei.hashdataptr = (uint32_t)&_pcpes[32];
		hleei.hashdatalen = length;
		hleei.pcrindex    = pcrIndex;
		hleei.logdataptr  = (uint32_t)_pcpes;
		hleei.logdatalen  = length + 32;
		rc = HashLogExtendEvent32(&hleei,
		                          &hleeo,
			                  TCG_MAGIC,
		                          0x0,
		                          0x0);
	} else {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_GENERAL_ERROR << 16));
	}

	return rc;
}

static
uint16_t tcpa_add_pcpes_to_log(struct pcpes *pcpes)
{
	uint32_t rc = 0;
	struct hleei_short hleei;
	struct hleeo hleeo;

	hleei.ipblength = 0x18;
	hleei.reserved  = 0x0;
	hleei.hashdataptr = 0;
	hleei.hashdatalen = 0;
	hleei.pcrindex    = pcpes->pcrindex;
	hleei.logdataptr  = (uint32_t)pcpes;
	hleei.logdatalen  = sizeof(pcpes);

	rc = HashLogExtendEvent32(&hleei,
	                          &hleeo,
		                  TCG_MAGIC,
	                          0x0,
	                          0x0);

	return rc;
}


/*
 * Add a measurement to the log; further description of the data
 * that are to be hashed are NOT appended to the TCG_PCClientPCREventStruc.
 * Input parameters:
 *  pcrIndex   : PCR to extend
 *  event_type : type of event; specs 10.4.1
 *  ptr        : 32 bit pointer to the data to be hashed
 *  length     : length of the data to be hashed
 *
 * Returns lower 16 bit of return code of TCG_HashLogExtendEvent. '0' means
 * success, otherwise an error is indicated.
 */
static
uint16_t tcpa_add_measurement_to_log_simple(uint32_t pcrIndex,
                                            uint16_t event_type,
                                            uint8_t *ptr, uint32_t length)
{
	uint32_t rc = 0;
	struct hleei_short hleei;
	struct hleeo hleeo;
	struct pcpes pcpes;

	memset(&pcpes, 0x0, sizeof(pcpes));
	pcpes.pcrindex = pcrIndex;
	pcpes.eventtype = event_type;
	/* specs: 10.4.1, EV_IPL eventfield should not contain the code.*/
	pcpes.eventdatasize = 0;

	hleei.ipblength = 0x18;
	hleei.reserved  = 0x0;
	hleei.hashdataptr = (uint32_t)ptr;
	hleei.hashdatalen = length;
	hleei.pcrindex = pcrIndex;
	hleei.logdataptr = (uint32_t)&pcpes;
	hleei.logdatalen = 32;

	rc = HashLogExtendEvent32(&hleei,
	                          &hleeo,
	                          TCG_MAGIC,
	                          0x0,
	                          0x0);
	return rc;
}

/* table of event types according to 10.4.1 / table 11 */
static const char ev_action[][23] = {
  /*  0 */ "Calling INT 19h",
           "Returned INT 19h",
           "Returned via INT 18h",
           "",
           "",
  /*  5 */ "",
           "",
           "",
           "",
           "",
  /* 10 */ "",
           "",
           "",
           "",
           "Start Option ROM Scan"
};

static char evt_separator[] = {0xff,0xff,0xff,0xff}; 
static char wake_event_1[]    = "Wake Event 1";

/*
 * Add a measurement to the list of measurements
 * pcrIndex   : PCR to be extended
 * event_type : type of event; specs 10.4.1
 * data       : additional parameter; used as parameter for 10.4.3
 *              'action index'
 */
static void tcpa_add_measurement(uint32_t pcrIndex,
                          uint16_t event_type,
                          uint32_t data)
{
	const char *string;

	switch (event_type) {
	case EV_SEPARATOR:
		tcpa_add_measurement_to_log_simple(pcrIndex,
		                            event_type,
		                            (uint8_t *)evt_separator,
		                            4);
	break;
	case EV_ACTION:
		string = ev_action[data /* event_id */];
		tcpa_add_measurement_to_log(pcrIndex,
		                            event_type,
		                            data,
		                            string,
		                            strlen(string));

	break;
	}
}


/*
 * Add measurement to log about call of int 19h
 */
void tcpa_calling_int19h()
{
	tcpa_add_measurement(4, EV_ACTION, 0);
}

/*
 * Add measurement to log about retuning from int 19h
 */
void tcpa_returned_int19h()
{
	tcpa_add_measurement(4, EV_ACTION, 1);
}

/*
 * Add event separators for PCRs 0 to 7; specs 8.2.3
 */
void tcpa_add_event_separators()
{
	uint32_t pcrIndex = 0;
	while (pcrIndex <= 7) {
		tcpa_add_measurement(pcrIndex, EV_SEPARATOR, 0);
		pcrIndex ++;
	}
}


/*
 * Add a wake event to the log
 */
void tcpa_wake_event()
{
	tcpa_add_measurement_to_log(6,
	                            EV_ACTION,
	                            10,
	                            wake_event_1,
	                            strlen(wake_event_1));
}

/*
 * Add a measurement regarding the boot device (CDRom, Floppy, HDD) to
 * the list of measurements.
 */
void tcpa_add_bootdevice(uint32_t bootcd, uint32_t bootdrv)
{
	char *string;
	if (bootcd == 0) {
		if (bootdrv == 0) {
			string = "Booting BCV device 00h (Floppy)";
		} else if (bootdrv == 0x80) {
			string = "Booting BCV device 80h (HDD)";
		} else {
			string = "Booting unknown device";
		}
	} else {
		string = "Booting from CD ROM device";
	}
	tcpa_add_measurement_to_log(4, 5, 0,
	                            string, strlen(string));
}

/*
 * Add measurement to the log about option rom scan
 * 10.4.3 : action 14
 */
void tcpa_start_option_rom_scan()
{
	tcpa_add_measurement(2, EV_ACTION, 14);
}


/*
 * Add measurement to the log about an option rom
 */
void tcpa_option_rom(uint32_t seg)
{
	uint32_t len = read_byte(seg, 2) << 9;
	uint8_t *addr = (uint8_t *)ADDR_FROM_SEG_OFF(seg,0);
	char append[32]; /* TCG_PCClientTaggedEventStruct and
	                     OptionROMExecuteStructure; specs 10.4.2.1 */
	struct hai hai;   /* HashAll Input Block; specs 12.10 */

	memset(append, 0x0, sizeof(append));

	append[0] = 7; /* Option ROM Execute */
	append[4] = 24;/* size of OptionROMExecute Structure */
	/* leave the rest to '0' */

	/* 12.10 table 21 */
	hai.ipblength   = 0x10;
	hai.reserved    = 0;
	hai.hashdataptr = (uint32_t)addr;
	hai.hashdatalen = len;
	hai.algorithmid = TPM_ALG_SHA;

	HashAll32(&hai,
	          (unsigned char *)append+12,
	          TCG_MAGIC,
	          0,
	          0);

	tcpa_add_measurement_to_log(2,
	                            EV_EVENT_TAG,
	                            0,
	                            append,
	                            32);
}

/*
 * Add a measurement to the log in support of 8.2.5.3
 * Creates two log entries
 *
 * Input parameter:
 *  bootcd : 0: MBR of hdd, 1: boot image, 2: boot catalog of El Torito
 *  seg    : segment where the IPL data are located
 *  off    : offset where the IPL data are located
 *  count  : length in bytes
 */
void tcpa_ipl(Bit32u bootcd,Bit32u seg,Bit32u off,Bit32u count)
{
	uint8_t *addr = (uint8_t *)ADDR_FROM_SEG_OFF(seg,off);
	if (bootcd == 1) {
		/* specs: 8.2.5.6 El Torito */
		tcpa_add_measurement_to_log_simple(4,
						   EV_IPL,
						   addr,
						   count);
	}
	else if (bootcd == 2) { /* Boot Catalog */

		/* specs: 8.2.5.6 El Torito */
		tcpa_add_measurement_to_log_simple(5,
						   EV_IPL_PARTITION_DATA,
						   addr,
						   count);
	}
	else {
		/* specs: 8.2.5.3 */
		/* equivalent to: dd if=/dev/hda ibs=1 count=440 | sha1sum */
		tcpa_add_measurement_to_log_simple(4,
						   EV_IPL,
						   addr,
		                                   0x1b8);


		/* equivalent to: dd if=/dev/hda ibs=1 count=72 skip=440 | sha1sum */
		tcpa_add_measurement_to_log_simple(5,
						   EV_IPL_PARTITION_DATA,
						   addr + 0x1b8,
						   0x48);
	}
}

void tcpa_measure_post(Bit32u from, Bit32u to)
{
	struct pcpes pcpes; /* PCClientPCREventStruc */
	int len = to - from;
	memset(&pcpes, 0x0, sizeof(pcpes));

	if (len > 0) {
		sha1((unsigned char *)from,
		     to-from,
		     (unsigned char *)&pcpes.digest);

		pcpes.eventtype = EV_POST_CODE;
		pcpes.eventdatasize = 0;
		pcpes.pcrindex = 0;
		tcpa_add_pcpes_to_log(&pcpes);
	}
}

static
uint32_t SendCommand32(uint32_t idx, struct pttto *pttto, uint32_t size_ptto)
{
	uint32_t rc = 0;
	struct pttti *pttti = (struct pttti *)TCG_CommandList[idx];
	uint8_t _pttto[30];

	if (size_ptto > 0 && size_ptto < 14) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INVALID_INPUT_PARA << 16));
	}

	if (rc == 0) {
		if (size_ptto == 0) {
			pttto = (struct pttto *)_pttto;
			size_ptto = sizeof(_pttto);
		}
		pttti->opblength = size_ptto;
	}

	if (rc == 0) {
		if (pttti->opblength > size_ptto) {
			rc = (TCG_PC_TPMERROR |
			      ((uint32_t)TCG_OUTPUT_BUFFER_TOO_SHORT << 16));
		}
	}

	if (rc == 0) {
		rc = PassThroughToTPM32(pttti,
		                        pttto,
		                        TCG_MAGIC,
		                        0x0,
		                        0x0);
	}

	return rc;
}


uint32_t tcpa_initialize_tpm(uint32_t physpres)
{
	uint32_t rc = 0;
	uint8_t _pttto[40];
	struct pttto *pttto = (struct pttto *)_pttto;
	uint32_t pttto_size = sizeof(_pttto);

	if (rc == 0) {
		rc = SendCommand32(IDX_CMD_TPM_Startup_0x01, pttto,
		                   pttto_size);
	}

	if (rc == 0 && physpres != 0) {
		rc = SendCommand32(IDX_CMD_TSC_PhysicalPresence_0x20,
		                   pttto, pttto_size);
	}

	if (rc == 0 && physpres != 0) {
		rc = SendCommand32(IDX_CMD_TSC_PhysicalPresence_0x08,
		                   pttto, pttto_size);
	}

	if (rc == 0 && physpres != 0) {
		rc = SendCommand32(IDX_CMD_TPM_PhysicalEnable,
		                   pttto, pttto_size);
	}

	if (rc == 0 && physpres != 0) {
		rc = SendCommand32(IDX_CMD_TPM_PhysicalSetDeactivated_0x00,
		                   pttto, pttto_size);
	}

	if (rc == 0) {
		rc = SendCommand32(IDX_CMD_TSC_PhysicalPresence_0x100,
		                   pttto, pttto_size);
	}

	if (rc == 0) {
		rc = SendCommand32(IDX_CMD_TSC_PhysicalPresence_0x10,
		                   pttto, pttto_size);
	}
	return rc;
}


static uint16_t TCG_IsShutdownPreBootInterface(void)
{
	return tcpa_acpi.flags & STATUS_FLAG_SHUTDOWN;
}


static
uint32_t _TCG_TPM_Extend(unsigned char *hash, uint32_t pcrindex)
{
	uint32_t rc;
	uint8_t _pttti[8+34];
	uint8_t _pttto[4+30];
	struct pttti *pttti = (struct pttti*)&_pttti;
	struct pttto *pttto = (struct pttto*)&_pttto;

	pttti->ipblength = 8 + 34;
	pttti->reserved  = 0;
	pttti->opblength = 4 + 30;
	pttti->reserved2 = 0;

	_pttti[8 + 0] = 0x0;
	_pttti[8 + 1] = 0xc1;
	*(uint32_t *)&_pttti[8 + 2] = bswap(34);
	*(uint32_t *)&_pttti[8 + 6] = bswap(0x14);
	*(uint32_t *)&_pttti[8 + 10]= bswap(pcrindex);
	memcpy(&_pttti[8+14], hash, 20);

	rc = PassThroughToTPM32(pttti,
	                        pttto,
	                        TCG_MAGIC,
	                        0x0,
	                        0x0);
	/* sanity check of result */
	if (_pttto[4] != 0x00 || _pttto[5] != 0xc4) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_FATAL_COM_ERROR << 16));
	}

	if (rc != 0) {
		/*
		   Invalidate the log since system did not process this
		   extend properly.
		 */
		tcpa_reset_acpi_log();
		memset(&tcpa_acpi, 0x0, sizeof(tcpa_acpi));
		TCG_ShutdownPreBootInterface(0);
	}
	return rc;
}


static
uint32_t HashLogExtendEvent32(struct hleei_short *hleei_s, struct hleeo *hleeo,
                              uint32_t magic, uint32_t ecx, uint32_t edx)
{
	uint32_t rc = 0;
	uint16_t size;
	struct hlei hlei ; /* HashLogEventInput block */
	struct hleo hleo;  /* HashLogEventOutput block */
	struct hleei_long *hleei_l = (struct hleei_long *)hleei_s;
	int sh = 0;
	uint32_t logdataptr;

	if (TCG_IsShutdownPreBootInterface() != 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (rc == 0) {
		/* short or long version? */
		size = hleei_s->ipblength;
		if (size == 0x18) {
			/* short */
			sh = 1;
		} else if (size == 0x1c) {
			/* long */
			sh = 0;
		} else {
			/* bad input block */
			rc = TCG_PC_TPMERROR |
			     ((uint32_t)(TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		uint32_t hashdataptr;
		uint32_t hashdatalen;
		uint32_t pcrindex;
		uint32_t logeventtype;
		uint32_t logdatalen;
		uint32_t eventnumber;
		uint8_t hash[20];
		struct pcpes *pcpes;

		hashdataptr = hleei_s->hashdataptr;
		hashdatalen = hleei_s->hashdatalen;
		pcrindex    = hleei_s->pcrindex;
		if (sh) {
			logdataptr = hleei_s->logdataptr;
			logdatalen = hleei_s->logdatalen;
		} else {
			logdataptr = hleei_l->logdataptr;
			logdatalen = hleei_l->logdatalen;
		}

		pcpes = (struct pcpes *)logdataptr;
		logeventtype = pcpes->eventtype;

		/* fill out HashLogEventInput block 'hlie' */
		hlei.ipblength = 0x1c;
		hlei.reserved = 0;
		hlei.hashdataptr = hashdataptr;
		hlei.hashdatalen = hashdatalen;
		hlei.pcrindex    = pcrindex;
		hlei.logeventtype= logeventtype;
		hlei.logdataptr  = logdataptr;
		hlei.logdatalen  = logdatalen;

		rc = HashLogEvent32(&hlei,
		                    &hleo,
		                    TCG_MAGIC,
		                    0x0,
		                    0x0);
		eventnumber = hleo.eventnumber;

		hleeo->opblength = 8 + 20;
		hleeo->reserved  = 0;
		hleeo->eventnumber = eventnumber;

		memcpy(hash, (unsigned char *)logdataptr + 0x8, 20);
		_TCG_TPM_Extend(hash, pcrindex);
	}

	if (rc != 0) {
		hleeo->opblength = 4;
		hleeo->reserved  = 0;
	}
	return rc;

}


static
uint32_t PassThroughToTPM32(struct pttti *pttti, struct pttto *pttto,
                            uint32_t magic, uint32_t ecx, uint32_t edx)
{
	uint32_t rc = 0;
	uint8_t *cmd32;
	uint32_t resbuflen = 0;

	if (TCG_IsShutdownPreBootInterface() != 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (rc == 0) {
		if (pttti->ipblength < 0x8 + 10) {
			rc = TCG_PC_TPMERROR |
			     ((uint32_t)(TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		if (pttti->opblength < 0x4) {
			rc = TCG_PC_TPMERROR |
			     ((uint32_t)(TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		uint8_t *resbuf32;

		cmd32 = &pttti->tpmoperandin[0];
		resbuflen = pttti->opblength - 4;
		resbuf32  = &pttto->tpmoperandout[0];

		rc = MA_Transmit(cmd32, resbuf32, resbuflen);
	}

	if (rc == 0) {
		pttto->opblength = resbuflen+4;
		pttto->reserved  = 0;
	}

	if (rc != 0) {
		pttto->opblength = 0;
		pttto->reserved = 0;
	}

	return rc;
}


static
uint32_t TCG_ShutdownPreBootInterface(uint32_t ebx)
{
	uint32_t rc = 0;
	if (TCG_IsShutdownPreBootInterface() == 0) {
		tcpa_acpi.flags |= STATUS_FLAG_SHUTDOWN;
	} else {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}
	return rc;
}


static
uint32_t HashLogEvent32(struct hlei *hlei, struct hleo *hleo,
                        uint32_t ebx, uint32_t ecx, uint32_t edx)
{
	uint32_t rc = 0;
	uint16_t size;
	uint32_t logdataptr;
	uint32_t logdatalen;
	uint32_t hashdataptr;
	uint32_t hashdatalen;

	if (TCG_IsShutdownPreBootInterface() != 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (rc == 0) {
		size = hlei->ipblength;
		if (size != 0x1c) {
			rc = (TCG_PC_TPMERROR |
			      ((uint32_t)TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		struct pcpes *pcpes;
		logdataptr = hlei->logdataptr;
		logdatalen = hlei->logdatalen;
		pcpes = (struct pcpes *)logdataptr;
		if (pcpes->pcrindex != hlei->pcrindex) {
			rc = (TCG_PC_TPMERROR |
			      ((uint32_t)TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		struct pcpes *pcpes= (struct pcpes *)logdataptr;
		if (pcpes->eventtype != hlei->logeventtype) {
			rc = (TCG_PC_TPMERROR |
			      ((uint32_t)TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		uint32_t entry;
		hashdataptr = hlei->hashdataptr;
		hashdatalen = hlei->hashdatalen;

		if ((hashdataptr != 0) | (hashdatalen != 0)) {
			uint8_t hash[20];
			struct hai hai; /* HashAll Input Block */
			hai.ipblength = 0x10;
			hai.reserved  = 0x0;
			hai.hashdataptr = hashdataptr;
			hai.hashdatalen = hashdatalen;
			hai.algorithmid = TPM_ALG_SHA;
			rc = HashAll32(&hai,
				       hash,
			               TCG_MAGIC,
			               0x0,
			               0x0);

			if (rc == 0) {
				/* hashing was done ok */
				memcpy((unsigned char *)logdataptr + 8,
				       hash,
				       20);
			}
		}

		if (rc == 0) {
			/* extend the log with this event */
			entry = tcpa_extend_acpi_log(logdataptr);
			if ((uint16_t)entry == 0) {
				/* upper 16 bits hold error code */
				rc = (entry >> 16);
			}
		}

		if (rc == 0) {
			/* updating the log was fine */
			hleo->opblength = 8;
			hleo->reserved  = 0;
			hleo->eventnumber = entry;
		}
	}

	if (rc != 0) {
		hleo->opblength = 2;
		hleo->reserved = 0;
	}

	return rc;
}

static
uint32_t HashAll32(struct hai *hai, unsigned char *hash,
                   uint32_t magic, uint32_t ecx, uint32_t edx)
{
	uint32_t rc = 0;

	if (TCG_IsShutdownPreBootInterface() != 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (rc == 0) {
		if (hai->ipblength != 0x10) {
			rc = (TCG_PC_TPMERROR |
			      ((uint32_t)TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		if (hai->algorithmid != TPM_ALG_SHA) {
			rc = (TCG_PC_TPMERROR |
			     ((uint32_t)TCG_INVALID_ACCESS_REQUEST << 16));
		}
	}

	if (rc == 0) {
		uint8_t *hashdataptr32;
		uint32_t hashdatalen32;

		hashdataptr32 = (uint8_t *)hai->hashdataptr;
		hashdatalen32 = hai->hashdatalen;

		sha1(hashdataptr32,
		     hashdatalen32,
		     hash);
	}

	return rc;
}


static
uint32_t TSS32(struct ti *ti, struct to *to,
               uint32_t ebx, uint32_t ecx, uint32_t edx)
{
	uint32_t rc = 0;
	if (TCG_IsShutdownPreBootInterface() == 0) {
		rc = TCG_PC_UNSUPPORTED;
	} else {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (rc != 0) {
		to->opblength = 4;
		to->reserved  = 0;
	}

	return rc;
}

static
uint32_t CompactHashLogExtendEvent32(unsigned char *buffer,
                                     uint32_t info,
                                     uint32_t magic,
                                     uint32_t length,
                                     uint32_t pcrindex,
                                     uint32_t *edx_ptr)
{
	uint32_t rc = 0;
	struct hleeo hleeo;

	if (TCG_IsShutdownPreBootInterface() != 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INTERFACE_SHUTDOWN << 16));
	}

	if (buffer == 0) {
		rc = (TCG_PC_TPMERROR |
		      ((uint32_t)TCG_INVALID_INPUT_PARA << 16));
	}

	if (rc == 0) {
		struct hleei_short hleei;
		struct pcpes pcpes;
		uint8_t *logdataptr;
		uint8_t *hashdataptr;

		logdataptr = (uint8_t*)&pcpes;
		hashdataptr = buffer;

		hleei.ipblength = 0x18;
		hleei.reserved  = 0x0;
		hleei.hashdataptr = (uint32_t)hashdataptr;
		hleei.hashdatalen = length;
		hleei.pcrindex = pcrindex;
		hleei.logdataptr = (uint32_t)logdataptr;
		hleei.logdatalen = 32;

		memset(&pcpes, 0x0, 32);
		pcpes.pcrindex = pcrindex;
		pcpes.eventtype = 12; /* EV_COMPACT_HASH */
		pcpes.eventdatasize = 4;
		pcpes.event = info;

		rc = HashLogExtendEvent32(&hleei,
		                          &hleeo,
		                          TCG_MAGIC,
		                          0x0,
		                          0x0);
	}

	if (rc == 0) {
		*edx_ptr = hleeo.eventnumber;
	}

	return rc;
}



/*******************************************************************
  Calculation of SHA1 in SW

  See: RFC3174, Wikipedia's SHA1 alogrithm description
 ******************************************************************/
typedef struct _sha1_ctx {
	uint32_t h[5];
} sha1_ctx;


static inline uint32_t rol(uint32_t val, uint16_t rol)
{
	return (val << rol) | (val >> (32 - rol));
}

static const uint32_t sha_ko[4] = { 0x5a827999,
                                    0x6ed9eba1,
                                    0x8f1bbcdc,
                                    0xca62c1d6 };


static void sha1_block(uint32_t *w, sha1_ctx *ctx)
{
	uint32_t i;
	uint32_t a,b,c,d,e,f;
	uint32_t tmp;
	uint32_t idx;

	/* change endianess of given data */
	for (i = 0; i < 16; i++) {
		w[i] = bswap(w[i]);
	}

	for (i = 16; i <= 79; i++) {
		tmp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
		w[i] = rol(tmp,1);
	}

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];

	for (i = 0; i <= 79; i++) {
		if (i <= 19) {
			f = (b & c) | ((b ^ 0xffffffff) & d);
			idx = 0;
		} else if (i <= 39) {
			f = b ^ c ^ d;
			idx = 1;
		} else if (i <= 59) {
			f = (b & c) | (b & d) | (c & d);
			idx = 2;
		} else {
			f = b ^ c ^ d;
			idx = 3;
		}

		tmp = rol(a, 5) +
		      f +
		      e +
		      sha_ko[idx] +
		      w[i];
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

static
void sha1_do(sha1_ctx *ctx, const unsigned char *data32, uint32_t length)
{
	uint32_t offset;
	uint16_t num;
	uint32_t bits = 0;
	uint32_t w[80];
	uint32_t tmp;

	/* treat data in 64-byte chunks */
	for (offset = 0; length - offset >= 64; offset += 64) {
		memcpy(w, data32 + offset, 64);
		sha1_block((uint32_t *)w, ctx);
		bits += (64 * 8);
	}

	/* last block with less than 64 bytes */
	num = length - offset;
	bits += (num << 3);

	memset(w, 0x0, 64);
	memcpy(w, data32 + offset, num);
	((uint8_t *)w)[num] = 0x80;

	if (num >= 56) {
		/* cannot append number of bits here */
		sha1_block((uint32_t *)w, ctx);
		memset(w, 0x0, 60);
	}

	/* write number of bits to end of block */
	tmp = bswap(bits);
	memcpy(&w[15], &tmp, 4);

	sha1_block(w, ctx);

	/* need to switch result's endianess */
	for (num = 0; num < 5; num++)
		ctx->h[num] = bswap(ctx->h[num]);
}

/* sha1 initialization constants */
static const uint32_t sha_const[5] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};

static
void sha1(const unsigned char *data, uint32_t length, unsigned char *hash)
{
	sha1_ctx ctx;

	memcpy(&ctx.h[0], sha_const, 20);
	sha1_do(&ctx, data, length);
	memcpy(hash, &ctx.h[0], 20);
}


uint32_t TCGInterruptHandler(pushad_regs_t *regs, uint32_t esds,
                             uint32_t flags_ptr)
{
	uint16_t DS = esds >> 16;
	uint16_t ES = esds & 0xffff;
	uint16_t *FLAGS = (uint16_t *)flags_ptr;

	switch(regs->u.r8.al) {
	case 0x00:
		if (MA_IsTPMPresent() == 0) {
			/* no TPM available */
			regs->u.r32.eax = TCG_PC_TPMERROR |
			     ((uint32_t)(TCG_PC_TPM_NOT_PRESENT) << 16);
		} else {
			regs->u.r32.eax = MA_InitTPM(TPM_ST_CLEAR);
			if (regs->u.r32.eax == 0) {
				regs->u.r32.ebx = TCG_MAGIC;
				regs->u.r8.ch = TCG_VERSION_MAJOR;
				regs->u.r8.cl = TCG_VERSION_MINOR;
				regs->u.r32.edx = 0x0;
				regs->u.r32.esi =
				             (Bit32u)tcpa_get_lasa_base_ptr();
				regs->u.r32.edi =
				             (Bit32u)tcpa_get_lasa_last_ptr();
				CLEAR_CF();
			}
		}
		break;
	case 0x01:
		regs->u.r32.eax =
			HashLogExtendEvent32((struct hleei_short*)
			                        ADDR_FROM_SEG_OFF(ES,
			                              regs->u.r16.di),
			                    (struct hleeo*)
			                        ADDR_FROM_SEG_OFF(DS,
			                              regs->u.r16.si),
			                    regs->u.r32.ebx,
			                    regs->u.r32.ecx,
			                    regs->u.r32.edx);
		CLEAR_CF();
		break;
	case 0x02:
		regs->u.r32.eax =
			PassThroughToTPM32((struct pttti *)
			                        ADDR_FROM_SEG_OFF(ES,
			                              regs->u.r16.di),
			                   (struct pttto *)
			                        ADDR_FROM_SEG_OFF(DS,
			                              regs->u.r16.si),
			                   regs->u.r32.ebx,
			                   regs->u.r32.ecx,
			                   regs->u.r32.edx);
		CLEAR_CF();
		break;
	case 0x03:
		regs->u.r32.eax =
			TCG_ShutdownPreBootInterface(regs->u.r32.ebx);
		CLEAR_CF();
		break;
	case 0x04:
		regs->u.r32.eax =
			HashLogEvent32((struct hlei*)
			                        ADDR_FROM_SEG_OFF(ES,
					              regs->u.r16.di),
		                       (struct hleo*)
			                        ADDR_FROM_SEG_OFF(DS,
			                              regs->u.r16.si),
			                   regs->u.r32.ebx,
			                   regs->u.r32.ecx,
			                   regs->u.r32.edx);
		CLEAR_CF();
		break;
	case 0x05:
		regs->u.r32.eax =
			HashAll32((struct hai*)
					ADDR_FROM_SEG_OFF(ES,
			                                  regs->u.r16.di),
			         (unsigned char *)
			                ADDR_FROM_SEG_OFF(DS,
			                                  regs->u.r16.si),
			           regs->u.r32.ebx,
			           regs->u.r32.ecx,
			           regs->u.r32.edx);
		CLEAR_CF();
		break;
	case 0x06:
		regs->u.r32.eax =
			TSS32((struct ti*)ADDR_FROM_SEG_OFF(ES,
			                                    regs->u.r16.di),
			      (struct to*)ADDR_FROM_SEG_OFF(DS,
			                                    regs->u.r16.si),
			      regs->u.r32.ebx,
			      regs->u.r32.ecx,
			      regs->u.r32.edx);
		CLEAR_CF();
		break;
	case 0x07:
		regs->u.r32.eax =
		  CompactHashLogExtendEvent32((unsigned char *)
		                                  ADDR_FROM_SEG_OFF(ES,
		                                        regs->u.r16.di),
		                              regs->u.r32.esi,
		                              regs->u.r32.ebx,
		                              regs->u.r32.ecx,
		                              regs->u.r32.edx,
		                              &regs->u.r32.edx);
		CLEAR_CF();
		break;
	default:
		SET_CF();
	}

	return 0;
}
