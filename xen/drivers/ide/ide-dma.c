/*
 *  linux/drivers/ide/ide-dma.c		Version 4.10	June 9, 2000
 *
 *  Copyright (c) 1999-2000	Andre Hedrick <andre@linux-ide.org>
 *  May be copied or modified under the terms of the GNU General Public License
 */

/*
 *  Special Thanks to Mark for his Six years of work.
 *
 *  Copyright (c) 1995-1998  Mark Lord
 *  May be copied or modified under the terms of the GNU General Public License
 */

/*
 * This module provides support for the bus-master IDE DMA functions
 * of various PCI chipsets, including the Intel PIIX (i82371FB for
 * the 430 FX chipset), the PIIX3 (i82371SB for the 430 HX/VX and 
 * 440 chipsets), and the PIIX4 (i82371AB for the 430 TX chipset)
 * ("PIIX" stands for "PCI ISA IDE Xcellerator").
 *
 * Pretty much the same code works for other IDE PCI bus-mastering chipsets.
 *
 * DMA is supported for all IDE devices (disk drives, cdroms, tapes, floppies).
 *
 * By default, DMA support is prepared for use, but is currently enabled only
 * for drives which already have DMA enabled (UltraDMA or mode 2 multi/single),
 * or which are recognized as "good" (see table below).  Drives with only mode0
 * or mode1 (multi/single) DMA should also work with this chipset/driver
 * (eg. MC2112A) but are not enabled by default.
 *
 * Use "hdparm -i" to view modes supported by a given drive.
 *
 * The hdparm-3.5 (or later) utility can be used for manually enabling/disabling
 * DMA support, but must be (re-)compiled against this kernel version or later.
 *
 * To enable DMA, use "hdparm -d1 /dev/hd?" on a per-drive basis after booting.
 * If problems arise, ide.c will disable DMA operation after a few retries.
 * This error recovery mechanism works and has been extremely well exercised.
 *
 * IDE drives, depending on their vintage, may support several different modes
 * of DMA operation.  The boot-time modes are indicated with a "*" in
 * the "hdparm -i" listing, and can be changed with *knowledgeable* use of
 * the "hdparm -X" feature.  There is seldom a need to do this, as drives
 * normally power-up with their "best" PIO/DMA modes enabled.
 *
 * Testing has been done with a rather extensive number of drives,
 * with Quantum & Western Digital models generally outperforming the pack,
 * and Fujitsu & Conner (and some Seagate which are really Conner) drives
 * showing more lackluster throughput.
 *
 * Keep an eye on /var/adm/messages for "DMA disabled" messages.
 *
 * Some people have reported trouble with Intel Zappa motherboards.
 * This can be fixed by upgrading the AMI BIOS to version 1.00.04.BS0,
 * available from ftp://ftp.intel.com/pub/bios/10004bs0.exe
 * (thanks to Glen Morrell <glen@spin.Stanford.edu> for researching this).
 *
 * Thanks to "Christopher J. Reimer" <reimer@doe.carleton.ca> for
 * fixing the problem with the BIOS on some Acer motherboards.
 *
 * Thanks to "Benoit Poulot-Cazajous" <poulot@chorus.fr> for testing
 * "TX" chipset compatibility and for providing patches for the "TX" chipset.
 *
 * Thanks to Christian Brunner <chb@muc.de> for taking a good first crack
 * at generic DMA -- his patches were referred to when preparing this code.
 *
 * Most importantly, thanks to Robert Bringman <rob@mars.trion.com>
 * for supplying a Promise UDMA board & WD UDMA drive for this work!
 *
 * And, yes, Intel Zappa boards really *do* use both PIIX IDE ports.
 *
 * check_drive_lists(ide_drive_t *drive, int good_bad)
 *
 * ATA-66/100 and recovery functions, I forgot the rest......
 * SELECT_READ_WRITE(hwif,drive,func) for active tuning based on IO direction.
 *
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/timer.h>
#include <xeno/mm.h>
#include <xeno/interrupt.h>
#include <xeno/pci.h>
#include <xeno/init.h>
#include <xeno/ide.h>

#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/irq.h>

/*
 * Long lost data from 2.0.34 that is now in 2.0.39
 *
 * This was used in ./drivers/block/triton.c to do DMA Base address setup
 * when PnP failed.  Oh the things we forget.  I believe this was part
 * of SFF-8038i that has been withdrawn from public access... :-((
 */
#define DEFAULT_BMIBA	0xe800	/* in case BIOS did not init it */
#define DEFAULT_BMCRBA	0xcc00	/* VIA's default value */
#define DEFAULT_BMALIBA	0xd400	/* ALI's default value */

extern char *ide_dmafunc_verbose(ide_dma_action_t dmafunc);

#ifdef CONFIG_IDEDMA_NEW_DRIVE_LISTINGS

struct drive_list_entry {
	char * id_model;
	char * id_firmware;
};

struct drive_list_entry drive_whitelist [] = {

	{ "Micropolis 2112A"	,       "ALL"		},
	{ "CONNER CTMA 4000"	,       "ALL"		},
	{ "CONNER CTT8000-A"	,       "ALL"		},
	{ "ST34342A"		,	"ALL"		},
	{ 0			,	0		}
};

struct drive_list_entry drive_blacklist [] = {

	{ "WDC AC11000H"	,	"ALL"		},
	{ "WDC AC22100H"	,	"ALL"		},
	{ "WDC AC31000H"	,	"ALL"		},
	{ "WDC AC32500H"	,	"ALL"		},
	{ "WDC AC33100H"	,	"ALL"		},
	{ "WDC AC31600H"	,	"ALL"		},
	{ "WDC AC32100H"	,	"24.09P07"	},
	{ "WDC AC23200L"	,	"21.10N21"	},
	{ "Compaq CRD-8241B"	,	"ALL"		},
	{ "CRD-8400B"		,	"ALL"		},
	{ "CRD-8480B",			"ALL"		},
	{ "CRD-8480C",			"ALL"		},
	{ "CRD-8482B",			"ALL"		},
 	{ "CRD-84"		,	"ALL"		},
	{ "SanDisk SDP3B"	,	"ALL"		},
	{ "SanDisk SDP3B-64"	,	"ALL"		},
	{ "SANYO CD-ROM CRD"	,	"ALL"		},
	{ "HITACHI CDR-8"	,	"ALL"		},
	{ "HITACHI CDR-8335"	,	"ALL"		},
	{ "HITACHI CDR-8435"	,	"ALL"		},
	{ "Toshiba CD-ROM XM-6202B"	,	"ALL"		},
	{ "CD-532E-A"		,	"ALL"		},
	{ "E-IDE CD-ROM CR-840",	"ALL"		},
	{ "CD-ROM Drive/F5A",	"ALL"		},
	{ "RICOH CD-R/RW MP7083A",	"ALL"		},
	{ "WPI CDD-820",		"ALL"		},
	{ "SAMSUNG CD-ROM SC-148C",	"ALL"		},
	{ "SAMSUNG CD-ROM SC-148F",	"ALL"		},
	{ "SAMSUNG CD-ROM SC",	"ALL"		},
	{ "SanDisk SDP3B-64"	,	"ALL"		},
	{ "SAMSUNG CD-ROM SN-124",	"ALL"		},
	{ "PLEXTOR CD-R PX-W8432T",	"ALL"		},
	{ "ATAPI CD-ROM DRIVE 40X MAXIMUM",	"ALL"		},
	{ "_NEC DV5800A",               "ALL"           },  
	{ 0			,	0		}

};

int in_drive_list(struct hd_driveid *id, struct drive_list_entry * drive_table)
{
	for ( ; drive_table->id_model ; drive_table++)
		if ((!strcmp(drive_table->id_model, id->model)) &&
		    ((!strstr(drive_table->id_firmware, id->fw_rev)) ||
		     (!strcmp(drive_table->id_firmware, "ALL"))))
			return 1;
	return 0;
}

#else /* !CONFIG_IDEDMA_NEW_DRIVE_LISTINGS */

/*
 * good_dma_drives() lists the model names (from "hdparm -i")
 * of drives which do not support mode2 DMA but which are
 * known to work fine with this interface under Linux.
 */
const char *good_dma_drives[] = {"Micropolis 2112A",
				 "CONNER CTMA 4000",
				 "CONNER CTT8000-A",
				 "ST34342A",	/* for Sun Ultra */
				 NULL};

/*
 * bad_dma_drives() lists the model names (from "hdparm -i")
 * of drives which supposedly support (U)DMA but which are
 * known to corrupt data with this interface under Linux.
 *
 * This is an empirical list. Its generated from bug reports. That means
 * while it reflects actual problem distributions it doesn't answer whether
 * the drive or the controller, or cabling, or software, or some combination
 * thereof is the fault. If you don't happen to agree with the kernel's 
 * opinion of your drive - use hdparm to turn DMA on.
 */
const char *bad_dma_drives[] = {"WDC AC11000H",
				"WDC AC22100H",
				"WDC AC32100H",
				"WDC AC32500H",
				"WDC AC33100H",
				"WDC AC31600H",
 				NULL};

#endif /* CONFIG_IDEDMA_NEW_DRIVE_LISTINGS */

/*
 * Our Physical Region Descriptor (PRD) table should be large enough
 * to handle the biggest I/O request we are likely to see.  Since requests
 * can have no more than 256 sectors, and since the typical blocksize is
 * two or more sectors, we could get by with a limit of 128 entries here for
 * the usual worst case.  Most requests seem to include some contiguous blocks,
 * further reducing the number of table entries required.
 *
 * The driver reverts to PIO mode for individual requests that exceed
 * this limit (possible with 512 byte blocksizes, eg. MSDOS f/s), so handling
 * 100% of all crazy scenarios here is not necessary.
 *
 * As it turns out though, we must allocate a full 4KB page for this,
 * so the two PRD tables (ide0 & ide1) will each get half of that,
 * allowing each to have about 256 entries (8 bytes each) from this.
 */
#define PRD_BYTES	8
#define PRD_ENTRIES	(PAGE_SIZE / (2 * PRD_BYTES))

/*
 * dma_intr() is the handler for disk read/write DMA interrupts
 */
ide_startstop_t ide_dma_intr (ide_drive_t *drive)
{
	int i;
	byte stat, dma_stat;

	dma_stat = HWIF(drive)->dmaproc(ide_dma_end, drive);
	stat = GET_STAT();			/* get drive status */
	if (OK_STAT(stat,DRIVE_READY,drive->bad_wstat|DRQ_STAT)) {
		if (!dma_stat) {
			struct request *rq = HWGROUP(drive)->rq;
			rq = HWGROUP(drive)->rq;
			for (i = rq->nr_sectors; i > 0;) {
				i -= rq->current_nr_sectors;
				ide_end_request(1, HWGROUP(drive));
			}
			return ide_stopped;
		}
		printk("%s: dma_intr: bad DMA status (dma_stat=%x)\n", 
		       drive->name, dma_stat);
	}
	return ide_error(drive, "dma_intr", stat);
}

static int ide_build_sglist (ide_hwif_t *hwif, struct request *rq)
{
	struct buffer_head *bh;
	struct scatterlist *sg = hwif->sg_table;
	unsigned long lastdataend = ~0UL;
	int nents = 0;

	if (hwif->sg_dma_active)
		BUG();

	if (rq->cmd == READ)
		hwif->sg_dma_direction = PCI_DMA_FROMDEVICE;
	else
		hwif->sg_dma_direction = PCI_DMA_TODEVICE;

	bh = rq->bh;
	do {
		struct scatterlist *sge;

		/*
		 * continue segment from before?
		 */
		if (virt_to_phys(bh->b_data) == lastdataend) {
			sg[nents - 1].length += bh->b_size;
			lastdataend += bh->b_size;
			continue;
		}

		/*
		 * start new segment
		 */
		if (nents >= PRD_ENTRIES)
			return 0;

		sge = &sg[nents];
		memset(sge, 0, sizeof(*sge));
		sge->address = bh->b_data;
		sge->length = bh->b_size;
		lastdataend = virt_to_phys(bh->b_data) + bh->b_size;
		nents++;
	} while ((bh = bh->b_reqnext) != NULL);

	return pci_map_sg(hwif->pci_dev, sg, nents, hwif->sg_dma_direction);
}

static int ide_raw_build_sglist (ide_hwif_t *hwif, struct request *rq)
{
	struct scatterlist *sg = hwif->sg_table;
	int nents = 0;
	ide_task_t *args = rq->special;
	unsigned char *virt_addr = rq->buffer;
	int sector_count = rq->nr_sectors;

//	if ((args->tfRegister[IDE_COMMAND_OFFSET] == WIN_WRITEDMA) ||
//	    (args->tfRegister[IDE_COMMAND_OFFSET] == WIN_WRITEDMA_EXT))
	if (args->command_type == IDE_DRIVE_TASK_RAW_WRITE)
		hwif->sg_dma_direction = PCI_DMA_TODEVICE;
	else
		hwif->sg_dma_direction = PCI_DMA_FROMDEVICE;
	
	if (sector_count > 128) {
		memset(&sg[nents], 0, sizeof(*sg));
		sg[nents].address = virt_addr;
		sg[nents].length = 128  * SECTOR_SIZE;
		nents++;
		virt_addr = virt_addr + (128 * SECTOR_SIZE);
		sector_count -= 128;
	}
	memset(&sg[nents], 0, sizeof(*sg));
	sg[nents].address = virt_addr;
	sg[nents].length =  sector_count  * SECTOR_SIZE;
	nents++;
   
	return pci_map_sg(hwif->pci_dev, sg, nents, hwif->sg_dma_direction);
}

/*
 * ide_build_dmatable() prepares a dma request.
 * Returns 0 if all went okay, returns 1 otherwise.
 * May also be invoked from trm290.c
 */
int ide_build_dmatable (ide_drive_t *drive, ide_dma_action_t func)
{
	unsigned int *table = HWIF(drive)->dmatable_cpu;
#ifdef CONFIG_BLK_DEV_TRM290
	unsigned int is_trm290_chipset = (HWIF(drive)->chipset == ide_trm290);
#else
	const int is_trm290_chipset = 0;
#endif
	unsigned int count = 0;
	int i;
	struct scatterlist *sg;

	if (HWGROUP(drive)->rq->cmd == IDE_DRIVE_TASKFILE)
		HWIF(drive)->sg_nents = i = ide_raw_build_sglist(HWIF(drive), HWGROUP(drive)->rq);
	else
		HWIF(drive)->sg_nents = i = ide_build_sglist(HWIF(drive), HWGROUP(drive)->rq);

	if (!i)
		return 0;

	sg = HWIF(drive)->sg_table;
	while (i) {
		u32 cur_addr;
		u32 cur_len;

		cur_addr = sg_dma_address(sg);
		cur_len = sg_dma_len(sg);

		/*
		 * Fill in the dma table, without crossing any 64kB boundaries.
		 * Most hardware requires 16-bit alignment of all blocks,
		 * but the trm290 requires 32-bit alignment.
		 */

		while (cur_len) {
			u32 xcount, bcount = 0x10000 - (cur_addr & 0xffff);
			
			if (count++ >= PRD_ENTRIES)
				BUG();

			if (bcount > cur_len)
				bcount = cur_len;
			*table++ = cpu_to_le32(cur_addr);
			xcount = bcount & 0xffff;
			if (is_trm290_chipset)
				xcount = ((xcount >> 2) - 1) << 16;
			if (xcount == 0x0000) {
				/* 
				 * Most chipsets correctly interpret a length
				 * of 0x0000 as 64KB, but at least one
				 * (e.g. CS5530) misinterprets it as zero (!).
				 * So here we break the 64KB entry into two
				 * 32KB entries instead.
				 */
				if (count++ >= PRD_ENTRIES)
					goto use_pio_instead;

				*table++ = cpu_to_le32(0x8000);
				*table++ = cpu_to_le32(cur_addr + 0x8000);
				xcount = 0x8000;
			}
			*table++ = cpu_to_le32(xcount);
			cur_addr += bcount;
			cur_len -= bcount;
		}

		sg++;
		i--;
	}

	if (count) {
		if (!is_trm290_chipset)
			*--table |= cpu_to_le32(0x80000000);
		return count;
	}
	printk("%s: empty DMA table?\n", drive->name);
use_pio_instead:
	pci_unmap_sg(HWIF(drive)->pci_dev,
		     HWIF(drive)->sg_table,
		     HWIF(drive)->sg_nents,
		     HWIF(drive)->sg_dma_direction);
	HWIF(drive)->sg_dma_active = 0;
	return 0; /* revert to PIO for this request */
}

/* Teardown mappings after DMA has completed.  */
void ide_destroy_dmatable (ide_drive_t *drive)
{
	struct pci_dev *dev = HWIF(drive)->pci_dev;
	struct scatterlist *sg = HWIF(drive)->sg_table;
	int nents = HWIF(drive)->sg_nents;

	pci_unmap_sg(dev, sg, nents, HWIF(drive)->sg_dma_direction);
	HWIF(drive)->sg_dma_active = 0;
}

/*
 *  For both Blacklisted and Whitelisted drives.
 *  This is setup to be called as an extern for future support
 *  to other special driver code.
 */
int check_drive_lists (ide_drive_t *drive, int good_bad)
{
	struct hd_driveid *id = drive->id;

#ifdef CONFIG_IDEDMA_NEW_DRIVE_LISTINGS
	if (good_bad) {
		return in_drive_list(id, drive_whitelist);
	} else {
		int blacklist = in_drive_list(id, drive_blacklist);
		if (blacklist)
			printk("%s: Disabling (U)DMA for %s\n", drive->name, id->model);
		return(blacklist);
	}
#else /* !CONFIG_IDEDMA_NEW_DRIVE_LISTINGS */
	const char **list;

	if (good_bad) {
		/* Consult the list of known "good" drives */
		list = good_dma_drives;
		while (*list) {
			if (!strcmp(*list++,id->model))
				return 1;
		}
	} else {
		/* Consult the list of known "bad" drives */
		list = bad_dma_drives;
		while (*list) {
			if (!strcmp(*list++,id->model)) {
				printk("%s: Disabling (U)DMA for %s\n",
					drive->name, id->model);
				return 1;
			}
		}
	}
#endif /* CONFIG_IDEDMA_NEW_DRIVE_LISTINGS */
	return 0;
}

int report_drive_dmaing (ide_drive_t *drive)
{
	struct hd_driveid *id = drive->id;

	if ((id->field_valid & 4) && (eighty_ninty_three(drive)) &&
	    (id->dma_ultra & (id->dma_ultra >> 14) & 3)) {
		if ((id->dma_ultra >> 15) & 1) {
			printk(", UDMA(mode 7)");	/* UDMA BIOS-enabled! */
		} else {
			printk(", UDMA(133)");	/* UDMA BIOS-enabled! */
		}
	} else if ((id->field_valid & 4) && (eighty_ninty_three(drive)) &&
	  	  (id->dma_ultra & (id->dma_ultra >> 11) & 7)) {
		if ((id->dma_ultra >> 13) & 1) {
			printk(", UDMA(100)");	/* UDMA BIOS-enabled! */
		} else if ((id->dma_ultra >> 12) & 1) {
			printk(", UDMA(66)");	/* UDMA BIOS-enabled! */
		} else {
			printk(", UDMA(44)");	/* UDMA BIOS-enabled! */
		}
	} else if ((id->field_valid & 4) &&
		   (id->dma_ultra & (id->dma_ultra >> 8) & 7)) {
		if ((id->dma_ultra >> 10) & 1) {
			printk(", UDMA(33)");	/* UDMA BIOS-enabled! */
		} else if ((id->dma_ultra >> 9) & 1) {
			printk(", UDMA(25)");	/* UDMA BIOS-enabled! */
		} else {
			printk(", UDMA(16)");	/* UDMA BIOS-enabled! */
		}
	} else if (id->field_valid & 4) {
		printk(", (U)DMA");	/* Can be BIOS-enabled! */
	} else {
		printk(", DMA");
	}
	return 1;
}

static int config_drive_for_dma (ide_drive_t *drive)
{
	int config_allows_dma = 1;
	struct hd_driveid *id = drive->id;
	ide_hwif_t *hwif = HWIF(drive);

#ifdef CONFIG_IDEDMA_ONLYDISK
	if (drive->media != ide_disk)
		config_allows_dma = 0;
#endif

	if (id && (id->capability & 1) && hwif->autodma && config_allows_dma) {
		/* Consult the list of known "bad" drives */
		if (ide_dmaproc(ide_dma_bad_drive, drive))
			return hwif->dmaproc(ide_dma_off, drive);

		/* Enable DMA on any drive that has UltraDMA (mode 6/7/?) enabled */
		if ((id->field_valid & 4) && (eighty_ninty_three(drive)))
			if ((id->dma_ultra & (id->dma_ultra >> 14) & 2))
				return hwif->dmaproc(ide_dma_on, drive);
		/* Enable DMA on any drive that has UltraDMA (mode 3/4/5) enabled */
		if ((id->field_valid & 4) && (eighty_ninty_three(drive)))
			if ((id->dma_ultra & (id->dma_ultra >> 11) & 7))
				return hwif->dmaproc(ide_dma_on, drive);
		/* Enable DMA on any drive that has UltraDMA (mode 0/1/2) enabled */
		if (id->field_valid & 4)	/* UltraDMA */
			if ((id->dma_ultra & (id->dma_ultra >> 8) & 7))
				return hwif->dmaproc(ide_dma_on, drive);
		/* Enable DMA on any drive that has mode2 DMA (multi or single) enabled */
		if (id->field_valid & 2)	/* regular DMA */
			if ((id->dma_mword & 0x404) == 0x404 || (id->dma_1word & 0x404) == 0x404)
				return hwif->dmaproc(ide_dma_on, drive);
		/* Consult the list of known "good" drives */
		if (ide_dmaproc(ide_dma_good_drive, drive))
			return hwif->dmaproc(ide_dma_on, drive);
	}
	return hwif->dmaproc(ide_dma_off_quietly, drive);
}

#ifndef CONFIG_BLK_DEV_IDEDMA_TIMEOUT
/*
 * 1 dmaing, 2 error, 4 intr
 */
static int dma_timer_expiry (ide_drive_t *drive)
{
	byte dma_stat = inb(HWIF(drive)->dma_base+2);

#ifdef DEBUG
	printk("%s: dma_timer_expiry: dma status == 0x%02x\n", drive->name, dma_stat);
#endif /* DEBUG */

#if 0
	HWGROUP(drive)->expiry = NULL;	/* one free ride for now */
#endif

	if (dma_stat & 2) {	/* ERROR */
		byte stat = GET_STAT();
		return ide_error(drive, "dma_timer_expiry", stat);
	}
	if (dma_stat & 1)	/* DMAing */
		return WAIT_CMD;
	return 0;
}
#else /* CONFIG_BLK_DEV_IDEDMA_TIMEOUT */
static ide_startstop_t ide_dma_timeout_revovery (ide_drive_t *drive)
{
	ide_hwgroup_t *hwgroup	= HWGROUP(drive);
	ide_hwif_t *hwif	= HWIF(drive);
	int enable_dma		= drive->using_dma;
	unsigned long flags;
	ide_startstop_t startstop;

	spin_lock_irqsave(&io_request_lock, flags);
	hwgroup->handler = NULL;
	del_timer(&hwgroup->timer);
	spin_unlock_irqrestore(&io_request_lock, flags);

	drive->waiting_for_dma = 0;

	startstop = ide_do_reset(drive);

	if ((enable_dma) && !(drive->using_dma))
		(void) hwif->dmaproc(ide_dma_on, drive);

	return startstop;
}
#endif /* CONFIG_BLK_DEV_IDEDMA_TIMEOUT */

#if 0
static inline void ide_toggle_bounce(ide_drive_t *drive, int on)
{
	dma64_addr_t addr = BLK_BOUNCE_HIGH;

	if (HWIF(drive)->no_highio || HWIF(drive)->pci_dev == NULL)
		return;

	if (on && drive->media == ide_disk) {
		if (!PCI_DMA_BUS_IS_PHYS)
			addr = BLK_BOUNCE_ANY;
		else
			addr = HWIF(drive)->pci_dev->dma_mask;
	}

	blk_queue_bounce_limit(&drive->queue, addr);
}
#endif

/*
 * ide_dmaproc() initiates/aborts DMA read/write operations on a drive.
 *
 * The caller is assumed to have selected the drive and programmed the drive's
 * sector address using CHS or LBA.  All that remains is to prepare for DMA
 * and then issue the actual read/write DMA/PIO command to the drive.
 *
 * For ATAPI devices, we just prepare for DMA and return. The caller should
 * then issue the packet command to the drive and call us again with
 * ide_dma_begin afterwards.
 *
 * Returns 0 if all went well.
 * Returns 1 if DMA read/write could not be started, in which case
 * the caller should revert to PIO for the current request.
 * May also be invoked from trm290.c
 */
int ide_dmaproc (ide_dma_action_t func, ide_drive_t *drive)
{
//	ide_hwgroup_t *hwgroup	= HWGROUP(drive);
	ide_hwif_t *hwif		= HWIF(drive);
	unsigned long dma_base		= hwif->dma_base;
	byte unit			= (drive->select.b.unit & 0x01);
	unsigned int count, reading = 0/*, set_high = 1*/;
	byte dma_stat;

	switch (func) {
		case ide_dma_off:
			printk("%s: DMA disabled\n", drive->name);
		case ide_dma_off_quietly:
                    /*set_high = 0;*/
			outb(inb(dma_base+2) & ~(1<<(5+unit)), dma_base+2);
		case ide_dma_on:
			drive->using_dma = (func == ide_dma_on);
			if (drive->using_dma)
				outb(inb(dma_base+2)|(1<<(5+unit)), dma_base+2);
			/*ide_toggle_bounce(drive, set_high);*/
			return 0;
		case ide_dma_check:
			return config_drive_for_dma (drive);
		case ide_dma_read:
			reading = 1 << 3;
		case ide_dma_write:
			SELECT_READ_WRITE(hwif,drive,func);
			if (!(count = ide_build_dmatable(drive, func)))
				return 1;	/* try PIO instead of DMA */
			outl(hwif->dmatable_dma, dma_base + 4); /* PRD table */
			outb(reading, dma_base);			/* specify r/w */
			outb(inb(dma_base+2)|6, dma_base+2);		/* clear INTR & ERROR flags */
			drive->waiting_for_dma = 1;
			if (drive->media != ide_disk)
				return 0;
#ifdef CONFIG_BLK_DEV_IDEDMA_TIMEOUT
			ide_set_handler(drive, &ide_dma_intr, 2*WAIT_CMD, NULL);	/* issue cmd to drive */
#else /* !CONFIG_BLK_DEV_IDEDMA_TIMEOUT */
			ide_set_handler(drive, &ide_dma_intr, WAIT_CMD, dma_timer_expiry);	/* issue cmd to drive */
#endif /* CONFIG_BLK_DEV_IDEDMA_TIMEOUT */
			if ((HWGROUP(drive)->rq->cmd == IDE_DRIVE_TASKFILE) &&
			    (drive->addressing == 1)) {
				ide_task_t *args = HWGROUP(drive)->rq->special;
				OUT_BYTE(args->tfRegister[IDE_COMMAND_OFFSET], IDE_COMMAND_REG);
			} else if (drive->addressing) {
				OUT_BYTE(reading ? WIN_READDMA_EXT : WIN_WRITEDMA_EXT, IDE_COMMAND_REG);
			} else {
				OUT_BYTE(reading ? WIN_READDMA : WIN_WRITEDMA, IDE_COMMAND_REG);
			}
			return HWIF(drive)->dmaproc(ide_dma_begin, drive);
		case ide_dma_begin:
			/* Note that this is done *after* the cmd has
			 * been issued to the drive, as per the BM-IDE spec.
			 * The Promise Ultra33 doesn't work correctly when
			 * we do this part before issuing the drive cmd.
			 */
			outb(inb(dma_base)|1, dma_base);		/* start DMA */
			return 0;
		case ide_dma_end: /* returns 1 on error, 0 otherwise */
			drive->waiting_for_dma = 0;
			outb(inb(dma_base)&~1, dma_base);	/* stop DMA */
			dma_stat = inb(dma_base+2);		/* get DMA status */
			outb(dma_stat|6, dma_base+2);	/* clear the INTR & ERROR bits */
			ide_destroy_dmatable(drive);	/* purge DMA mappings */
			return (dma_stat & 7) != 4 ? (0x10 | dma_stat) : 0;	/* verify good DMA status */
		case ide_dma_test_irq: /* returns 1 if dma irq issued, 0 otherwise */
			dma_stat = inb(dma_base+2);
#if 0  /* do not set unless you know what you are doing */
			if (dma_stat & 4) {
				byte stat = GET_STAT();
				outb(dma_base+2, dma_stat & 0xE4);
			}
#endif
			return (dma_stat & 4) == 4;	/* return 1 if INTR asserted */
		case ide_dma_bad_drive:
		case ide_dma_good_drive:
			return check_drive_lists(drive, (func == ide_dma_good_drive));
		case ide_dma_verbose:
			return report_drive_dmaing(drive);
		case ide_dma_timeout:
			// FIXME: Many IDE chipsets do not permit command file register access
			// FIXME: while the bus-master function is still active.
			// FIXME: To prevent deadlock with those chipsets, we must be extremely
			// FIXME: careful here (and in ide_intr() as well) to NOT access any
			// FIXME: registers from the 0x1Fx/0x17x sets before terminating the
			// FIXME: bus-master operation via the bus-master control reg.
			// FIXME: Otherwise, chipset deadlock will occur, and some systems will
			// FIXME: lock up completely!!
#ifdef CONFIG_BLK_DEV_IDEDMA_TIMEOUT
			/*
			 * Have to issue an abort and requeue the request
			 * DMA engine got turned off by a goofy ASIC, and
			 * we have to clean up the mess, and here is as good
			 * as any.  Do it globally for all chipsets.
			 */
			outb(0x00, dma_base);		/* stop DMA */
			dma_stat = inb(dma_base+2);	/* get DMA status */
			outb(dma_stat|6, dma_base+2);	/* clear the INTR & ERROR bits */
			printk("%s: %s: Lets do it again!" \
				"stat = 0x%02x, dma_stat = 0x%02x\n",
				drive->name, ide_dmafunc_verbose(func),
				GET_STAT(), dma_stat);

			if (dma_stat & 0xF0)
				return ide_dma_timeout_revovery(drive);

			printk("%s: %s: (restart_request) Lets do it again!" \
				"stat = 0x%02x, dma_stat = 0x%02x\n",
				drive->name, ide_dmafunc_verbose(func),
				GET_STAT(), dma_stat);

			return restart_request(drive);  // BUG: return types do not match!!
//#else
//			return HWGROUP(drive)->handler(drive);
#endif /* CONFIG_BLK_DEV_IDEDMA_TIMEOUT */
		case ide_dma_retune:
		case ide_dma_lostirq:
			printk("ide_dmaproc: chipset supported %s func only: %d\n", ide_dmafunc_verbose(func),  func);
			return 1;
		default:
			printk("ide_dmaproc: unsupported %s func: %d\n", ide_dmafunc_verbose(func), func);
			return 1;
	}
}

/*
 * Needed for allowing full modular support of ide-driver
 */
int ide_release_dma (ide_hwif_t *hwif)
{
	if (hwif->dmatable_cpu) {
		pci_free_consistent(hwif->pci_dev,
				    PRD_ENTRIES * PRD_BYTES,
				    hwif->dmatable_cpu,
				    hwif->dmatable_dma);
		hwif->dmatable_cpu = NULL;
	}
	if (hwif->sg_table) {
		kfree(hwif->sg_table);
		hwif->sg_table = NULL;
	}
	if ((hwif->dma_extra) && (hwif->channel == 0))
		release_region((hwif->dma_base + 16), hwif->dma_extra);
	release_region(hwif->dma_base, 8);
	return 1;
}

/*
 *	This can be called for a dynamically installed interface. Don't __init it
 */
 
void ide_setup_dma (ide_hwif_t *hwif, unsigned long dma_base, unsigned int num_ports)
{
	printk("    %s: BM-DMA at 0x%04lx-0x%04lx", hwif->name, dma_base, dma_base + num_ports - 1);
	if (check_region(dma_base, num_ports)) {
		printk(" -- ERROR, PORT ADDRESSES ALREADY IN USE\n");
		return;
	}
	request_region(dma_base, num_ports, hwif->name);
	hwif->dma_base = dma_base;
	hwif->dmatable_cpu = pci_alloc_consistent(hwif->pci_dev,
						    PRD_ENTRIES * PRD_BYTES,
						    &hwif->dmatable_dma);
	if (hwif->dmatable_cpu == NULL)
		goto dma_alloc_failure;

	hwif->sg_table = kmalloc(sizeof(struct scatterlist) * PRD_ENTRIES,
				 GFP_KERNEL);
	if (hwif->sg_table == NULL) {
		pci_free_consistent(hwif->pci_dev, PRD_ENTRIES * PRD_BYTES,
				    hwif->dmatable_cpu, hwif->dmatable_dma);
		goto dma_alloc_failure;
	}

	hwif->dmaproc = &ide_dmaproc;

	if (hwif->chipset != ide_trm290) {
		byte dma_stat = inb(dma_base+2);
		printk(", BIOS settings: %s:%s, %s:%s",
		       hwif->drives[0].name, (dma_stat & 0x20) ? "DMA" : "pio",
		       hwif->drives[1].name, (dma_stat & 0x40) ? "DMA" : "pio");
	}
	printk("\n");
	return;

dma_alloc_failure:
	printk(" -- ERROR, UNABLE TO ALLOCATE DMA TABLES\n");
}

/*
 * Fetch the DMA Bus-Master-I/O-Base-Address (BMIBA) from PCI space:
 */
unsigned long __init ide_get_or_set_dma_base (ide_hwif_t *hwif, int extra, const char *name)
{
	unsigned long	dma_base = 0;
	struct pci_dev	*dev = hwif->pci_dev;

#ifdef CONFIG_BLK_DEV_IDEDMA_FORCED
	int second_chance = 0;

second_chance_to_dma:
#endif /* CONFIG_BLK_DEV_IDEDMA_FORCED */

	if (hwif->mate && hwif->mate->dma_base) {
		dma_base = hwif->mate->dma_base - (hwif->channel ? 0 : 8);
	} else {
		dma_base = pci_resource_start(dev, 4);
		if (!dma_base) {
			printk("%s: dma_base is invalid (0x%04lx)\n", name, dma_base);
			dma_base = 0;
		}
	}

#ifdef CONFIG_BLK_DEV_IDEDMA_FORCED
	if ((!dma_base) && (!second_chance)) {
		unsigned long set_bmiba = 0;
		second_chance++;
		switch(dev->vendor) {
			case PCI_VENDOR_ID_AL:
				set_bmiba = DEFAULT_BMALIBA; break;
			case PCI_VENDOR_ID_VIA:
				set_bmiba = DEFAULT_BMCRBA; break;
			case PCI_VENDOR_ID_INTEL:
				set_bmiba = DEFAULT_BMIBA; break;
			default:
				return dma_base;
		}
		pci_write_config_dword(dev, 0x20, set_bmiba|1);
		goto second_chance_to_dma;
	}
#endif /* CONFIG_BLK_DEV_IDEDMA_FORCED */

	if (dma_base) {
		if (extra) /* PDC20246, PDC20262, HPT343, & HPT366 */
			request_region(dma_base+16, extra, name);
		dma_base += hwif->channel ? 8 : 0;
		hwif->dma_extra = extra;

		switch(dev->device) {
			case PCI_DEVICE_ID_AL_M5219:
			case PCI_DEVICE_ID_AMD_VIPER_7409:
			case PCI_DEVICE_ID_CMD_643:
				outb(inb(dma_base+2) & 0x60, dma_base+2);
				if (inb(dma_base+2) & 0x80) {
					printk("%s: simplex device: DMA forced\n", name);
				}
				break;
			default:
				/*
				 * If the device claims "simplex" DMA,
				 * this means only one of the two interfaces
				 * can be trusted with DMA at any point in time.
				 * So we should enable DMA only on one of the
				 * two interfaces.
				 */
				if ((inb(dma_base+2) & 0x80)) {	/* simplex device? */
					if ((!hwif->drives[0].present && !hwif->drives[1].present) ||
					    (hwif->mate && hwif->mate->dma_base)) {
						printk("%s: simplex device:  DMA disabled\n", name);
						dma_base = 0;
					}
				}
		}
	}
	return dma_base;
}
