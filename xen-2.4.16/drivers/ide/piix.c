/*
 *  linux/drivers/ide/piix.c		Version 0.32	June 9, 2000
 *
 *  Copyright (C) 1998-1999 Andrzej Krzysztofowicz, Author and Maintainer
 *  Copyright (C) 1998-2000 Andre Hedrick <andre@linux-ide.org>
 *  May be copied or modified under the terms of the GNU General Public License
 *
 *  PIO mode setting function for Intel chipsets.  
 *  For use instead of BIOS settings.
 *
 * 40-41
 * 42-43
 * 
 *                 41
 *                 43
 *
 * | PIO 0       | c0 | 80 | 0 | 	piix_tune_drive(drive, 0);
 * | PIO 2 | SW2 | d0 | 90 | 4 | 	piix_tune_drive(drive, 2);
 * | PIO 3 | MW1 | e1 | a1 | 9 | 	piix_tune_drive(drive, 3);
 * | PIO 4 | MW2 | e3 | a3 | b | 	piix_tune_drive(drive, 4);
 * 
 * sitre = word40 & 0x4000; primary
 * sitre = word42 & 0x4000; secondary
 *
 * 44 8421|8421    hdd|hdb
 * 
 * 48 8421         hdd|hdc|hdb|hda udma enabled
 *
 *    0001         hda
 *    0010         hdb
 *    0100         hdc
 *    1000         hdd
 *
 * 4a 84|21        hdb|hda
 * 4b 84|21        hdd|hdc
 *
 *    ata-33/82371AB
 *    ata-33/82371EB
 *    ata-33/82801AB            ata-66/82801AA
 *    00|00 udma 0              00|00 reserved
 *    01|01 udma 1              01|01 udma 3
 *    10|10 udma 2              10|10 udma 4
 *    11|11 reserved            11|11 reserved
 *
 * 54 8421|8421    ata66 drive|ata66 enable
 *
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x40, &reg40);
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x42, &reg42);
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x44, &reg44);
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x48, &reg48);
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x4a, &reg4a);
 * pci_read_config_word(HWIF(drive)->pci_dev, 0x54, &reg54);
 *
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/delay.h>
#include <linux/init.h>

#include <asm/io.h>

#include "ide_modes.h"

#define PIIX_DEBUG_DRIVE_INFO		0

#define DISPLAY_PIIX_TIMINGS

#if defined(DISPLAY_PIIX_TIMINGS) && defined(CONFIG_PROC_FS)
#include <linux/stat.h>
#include <linux/proc_fs.h>

static int piix_get_info(char *, char **, off_t, int);
extern int (*piix_display_info)(char *, char **, off_t, int); /* ide-proc.c */
extern char *ide_media_verbose(ide_drive_t *);
static struct pci_dev *bmide_dev;

static int piix_get_info (char *buffer, char **addr, off_t offset, int count)
{
	char *p = buffer;
	u32 bibma = pci_resource_start(bmide_dev, 4);
        u16 reg40 = 0, psitre = 0, reg42 = 0, ssitre = 0;
	u8  c0 = 0, c1 = 0;
	u8  reg44 = 0, reg48 = 0, reg4a = 0, reg4b = 0, reg54 = 0, reg55 = 0;

	switch(bmide_dev->device) {
		case PCI_DEVICE_ID_INTEL_82801BA_8:
		case PCI_DEVICE_ID_INTEL_82801BA_9:
	        case PCI_DEVICE_ID_INTEL_82801CA_10:
			p += sprintf(p, "\n                                Intel PIIX4 Ultra 100 Chipset.\n");
			break;
		case PCI_DEVICE_ID_INTEL_82372FB_1:
		case PCI_DEVICE_ID_INTEL_82801AA_1:
			p += sprintf(p, "\n                                Intel PIIX4 Ultra 66 Chipset.\n");
			break;
		case PCI_DEVICE_ID_INTEL_82451NX:
		case PCI_DEVICE_ID_INTEL_82801AB_1:
		case PCI_DEVICE_ID_INTEL_82443MX_1:
		case PCI_DEVICE_ID_INTEL_82371AB:
			p += sprintf(p, "\n                                Intel PIIX4 Ultra 33 Chipset.\n");
			break;
		case PCI_DEVICE_ID_INTEL_82371SB_1:
			p += sprintf(p, "\n                                Intel PIIX3 Chipset.\n");
			break;
		case PCI_DEVICE_ID_INTEL_82371MX:
			p += sprintf(p, "\n                                Intel MPIIX Chipset.\n");
			return p-buffer;	/* => must be less than 4k! */
		case PCI_DEVICE_ID_INTEL_82371FB_1:
		case PCI_DEVICE_ID_INTEL_82371FB_0:
		default:
			p += sprintf(p, "\n                                Intel PIIX Chipset.\n");
			break;
	}

	pci_read_config_word(bmide_dev, 0x40, &reg40);
	pci_read_config_word(bmide_dev, 0x42, &reg42);
	pci_read_config_byte(bmide_dev, 0x44, &reg44);
	pci_read_config_byte(bmide_dev, 0x48, &reg48);
	pci_read_config_byte(bmide_dev, 0x4a, &reg4a);
	pci_read_config_byte(bmide_dev, 0x4b, &reg4b);
	pci_read_config_byte(bmide_dev, 0x54, &reg54);
	pci_read_config_byte(bmide_dev, 0x55, &reg55);

	psitre = (reg40 & 0x4000) ? 1 : 0;
	ssitre = (reg42 & 0x4000) ? 1 : 0;

	/*
	 * at that point bibma+0x2 et bibma+0xa are byte registers
	 * to investigate:
	 */
	c0 = inb_p((unsigned short)bibma + 0x02);
	c1 = inb_p((unsigned short)bibma + 0x0a);

	p += sprintf(p, "--------------- Primary Channel ---------------- Secondary Channel -------------\n");
	p += sprintf(p, "                %sabled                         %sabled\n",
			(c0&0x80) ? "dis" : " en",
			(c1&0x80) ? "dis" : " en");
	p += sprintf(p, "--------------- drive0 --------- drive1 -------- drive0 ---------- drive1 ------\n");
	p += sprintf(p, "DMA enabled:    %s              %s             %s               %s\n",
			(c0&0x20) ? "yes" : "no ",
			(c0&0x40) ? "yes" : "no ",
			(c1&0x20) ? "yes" : "no ",
			(c1&0x40) ? "yes" : "no " );
	p += sprintf(p, "UDMA enabled:   %s              %s             %s               %s\n",
			(reg48&0x01) ? "yes" : "no ",
			(reg48&0x02) ? "yes" : "no ",
			(reg48&0x04) ? "yes" : "no ",
			(reg48&0x08) ? "yes" : "no " );
	p += sprintf(p, "UDMA enabled:   %s                %s               %s                 %s\n",
			((reg54&0x11) && (reg55&0x10) && (reg4a&0x01)) ? "5" :
			((reg54&0x11) && (reg4a&0x02)) ? "4" :
			((reg54&0x11) && (reg4a&0x01)) ? "3" :
			(reg4a&0x02) ? "2" :
			(reg4a&0x01) ? "1" :
			(reg4a&0x00) ? "0" : "X",
			((reg54&0x22) && (reg55&0x20) && (reg4a&0x10)) ? "5" :
			((reg54&0x22) && (reg4a&0x20)) ? "4" :
			((reg54&0x22) && (reg4a&0x10)) ? "3" :
			(reg4a&0x20) ? "2" :
			(reg4a&0x10) ? "1" :
			(reg4a&0x00) ? "0" : "X",
			((reg54&0x44) && (reg55&0x40) && (reg4b&0x03)) ? "5" :
			((reg54&0x44) && (reg4b&0x02)) ? "4" :
			((reg54&0x44) && (reg4b&0x01)) ? "3" :
			(reg4b&0x02) ? "2" :
			(reg4b&0x01) ? "1" :
			(reg4b&0x00) ? "0" : "X",
			((reg54&0x88) && (reg55&0x80) && (reg4b&0x30)) ? "5" :
			((reg54&0x88) && (reg4b&0x20)) ? "4" :
			((reg54&0x88) && (reg4b&0x10)) ? "3" :
			(reg4b&0x20) ? "2" :
			(reg4b&0x10) ? "1" :
			(reg4b&0x00) ? "0" : "X");

	p += sprintf(p, "UDMA\n");
	p += sprintf(p, "DMA\n");
	p += sprintf(p, "PIO\n");

/*
 *	FIXME.... Add configuration junk data....blah blah......
 */

	return p-buffer;	 /* => must be less than 4k! */
}
#endif  /* defined(DISPLAY_PIIX_TIMINGS) && defined(CONFIG_PROC_FS) */

/*
 *  Used to set Fifo configuration via kernel command line:
 */

byte piix_proc = 0;

extern char *ide_xfer_verbose (byte xfer_rate);

#if defined(CONFIG_BLK_DEV_IDEDMA) && defined(CONFIG_PIIX_TUNING)
/*
 *
 */
static byte piix_dma_2_pio (byte xfer_rate) {
	switch(xfer_rate) {
		case XFER_UDMA_5:
		case XFER_UDMA_4:
		case XFER_UDMA_3:
		case XFER_UDMA_2:
		case XFER_UDMA_1:
		case XFER_UDMA_0:
		case XFER_MW_DMA_2:
		case XFER_PIO_4:
			return 4;
		case XFER_MW_DMA_1:
		case XFER_PIO_3:
			return 3;
		case XFER_SW_DMA_2:
		case XFER_PIO_2:
			return 2;
		case XFER_MW_DMA_0:
		case XFER_SW_DMA_1:
		case XFER_SW_DMA_0:
		case XFER_PIO_1:
		case XFER_PIO_0:
		case XFER_PIO_SLOW:
		default:
			return 0;
	}
}
#endif /* defined(CONFIG_BLK_DEV_IDEDMA) && (CONFIG_PIIX_TUNING) */

/*
 *  Based on settings done by AMI BIOS
 *  (might be useful if drive is not registered in CMOS for any reason).
 */
static void piix_tune_drive (ide_drive_t *drive, byte pio)
{
	unsigned long flags;
	u16 master_data;
	byte slave_data;
	int is_slave		= (&HWIF(drive)->drives[1] == drive);
	int master_port		= HWIF(drive)->index ? 0x42 : 0x40;
	int slave_port		= 0x44;
				 /* ISP  RTC */
	byte timings[][2]	= { { 0, 0 },
				    { 0, 0 },
				    { 1, 0 },
				    { 2, 1 },
				    { 2, 3 }, };

	pio = ide_get_best_pio_mode(drive, pio, 5, NULL);
	pci_read_config_word(HWIF(drive)->pci_dev, master_port, &master_data);
	if (is_slave) {
		master_data = master_data | 0x4000;
		if (pio > 1)
			/* enable PPE, IE and TIME */
			master_data = master_data | 0x0070;
		pci_read_config_byte(HWIF(drive)->pci_dev, slave_port, &slave_data);
		slave_data = slave_data & (HWIF(drive)->index ? 0x0f : 0xf0);
		slave_data = slave_data | ((timings[pio][0] << 2) | (timings[pio][1]
					   << (HWIF(drive)->index ? 4 : 0)));
	} else {
		master_data = master_data & 0xccf8;
		if (pio > 1)
			/* enable PPE, IE and TIME */
			master_data = master_data | 0x0007;
		master_data = master_data | (timings[pio][0] << 12) |
			      (timings[pio][1] << 8);
	}
	save_flags(flags);
	cli();
	pci_write_config_word(HWIF(drive)->pci_dev, master_port, master_data);
	if (is_slave)
		pci_write_config_byte(HWIF(drive)->pci_dev, slave_port, slave_data);
	restore_flags(flags);
}

#if defined(CONFIG_BLK_DEV_IDEDMA) && defined(CONFIG_PIIX_TUNING)
static int piix_tune_chipset (ide_drive_t *drive, byte speed)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct pci_dev *dev	= hwif->pci_dev;
	byte maslave		= hwif->channel ? 0x42 : 0x40;
	int a_speed		= 3 << (drive->dn * 4);
	int u_flag		= 1 << drive->dn;
	int v_flag		= 0x01 << drive->dn;
	int w_flag		= 0x10 << drive->dn;
	int u_speed		= 0;
	int err			= 0;
	int			sitre;
	short			reg4042, reg44, reg48, reg4a, reg54;
	byte			reg55;

	pci_read_config_word(dev, maslave, &reg4042);
	sitre = (reg4042 & 0x4000) ? 1 : 0;
	pci_read_config_word(dev, 0x44, &reg44);
	pci_read_config_word(dev, 0x48, &reg48);
	pci_read_config_word(dev, 0x4a, &reg4a);
	pci_read_config_word(dev, 0x54, &reg54);
	pci_read_config_byte(dev, 0x55, &reg55);

	switch(speed) {
		case XFER_UDMA_4:
		case XFER_UDMA_2:	u_speed = 2 << (drive->dn * 4); break;
		case XFER_UDMA_5:
		case XFER_UDMA_3:
		case XFER_UDMA_1:	u_speed = 1 << (drive->dn * 4); break;
		case XFER_UDMA_0:	u_speed = 0 << (drive->dn * 4); break;
		case XFER_MW_DMA_2:
		case XFER_MW_DMA_1:
		case XFER_SW_DMA_2:	break;
		default:		return -1;
	}

	if (speed >= XFER_UDMA_0) {
		if (!(reg48 & u_flag))
			pci_write_config_word(dev, 0x48, reg48|u_flag);
		if (speed == XFER_UDMA_5) {
			pci_write_config_byte(dev, 0x55, (byte) reg55|w_flag);
		} else {
			pci_write_config_byte(dev, 0x55, (byte) reg55 & ~w_flag);
		}
		if (!(reg4a & u_speed)) {
			pci_write_config_word(dev, 0x4a, reg4a & ~a_speed);
			pci_write_config_word(dev, 0x4a, reg4a|u_speed);
		}
		if (speed > XFER_UDMA_2) {
			if (!(reg54 & v_flag)) {
				pci_write_config_word(dev, 0x54, reg54|v_flag);
			}
		} else {
			pci_write_config_word(dev, 0x54, reg54 & ~v_flag);
		}
	}
	if (speed < XFER_UDMA_0) {
		if (reg48 & u_flag)
			pci_write_config_word(dev, 0x48, reg48 & ~u_flag);
		if (reg4a & a_speed)
			pci_write_config_word(dev, 0x4a, reg4a & ~a_speed);
		if (reg54 & v_flag)
			pci_write_config_word(dev, 0x54, reg54 & ~v_flag);
		if (reg55 & w_flag)
			pci_write_config_byte(dev, 0x55, (byte) reg55 & ~w_flag);
	}

	piix_tune_drive(drive, piix_dma_2_pio(speed));

#if PIIX_DEBUG_DRIVE_INFO
	printk("%s: %s drive%d\n", drive->name, ide_xfer_verbose(speed), drive->dn);
#endif /* PIIX_DEBUG_DRIVE_INFO */
	if (!drive->init_speed)
		drive->init_speed = speed;
	err = ide_config_drive_speed(drive, speed);
	drive->current_speed = speed;
	return err;
}

static int piix_config_drive_for_dma (ide_drive_t *drive)
{
	struct hd_driveid *id	= drive->id;
	ide_hwif_t *hwif	= HWIF(drive);
	struct pci_dev *dev	= hwif->pci_dev;
	byte			speed;

	byte udma_66		= eighty_ninty_three(drive);
	int ultra100		= ((dev->device == PCI_DEVICE_ID_INTEL_82801BA_8) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82801BA_9) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82801CA_10)) ? 1 : 0;
	int ultra66		= ((ultra100) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82801AA_1) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82372FB_1)) ? 1 : 0;
	int ultra		= ((ultra66) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82371AB) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82443MX_1) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82451NX) ||
				   (dev->device == PCI_DEVICE_ID_INTEL_82801AB_1)) ? 1 : 0;

	if ((id->dma_ultra & 0x0020) && (udma_66) && (ultra100)) {
		speed = XFER_UDMA_5;
	} else if ((id->dma_ultra & 0x0010) && (ultra)) {
		speed = ((udma_66) && (ultra66)) ? XFER_UDMA_4 : XFER_UDMA_2;
	} else if ((id->dma_ultra & 0x0008) && (ultra)) {
		speed = ((udma_66) && (ultra66)) ? XFER_UDMA_3 : XFER_UDMA_1;
	} else if ((id->dma_ultra & 0x0004) && (ultra)) {
		speed = XFER_UDMA_2;
	} else if ((id->dma_ultra & 0x0002) && (ultra)) {
		speed = XFER_UDMA_1;
	} else if ((id->dma_ultra & 0x0001) && (ultra)) {
		speed = XFER_UDMA_0;
	} else if (id->dma_mword & 0x0004) {
		speed = XFER_MW_DMA_2;
	} else if (id->dma_mword & 0x0002) {
		speed = XFER_MW_DMA_1;
	} else if (id->dma_1word & 0x0004) {
		speed = XFER_SW_DMA_2;
        } else {
		speed = XFER_PIO_0 + ide_get_best_pio_mode(drive, 255, 5, NULL);
	}

	(void) piix_tune_chipset(drive, speed);

	return ((int)	((id->dma_ultra >> 11) & 7) ? ide_dma_on :
			((id->dma_ultra >> 8) & 7) ? ide_dma_on :
			((id->dma_mword >> 8) & 7) ? ide_dma_on :
			((id->dma_1word >> 8) & 7) ? ide_dma_on :
						     ide_dma_off_quietly);
}

static void config_chipset_for_pio (ide_drive_t *drive)
{
	piix_tune_drive(drive, ide_get_best_pio_mode(drive, 255, 5, NULL));
}

static int config_drive_xfer_rate (ide_drive_t *drive)
{
	struct hd_driveid *id = drive->id;
	ide_dma_action_t dma_func = ide_dma_on;

	if (id && (id->capability & 1) && HWIF(drive)->autodma) {
		/* Consult the list of known "bad" drives */
		if (ide_dmaproc(ide_dma_bad_drive, drive)) {
			dma_func = ide_dma_off;
			goto fast_ata_pio;
		}
		dma_func = ide_dma_off_quietly;
		if (id->field_valid & 4) {
			if (id->dma_ultra & 0x002F) {
				/* Force if Capable UltraDMA */
				dma_func = piix_config_drive_for_dma(drive);
				if ((id->field_valid & 2) &&
				    (dma_func != ide_dma_on))
					goto try_dma_modes;
			}
		} else if (id->field_valid & 2) {
try_dma_modes:
			if ((id->dma_mword & 0x0007) ||
			    (id->dma_1word & 0x007)) {
				/* Force if Capable regular DMA modes */
				dma_func = piix_config_drive_for_dma(drive);
				if (dma_func != ide_dma_on)
					goto no_dma_set;
			}
		} else if (ide_dmaproc(ide_dma_good_drive, drive)) {
			if (id->eide_dma_time > 150) {
				goto no_dma_set;
			}
			/* Consult the list of known "good" drives */
			dma_func = piix_config_drive_for_dma(drive);
			if (dma_func != ide_dma_on)
				goto no_dma_set;
		} else {
			goto fast_ata_pio;
		}
	} else if ((id->capability & 8) || (id->field_valid & 2)) {
fast_ata_pio:
		dma_func = ide_dma_off_quietly;
no_dma_set:
		config_chipset_for_pio(drive);
	}
	return HWIF(drive)->dmaproc(dma_func, drive);
}

static int piix_dmaproc(ide_dma_action_t func, ide_drive_t *drive)
{
	switch (func) {
		case ide_dma_check:
			return config_drive_xfer_rate(drive);
		default :
			break;
	}
	/* Other cases are done by generic IDE-DMA code. */
	return ide_dmaproc(func, drive);
}
#endif /* defined(CONFIG_BLK_DEV_IDEDMA) && (CONFIG_PIIX_TUNING) */

unsigned int __init pci_init_piix (struct pci_dev *dev, const char *name)
{
#if defined(DISPLAY_PIIX_TIMINGS) && defined(CONFIG_PROC_FS)
	if (!piix_proc) {
		piix_proc = 1;
		bmide_dev = dev;
		piix_display_info = &piix_get_info;
	}
#endif /* DISPLAY_PIIX_TIMINGS && CONFIG_PROC_FS */
	return 0;
}

/*
 * Sheesh, someone at Intel needs to go read the ATA-4/5 T13 standards.
 * It does not specify device detection, but channel!!!
 * You determine later if bit 13 of word93 is set...
 */
unsigned int __init ata66_piix (ide_hwif_t *hwif)
{
	byte reg54h = 0, reg55h = 0, ata66 = 0;
	byte mask = hwif->channel ? 0xc0 : 0x30;

	pci_read_config_byte(hwif->pci_dev, 0x54, &reg54h);
	pci_read_config_byte(hwif->pci_dev, 0x55, &reg55h);

	ata66 = (reg54h & mask) ? 1 : 0;

	return ata66;
}

void __init ide_init_piix (ide_hwif_t *hwif)
{
#ifndef CONFIG_IA64
	if (!hwif->irq)
		hwif->irq = hwif->channel ? 15 : 14;
#endif /* CONFIG_IA64 */

	if (hwif->pci_dev->device == PCI_DEVICE_ID_INTEL_82371MX) {
		/* This is a painful system best to let it self tune for now */
		return;
	}

	hwif->tuneproc = &piix_tune_drive;
	hwif->drives[0].autotune = 1;
	hwif->drives[1].autotune = 1;

	if (!hwif->dma_base)
		return;

#ifndef CONFIG_BLK_DEV_IDEDMA
	hwif->autodma = 0;
#else /* CONFIG_BLK_DEV_IDEDMA */
#ifdef CONFIG_PIIX_TUNING
	if (!noautodma)
		hwif->autodma = 1;
	hwif->dmaproc = &piix_dmaproc;
	hwif->speedproc = &piix_tune_chipset;
#endif /* CONFIG_PIIX_TUNING */
#endif /* !CONFIG_BLK_DEV_IDEDMA */
}
