/*
 * linux/drivers/block/ide-features.c	Version 0.04	June 9, 2000
 *
 *  Copyright (C) 1999-2000	Linus Torvalds & authors (see below)
 *  
 *  Copyright (C) 1999-2000	Andre Hedrick <andre@linux-ide.org>
 *
 *  Extracts if ide.c to address the evolving transfer rate code for
 *  the SETFEATURES_XFER callouts.  Various parts of any given function
 *  are credited to previous ATA-IDE maintainers.
 *
 *  Auto-CRC downgrade for Ultra DMA(ing)
 *
 *  May be copied or modified under the terms of the GNU General Public License
 */

#include <xeno/config.h>
#define __NO_VERSION__
#include <xeno/module.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/timer.h>
#include <xeno/mm.h>
#include <xeno/interrupt.h>
#include <xeno/major.h>
#include <xeno/errno.h>
#include <xeno/genhd.h>
#include <xeno/blkpg.h>
#include <xeno/slab.h>
#include <xeno/pci.h>
#include <xeno/delay.h>
#include <xeno/hdreg.h>
#include <xeno/ide.h>

#include <asm/byteorder.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bitops.h>

/*
 * A Verbose noise maker for debugging on the attempted transfer rates.
 */
char *ide_xfer_verbose (byte xfer_rate)
{
	switch(xfer_rate) {
		case XFER_UDMA_7:	return("UDMA 7");
		case XFER_UDMA_6:	return("UDMA 6");
		case XFER_UDMA_5:	return("UDMA 5");
		case XFER_UDMA_4:	return("UDMA 4");
		case XFER_UDMA_3:	return("UDMA 3");
		case XFER_UDMA_2:	return("UDMA 2");
		case XFER_UDMA_1:	return("UDMA 1");
		case XFER_UDMA_0:	return("UDMA 0");
		case XFER_MW_DMA_2:	return("MW DMA 2");
		case XFER_MW_DMA_1:	return("MW DMA 1");
		case XFER_MW_DMA_0:	return("MW DMA 0");
		case XFER_SW_DMA_2:	return("SW DMA 2");
		case XFER_SW_DMA_1:	return("SW DMA 1");
		case XFER_SW_DMA_0:	return("SW DMA 0");
		case XFER_PIO_4:	return("PIO 4");
		case XFER_PIO_3:	return("PIO 3");
		case XFER_PIO_2:	return("PIO 2");
		case XFER_PIO_1:	return("PIO 1");
		case XFER_PIO_0:	return("PIO 0");
		case XFER_PIO_SLOW:	return("PIO SLOW");
		default:		return("XFER ERROR");
	}
}

/*
 *
 */
char *ide_media_verbose (ide_drive_t *drive)
{
	switch (drive->media) {
		case ide_scsi:		return("scsi   ");
		case ide_disk:		return("disk   ");
		case ide_optical:	return("optical");
		case ide_cdrom:		return("cdrom  ");
		case ide_tape:		return("tape   ");
		case ide_floppy:	return("floppy ");
		default:		return("???????");
	}
}

/*
 * A Verbose noise maker for debugging on the attempted dmaing calls.
 */
char *ide_dmafunc_verbose (ide_dma_action_t dmafunc)
{
	switch (dmafunc) {
		case ide_dma_read:		return("ide_dma_read");
		case ide_dma_write:		return("ide_dma_write");
		case ide_dma_begin:		return("ide_dma_begin");
		case ide_dma_end:		return("ide_dma_end:");
		case ide_dma_check:		return("ide_dma_check");
		case ide_dma_on:		return("ide_dma_on");
		case ide_dma_off:		return("ide_dma_off");
		case ide_dma_off_quietly:	return("ide_dma_off_quietly");
		case ide_dma_test_irq:		return("ide_dma_test_irq");
		case ide_dma_bad_drive:		return("ide_dma_bad_drive");
		case ide_dma_good_drive:	return("ide_dma_good_drive");
		case ide_dma_verbose:		return("ide_dma_verbose");
		case ide_dma_retune:		return("ide_dma_retune");
		case ide_dma_lostirq:		return("ide_dma_lostirq");
		case ide_dma_timeout:		return("ide_dma_timeout");
		default:			return("unknown");
	}
}

/*
 *
 */
byte ide_auto_reduce_xfer (ide_drive_t *drive)
{
	if (!drive->crc_count)
		return drive->current_speed;
	drive->crc_count = 0;

	switch(drive->current_speed) {
		case XFER_UDMA_7:	return XFER_UDMA_6;
		case XFER_UDMA_6:	return XFER_UDMA_5;
		case XFER_UDMA_5:	return XFER_UDMA_4;
		case XFER_UDMA_4:	return XFER_UDMA_3;
		case XFER_UDMA_3:	return XFER_UDMA_2;
		case XFER_UDMA_2:	return XFER_UDMA_1;
		case XFER_UDMA_1:	return XFER_UDMA_0;
			/*
			 * OOPS we do not goto non Ultra DMA modes
			 * without iCRC's available we force
			 * the system to PIO and make the user
			 * invoke the ATA-1 ATA-2 DMA modes.
			 */
		case XFER_UDMA_0:
		default:		return XFER_PIO_4;
	}
}

/*
 * Update the 
 */
int ide_driveid_update (ide_drive_t *drive)
{
	/*
	 * Re-read drive->id for possible DMA mode
	 * change (copied from ide-probe.c)
	 */
	struct hd_driveid *id;
	unsigned long timeout, flags;

	SELECT_MASK(HWIF(drive), drive, 1);
	if (IDE_CONTROL_REG)
		OUT_BYTE(drive->ctl,IDE_CONTROL_REG);
	ide_delay_50ms();
	OUT_BYTE(WIN_IDENTIFY, IDE_COMMAND_REG);
	timeout = jiffies + WAIT_WORSTCASE;
	do {
		if (0 < (signed long)(jiffies - timeout)) {
			SELECT_MASK(HWIF(drive), drive, 0);
			return 0;	/* drive timed-out */
		}
		ide_delay_50ms();	/* give drive a breather */
	} while (IN_BYTE(IDE_ALTSTATUS_REG) & BUSY_STAT);
	ide_delay_50ms();	/* wait for IRQ and DRQ_STAT */
	if (!OK_STAT(GET_STAT(),DRQ_STAT,BAD_R_STAT)) {
		SELECT_MASK(HWIF(drive), drive, 0);
		printk("%s: CHECK for good STATUS\n", drive->name);
		return 0;
	}
	__save_flags(flags);	/* local CPU only */
	__cli();		/* local CPU only; some systems need this */
	SELECT_MASK(HWIF(drive), drive, 0);
	id = kmalloc(SECTOR_WORDS*4, GFP_ATOMIC);
	if (!id) {
		__restore_flags(flags);	/* local CPU only */
		return 0;
	}
	ide_input_data(drive, id, SECTOR_WORDS);
	(void) GET_STAT();	/* clear drive IRQ */
	ide__sti();		/* local CPU only */
	__restore_flags(flags);	/* local CPU only */
	ide_fix_driveid(id);
	if (id) {
		drive->id->dma_ultra = id->dma_ultra;
		drive->id->dma_mword = id->dma_mword;
		drive->id->dma_1word = id->dma_1word;
		/* anything more ? */
		kfree(id);
	}

	return 1;
}

/*
 * Verify that we are doing an approved SETFEATURES_XFER with respect
 * to the hardware being able to support request.  Since some hardware
 * can improperly report capabilties, we check to see if the host adapter
 * in combination with the device (usually a disk) properly detect
 * and acknowledge each end of the ribbon.
 */
int ide_ata66_check (ide_drive_t *drive, ide_task_t *args)
{
	if ((args->tfRegister[IDE_COMMAND_OFFSET] == WIN_SETFEATURES) &&
	    (args->tfRegister[IDE_SECTOR_OFFSET] > XFER_UDMA_2) &&
	    (args->tfRegister[IDE_FEATURE_OFFSET] == SETFEATURES_XFER)) {
		if (!HWIF(drive)->udma_four) {
			printk("%s: Speed warnings UDMA 3/4/5 is not functional.\n", HWIF(drive)->name);
			return 1;
		}
#ifndef CONFIG_IDEDMA_IVB
		if ((drive->id->hw_config & 0x6000) == 0) {
#else /* !CONFIG_IDEDMA_IVB */
		if (((drive->id->hw_config & 0x2000) == 0) ||
		    ((drive->id->hw_config & 0x4000) == 0)) {
#endif /* CONFIG_IDEDMA_IVB */
			printk("%s: Speed warnings UDMA 3/4/5 is not functional.\n", drive->name);
			return 1;
		}
	}
	return 0;
}

/*
 * Backside of HDIO_DRIVE_CMD call of SETFEATURES_XFER.
 * 1 : Safe to update drive->id DMA registers.
 * 0 : OOPs not allowed.
 */
int set_transfer (ide_drive_t *drive, ide_task_t *args)
{
	if ((args->tfRegister[IDE_COMMAND_OFFSET] == WIN_SETFEATURES) &&
	    (args->tfRegister[IDE_SECTOR_OFFSET] >= XFER_SW_DMA_0) &&
	    (args->tfRegister[IDE_FEATURE_OFFSET] == SETFEATURES_XFER) &&
	    (drive->id->dma_ultra ||
	     drive->id->dma_mword ||
	     drive->id->dma_1word))
		return 1;

	return 0;
}

#ifdef CONFIG_BLK_DEV_IDEDMA
/*
 *  All hosts that use the 80c ribbon mus use!
 */
byte eighty_ninty_three (ide_drive_t *drive)
{
#ifdef CONFIG_BLK_DEV_IDEPCI
	if (HWIF(drive)->pci_devid.vid==0x105a)
	    return(HWIF(drive)->udma_four);
#endif
	/* PDC202XX: that's because some HDD will return wrong info */
	return ((byte) ((HWIF(drive)->udma_four) &&
#ifndef CONFIG_IDEDMA_IVB
			(drive->id->hw_config & 0x4000) &&
#endif /* CONFIG_IDEDMA_IVB */
			(drive->id->hw_config & 0x6000)) ? 1 : 0);
}
#endif // CONFIG_BLK_DEV_IDEDMA

/*
 * Similar to ide_wait_stat(), except it never calls ide_error internally.
 * This is a kludge to handle the new ide_config_drive_speed() function,
 * and should not otherwise be used anywhere.  Eventually, the tuneproc's
 * should be updated to return ide_startstop_t, in which case we can get
 * rid of this abomination again.  :)   -ml
 *
 * It is gone..........
 *
 * const char *msg == consider adding for verbose errors.
 */
int ide_config_drive_speed (ide_drive_t *drive, byte speed)
{
	ide_hwif_t *hwif = HWIF(drive);
	int	i, error = 1;
	byte stat;

#if defined(CONFIG_BLK_DEV_IDEDMA) && !defined(CONFIG_DMA_NONPCI)
	byte unit = (drive->select.b.unit & 0x01);
	outb(inb(hwif->dma_base+2) & ~(1<<(5+unit)), hwif->dma_base+2);
#endif /* (CONFIG_BLK_DEV_IDEDMA) && !(CONFIG_DMA_NONPCI) */

	/*
	 * Don't use ide_wait_cmd here - it will
	 * attempt to set_geometry and recalibrate,
	 * but for some reason these don't work at
	 * this point (lost interrupt).
	 */
        /*
         * Select the drive, and issue the SETFEATURES command
         */
	disable_irq(hwif->irq);	/* disable_irq_nosync ?? */
	udelay(1);
	SELECT_DRIVE(HWIF(drive), drive);
	SELECT_MASK(HWIF(drive), drive, 0);
	udelay(1);
	if (IDE_CONTROL_REG)
		OUT_BYTE(drive->ctl | 2, IDE_CONTROL_REG);
	OUT_BYTE(speed, IDE_NSECTOR_REG);
	OUT_BYTE(SETFEATURES_XFER, IDE_FEATURE_REG);
	OUT_BYTE(WIN_SETFEATURES, IDE_COMMAND_REG);
	if ((IDE_CONTROL_REG) && (drive->quirk_list == 2))
		OUT_BYTE(drive->ctl, IDE_CONTROL_REG);
	udelay(1);
	/*
	 * Wait for drive to become non-BUSY
	 */
	if ((stat = GET_STAT()) & BUSY_STAT) {
		unsigned long flags, timeout;
		__save_flags(flags);	/* local CPU only */
		ide__sti();		/* local CPU only -- for jiffies */
		timeout = jiffies + WAIT_CMD;
		while ((stat = GET_STAT()) & BUSY_STAT) {
			if (0 < (signed long)(jiffies - timeout))
				break;
		}
		__restore_flags(flags); /* local CPU only */
	}

	/*
	 * Allow status to settle, then read it again.
	 * A few rare drives vastly violate the 400ns spec here,
	 * so we'll wait up to 10usec for a "good" status
	 * rather than expensively fail things immediately.
	 * This fix courtesy of Matthew Faupel & Niccolo Rigacci.
	 */
	for (i = 0; i < 10; i++) {
		udelay(1);
		if (OK_STAT((stat = GET_STAT()), DRIVE_READY, BUSY_STAT|DRQ_STAT|ERR_STAT)) {
			error = 0;
			break;
		}
	}

	SELECT_MASK(HWIF(drive), drive, 0);

	enable_irq(hwif->irq);

	if (error) {
		(void) ide_dump_status(drive, "set_drive_speed_status", stat);
		return error;
	}

	drive->id->dma_ultra &= ~0xFF00;
	drive->id->dma_mword &= ~0x0F00;
	drive->id->dma_1word &= ~0x0F00;

#if defined(CONFIG_BLK_DEV_IDEDMA) && !defined(CONFIG_DMA_NONPCI)
	if (speed > XFER_PIO_4) {
		outb(inb(hwif->dma_base+2)|(1<<(5+unit)), hwif->dma_base+2);
	} else {
		outb(inb(hwif->dma_base+2) & ~(1<<(5+unit)), hwif->dma_base+2);
	}
#endif /* (CONFIG_BLK_DEV_IDEDMA) && !(CONFIG_DMA_NONPCI) */

	switch(speed) {
		case XFER_UDMA_7:   drive->id->dma_ultra |= 0x8080; break;
		case XFER_UDMA_6:   drive->id->dma_ultra |= 0x4040; break;
		case XFER_UDMA_5:   drive->id->dma_ultra |= 0x2020; break;
		case XFER_UDMA_4:   drive->id->dma_ultra |= 0x1010; break;
		case XFER_UDMA_3:   drive->id->dma_ultra |= 0x0808; break;
		case XFER_UDMA_2:   drive->id->dma_ultra |= 0x0404; break;
		case XFER_UDMA_1:   drive->id->dma_ultra |= 0x0202; break;
		case XFER_UDMA_0:   drive->id->dma_ultra |= 0x0101; break;
		case XFER_MW_DMA_2: drive->id->dma_mword |= 0x0404; break;
		case XFER_MW_DMA_1: drive->id->dma_mword |= 0x0202; break;
		case XFER_MW_DMA_0: drive->id->dma_mword |= 0x0101; break;
		case XFER_SW_DMA_2: drive->id->dma_1word |= 0x0404; break;
		case XFER_SW_DMA_1: drive->id->dma_1word |= 0x0202; break;
		case XFER_SW_DMA_0: drive->id->dma_1word |= 0x0101; break;
		default: break;
	}
	return error;
}

EXPORT_SYMBOL(ide_auto_reduce_xfer);
EXPORT_SYMBOL(ide_driveid_update);
EXPORT_SYMBOL(ide_ata66_check);
EXPORT_SYMBOL(set_transfer);
#ifdef CONFIG_BLK_DEV_IDEDMA
EXPORT_SYMBOL(eighty_ninty_three);
#endif // CONFIG_BLK_DEV_IDEDMA
EXPORT_SYMBOL(ide_config_drive_speed);

