/*
 * linux/drivers/ide/ide-taskfile.c	Version 0.20	Oct 11, 2000
 *
 *  Copyright (C) 2000		Michael Cornwell <cornwell@acm.org>
 *  Copyright (C) 2000		Andre Hedrick <andre@linux-ide.org>
 *
 *  May be copied or modified under the terms of the GNU General Public License
 *
 * IDE_DEBUG(__LINE__);
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

#ifdef CONFIG_IDE_TASKFILE_IO
#  define __TASKFILE__IO
#else /* CONFIG_IDE_TASKFILE_IO */
#  undef __TASKFILE__IO
#endif /* CONFIG_IDE_TASKFILE_IO */

#define DEBUG_TASKFILE	0	/* unset when fixed */

#if DEBUG_TASKFILE
#define DTF(x...) printk(##x)
#else
#define DTF(x...)
#endif

inline u32 task_read_24 (ide_drive_t *drive)
{
	return	(IN_BYTE(IDE_HCYL_REG)<<16) |
		(IN_BYTE(IDE_LCYL_REG)<<8) |
		 IN_BYTE(IDE_SECTOR_REG);
}

static void ata_bswap_data (void *buffer, int wcount)
{
	u16 *p = buffer;

	while (wcount--) {
		*p = *p << 8 | *p >> 8; p++;
		*p = *p << 8 | *p >> 8; p++;
	}
}

#if SUPPORT_VLB_SYNC
/*
 * Some localbus EIDE interfaces require a special access sequence
 * when using 32-bit I/O instructions to transfer data.  We call this
 * the "vlb_sync" sequence, which consists of three successive reads
 * of the sector count register location, with interrupts disabled
 * to ensure that the reads all happen together.
 */
static inline void task_vlb_sync (ide_ioreg_t port) {
	(void) inb (port);
	(void) inb (port);
	(void) inb (port);
}
#endif /* SUPPORT_VLB_SYNC */

/*
 * This is used for most PIO data transfers *from* the IDE interface
 */
void ata_input_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	byte io_32bit = drive->io_32bit;

	if (io_32bit) {
#if SUPPORT_VLB_SYNC
		if (io_32bit & 2) {
			unsigned long flags;
			__save_flags(flags);	/* local CPU only */
			__cli();		/* local CPU only */
			task_vlb_sync(IDE_NSECTOR_REG);
			insl(IDE_DATA_REG, buffer, wcount);
			__restore_flags(flags);	/* local CPU only */
		} else
#endif /* SUPPORT_VLB_SYNC */
			insl(IDE_DATA_REG, buffer, wcount);
	} else {
#if SUPPORT_SLOW_DATA_PORTS
		if (drive->slow) {
			unsigned short *ptr = (unsigned short *) buffer;
			while (wcount--) {
				*ptr++ = inw_p(IDE_DATA_REG);
				*ptr++ = inw_p(IDE_DATA_REG);
			}
		} else
#endif /* SUPPORT_SLOW_DATA_PORTS */
			insw(IDE_DATA_REG, buffer, wcount<<1);
	}
}

/*
 * This is used for most PIO data transfers *to* the IDE interface
 */
void ata_output_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	byte io_32bit = drive->io_32bit;

	if (io_32bit) {
#if SUPPORT_VLB_SYNC
		if (io_32bit & 2) {
			unsigned long flags;
			__save_flags(flags);	/* local CPU only */
			__cli();		/* local CPU only */
			task_vlb_sync(IDE_NSECTOR_REG);
			outsl(IDE_DATA_REG, buffer, wcount);
			__restore_flags(flags);	/* local CPU only */
		} else
#endif /* SUPPORT_VLB_SYNC */
			outsl(IDE_DATA_REG, buffer, wcount);
	} else {
#if SUPPORT_SLOW_DATA_PORTS
		if (drive->slow) {
			unsigned short *ptr = (unsigned short *) buffer;
			while (wcount--) {
				outw_p(*ptr++, IDE_DATA_REG);
				outw_p(*ptr++, IDE_DATA_REG);
			}
		} else
#endif /* SUPPORT_SLOW_DATA_PORTS */
			outsw(IDE_DATA_REG, buffer, wcount<<1);
	}
}


static inline void taskfile_input_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	ata_input_data(drive, buffer, wcount);
	if (drive->bswap)
		ata_bswap_data(buffer, wcount);
}

static inline void taskfile_output_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	if (drive->bswap) {
		ata_bswap_data(buffer, wcount);
		ata_output_data(drive, buffer, wcount);
		ata_bswap_data(buffer, wcount);
	} else {
		ata_output_data(drive, buffer, wcount);
	}
}

ide_startstop_t do_rw_taskfile (ide_drive_t *drive, ide_task_t *task)
{
	task_struct_t *taskfile = (task_struct_t *) task->tfRegister;
	hob_struct_t *hobfile = (hob_struct_t *) task->hobRegister;
	struct hd_driveid *id = drive->id;
	byte HIHI = (drive->addressing) ? 0xE0 : 0xEF;

	/* (ks/hs): Moved to start, do not use for multiple out commands */
	if (task->handler != task_mulout_intr) {
		if (IDE_CONTROL_REG)
			OUT_BYTE(drive->ctl, IDE_CONTROL_REG);	/* clear nIEN */
		SELECT_MASK(HWIF(drive), drive, 0);
	}

	if ((id->command_set_2 & 0x0400) &&
	    (id->cfs_enable_2 & 0x0400) &&
	    (drive->addressing == 1)) {
		OUT_BYTE(hobfile->feature, IDE_FEATURE_REG);
		OUT_BYTE(hobfile->sector_count, IDE_NSECTOR_REG);
		OUT_BYTE(hobfile->sector_number, IDE_SECTOR_REG);
		OUT_BYTE(hobfile->low_cylinder, IDE_LCYL_REG);
		OUT_BYTE(hobfile->high_cylinder, IDE_HCYL_REG);
	}

	OUT_BYTE(taskfile->feature, IDE_FEATURE_REG);
	OUT_BYTE(taskfile->sector_count, IDE_NSECTOR_REG);
	/* refers to number of sectors to transfer */
	OUT_BYTE(taskfile->sector_number, IDE_SECTOR_REG);
	/* refers to sector offset or start sector */
	OUT_BYTE(taskfile->low_cylinder, IDE_LCYL_REG);
	OUT_BYTE(taskfile->high_cylinder, IDE_HCYL_REG);

	OUT_BYTE((taskfile->device_head & HIHI) | drive->select.all, IDE_SELECT_REG);
	if (task->handler != NULL) {
#if 0
		ide_set_handler (drive, task->handler, WAIT_CMD, NULL);
		OUT_BYTE(taskfile->command, IDE_COMMAND_REG);
		/*
		 * warning check for race between handler and prehandler for
		 * writing first block of data.  however since we are well
		 * inside the boundaries of the seek, we should be okay.
		 */
		if (task->prehandler != NULL) {
			return task->prehandler(drive, task->rq);
		}
#else
		ide_startstop_t startstop;

		ide_set_handler (drive, task->handler, WAIT_CMD, NULL);
		OUT_BYTE(taskfile->command, IDE_COMMAND_REG);

		if (ide_wait_stat(&startstop, drive, DATA_READY, drive->bad_wstat, WAIT_DRQ)) {
			printk(KERN_ERR "%s: no DRQ after issuing %s\n",
				drive->name,
				drive->mult_count ? "MULTWRITE" : "WRITE");
			return startstop;
		}
		/* (ks/hs): Fixed Multi Write */
		if ((taskfile->command != WIN_MULTWRITE) &&
		    (taskfile->command != WIN_MULTWRITE_EXT)) {
			struct request *rq = HWGROUP(drive)->rq;
		/* For Write_sectors we need to stuff the first sector */
			taskfile_output_data(drive, rq->buffer, SECTOR_WORDS);
			rq->current_nr_sectors--;
		} else {
		/* Stuff first sector(s) by implicitly calling the handler */
			if (!(drive_is_ready(drive))) {
			/* FIXME: Replace hard-coded 100, error handling? */
				int i;
				for (i=0; i<100; i++) {
					if (drive_is_ready(drive))
						break;
				}
			}
			return task->handler(drive);
		}
#endif
	} else {
		/* for dma commands we down set the handler */
		if (drive->using_dma && !(HWIF(drive)->dmaproc(((taskfile->command == WIN_WRITEDMA) || (taskfile->command == WIN_WRITEDMA_EXT)) ? ide_dma_write : ide_dma_read, drive)));
	}

	return ide_started;
}

void do_taskfile (ide_drive_t *drive, struct hd_drive_task_hdr *taskfile, struct hd_drive_hob_hdr *hobfile, ide_handler_t *handler)
{
	struct hd_driveid *id = drive->id;
	byte HIHI = (drive->addressing) ? 0xE0 : 0xEF;

	/* (ks/hs): Moved to start, do not use for multiple out commands */
	if (*handler != task_mulout_intr) {
		if (IDE_CONTROL_REG)
			OUT_BYTE(drive->ctl, IDE_CONTROL_REG);  /* clear nIEN */
		SELECT_MASK(HWIF(drive), drive, 0);
	}

	if ((id->command_set_2 & 0x0400) &&
	    (id->cfs_enable_2 & 0x0400) &&
	    (drive->addressing == 1)) {
		OUT_BYTE(hobfile->feature, IDE_FEATURE_REG);
		OUT_BYTE(hobfile->sector_count, IDE_NSECTOR_REG);
		OUT_BYTE(hobfile->sector_number, IDE_SECTOR_REG);
		OUT_BYTE(hobfile->low_cylinder, IDE_LCYL_REG);
		OUT_BYTE(hobfile->high_cylinder, IDE_HCYL_REG);
	}

	OUT_BYTE(taskfile->feature, IDE_FEATURE_REG);
	OUT_BYTE(taskfile->sector_count, IDE_NSECTOR_REG);
	/* refers to number of sectors to transfer */
	OUT_BYTE(taskfile->sector_number, IDE_SECTOR_REG);
	/* refers to sector offset or start sector */
	OUT_BYTE(taskfile->low_cylinder, IDE_LCYL_REG);
	OUT_BYTE(taskfile->high_cylinder, IDE_HCYL_REG);

	OUT_BYTE((taskfile->device_head & HIHI) | drive->select.all, IDE_SELECT_REG);
	if (handler != NULL) {
		ide_set_handler (drive, handler, WAIT_CMD, NULL);
		OUT_BYTE(taskfile->command, IDE_COMMAND_REG);
	} else {
		/* for dma commands we down set the handler */
		if (drive->using_dma && !(HWIF(drive)->dmaproc(((taskfile->command == WIN_WRITEDMA) || (taskfile->command == WIN_WRITEDMA_EXT)) ? ide_dma_write : ide_dma_read, drive)));
	}
}

#if 0
ide_startstop_t flagged_taskfile (ide_drive_t *drive, ide_task_t *task)
{
	task_struct_t *taskfile = (task_struct_t *) task->tfRegister;
	hob_struct_t *hobfile = (hob_struct_t *) task->hobRegister;
	struct hd_driveid *id = drive->id;

	/*
	 * (KS) Check taskfile in/out flags.
	 * If set, then execute as it is defined.
	 * If not set, then define default settings.
	 * The default values are:
	 *	write and read all taskfile registers (except data) 
	 *	write and read the hob registers (sector,nsector,lcyl,hcyl)
	 */
	if (task->tf_out_flags.all == 0) {
		task->tf_out_flags.all = IDE_TASKFILE_STD_OUT_FLAGS;
		if ((id->command_set_2 & 0x0400) &&
		    (id->cfs_enable_2 & 0x0400) &&
		    (drive->addressing == 1)) {
			task->tf_out_flags.all != (IDE_HOB_STD_OUT_FLAGS << 8);
		}
        }

	if (task->tf_in_flags.all == 0) {
		task->tf_in_flags.all = IDE_TASKFILE_STD_IN_FLAGS;
		if ((id->command_set_2 & 0x0400) &&
		    (id->cfs_enable_2 & 0x0400) &&
		    (drive->addressing == 1)) {
			task->tf_in_flags.all  != (IDE_HOB_STD_IN_FLAGS  << 8);
		}
        }

	if (IDE_CONTROL_REG)
		OUT_BYTE(drive->ctl, IDE_CONTROL_REG);	/* clear nIEN */
	SELECT_MASK(HWIF(drive), drive, 0);

	if (task->tf_out_flags.b.data) {
		unsigned short data =  taskfile->data + (hobfile->data << 8);
		OUT_WORD (data, IDE_DATA_REG);
	}

	/* (KS) send hob registers first */
	if (task->tf_out_flags.b.nsector_hob)
		OUT_BYTE(hobfile->sector_count, IDE_NSECTOR_REG);
	if (task->tf_out_flags.b.sector_hob)
		OUT_BYTE(hobfile->sector_number, IDE_SECTOR_REG);
	if (task->tf_out_flags.b.lcyl_hob)
		OUT_BYTE(hobfile->low_cylinder, IDE_LCYL_REG);
	if (task->tf_out_flags.b.hcyl_hob)
		OUT_BYTE(hobfile->high_cylinder, IDE_HCYL_REG);


	/* (KS) Send now the standard registers */
	if (task->tf_out_flags.b.error_feature)
		OUT_BYTE(taskfile->feature, IDE_FEATURE_REG);
	/* refers to number of sectors to transfer */
	if (task->tf_out_flags.b.nsector)
		OUT_BYTE(taskfile->sector_count, IDE_NSECTOR_REG);
	/* refers to sector offset or start sector */
	if (task->tf_out_flags.b.sector)
		OUT_BYTE(taskfile->sector_number, IDE_SECTOR_REG);
	if (task->tf_out_flags.b.lcyl)
		OUT_BYTE(taskfile->low_cylinder, IDE_LCYL_REG);
	if (task->tf_out_flags.b.hcyl)
		OUT_BYTE(taskfile->high_cylinder, IDE_HCYL_REG);

        /*
	 * (KS) Do not modify the specified taskfile. We want to have a
	 * universal pass through, so we must execute ALL specified values.
	 *
	 * (KS) The drive head register is mandatory.
	 * Don't care about the out flags !
	 */
	OUT_BYTE(taskfile->device_head | drive->select.all, IDE_SELECT_REG);
	if (task->handler != NULL) {
#if 0
		ide_set_handler (drive, task->handler, WAIT_CMD, NULL);
		OUT_BYTE(taskfile->command, IDE_COMMAND_REG);
		/*
		 * warning check for race between handler and prehandler for
		 * writing first block of data.  however since we are well
		 * inside the boundaries of the seek, we should be okay.
		 */
		if (task->prehandler != NULL) {
			return task->prehandler(drive, task->rq);
		}
#else
		ide_startstop_t startstop;

		ide_set_handler (drive, task->handler, WAIT_CMD, NULL);

		/*
		 * (KS) The drive command register is also mandatory.
		 * Don't care about the out flags !
		 */
		OUT_BYTE(taskfile->command, IDE_COMMAND_REG);

		if (ide_wait_stat(&startstop, drive, DATA_READY, drive->bad_wstat, WAIT_DRQ)) {
			printk(KERN_ERR "%s: no DRQ after issuing %s\n",
				drive->name,
				drive->mult_count ? "MULTWRITE" : "WRITE");
			return startstop;
		}
		/* (ks/hs): Fixed Multi Write */
		if ((taskfile->command != WIN_MULTWRITE) &&
		    (taskfile->command != WIN_MULTWRITE_EXT)) {
			struct request *rq = HWGROUP(drive)->rq;
		/* For Write_sectors we need to stuff the first sector */
			taskfile_output_data(drive, rq->buffer, SECTOR_WORDS);
			rq->current_nr_sectors--;
		} else {
		/* Stuff first sector(s) by implicitly calling the handler */
			if (!(drive_is_ready(drive))) {
			/* FIXME: Replace hard-coded 100, error handling? */
				int i;
				for (i=0; i<100; i++) {
					if (drive_is_ready(drive))
						break;
				}
			}
			return task->handler(drive);
		}
#endif
	} else {
		/* for dma commands we down set the handler */
		if (drive->using_dma && !(HWIF(drive)->dmaproc(((taskfile->command == WIN_WRITEDMA) || (taskfile->command == WIN_WRITEDMA_EXT)) ? ide_dma_write : ide_dma_read, drive)));
	}

	return ide_started;
}
#endif

#if 0
/*
 * Error reporting, in human readable form (luxurious, but a memory hog).
 */
byte taskfile_dump_status (ide_drive_t *drive, const char *msg, byte stat)
{
	unsigned long flags;
	byte err = 0;

	__save_flags (flags);	/* local CPU only */
	ide__sti();		/* local CPU only */
	printk("%s: %s: status=0x%02x", drive->name, msg, stat);
#if FANCY_STATUS_DUMPS
	printk(" { ");
	if (stat & BUSY_STAT)
		printk("Busy ");
	else {
		if (stat & READY_STAT)	printk("DriveReady ");
		if (stat & WRERR_STAT)	printk("DeviceFault ");
		if (stat & SEEK_STAT)	printk("SeekComplete ");
		if (stat & DRQ_STAT)	printk("DataRequest ");
		if (stat & ECC_STAT)	printk("CorrectedError ");
		if (stat & INDEX_STAT)	printk("Index ");
		if (stat & ERR_STAT)	printk("Error ");
	}
	printk("}");
#endif  /* FANCY_STATUS_DUMPS */
	printk("\n");
	if ((stat & (BUSY_STAT|ERR_STAT)) == ERR_STAT) {
		err = GET_ERR();
		printk("%s: %s: error=0x%02x", drive->name, msg, err);
#if FANCY_STATUS_DUMPS
		if (drive->media == ide_disk) {
			printk(" { ");
			if (err & ABRT_ERR)	printk("DriveStatusError ");
			if (err & ICRC_ERR)	printk("%s", (err & ABRT_ERR) ? "BadCRC " : "BadSector ");
			if (err & ECC_ERR)	printk("UncorrectableError ");
			if (err & ID_ERR)	printk("SectorIdNotFound ");
			if (err & TRK0_ERR)	printk("TrackZeroNotFound ");
			if (err & MARK_ERR)	printk("AddrMarkNotFound ");
			printk("}");
			if ((err & (BBD_ERR | ABRT_ERR)) == BBD_ERR || (err & (ECC_ERR|ID_ERR|MARK_ERR))) {
				if ((drive->id->command_set_2 & 0x0400) &&
				    (drive->id->cfs_enable_2 & 0x0400) &&
				    (drive->addressing == 1)) {
					__u64 sectors = 0;
					u32 low = 0, high = 0;
					low = task_read_24(drive);
					OUT_BYTE(0x80, IDE_CONTROL_REG);
					high = task_read_24(drive);
					sectors = ((__u64)high << 24) | low;
					printk(", LBAsect=%lld", sectors);
				} else {
					byte cur = IN_BYTE(IDE_SELECT_REG);
					if (cur & 0x40) {	/* using LBA? */
						printk(", LBAsect=%ld", (unsigned long)
						 ((cur&0xf)<<24)
						 |(IN_BYTE(IDE_HCYL_REG)<<16)
						 |(IN_BYTE(IDE_LCYL_REG)<<8)
						 | IN_BYTE(IDE_SECTOR_REG));
					} else {
						printk(", CHS=%d/%d/%d",
						  (IN_BYTE(IDE_HCYL_REG)<<8) +
						   IN_BYTE(IDE_LCYL_REG),
						  cur & 0xf,
						  IN_BYTE(IDE_SECTOR_REG));
					}
				}
				if (HWGROUP(drive)->rq)
					printk(", sector=%llu", (__u64) HWGROUP(drive)->rq->sector);
			}
		}
#endif  /* FANCY_STATUS_DUMPS */
		printk("\n");
	}
	__restore_flags (flags);	/* local CPU only */
	return err;
}

/*
 * Clean up after success/failure of an explicit taskfile operation.
 */
void ide_end_taskfile (ide_drive_t *drive, byte stat, byte err)
{
	unsigned long flags;
	struct request *rq;
	ide_task_t *args;
	task_ioreg_t command;

	spin_lock_irqsave(&io_request_lock, flags);
	rq = HWGROUP(drive)->rq;
	spin_unlock_irqrestore(&io_request_lock, flags);
	args = (ide_task_t *) rq->special;

	command = args->tfRegister[IDE_COMMAND_OFFSET];

	rq->errors = !OK_STAT(stat,READY_STAT,BAD_STAT);

	args->tfRegister[IDE_ERROR_OFFSET]   = err;
	args->tfRegister[IDE_NSECTOR_OFFSET] = IN_BYTE(IDE_NSECTOR_REG);
	args->tfRegister[IDE_SECTOR_OFFSET]  = IN_BYTE(IDE_SECTOR_REG);
	args->tfRegister[IDE_LCYL_OFFSET]    = IN_BYTE(IDE_LCYL_REG);
	args->tfRegister[IDE_HCYL_OFFSET]    = IN_BYTE(IDE_HCYL_REG);
	args->tfRegister[IDE_SELECT_OFFSET]  = IN_BYTE(IDE_SELECT_REG);
	args->tfRegister[IDE_STATUS_OFFSET]  = stat;
	if ((drive->id->command_set_2 & 0x0400) &&
	    (drive->id->cfs_enable_2 & 0x0400) &&
	    (drive->addressing == 1)) {
		OUT_BYTE(drive->ctl|0x80, IDE_CONTROL_REG_HOB);
		args->hobRegister[IDE_FEATURE_OFFSET_HOB] = IN_BYTE(IDE_FEATURE_REG);
		args->hobRegister[IDE_NSECTOR_OFFSET_HOB] = IN_BYTE(IDE_NSECTOR_REG);
		args->hobRegister[IDE_SECTOR_OFFSET_HOB]  = IN_BYTE(IDE_SECTOR_REG);
		args->hobRegister[IDE_LCYL_OFFSET_HOB]    = IN_BYTE(IDE_LCYL_REG);
		args->hobRegister[IDE_HCYL_OFFSET_HOB]    = IN_BYTE(IDE_HCYL_REG);
	}

/*	taskfile_settings_update(drive, args, command); */

	spin_lock_irqsave(&io_request_lock, flags);
	blkdev_dequeue_request(rq);
	HWGROUP(drive)->rq = NULL;
	end_that_request_last(rq);
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * try_to_flush_leftover_data() is invoked in response to a drive
 * unexpectedly having its DRQ_STAT bit set.  As an alternative to
 * resetting the drive, this routine tries to clear the condition
 * by read a sector's worth of data from the drive.  Of course,
 * this may not help if the drive is *waiting* for data from *us*.
 */
void task_try_to_flush_leftover_data (ide_drive_t *drive)
{
	int i = (drive->mult_count ? drive->mult_count : 1) * SECTOR_WORDS;

	if (drive->media != ide_disk)
		return;
	while (i > 0) {
		u32 buffer[16];
		unsigned int wcount = (i > 16) ? 16 : i;
		i -= wcount;
		taskfile_input_data (drive, buffer, wcount);
	}
}

/*
 * taskfile_error() takes action based on the error returned by the drive.
 */
ide_startstop_t taskfile_error (ide_drive_t *drive, const char *msg, byte stat)
{
	struct request *rq;
	byte err;

        err = taskfile_dump_status(drive, msg, stat);
	if (drive == NULL || (rq = HWGROUP(drive)->rq) == NULL)
		return ide_stopped;
	/* retry only "normal" I/O: */
	if (rq->cmd == IDE_DRIVE_TASKFILE) {
		rq->errors = 1;
		ide_end_taskfile(drive, stat, err);
		return ide_stopped;
	}
	if (stat & BUSY_STAT || ((stat & WRERR_STAT) && !drive->nowerr)) { /* other bits are useless when BUSY */
		rq->errors |= ERROR_RESET;
	} else {
		if (drive->media == ide_disk && (stat & ERR_STAT)) {
			/* err has different meaning on cdrom and tape */
			if (err == ABRT_ERR) {
				if (drive->select.b.lba && IN_BYTE(IDE_COMMAND_REG) == WIN_SPECIFY)
					return ide_stopped;	/* some newer drives don't support WIN_SPECIFY */
			} else if ((err & (ABRT_ERR | ICRC_ERR)) == (ABRT_ERR | ICRC_ERR)) {
				drive->crc_count++;	/* UDMA crc error -- just retry the operation */
			} else if (err & (BBD_ERR | ECC_ERR))	/* retries won't help these */
				rq->errors = ERROR_MAX;
			else if (err & TRK0_ERR)	/* help it find track zero */
                                rq->errors |= ERROR_RECAL;
                }
                if ((stat & DRQ_STAT) && rq->cmd != WRITE)
                        task_try_to_flush_leftover_data(drive);
	}
	if (GET_STAT() & (BUSY_STAT|DRQ_STAT))
		OUT_BYTE(WIN_IDLEIMMEDIATE,IDE_COMMAND_REG);	/* force an abort */

	if (rq->errors >= ERROR_MAX) {
		if (drive->driver != NULL)
			DRIVER(drive)->end_request(0, HWGROUP(drive));
		else
			ide_end_request(0, HWGROUP(drive));
	} else {
		if ((rq->errors & ERROR_RESET) == ERROR_RESET) {
			++rq->errors;
			return ide_do_reset(drive);
		}
		if ((rq->errors & ERROR_RECAL) == ERROR_RECAL)
			drive->special.b.recalibrate = 1;
		++rq->errors;
	}
	return ide_stopped;
}
#endif

/*
 * Handler for special commands without a data phase from ide-disk
 */

/*
 * set_multmode_intr() is invoked on completion of a WIN_SETMULT cmd.
 */
ide_startstop_t set_multmode_intr (ide_drive_t *drive)
{
	byte stat;

	if (OK_STAT(stat=GET_STAT(),READY_STAT,BAD_STAT)) {
		drive->mult_count = drive->mult_req;
	} else {
		drive->mult_req = drive->mult_count = 0;
		drive->special.b.recalibrate = 1;
		(void) ide_dump_status(drive, "set_multmode", stat);
	}
	return ide_stopped;
}

/*
 * set_geometry_intr() is invoked on completion of a WIN_SPECIFY cmd.
 */
ide_startstop_t set_geometry_intr (ide_drive_t *drive)
{
	byte stat;

	if (OK_STAT(stat=GET_STAT(),READY_STAT,BAD_STAT))
		return ide_stopped;

	if (stat & (ERR_STAT|DRQ_STAT))
		return ide_error(drive, "set_geometry_intr", stat);

	ide_set_handler(drive, &set_geometry_intr, WAIT_CMD, NULL);
	return ide_started;
}

/*
 * recal_intr() is invoked on completion of a WIN_RESTORE (recalibrate) cmd.
 */
ide_startstop_t recal_intr (ide_drive_t *drive)
{
	byte stat = GET_STAT();

	if (!OK_STAT(stat,READY_STAT,BAD_STAT))
		return ide_error(drive, "recal_intr", stat);
	return ide_stopped;
}

/*
 * Handler for commands without a data phase
 */
ide_startstop_t task_no_data_intr (ide_drive_t *drive)
{
	ide_task_t *args	= HWGROUP(drive)->rq->special;
	byte stat		= GET_STAT();

	ide__sti();	/* local CPU only */

	if (!OK_STAT(stat, READY_STAT, BAD_STAT))
		return ide_error(drive, "task_no_data_intr", stat); /* calls ide_end_drive_cmd */

	if (args)
		ide_end_drive_cmd (drive, stat, GET_ERR());

	return ide_stopped;
}

/*
 * Handler for command with PIO data-in phase
 */
ide_startstop_t task_in_intr (ide_drive_t *drive)
{
	byte stat		= GET_STAT();
	byte io_32bit		= drive->io_32bit;
	struct request *rq	= HWGROUP(drive)->rq;
	char *pBuf		= NULL;

	if (!OK_STAT(stat,DATA_READY,BAD_R_STAT)) {
		if (stat & (ERR_STAT|DRQ_STAT)) {
			return ide_error(drive, "task_in_intr", stat);
		}
		if (!(stat & BUSY_STAT)) {
			DTF("task_in_intr to Soon wait for next interrupt\n");
			ide_set_handler(drive, &task_in_intr, WAIT_CMD, NULL);
			return ide_started;  
		}
	}
	DTF("stat: %02x\n", stat);
	pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);
	DTF("Read: %p, rq->current_nr_sectors: %d\n", pBuf, (int) rq->current_nr_sectors);

	drive->io_32bit = 0;
	taskfile_input_data(drive, pBuf, SECTOR_WORDS);
	drive->io_32bit = io_32bit;

	if (--rq->current_nr_sectors <= 0) {
		/* (hs): swapped next 2 lines */
		DTF("Request Ended stat: %02x\n", GET_STAT());
		ide_end_request(1, HWGROUP(drive));
	} else {
		ide_set_handler(drive, &task_in_intr,  WAIT_CMD, NULL);
		return ide_started;
	}
	return ide_stopped;
}

#undef ALTSTAT_SCREW_UP

#ifdef ALTSTAT_SCREW_UP
/*
 * (ks/hs): Poll Alternate Status Register to ensure
 * that drive is not busy.
 */
byte altstat_multi_busy (ide_drive_t *drive, byte stat, const char *msg)
{
	int i;

	DTF("multi%s: ASR = %x\n", msg, stat);
	if (stat & BUSY_STAT) {
		/* (ks/hs): FIXME: Replace hard-coded 100, error handling? */
		for (i=0; i<100; i++) {
			stat = GET_ALTSTAT();
			if ((stat & BUSY_STAT) == 0)
				break;
		}
	}
	/*
	 * (ks/hs): Read Status AFTER Alternate Status Register
	 */
	return(GET_STAT());
}

/*
 * (ks/hs): Poll Alternate status register to wait for drive
 * to become ready for next transfer
 */
byte altstat_multi_poll (ide_drive_t *drive, byte stat, const char *msg)
{
	/* (ks/hs): FIXME: Error handling, time-out? */
	while (stat & BUSY_STAT)
		stat = GET_ALTSTAT();
	DTF("multi%s: nsect=1, ASR = %x\n", msg, stat);
	return(GET_STAT());	/* (ks/hs): Clear pending IRQ */
}
#endif /* ALTSTAT_SCREW_UP */

/*
 * Handler for command with Read Multiple
 */
ide_startstop_t task_mulin_intr (ide_drive_t *drive)
{
	unsigned int		msect, nsect;

#ifdef ALTSTAT_SCREW_UP
	byte stat	= altstat_multi_busy(drive, GET_ALTSTAT(), "read");
#else
	byte stat		= GET_STAT();
#endif /* ALTSTAT_SCREW_UP */

	byte io_32bit		= drive->io_32bit;
	struct request *rq	= HWGROUP(drive)->rq;
	char *pBuf		= NULL;

	if (!OK_STAT(stat,DATA_READY,BAD_R_STAT)) {
		if (stat & (ERR_STAT|DRQ_STAT)) {
			return ide_error(drive, "task_mulin_intr", stat);
		}
		/* no data yet, so wait for another interrupt */
		ide_set_handler(drive, &task_mulin_intr, WAIT_CMD, NULL);
		return ide_started;
	}

	/* (ks/hs): Fixed Multi-Sector transfer */
	msect = drive->mult_count;

#ifdef ALTSTAT_SCREW_UP
	/*
	 * Screw the request we do not support bad data-phase setups!
	 * Either read and learn the ATA standard or crash yourself!
	 */
	if (!msect) {
		/*
		 * (ks/hs): Drive supports multi-sector transfer,
		 * drive->mult_count was not set
		 */
		nsect = 1;
		while (rq->current_nr_sectors) {
			pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);
			DTF("Multiread: %p, nsect: %d, rq->current_nr_sectors: %ld\n", pBuf, nsect, rq->current_nr_sectors);
			drive->io_32bit = 0;
			taskfile_input_data(drive, pBuf, nsect * SECTOR_WORDS);
			drive->io_32bit = io_32bit;
			rq->errors = 0;
			rq->current_nr_sectors -= nsect;
			stat = altstat_multi_poll(drive, GET_ALTSTAT(), "read");
		}
		ide_end_request(1, HWGROUP(drive));
		return ide_stopped;
	}
#endif /* ALTSTAT_SCREW_UP */

	nsect = (rq->current_nr_sectors > msect) ? msect : rq->current_nr_sectors;
	pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);

	DTF("Multiread: %p, nsect: %d , rq->current_nr_sectors: %ld\n",
		pBuf, nsect, rq->current_nr_sectors);
	drive->io_32bit = 0;
	taskfile_input_data(drive, pBuf, nsect * SECTOR_WORDS);
	drive->io_32bit = io_32bit;
	rq->errors = 0;
	rq->current_nr_sectors -= nsect;
	if (rq->current_nr_sectors != 0) {
		ide_set_handler(drive, &task_mulin_intr, WAIT_CMD, NULL);
		return ide_started;
	}
	ide_end_request(1, HWGROUP(drive));
	return ide_stopped;
}

ide_startstop_t pre_task_out_intr (ide_drive_t *drive, struct request *rq)
{
	ide_task_t *args = rq->special;
	ide_startstop_t startstop;

	if (ide_wait_stat(&startstop, drive, DATA_READY, drive->bad_wstat, WAIT_DRQ)) {
		printk(KERN_ERR "%s: no DRQ after issuing %s\n", drive->name, drive->mult_count ? "MULTWRITE" : "WRITE");
		return startstop;
	}

	/* (ks/hs): Fixed Multi Write */
	if ((args->tfRegister[IDE_COMMAND_OFFSET] != WIN_MULTWRITE) &&
	    (args->tfRegister[IDE_COMMAND_OFFSET] != WIN_MULTWRITE_EXT)) {
		/* For Write_sectors we need to stuff the first sector */
		taskfile_output_data(drive, rq->buffer, SECTOR_WORDS);
		rq->current_nr_sectors--;
		return ide_started;
	} else {
		/*
		 * (ks/hs): Stuff the first sector(s)
		 * by implicitly calling the handler
		 */
		if (!(drive_is_ready(drive))) {
			int i;
			/*
			 * (ks/hs): FIXME: Replace hard-coded
			 *               100, error handling?
			 */
			for (i=0; i<100; i++) {
				if (drive_is_ready(drive))
					break;
			}
		}
		return args->handler(drive);
	}
	return ide_started;
}

/*
 * Handler for command with PIO data-out phase
 */
ide_startstop_t task_out_intr (ide_drive_t *drive)
{
	byte stat		= GET_STAT();
	byte io_32bit		= drive->io_32bit;
	struct request *rq	= HWGROUP(drive)->rq;
	char *pBuf		= NULL;

	if (!rq->current_nr_sectors) { 
		ide_end_request(1, HWGROUP(drive));
		return ide_stopped;
	}

	if (!OK_STAT(stat,DRIVE_READY,drive->bad_wstat)) {
		return ide_error(drive, "task_out_intr", stat);
	}
	if ((rq->current_nr_sectors==1) ^ (stat & DRQ_STAT)) {
		rq = HWGROUP(drive)->rq;
		pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);
		DTF("write: %p, rq->current_nr_sectors: %d\n", pBuf, (int) rq->current_nr_sectors);
		drive->io_32bit = 0;
		taskfile_output_data(drive, pBuf, SECTOR_WORDS);
		drive->io_32bit = io_32bit;
		rq->errors = 0;
		rq->current_nr_sectors--;
	}

	if (rq->current_nr_sectors <= 0) {
		ide_end_request(1, HWGROUP(drive));
	} else {
		ide_set_handler(drive, &task_out_intr, WAIT_CMD, NULL);
		return ide_started;
	}
	return ide_stopped;
}

/*
 * Handler for command write multiple
 * Called directly from execute_drive_cmd for the first bunch of sectors,
 * afterwards only by the ISR
 */
ide_startstop_t task_mulout_intr (ide_drive_t *drive)
{
	unsigned int		msect, nsect;

#ifdef ALTSTAT_SCREW_UP
	byte stat	= altstat_multi_busy(drive, GET_ALTSTAT(), "write");
#else
	byte stat		= GET_STAT();
#endif /* ALTSTAT_SCREW_UP */

	byte io_32bit		= drive->io_32bit;
	struct request *rq	= HWGROUP(drive)->rq;
	ide_hwgroup_t *hwgroup	= HWGROUP(drive);
	char *pBuf		= NULL;

	/*
	 * (ks/hs): Handle last IRQ on multi-sector transfer,
	 * occurs after all data was sent
	 */
	if (rq->current_nr_sectors == 0) {
		if (stat & (ERR_STAT|DRQ_STAT))
			return ide_error(drive, "task_mulout_intr", stat);
		ide_end_request(1, HWGROUP(drive));
		return ide_stopped;
	}

	if (!OK_STAT(stat,DATA_READY,BAD_R_STAT)) {
		if (stat & (ERR_STAT|DRQ_STAT)) {
			return ide_error(drive, "task_mulout_intr", stat);
		}
		/* no data yet, so wait for another interrupt */
		if (hwgroup->handler == NULL)
			ide_set_handler(drive, &task_mulout_intr, WAIT_CMD, NULL);
		return ide_started;
	}

	/* (ks/hs): See task_mulin_intr */
	msect = drive->mult_count;

#ifdef ALTSTAT_SCREW_UP
	/*
	 * Screw the request we do not support bad data-phase setups!
	 * Either read and learn the ATA standard or crash yourself!
	 */
	if (!msect) {
		nsect = 1;
		while (rq->current_nr_sectors) {
			pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);
			DTF("Multiwrite: %p, nsect: %d, rq->current_nr_sectors: %ld\n", pBuf, nsect, rq->current_nr_sectors);
			drive->io_32bit = 0;
			taskfile_output_data(drive, pBuf, nsect * SECTOR_WORDS);
			drive->io_32bit = io_32bit;
			rq->errors = 0;
			rq->current_nr_sectors -= nsect;
			stat = altstat_multi_poll(drive, GET_ALTSTAT(), "write");
		}
		ide_end_request(1, HWGROUP(drive));
		return ide_stopped;
	}
#endif /* ALTSTAT_SCREW_UP */

	nsect = (rq->current_nr_sectors > msect) ? msect : rq->current_nr_sectors;
	pBuf = rq->buffer + ((rq->nr_sectors - rq->current_nr_sectors) * SECTOR_SIZE);
	DTF("Multiwrite: %p, nsect: %d , rq->current_nr_sectors: %ld\n",
		pBuf, nsect, rq->current_nr_sectors);
	drive->io_32bit = 0;
	taskfile_output_data(drive, pBuf, nsect * SECTOR_WORDS);
	drive->io_32bit = io_32bit;
	rq->errors = 0;
	rq->current_nr_sectors -= nsect;
	if (hwgroup->handler == NULL)
		ide_set_handler(drive, &task_mulout_intr, WAIT_CMD, NULL);
	return ide_started;
}

/* Called by internal to feature out type of command being called */
ide_pre_handler_t * ide_pre_handler_parser (struct hd_drive_task_hdr *taskfile, struct hd_drive_hob_hdr *hobfile)
{
	switch(taskfile->command) {
				/* IDE_DRIVE_TASK_RAW_WRITE */
		case CFA_WRITE_MULTI_WO_ERASE:
		case WIN_MULTWRITE:
		case WIN_MULTWRITE_EXT:
//		case WIN_WRITEDMA:
//		case WIN_WRITEDMA_QUEUED:
//		case WIN_WRITEDMA_EXT:
//		case WIN_WRITEDMA_QUEUED_EXT:
				/* IDE_DRIVE_TASK_OUT */
		case WIN_WRITE:
		case WIN_WRITE_VERIFY:
		case WIN_WRITE_BUFFER:
		case CFA_WRITE_SECT_WO_ERASE:
		case WIN_DOWNLOAD_MICROCODE:
			return &pre_task_out_intr;
				/* IDE_DRIVE_TASK_OUT */
		case WIN_SMART:
			if (taskfile->feature == SMART_WRITE_LOG_SECTOR)
				return &pre_task_out_intr;
		default:
			break;
	}
	return(NULL);
}

/* Called by internal to feature out type of command being called */
ide_handler_t * ide_handler_parser (struct hd_drive_task_hdr *taskfile, struct hd_drive_hob_hdr *hobfile)
{
	switch(taskfile->command) {
		case WIN_IDENTIFY:
		case WIN_PIDENTIFY:
		case CFA_TRANSLATE_SECTOR:
		case WIN_READ_BUFFER:
		case WIN_READ:
		case WIN_READ_EXT:
			return &task_in_intr;
		case WIN_SECURITY_DISABLE:
		case WIN_SECURITY_ERASE_UNIT:
		case WIN_SECURITY_SET_PASS:
		case WIN_SECURITY_UNLOCK:
		case WIN_DOWNLOAD_MICROCODE:
		case CFA_WRITE_SECT_WO_ERASE:
		case WIN_WRITE_BUFFER:
		case WIN_WRITE_VERIFY:
		case WIN_WRITE:
		case WIN_WRITE_EXT:
			return &task_out_intr;
		case WIN_MULTREAD:
		case WIN_MULTREAD_EXT:
			return &task_mulin_intr;
		case CFA_WRITE_MULTI_WO_ERASE:
		case WIN_MULTWRITE:
		case WIN_MULTWRITE_EXT:
			return &task_mulout_intr;
		case WIN_SMART:
			switch(taskfile->feature) {
				case SMART_READ_VALUES:
				case SMART_READ_THRESHOLDS:
				case SMART_READ_LOG_SECTOR:
					return &task_in_intr;
				case SMART_WRITE_LOG_SECTOR:
					return &task_out_intr;
				default:
					return &task_no_data_intr;
			}
		case CFA_REQ_EXT_ERROR_CODE:
		case CFA_ERASE_SECTORS:
		case WIN_VERIFY:
		case WIN_VERIFY_EXT:
		case WIN_SEEK:
			return &task_no_data_intr;
		case WIN_SPECIFY:
			return &set_geometry_intr;
		case WIN_RESTORE:
			return &recal_intr;
		case WIN_DIAGNOSE:
		case WIN_FLUSH_CACHE:
		case WIN_FLUSH_CACHE_EXT:
		case WIN_STANDBYNOW1:
		case WIN_STANDBYNOW2:
		case WIN_SLEEPNOW1:
		case WIN_SLEEPNOW2:
		case WIN_SETIDLE1:
		case WIN_CHECKPOWERMODE1:
		case WIN_CHECKPOWERMODE2:
		case WIN_GETMEDIASTATUS:
		case WIN_MEDIAEJECT:
			return &task_no_data_intr;
		case WIN_SETMULT:
			return &set_multmode_intr;
		case WIN_READ_NATIVE_MAX:
		case WIN_SET_MAX:
		case WIN_READ_NATIVE_MAX_EXT:
		case WIN_SET_MAX_EXT:
		case WIN_SECURITY_ERASE_PREPARE:
		case WIN_SECURITY_FREEZE_LOCK:
		case WIN_DOORLOCK:
		case WIN_DOORUNLOCK:
		case WIN_SETFEATURES:
			return &task_no_data_intr;
		case DISABLE_SEAGATE:
		case EXABYTE_ENABLE_NEST:
			return &task_no_data_intr;
#ifdef CONFIG_BLK_DEV_IDEDMA
		case WIN_READDMA:
		case WIN_IDENTIFY_DMA:
		case WIN_READDMA_QUEUED:
		case WIN_READDMA_EXT:
		case WIN_READDMA_QUEUED_EXT:
		case WIN_WRITEDMA:
		case WIN_WRITEDMA_QUEUED:
		case WIN_WRITEDMA_EXT:
		case WIN_WRITEDMA_QUEUED_EXT:
#endif
		case WIN_FORMAT:
		case WIN_INIT:
		case WIN_DEVICE_RESET:
		case WIN_QUEUED_SERVICE:
		case WIN_PACKETCMD:
		default:
			return(NULL);
	}	
}

/* Called by ioctl to feature out type of command being called */
int ide_cmd_type_parser (ide_task_t *args)
{
	struct hd_drive_task_hdr *taskfile = (struct hd_drive_task_hdr *) args->tfRegister;
	struct hd_drive_hob_hdr *hobfile = (struct hd_drive_hob_hdr *) args->hobRegister;

	args->prehandler = ide_pre_handler_parser(taskfile, hobfile);
	args->handler = ide_handler_parser(taskfile, hobfile);

	switch(args->tfRegister[IDE_COMMAND_OFFSET]) {
		case WIN_IDENTIFY:
		case WIN_PIDENTIFY:
			return IDE_DRIVE_TASK_IN;
		case CFA_TRANSLATE_SECTOR:
		case WIN_READ:
		case WIN_READ_BUFFER:
			return IDE_DRIVE_TASK_IN;
		case WIN_WRITE:
		case WIN_WRITE_VERIFY:
		case WIN_WRITE_BUFFER:
		case CFA_WRITE_SECT_WO_ERASE:
		case WIN_DOWNLOAD_MICROCODE:
			return IDE_DRIVE_TASK_RAW_WRITE;
		case WIN_MULTREAD:
			return IDE_DRIVE_TASK_IN;
		case CFA_WRITE_MULTI_WO_ERASE:
		case WIN_MULTWRITE:
			return IDE_DRIVE_TASK_RAW_WRITE;
		case WIN_SECURITY_DISABLE:
		case WIN_SECURITY_ERASE_UNIT:
		case WIN_SECURITY_SET_PASS:
		case WIN_SECURITY_UNLOCK:
			return IDE_DRIVE_TASK_OUT;
		case WIN_SMART:
			args->tfRegister[IDE_LCYL_OFFSET] = SMART_LCYL_PASS;
			args->tfRegister[IDE_HCYL_OFFSET] = SMART_HCYL_PASS;
			switch(args->tfRegister[IDE_FEATURE_OFFSET]) {
				case SMART_READ_VALUES:
				case SMART_READ_THRESHOLDS:
				case SMART_READ_LOG_SECTOR:
					return IDE_DRIVE_TASK_IN;
				case SMART_WRITE_LOG_SECTOR:
					return IDE_DRIVE_TASK_OUT;
				default:
					return IDE_DRIVE_TASK_NO_DATA;
			}
#ifdef CONFIG_BLK_DEV_IDEDMA
		case WIN_READDMA:
		case WIN_IDENTIFY_DMA:
		case WIN_READDMA_QUEUED:
		case WIN_READDMA_EXT:
		case WIN_READDMA_QUEUED_EXT:
			return IDE_DRIVE_TASK_IN;
		case WIN_WRITEDMA:
		case WIN_WRITEDMA_QUEUED:
		case WIN_WRITEDMA_EXT:
		case WIN_WRITEDMA_QUEUED_EXT:
			return IDE_DRIVE_TASK_RAW_WRITE;
#endif
		case WIN_SETFEATURES:
			switch(args->tfRegister[IDE_FEATURE_OFFSET]) {
				case SETFEATURES_XFER:
					return IDE_DRIVE_TASK_SET_XFER;
				case SETFEATURES_DIS_DEFECT:
				case SETFEATURES_EN_APM:
				case SETFEATURES_DIS_MSN:
				case SETFEATURES_EN_RI:
				case SETFEATURES_EN_SI:
				case SETFEATURES_DIS_RPOD:
				case SETFEATURES_DIS_WCACHE:
				case SETFEATURES_EN_DEFECT:
				case SETFEATURES_DIS_APM:
				case SETFEATURES_EN_MSN:
				case SETFEATURES_EN_RLA:
				case SETFEATURES_PREFETCH:
				case SETFEATURES_EN_RPOD:
				case SETFEATURES_DIS_RI:
				case SETFEATURES_DIS_SI:
				default:
					return IDE_DRIVE_TASK_NO_DATA;
			}
		case WIN_NOP:
		case CFA_REQ_EXT_ERROR_CODE:
		case CFA_ERASE_SECTORS:
		case WIN_VERIFY:
		case WIN_VERIFY_EXT:
		case WIN_SEEK:
		case WIN_SPECIFY:
		case WIN_RESTORE:
		case WIN_DIAGNOSE:
		case WIN_FLUSH_CACHE:
		case WIN_FLUSH_CACHE_EXT:
		case WIN_STANDBYNOW1:
		case WIN_STANDBYNOW2:
		case WIN_SLEEPNOW1:
		case WIN_SLEEPNOW2:
		case WIN_SETIDLE1:
		case DISABLE_SEAGATE:
		case WIN_CHECKPOWERMODE1:
		case WIN_CHECKPOWERMODE2:
		case WIN_GETMEDIASTATUS:
		case WIN_MEDIAEJECT:
		case WIN_SETMULT:
		case WIN_READ_NATIVE_MAX:
		case WIN_SET_MAX:
		case WIN_READ_NATIVE_MAX_EXT:
		case WIN_SET_MAX_EXT:
		case WIN_SECURITY_ERASE_PREPARE:
		case WIN_SECURITY_FREEZE_LOCK:
		case EXABYTE_ENABLE_NEST:
		case WIN_DOORLOCK:
		case WIN_DOORUNLOCK:
			return IDE_DRIVE_TASK_NO_DATA;
		case WIN_FORMAT:
		case WIN_INIT:
		case WIN_DEVICE_RESET:
		case WIN_QUEUED_SERVICE:
		case WIN_PACKETCMD:
		default:
			return IDE_DRIVE_TASK_INVALID;
	}
}

/*
 * This function is intended to be used prior to invoking ide_do_drive_cmd().
 */
void ide_init_drive_taskfile (struct request *rq)
{
	memset(rq, 0, sizeof(*rq));
	rq->cmd = IDE_DRIVE_TASK_NO_DATA;
}

/*
 * This is kept for internal use only !!!
 * This is an internal call and nobody in user-space has a damn
 * reason to call this taskfile.
 *
 * ide_raw_taskfile is the one that user-space executes.
 */
int ide_wait_taskfile (ide_drive_t *drive, struct hd_drive_task_hdr *taskfile, struct hd_drive_hob_hdr *hobfile, byte *buf)
{
	struct request rq;
	ide_task_t args;

	memset(&args, 0, sizeof(ide_task_t));

	args.tfRegister[IDE_DATA_OFFSET]         = taskfile->data;
	args.tfRegister[IDE_FEATURE_OFFSET]      = taskfile->feature;
	args.tfRegister[IDE_NSECTOR_OFFSET]      = taskfile->sector_count;
	args.tfRegister[IDE_SECTOR_OFFSET]       = taskfile->sector_number;
	args.tfRegister[IDE_LCYL_OFFSET]         = taskfile->low_cylinder;
	args.tfRegister[IDE_HCYL_OFFSET]         = taskfile->high_cylinder;
	args.tfRegister[IDE_SELECT_OFFSET]       = taskfile->device_head;
	args.tfRegister[IDE_COMMAND_OFFSET]      = taskfile->command;

	args.hobRegister[IDE_DATA_OFFSET_HOB]    = hobfile->data;
	args.hobRegister[IDE_FEATURE_OFFSET_HOB] = hobfile->feature;
	args.hobRegister[IDE_NSECTOR_OFFSET_HOB] = hobfile->sector_count;
	args.hobRegister[IDE_SECTOR_OFFSET_HOB]  = hobfile->sector_number;
	args.hobRegister[IDE_LCYL_OFFSET_HOB]    = hobfile->low_cylinder;
	args.hobRegister[IDE_HCYL_OFFSET_HOB]    = hobfile->high_cylinder;
	args.hobRegister[IDE_SELECT_OFFSET_HOB]  = hobfile->device_head;
	args.hobRegister[IDE_CONTROL_OFFSET_HOB] = hobfile->control;

	ide_init_drive_taskfile(&rq);
	/* This is kept for internal use only !!! */
	args.command_type = ide_cmd_type_parser (&args);
	if (args.command_type != IDE_DRIVE_TASK_NO_DATA)
		rq.current_nr_sectors = rq.nr_sectors = (hobfile->sector_count << 8) | taskfile->sector_count;

	rq.cmd = IDE_DRIVE_TASKFILE;
	rq.buffer = buf;
	rq.special = &args;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}

int ide_raw_taskfile (ide_drive_t *drive, ide_task_t *args, byte *buf)
{
	struct request rq;
	ide_init_drive_taskfile(&rq);
	rq.cmd = IDE_DRIVE_TASKFILE;
	rq.buffer = buf;

	if (args->command_type != IDE_DRIVE_TASK_NO_DATA)
		rq.current_nr_sectors = rq.nr_sectors = (args->hobRegister[IDE_NSECTOR_OFFSET_HOB] << 8) | args->tfRegister[IDE_NSECTOR_OFFSET];

	rq.special = args;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}


#ifdef CONFIG_IDE_TASK_IOCTL_DEBUG
char * ide_ioctl_verbose (unsigned int cmd)
{
	return("unknown");
}

char * ide_task_cmd_verbose (byte task)
{
	return("unknown");
}
#endif /* CONFIG_IDE_TASK_IOCTL_DEBUG */

/*
 *  The taskfile glue table
 *
 *  reqtask.data_phase	reqtask.req_cmd
 *  			args.command_type		args.handler
 *
 *  TASKFILE_P_OUT_DMAQ	??				??
 *  TASKFILE_P_IN_DMAQ	??				??
 *  TASKFILE_P_OUT_DMA	??				??
 *  TASKFILE_P_IN_DMA	??				??
 *  TASKFILE_P_OUT	??				??
 *  TASKFILE_P_IN	??				??
 *
 *  TASKFILE_OUT_DMAQ	IDE_DRIVE_TASK_RAW_WRITE	NULL
 *  TASKFILE_IN_DMAQ	IDE_DRIVE_TASK_IN		NULL
 *
 *  TASKFILE_OUT_DMA	IDE_DRIVE_TASK_RAW_WRITE	NULL
 *  TASKFILE_IN_DMA	IDE_DRIVE_TASK_IN		NULL
 *
 *  TASKFILE_IN_OUT	??				??
 *
 *  TASKFILE_MULTI_OUT	IDE_DRIVE_TASK_RAW_WRITE	task_mulout_intr
 *  TASKFILE_MULTI_IN	IDE_DRIVE_TASK_IN		task_mulin_intr
 *
 *  TASKFILE_OUT	IDE_DRIVE_TASK_RAW_WRITE	task_out_intr
 *  TASKFILE_OUT	IDE_DRIVE_TASK_OUT		task_out_intr
 *
 *  TASKFILE_IN		IDE_DRIVE_TASK_IN		task_in_intr
 *  TASKFILE_NO_DATA	IDE_DRIVE_TASK_NO_DATA		task_no_data_intr
 *
 *  			IDE_DRIVE_TASK_SET_XFER		task_no_data_intr
 *  			IDE_DRIVE_TASK_INVALID
 *
 */

#define MAX_DMA		(256*SECTOR_WORDS)

int ide_taskfile_ioctl (ide_drive_t *drive, struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	ide_task_request_t	*req_task;
	ide_task_t		args;

	byte *outbuf		= NULL;
	byte *inbuf		= NULL;
	task_ioreg_t *argsptr	= args.tfRegister;
	task_ioreg_t *hobsptr	= args.hobRegister;
	int err			= 0;
	int tasksize		= sizeof(struct ide_task_request_s);
	int taskin		= 0;
	int taskout		= 0;

	req_task = kmalloc(tasksize, GFP_KERNEL);
	if (req_task == NULL) return -ENOMEM;
	memset(req_task, 0, tasksize);
	if (copy_from_user(req_task, (void *) arg, tasksize)) {
		kfree(req_task);
		return -EFAULT;
	}

	taskout = (int) req_task->out_size;
	taskin  = (int) req_task->in_size;

	if (taskout) {
		int outtotal = tasksize;
		outbuf = kmalloc(taskout, GFP_KERNEL);
		if (outbuf == NULL) {
			err = -ENOMEM;
			goto abort;
		}
		memset(outbuf, 0, taskout);
		if (copy_from_user(outbuf, (void *)arg + outtotal, taskout)) {
			err = -EFAULT;
			goto abort;
		}
	}

	if (taskin) {
		int intotal = tasksize + taskout;
		inbuf = kmalloc(taskin, GFP_KERNEL);
		if (inbuf == NULL) {
			err = -ENOMEM;
			goto abort;
		}
		memset(inbuf, 0, taskin);
		if (copy_from_user(inbuf, (void *)arg + intotal , taskin)) {
			err = -EFAULT;
			goto abort;
		}
	}

	memset(argsptr, 0, HDIO_DRIVE_TASK_HDR_SIZE);
	memset(hobsptr, 0, HDIO_DRIVE_HOB_HDR_SIZE);
	memcpy(argsptr, req_task->io_ports, HDIO_DRIVE_TASK_HDR_SIZE);
	memcpy(hobsptr, req_task->hob_ports, HDIO_DRIVE_HOB_HDR_SIZE);

	args.tf_in_flags  = req_task->in_flags;
	args.tf_out_flags = req_task->out_flags;
	args.data_phase   = req_task->data_phase;
	args.command_type = req_task->req_cmd;

#ifdef CONFIG_IDE_TASK_IOCTL_DEBUG
	DTF("%s: ide_ioctl_cmd %s:  ide_task_cmd %s\n",
		drive->name,
		ide_ioctl_verbose(cmd),
		ide_task_cmd_verbose(args.tfRegister[IDE_COMMAND_OFFSET]));
#endif /* CONFIG_IDE_TASK_IOCTL_DEBUG */

	switch(req_task->data_phase) {
		case TASKFILE_OUT_DMAQ:
		case TASKFILE_OUT_DMA:
			args.prehandler = NULL;
			args.handler = NULL;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, outbuf);
			break;
		case TASKFILE_IN_DMAQ:
		case TASKFILE_IN_DMA:
			args.prehandler = NULL;
			args.handler = NULL;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, inbuf);
			break;
		case TASKFILE_IN_OUT:
#if 0
			args.prehandler = &pre_task_out_intr;
			args.handler = &task_out_intr;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, outbuf);
			args.prehandler = NULL;
			args.handler = &task_in_intr;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, inbuf);
			break;
#else
			err = -EFAULT;
			goto abort;
#endif
		case TASKFILE_MULTI_OUT:
			if (drive->mult_count) {
				args.prehandler = &pre_task_out_intr;
				args.handler = &task_mulout_intr;
				args.posthandler = NULL;
				err = ide_raw_taskfile(drive, &args, outbuf);
			} else {
				/* (hs): give up if multcount is not set */
				printk("%s: %s Multimode Write " \
					"multcount is not set\n",
					 drive->name, __FUNCTION__);
				err = -EPERM;
				goto abort;
			}
			break;
		case TASKFILE_OUT:
			args.prehandler = &pre_task_out_intr;
			args.handler = &task_out_intr;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, outbuf);
			break;
		case TASKFILE_MULTI_IN:
			if (drive->mult_count) {
				args.prehandler = NULL;
				args.handler = &task_mulin_intr;
				args.posthandler = NULL;
				err = ide_raw_taskfile(drive, &args, inbuf);
			} else {
				/* (hs): give up if multcount is not set */
				printk("%s: %s Multimode Read failure " \
					"multcount is not set\n",
					drive->name, __FUNCTION__);
				err = -EPERM;
				goto abort;
			}
			break;
		case TASKFILE_IN:
			args.prehandler = NULL;
			args.handler = &task_in_intr;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, inbuf);
			break;
		case TASKFILE_NO_DATA:
			args.prehandler = NULL;
			args.handler = &task_no_data_intr;
			args.posthandler = NULL;
			err = ide_raw_taskfile(drive, &args, NULL);
			break;
		default:
			args.prehandler = NULL;
			args.handler = NULL;
			args.posthandler = NULL;
			err = -EFAULT;
			goto abort;
	}

	memcpy(req_task->io_ports, &(args.tfRegister), HDIO_DRIVE_TASK_HDR_SIZE);
	memcpy(req_task->hob_ports, &(args.hobRegister), HDIO_DRIVE_HOB_HDR_SIZE);
	req_task->in_flags  = args.tf_in_flags;
	req_task->out_flags = args.tf_out_flags;

	if (copy_to_user((void *)arg, req_task, tasksize)) {
		err = -EFAULT;
		goto abort;
	}
	if (taskout) {
		int outtotal = tasksize;
		if (copy_to_user((void *)arg+outtotal, outbuf, taskout)) {
			err = -EFAULT;
			goto abort;
		}
	}
	if (taskin) {
		int intotal = tasksize + taskout;
		if (copy_to_user((void *)arg+intotal, inbuf, taskin)) {
			err = -EFAULT;
			goto abort;
		}
	}
abort:
	kfree(req_task);
	if (outbuf != NULL)
		kfree(outbuf);
	if (inbuf != NULL)
		kfree(inbuf);
	return err;
}

EXPORT_SYMBOL(task_read_24);
EXPORT_SYMBOL(do_rw_taskfile);
EXPORT_SYMBOL(do_taskfile);
// EXPORT_SYMBOL(flagged_taskfile);

//EXPORT_SYMBOL(ide_end_taskfile);

EXPORT_SYMBOL(set_multmode_intr);
EXPORT_SYMBOL(set_geometry_intr);
EXPORT_SYMBOL(recal_intr);

EXPORT_SYMBOL(task_no_data_intr);
EXPORT_SYMBOL(task_in_intr);
EXPORT_SYMBOL(task_mulin_intr);
EXPORT_SYMBOL(pre_task_out_intr);
EXPORT_SYMBOL(task_out_intr);
EXPORT_SYMBOL(task_mulout_intr);

EXPORT_SYMBOL(ide_init_drive_taskfile);
EXPORT_SYMBOL(ide_wait_taskfile);
EXPORT_SYMBOL(ide_raw_taskfile);
EXPORT_SYMBOL(ide_pre_handler_parser);
EXPORT_SYMBOL(ide_handler_parser);
EXPORT_SYMBOL(ide_cmd_type_parser);
EXPORT_SYMBOL(ide_taskfile_ioctl);

#ifdef CONFIG_PKT_TASK_IOCTL

#if 0
{

{ /* start cdrom */

	struct cdrom_info *info = drive->driver_data;

	if (info->dma) {
		if (info->cmd == READ) {
			info->dma = !HWIF(drive)->dmaproc(ide_dma_read, drive);
		} else if (info->cmd == WRITE) {
			info->dma = !HWIF(drive)->dmaproc(ide_dma_write, drive);
		} else {
			printk("ide-cd: DMA set, but not allowed\n");
		}
	}

	/* Set up the controller registers. */
	OUT_BYTE (info->dma, IDE_FEATURE_REG);
	OUT_BYTE (0, IDE_NSECTOR_REG);
	OUT_BYTE (0, IDE_SECTOR_REG);

	OUT_BYTE (xferlen & 0xff, IDE_LCYL_REG);
	OUT_BYTE (xferlen >> 8  , IDE_HCYL_REG);
	if (IDE_CONTROL_REG)
		OUT_BYTE (drive->ctl, IDE_CONTROL_REG);

	if (info->dma)
		(void) (HWIF(drive)->dmaproc(ide_dma_begin, drive));

	if (CDROM_CONFIG_FLAGS (drive)->drq_interrupt) {
		ide_set_handler (drive, handler, WAIT_CMD, cdrom_timer_expiry);
		OUT_BYTE (WIN_PACKETCMD, IDE_COMMAND_REG); /* packet command */
		return ide_started;
	} else {
		OUT_BYTE (WIN_PACKETCMD, IDE_COMMAND_REG); /* packet command */
		return (*handler) (drive);
	}

} /* end cdrom */

{ /* start floppy */

	idefloppy_floppy_t *floppy = drive->driver_data;
	idefloppy_bcount_reg_t bcount;
	int dma_ok = 0;

	floppy->pc=pc;		/* Set the current packet command */

	pc->retries++;
	pc->actually_transferred=0; /* We haven't transferred any data yet */
	pc->current_position=pc->buffer;
	bcount.all = IDE_MIN(pc->request_transfer, 63 * 1024);

#ifdef CONFIG_BLK_DEV_IDEDMA
	if (test_and_clear_bit (PC_DMA_ERROR, &pc->flags)) {
		(void) HWIF(drive)->dmaproc(ide_dma_off, drive);
	}
	if (test_bit (PC_DMA_RECOMMENDED, &pc->flags) && drive->using_dma)
		dma_ok=!HWIF(drive)->dmaproc(test_bit (PC_WRITING, &pc->flags) ? ide_dma_write : ide_dma_read, drive);
#endif /* CONFIG_BLK_DEV_IDEDMA */

	if (IDE_CONTROL_REG)
		OUT_BYTE (drive->ctl,IDE_CONTROL_REG);
	OUT_BYTE (dma_ok ? 1:0,IDE_FEATURE_REG);	/* Use PIO/DMA */
	OUT_BYTE (bcount.b.high,IDE_BCOUNTH_REG);
	OUT_BYTE (bcount.b.low,IDE_BCOUNTL_REG);
	OUT_BYTE (drive->select.all,IDE_SELECT_REG);

#ifdef CONFIG_BLK_DEV_IDEDMA
	if (dma_ok) {	/* Begin DMA, if necessary */
		set_bit (PC_DMA_IN_PROGRESS, &pc->flags);
		(void) (HWIF(drive)->dmaproc(ide_dma_begin, drive));
	}
#endif /* CONFIG_BLK_DEV_IDEDMA */

} /* end floppy */

{ /* start tape */

	idetape_tape_t *tape = drive->driver_data;

#ifdef CONFIG_BLK_DEV_IDEDMA
	if (test_and_clear_bit (PC_DMA_ERROR, &pc->flags)) {
		printk (KERN_WARNING "ide-tape: DMA disabled, reverting to PIO\n");
		(void) HWIF(drive)->dmaproc(ide_dma_off, drive);
	}
	if (test_bit (PC_DMA_RECOMMENDED, &pc->flags) && drive->using_dma)
		dma_ok=!HWIF(drive)->dmaproc(test_bit (PC_WRITING, &pc->flags) ? ide_dma_write : ide_dma_read, drive);
#endif /* CONFIG_BLK_DEV_IDEDMA */

	if (IDE_CONTROL_REG)
		OUT_BYTE (drive->ctl,IDE_CONTROL_REG);
	OUT_BYTE (dma_ok ? 1:0,IDE_FEATURE_REG);	/* Use PIO/DMA */
	OUT_BYTE (bcount.b.high,IDE_BCOUNTH_REG);
	OUT_BYTE (bcount.b.low,IDE_BCOUNTL_REG);
	OUT_BYTE (drive->select.all,IDE_SELECT_REG);
#ifdef CONFIG_BLK_DEV_IDEDMA
	if (dma_ok) {	/* Begin DMA, if necessary */
		set_bit (PC_DMA_IN_PROGRESS, &pc->flags);
		(void) (HWIF(drive)->dmaproc(ide_dma_begin, drive));
	}
#endif /* CONFIG_BLK_DEV_IDEDMA */
	if (test_bit(IDETAPE_DRQ_INTERRUPT, &tape->flags)) {
		ide_set_handler(drive, &idetape_transfer_pc, IDETAPE_WAIT_CMD, NULL);
		OUT_BYTE(WIN_PACKETCMD, IDE_COMMAND_REG);
		return ide_started;
	} else {
		OUT_BYTE(WIN_PACKETCMD, IDE_COMMAND_REG);
		return idetape_transfer_pc(drive);
	}

} /* end tape */

}
#endif

int pkt_taskfile_ioctl (ide_drive_t *drive, struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
#if 0
	switch(req_task->data_phase) {
		case TASKFILE_P_OUT_DMAQ:
		case TASKFILE_P_IN_DMAQ:
		case TASKFILE_P_OUT_DMA:
		case TASKFILE_P_IN_DMA:
		case TASKFILE_P_OUT:
		case TASKFILE_P_IN:
	}
#endif
	return -ENOMSG;
}

EXPORT_SYMBOL(pkt_taskfile_ioctl);

#endif /* CONFIG_PKT_TASK_IOCTL */
