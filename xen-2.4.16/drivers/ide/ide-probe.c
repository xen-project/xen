/*
 *  linux/drivers/ide/ide-probe.c	Version 1.07	March 18, 2001
 *
 *  Copyright (C) 1994-1998  Linus Torvalds & authors (see below)
 */

/*
 *  Mostly written by Mark Lord <mlord@pobox.com>
 *                and Gadi Oxman <gadio@netvision.net.il>
 *                and Andre Hedrick <andre@linux-ide.org>
 *
 *  See linux/MAINTAINERS for address of current maintainer.
 *
 * This is the IDE probe module, as evolved from hd.c and ide.c.
 *
 * Version 1.00		move drive probing code from ide.c to ide-probe.c
 * Version 1.01		fix compilation problem for m68k
 * Version 1.02		increase WAIT_PIDENTIFY to avoid CD-ROM locking at boot
 *			 by Andrea Arcangeli
 * Version 1.03		fix for (hwif->chipset == ide_4drives)
 * Version 1.04		fixed buggy treatments of known flash memory cards
 *
 * Version 1.05		fix for (hwif->chipset == ide_pdc4030)
 *			added ide6/7/8/9
 *			allowed for secondary flash card to be detectable
 *			 with new flag : drive->ata_flash : 1;
 * Version 1.06		stream line request queue and prep for cascade project.
 * Version 1.07		max_sect <= 255; slower disks would get behind and
 * 			then fall over when they get to 256.	Paul G.
 */

#undef REALLY_SLOW_IO		/* most systems can safely undef this */

#include <xeno/config.h>
#include <xeno/module.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/timer.h>
#include <xeno/mm.h>
#include <xeno/interrupt.h>
#include <xeno/major.h>
#include <xeno/errno.h>
#include <xeno/genhd.h>
#include <xeno/slab.h>
#include <xeno/delay.h>
#include <xeno/ide.h>
#include <xeno/spinlock.h>

#include <asm/byteorder.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/io.h>

static inline void do_identify (ide_drive_t *drive, byte cmd)
{
	int bswap = 1;
	struct hd_driveid *id;

	id = drive->id = kmalloc (SECTOR_WORDS*4, GFP_ATOMIC);	/* called with interrupts disabled! */
	if (!id) {
		printk(KERN_WARNING "(ide-probe::do_identify) Out of memory.\n");
		goto err_kmalloc;
	}

	ide_input_data(drive, id, SECTOR_WORDS);		/* read 512 bytes of id info */
	ide__sti();	/* local CPU only */
	ide_fix_driveid(id);

	if (id->word156 == 0x4d42) {
		printk("%s: drive->id->word156 == 0x%04x \n", drive->name, drive->id->word156);
	}

	if (!drive->forced_lun)
		drive->last_lun = id->last_lun & 0x7;
#if defined (CONFIG_SCSI_EATA_DMA) || defined (CONFIG_SCSI_EATA_PIO) || defined (CONFIG_SCSI_EATA)
	/*
	 * EATA SCSI controllers do a hardware ATA emulation:
	 * Ignore them if there is a driver for them available.
	 */
	if ((id->model[0] == 'P' && id->model[1] == 'M')
	 || (id->model[0] == 'S' && id->model[1] == 'K')) {
		printk("%s: EATA SCSI HBA %.10s\n", drive->name, id->model);
		goto err_misc;
	}
#endif /* CONFIG_SCSI_EATA_DMA || CONFIG_SCSI_EATA_PIO */

	/*
	 *  WIN_IDENTIFY returns little-endian info,
	 *  WIN_PIDENTIFY *usually* returns little-endian info.
	 */
	if (cmd == WIN_PIDENTIFY) {
		if ((id->model[0] == 'N' && id->model[1] == 'E') /* NEC */
		 || (id->model[0] == 'F' && id->model[1] == 'X') /* Mitsumi */
		 || (id->model[0] == 'P' && id->model[1] == 'i'))/* Pioneer */
			bswap ^= 1;	/* Vertos drives may still be weird */
	}
	ide_fixstring (id->model,     sizeof(id->model),     bswap);
	ide_fixstring (id->fw_rev,    sizeof(id->fw_rev),    bswap);
	ide_fixstring (id->serial_no, sizeof(id->serial_no), bswap);

	if (strstr(id->model, "E X A B Y T E N E S T"))
		goto err_misc;

	id->model[sizeof(id->model)-1] = '\0';	/* we depend on this a lot! */
	printk("%s: %s, ", drive->name, id->model);
	drive->present = 1;

	/*
	 * Check for an ATAPI device
	 */
	if (cmd == WIN_PIDENTIFY) {
		byte type = (id->config >> 8) & 0x1f;
		printk("ATAPI ");
#ifdef CONFIG_BLK_DEV_PDC4030
		if (HWIF(drive)->channel == 1 && HWIF(drive)->chipset == ide_pdc4030) {
			printk(" -- not supported on 2nd Promise port\n");
			goto err_misc;
		}
#endif /* CONFIG_BLK_DEV_PDC4030 */
		switch (type) {
			case ide_floppy:
				if (!strstr(id->model, "CD-ROM")) {
					if (!strstr(id->model, "oppy") && !strstr(id->model, "poyp") && !strstr(id->model, "ZIP"))
						printk("cdrom or floppy?, assuming ");
					if (drive->media != ide_cdrom) {
						printk ("FLOPPY");
						break;
					}
				}
				type = ide_cdrom;	/* Early cdrom models used zero */
			case ide_cdrom:
				drive->removable = 1;
#ifdef CONFIG_PPC
				/* kludge for Apple PowerBook internal zip */
				if (!strstr(id->model, "CD-ROM") && strstr(id->model, "ZIP")) {
					printk ("FLOPPY");
					type = ide_floppy;
					break;
				}
#endif
				printk ("CD/DVD-ROM");
				break;
			case ide_tape:
				printk ("TAPE");
				break;
			case ide_optical:
				printk ("OPTICAL");
				drive->removable = 1;
				break;
			default:
				printk("UNKNOWN (type %d)", type);
				break;
		}
		printk (" drive\n");
		drive->media = type;
		return;
	}

	/*
	 * Not an ATAPI device: looks like a "regular" hard disk
	 */
	if (id->config & (1<<7))
		drive->removable = 1;
	/*
	 * Prevent long system lockup probing later for non-existant
	 * slave drive if the hwif is actually a flash memory card of some variety:
	 */
	if (drive_is_flashcard(drive)) {
		ide_drive_t *mate = &HWIF(drive)->drives[1^drive->select.b.unit];
		if (!mate->ata_flash) {
			mate->present = 0;
			mate->noprobe = 1;
		}
	}
	drive->media = ide_disk;
	printk("ATA DISK drive\n");
	QUIRK_LIST(HWIF(drive),drive);
	return;

err_misc:
	kfree(id);
err_kmalloc:
	drive->present = 0;
	return;
}

/*
 * try_to_identify() sends an ATA(PI) IDENTIFY request to a drive
 * and waits for a response.  It also monitors irqs while this is
 * happening, in hope of automatically determining which one is
 * being used by the interface.
 *
 * Returns:	0  device was identified
 *		1  device timed-out (no response to identify request)
 *		2  device aborted the command (refused to identify itself)
 */
static int actual_try_to_identify (ide_drive_t *drive, byte cmd)
{
	int rc;
	ide_ioreg_t hd_status;
	unsigned long timeout;
	byte s, a;

	if (IDE_CONTROL_REG) {
		/* take a deep breath */
		ide_delay_50ms();
		a = IN_BYTE(IDE_ALTSTATUS_REG);
		s = IN_BYTE(IDE_STATUS_REG);
		if ((a ^ s) & ~INDEX_STAT) {
			printk("%s: probing with STATUS(0x%02x) instead of ALTSTATUS(0x%02x)\n", drive->name, s, a);
			hd_status = IDE_STATUS_REG;	/* ancient Seagate drives, broken interfaces */
		} else {
			hd_status = IDE_ALTSTATUS_REG;	/* use non-intrusive polling */
		}
	} else {
		ide_delay_50ms();
		hd_status = IDE_STATUS_REG;
	}

	/* set features register for atapi identify command to be sure of reply */
	if ((cmd == WIN_PIDENTIFY))
		OUT_BYTE(0,IDE_FEATURE_REG);	/* disable dma & overlap */

#if CONFIG_BLK_DEV_PDC4030
	if (HWIF(drive)->chipset == ide_pdc4030) {
		/* DC4030 hosted drives need their own identify... */
		extern int pdc4030_identify(ide_drive_t *);
		if (pdc4030_identify(drive)) {
			return 1;
		}
	} else
#endif /* CONFIG_BLK_DEV_PDC4030 */
		OUT_BYTE(cmd,IDE_COMMAND_REG);		/* ask drive for ID */
	timeout = ((cmd == WIN_IDENTIFY) ? WAIT_WORSTCASE : WAIT_PIDENTIFY) / 2;
	timeout += jiffies;
	do {
		if (0 < (signed long)(jiffies - timeout)) {
			return 1;	/* drive timed-out */
		}
		ide_delay_50ms();		/* give drive a breather */
	} while (IN_BYTE(hd_status) & BUSY_STAT);

	ide_delay_50ms();		/* wait for IRQ and DRQ_STAT */
	if (OK_STAT(GET_STAT(),DRQ_STAT,BAD_R_STAT)) {
		unsigned long flags;
		__save_flags(flags);	/* local CPU only */
		__cli();		/* local CPU only; some systems need this */
		do_identify(drive, cmd); /* drive returned ID */
		rc = 0;			/* drive responded with ID */
		(void) GET_STAT();	/* clear drive IRQ */
		__restore_flags(flags);	/* local CPU only */
	} else
		rc = 2;			/* drive refused ID */
	return rc;
}

static int try_to_identify (ide_drive_t *drive, byte cmd)
{
	int retval;
	int autoprobe = 0;
	unsigned long cookie = 0;

	if (IDE_CONTROL_REG && !HWIF(drive)->irq) {
		autoprobe = 1;
		cookie = probe_irq_on();
		OUT_BYTE(drive->ctl,IDE_CONTROL_REG);	/* enable device irq */
	}

	retval = actual_try_to_identify(drive, cmd);

	if (autoprobe) {
		int irq;
		OUT_BYTE(drive->ctl|2,IDE_CONTROL_REG);	/* mask device irq */
		(void) GET_STAT();			/* clear drive IRQ */
		udelay(5);
		irq = probe_irq_off(cookie);
		if (!HWIF(drive)->irq) {
			if (irq > 0) {
				HWIF(drive)->irq = irq;
			} else {	/* Mmmm.. multiple IRQs.. don't know which was ours */
				printk("%s: IRQ probe failed (0x%lx)\n", drive->name, cookie);
#ifdef CONFIG_BLK_DEV_CMD640
#ifdef CMD640_DUMP_REGS
				if (HWIF(drive)->chipset == ide_cmd640) {
					printk("%s: Hmmm.. probably a driver problem.\n", drive->name);
					CMD640_DUMP_REGS;
				}
#endif /* CMD640_DUMP_REGS */
#endif /* CONFIG_BLK_DEV_CMD640 */
			}
		}
	}
	return retval;
}


/*
 * do_probe() has the difficult job of finding a drive if it exists,
 * without getting hung up if it doesn't exist, without trampling on
 * ethernet cards, and without leaving any IRQs dangling to haunt us later.
 *
 * If a drive is "known" to exist (from CMOS or kernel parameters),
 * but does not respond right away, the probe will "hang in there"
 * for the maximum wait time (about 30 seconds), otherwise it will
 * exit much more quickly.
 *
 * Returns:	0  device was identified
 *		1  device timed-out (no response to identify request)
 *		2  device aborted the command (refused to identify itself)
 *		3  bad status from device (possible for ATAPI drives)
 *		4  probe was not attempted because failure was obvious
 */
static int do_probe (ide_drive_t *drive, byte cmd)
{
	int rc;
	ide_hwif_t *hwif = HWIF(drive);
	if (drive->present) {	/* avoid waiting for inappropriate probes */
		if ((drive->media != ide_disk) && (cmd == WIN_IDENTIFY))
			return 4;
	}
#ifdef DEBUG
	printk("probing for %s: present=%d, media=%d, probetype=%s\n",
		drive->name, drive->present, drive->media,
		(cmd == WIN_IDENTIFY) ? "ATA" : "ATAPI");
#endif
	ide_delay_50ms();	/* needed for some systems (e.g. crw9624 as drive0 with disk as slave) */
	SELECT_DRIVE(hwif,drive);
	ide_delay_50ms();
	if (IN_BYTE(IDE_SELECT_REG) != drive->select.all && !drive->present) {
		if (drive->select.b.unit != 0) {
			SELECT_DRIVE(hwif,&hwif->drives[0]);	/* exit with drive0 selected */
			ide_delay_50ms();		/* allow BUSY_STAT to assert & clear */
		}
		return 3;    /* no i/f present: mmm.. this should be a 4 -ml */
	}

	if (OK_STAT(GET_STAT(),READY_STAT,BUSY_STAT)
	 || drive->present || cmd == WIN_PIDENTIFY)
	{
		if ((rc = try_to_identify(drive,cmd)))   /* send cmd and wait */
			rc = try_to_identify(drive,cmd); /* failed: try again */
		if (rc == 1 && cmd == WIN_PIDENTIFY && drive->autotune != 2) {
			unsigned long timeout;
			printk("%s: no response (status = 0x%02x), resetting drive\n", drive->name, GET_STAT());
			ide_delay_50ms();
			OUT_BYTE (drive->select.all, IDE_SELECT_REG);
			ide_delay_50ms();
			OUT_BYTE(WIN_SRST, IDE_COMMAND_REG);
			timeout = jiffies;
			while ((GET_STAT() & BUSY_STAT) && time_before(jiffies, timeout + WAIT_WORSTCASE))
				ide_delay_50ms();
			rc = try_to_identify(drive, cmd);
		}
		if (rc == 1)
			printk("%s: no response (status = 0x%02x)\n", drive->name, GET_STAT());
		(void) GET_STAT();		/* ensure drive irq is clear */
	} else {
		rc = 3;				/* not present or maybe ATAPI */
	}
	if (drive->select.b.unit != 0) {
		SELECT_DRIVE(hwif,&hwif->drives[0]);	/* exit with drive0 selected */
		ide_delay_50ms();
		(void) GET_STAT();		/* ensure drive irq is clear */
	}
	return rc;
}

/*
 *
 */
static void enable_nest (ide_drive_t *drive)
{
	unsigned long timeout;

	printk("%s: enabling %s -- ", HWIF(drive)->name, drive->id->model);
	SELECT_DRIVE(HWIF(drive), drive);
	ide_delay_50ms();
	OUT_BYTE(EXABYTE_ENABLE_NEST, IDE_COMMAND_REG);
	timeout = jiffies + WAIT_WORSTCASE;
	do {
		if (time_after(jiffies, timeout)) {
			printk("failed (timeout)\n");
			return;
		}
		ide_delay_50ms();
	} while (GET_STAT() & BUSY_STAT);
	ide_delay_50ms();
	if (!OK_STAT(GET_STAT(), 0, BAD_STAT))
		printk("failed (status = 0x%02x)\n", GET_STAT());
	else
		printk("success\n");
	if (do_probe(drive, WIN_IDENTIFY) >= 2) {	/* if !(success||timed-out) */
		(void) do_probe(drive, WIN_PIDENTIFY);	/* look for ATAPI device */
	}
}

/*
 * probe_for_drive() tests for existence of a given drive using do_probe().
 *
 * Returns:	0  no device was found
 *		1  device was found (note: drive->present might still be 0)
 */
static inline byte probe_for_drive (ide_drive_t *drive)
{
	if (drive->noprobe)			/* skip probing? */
		return drive->present;
	if (do_probe(drive, WIN_IDENTIFY) >= 2) { /* if !(success||timed-out) */
		(void) do_probe(drive, WIN_PIDENTIFY); /* look for ATAPI device */
	}
	if (drive->id && strstr(drive->id->model, "E X A B Y T E N E S T"))
		enable_nest(drive);
	if (!drive->present)
		return 0;			/* drive not found */
	if (drive->id == NULL) {		/* identification failed? */
		if (drive->media == ide_disk) {
			printk ("%s: non-IDE drive, CHS=%d/%d/%d\n",
			 drive->name, drive->cyl, drive->head, drive->sect);
		} else if (drive->media == ide_cdrom) {
			printk("%s: ATAPI cdrom (?)\n", drive->name);
		} else {
			drive->present = 0;	/* nuke it */
		}
	}
	return 1;	/* drive was found */
}

/*
 * Calculate the region that this interface occupies,
 * handling interfaces where the registers may not be
 * ordered sanely.  We deal with the CONTROL register
 * separately.
 */
static int hwif_check_regions (ide_hwif_t *hwif)
{
	int region_errors = 0;

	hwif->straight8 = 0;
	region_errors  = ide_check_region(hwif->io_ports[IDE_DATA_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_ERROR_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_NSECTOR_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_SECTOR_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_LCYL_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_HCYL_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_SELECT_OFFSET], 1);
	region_errors += ide_check_region(hwif->io_ports[IDE_STATUS_OFFSET], 1);

	if (hwif->io_ports[IDE_CONTROL_OFFSET])
		region_errors += ide_check_region(hwif->io_ports[IDE_CONTROL_OFFSET], 1);
#if defined(CONFIG_AMIGA) || defined(CONFIG_MAC)
	if (hwif->io_ports[IDE_IRQ_OFFSET])
		region_errors += ide_check_region(hwif->io_ports[IDE_IRQ_OFFSET], 1);
#endif /* (CONFIG_AMIGA) || (CONFIG_MAC) */
	/*
	 * If any errors are return, we drop the hwif interface.
	 */
	return(region_errors);
}

static void hwif_register (ide_hwif_t *hwif)
{
	if (((unsigned long)hwif->io_ports[IDE_DATA_OFFSET] | 7) ==
	    ((unsigned long)hwif->io_ports[IDE_STATUS_OFFSET])) {
		ide_request_region(hwif->io_ports[IDE_DATA_OFFSET], 8, hwif->name);
		hwif->straight8 = 1;
		goto jump_straight8;
	}

	if (hwif->io_ports[IDE_DATA_OFFSET])
		ide_request_region(hwif->io_ports[IDE_DATA_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_ERROR_OFFSET])
		ide_request_region(hwif->io_ports[IDE_ERROR_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_NSECTOR_OFFSET])
		ide_request_region(hwif->io_ports[IDE_NSECTOR_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_SECTOR_OFFSET])
		ide_request_region(hwif->io_ports[IDE_SECTOR_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_LCYL_OFFSET])
		ide_request_region(hwif->io_ports[IDE_LCYL_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_HCYL_OFFSET])
		ide_request_region(hwif->io_ports[IDE_HCYL_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_SELECT_OFFSET])
		ide_request_region(hwif->io_ports[IDE_SELECT_OFFSET], 1, hwif->name);
	if (hwif->io_ports[IDE_STATUS_OFFSET])
		ide_request_region(hwif->io_ports[IDE_STATUS_OFFSET], 1, hwif->name);

jump_straight8:
	if (hwif->io_ports[IDE_CONTROL_OFFSET])
		ide_request_region(hwif->io_ports[IDE_CONTROL_OFFSET], 1, hwif->name);
#if defined(CONFIG_AMIGA) || defined(CONFIG_MAC)
	if (hwif->io_ports[IDE_IRQ_OFFSET])
		ide_request_region(hwif->io_ports[IDE_IRQ_OFFSET], 1, hwif->name);
#endif /* (CONFIG_AMIGA) || (CONFIG_MAC) */
}

/*
 * This routine only knows how to look for drive units 0 and 1
 * on an interface, so any setting of MAX_DRIVES > 2 won't work here.
 */
static void probe_hwif (ide_hwif_t *hwif)
{
	unsigned int unit;
	unsigned long flags;

	if (hwif->noprobe)
		return;
#ifdef CONFIG_BLK_DEV_IDE
	if (hwif->io_ports[IDE_DATA_OFFSET] == HD_DATA) {
		extern void probe_cmos_for_drives(ide_hwif_t *);

		probe_cmos_for_drives (hwif);
	}
#endif

	if ((hwif->chipset != ide_4drives || !hwif->mate->present) &&
#if CONFIG_BLK_DEV_PDC4030
	    (hwif->chipset != ide_pdc4030 || hwif->channel == 0) &&
#endif /* CONFIG_BLK_DEV_PDC4030 */
	    (hwif_check_regions(hwif))) {
		int msgout = 0;
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			ide_drive_t *drive = &hwif->drives[unit];
			if (drive->present) {
				drive->present = 0;
				printk("%s: ERROR, PORTS ALREADY IN USE\n", drive->name);
				msgout = 1;
			}
		}
		if (!msgout)
			printk("%s: ports already in use, skipping probe\n", hwif->name);
		return;	
	}

	__save_flags(flags);	/* local CPU only */
	__sti();		/* local CPU only; needed for jiffies and irq probing */
	/*
	 * Second drive should only exist if first drive was found,
	 * but a lot of cdrom drives are configured as single slaves.
	 */
	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		ide_drive_t *drive = &hwif->drives[unit];
		(void) probe_for_drive (drive);
		if (drive->present && !hwif->present) {
			hwif->present = 1;
			if (hwif->chipset != ide_4drives || !hwif->mate->present) {
				hwif_register(hwif);
			}
		}
	}
	if (hwif->io_ports[IDE_CONTROL_OFFSET] && hwif->reset) {
		unsigned long timeout = jiffies + WAIT_WORSTCASE;
		byte stat;

		printk("%s: reset\n", hwif->name);
		OUT_BYTE(12, hwif->io_ports[IDE_CONTROL_OFFSET]);
		udelay(10);
		OUT_BYTE(8, hwif->io_ports[IDE_CONTROL_OFFSET]);
		do {
			ide_delay_50ms();
			stat = IN_BYTE(hwif->io_ports[IDE_STATUS_OFFSET]);
		} while ((stat & BUSY_STAT) && 0 < (signed long)(timeout - jiffies));

	}
	__restore_flags(flags);	/* local CPU only */
	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		ide_drive_t *drive = &hwif->drives[unit];
		if (drive->present) {
			ide_tuneproc_t *tuneproc = HWIF(drive)->tuneproc;
			if (tuneproc != NULL && drive->autotune == 1)
				tuneproc(drive, 255);	/* auto-tune PIO mode */
		}
	}
}

#if MAX_HWIFS > 1
/*
 * save_match() is used to simplify logic in init_irq() below.
 *
 * A loophole here is that we may not know about a particular
 * hwif's irq until after that hwif is actually probed/initialized..
 * This could be a problem for the case where an hwif is on a
 * dual interface that requires serialization (eg. cmd640) and another
 * hwif using one of the same irqs is initialized beforehand.
 *
 * This routine detects and reports such situations, but does not fix them.
 */
static void save_match (ide_hwif_t *hwif, ide_hwif_t *new, ide_hwif_t **match)
{
	ide_hwif_t *m = *match;

	if (m && m->hwgroup && m->hwgroup != new->hwgroup) {
		if (!new->hwgroup)
			return;
		printk("%s: potential irq problem with %s and %s\n", hwif->name, new->name, m->name);
	}
	if (!m || m->irq != hwif->irq) /* don't undo a prior perfect match */
		*match = new;
}
#endif /* MAX_HWIFS > 1 */

/*
 * init request queue
 */
static void ide_init_queue(ide_drive_t *drive)
{
	request_queue_t *q = &drive->queue;

	q->queuedata = HWGROUP(drive);
	blk_init_queue(q, do_ide_request);

	if (drive->media == ide_disk) {
#ifdef CONFIG_BLK_DEV_ELEVATOR_NOOP
		elevator_init(&q->elevator, ELEVATOR_NOOP);
#endif
	}
}

/*
 * This routine sets up the irq for an ide interface, and creates a new
 * hwgroup for the irq/hwif if none was previously assigned.
 *
 * Much of the code is for correctly detecting/handling irq sharing
 * and irq serialization situations.  This is somewhat complex because
 * it handles static as well as dynamic (PCMCIA) IDE interfaces.
 *
 * The SA_INTERRUPT in sa_flags means ide_intr() is always entered with
 * interrupts completely disabled.  This can be bad for interrupt latency,
 * but anything else has led to problems on some machines.  We re-enable
 * interrupts as much as we can safely do in most places.
 */
static int init_irq (ide_hwif_t *hwif)
{
	unsigned long flags;
	unsigned int index;
	ide_hwgroup_t *hwgroup, *new_hwgroup;
	ide_hwif_t *match = NULL;

	
	/* Allocate the buffer and potentially sleep first */
	
	new_hwgroup = kmalloc(sizeof(ide_hwgroup_t),GFP_KERNEL);
	
	save_flags(flags);	/* all CPUs */
	cli();			/* all CPUs */

	hwif->hwgroup = NULL;
#if MAX_HWIFS > 1
	/*
	 * Group up with any other hwifs that share our irq(s).
	 */
	for (index = 0; index < MAX_HWIFS; index++) {
		ide_hwif_t *h = &ide_hwifs[index];
		if (h->hwgroup) {  /* scan only initialized hwif's */
			if (hwif->irq == h->irq) {
				hwif->sharing_irq = h->sharing_irq = 1;
				if (hwif->chipset != ide_pci || h->chipset != ide_pci) {
					save_match(hwif, h, &match);
				}
			}
			if (hwif->serialized) {
				if (hwif->mate && hwif->mate->irq == h->irq)
					save_match(hwif, h, &match);
			}
			if (h->serialized) {
				if (h->mate && hwif->irq == h->mate->irq)
					save_match(hwif, h, &match);
			}
		}
	}
#endif /* MAX_HWIFS > 1 */
	/*
	 * If we are still without a hwgroup, then form a new one
	 */
	if (match) {
		hwgroup = match->hwgroup;
		if(new_hwgroup)
			kfree(new_hwgroup);
	} else {
		hwgroup = new_hwgroup;
		if (!hwgroup) {
			restore_flags(flags);	/* all CPUs */
			return 1;
		}
		memset(hwgroup, 0, sizeof(ide_hwgroup_t));
		hwgroup->hwif     = hwif->next = hwif;
		hwgroup->rq       = NULL;
		hwgroup->handler  = NULL;
		hwgroup->drive    = NULL;
		hwgroup->busy     = 0;
		init_timer(&hwgroup->timer);
		hwgroup->timer.function = &ide_timer_expiry;
		hwgroup->timer.data = (unsigned long) hwgroup;
	}

	/*
	 * Allocate the irq, if not already obtained for another hwif
	 */
	if (!match || match->irq != hwif->irq) {
#ifdef CONFIG_IDEPCI_SHARE_IRQ
		int sa = IDE_CHIPSET_IS_PCI(hwif->chipset) ? SA_SHIRQ : SA_INTERRUPT;
#else /* !CONFIG_IDEPCI_SHARE_IRQ */
		int sa = IDE_CHIPSET_IS_PCI(hwif->chipset) ? SA_INTERRUPT|SA_SHIRQ : SA_INTERRUPT;
#endif /* CONFIG_IDEPCI_SHARE_IRQ */

		if (hwif->io_ports[IDE_CONTROL_OFFSET])
			OUT_BYTE(0x08, hwif->io_ports[IDE_CONTROL_OFFSET]); /* clear nIEN */

		if (ide_request_irq(hwif->irq, &ide_intr, sa, hwif->name, hwgroup)) {
			if (!match)
				kfree(hwgroup);
			restore_flags(flags);	/* all CPUs */
			return 1;
		}
	}

	/*
	 * Everything is okay, so link us into the hwgroup
	 */
	hwif->hwgroup = hwgroup;
	hwif->next = hwgroup->hwif->next;
	hwgroup->hwif->next = hwif;

	for (index = 0; index < MAX_DRIVES; ++index) {
		ide_drive_t *drive = &hwif->drives[index];
		if (!drive->present)
			continue;
		if (!hwgroup->drive)
			hwgroup->drive = drive;
		drive->next = hwgroup->drive->next;
		hwgroup->drive->next = drive;
		ide_init_queue(drive);
	}
	if (!hwgroup->hwif) {
		hwgroup->hwif = HWIF(hwgroup->drive);
#ifdef DEBUG
		printk("%s : Adding missed hwif to hwgroup!!\n", hwif->name);
#endif
	}
	restore_flags(flags);	/* all CPUs; safe now that hwif->hwgroup is set up */

#if !defined(__mc68000__) && !defined(CONFIG_APUS) && !defined(__sparc__)
	printk("%s at 0x%03x-0x%03x,0x%03x on irq %d", hwif->name,
		hwif->io_ports[IDE_DATA_OFFSET],
		hwif->io_ports[IDE_DATA_OFFSET]+7,
		hwif->io_ports[IDE_CONTROL_OFFSET], hwif->irq);
#elif defined(__sparc__)
	printk("%s at 0x%03lx-0x%03lx,0x%03lx on irq %s", hwif->name,
		hwif->io_ports[IDE_DATA_OFFSET],
		hwif->io_ports[IDE_DATA_OFFSET]+7,
		hwif->io_ports[IDE_CONTROL_OFFSET], __irq_itoa(hwif->irq));
#else
	printk("%s at %p on irq 0x%08x", hwif->name,
		hwif->io_ports[IDE_DATA_OFFSET], hwif->irq);
#endif /* __mc68000__ && CONFIG_APUS */
	if (match)
		printk(" (%sed with %s)",
			hwif->sharing_irq ? "shar" : "serializ", match->name);
	printk("\n");
	return 0;
}

/*
 * init_gendisk() (as opposed to ide_geninit) is called for each major device,
 * after probing for drives, to allocate partition tables and other data
 * structures needed for the routines in genhd.c.  ide_geninit() gets called
 * somewhat later, during the partition check.
 */
static void init_gendisk (ide_hwif_t *hwif)
{
	struct gendisk *gd;
	unsigned int unit, units, minors;
	int *bs, *max_sect; /* , *max_ra; */
#ifdef DEVFS_MUST_DIE
	extern devfs_handle_t ide_devfs_handle;
#endif

#if 1
	units = MAX_DRIVES;
#else
	/* figure out maximum drive number on the interface */
	for (units = MAX_DRIVES; units > 0; --units) {
		if (hwif->drives[units-1].present)
			break;
	}
#endif

	minors    = units * (1<<PARTN_BITS);
	gd        = kmalloc (sizeof(struct gendisk), GFP_KERNEL);
	if (!gd)
		goto err_kmalloc_gd;
	gd->sizes = kmalloc (minors * sizeof(int), GFP_KERNEL);
	if (!gd->sizes)
		goto err_kmalloc_gd_sizes;
	gd->part  = kmalloc (minors * sizeof(struct hd_struct), GFP_KERNEL);
	if (!gd->part)
		goto err_kmalloc_gd_part;
	bs        = kmalloc (minors*sizeof(int), GFP_KERNEL);
	if (!bs)
		goto err_kmalloc_bs;
	max_sect  = kmalloc (minors*sizeof(int), GFP_KERNEL);
	if (!max_sect)
		goto err_kmalloc_max_sect;
#if 0
	max_ra    = kmalloc (minors*sizeof(int), GFP_KERNEL);
	if (!max_ra)
		goto err_kmalloc_max_ra;
#endif

	memset(gd->part, 0, minors * sizeof(struct hd_struct));

	/* cdroms and msdos f/s are examples of non-1024 blocksizes */
	blksize_size[hwif->major] = bs;
	max_sectors[hwif->major] = max_sect;
	/*max_readahead[hwif->major] = max_ra;*/
	for (unit = 0; unit < minors; ++unit) {
		*bs++ = BLOCK_SIZE;
		/*
		 * IDE can do up to 128K per request == 256
		 */
		*max_sect++ = ((hwif->chipset == ide_pdc4030) ? 127 : 128);
		/* *max_ra++ = vm_max_readahead; */
	}

	for (unit = 0; unit < units; ++unit)
		hwif->drives[unit].part = &gd->part[unit << PARTN_BITS];

	gd->major	= hwif->major;		/* our major device number */
	gd->major_name	= IDE_MAJOR_NAME;	/* treated special in genhd.c */
	gd->minor_shift	= PARTN_BITS;		/* num bits for partitions */
	gd->max_p	= 1<<PARTN_BITS;	/* 1 + max partitions / drive */
	gd->nr_real	= units;		/* current num real drives */
	gd->real_devices= hwif;			/* ptr to internal data */
	gd->next	= NULL;			/* linked list of major devs */
	gd->fops        = ide_fops;             /* file operations */
	gd->flags	= kmalloc (sizeof *gd->flags * units, GFP_KERNEL);
	if (gd->flags)
		memset (gd->flags, 0, sizeof *gd->flags * units);
#ifdef DEVFS_MUST_DIE
	gd->de_arr	= kmalloc (sizeof *gd->de_arr * units, GFP_KERNEL);
	if (gd->de_arr)
		memset (gd->de_arr, 0, sizeof *gd->de_arr * units);
#endif

	hwif->gd = gd;
	add_gendisk(gd);

	for (unit = 0; unit < units; ++unit) {
#if 1
		char name[64];
		ide_add_generic_settings(hwif->drives + unit);
		hwif->drives[unit].dn = ((hwif->channel ? 2 : 0) + unit);
		sprintf (name, "host%d/bus%d/target%d/lun%d",
			(hwif->channel && hwif->mate) ?
			hwif->mate->index : hwif->index,
			hwif->channel, unit, hwif->drives[unit].lun);
#ifdef DEVFS_MUST_DIE
		if (hwif->drives[unit].present)
			hwif->drives[unit].de = devfs_mk_dir(ide_devfs_handle, name, NULL);
#endif
#else
		if (hwif->drives[unit].present) {
			char name[64];

			ide_add_generic_settings(hwif->drives + unit);
			hwif->drives[unit].dn = ((hwif->channel ? 2 : 0) + unit);
			sprintf (name, "host%d/bus%d/target%d/lun%d",
				 (hwif->channel && hwif->mate) ? hwif->mate->index : hwif->index,
				 hwif->channel, unit, hwif->drives[unit].lun);
			hwif->drives[unit].de =
				devfs_mk_dir (ide_devfs_handle, name, NULL);
		}
#endif
	}
	return;

#if 0
err_kmalloc_max_ra:
	kfree(max_sect);
#endif
err_kmalloc_max_sect:
	kfree(bs);
err_kmalloc_bs:
	kfree(gd->part);
err_kmalloc_gd_part:
	kfree(gd->sizes);
err_kmalloc_gd_sizes:
	kfree(gd);
err_kmalloc_gd:
	printk(KERN_WARNING "(ide::init_gendisk) Out of memory\n");
	return;
}

static int hwif_init (ide_hwif_t *hwif)
{
	if (!hwif->present)
		return 0;
	if (!hwif->irq) {
		if (!(hwif->irq = ide_default_irq(hwif->io_ports[IDE_DATA_OFFSET])))
		{
			printk("%s: DISABLED, NO IRQ\n", hwif->name);
			return (hwif->present = 0);
		}
	}
#ifdef CONFIG_BLK_DEV_HD
	if (hwif->irq == HD_IRQ && hwif->io_ports[IDE_DATA_OFFSET] != HD_DATA) {
		printk("%s: CANNOT SHARE IRQ WITH OLD HARDDISK DRIVER (hd.c)\n", hwif->name);
		return (hwif->present = 0);
	}
#endif /* CONFIG_BLK_DEV_HD */
	
	hwif->present = 0; /* we set it back to 1 if all is ok below */

#ifdef DEVFS_MUST_DIE
	if (devfs_register_blkdev (hwif->major, hwif->name, ide_fops)) {
		printk("%s: UNABLE TO GET MAJOR NUMBER %d\n", hwif->name, hwif->major);
		return (hwif->present = 0);
	}
#endif	

	if (init_irq(hwif)) {
		int i = hwif->irq;
		/*
		 *	It failed to initialise. Find the default IRQ for 
		 *	this port and try that.
		 */
		if (!(hwif->irq = ide_default_irq(hwif->io_ports[IDE_DATA_OFFSET]))) {
			printk("%s: Disabled unable to get IRQ %d.\n", hwif->name, i);
			(void) unregister_blkdev (hwif->major, hwif->name);
			return (hwif->present = 0);
		}
		if (init_irq(hwif)) {
			printk("%s: probed IRQ %d and default IRQ %d failed.\n",
				hwif->name, i, hwif->irq);
			(void) unregister_blkdev (hwif->major, hwif->name);
			return (hwif->present = 0);
		}
		printk("%s: probed IRQ %d failed, using default.\n",
			hwif->name, hwif->irq);
	}
	
	init_gendisk(hwif);
	blk_dev[hwif->major].data = hwif;
	blk_dev[hwif->major].queue = ide_get_queue;
#if 0
	read_ahead[hwif->major] = 8;	/* (4kB) */
#endif
	hwif->present = 1;	/* success */

#if (DEBUG_SPINLOCK > 0)
{
	static int done = 0;
	if (!done++)
		printk("io_request_lock is %p\n", &io_request_lock);    /* FIXME */
}
#endif
	return hwif->present;
}

void export_ide_init_queue (ide_drive_t *drive)
{
	ide_init_queue(drive);
}

byte export_probe_for_drive (ide_drive_t *drive)
{
	return probe_for_drive(drive);
}

EXPORT_SYMBOL(export_ide_init_queue);
EXPORT_SYMBOL(export_probe_for_drive);

int ideprobe_init (void);
static ide_module_t ideprobe_module = {
	IDE_PROBE_MODULE,
	ideprobe_init,
	NULL
};

int ideprobe_init (void)
{
	unsigned int index;
	int probe[MAX_HWIFS];
	
	MOD_INC_USE_COUNT;
	memset(probe, 0, MAX_HWIFS * sizeof(int));
	for (index = 0; index < MAX_HWIFS; ++index)
		probe[index] = !ide_hwifs[index].present;

	/*
	 * Probe for drives in the usual way.. CMOS/BIOS, then poke at ports
	 */
	for (index = 0; index < MAX_HWIFS; ++index)
		if (probe[index])
			probe_hwif(&ide_hwifs[index]);
	for (index = 0; index < MAX_HWIFS; ++index)
		if (probe[index])
			hwif_init(&ide_hwifs[index]);
	if (!ide_probe)
		ide_probe = &ideprobe_module;
	MOD_DEC_USE_COUNT;
	return 0;
}

#ifdef MODULE
extern int (*ide_xlate_1024_hook)(kdev_t, int, int, const char *);

int init_module (void)
{
	unsigned int index;
	
	for (index = 0; index < MAX_HWIFS; ++index)
		ide_unregister(index);
	ideprobe_init();
	create_proc_ide_interfaces();
	ide_xlate_1024_hook = ide_xlate_1024;
	return 0;
}

void cleanup_module (void)
{
	ide_probe = NULL;
	ide_xlate_1024_hook = 0;
}
MODULE_LICENSE("GPL");
#endif /* MODULE */
