/*
 *  linux/drivers/ide/ide.c		Version 6.31	June 9, 2000
 *
 *  Copyright (C) 1994-1998  Linus Torvalds & authors (see below)
 */

/*
 *  Mostly written by Mark Lord  <mlord@pobox.com>
 *                and Gadi Oxman <gadio@netvision.net.il>
 *                and Andre Hedrick <andre@linux-ide.org>
 *
 *  See linux/MAINTAINERS for address of current maintainer.
 *
 * This is the multiple IDE interface driver, as evolved from hd.c.
 * It supports up to MAX_HWIFS IDE interfaces, on one or more IRQs (usually 14 & 15).
 * There can be up to two drives per interface, as per the ATA-2 spec.
 *
 * Primary:    ide0, port 0x1f0; major=3;  hda is minor=0; hdb is minor=64
 * Secondary:  ide1, port 0x170; major=22; hdc is minor=0; hdd is minor=64
 * Tertiary:   ide2, port 0x???; major=33; hde is minor=0; hdf is minor=64
 * Quaternary: ide3, port 0x???; major=34; hdg is minor=0; hdh is minor=64
 * ...
 *
 *  From hd.c:
 *  |
 *  | It traverses the request-list, using interrupts to jump between functions.
 *  | As nearly all functions can be called within interrupts, we may not sleep.
 *  | Special care is recommended.  Have Fun!
 *  |
 *  | modified by Drew Eckhardt to check nr of hd's from the CMOS.
 *  |
 *  | Thanks to Branko Lankester, lankeste@fwi.uva.nl, who found a bug
 *  | in the early extended-partition checks and added DM partitions.
 *  |
 *  | Early work on error handling by Mika Liljeberg (liljeber@cs.Helsinki.FI).
 *  |
 *  | IRQ-unmask, drive-id, multiple-mode, support for ">16 heads",
 *  | and general streamlining by Mark Lord (mlord@pobox.com).
 *
 *  October, 1994 -- Complete line-by-line overhaul for linux 1.1.x, by:
 *
 *	Mark Lord	(mlord@pobox.com)		(IDE Perf.Pkg)
 *	Delman Lee	(delman@ieee.org)		("Mr. atdisk2")
 *	Scott Snyder	(snyder@fnald0.fnal.gov)	(ATAPI IDE cd-rom)
 *
 *  This was a rewrite of just about everything from hd.c, though some original
 *  code is still sprinkled about.  Think of it as a major evolution, with
 *  inspiration from lots of linux users, esp.  hamish@zot.apana.org.au
 *
 *  Version 1.0 ALPHA	initial code, primary i/f working okay
 *  Version 1.3 BETA	dual i/f on shared irq tested & working!
 *  Version 1.4 BETA	added auto probing for irq(s)
 *  Version 1.5 BETA	added ALPHA (untested) support for IDE cd-roms,
 *  ...
 * Version 5.50		allow values as small as 20 for idebus=
 * Version 5.51		force non io_32bit in drive_cmd_intr()
 *			change delay_10ms() to delay_50ms() to fix problems
 * Version 5.52		fix incorrect invalidation of removable devices
 *			add "hdx=slow" command line option
 * Version 5.60		start to modularize the driver; the disk and ATAPI
 *			 drivers can be compiled as loadable modules.
 *			move IDE probe code to ide-probe.c
 *			move IDE disk code to ide-disk.c
 *			add support for generic IDE device subdrivers
 *			add m68k code from Geert Uytterhoeven
 *			probe all interfaces by default
 *			add ioctl to (re)probe an interface
 * Version 6.00		use per device request queues
 *			attempt to optimize shared hwgroup performance
 *			add ioctl to manually adjust bandwidth algorithms
 *			add kerneld support for the probe module
 *			fix bug in ide_error()
 *			fix bug in the first ide_get_lock() call for Atari
 *			don't flush leftover data for ATAPI devices
 * Version 6.01		clear hwgroup->active while the hwgroup sleeps
 *			support HDIO_GETGEO for floppies
 * Version 6.02		fix ide_ack_intr() call
 *			check partition table on floppies
 * Version 6.03		handle bad status bit sequencing in ide_wait_stat()
 * Version 6.10		deleted old entries from this list of updates
 *			replaced triton.c with ide-dma.c generic PCI DMA
 *			added support for BIOS-enabled UltraDMA
 *			rename all "promise" things to "pdc4030"
 *			fix EZ-DRIVE handling on small disks
 * Version 6.11		fix probe error in ide_scan_devices()
 *			fix ancient "jiffies" polling bugs
 *			mask all hwgroup interrupts on each irq entry
 * Version 6.12		integrate ioctl and proc interfaces
 *			fix parsing of "idex=" command line parameter
 * Version 6.13		add support for ide4/ide5 courtesy rjones@orchestream.com
 * Version 6.14		fixed IRQ sharing among PCI devices
 * Version 6.15		added SMP awareness to IDE drivers
 * Version 6.16		fixed various bugs; even more SMP friendly
 * Version 6.17		fix for newest EZ-Drive problem
 * Version 6.18		default unpartitioned-disk translation now "BIOS LBA"
 * Version 6.19		Re-design for a UNIFORM driver for all platforms,
 *			  model based on suggestions from Russell King and
 *			  Geert Uytterhoeven
 *			Promise DC4030VL now supported.
 *			add support for ide6/ide7
 *			delay_50ms() changed to ide_delay_50ms() and exported.
 * Version 6.20		Added/Fixed Generic ATA-66 support and hwif detection.
 *			Added hdx=flash to allow for second flash disk
 *			  detection w/o the hang loop.
 *			Added support for ide8/ide9
 *			Added idex=ata66 for the quirky chipsets that are
 *			  ATA-66 compliant, but have yet to determine a method
 *			  of verification of the 80c cable presence.
 *			  Specifically Promise's PDC20262 chipset.
 * Version 6.21		Fixing/Fixed SMP spinlock issue with insight from an old
 *			  hat that clarified original low level driver design.
 * Version 6.30		Added SMP support; fixed multmode issues.  -ml
 * Version 6.31		Debug Share INTR's and request queue streaming
 *			Native ATA-100 support
 *			Prep for Cascades Project
 *
 *  Some additional driver compile-time options are in ./include/linux/ide.h
 *
 *  To do, in likely order of completion:
 *	- modify kernel to obtain BIOS geometry for drives on 2nd/3rd/4th i/f
 *
 */

#define	REVISION	"Revision: 6.31"
#define	VERSION		"Id: ide.c 6.31 2000/06/09"

#undef REALLY_SLOW_IO		/* most systems can safely undef this */

#define _IDE_C			/* Tell ide.h it's really us */

#include <xeno/config.h>
#include <xeno/module.h>
#include <xeno/types.h>
#include <xeno/lib.h>
/*#include <xeno/kernel.h>*/
#include <xeno/timer.h>
#include <xeno/mm.h>
#include <xeno/interrupt.h>
#include <xeno/major.h>
#include <xeno/errno.h>
#include <xeno/genhd.h>
#include <xeno/blkpg.h>
#include <xeno/slab.h>
#include <xeno/init.h>
#include <xeno/pci.h>
#include <xeno/delay.h>
#include <xeno/ide.h>
/*#include <xeno/devfs_fs_kernel.h>*/
/*#include <xeno/completion.h>*/
/*#include <xeno/reboot.h>*/

#include <asm/byteorder.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bitops.h>

#include "ide_modes.h"

#ifdef CONFIG_KMOD
#include <xeno/kmod.h>
#endif /* CONFIG_KMOD */

#ifdef CONFIG_IDE_TASKFILE_IO
#  define __TASKFILE__IO
#else /* CONFIG_IDE_TASKFILE_IO */
#  undef __TASKFILE__IO
#endif /* CONFIG_IDE_TASKFILE_IO */

#ifdef __TASKFILE__IO
#else /* !__TASKFILE__IO */
#endif /* __TASKFILE__IO */




/* XXXXXXXXXXXX This may be replaced by fs/block_dev.c versions!!! XXXXX */
/* (only included here so the hypervisor will link :-) */
int check_disk_change(kdev_t dev) { return 0; }
int unregister_blkdev(unsigned int major, const char * name) { return 0; }
/* And these ones are from fs/inode.c... */
int invalidate_device(kdev_t dev, int do_sync) { return 0; }
/* fs/buffer.c... */
void invalidate_bdev(struct block_device *bdev, int destroy_dirty_buffers) { }
/* fs/partitions/check.c... */
void grok_partitions(struct gendisk *dev, int drive, 
                     unsigned minors, long size) { }
void register_disk(struct gendisk *dev, kdev_t first, 
                   unsigned minors, struct block_device_operations *ops, 
                   long size) { }
/* fs/devices.c... */
const char * kdevname(kdev_t dev) { return NULL; }
/* End of XXXXXX region */




/* default maximum number of failures */
#define IDE_DEFAULT_MAX_FAILURES 	1

static const byte ide_hwif_to_major[] = { IDE0_MAJOR, IDE1_MAJOR, IDE2_MAJOR, IDE3_MAJOR, IDE4_MAJOR, IDE5_MAJOR, IDE6_MAJOR, IDE7_MAJOR, IDE8_MAJOR, IDE9_MAJOR };

static int	idebus_parameter; /* holds the "idebus=" parameter */
static int	system_bus_speed; /* holds what we think is VESA/PCI bus speed */
static int	initializing;     /* set while initializing built-in drivers */

#ifdef CONFIG_BLK_DEV_IDEPCI
static int	ide_scan_direction;	/* THIS was formerly 2.2.x pci=reverse */
#endif /* CONFIG_BLK_DEV_IDEPCI */

#if defined(__mc68000__) || defined(CONFIG_APUS)
/*
 * ide_lock is used by the Atari code to obtain access to the IDE interrupt,
 * which is shared between several drivers.
 */
static int	ide_lock;
#endif /* __mc68000__ || CONFIG_APUS */

int noautodma = 0;

/*
 * ide_modules keeps track of the available IDE chipset/probe/driver modules.
 */
ide_module_t *ide_modules;
ide_module_t *ide_probe;

/*
 * This is declared extern in ide.h, for access by other IDE modules:
 */
ide_hwif_t	ide_hwifs[MAX_HWIFS];	/* master data repository */

#if (DISK_RECOVERY_TIME > 0)
/*
 * For really screwy hardware (hey, at least it *can* be used with Linux)
 * we can enforce a minimum delay time between successive operations.
 */
static unsigned long read_timer (void)
{
	unsigned long t, flags;
	int i;

	__save_flags(flags);	/* local CPU only */
	__cli();		/* local CPU only */
	t = jiffies * 11932;
    	outb_p(0, 0x43);
	i = inb_p(0x40);
	i |= inb(0x40) << 8;
	__restore_flags(flags);	/* local CPU only */
	return (t - i);
}
#endif /* DISK_RECOVERY_TIME */

static inline void set_recovery_timer (ide_hwif_t *hwif)
{
#if (DISK_RECOVERY_TIME > 0)
	hwif->last_time = read_timer();
#endif /* DISK_RECOVERY_TIME */
}

/*
 * Do not even *think* about calling this!
 */
static void init_hwif_data (unsigned int index)
{
	unsigned int unit;
	hw_regs_t hw;
	ide_hwif_t *hwif = &ide_hwifs[index];

	/* bulk initialize hwif & drive info with zeros */
	memset(hwif, 0, sizeof(ide_hwif_t));
	memset(&hw, 0, sizeof(hw_regs_t));

	/* fill in any non-zero initial values */
	hwif->index     = index;
	ide_init_hwif_ports(&hw, ide_default_io_base(index), 0, &hwif->irq);
	memcpy(&hwif->hw, &hw, sizeof(hw));
	memcpy(hwif->io_ports, hw.io_ports, sizeof(hw.io_ports));
	hwif->noprobe	= !hwif->io_ports[IDE_DATA_OFFSET];
#ifdef CONFIG_BLK_DEV_HD
	if (hwif->io_ports[IDE_DATA_OFFSET] == HD_DATA)
		hwif->noprobe = 1; /* may be overridden by ide_setup() */
#endif /* CONFIG_BLK_DEV_HD */
	hwif->major	= ide_hwif_to_major[index];
	hwif->name[0]	= 'i';
	hwif->name[1]	= 'd';
	hwif->name[2]	= 'e';
	hwif->name[3]	= '0' + index;
	hwif->bus_state = BUSSTATE_ON;
	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		ide_drive_t *drive = &hwif->drives[unit];

		drive->media			= ide_disk;
		drive->select.all		= (unit<<4)|0xa0;
		drive->hwif			= hwif;
		drive->ctl			= 0x08;
		drive->ready_stat		= READY_STAT;
		drive->bad_wstat		= BAD_W_STAT;
		drive->special.b.recalibrate	= 1;
		drive->special.b.set_geometry	= 1;
		drive->name[0]			= 'h';
		drive->name[1]			= 'd';
		drive->name[2]			= 'a' + (index * MAX_DRIVES) + unit;
		drive->max_failures		= IDE_DEFAULT_MAX_FAILURES;
		/*init_waitqueue_head(&drive->wqueue);*/
	}
}

/*
 * init_ide_data() sets reasonable default values into all fields
 * of all instances of the hwifs and drives, but only on the first call.
 * Subsequent calls have no effect (they don't wipe out anything).
 *
 * This routine is normally called at driver initialization time,
 * but may also be called MUCH earlier during kernel "command-line"
 * parameter processing.  As such, we cannot depend on any other parts
 * of the kernel (such as memory allocation) to be functioning yet.
 *
 * This is too bad, as otherwise we could dynamically allocate the
 * ide_drive_t structs as needed, rather than always consuming memory
 * for the max possible number (MAX_HWIFS * MAX_DRIVES) of them.
 */
#define MAGIC_COOKIE 0x12345678
static void __init init_ide_data (void)
{
	unsigned int index;
	static unsigned long magic_cookie = MAGIC_COOKIE;

	if (magic_cookie != MAGIC_COOKIE)
		return;		/* already initialized */
	magic_cookie = 0;

	/* Initialise all interface structures */
	for (index = 0; index < MAX_HWIFS; ++index)
		init_hwif_data(index);

	/* Add default hw interfaces */
	ide_init_default_hwifs();

	idebus_parameter = 0;
	system_bus_speed = 0;
}

/*
 * CompactFlash cards and their brethern pretend to be removable hard disks, except:
 *	(1) they never have a slave unit, and
 *	(2) they don't have doorlock mechanisms.
 * This test catches them, and is invoked elsewhere when setting appropriate config bits.
 *
 * FIXME: This treatment is probably applicable for *all* PCMCIA (PC CARD) devices,
 * so in linux 2.3.x we should change this to just treat all PCMCIA drives this way,
 * and get rid of the model-name tests below (too big of an interface change for 2.2.x).
 * At that time, we might also consider parameterizing the timeouts and retries,
 * since these are MUCH faster than mechanical drives.	-M.Lord
 */
int drive_is_flashcard (ide_drive_t *drive)
{
	struct hd_driveid *id = drive->id;

	if (drive->removable && id != NULL) {
		if (id->config == 0x848a) return 1;	/* CompactFlash */
		if (!strncmp(id->model, "KODAK ATA_FLASH", 15)	/* Kodak */
		 || !strncmp(id->model, "Hitachi CV", 10)	/* Hitachi */
		 || !strncmp(id->model, "SunDisk SDCFB", 13)	/* SunDisk */
		 || !strncmp(id->model, "HAGIWARA HPC", 12)	/* Hagiwara */
		 || !strncmp(id->model, "LEXAR ATA_FLASH", 15)	/* Lexar */
		 || !strncmp(id->model, "ATA_FLASH", 9))	/* Simple Tech */
		{
			return 1;	/* yes, it is a flash memory card */
		}
	}
	return 0;	/* no, it is not a flash memory card */
}

/*
 * ide_system_bus_speed() returns what we think is the system VESA/PCI
 * bus speed (in MHz).  This is used for calculating interface PIO timings.
 * The default is 40 for known PCI systems, 50 otherwise.
 * The "idebus=xx" parameter can be used to override this value.
 * The actual value to be used is computed/displayed the first time through.
 */
int ide_system_bus_speed (void)
{
	if (!system_bus_speed) {
		if (idebus_parameter)
			system_bus_speed = idebus_parameter;	/* user supplied value */
#ifdef CONFIG_PCI
		else if (pci_present())
			system_bus_speed = 33;	/* safe default value for PCI */
#endif /* CONFIG_PCI */
		else
			system_bus_speed = 50;	/* safe default value for VESA and PCI */
		printk("ide: Assuming %dMHz system bus speed for PIO modes%s\n", system_bus_speed,
			idebus_parameter ? "" : "; override with idebus=xx");
	}
	return system_bus_speed;
}

#if SUPPORT_VLB_SYNC
/*
 * Some localbus EIDE interfaces require a special access sequence
 * when using 32-bit I/O instructions to transfer data.  We call this
 * the "vlb_sync" sequence, which consists of three successive reads
 * of the sector count register location, with interrupts disabled
 * to ensure that the reads all happen together.
 */
static inline void do_vlb_sync (ide_ioreg_t port) {
	(void) inb (port);
	(void) inb (port);
	(void) inb (port);
}
#endif /* SUPPORT_VLB_SYNC */

/*
 * This is used for most PIO data transfers *from* the IDE interface
 */
void ide_input_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	byte io_32bit;

	/* first check if this controller has defined a special function
	 * for handling polled ide transfers
	 */

	if(HWIF(drive)->ideproc) {
		HWIF(drive)->ideproc(ideproc_ide_input_data,
				     drive, buffer, wcount);
		return;
	}

	io_32bit = drive->io_32bit;

	if (io_32bit) {
#if SUPPORT_VLB_SYNC
		if (io_32bit & 2) {
			unsigned long flags;
			__save_flags(flags);	/* local CPU only */
			__cli();		/* local CPU only */
			do_vlb_sync(IDE_NSECTOR_REG);
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
void ide_output_data (ide_drive_t *drive, void *buffer, unsigned int wcount)
{
	byte io_32bit;

	if(HWIF(drive)->ideproc) {
		HWIF(drive)->ideproc(ideproc_ide_output_data,
				     drive, buffer, wcount);
		return;
	}

	io_32bit = drive->io_32bit;

	if (io_32bit) {
#if SUPPORT_VLB_SYNC
		if (io_32bit & 2) {
			unsigned long flags;
			__save_flags(flags);	/* local CPU only */
			__cli();		/* local CPU only */
			do_vlb_sync(IDE_NSECTOR_REG);
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

/*
 * The following routines are mainly used by the ATAPI drivers.
 *
 * These routines will round up any request for an odd number of bytes,
 * so if an odd bytecount is specified, be sure that there's at least one
 * extra byte allocated for the buffer.
 */
void atapi_input_bytes (ide_drive_t *drive, void *buffer, unsigned int bytecount)
{
	if(HWIF(drive)->ideproc) {
		HWIF(drive)->ideproc(ideproc_atapi_input_bytes,
				     drive, buffer, bytecount);
		return;
	}

	++bytecount;
#if defined(CONFIG_ATARI) || defined(CONFIG_Q40)
	if (MACH_IS_ATARI || MACH_IS_Q40) {
		/* Atari has a byte-swapped IDE interface */
		insw_swapw(IDE_DATA_REG, buffer, bytecount / 2);
		return;
	}
#endif /* CONFIG_ATARI */
	ide_input_data (drive, buffer, bytecount / 4);
	if ((bytecount & 0x03) >= 2)
		insw (IDE_DATA_REG, ((byte *)buffer) + (bytecount & ~0x03), 1);
}

void atapi_output_bytes (ide_drive_t *drive, void *buffer, unsigned int bytecount)
{
	if(HWIF(drive)->ideproc) {
		HWIF(drive)->ideproc(ideproc_atapi_output_bytes,
				     drive, buffer, bytecount);
		return;
	}

	++bytecount;
#if defined(CONFIG_ATARI) || defined(CONFIG_Q40)
	if (MACH_IS_ATARI || MACH_IS_Q40) {
		/* Atari has a byte-swapped IDE interface */
		outsw_swapw(IDE_DATA_REG, buffer, bytecount / 2);
		return;
	}
#endif /* CONFIG_ATARI */
	ide_output_data (drive, buffer, bytecount / 4);
	if ((bytecount & 0x03) >= 2)
		outsw (IDE_DATA_REG, ((byte *)buffer) + (bytecount & ~0x03), 1);
}

/*
 * Needed for PCI irq sharing
 */
//static inline
int drive_is_ready (ide_drive_t *drive)
{
	byte stat = 0;
	if (drive->waiting_for_dma)
		return HWIF(drive)->dmaproc(ide_dma_test_irq, drive);
#if 0
	udelay(1);	/* need to guarantee 400ns since last command was issued */
#endif

#ifdef CONFIG_IDEPCI_SHARE_IRQ
	/*
	 * We do a passive status test under shared PCI interrupts on
	 * cards that truly share the ATA side interrupt, but may also share
	 * an interrupt with another pci card/device.  We make no assumptions
	 * about possible isa-pnp and pci-pnp issues yet.
	 */
	if (IDE_CONTROL_REG)
		stat = GET_ALTSTAT();
	else
#endif /* CONFIG_IDEPCI_SHARE_IRQ */
	stat = GET_STAT();	/* Note: this may clear a pending IRQ!! */

	if (stat & BUSY_STAT)
		return 0;	/* drive busy:  definitely not interrupting */
	return 1;		/* drive ready: *might* be interrupting */
}

/*
 * This is our end_request replacement function.
 */
void ide_end_request (byte uptodate, ide_hwgroup_t *hwgroup)
{
	struct request *rq;
	unsigned long flags;
	ide_drive_t *drive = hwgroup->drive;

	spin_lock_irqsave(&io_request_lock, flags);
	rq = hwgroup->rq;

	/*
	 * decide whether to reenable DMA -- 3 is a random magic for now,
	 * if we DMA timeout more than 3 times, just stay in PIO
	 */
	if (drive->state == DMA_PIO_RETRY && drive->retry_pio <= 3) {
		drive->state = 0;
		hwgroup->hwif->dmaproc(ide_dma_on, drive);
	}

	if (!end_that_request_first(rq, uptodate, hwgroup->drive->name)) {
		add_blkdev_randomness(MAJOR(rq->rq_dev));
		blkdev_dequeue_request(rq);
        	hwgroup->rq = NULL;
		end_that_request_last(rq);
	}
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * This should get invoked any time we exit the driver to
 * wait for an interrupt response from a drive.  handler() points
 * at the appropriate code to handle the next interrupt, and a
 * timer is started to prevent us from waiting forever in case
 * something goes wrong (see the ide_timer_expiry() handler later on).
 */
void ide_set_handler (ide_drive_t *drive, ide_handler_t *handler,
		      unsigned int timeout, ide_expiry_t *expiry)
{
	unsigned long flags;
	ide_hwgroup_t *hwgroup = HWGROUP(drive);

	spin_lock_irqsave(&io_request_lock, flags);
	if (hwgroup->handler != NULL) {
		printk("%s: ide_set_handler: handler not null; old=%p, new=%p\n",
			drive->name, hwgroup->handler, handler);
	}
	hwgroup->handler	= handler;
	hwgroup->expiry		= expiry;
	hwgroup->timer.expires	= jiffies + timeout;
	add_timer(&hwgroup->timer);
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * current_capacity() returns the capacity (in sectors) of a drive
 * according to its current geometry/LBA settings.
 */
unsigned long current_capacity (ide_drive_t *drive)
{
	if (!drive->present)
		return 0;
	if (drive->driver != NULL)
		return DRIVER(drive)->capacity(drive);
	return 0;
}

extern struct block_device_operations ide_fops[];
/*
 * ide_geninit() is called exactly *once* for each interface.
 */
void ide_geninit (ide_hwif_t *hwif)
{
	unsigned int unit;
	struct gendisk *gd = hwif->gd;

	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		ide_drive_t *drive = &hwif->drives[unit];

		if (!drive->present)
			continue;
		if (drive->media!=ide_disk && drive->media!=ide_floppy)
			continue;
		register_disk(gd,MKDEV(hwif->major,unit<<PARTN_BITS),
#ifdef CONFIG_BLK_DEV_ISAPNP
			(drive->forced_geom && drive->noprobe) ? 1 :
#endif /* CONFIG_BLK_DEV_ISAPNP */
			1<<PARTN_BITS, ide_fops,
			current_capacity(drive));
	}
}

static ide_startstop_t do_reset1 (ide_drive_t *, int);		/* needed below */

/*
 * atapi_reset_pollfunc() gets invoked to poll the interface for completion every 50ms
 * during an atapi drive reset operation. If the drive has not yet responded,
 * and we have not yet hit our maximum waiting time, then the timer is restarted
 * for another 50ms.
 */
static ide_startstop_t atapi_reset_pollfunc (ide_drive_t *drive)
{
	ide_hwgroup_t *hwgroup = HWGROUP(drive);
	byte stat;

	SELECT_DRIVE(HWIF(drive),drive);
	udelay (10);

	if (OK_STAT(stat=GET_STAT(), 0, BUSY_STAT)) {
		printk("%s: ATAPI reset complete\n", drive->name);
	} else {
		if (0 < (signed long)(hwgroup->poll_timeout - jiffies)) {
			ide_set_handler (drive, &atapi_reset_pollfunc, HZ/20, NULL);
			return ide_started;	/* continue polling */
		}
		hwgroup->poll_timeout = 0;	/* end of polling */
		printk("%s: ATAPI reset timed-out, status=0x%02x\n", drive->name, stat);
		return do_reset1 (drive, 1);	/* do it the old fashioned way */
	}
	hwgroup->poll_timeout = 0;	/* done polling */
	return ide_stopped;
}

/*
 * reset_pollfunc() gets invoked to poll the interface for completion every 50ms
 * during an ide reset operation. If the drives have not yet responded,
 * and we have not yet hit our maximum waiting time, then the timer is restarted
 * for another 50ms.
 */
static ide_startstop_t reset_pollfunc (ide_drive_t *drive)
{
	ide_hwgroup_t *hwgroup = HWGROUP(drive);
	ide_hwif_t *hwif = HWIF(drive);
	byte tmp;

	if (!OK_STAT(tmp=GET_STAT(), 0, BUSY_STAT)) {
		if (0 < (signed long)(hwgroup->poll_timeout - jiffies)) {
			ide_set_handler (drive, &reset_pollfunc, HZ/20, NULL);
			return ide_started;	/* continue polling */
		}
		printk("%s: reset timed-out, status=0x%02x\n", hwif->name, tmp);
		drive->failures++;
	} else  {
		printk("%s: reset: ", hwif->name);
		if ((tmp = GET_ERR()) == 1) {
			printk("success\n");
			drive->failures = 0;
		} else {
			drive->failures++;
#if FANCY_STATUS_DUMPS
			printk("master: ");
			switch (tmp & 0x7f) {
				case 1: printk("passed");
					break;
				case 2: printk("formatter device error");
					break;
				case 3: printk("sector buffer error");
					break;
				case 4: printk("ECC circuitry error");
					break;
				case 5: printk("controlling MPU error");
					break;
				default:printk("error (0x%02x?)", tmp);
			}
			if (tmp & 0x80)
				printk("; slave: failed");
			printk("\n");
#else
			printk("failed\n");
#endif /* FANCY_STATUS_DUMPS */
		}
	}
	hwgroup->poll_timeout = 0;	/* done polling */
	return ide_stopped;
}

static void check_dma_crc (ide_drive_t *drive)
{
	if (drive->crc_count) {
		(void) HWIF(drive)->dmaproc(ide_dma_off_quietly, drive);
		if ((HWIF(drive)->speedproc) != NULL)
			HWIF(drive)->speedproc(drive, ide_auto_reduce_xfer(drive));
		if (drive->current_speed >= XFER_SW_DMA_0)
			(void) HWIF(drive)->dmaproc(ide_dma_on, drive);
	} else {
		(void) HWIF(drive)->dmaproc(ide_dma_off, drive);
	}
}

static void pre_reset (ide_drive_t *drive)
{
	if (drive->driver != NULL)
		DRIVER(drive)->pre_reset(drive);

	if (!drive->keep_settings) {
		if (drive->using_dma) {
			check_dma_crc(drive);
		} else {
			drive->unmask = 0;
			drive->io_32bit = 0;
		}
		return;
	}
	if (drive->using_dma)
		check_dma_crc(drive);
}

/*
 * do_reset1() attempts to recover a confused drive by resetting it.
 * Unfortunately, resetting a disk drive actually resets all devices on
 * the same interface, so it can really be thought of as resetting the
 * interface rather than resetting the drive.
 *
 * ATAPI devices have their own reset mechanism which allows them to be
 * individually reset without clobbering other devices on the same interface.
 *
 * Unfortunately, the IDE interface does not generate an interrupt to let
 * us know when the reset operation has finished, so we must poll for this.
 * Equally poor, though, is the fact that this may a very long time to complete,
 * (up to 30 seconds worstcase).  So, instead of busy-waiting here for it,
 * we set a timer to poll at 50ms intervals.
 */
static ide_startstop_t do_reset1 (ide_drive_t *drive, int do_not_try_atapi)
{
	unsigned int unit;
	unsigned long flags;
	ide_hwif_t *hwif = HWIF(drive);
	ide_hwgroup_t *hwgroup = HWGROUP(drive);

	__save_flags(flags);	/* local CPU only */
	__cli();		/* local CPU only */

	/* For an ATAPI device, first try an ATAPI SRST. */
	if (drive->media != ide_disk && !do_not_try_atapi) {
		pre_reset(drive);
		SELECT_DRIVE(hwif,drive);
		udelay (20);
		OUT_BYTE (WIN_SRST, IDE_COMMAND_REG);
		hwgroup->poll_timeout = jiffies + WAIT_WORSTCASE;
		ide_set_handler (drive, &atapi_reset_pollfunc, HZ/20, NULL);
		__restore_flags (flags);	/* local CPU only */
		return ide_started;
	}

	/*
	 * First, reset any device state data we were maintaining
	 * for any of the drives on this interface.
	 */
	for (unit = 0; unit < MAX_DRIVES; ++unit)
		pre_reset(&hwif->drives[unit]);

#if OK_TO_RESET_CONTROLLER
	if (!IDE_CONTROL_REG) {
		__restore_flags(flags);
		return ide_stopped;
	}
	/*
	 * Note that we also set nIEN while resetting the device,
	 * to mask unwanted interrupts from the interface during the reset.
	 * However, due to the design of PC hardware, this will cause an
	 * immediate interrupt due to the edge transition it produces.
	 * This single interrupt gives us a "fast poll" for drives that
	 * recover from reset very quickly, saving us the first 50ms wait time.
	 */
	OUT_BYTE(drive->ctl|6,IDE_CONTROL_REG);	/* set SRST and nIEN */
	udelay(10);			/* more than enough time */
	if (drive->quirk_list == 2) {
		OUT_BYTE(drive->ctl,IDE_CONTROL_REG);	/* clear SRST and nIEN */
	} else {
		OUT_BYTE(drive->ctl|2,IDE_CONTROL_REG);	/* clear SRST, leave nIEN */
	}
	udelay(10);			/* more than enough time */
	hwgroup->poll_timeout = jiffies + WAIT_WORSTCASE;
	ide_set_handler (drive, &reset_pollfunc, HZ/20, NULL);

	/*
	 * Some weird controller like resetting themselves to a strange
	 * state when the disks are reset this way. At least, the Winbond
	 * 553 documentation says that
	 */
	if (hwif->resetproc != NULL)
		hwif->resetproc(drive);

#endif	/* OK_TO_RESET_CONTROLLER */

	__restore_flags (flags);	/* local CPU only */
	return ide_started;
}

/*
 * ide_do_reset() is the entry point to the drive/interface reset code.
 */
ide_startstop_t ide_do_reset (ide_drive_t *drive)
{
	return do_reset1 (drive, 0);
}

static inline u32 read_24 (ide_drive_t *drive)
{
	return  (IN_BYTE(IDE_HCYL_REG)<<16) |
		(IN_BYTE(IDE_LCYL_REG)<<8) |
		 IN_BYTE(IDE_SECTOR_REG);
}

/*
 * Clean up after success/failure of an explicit drive cmd
 */
void ide_end_drive_cmd (ide_drive_t *drive, byte stat, byte err)
{
	unsigned long flags;
	struct request *rq;

	spin_lock_irqsave(&io_request_lock, flags);
	rq = HWGROUP(drive)->rq;
	spin_unlock_irqrestore(&io_request_lock, flags);

	switch(rq->cmd) {
		case IDE_DRIVE_CMD:
		{
			byte *args = (byte *) rq->buffer;
			rq->errors = !OK_STAT(stat,READY_STAT,BAD_STAT);
			if (args) {
				args[0] = stat;
				args[1] = err;
				args[2] = IN_BYTE(IDE_NSECTOR_REG);
			}
			break;
		}
		case IDE_DRIVE_TASK:
		{
			byte *args = (byte *) rq->buffer;
			rq->errors = !OK_STAT(stat,READY_STAT,BAD_STAT);
			if (args) {
				args[0] = stat;
				args[1] = err;
				args[2] = IN_BYTE(IDE_NSECTOR_REG);
				args[3] = IN_BYTE(IDE_SECTOR_REG);
				args[4] = IN_BYTE(IDE_LCYL_REG);
				args[5] = IN_BYTE(IDE_HCYL_REG);
				args[6] = IN_BYTE(IDE_SELECT_REG);
			}
			break;
		}
		case IDE_DRIVE_TASKFILE:
		{
			ide_task_t *args = (ide_task_t *) rq->special;
			rq->errors = !OK_STAT(stat,READY_STAT,BAD_STAT);
			if (args) {
				if (args->tf_in_flags.b.data) {
					unsigned short data			= IN_WORD(IDE_DATA_REG);
					args->tfRegister[IDE_DATA_OFFSET]	= (data) & 0xFF;
					args->hobRegister[IDE_DATA_OFFSET_HOB]	= (data >> 8) & 0xFF;
				}
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
			}
			break;
		}
		default:
			break;
	}
	spin_lock_irqsave(&io_request_lock, flags);
	blkdev_dequeue_request(rq);
	HWGROUP(drive)->rq = NULL;
	end_that_request_last(rq);
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * Error reporting, in human readable form (luxurious, but a memory hog).
 */
byte ide_dump_status (ide_drive_t *drive, const char *msg, byte stat)
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
#endif	/* FANCY_STATUS_DUMPS */
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
					low = read_24(drive);
					OUT_BYTE(drive->ctl|0x80, IDE_CONTROL_REG);
					high = read_24(drive);

					sectors = ((__u64)high << 24) | low;
					printk(", LBAsect=%llu, high=%d, low=%d",
					       (unsigned long long) sectors,
					       high, low);
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
				if (HWGROUP(drive) && HWGROUP(drive)->rq)
					printk(", sector=%ld", HWGROUP(drive)->rq->sector);
			}
		}
#endif	/* FANCY_STATUS_DUMPS */
		printk("\n");
	}
	__restore_flags (flags);	/* local CPU only */
	return err;
}

/*
 * try_to_flush_leftover_data() is invoked in response to a drive
 * unexpectedly having its DRQ_STAT bit set.  As an alternative to
 * resetting the drive, this routine tries to clear the condition
 * by read a sector's worth of data from the drive.  Of course,
 * this may not help if the drive is *waiting* for data from *us*.
 */
static void try_to_flush_leftover_data (ide_drive_t *drive)
{
	int i = (drive->mult_count ? drive->mult_count : 1) * SECTOR_WORDS;

	if (drive->media != ide_disk)
		return;
	while (i > 0) {
		u32 buffer[16];
		unsigned int wcount = (i > 16) ? 16 : i;
		i -= wcount;
		ide_input_data (drive, buffer, wcount);
	}
}

/*
 * ide_error() takes action based on the error returned by the drive.
 */
ide_startstop_t ide_error (ide_drive_t *drive, const char *msg, byte stat)
{
	struct request *rq;
	byte err;

	err = ide_dump_status(drive, msg, stat);
	if (drive == NULL || (rq = HWGROUP(drive)->rq) == NULL)
		return ide_stopped;
	/* retry only "normal" I/O: */
	if (rq->cmd == IDE_DRIVE_CMD || rq->cmd == IDE_DRIVE_TASK) {
		rq->errors = 1;
		ide_end_drive_cmd(drive, stat, err);
		return ide_stopped;
	}
	if (rq->cmd == IDE_DRIVE_TASKFILE) {
		rq->errors = 1;
		ide_end_drive_cmd(drive, stat, err);
//		ide_end_taskfile(drive, stat, err);
		return ide_stopped;
	}

	if (stat & BUSY_STAT || ((stat & WRERR_STAT) && !drive->nowerr)) { /* other bits are useless when BUSY */
		rq->errors |= ERROR_RESET;
	} else {
		if (drive->media == ide_disk && (stat & ERR_STAT)) {
			/* err has different meaning on cdrom and tape */
			if (err == ABRT_ERR) {
				if (drive->select.b.lba && IN_BYTE(IDE_COMMAND_REG) == WIN_SPECIFY)
					return ide_stopped; /* some newer drives don't support WIN_SPECIFY */
			} else if ((err & (ABRT_ERR | ICRC_ERR)) == (ABRT_ERR | ICRC_ERR)) {
				drive->crc_count++; /* UDMA crc error -- just retry the operation */
			} else if (err & (BBD_ERR | ECC_ERR))	/* retries won't help these */
				rq->errors = ERROR_MAX;
			else if (err & TRK0_ERR)	/* help it find track zero */
				rq->errors |= ERROR_RECAL;
		}
		if ((stat & DRQ_STAT) && rq->cmd != WRITE)
			try_to_flush_leftover_data(drive);
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

/*
 * Issue a simple drive command
 * The drive must be selected beforehand.
 */
void ide_cmd (ide_drive_t *drive, byte cmd, byte nsect, ide_handler_t *handler)
{
	ide_set_handler (drive, handler, WAIT_CMD, NULL);
	if (IDE_CONTROL_REG)
		OUT_BYTE(drive->ctl,IDE_CONTROL_REG);	/* clear nIEN */
	SELECT_MASK(HWIF(drive),drive,0);
	OUT_BYTE(nsect,IDE_NSECTOR_REG);
	OUT_BYTE(cmd,IDE_COMMAND_REG);
}

/*
 * drive_cmd_intr() is invoked on completion of a special DRIVE_CMD.
 */
static ide_startstop_t drive_cmd_intr (ide_drive_t *drive)
{
	struct request *rq = HWGROUP(drive)->rq;
	byte *args = (byte *) rq->buffer;
	byte stat = GET_STAT();
	int retries = 10;

	ide__sti();	/* local CPU only */
	if ((stat & DRQ_STAT) && args && args[3]) {
		byte io_32bit = drive->io_32bit;
		drive->io_32bit = 0;
		ide_input_data(drive, &args[4], args[3] * SECTOR_WORDS);
		drive->io_32bit = io_32bit;
		while (((stat = GET_STAT()) & BUSY_STAT) && retries--)
			udelay(100);
	}

	if (!OK_STAT(stat, READY_STAT, BAD_STAT))
		return ide_error(drive, "drive_cmd", stat); /* calls ide_end_drive_cmd */
	ide_end_drive_cmd (drive, stat, GET_ERR());
	return ide_stopped;
}

/*
 * do_special() is used to issue WIN_SPECIFY, WIN_RESTORE, and WIN_SETMULT
 * commands to a drive.  It used to do much more, but has been scaled back.
 */
static ide_startstop_t do_special (ide_drive_t *drive)
{
	special_t *s = &drive->special;

#ifdef DEBUG
	printk("%s: do_special: 0x%02x\n", drive->name, s->all);
#endif
	if (s->b.set_tune) {
		ide_tuneproc_t *tuneproc = HWIF(drive)->tuneproc;
		s->b.set_tune = 0;
		if (tuneproc != NULL)
			tuneproc(drive, drive->tune_req);
	} else if (drive->driver != NULL) {
		return DRIVER(drive)->special(drive);
	} else if (s->all) {
		printk("%s: bad special flag: 0x%02x\n", drive->name, s->all);
		s->all = 0;
	}
	return ide_stopped;
}

/*
 * This routine busy-waits for the drive status to be not "busy".
 * It then checks the status for all of the "good" bits and none
 * of the "bad" bits, and if all is okay it returns 0.  All other
 * cases return 1 after invoking ide_error() -- caller should just return.
 *
 * This routine should get fixed to not hog the cpu during extra long waits..
 * That could be done by busy-waiting for the first jiffy or two, and then
 * setting a timer to wake up at half second intervals thereafter,
 * until timeout is achieved, before timing out.
 */
int ide_wait_stat (ide_startstop_t *startstop, ide_drive_t *drive, byte good, byte bad, unsigned long timeout) {
	byte stat;
	int i;
	unsigned long flags;
 
	/* bail early if we've exceeded max_failures */
	if (drive->max_failures && (drive->failures > drive->max_failures)) {
		*startstop = ide_stopped;
		return 1;
	}

	udelay(1);	/* spec allows drive 400ns to assert "BUSY" */
	if ((stat = GET_STAT()) & BUSY_STAT) {
		__save_flags(flags);	/* local CPU only */
		ide__sti();		/* local CPU only */
		timeout += jiffies;
		while ((stat = GET_STAT()) & BUSY_STAT) {
			if (0 < (signed long)(jiffies - timeout)) {
				__restore_flags(flags);	/* local CPU only */
				*startstop = ide_error(drive, "status timeout", stat);
				return 1;
			}
		}
		__restore_flags(flags);	/* local CPU only */
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
		if (OK_STAT((stat = GET_STAT()), good, bad))
			return 0;
	}
	*startstop = ide_error(drive, "status error", stat);
	return 1;
}

/*
 * execute_drive_cmd() issues a special drive command,
 * usually initiated by ioctl() from the external hdparm program.
 */
static ide_startstop_t execute_drive_cmd (ide_drive_t *drive, struct request *rq)
{
 	switch(rq->cmd) {
 		case IDE_DRIVE_TASKFILE:
 		{
 			ide_task_t *args = rq->special;
 
 			if (!(args)) break;
 
#ifdef CONFIG_IDE_TASK_IOCTL_DEBUG
	{
	printk(KERN_INFO "%s: ", drive->name);
//	printk("TF.0=x%02x ", args->tfRegister[IDE_DATA_OFFSET]);
	printk("TF.1=x%02x ", args->tfRegister[IDE_FEATURE_OFFSET]);
	printk("TF.2=x%02x ", args->tfRegister[IDE_NSECTOR_OFFSET]);
	printk("TF.3=x%02x ", args->tfRegister[IDE_SECTOR_OFFSET]);
	printk("TF.4=x%02x ", args->tfRegister[IDE_LCYL_OFFSET]);
	printk("TF.5=x%02x ", args->tfRegister[IDE_HCYL_OFFSET]);
	printk("TF.6=x%02x ", args->tfRegister[IDE_SELECT_OFFSET]);
	printk("TF.7=x%02x\n", args->tfRegister[IDE_COMMAND_OFFSET]);
	printk(KERN_INFO "%s: ", drive->name);
//	printk("HTF.0=x%02x ", args->hobRegister[IDE_DATA_OFFSET_HOB]);
	printk("HTF.1=x%02x ", args->hobRegister[IDE_FEATURE_OFFSET_HOB]);
	printk("HTF.2=x%02x ", args->hobRegister[IDE_NSECTOR_OFFSET_HOB]);
	printk("HTF.3=x%02x ", args->hobRegister[IDE_SECTOR_OFFSET_HOB]);
	printk("HTF.4=x%02x ", args->hobRegister[IDE_LCYL_OFFSET_HOB]);
	printk("HTF.5=x%02x ", args->hobRegister[IDE_HCYL_OFFSET_HOB]);
	printk("HTF.6=x%02x ", args->hobRegister[IDE_SELECT_OFFSET_HOB]);
	printk("HTF.7=x%02x\n", args->hobRegister[IDE_CONTROL_OFFSET_HOB]);
	}
#endif /* CONFIG_IDE_TASK_IOCTL_DEBUG */

//			if (args->tf_out_flags.all == 0) {
 			do_taskfile(drive,
 				(struct hd_drive_task_hdr *)&args->tfRegister,
				(struct hd_drive_hob_hdr *)&args->hobRegister,
 				args->handler);
//			} else {
//				return flagged_taskfile(drive, args);
//			} 

 			if (((args->command_type == IDE_DRIVE_TASK_RAW_WRITE) ||
 			     (args->command_type == IDE_DRIVE_TASK_OUT)) &&
			      args->prehandler && args->handler)
				return args->prehandler(drive, rq);
 			return ide_started;
 		}
 		case IDE_DRIVE_TASK:
 		{
 			byte *args = rq->buffer;
 			byte sel;
 
 			if (!(args)) break;
#ifdef DEBUG
 			printk("%s: DRIVE_TASK_CMD ", drive->name);
 			printk("cmd=0x%02x ", args[0]);
 			printk("fr=0x%02x ", args[1]);
 			printk("ns=0x%02x ", args[2]);
 			printk("sc=0x%02x ", args[3]);
 			printk("lcyl=0x%02x ", args[4]);
 			printk("hcyl=0x%02x ", args[5]);
 			printk("sel=0x%02x\n", args[6]);
#endif
 			OUT_BYTE(args[1], IDE_FEATURE_REG);
 			OUT_BYTE(args[3], IDE_SECTOR_REG);
 			OUT_BYTE(args[4], IDE_LCYL_REG);
 			OUT_BYTE(args[5], IDE_HCYL_REG);
 			sel = (args[6] & ~0x10);
 			if (drive->select.b.unit)
 				sel |= 0x10;
 			OUT_BYTE(sel, IDE_SELECT_REG);
 			ide_cmd(drive, args[0], args[2], &drive_cmd_intr);
 			return ide_started;
 		}
 		case IDE_DRIVE_CMD:
 		{
 			byte *args = rq->buffer;
 
 			if (!(args)) break;
#ifdef DEBUG
 			printk("%s: DRIVE_CMD ", drive->name);
 			printk("cmd=0x%02x ", args[0]);
 			printk("sc=0x%02x ", args[1]);
 			printk("fr=0x%02x ", args[2]);
 			printk("xx=0x%02x\n", args[3]);
#endif
 			if (args[0] == WIN_SMART) {
 				OUT_BYTE(0x4f, IDE_LCYL_REG);
 				OUT_BYTE(0xc2, IDE_HCYL_REG);
 				OUT_BYTE(args[2],IDE_FEATURE_REG);
 				OUT_BYTE(args[1],IDE_SECTOR_REG);
 				ide_cmd(drive, args[0], args[3], &drive_cmd_intr);
 				return ide_started;
 			}
 			OUT_BYTE(args[2],IDE_FEATURE_REG);
 			ide_cmd(drive, args[0], args[1], &drive_cmd_intr);
 			return ide_started;
 		}
 		default:
 			break;
 	}
 	/*
 	 * NULL is actually a valid way of waiting for
 	 * all current requests to be flushed from the queue.
 	 */
#ifdef DEBUG
 	printk("%s: DRIVE_CMD (null)\n", drive->name);
#endif
 	ide_end_drive_cmd(drive, GET_STAT(), GET_ERR());
 	return ide_stopped;
}

/*
 * start_request() initiates handling of a new I/O request
 * needed to reverse the perverted changes anonymously made back
 * 2.3.99-pre6
 */
static ide_startstop_t start_request (ide_drive_t *drive, struct request *rq)
{
	ide_startstop_t startstop;
	unsigned long block, blockend;
	unsigned int minor = MINOR(rq->rq_dev), unit = minor >> PARTN_BITS;
	ide_hwif_t *hwif = HWIF(drive);

#ifdef DEBUG
	printk("%s: start_request: current=0x%08lx\n", hwif->name, (unsigned long) rq);
#endif
	/* bail early if we've exceeded max_failures */
	if (drive->max_failures && (drive->failures > drive->max_failures)) {
		goto kill_rq;
	}

	if (unit >= MAX_DRIVES) {
		printk("%s: bad device number: %s\n", hwif->name, kdevname(rq->rq_dev));
		goto kill_rq;
	}
#ifdef DEBUG
	if (rq->bh && !buffer_locked(rq->bh)) {
		printk("%s: block not locked\n", drive->name);
		goto kill_rq;
	}
#endif
	block    = rq->sector;
	blockend = block + rq->nr_sectors;

	if ((rq->cmd == READ || rq->cmd == WRITE) &&
	    (drive->media == ide_disk || drive->media == ide_floppy)) {
		if ((blockend < block) || (blockend > drive->part[minor&PARTN_MASK].nr_sects)) {
			printk("%s%c: bad access: block=%ld, count=%ld\n", drive->name,
			 (minor&PARTN_MASK)?'0'+(minor&PARTN_MASK):' ', block, rq->nr_sectors);
			goto kill_rq;
		}
		block += drive->part[minor&PARTN_MASK].start_sect + drive->sect0;
	}
	/* Yecch - this will shift the entire interval,
	   possibly killing some innocent following sector */
	if (block == 0 && drive->remap_0_to_1 == 1)
		block = 1;  /* redirect MBR access to EZ-Drive partn table */

#if (DISK_RECOVERY_TIME > 0)
	while ((read_timer() - hwif->last_time) < DISK_RECOVERY_TIME);
#endif

	SELECT_DRIVE(hwif, drive);
	if (ide_wait_stat(&startstop, drive, drive->ready_stat, BUSY_STAT|DRQ_STAT, WAIT_READY)) {
		printk("%s: drive not ready for command\n", drive->name);
		return startstop;
	}
	if (!drive->special.all) {
		switch(rq->cmd) {
			case IDE_DRIVE_CMD:
			case IDE_DRIVE_TASK:
			case IDE_DRIVE_TASKFILE:
				return execute_drive_cmd(drive, rq);
			default:
				break;
		}
		if (drive->driver != NULL) {
			return (DRIVER(drive)->do_request(drive, rq, block));
		}
		printk("%s: media type %d not supported\n", drive->name, drive->media);
		goto kill_rq;
	}
	return do_special(drive);
kill_rq:
	if (drive->driver != NULL)
		DRIVER(drive)->end_request(0, HWGROUP(drive));
	else
		ide_end_request(0, HWGROUP(drive));
	return ide_stopped;
}

ide_startstop_t restart_request (ide_drive_t *drive)
{
	ide_hwgroup_t *hwgroup = HWGROUP(drive);
	unsigned long flags;
	struct request *rq;

	spin_lock_irqsave(&io_request_lock, flags);
	hwgroup->handler = NULL;
	del_timer(&hwgroup->timer);
	rq = hwgroup->rq;
	spin_unlock_irqrestore(&io_request_lock, flags);

	return start_request(drive, rq);
}

/*
 * ide_stall_queue() can be used by a drive to give excess bandwidth back
 * to the hwgroup by sleeping for timeout jiffies.
 */
void ide_stall_queue (ide_drive_t *drive, unsigned long timeout)
{
	if (timeout > WAIT_WORSTCASE)
		timeout = WAIT_WORSTCASE;
	drive->sleep = timeout + jiffies;
}

#define WAKEUP(drive)	((drive)->service_start + 2 * (drive)->service_time)

/*
 * choose_drive() selects the next drive which will be serviced.
 */
static inline ide_drive_t *choose_drive (ide_hwgroup_t *hwgroup)
{
	ide_drive_t *drive, *best;

repeat:	
	best = NULL;
	drive = hwgroup->drive;
	do {
		if (!list_empty(&drive->queue.queue_head) && (!drive->sleep || 0 <= (signed long)(jiffies - drive->sleep))) {
			if (!best
			 || (drive->sleep && (!best->sleep || 0 < (signed long)(best->sleep - drive->sleep)))
			 || (!best->sleep && 0 < (signed long)(WAKEUP(best) - WAKEUP(drive))))
			{
				if( !drive->queue.plugged )
					best = drive;
			}
		}
	} while ((drive = drive->next) != hwgroup->drive);
	if (best && best->nice1 && !best->sleep && best != hwgroup->drive && best->service_time > WAIT_MIN_SLEEP) {
		long t = (signed long)(WAKEUP(best) - jiffies);
		if (t >= WAIT_MIN_SLEEP) {
			/*
			 * We *may* have some time to spare, but first let's see if
			 * someone can potentially benefit from our nice mood today..
			 */
			drive = best->next;
			do {
				if (!drive->sleep
				 && 0 < (signed long)(WAKEUP(drive) - (jiffies - best->service_time))
				 && 0 < (signed long)((jiffies + t) - WAKEUP(drive)))
				{
					ide_stall_queue(best, IDE_MIN(t, 10 * WAIT_MIN_SLEEP));
					goto repeat;
				}
			} while ((drive = drive->next) != best);
		}
	}
	return best;
}

/*
 * Issue a new request to a drive from hwgroup
 * Caller must have already done spin_lock_irqsave(&io_request_lock, ..);
 *
 * A hwgroup is a serialized group of IDE interfaces.  Usually there is
 * exactly one hwif (interface) per hwgroup, but buggy controllers (eg. CMD640)
 * may have both interfaces in a single hwgroup to "serialize" access.
 * Or possibly multiple ISA interfaces can share a common IRQ by being grouped
 * together into one hwgroup for serialized access.
 *
 * Note also that several hwgroups can end up sharing a single IRQ,
 * possibly along with many other devices.  This is especially common in
 * PCI-based systems with off-board IDE controller cards.
 *
 * The IDE driver uses the single global io_request_lock spinlock to protect
 * access to the request queues, and to protect the hwgroup->busy flag.
 *
 * The first thread into the driver for a particular hwgroup sets the
 * hwgroup->busy flag to indicate that this hwgroup is now active,
 * and then initiates processing of the top request from the request queue.
 *
 * Other threads attempting entry notice the busy setting, and will simply
 * queue their new requests and exit immediately.  Note that hwgroup->busy
 * remains set even when the driver is merely awaiting the next interrupt.
 * Thus, the meaning is "this hwgroup is busy processing a request".
 *
 * When processing of a request completes, the completing thread or IRQ-handler
 * will start the next request from the queue.  If no more work remains,
 * the driver will clear the hwgroup->busy flag and exit.
 *
 * The io_request_lock (spinlock) is used to protect all access to the
 * hwgroup->busy flag, but is otherwise not needed for most processing in
 * the driver.  This makes the driver much more friendlier to shared IRQs
 * than previous designs, while remaining 100% (?) SMP safe and capable.
 */
/* --BenH: made non-static as ide-pmac.c uses it to kick the hwgroup back
 *         into life on wakeup from machine sleep.
 */ 
void ide_do_request (ide_hwgroup_t *hwgroup, int masked_irq)
{
	ide_drive_t	*drive;
	ide_hwif_t	*hwif;
	struct request	*rq;
	ide_startstop_t	startstop;

	ide_get_lock(&ide_lock, ide_intr, hwgroup);	/* for atari only: POSSIBLY BROKEN HERE(?) */

	__cli();	/* necessary paranoia: ensure IRQs are masked on local CPU */

	while (!hwgroup->busy) {
		hwgroup->busy = 1;
		drive = choose_drive(hwgroup);
		if (drive == NULL) {
			unsigned long sleep = 0;
			hwgroup->rq = NULL;
			drive = hwgroup->drive;
			do {
				if (drive->sleep && (!sleep || 0 < (signed long)(sleep - drive->sleep)))
					sleep = drive->sleep;
			} while ((drive = drive->next) != hwgroup->drive);
			if (sleep) {
				/*
				 * Take a short snooze, and then wake up this hwgroup again.
				 * This gives other hwgroups on the same a chance to
				 * play fairly with us, just in case there are big differences
				 * in relative throughputs.. don't want to hog the cpu too much.
				 */
				if (0 < (signed long)(jiffies + WAIT_MIN_SLEEP - sleep)) 
					sleep = jiffies + WAIT_MIN_SLEEP;
#if 1
				if (timer_pending(&hwgroup->timer))
					printk("ide_set_handler: timer already active\n");
#endif
				hwgroup->sleeping = 1;	/* so that ide_timer_expiry knows what to do */
				mod_timer(&hwgroup->timer, sleep);
				/* we purposely leave hwgroup->busy==1 while sleeping */
			} else {
				/* Ugly, but how can we sleep for the lock otherwise? perhaps from tq_disk? */
				ide_release_lock(&ide_lock);	/* for atari only */
				hwgroup->busy = 0;
			}
			return;		/* no more work for this hwgroup (for now) */
		}
		hwif = HWIF(drive);
		if (hwgroup->hwif->sharing_irq && hwif != hwgroup->hwif && hwif->io_ports[IDE_CONTROL_OFFSET]) {
			/* set nIEN for previous hwif */
			SELECT_INTERRUPT(hwif, drive);
		}
		hwgroup->hwif = hwif;
		hwgroup->drive = drive;
		drive->sleep = 0;
		drive->service_start = jiffies;

		if ( drive->queue.plugged )	/* paranoia */
			printk("%s: Huh? nuking plugged queue\n", drive->name);

		rq = hwgroup->rq = blkdev_entry_next_request(&drive->queue.queue_head);
		/*
		 * Some systems have trouble with IDE IRQs arriving while
		 * the driver is still setting things up.  So, here we disable
		 * the IRQ used by this interface while the request is being started.
		 * This may look bad at first, but pretty much the same thing
		 * happens anyway when any interrupt comes in, IDE or otherwise
		 *  -- the kernel masks the IRQ while it is being handled.
		 */
		if (masked_irq && hwif->irq != masked_irq)
			disable_irq_nosync(hwif->irq);
		spin_unlock(&io_request_lock);
		ide__sti();	/* allow other IRQs while we start this request */
		startstop = start_request(drive, rq);
		spin_lock_irq(&io_request_lock);
		if (masked_irq && hwif->irq != masked_irq)
			enable_irq(hwif->irq);
		if (startstop == ide_stopped)
			hwgroup->busy = 0;
	}
}

/*
 * ide_get_queue() returns the queue which corresponds to a given device.
 */
request_queue_t *ide_get_queue (kdev_t dev)
{
	ide_hwif_t *hwif = (ide_hwif_t *)blk_dev[MAJOR(dev)].data;

	return &hwif->drives[DEVICE_NR(dev) & 1].queue;
}

/*
 * Passes the stuff to ide_do_request
 */
void do_ide_request(request_queue_t *q)
{
	ide_do_request(q->queuedata, 0);
}

/*
 * un-busy the hwgroup etc, and clear any pending DMA status. we want to
 * retry the current request in pio mode instead of risking tossing it
 * all away
 */
void ide_dma_timeout_retry(ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	struct request *rq;

	/*
	 * end current dma transaction
	 */
	(void) hwif->dmaproc(ide_dma_end, drive);

	/*
	 * complain a little, later we might remove some of this verbosity
	 */
	printk("%s: timeout waiting for DMA\n", drive->name);
	(void) hwif->dmaproc(ide_dma_timeout, drive);

	/*
	 * disable dma for now, but remember that we did so because of
	 * a timeout -- we'll reenable after we finish this next request
	 * (or rather the first chunk of it) in pio.
	 */
	drive->retry_pio++;
	drive->state = DMA_PIO_RETRY;
	(void) hwif->dmaproc(ide_dma_off_quietly, drive);

	/*
	 * un-busy drive etc (hwgroup->busy is cleared on return) and
	 * make sure request is sane
	 */
	rq = HWGROUP(drive)->rq;
	HWGROUP(drive)->rq = NULL;

	rq->errors = 0;
	rq->sector = rq->bh->b_rsector;
	rq->current_nr_sectors = rq->bh->b_size >> 9;
	rq->buffer = rq->bh->b_data;
}

/*
 * ide_timer_expiry() is our timeout function for all drive operations.
 * But note that it can also be invoked as a result of a "sleep" operation
 * triggered by the mod_timer() call in ide_do_request.
 */
void ide_timer_expiry (unsigned long data)
{
	ide_hwgroup_t	*hwgroup = (ide_hwgroup_t *) data;
	ide_handler_t	*handler;
	ide_expiry_t	*expiry;
 	unsigned long	flags;
	unsigned long	wait;

	spin_lock_irqsave(&io_request_lock, flags);
	del_timer(&hwgroup->timer);

	if ((handler = hwgroup->handler) == NULL) {
		/*
		 * Either a marginal timeout occurred
		 * (got the interrupt just as timer expired),
		 * or we were "sleeping" to give other devices a chance.
		 * Either way, we don't really want to complain about anything.
		 */
		if (hwgroup->sleeping) {
			hwgroup->sleeping = 0;
			hwgroup->busy = 0;
		}
	} else {
		ide_drive_t *drive = hwgroup->drive;
		if (!drive) {
			printk("ide_timer_expiry: hwgroup->drive was NULL\n");
			hwgroup->handler = NULL;
		} else {
			ide_hwif_t *hwif;
			ide_startstop_t startstop;
			if (!hwgroup->busy) {
				hwgroup->busy = 1;	/* paranoia */
				printk("%s: ide_timer_expiry: hwgroup->busy was 0 ??\n", drive->name);
			}
			if ((expiry = hwgroup->expiry) != NULL) {
				/* continue */
				if ((wait = expiry(drive)) != 0) {
					/* reset timer */
					hwgroup->timer.expires  = jiffies + wait;
					add_timer(&hwgroup->timer);
					spin_unlock_irqrestore(&io_request_lock, flags);
					return;
				}
			}
			hwgroup->handler = NULL;
			/*
			 * We need to simulate a real interrupt when invoking
			 * the handler() function, which means we need to globally
			 * mask the specific IRQ:
			 */
			spin_unlock(&io_request_lock);
			hwif  = HWIF(drive);
#if DISABLE_IRQ_NOSYNC
			disable_irq_nosync(hwif->irq);
#else
			disable_irq(hwif->irq);	/* disable_irq_nosync ?? */
#endif /* DISABLE_IRQ_NOSYNC */
			__cli();	/* local CPU only, as if we were handling an interrupt */
			if (hwgroup->poll_timeout != 0) {
				startstop = handler(drive);
			} else if (drive_is_ready(drive)) {
				if (drive->waiting_for_dma)
					(void) hwgroup->hwif->dmaproc(ide_dma_lostirq, drive);
				(void)ide_ack_intr(hwif);
				printk("%s: lost interrupt\n", drive->name);
				startstop = handler(drive);
			} else {
				if (drive->waiting_for_dma) {
					startstop = ide_stopped;
					ide_dma_timeout_retry(drive);
				} else
					startstop = ide_error(drive, "irq timeout", GET_STAT());
			}
			set_recovery_timer(hwif);
			drive->service_time = jiffies - drive->service_start;
			enable_irq(hwif->irq);
			spin_lock_irq(&io_request_lock);
			if (startstop == ide_stopped)
				hwgroup->busy = 0;
		}
	}
	ide_do_request(hwgroup, 0);
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * There's nothing really useful we can do with an unexpected interrupt,
 * other than reading the status register (to clear it), and logging it.
 * There should be no way that an irq can happen before we're ready for it,
 * so we needn't worry much about losing an "important" interrupt here.
 *
 * On laptops (and "green" PCs), an unexpected interrupt occurs whenever the
 * drive enters "idle", "standby", or "sleep" mode, so if the status looks
 * "good", we just ignore the interrupt completely.
 *
 * This routine assumes __cli() is in effect when called.
 *
 * If an unexpected interrupt happens on irq15 while we are handling irq14
 * and if the two interfaces are "serialized" (CMD640), then it looks like
 * we could screw up by interfering with a new request being set up for irq15.
 *
 * In reality, this is a non-issue.  The new command is not sent unless the
 * drive is ready to accept one, in which case we know the drive is not
 * trying to interrupt us.  And ide_set_handler() is always invoked before
 * completing the issuance of any new drive command, so we will not be
 * accidentally invoked as a result of any valid command completion interrupt.
 *
 */
static void unexpected_intr (int irq, ide_hwgroup_t *hwgroup)
{
	byte stat;
	ide_hwif_t *hwif = hwgroup->hwif;

	/*
	 * handle the unexpected interrupt
	 */
	do {
		if (hwif->irq == irq) {
			stat = IN_BYTE(hwif->io_ports[IDE_STATUS_OFFSET]);
			if (!OK_STAT(stat, READY_STAT, BAD_STAT)) {
				/* Try to not flood the console with msgs */
				static unsigned long last_msgtime, count;
				++count;
				if (0 < (signed long)(jiffies - (last_msgtime + HZ))) {
					last_msgtime = jiffies;
					printk("%s%s: unexpected interrupt, status=0x%02x, count=%ld\n",
					 hwif->name, (hwif->next == hwgroup->hwif) ? "" : "(?)", stat, count);
				}
			}
		}
	} while ((hwif = hwif->next) != hwgroup->hwif);
}

/*
 * entry point for all interrupts, caller does __cli() for us
 */
void ide_intr (int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned long flags;
	ide_hwgroup_t *hwgroup = (ide_hwgroup_t *)dev_id;
	ide_hwif_t *hwif;
	ide_drive_t *drive;
	ide_handler_t *handler;
	ide_startstop_t startstop;

	spin_lock_irqsave(&io_request_lock, flags);
	hwif = hwgroup->hwif;

	if (!ide_ack_intr(hwif)) {
		spin_unlock_irqrestore(&io_request_lock, flags);
		return;
	}

	if ((handler = hwgroup->handler) == NULL || hwgroup->poll_timeout != 0) {
		/*
		 * Not expecting an interrupt from this drive.
		 * That means this could be:
		 *	(1) an interrupt from another PCI device
		 *	sharing the same PCI INT# as us.
		 * or	(2) a drive just entered sleep or standby mode,
		 *	and is interrupting to let us know.
		 * or	(3) a spurious interrupt of unknown origin.
		 *
		 * For PCI, we cannot tell the difference,
		 * so in that case we just ignore it and hope it goes away.
		 */
#ifdef CONFIG_BLK_DEV_IDEPCI
		if (IDE_PCI_DEVID_EQ(hwif->pci_devid, IDE_PCI_DEVID_NULL))
#endif	/* CONFIG_BLK_DEV_IDEPCI */
		{
			/*
			 * Probably not a shared PCI interrupt,
			 * so we can safely try to do something about it:
			 */
			unexpected_intr(irq, hwgroup);
#ifdef CONFIG_BLK_DEV_IDEPCI
		} else {
			/*
			 * Whack the status register, just in case we have a leftover pending IRQ.
			 */
			(void) IN_BYTE(hwif->io_ports[IDE_STATUS_OFFSET]);
#endif /* CONFIG_BLK_DEV_IDEPCI */
		}
		spin_unlock_irqrestore(&io_request_lock, flags);
		return;
	}
	drive = hwgroup->drive;
	if (!drive) {
		/*
		 * This should NEVER happen, and there isn't much we could do about it here.
		 */
		spin_unlock_irqrestore(&io_request_lock, flags);
		return;
	}
	if (!drive_is_ready(drive)) {
		/*
		 * This happens regularly when we share a PCI IRQ with another device.
		 * Unfortunately, it can also happen with some buggy drives that trigger
		 * the IRQ before their status register is up to date.  Hopefully we have
		 * enough advance overhead that the latter isn't a problem.
		 */
		spin_unlock_irqrestore(&io_request_lock, flags);
		return;
	}
	if (!hwgroup->busy) {
		hwgroup->busy = 1;	/* paranoia */
		printk("%s: ide_intr: hwgroup->busy was 0 ??\n", drive->name);
	}
	hwgroup->handler = NULL;
	del_timer(&hwgroup->timer);
	spin_unlock(&io_request_lock);

	if (drive->unmask)
		ide__sti();	/* local CPU only */
	startstop = handler(drive);		/* service this interrupt, may set handler for next interrupt */
	spin_lock_irq(&io_request_lock);

	/*
	 * Note that handler() may have set things up for another
	 * interrupt to occur soon, but it cannot happen until
	 * we exit from this routine, because it will be the
	 * same irq as is currently being serviced here, and Linux
	 * won't allow another of the same (on any CPU) until we return.
	 */
	set_recovery_timer(HWIF(drive));
	drive->service_time = jiffies - drive->service_start;
	if (startstop == ide_stopped) {
		if (hwgroup->handler == NULL) {	/* paranoia */
			hwgroup->busy = 0;
			ide_do_request(hwgroup, hwif->irq);
		} else {
			printk("%s: ide_intr: huh? expected NULL handler on exit\n", drive->name);
		}
	}
	spin_unlock_irqrestore(&io_request_lock, flags);
}

/*
 * get_info_ptr() returns the (ide_drive_t *) for a given device number.
 * It returns NULL if the given device number does not match any present drives.
 */
ide_drive_t *get_info_ptr (kdev_t i_rdev)
{
	int		major = MAJOR(i_rdev);
#if 0
	int		minor = MINOR(i_rdev) & PARTN_MASK;
#endif
	unsigned int	h;

	for (h = 0; h < MAX_HWIFS; ++h) {
		ide_hwif_t  *hwif = &ide_hwifs[h];
		if (hwif->present && major == hwif->major) {
			unsigned unit = DEVICE_NR(i_rdev);
			if (unit < MAX_DRIVES) {
				ide_drive_t *drive = &hwif->drives[unit];
#if 0
				if ((drive->present) && (drive->part[minor].nr_sects))
#else
				if (drive->present)
#endif
					return drive;
			}
			break;
		}
	}
	return NULL;
}

/*
 * This function is intended to be used prior to invoking ide_do_drive_cmd().
 */
void ide_init_drive_cmd (struct request *rq)
{
	memset(rq, 0, sizeof(*rq));
	rq->cmd = IDE_DRIVE_CMD;
}

/*
 * This function issues a special IDE device request
 * onto the request queue.
 *
 * If action is ide_wait, then the rq is queued at the end of the
 * request queue, and the function sleeps until it has been processed.
 * This is for use when invoked from an ioctl handler.
 *
 * If action is ide_preempt, then the rq is queued at the head of
 * the request queue, displacing the currently-being-processed
 * request and this function returns immediately without waiting
 * for the new rq to be completed.  This is VERY DANGEROUS, and is
 * intended for careful use by the ATAPI tape/cdrom driver code.
 *
 * If action is ide_next, then the rq is queued immediately after
 * the currently-being-processed-request (if any), and the function
 * returns without waiting for the new rq to be completed.  As above,
 * This is VERY DANGEROUS, and is intended for careful use by the
 * ATAPI tape/cdrom driver code.
 *
 * If action is ide_end, then the rq is queued at the end of the
 * request queue, and the function returns immediately without waiting
 * for the new rq to be completed. This is again intended for careful
 * use by the ATAPI tape/cdrom driver code.
 */
int ide_do_drive_cmd (ide_drive_t *drive, struct request *rq, ide_action_t action)
{
	unsigned long flags;
	ide_hwgroup_t *hwgroup = HWGROUP(drive);
	unsigned int major = HWIF(drive)->major;
	struct list_head *queue_head = &drive->queue.queue_head;
	/*DECLARE_COMPLETION(wait);*/

#ifdef CONFIG_BLK_DEV_PDC4030
	if (HWIF(drive)->chipset == ide_pdc4030 && rq->buffer != NULL)
		return -ENOSYS;  /* special drive cmds not supported */
#endif
	rq->errors = 0;
	rq->rq_status = RQ_ACTIVE;
	rq->rq_dev = MKDEV(major,(drive->select.b.unit)<<PARTN_BITS);
	if (action == ide_wait) { 
		printk("SMH says: wait on IDE device but no queue :-(\n"); 
		return 0; 
	} 
	spin_lock_irqsave(&io_request_lock, flags);
	if (list_empty(queue_head) || action == ide_preempt) {
		if (action == ide_preempt)
			hwgroup->rq = NULL;
	} else {
		if (action == ide_wait || action == ide_end) {
			queue_head = queue_head->prev;
		} else
			queue_head = queue_head->next;
	}
	list_add(&rq->queue, queue_head);
	ide_do_request(hwgroup, 0);
	spin_unlock_irqrestore(&io_request_lock, flags);
	return 0;

}

/*
 * This routine is called to flush all partitions and partition tables
 * for a changed disk, and then re-read the new partition table.
 * If we are revalidating a disk because of a media change, then we
 * enter with usage == 0.  If we are using an ioctl, we automatically have
 * usage == 1 (we need an open channel to use an ioctl :-), so this
 * is our limit.
 */
int ide_revalidate_disk (kdev_t i_rdev)
{
	ide_drive_t *drive;
	ide_hwgroup_t *hwgroup;
	unsigned int p, major, minor;
	unsigned long flags;

	if ((drive = get_info_ptr(i_rdev)) == NULL)
		return -ENODEV;
	major = MAJOR(i_rdev);
	minor = drive->select.b.unit << PARTN_BITS;
	hwgroup = HWGROUP(drive);
	spin_lock_irqsave(&io_request_lock, flags);
	if (drive->busy || (drive->usage > 1)) {
		spin_unlock_irqrestore(&io_request_lock, flags);
		return -EBUSY;
	};
	drive->busy = 1;
	MOD_INC_USE_COUNT;
	spin_unlock_irqrestore(&io_request_lock, flags);

	for (p = 0; p < (1<<PARTN_BITS); ++p) {
		if (drive->part[p].nr_sects > 0) {
			kdev_t devp = MKDEV(major, minor+p);
			invalidate_device(devp, 1);
		}
		drive->part[p].start_sect = 0;
		drive->part[p].nr_sects   = 0;
	};

	if (DRIVER(drive)->revalidate)
		DRIVER(drive)->revalidate(drive);

	drive->busy = 0;
	/*wake_up(&drive->wqueue);*/
	MOD_DEC_USE_COUNT;
	return 0;
}

static void revalidate_drives (void)
{
	ide_hwif_t *hwif;
	ide_drive_t *drive;
	int index, unit;

	for (index = 0; index < MAX_HWIFS; ++index) {
		hwif = &ide_hwifs[index];
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			drive = &ide_hwifs[index].drives[unit];
			if (drive->revalidate) {
				drive->revalidate = 0;
				if (!initializing)
					(void) ide_revalidate_disk(MKDEV(hwif->major, unit<<PARTN_BITS));
			}
		}
	}
}

static void ide_probe_module (void)
{
	if (!ide_probe) {
#if defined(CONFIG_KMOD) && defined(CONFIG_BLK_DEV_IDE_MODULE)
		(void) request_module("ide-probe-mod");
#endif /* (CONFIG_KMOD) && (CONFIG_BLK_DEV_IDE_MODULE) */
	} else {
		(void) ide_probe->init();
	}
	revalidate_drives();
}

static void ide_driver_module (void)
{
	int index;
	ide_module_t *module = ide_modules;

	for (index = 0; index < MAX_HWIFS; ++index)
		if (ide_hwifs[index].present)
			goto search;
	ide_probe_module();
search:
	while (module) {
		(void) module->init();
		module = module->next;
	}
	revalidate_drives();
}

static int ide_open (struct inode * inode, struct file * filp)
{
	ide_drive_t *drive;

	if ((drive = get_info_ptr(inode->i_rdev)) == NULL)
		return -ENXIO;
	if (drive->driver == NULL)
		ide_driver_module();
#ifdef CONFIG_KMOD
	if (drive->driver == NULL) {
		if (drive->media == ide_disk)
			(void) request_module("ide-disk");
		if (drive->media == ide_cdrom)
			(void) request_module("ide-cd");
		if (drive->media == ide_tape)
			(void) request_module("ide-tape");
		if (drive->media == ide_floppy)
			(void) request_module("ide-floppy");
#if defined(CONFIG_BLK_DEV_IDESCSI) && defined(CONFIG_SCSI)
		if (drive->media == ide_scsi)
			(void) request_module("ide-scsi");
#endif /* defined(CONFIG_BLK_DEV_IDESCSI) && defined(CONFIG_SCSI) */
	}
#endif /* CONFIG_KMOD */
#if 0
	while (drive->busy)
		sleep_on(&drive->wqueue);
#endif
	drive->usage++;
	if (drive->driver != NULL)
		return DRIVER(drive)->open(inode, filp, drive);
	printk ("%s: driver not present\n", drive->name);
	drive->usage--;
	return -ENXIO;
}

/*
 * Releasing a block device means we sync() it, so that it can safely
 * be forgotten about...
 */
static int ide_release (struct inode * inode, struct file * file)
{
	ide_drive_t *drive;

	if ((drive = get_info_ptr(inode->i_rdev)) != NULL) {
		drive->usage--;
		if (drive->driver != NULL)
			DRIVER(drive)->release(inode, file, drive);
	}
	return 0;
}

int ide_replace_subdriver (ide_drive_t *drive, const char *driver)
{
	if (!drive->present || drive->busy || drive->usage)
		goto abort;
	if (drive->driver != NULL && DRIVER(drive)->cleanup(drive))
		goto abort;
	strncpy(drive->driver_req, driver, 9);
	ide_driver_module();
	drive->driver_req[0] = 0;
	ide_driver_module();
	if (DRIVER(drive) && !strcmp(DRIVER(drive)->name, driver))
		return 0;
abort:
	return 1;
}

#ifdef CONFIG_PROC_FS
ide_proc_entry_t generic_subdriver_entries[] = {
	{ "capacity",	S_IFREG|S_IRUGO,	proc_ide_read_capacity,	NULL },
	{ NULL, 0, NULL, NULL }
};
#endif

/*
 * Note that we only release the standard ports,
 * and do not even try to handle any extra ports
 * allocated for weird IDE interface chipsets.
 */
void hwif_unregister (ide_hwif_t *hwif)
{
	if (hwif->straight8) {
		ide_release_region(hwif->io_ports[IDE_DATA_OFFSET], 8);
		goto jump_eight;
	}
	if (hwif->io_ports[IDE_DATA_OFFSET])
		ide_release_region(hwif->io_ports[IDE_DATA_OFFSET], 1);
	if (hwif->io_ports[IDE_ERROR_OFFSET])
		ide_release_region(hwif->io_ports[IDE_ERROR_OFFSET], 1);
	if (hwif->io_ports[IDE_NSECTOR_OFFSET])
		ide_release_region(hwif->io_ports[IDE_NSECTOR_OFFSET], 1);
	if (hwif->io_ports[IDE_SECTOR_OFFSET])
		ide_release_region(hwif->io_ports[IDE_SECTOR_OFFSET], 1);
	if (hwif->io_ports[IDE_LCYL_OFFSET])
		ide_release_region(hwif->io_ports[IDE_LCYL_OFFSET], 1);
	if (hwif->io_ports[IDE_HCYL_OFFSET])
		ide_release_region(hwif->io_ports[IDE_HCYL_OFFSET], 1);
	if (hwif->io_ports[IDE_SELECT_OFFSET])
		ide_release_region(hwif->io_ports[IDE_SELECT_OFFSET], 1);
	if (hwif->io_ports[IDE_STATUS_OFFSET])
		ide_release_region(hwif->io_ports[IDE_STATUS_OFFSET], 1);
jump_eight:
	if (hwif->io_ports[IDE_CONTROL_OFFSET])
		ide_release_region(hwif->io_ports[IDE_CONTROL_OFFSET], 1);
#if defined(CONFIG_AMIGA) || defined(CONFIG_MAC)
	if (hwif->io_ports[IDE_IRQ_OFFSET])
		ide_release_region(hwif->io_ports[IDE_IRQ_OFFSET], 1);
#endif /* (CONFIG_AMIGA) || (CONFIG_MAC) */
}

void ide_unregister (unsigned int index)
{
	struct gendisk *gd;
	ide_drive_t *drive, *d;
	ide_hwif_t *hwif, *g;
	ide_hwgroup_t *hwgroup;
	int irq_count = 0, unit, i;
	unsigned long flags;
	unsigned int p, minor;
	ide_hwif_t old_hwif;

	if (index >= MAX_HWIFS)
		return;
	save_flags(flags);	/* all CPUs */
	cli();			/* all CPUs */
	hwif = &ide_hwifs[index];
	if (!hwif->present)
		goto abort;
	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		drive = &hwif->drives[unit];
		if (!drive->present)
			continue;
		if (drive->busy || drive->usage)
			goto abort;
		if (drive->driver != NULL && DRIVER(drive)->cleanup(drive))
			goto abort;
	}
	hwif->present = 0;
	
	/*
	 * All clear?  Then blow away the buffer cache
	 */
	sti();
	for (unit = 0; unit < MAX_DRIVES; ++unit) {
		drive = &hwif->drives[unit];
		if (!drive->present)
			continue;
		minor = drive->select.b.unit << PARTN_BITS;
		for (p = 0; p < (1<<PARTN_BITS); ++p) {
			if (drive->part[p].nr_sects > 0) {
				kdev_t devp = MKDEV(hwif->major, minor+p);
				invalidate_device(devp, 0);
			}
		}
#ifdef CONFIG_PROC_FS
		destroy_proc_ide_drives(hwif);
#endif
	}
	cli();
	hwgroup = hwif->hwgroup;

	/*
	 * free the irq if we were the only hwif using it
	 */
	g = hwgroup->hwif;
	do {
		if (g->irq == hwif->irq)
			++irq_count;
		g = g->next;
	} while (g != hwgroup->hwif);
	if (irq_count == 1)
		free_irq(hwif->irq, hwgroup);

	/*
	 * Note that we only release the standard ports,
	 * and do not even try to handle any extra ports
	 * allocated for weird IDE interface chipsets.
	 */
	hwif_unregister(hwif);

	/*
	 * Remove us from the hwgroup, and free
	 * the hwgroup if we were the only member
	 */
	d = hwgroup->drive;
	for (i = 0; i < MAX_DRIVES; ++i) {
		drive = &hwif->drives[i];
#ifdef DEVFS_MUST_DIE
		if (drive->de) {
			devfs_unregister (drive->de);
			drive->de = NULL;
		}
#endif
		if (!drive->present)
			continue;
		while (hwgroup->drive->next != drive)
			hwgroup->drive = hwgroup->drive->next;
		hwgroup->drive->next = drive->next;
		if (hwgroup->drive == drive)
			hwgroup->drive = NULL;
		if (drive->id != NULL) {
			kfree(drive->id);
			drive->id = NULL;
		}
		drive->present = 0;
		blk_cleanup_queue(&drive->queue);
	}
	if (d->present)
		hwgroup->drive = d;
	while (hwgroup->hwif->next != hwif)
		hwgroup->hwif = hwgroup->hwif->next;
	hwgroup->hwif->next = hwif->next;
	if (hwgroup->hwif == hwif)
		kfree(hwgroup);
	else
		hwgroup->hwif = HWIF(hwgroup->drive);

#if defined(CONFIG_BLK_DEV_IDEDMA) && !defined(CONFIG_DMA_NONPCI)
	if (hwif->dma_base) {
		(void) ide_release_dma(hwif);
		hwif->dma_base = 0;
	}
#endif /* (CONFIG_BLK_DEV_IDEDMA) && !(CONFIG_DMA_NONPCI) */

	/*
	 * Remove us from the kernel's knowledge
	 */
	unregister_blkdev(hwif->major, hwif->name);
	kfree(blksize_size[hwif->major]);
	kfree(max_sectors[hwif->major]);
	/*kfree(max_readahead[hwif->major]);*/
	blk_dev[hwif->major].data = NULL;
	blk_dev[hwif->major].queue = NULL;
	blksize_size[hwif->major] = NULL;
	gd = hwif->gd;
	if (gd) {
		del_gendisk(gd);
		kfree(gd->sizes);
		kfree(gd->part);
#ifdef DEVFS_MUST_DIE
		if (gd->de_arr)
			kfree (gd->de_arr);
#endif
		if (gd->flags)
			kfree (gd->flags);
		kfree(gd);
		hwif->gd = NULL;
	}
	old_hwif		= *hwif;
	init_hwif_data (index);	/* restore hwif data to pristine status */
	hwif->hwgroup		= old_hwif.hwgroup;
	hwif->tuneproc		= old_hwif.tuneproc;
	hwif->speedproc		= old_hwif.speedproc;
	hwif->selectproc	= old_hwif.selectproc;
	hwif->resetproc		= old_hwif.resetproc;
	hwif->intrproc		= old_hwif.intrproc;
	hwif->maskproc		= old_hwif.maskproc;
	hwif->quirkproc		= old_hwif.quirkproc;
	hwif->rwproc		= old_hwif.rwproc;
	hwif->ideproc		= old_hwif.ideproc;
	hwif->dmaproc		= old_hwif.dmaproc;
	hwif->busproc		= old_hwif.busproc;
	hwif->bus_state		= old_hwif.bus_state;
	hwif->dma_base		= old_hwif.dma_base;
	hwif->dma_extra		= old_hwif.dma_extra;
	hwif->config_data	= old_hwif.config_data;
	hwif->select_data	= old_hwif.select_data;
	hwif->proc		= old_hwif.proc;
#ifndef CONFIG_BLK_DEV_IDECS
	hwif->irq		= old_hwif.irq;
#endif /* CONFIG_BLK_DEV_IDECS */
	hwif->major		= old_hwif.major;
	hwif->chipset		= old_hwif.chipset;
	hwif->autodma		= old_hwif.autodma;
	hwif->udma_four		= old_hwif.udma_four;
#ifdef CONFIG_BLK_DEV_IDEPCI
	hwif->pci_dev		= old_hwif.pci_dev;
	hwif->pci_devid		= old_hwif.pci_devid;
#endif /* CONFIG_BLK_DEV_IDEPCI */
	hwif->straight8		= old_hwif.straight8;
	hwif->hwif_data		= old_hwif.hwif_data;
abort:
	restore_flags(flags);	/* all CPUs */
}

/*
 * Setup hw_regs_t structure described by parameters.  You
 * may set up the hw structure yourself OR use this routine to
 * do it for you.
 */
void ide_setup_ports (	hw_regs_t *hw,
			ide_ioreg_t base, int *offsets,
			ide_ioreg_t ctrl, ide_ioreg_t intr,
			ide_ack_intr_t *ack_intr, int irq)
{
	int i;

	for (i = 0; i < IDE_NR_PORTS; i++) {
		if (offsets[i] == -1) {
			switch(i) {
				case IDE_CONTROL_OFFSET:
					hw->io_ports[i] = ctrl;
					break;
#if defined(CONFIG_AMIGA) || defined(CONFIG_MAC)
				case IDE_IRQ_OFFSET:
					hw->io_ports[i] = intr;
					break;
#endif /* (CONFIG_AMIGA) || (CONFIG_MAC) */
				default:
					hw->io_ports[i] = 0;
					break;
			}
		} else {
			hw->io_ports[i] = base + offsets[i];
		}
	}
	hw->irq = irq;
	hw->dma = NO_DMA;
	hw->ack_intr = ack_intr;
}

/*
 * Register an IDE interface, specifing exactly the registers etc
 * Set init=1 iff calling before probes have taken place.
 */
int ide_register_hw (hw_regs_t *hw, ide_hwif_t **hwifp)
{
	int index, retry = 1;
	ide_hwif_t *hwif;

	do {
		for (index = 0; index < MAX_HWIFS; ++index) {
			hwif = &ide_hwifs[index];
			if (hwif->hw.io_ports[IDE_DATA_OFFSET] == hw->io_ports[IDE_DATA_OFFSET])
				goto found;
		}
		for (index = 0; index < MAX_HWIFS; ++index) {
			hwif = &ide_hwifs[index];
			if ((!hwif->present && !hwif->mate && !initializing) ||
			    (!hwif->hw.io_ports[IDE_DATA_OFFSET] && initializing))
				goto found;
		}
		for (index = 0; index < MAX_HWIFS; index++)
			ide_unregister(index);
	} while (retry--);
	return -1;
found:
	if (hwif->present)
		ide_unregister(index);
	if (hwif->present)
		return -1;
	memcpy(&hwif->hw, hw, sizeof(*hw));
	memcpy(hwif->io_ports, hwif->hw.io_ports, sizeof(hwif->hw.io_ports));
	hwif->irq = hw->irq;
	hwif->noprobe = 0;
	hwif->chipset = hw->chipset;

	if (!initializing) {
		ide_probe_module();
#ifdef CONFIG_PROC_FS
		create_proc_ide_interfaces();
#endif
		ide_driver_module();
	}

	if (hwifp)
		*hwifp = hwif;

	return (initializing || hwif->present) ? index : -1;
}

/*
 * Compatability function with existing drivers.  If you want
 * something different, use the function above.
 */
int ide_register (int arg1, int arg2, int irq)
{
	hw_regs_t hw;
	ide_init_hwif_ports(&hw, (ide_ioreg_t) arg1, (ide_ioreg_t) arg2, NULL);
	hw.irq = irq;
	return ide_register_hw(&hw, NULL);
}

void ide_add_setting (ide_drive_t *drive, const char *name, int rw, int read_ioctl, int write_ioctl, int data_type, int min, int max, int mul_factor, int div_factor, void *data, ide_procset_t *set)
{
	ide_settings_t **p = (ide_settings_t **) &drive->settings, *setting = NULL;

	while ((*p) && strcmp((*p)->name, name) < 0)
		p = &((*p)->next);
	if ((setting = kmalloc(sizeof(*setting), GFP_KERNEL)) == NULL)
		goto abort;
	memset(setting, 0, sizeof(*setting));
	if ((setting->name = kmalloc(strlen(name) + 1, GFP_KERNEL)) == NULL)
		goto abort;
	strcpy(setting->name, name);		setting->rw = rw;
	setting->read_ioctl = read_ioctl;	setting->write_ioctl = write_ioctl;
	setting->data_type = data_type;		setting->min = min;
	setting->max = max;			setting->mul_factor = mul_factor;
	setting->div_factor = div_factor;	setting->data = data;
	setting->set = set;			setting->next = *p;
	if (drive->driver)
		setting->auto_remove = 1;
	*p = setting;
	return;
abort:
	if (setting)
		kfree(setting);
}

void ide_remove_setting (ide_drive_t *drive, char *name)
{
	ide_settings_t **p = (ide_settings_t **) &drive->settings, *setting;

	while ((*p) && strcmp((*p)->name, name))
		p = &((*p)->next);
	if ((setting = (*p)) == NULL)
		return;
	(*p) = setting->next;
	kfree(setting->name);
	kfree(setting);
}

static ide_settings_t *ide_find_setting_by_ioctl (ide_drive_t *drive, int cmd)
{
	ide_settings_t *setting = drive->settings;

	while (setting) {
		if (setting->read_ioctl == cmd || setting->write_ioctl == cmd)
			break;
		setting = setting->next;
	}
	return setting;
}

ide_settings_t *ide_find_setting_by_name (ide_drive_t *drive, char *name)
{
	ide_settings_t *setting = drive->settings;

	while (setting) {
		if (strcmp(setting->name, name) == 0)
			break;
		setting = setting->next;
	}
	return setting;
}

static void auto_remove_settings (ide_drive_t *drive)
{
	ide_settings_t *setting;
repeat:
	setting = drive->settings;
	while (setting) {
		if (setting->auto_remove) {
			ide_remove_setting(drive, setting->name);
			goto repeat;
		}
		setting = setting->next;
	}
}

int ide_read_setting (ide_drive_t *drive, ide_settings_t *setting)
{
	int		val = -EINVAL;
	unsigned long	flags;

	if ((setting->rw & SETTING_READ)) {
		spin_lock_irqsave(&io_request_lock, flags);
		switch(setting->data_type) {
			case TYPE_BYTE:
				val = *((u8 *) setting->data);
				break;
			case TYPE_SHORT:
				val = *((u16 *) setting->data);
				break;
			case TYPE_INT:
			case TYPE_INTA:
				val = *((u32 *) setting->data);
				break;
		}
		spin_unlock_irqrestore(&io_request_lock, flags);
	}
	return val;
}

int ide_spin_wait_hwgroup (ide_drive_t *drive)
{
	ide_hwgroup_t *hwgroup = HWGROUP(drive);
	unsigned long timeout = jiffies + (3 * HZ);

	spin_lock_irq(&io_request_lock);

	while (hwgroup->busy) {
		unsigned long lflags;
		spin_unlock_irq(&io_request_lock);
		__save_flags(lflags);	/* local CPU only */
		__sti();		/* local CPU only; needed for jiffies */
		if (0 < (signed long)(jiffies - timeout)) {
			__restore_flags(lflags);	/* local CPU only */
			printk("%s: channel busy\n", drive->name);
			return -EBUSY;
		}
		__restore_flags(lflags);	/* local CPU only */
		spin_lock_irq(&io_request_lock);
	}
	return 0;
}

/*
 * FIXME:  This should be changed to enqueue a special request
 * to the driver to change settings, and then wait on a sema for completion.
 * The current scheme of polling is kludgey, though safe enough.
 */
int ide_write_setting (ide_drive_t *drive, ide_settings_t *setting, int val)
{
	int i;
	u32 *p;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (!(setting->rw & SETTING_WRITE))
		return -EPERM;
	if (val < setting->min || val > setting->max)
		return -EINVAL;
	if (setting->set)
		return setting->set(drive, val);
	if (ide_spin_wait_hwgroup(drive))
		return -EBUSY;
	switch (setting->data_type) {
		case TYPE_BYTE:
			*((u8 *) setting->data) = val;
			break;
		case TYPE_SHORT:
			*((u16 *) setting->data) = val;
			break;
		case TYPE_INT:
			*((u32 *) setting->data) = val;
			break;
		case TYPE_INTA:
			p = (u32 *) setting->data;
			for (i = 0; i < 1 << PARTN_BITS; i++, p++)
				*p = val;
			break;
	}
	spin_unlock_irq(&io_request_lock);
	return 0;
}

static int set_io_32bit(ide_drive_t *drive, int arg)
{
	drive->io_32bit = arg;
#ifdef CONFIG_BLK_DEV_DTC2278
	if (HWIF(drive)->chipset == ide_dtc2278)
		HWIF(drive)->drives[!drive->select.b.unit].io_32bit = arg;
#endif /* CONFIG_BLK_DEV_DTC2278 */
	return 0;
}

static int set_using_dma (ide_drive_t *drive, int arg)
{
	if (!drive->driver || !DRIVER(drive)->supports_dma)
		return -EPERM;
	if (!drive->id || !(drive->id->capability & 1) || !HWIF(drive)->dmaproc)
		return -EPERM;
	if (HWIF(drive)->dmaproc(arg ? ide_dma_on : ide_dma_off, drive))
		return -EIO;
	return 0;
}

static int set_pio_mode (ide_drive_t *drive, int arg)
{
	struct request rq;

	if (!HWIF(drive)->tuneproc)
		return -ENOSYS;
	if (drive->special.b.set_tune)
		return -EBUSY;
	ide_init_drive_cmd(&rq);
	drive->tune_req = (byte) arg;
	drive->special.b.set_tune = 1;
	(void) ide_do_drive_cmd (drive, &rq, ide_wait);
	return 0;
}

void ide_add_generic_settings (ide_drive_t *drive)
{
/*
 *			drive	setting name		read/write access				read ioctl		write ioctl		data type	min	max				mul_factor	div_factor	data pointer			set function
 */
	ide_add_setting(drive,	"io_32bit",		drive->no_io_32bit ? SETTING_READ : SETTING_RW,	HDIO_GET_32BIT,		HDIO_SET_32BIT,		TYPE_BYTE,	0,	1 + (SUPPORT_VLB_SYNC << 1),	1,		1,		&drive->io_32bit,		set_io_32bit);
	ide_add_setting(drive,	"keepsettings",		SETTING_RW,					HDIO_GET_KEEPSETTINGS,	HDIO_SET_KEEPSETTINGS,	TYPE_BYTE,	0,	1,				1,		1,		&drive->keep_settings,		NULL);
	ide_add_setting(drive,	"nice1",		SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	1,				1,		1,		&drive->nice1,			NULL);
	ide_add_setting(drive,	"pio_mode",		SETTING_WRITE,					-1,			HDIO_SET_PIO_MODE,	TYPE_BYTE,	0,	255,				1,		1,		NULL,				set_pio_mode);
	ide_add_setting(drive,	"slow",			SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	1,				1,		1,		&drive->slow,			NULL);
	ide_add_setting(drive,	"unmaskirq",		drive->no_unmask ? SETTING_READ : SETTING_RW,	HDIO_GET_UNMASKINTR,	HDIO_SET_UNMASKINTR,	TYPE_BYTE,	0,	1,				1,		1,		&drive->unmask,			NULL);
	ide_add_setting(drive,	"using_dma",		SETTING_RW,					HDIO_GET_DMA,		HDIO_SET_DMA,		TYPE_BYTE,	0,	1,				1,		1,		&drive->using_dma,		set_using_dma);
	ide_add_setting(drive,	"ide_scsi",		SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	1,				1,		1,		&drive->scsi,			NULL);
	ide_add_setting(drive,	"init_speed",		SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	69,				1,		1,		&drive->init_speed,		NULL);
	ide_add_setting(drive,	"current_speed",	SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	69,				1,		1,		&drive->current_speed,		NULL);
	ide_add_setting(drive,	"number",		SETTING_RW,					-1,			-1,			TYPE_BYTE,	0,	3,				1,		1,		&drive->dn,			NULL);
}

int ide_wait_cmd (ide_drive_t *drive, int cmd, int nsect, int feature, int sectors, byte *buf)
{
	struct request rq;
	byte buffer[4];

	if (!buf)
		buf = buffer;
	memset(buf, 0, 4 + SECTOR_WORDS * 4 * sectors);
	ide_init_drive_cmd(&rq);
	rq.buffer = buf;
	*buf++ = cmd;
	*buf++ = nsect;
	*buf++ = feature;
	*buf++ = sectors;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}

int ide_wait_cmd_task (ide_drive_t *drive, byte *buf)
{
	struct request rq;

	ide_init_drive_cmd(&rq);
	rq.cmd = IDE_DRIVE_TASK;
	rq.buffer = buf;
	return ide_do_drive_cmd(drive, &rq, ide_wait);
}

/*
 * Delay for *at least* 50ms.  As we don't know how much time is left
 * until the next tick occurs, we wait an extra tick to be safe.
 * This is used only during the probing/polling for drives at boot time.
 *
 * However, its usefullness may be needed in other places, thus we export it now.
 * The future may change this to a millisecond setable delay.
 */
void ide_delay_50ms (void)
{
#ifndef CONFIG_BLK_DEV_IDECS
	mdelay(50);
#else
	__set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_timeout(HZ/20);
#endif /* CONFIG_BLK_DEV_IDECS */
}

int system_bus_clock (void)
{
	return((int) ((!system_bus_speed) ? ide_system_bus_speed() : system_bus_speed ));
}

int ide_reinit_drive (ide_drive_t *drive)
{
	switch (drive->media) {
#ifdef CONFIG_BLK_DEV_IDECD
		case ide_cdrom:
		{
			extern int ide_cdrom_reinit(ide_drive_t *drive);
			if (ide_cdrom_reinit(drive))
				return 1;
			break;
		}
#endif /* CONFIG_BLK_DEV_IDECD */
#ifdef CONFIG_BLK_DEV_IDEDISK
		case ide_disk:
		{
			extern int idedisk_reinit(ide_drive_t *drive);
			if (idedisk_reinit(drive))
				return 1;
			break;
		}
#endif /* CONFIG_BLK_DEV_IDEDISK */
#ifdef CONFIG_BLK_DEV_IDEFLOPPY
		case ide_floppy:
		{
			extern int idefloppy_reinit(ide_drive_t *drive);
			if (idefloppy_reinit(drive))
				return 1;
			break;
		}
#endif /* CONFIG_BLK_DEV_IDEFLOPPY */
#ifdef CONFIG_BLK_DEV_IDETAPE
		case ide_tape:
		{
			extern int idetape_reinit(ide_drive_t *drive);
			if (idetape_reinit(drive))
				return 1;
			break;
		}
#endif /* CONFIG_BLK_DEV_IDETAPE */
#ifdef CONFIG_BLK_DEV_IDESCSI
/*
 *              {
 *                      extern int idescsi_reinit(ide_drive_t *drive);
 *                      if (idescsi_reinit(drive))
 *                              return 1;
 *                      break;
 * }
 */
#endif /* CONFIG_BLK_DEV_IDESCSI */
		default:
			return 1;
	}
	return 0;
}

static int ide_ioctl (struct inode *inode, struct file *file,
			unsigned int cmd, unsigned long arg)
{
	int err = 0, major, minor;
	ide_drive_t *drive;
	struct request rq;
	kdev_t dev;
	ide_settings_t *setting;

	if (!inode || !(dev = inode->i_rdev))
		return -EINVAL;
	major = MAJOR(dev); minor = MINOR(dev);
	if ((drive = get_info_ptr(inode->i_rdev)) == NULL)
		return -ENODEV;

	if ((setting = ide_find_setting_by_ioctl(drive, cmd)) != NULL) {
		if (cmd == setting->read_ioctl) {
			err = ide_read_setting(drive, setting);
			return err >= 0 ? put_user(err, (long *) arg) : err;
		} else {
			if ((MINOR(inode->i_rdev) & PARTN_MASK))
				return -EINVAL;
			return ide_write_setting(drive, setting, arg);
		}
	}

	ide_init_drive_cmd (&rq);
	switch (cmd) {
		case HDIO_GETGEO:
		{
			struct hd_geometry *loc = (struct hd_geometry *) arg;
			unsigned short bios_cyl = drive->bios_cyl; /* truncate */
			if (!loc || (drive->media != ide_disk && drive->media != ide_floppy)) return -EINVAL;
			if (put_user(drive->bios_head, (byte *) &loc->heads)) return -EFAULT;
			if (put_user(drive->bios_sect, (byte *) &loc->sectors)) return -EFAULT;
			if (put_user(bios_cyl, (unsigned short *) &loc->cylinders)) return -EFAULT;
			if (put_user((unsigned)drive->part[MINOR(inode->i_rdev)&PARTN_MASK].start_sect,
				(unsigned long *) &loc->start)) return -EFAULT;
			return 0;
		}

		case HDIO_GETGEO_BIG:
		{
			struct hd_big_geometry *loc = (struct hd_big_geometry *) arg;
			if (!loc || (drive->media != ide_disk && drive->media != ide_floppy)) return -EINVAL;
			if (put_user(drive->bios_head, (byte *) &loc->heads)) return -EFAULT;
			if (put_user(drive->bios_sect, (byte *) &loc->sectors)) return -EFAULT;
			if (put_user(drive->bios_cyl, (unsigned int *) &loc->cylinders)) return -EFAULT;
			if (put_user((unsigned)drive->part[MINOR(inode->i_rdev)&PARTN_MASK].start_sect,
				(unsigned long *) &loc->start)) return -EFAULT;
			return 0;
		}

		case HDIO_GETGEO_BIG_RAW:
		{
			struct hd_big_geometry *loc = (struct hd_big_geometry *) arg;
			if (!loc || (drive->media != ide_disk && drive->media != ide_floppy)) return -EINVAL;
			if (put_user(drive->head, (byte *) &loc->heads)) return -EFAULT;
			if (put_user(drive->sect, (byte *) &loc->sectors)) return -EFAULT;
			if (put_user(drive->cyl, (unsigned int *) &loc->cylinders)) return -EFAULT;
			if (put_user((unsigned)drive->part[MINOR(inode->i_rdev)&PARTN_MASK].start_sect,
				(unsigned long *) &loc->start)) return -EFAULT;
			return 0;
		}

#if 0
	 	case BLKGETSIZE:   /* Return device size */
			return put_user(drive->part[MINOR(inode->i_rdev)&PARTN_MASK].nr_sects, (unsigned long *) arg);
	 	case BLKGETSIZE64:
			return put_user((u64)drive->part[MINOR(inode->i_rdev)&PARTN_MASK].nr_sects << 9, (u64 *) arg);

		case BLKRRPART: /* Re-read partition tables */
			if (!capable(CAP_SYS_ADMIN)) return -EACCES;
			return ide_revalidate_disk(inode->i_rdev);
#endif

		case HDIO_OBSOLETE_IDENTITY:
		case HDIO_GET_IDENTITY:
			if (MINOR(inode->i_rdev) & PARTN_MASK)
				return -EINVAL;
			if (drive->id == NULL)
				return -ENOMSG;
			if (copy_to_user((char *)arg, (char *)drive->id, (cmd == HDIO_GET_IDENTITY) ? sizeof(*drive->id) : 142))
				return -EFAULT;
			return 0;

		case HDIO_GET_NICE:
			return put_user(drive->dsc_overlap	<<	IDE_NICE_DSC_OVERLAP	|
					drive->atapi_overlap	<<	IDE_NICE_ATAPI_OVERLAP	|
					drive->nice0		<< 	IDE_NICE_0		|
					drive->nice1		<<	IDE_NICE_1		|
					drive->nice2		<<	IDE_NICE_2,
					(long *) arg);

#ifdef CONFIG_IDE_TASK_IOCTL
		case HDIO_DRIVE_TASKFILE:
		        if (!capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_RAWIO))
				return -EACCES;
			switch(drive->media) {
				case ide_disk:
					return ide_taskfile_ioctl(drive, inode, file, cmd, arg);
#ifdef CONFIG_PKT_TASK_IOCTL
				case ide_cdrom:
				case ide_tape:
				case ide_floppy:
					return pkt_taskfile_ioctl(drive, inode, file, cmd, arg);
#endif /* CONFIG_PKT_TASK_IOCTL */
				default:
					return -ENOMSG;
			}
#endif /* CONFIG_IDE_TASK_IOCTL */

		case HDIO_DRIVE_CMD:
		{
			byte args[4], *argbuf = args;
			byte xfer_rate = 0;
			int argsize = 4;
			ide_task_t tfargs;

			if (!capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_RAWIO))
				return -EACCES;
			if (NULL == (void *) arg)
				return ide_do_drive_cmd(drive, &rq, ide_wait);
			if (copy_from_user(args, (void *)arg, 4))
				return -EFAULT;

			tfargs.tfRegister[IDE_FEATURE_OFFSET] = args[2];
			tfargs.tfRegister[IDE_NSECTOR_OFFSET] = args[3];
			tfargs.tfRegister[IDE_SECTOR_OFFSET]  = args[1];
			tfargs.tfRegister[IDE_LCYL_OFFSET]    = 0x00;
			tfargs.tfRegister[IDE_HCYL_OFFSET]    = 0x00;
			tfargs.tfRegister[IDE_SELECT_OFFSET]  = 0x00;
			tfargs.tfRegister[IDE_COMMAND_OFFSET] = args[0];

			if (args[3]) {
				argsize = 4 + (SECTOR_WORDS * 4 * args[3]);
				argbuf = kmalloc(argsize, GFP_KERNEL);
				if (argbuf == NULL)
					return -ENOMEM;
				memcpy(argbuf, args, 4);
			}

			if (set_transfer(drive, &tfargs)) {
				xfer_rate = args[1];
				if (ide_ata66_check(drive, &tfargs))
					goto abort;
			}

			err = ide_wait_cmd(drive, args[0], args[1], args[2], args[3], argbuf);

			if (!err && xfer_rate) {
				/* active-retuning-calls future */
				if ((HWIF(drive)->speedproc) != NULL)
					HWIF(drive)->speedproc(drive, xfer_rate);
				ide_driveid_update(drive);
			}
		abort:
			if (copy_to_user((void *)arg, argbuf, argsize))
				err = -EFAULT;
			if (argsize > 4)
				kfree(argbuf);
			return err;
		}
		case HDIO_DRIVE_TASK:
		{
			byte args[7], *argbuf = args;
			int argsize = 7;
			if (!capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_RAWIO)) return -EACCES;
			if (copy_from_user(args, (void *)arg, 7))
				return -EFAULT;
			err = ide_wait_cmd_task(drive, argbuf);
			if (copy_to_user((void *)arg, argbuf, argsize))
				err = -EFAULT;
			return err;
		}
		case HDIO_SCAN_HWIF:
		{
			int args[3];
			if (!capable(CAP_SYS_ADMIN)) return -EACCES;
			if (copy_from_user(args, (void *)arg, 3 * sizeof(int)))
				return -EFAULT;
			if (ide_register(args[0], args[1], args[2]) == -1)
				return -EIO;
			return 0;
		}
	        case HDIO_UNREGISTER_HWIF:
			if (!capable(CAP_SYS_ADMIN)) return -EACCES;
			/* (arg > MAX_HWIFS) checked in function */
			ide_unregister(arg);
			return 0;
		case HDIO_SET_NICE:
			if (!capable(CAP_SYS_ADMIN)) return -EACCES;
			if (drive->driver == NULL)
				return -EPERM;
			if (arg != (arg & ((1 << IDE_NICE_DSC_OVERLAP) | (1 << IDE_NICE_1))))
				return -EPERM;
			drive->dsc_overlap = (arg >> IDE_NICE_DSC_OVERLAP) & 1;
			if (drive->dsc_overlap && !DRIVER(drive)->supports_dsc_overlap) {
				drive->dsc_overlap = 0;
				return -EPERM;
			}
			drive->nice1 = (arg >> IDE_NICE_1) & 1;
			return 0;
		case HDIO_DRIVE_RESET:
		{
			unsigned long flags;
			ide_hwgroup_t *hwgroup = HWGROUP(drive);

			if (!capable(CAP_SYS_ADMIN)) return -EACCES;
#if 1
			spin_lock_irqsave(&io_request_lock, flags);
			if (hwgroup->handler != NULL) {
				printk("%s: ide_set_handler: handler not null; %p\n", drive->name, hwgroup->handler);
				(void) hwgroup->handler(drive);
//				hwgroup->handler = NULL;
//				hwgroup->expiry	= NULL;
				hwgroup->timer.expires = jiffies + 0;;
				del_timer(&hwgroup->timer);
			}
			spin_unlock_irqrestore(&io_request_lock, flags);

#endif
			(void) ide_do_reset(drive);
			if (drive->suspend_reset) {
/*
 *				APM WAKE UP todo !!
 *				int nogoodpower = 1;
 *				while(nogoodpower) {
 *					check_power1() or check_power2()
 *					nogoodpower = 0;
 *				} 
 *				HWIF(drive)->multiproc(drive);
 */
				return ide_revalidate_disk(inode->i_rdev);
			}
			return 0;
		}
#if 0
		case BLKROSET:
		case BLKROGET:
		case BLKFLSBUF:
		case BLKSSZGET:
		case BLKPG:
		case BLKELVGET:
		case BLKELVSET:
		case BLKBSZGET:
		case BLKBSZSET:
			return blk_ioctl(inode->i_rdev, cmd, arg);
#endif

		case HDIO_GET_BUSSTATE:
			if (!capable(CAP_SYS_ADMIN))
				return -EACCES;
			if (put_user(HWIF(drive)->bus_state, (long *)arg))
				return -EFAULT;
			return 0;

		case HDIO_SET_BUSSTATE:
			if (!capable(CAP_SYS_ADMIN))
				return -EACCES;
			if (HWIF(drive)->busproc)
				HWIF(drive)->busproc(drive, (int)arg);
			return 0;

		default:
			if (drive->driver != NULL)
				return DRIVER(drive)->ioctl(drive, inode, file, cmd, arg);
			return -EPERM;
	}
}

static int ide_check_media_change (kdev_t i_rdev)
{
	ide_drive_t *drive;

	if ((drive = get_info_ptr(i_rdev)) == NULL)
		return -ENODEV;
	if (drive->driver != NULL)
		return DRIVER(drive)->media_change(drive);
	return 0;
}

void ide_fixstring (byte *s, const int bytecount, const int byteswap)
{
	byte *p = s, *end = &s[bytecount & ~1]; /* bytecount must be even */

	if (byteswap) {
		/* convert from big-endian to host byte order */
		for (p = end ; p != s;) {
			unsigned short *pp = (unsigned short *) (p -= 2);
			*pp = ntohs(*pp);
		}
	}

	/* strip leading blanks */
	while (s != end && *s == ' ')
		++s;

	/* compress internal blanks and strip trailing blanks */
	while (s != end && *s) {
		if (*s++ != ' ' || (s != end && *s && *s != ' '))
			*p++ = *(s-1);
	}

	/* wipe out trailing garbage */
	while (p != end)
		*p++ = '\0';
}

/*
 * stridx() returns the offset of c within s,
 * or -1 if c is '\0' or not found within s.
 */
static int __init stridx (const char *s, char c)
{
	char *i = strchr(s, c);
	return (i && c) ? i - s : -1;
}

/*
 * match_parm() does parsing for ide_setup():
 *
 * 1. the first char of s must be '='.
 * 2. if the remainder matches one of the supplied keywords,
 *     the index (1 based) of the keyword is negated and returned.
 * 3. if the remainder is a series of no more than max_vals numbers
 *     separated by commas, the numbers are saved in vals[] and a
 *     count of how many were saved is returned.  Base10 is assumed,
 *     and base16 is allowed when prefixed with "0x".
 * 4. otherwise, zero is returned.
 */
static int __init match_parm (char *s, const char *keywords[], int vals[], int max_vals)
{
	static const char *decimal = "0123456789";
	static const char *hex = "0123456789abcdef";
	int i, n;

	if (*s++ == '=') {
		/*
		 * Try matching against the supplied keywords,
		 * and return -(index+1) if we match one
		 */
		if (keywords != NULL) {
			for (i = 0; *keywords != NULL; ++i) {
				if (!strcmp(s, *keywords++))
					return -(i+1);
			}
		}
		/*
		 * Look for a series of no more than "max_vals"
		 * numeric values separated by commas, in base10,
		 * or base16 when prefixed with "0x".
		 * Return a count of how many were found.
		 */
		for (n = 0; (i = stridx(decimal, *s)) >= 0;) {
			vals[n] = i;
			while ((i = stridx(decimal, *++s)) >= 0)
				vals[n] = (vals[n] * 10) + i;
			if (*s == 'x' && !vals[n]) {
				while ((i = stridx(hex, *++s)) >= 0)
					vals[n] = (vals[n] * 0x10) + i;
			}
			if (++n == max_vals)
				break;
			if (*s == ',' || *s == ';')
				++s;
		}
		if (!*s)
			return n;
	}
	return 0;	/* zero = nothing matched */
}

/*
 * ide_setup() gets called VERY EARLY during initialization,
 * to handle kernel "command line" strings beginning with "hdx="
 * or "ide".  Here is the complete set currently supported:
 *
 * "hdx="  is recognized for all "x" from "a" to "h", such as "hdc".
 * "idex=" is recognized for all "x" from "0" to "3", such as "ide1".
 *
 * "hdx=noprobe"	: drive may be present, but do not probe for it
 * "hdx=none"		: drive is NOT present, ignore cmos and do not probe
 * "hdx=nowerr"		: ignore the WRERR_STAT bit on this drive
 * "hdx=cdrom"		: drive is present, and is a cdrom drive
 * "hdx=cyl,head,sect"	: disk drive is present, with specified geometry
 * "hdx=noremap"	: do not remap 0->1 even though EZD was detected
 * "hdx=autotune"	: driver will attempt to tune interface speed
 *				to the fastest PIO mode supported,
 *				if possible for this drive only.
 *				Not fully supported by all chipset types,
 *				and quite likely to cause trouble with
 *				older/odd IDE drives.
 *
 * "hdx=slow"		: insert a huge pause after each access to the data
 *				port. Should be used only as a last resort.
 *
 * "hdx=swapdata"	: when the drive is a disk, byte swap all data
 * "hdx=bswap"		: same as above..........
 * "hdxlun=xx"          : set the drive last logical unit.
 * "hdx=flash"		: allows for more than one ata_flash disk to be
 *				registered. In most cases, only one device
 *				will be present.
 * "hdx=scsi"		: the return of the ide-scsi flag, this is useful for
 *				allowwing ide-floppy, ide-tape, and ide-cdrom|writers
 *				to use ide-scsi emulation on a device specific option.
 * "idebus=xx"		: inform IDE driver of VESA/PCI bus speed in MHz,
 *				where "xx" is between 20 and 66 inclusive,
 *				used when tuning chipset PIO modes.
 *				For PCI bus, 25 is correct for a P75 system,
 *				30 is correct for P90,P120,P180 systems,
 *				and 33 is used for P100,P133,P166 systems.
 *				If in doubt, use idebus=33 for PCI.
 *				As for VLB, it is safest to not specify it.
 *
 * "idex=noprobe"	: do not attempt to access/use this interface
 * "idex=base"		: probe for an interface at the addr specified,
 *				where "base" is usually 0x1f0 or 0x170
 *				and "ctl" is assumed to be "base"+0x206
 * "idex=base,ctl"	: specify both base and ctl
 * "idex=base,ctl,irq"	: specify base, ctl, and irq number
 * "idex=autotune"	: driver will attempt to tune interface speed
 *				to the fastest PIO mode supported,
 *				for all drives on this interface.
 *				Not fully supported by all chipset types,
 *				and quite likely to cause trouble with
 *				older/odd IDE drives.
 * "idex=noautotune"	: driver will NOT attempt to tune interface speed
 *				This is the default for most chipsets,
 *				except the cmd640.
 * "idex=serialize"	: do not overlap operations on idex and ide(x^1)
 * "idex=four"		: four drives on idex and ide(x^1) share same ports
 * "idex=reset"		: reset interface before first use
 * "idex=dma"		: enable DMA by default on both drives if possible
 * "idex=ata66"		: informs the interface that it has an 80c cable
 *				for chipsets that are ATA-66 capable, but
 *				the ablity to bit test for detection is
 *				currently unknown.
 * "ide=reverse"	: Formerly called to pci sub-system, but now local.
 *
 * The following are valid ONLY on ide0, (except dc4030)
 * and the defaults for the base,ctl ports must not be altered.
 *
 * "ide0=dtc2278"	: probe/support DTC2278 interface
 * "ide0=ht6560b"	: probe/support HT6560B interface
 * "ide0=cmd640_vlb"	: *REQUIRED* for VLB cards with the CMD640 chip
 *			  (not for PCI -- automatically detected)
 * "ide0=qd65xx"	: probe/support qd65xx interface
 * "ide0=ali14xx"	: probe/support ali14xx chipsets (ALI M1439, M1443, M1445)
 * "ide0=umc8672"	: probe/support umc8672 chipsets
 * "idex=dc4030"	: probe/support Promise DC4030VL interface
 * "ide=doubler"	: probe/support IDE doublers on Amiga
 */
int __init ide_setup (char *s)
{
	int i, vals[3];
	ide_hwif_t *hwif;
	ide_drive_t *drive;
	unsigned int hw, unit;
	const char max_drive = 'a' + ((MAX_HWIFS * MAX_DRIVES) - 1);
	const char max_hwif  = '0' + (MAX_HWIFS - 1);

	
	if (strncmp(s,"hd",2) == 0 && s[2] == '=')	/* hd= is for hd.c   */
		return 0;				/* driver and not us */

	if (strncmp(s,"ide",3) &&
	    strncmp(s,"idebus",6) &&
	    strncmp(s,"hd",2))		/* hdx= & hdxlun= */
		return 0;

	printk("ide_setup: %s", s);
	init_ide_data ();

#ifdef CONFIG_BLK_DEV_IDEDOUBLER
	if (!strcmp(s, "ide=doubler")) {
		extern int ide_doubler;

		printk(" : Enabled support for IDE doublers\n");
		ide_doubler = 1;
		return 1;
	}
#endif /* CONFIG_BLK_DEV_IDEDOUBLER */

	if (!strcmp(s, "ide=nodma")) {
		printk("IDE: Prevented DMA\n");
		noautodma = 1;
		return 1;
	}

#ifdef CONFIG_BLK_DEV_IDEPCI
	if (!strcmp(s, "ide=reverse")) {
		ide_scan_direction = 1;
		printk(" : Enabled support for IDE inverse scan order.\n");
		return 1;
	}
#endif /* CONFIG_BLK_DEV_IDEPCI */

	/*
	 * Look for drive options:  "hdx="
	 */
	if (s[0] == 'h' && s[1] == 'd' && s[2] >= 'a' && s[2] <= max_drive) {
		const char *hd_words[] = {"none", "noprobe", "nowerr", "cdrom",
				"serialize", "autotune", "noautotune",
				"slow", "swapdata", "bswap", "flash",
				"remap", "noremap", "scsi", NULL};
		unit = s[2] - 'a';
		hw   = unit / MAX_DRIVES;
		unit = unit % MAX_DRIVES;
		hwif = &ide_hwifs[hw];
		drive = &hwif->drives[unit];
		if (strncmp(s + 4, "ide-", 4) == 0) {
			strncpy(drive->driver_req, s + 4, 9);
			goto done;
		}
		/*
		 * Look for last lun option:  "hdxlun="
		 */
		if (s[3] == 'l' && s[4] == 'u' && s[5] == 'n') {
			if (match_parm(&s[6], NULL, vals, 1) != 1)
				goto bad_option;
			if (vals[0] >= 0 && vals[0] <= 7) {
				drive->last_lun = vals[0];
				drive->forced_lun = 1;
			} else
				printk(" -- BAD LAST LUN! Expected value from 0 to 7");
			goto done;
		}
		switch (match_parm(&s[3], hd_words, vals, 3)) {
			case -1: /* "none" */
				drive->nobios = 1;  /* drop into "noprobe" */
			case -2: /* "noprobe" */
				drive->noprobe = 1;
				goto done;
			case -3: /* "nowerr" */
				drive->bad_wstat = BAD_R_STAT;
				hwif->noprobe = 0;
				goto done;
			case -4: /* "cdrom" */
				drive->present = 1;
				drive->media = ide_cdrom;
				hwif->noprobe = 0;
				goto done;
			case -5: /* "serialize" */
				printk(" -- USE \"ide%d=serialize\" INSTEAD", hw);
				goto do_serialize;
			case -6: /* "autotune" */
				drive->autotune = 1;
				goto done;
			case -7: /* "noautotune" */
				drive->autotune = 2;
				goto done;
			case -8: /* "slow" */
				drive->slow = 1;
				goto done;
			case -9: /* "swapdata" or "bswap" */
			case -10:
				drive->bswap = 1;
				goto done;
			case -11: /* "flash" */
				drive->ata_flash = 1;
				goto done;
			case -12: /* "remap" */
				drive->remap_0_to_1 = 1;
				goto done;
			case -13: /* "noremap" */
				drive->remap_0_to_1 = 2;
				goto done;
			case -14: /* "scsi" */
#if defined(CONFIG_BLK_DEV_IDESCSI) && defined(CONFIG_SCSI)
				drive->scsi = 1;
				goto done;
#else
				drive->scsi = 0;
				goto bad_option;
#endif /* defined(CONFIG_BLK_DEV_IDESCSI) && defined(CONFIG_SCSI) */
			case 3: /* cyl,head,sect */
				drive->media	= ide_disk;
				drive->cyl	= drive->bios_cyl  = vals[0];
				drive->head	= drive->bios_head = vals[1];
				drive->sect	= drive->bios_sect = vals[2];
				drive->present	= 1;
				drive->forced_geom = 1;
				hwif->noprobe = 0;
				goto done;
			default:
				goto bad_option;
		}
	}

	if (s[0] != 'i' || s[1] != 'd' || s[2] != 'e')
		goto bad_option;
	/*
	 * Look for bus speed option:  "idebus="
	 */
	if (s[3] == 'b' && s[4] == 'u' && s[5] == 's') {
		if (match_parm(&s[6], NULL, vals, 1) != 1)
			goto bad_option;
		if (vals[0] >= 20 && vals[0] <= 66) {
			idebus_parameter = vals[0];
		} else
			printk(" -- BAD BUS SPEED! Expected value from 20 to 66");
		goto done;
	}
	/*
	 * Look for interface options:  "idex="
	 */
	if (s[3] >= '0' && s[3] <= max_hwif) {
		/*
		 * Be VERY CAREFUL changing this: note hardcoded indexes below
		 * -8,-9,-10 : are reserved for future idex calls to ease the hardcoding.
		 */
		const char *ide_words[] = {
			"noprobe", "serialize", "autotune", "noautotune", "reset", "dma", "ata66",
			"minus8", "minus9", "minus10",
			"four", "qd65xx", "ht6560b", "cmd640_vlb", "dtc2278", "umc8672", "ali14xx", "dc4030", NULL };
		hw = s[3] - '0';
		hwif = &ide_hwifs[hw];
		i = match_parm(&s[4], ide_words, vals, 3);

		/*
		 * Cryptic check to ensure chipset not already set for hwif:
		 */
		if (i > 0 || i <= -11) {			/* is parameter a chipset name? */
			if (hwif->chipset != ide_unknown)
				goto bad_option;	/* chipset already specified */
			if (i <= -11 && i != -18 && hw != 0)
				goto bad_hwif;		/* chipset drivers are for "ide0=" only */
			if (i <= -11 && i != -18 && ide_hwifs[hw+1].chipset != ide_unknown)
				goto bad_option;	/* chipset for 2nd port already specified */
			printk("\n");
		}

		switch (i) {
#ifdef CONFIG_BLK_DEV_PDC4030
			case -18: /* "dc4030" */
			{
				extern void init_pdc4030(void);
				init_pdc4030();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_PDC4030 */
#ifdef CONFIG_BLK_DEV_ALI14XX
			case -17: /* "ali14xx" */
			{
				extern void init_ali14xx (void);
				init_ali14xx();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_ALI14XX */
#ifdef CONFIG_BLK_DEV_UMC8672
			case -16: /* "umc8672" */
			{
				extern void init_umc8672 (void);
				init_umc8672();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_UMC8672 */
#ifdef CONFIG_BLK_DEV_DTC2278
			case -15: /* "dtc2278" */
			{
				extern void init_dtc2278 (void);
				init_dtc2278();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_DTC2278 */
#ifdef CONFIG_BLK_DEV_CMD640
			case -14: /* "cmd640_vlb" */
			{
				extern int cmd640_vlb; /* flag for cmd640.c */
				cmd640_vlb = 1;
				goto done;
			}
#endif /* CONFIG_BLK_DEV_CMD640 */
#ifdef CONFIG_BLK_DEV_HT6560B
			case -13: /* "ht6560b" */
			{
				extern void init_ht6560b (void);
				init_ht6560b();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_HT6560B */
#if CONFIG_BLK_DEV_QD65XX
			case -12: /* "qd65xx" */
			{
				extern void init_qd65xx (void);
				init_qd65xx();
				goto done;
			}
#endif /* CONFIG_BLK_DEV_QD65XX */
#ifdef CONFIG_BLK_DEV_4DRIVES
			case -11: /* "four" drives on one set of ports */
			{
				ide_hwif_t *mate = &ide_hwifs[hw^1];
				mate->drives[0].select.all ^= 0x20;
				mate->drives[1].select.all ^= 0x20;
				hwif->chipset = mate->chipset = ide_4drives;
				mate->irq = hwif->irq;
				memcpy(mate->io_ports, hwif->io_ports, sizeof(hwif->io_ports));
				goto do_serialize;
			}
#endif /* CONFIG_BLK_DEV_4DRIVES */
			case -10: /* minus10 */
			case -9: /* minus9 */
			case -8: /* minus8 */
				goto bad_option;
			case -7: /* ata66 */
#ifdef CONFIG_BLK_DEV_IDEPCI
				hwif->udma_four = 1;
				goto done;
#else /* !CONFIG_BLK_DEV_IDEPCI */
				hwif->udma_four = 0;
				goto bad_hwif;
#endif /* CONFIG_BLK_DEV_IDEPCI */
			case -6: /* dma */
				hwif->autodma = 1;
				goto done;
			case -5: /* "reset" */
				hwif->reset = 1;
				goto done;
			case -4: /* "noautotune" */
				hwif->drives[0].autotune = 2;
				hwif->drives[1].autotune = 2;
				goto done;
			case -3: /* "autotune" */
				hwif->drives[0].autotune = 1;
				hwif->drives[1].autotune = 1;
				goto done;
			case -2: /* "serialize" */
			do_serialize:
				hwif->mate = &ide_hwifs[hw^1];
				hwif->mate->mate = hwif;
				hwif->serialized = hwif->mate->serialized = 1;
				goto done;

			case -1: /* "noprobe" */
				hwif->noprobe = 1;
				goto done;

			case 1:	/* base */
				vals[1] = vals[0] + 0x206; /* default ctl */
			case 2: /* base,ctl */
				vals[2] = 0;	/* default irq = probe for it */
			case 3: /* base,ctl,irq */
				hwif->hw.irq = vals[2];
				ide_init_hwif_ports(&hwif->hw, (ide_ioreg_t) vals[0], (ide_ioreg_t) vals[1], &hwif->irq);
				memcpy(hwif->io_ports, hwif->hw.io_ports, sizeof(hwif->io_ports));
				hwif->irq      = vals[2];
				hwif->noprobe  = 0;
				hwif->chipset  = ide_generic;
				goto done;

			case 0: goto bad_option;
			default:
				printk(" -- SUPPORT NOT CONFIGURED IN THIS KERNEL\n");
				return 1;
		}
	}
bad_option:
	printk(" -- BAD OPTION\n");
	return 1;
bad_hwif:
	printk("-- NOT SUPPORTED ON ide%d", hw);
done:
	printk("\n");
	return 1;
}

/*
 * probe_for_hwifs() finds/initializes "known" IDE interfaces
 */
static void __init probe_for_hwifs (void)
{
#ifdef CONFIG_PCI
	if (pci_present())
	{
#ifdef CONFIG_BLK_DEV_IDEPCI
		ide_scan_pcibus(ide_scan_direction);
#else
#ifdef CONFIG_BLK_DEV_RZ1000
		{
			extern void ide_probe_for_rz100x(void);
			ide_probe_for_rz100x();
		}
#endif /* CONFIG_BLK_DEV_RZ1000 */
#endif /* CONFIG_BLK_DEV_IDEPCI */
	}
#endif /* CONFIG_PCI */

#ifdef CONFIG_ETRAX_IDE
	{
		extern void init_e100_ide(void);
		init_e100_ide();
	}
#endif /* CONFIG_ETRAX_IDE */
#ifdef CONFIG_BLK_DEV_CMD640
	{
		extern void ide_probe_for_cmd640x(void);
		ide_probe_for_cmd640x();
	}
#endif /* CONFIG_BLK_DEV_CMD640 */
#ifdef CONFIG_BLK_DEV_PDC4030
	{
		extern int ide_probe_for_pdc4030(void);
		(void) ide_probe_for_pdc4030();
	}
#endif /* CONFIG_BLK_DEV_PDC4030 */
#ifdef CONFIG_BLK_DEV_IDE_PMAC
	{
		extern void pmac_ide_probe(void);
		pmac_ide_probe();
	}
#endif /* CONFIG_BLK_DEV_IDE_PMAC */
#ifdef CONFIG_BLK_DEV_IDE_SWARM
	{
		extern void swarm_ide_probe(void);
		swarm_ide_probe();
	}
#endif /* CONFIG_BLK_DEV_IDE_SWARM */
#ifdef CONFIG_BLK_DEV_IDE_ICSIDE
	{
		extern void icside_init(void);
		icside_init();
	}
#endif /* CONFIG_BLK_DEV_IDE_ICSIDE */
#ifdef CONFIG_BLK_DEV_IDE_RAPIDE
	{
		extern void rapide_init(void);
		rapide_init();
	}
#endif /* CONFIG_BLK_DEV_IDE_RAPIDE */
#ifdef CONFIG_BLK_DEV_GAYLE
	{
		extern void gayle_init(void);
		gayle_init();
	}
#endif /* CONFIG_BLK_DEV_GAYLE */
#ifdef CONFIG_BLK_DEV_FALCON_IDE
	{
		extern void falconide_init(void);
		falconide_init();
	}
#endif /* CONFIG_BLK_DEV_FALCON_IDE */
#ifdef CONFIG_BLK_DEV_MAC_IDE
	{
		extern void macide_init(void);
		macide_init();
	}
#endif /* CONFIG_BLK_DEV_MAC_IDE */
#ifdef CONFIG_BLK_DEV_Q40IDE
	{
		extern void q40ide_init(void);
		q40ide_init();
	}
#endif /* CONFIG_BLK_DEV_Q40IDE */
#ifdef CONFIG_BLK_DEV_BUDDHA
	{
		extern void buddha_init(void);
		buddha_init();
	}
#endif /* CONFIG_BLK_DEV_BUDDHA */
#if defined(CONFIG_BLK_DEV_ISAPNP) && defined(CONFIG_ISAPNP)
	{
		extern void pnpide_init(int enable);
		pnpide_init(1);
	}
#endif /* CONFIG_BLK_DEV_ISAPNP */
}

void __init ide_init_builtin_drivers (void)
{
	/*
	 * Probe for special PCI and other "known" interface chipsets
	 */
	probe_for_hwifs ();

#ifdef CONFIG_BLK_DEV_IDE
#if defined(__mc68000__) || defined(CONFIG_APUS)
	if (ide_hwifs[0].io_ports[IDE_DATA_OFFSET]) {
		ide_get_lock(&ide_lock, NULL, NULL);	/* for atari only */
		disable_irq(ide_hwifs[0].irq);	/* disable_irq_nosync ?? */
//		disable_irq_nosync(ide_hwifs[0].irq);
	}
#endif /* __mc68000__ || CONFIG_APUS */

	(void) ideprobe_init();

#if defined(__mc68000__) || defined(CONFIG_APUS)
	if (ide_hwifs[0].io_ports[IDE_DATA_OFFSET]) {
		enable_irq(ide_hwifs[0].irq);
		ide_release_lock(&ide_lock);	/* for atari only */
	}
#endif /* __mc68000__ || CONFIG_APUS */
#endif /* CONFIG_BLK_DEV_IDE */

#ifdef CONFIG_PROC_FS
	proc_ide_create();
#endif

	/*
	 * Attempt to match drivers for the available drives
	 */
#ifdef CONFIG_BLK_DEV_IDEDISK
	(void) idedisk_init();
#endif /* CONFIG_BLK_DEV_IDEDISK */
#ifdef CONFIG_BLK_DEV_IDECD
	(void) ide_cdrom_init();
#endif /* CONFIG_BLK_DEV_IDECD */
#ifdef CONFIG_BLK_DEV_IDETAPE
	(void) idetape_init();
#endif /* CONFIG_BLK_DEV_IDETAPE */
#ifdef CONFIG_BLK_DEV_IDEFLOPPY
	(void) idefloppy_init();
#endif /* CONFIG_BLK_DEV_IDEFLOPPY */
#ifdef CONFIG_BLK_DEV_IDESCSI
 #ifdef CONFIG_SCSI
	(void) idescsi_init();
 #else
    #warning ide scsi-emulation selected but no SCSI-subsystem in kernel
 #endif
#endif /* CONFIG_BLK_DEV_IDESCSI */
}

static int default_cleanup (ide_drive_t *drive)
{
	return ide_unregister_subdriver(drive);
}

static int default_standby (ide_drive_t *drive)
{
	return 0;
}

static int default_flushcache (ide_drive_t *drive)
{
	return 0;
}

static ide_startstop_t default_do_request(ide_drive_t *drive, struct request *rq, unsigned long block)
{
	ide_end_request(0, HWGROUP(drive));
	return ide_stopped;
}
 
static void default_end_request (byte uptodate, ide_hwgroup_t *hwgroup)
{
	ide_end_request(uptodate, hwgroup);
}
  
static int default_ioctl (ide_drive_t *drive, struct inode *inode, struct file *file,
			  unsigned int cmd, unsigned long arg)
{
	return -EIO;
}

static int default_open (struct inode *inode, struct file *filp, ide_drive_t *drive)
{
	drive->usage--;
	return -EIO;
}

static void default_release (struct inode *inode, struct file *filp, ide_drive_t *drive)
{
}

static int default_check_media_change (ide_drive_t *drive)
{
	return 1;
}

static void default_pre_reset (ide_drive_t *drive)
{
}

static unsigned long default_capacity (ide_drive_t *drive)
{
	return 0x7fffffff;
}

static ide_startstop_t default_special (ide_drive_t *drive)
{
	special_t *s = &drive->special;

	s->all = 0;
	drive->mult_req = 0;
	return ide_stopped;
}

static int default_reinit (ide_drive_t *drive)
{
	printk(KERN_ERR "%s: does not support hotswap of device class !\n", drive->name);

	return 0;
}

static void setup_driver_defaults (ide_drive_t *drive)
{
	ide_driver_t *d = drive->driver;

	if (d->cleanup == NULL)		d->cleanup = default_cleanup;
	if (d->standby == NULL)		d->standby = default_standby;
	if (d->flushcache == NULL)	d->flushcache = default_flushcache;
	if (d->do_request == NULL)	d->do_request = default_do_request;
	if (d->end_request == NULL)	d->end_request = default_end_request;
	if (d->ioctl == NULL)		d->ioctl = default_ioctl;
	if (d->open == NULL)		d->open = default_open;
	if (d->release == NULL)		d->release = default_release;
	if (d->media_change == NULL)	d->media_change = default_check_media_change;
	if (d->pre_reset == NULL)	d->pre_reset = default_pre_reset;
	if (d->capacity == NULL)	d->capacity = default_capacity;
	if (d->special == NULL)		d->special = default_special;
	if (d->reinit == NULL)		d->reinit = default_reinit;
}

ide_drive_t *ide_scan_devices (byte media, const char *name, ide_driver_t *driver, int n)
{
	unsigned int unit, index, i;

	for (index = 0, i = 0; index < MAX_HWIFS; ++index) {
		ide_hwif_t *hwif = &ide_hwifs[index];
		if (!hwif->present)
			continue;
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			ide_drive_t *drive = &hwif->drives[unit];
			char *req = drive->driver_req;
			if (*req && !strstr(name, req))
				continue;
			if (drive->present && drive->media == media && drive->driver == driver && ++i > n)
				return drive;
		}
	}
	return NULL;
}

int ide_register_subdriver (ide_drive_t *drive, ide_driver_t *driver, int version)
{
	unsigned long flags;
	
	save_flags(flags);		/* all CPUs */
	cli();				/* all CPUs */
	if (version != IDE_SUBDRIVER_VERSION || !drive->present || drive->driver != NULL || drive->busy || drive->usage) {
		restore_flags(flags);	/* all CPUs */
		return 1;
	}
	drive->driver = driver;
	setup_driver_defaults(drive);
	restore_flags(flags);		/* all CPUs */
	if (drive->autotune != 2) {
		if (driver->supports_dma && HWIF(drive)->dmaproc != NULL) {
			/*
			 * Force DMAing for the beginning of the check.
			 * Some chipsets appear to do interesting things,
			 * if not checked and cleared.
			 *   PARANOIA!!!
			 */
			(void) (HWIF(drive)->dmaproc(ide_dma_off_quietly, drive));
			(void) (HWIF(drive)->dmaproc(ide_dma_check, drive));
		}
		drive->dsc_overlap = (drive->next != drive && driver->supports_dsc_overlap);
		drive->nice1 = 1;
	}
	drive->revalidate = 1;
	drive->suspend_reset = 0;
#ifdef CONFIG_PROC_FS
	ide_add_proc_entries(drive->proc, generic_subdriver_entries, drive);
	ide_add_proc_entries(drive->proc, driver->proc, drive);
#endif
	return 0;
}

int ide_unregister_subdriver (ide_drive_t *drive)
{
	unsigned long flags;
	
	save_flags(flags);		/* all CPUs */
	cli();				/* all CPUs */
	if (drive->usage || drive->busy || drive->driver == NULL || DRIVER(drive)->busy) {
		restore_flags(flags);	/* all CPUs */
		return 1;
	}
#if defined(CONFIG_BLK_DEV_ISAPNP) && defined(CONFIG_ISAPNP) && defined(MODULE)
	pnpide_init(0);
#endif /* CONFIG_BLK_DEV_ISAPNP */
#ifdef CONFIG_PROC_FS
	ide_remove_proc_entries(drive->proc, DRIVER(drive)->proc);
	ide_remove_proc_entries(drive->proc, generic_subdriver_entries);
#endif
	auto_remove_settings(drive);
	drive->driver = NULL;
	restore_flags(flags);		/* all CPUs */
	return 0;
}

int ide_register_module (ide_module_t *module)
{
	ide_module_t *p = ide_modules;

	while (p) {
		if (p == module)
			return 1;
		p = p->next;
	}
	module->next = ide_modules;
	ide_modules = module;
	revalidate_drives();
	return 0;
}

void ide_unregister_module (ide_module_t *module)
{
	ide_module_t **p;

	for (p = &ide_modules; (*p) && (*p) != module; p = &((*p)->next));
	if (*p)
		*p = (*p)->next;
}

struct block_device_operations ide_fops[] = {{
	open:			ide_open,
	release:		ide_release,
	ioctl:			ide_ioctl,
	check_media_change:	ide_check_media_change,
	revalidate:		ide_revalidate_disk
}};

EXPORT_SYMBOL(ide_hwifs);
EXPORT_SYMBOL(ide_register_module);
EXPORT_SYMBOL(ide_unregister_module);
EXPORT_SYMBOL(ide_spin_wait_hwgroup);

/*
 * Probe module
 */
#ifdef DEVFS_MUST_DIE
devfs_handle_t ide_devfs_handle;
#endif

EXPORT_SYMBOL(ide_probe);
EXPORT_SYMBOL(drive_is_flashcard);
EXPORT_SYMBOL(ide_timer_expiry);
EXPORT_SYMBOL(ide_intr);
EXPORT_SYMBOL(ide_fops);
EXPORT_SYMBOL(ide_get_queue);
EXPORT_SYMBOL(ide_add_generic_settings);
#ifdef DEVFS_MUST_DIE
EXPORT_SYMBOL(ide_devfs_handle);
#endif
EXPORT_SYMBOL(do_ide_request);
/*
 * Driver module
 */
EXPORT_SYMBOL(ide_scan_devices);
EXPORT_SYMBOL(ide_register_subdriver);
EXPORT_SYMBOL(ide_unregister_subdriver);
EXPORT_SYMBOL(ide_replace_subdriver);
EXPORT_SYMBOL(ide_input_data);
EXPORT_SYMBOL(ide_output_data);
EXPORT_SYMBOL(atapi_input_bytes);
EXPORT_SYMBOL(atapi_output_bytes);
EXPORT_SYMBOL(drive_is_ready);
EXPORT_SYMBOL(ide_set_handler);
EXPORT_SYMBOL(ide_dump_status);
EXPORT_SYMBOL(ide_error);
EXPORT_SYMBOL(ide_fixstring);
EXPORT_SYMBOL(ide_wait_stat);
EXPORT_SYMBOL(ide_do_reset);
EXPORT_SYMBOL(restart_request);
EXPORT_SYMBOL(ide_init_drive_cmd);
EXPORT_SYMBOL(ide_do_drive_cmd);
EXPORT_SYMBOL(ide_end_drive_cmd);
EXPORT_SYMBOL(ide_end_request);
EXPORT_SYMBOL(ide_revalidate_disk);
EXPORT_SYMBOL(ide_cmd);
EXPORT_SYMBOL(ide_wait_cmd);
EXPORT_SYMBOL(ide_wait_cmd_task);
EXPORT_SYMBOL(ide_delay_50ms);
EXPORT_SYMBOL(ide_stall_queue);
#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(ide_add_proc_entries);
EXPORT_SYMBOL(ide_remove_proc_entries);
EXPORT_SYMBOL(proc_ide_read_geometry);
EXPORT_SYMBOL(create_proc_ide_interfaces);
EXPORT_SYMBOL(recreate_proc_ide_device);
EXPORT_SYMBOL(destroy_proc_ide_device);
#endif
EXPORT_SYMBOL(ide_add_setting);
EXPORT_SYMBOL(ide_remove_setting);

EXPORT_SYMBOL(ide_register_hw);
EXPORT_SYMBOL(ide_register);
EXPORT_SYMBOL(ide_unregister);
EXPORT_SYMBOL(ide_setup_ports);
EXPORT_SYMBOL(hwif_unregister);
EXPORT_SYMBOL(get_info_ptr);
EXPORT_SYMBOL(current_capacity);

EXPORT_SYMBOL(system_bus_clock);

EXPORT_SYMBOL(ide_reinit_drive);

#if 0
static int ide_notify_reboot (struct notifier_block *this, unsigned long event, void *x)
{
	ide_hwif_t *hwif;
	ide_drive_t *drive;
	int i, unit;

	switch (event) {
		case SYS_HALT:
		case SYS_POWER_OFF:
		case SYS_RESTART:
			break;
		default:
			return NOTIFY_DONE;
	}

	printk("flushing ide devices: ");

	for (i = 0; i < MAX_HWIFS; i++) {
		hwif = &ide_hwifs[i];
		if (!hwif->present)
			continue;
		for (unit = 0; unit < MAX_DRIVES; ++unit) {
			drive = &hwif->drives[unit];
			if (!drive->present)
				continue;

			/* set the drive to standby */
			printk("%s ", drive->name);
			if (event != SYS_RESTART)
				if (drive->driver != NULL && DRIVER(drive)->standby(drive))
				continue;

			if (drive->driver != NULL && DRIVER(drive)->cleanup(drive))
				continue;
		}
	}
	printk("\n");
	return NOTIFY_DONE;
}

static struct notifier_block ide_notifier = {
	ide_notify_reboot,
	NULL,
	5
};
#endif

/*
 * This is gets invoked once during initialization, to set *everything* up
 */
int __init ide_init (void)
{
	static char banner_printed;
	int i;

	if (!banner_printed) {
		printk(KERN_INFO "Uniform Multi-Platform E-IDE driver " REVISION "\n");
#ifdef DEVFS_MUST_DIE
		ide_devfs_handle = devfs_mk_dir (NULL, "ide", NULL);
#endif
		system_bus_speed = ide_system_bus_speed();
		banner_printed = 1;
	}

	init_ide_data ();

	initializing = 1;
	ide_init_builtin_drivers();
	initializing = 0;

	for (i = 0; i < MAX_HWIFS; ++i) {
		ide_hwif_t  *hwif = &ide_hwifs[i];
		if (hwif->present)
			ide_geninit(hwif);
	}

	/*register_reboot_notifier(&ide_notifier);*/
	return 0;
}

#ifdef MODULE
char *options = NULL;
MODULE_PARM(options,"s");
MODULE_LICENSE("GPL");

static void __init parse_options (char *line)
{
	char *next = line;

	if (line == NULL || !*line)
		return;
	while ((line = next) != NULL) {
 		if ((next = strchr(line,' ')) != NULL)
			*next++ = 0;
		if (!ide_setup(line))
			printk ("Unknown option '%s'\n", line);
	}
}

int init_module (void)
{
	parse_options(options);
	return ide_init();
}

void cleanup_module (void)
{
	int index;

	/*unregister_reboot_notifier(&ide_notifier);*/
	for (index = 0; index < MAX_HWIFS; ++index) {
		ide_unregister(index);
#if defined(CONFIG_BLK_DEV_IDEDMA) && !defined(CONFIG_DMA_NONPCI)
		if (ide_hwifs[index].dma_base)
			(void) ide_release_dma(&ide_hwifs[index]);
#endif /* (CONFIG_BLK_DEV_IDEDMA) && !(CONFIG_DMA_NONPCI) */
	}

#ifdef CONFIG_PROC_FS
	proc_ide_destroy();
#endif
#ifdef DEVFS_MUST_DIE
	devfs_unregister (ide_devfs_handle);
#endif
}

#else /* !MODULE */

__setup("", ide_setup);

#endif /* MODULE */
