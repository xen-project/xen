/*
 *  linux/drivers/ide/ide_modes.h
 *
 *  Copyright (C) 1996  Linus Torvalds, Igor Abramov, and Mark Lord
 */

#ifndef _IDE_MODES_H
#define _IDE_MODES_H

#include <linux/config.h>

/*
 * Shared data/functions for determining best PIO mode for an IDE drive.
 * Most of this stuff originally lived in cmd640.c, and changes to the
 * ide_pio_blacklist[] table should be made with EXTREME CAUTION to avoid
 * breaking the fragile cmd640.c support.
 */

#ifdef CONFIG_BLK_DEV_IDE_MODES

/*
 * Standard (generic) timings for PIO modes, from ATA2 specification.
 * These timings are for access to the IDE data port register *only*.
 * Some drives may specify a mode, while also specifying a different
 * value for cycle_time (from drive identification data).
 */
typedef struct ide_pio_timings_s {
	int	setup_time;	/* Address setup (ns) minimum */
	int	active_time;	/* Active pulse (ns) minimum */
	int	cycle_time;	/* Cycle time (ns) minimum = (setup + active + recovery) */
} ide_pio_timings_t;

typedef struct ide_pio_data_s {
	byte pio_mode;
	byte use_iordy;
	byte overridden;
	byte blacklisted;
	unsigned int cycle_time;
} ide_pio_data_t;
	
#ifndef _IDE_C

int ide_scan_pio_blacklist (char *model);
byte ide_get_best_pio_mode (ide_drive_t *drive, byte mode_wanted, byte max_mode, ide_pio_data_t *d);
extern const ide_pio_timings_t ide_pio_timings[6];

#else /* _IDE_C */

const ide_pio_timings_t ide_pio_timings[6] = {
	{ 70,	165,	600 },	/* PIO Mode 0 */
	{ 50,	125,	383 },	/* PIO Mode 1 */
	{ 30,	100,	240 },	/* PIO Mode 2 */
	{ 30,	80,	180 },	/* PIO Mode 3 with IORDY */
	{ 25,	70,	120 },	/* PIO Mode 4 with IORDY */
	{ 20,	50,	100 }	/* PIO Mode 5 with IORDY (nonstandard) */
};

/*
 * Black list. Some drives incorrectly report their maximal PIO mode,
 * at least in respect to CMD640. Here we keep info on some known drives.
 */
static struct ide_pio_info {
	const char	*name;
	int		pio;
} ide_pio_blacklist [] = {
/*	{ "Conner Peripherals 1275MB - CFS1275A", 4 }, */
	{ "Conner Peripherals 540MB - CFS540A", 3 },

	{ "WDC AC2700",  3 },
	{ "WDC AC2540",  3 },
	{ "WDC AC2420",  3 },
	{ "WDC AC2340",  3 },
	{ "WDC AC2250",  0 },
	{ "WDC AC2200",  0 },
	{ "WDC AC21200", 4 },
	{ "WDC AC2120",  0 },
	{ "WDC AC2850",  3 },
	{ "WDC AC1270",  3 },
	{ "WDC AC1170",  1 },
	{ "WDC AC1210",  1 },
	{ "WDC AC280",   0 },
/*	{ "WDC AC21000", 4 }, */
	{ "WDC AC31000", 3 },
	{ "WDC AC31200", 3 },
/*	{ "WDC AC31600", 4 }, */

	{ "Maxtor 7131 AT", 1 },
	{ "Maxtor 7171 AT", 1 },
	{ "Maxtor 7213 AT", 1 },
	{ "Maxtor 7245 AT", 1 },
	{ "Maxtor 7345 AT", 1 },
	{ "Maxtor 7546 AT", 3 },
	{ "Maxtor 7540 AV", 3 },

	{ "SAMSUNG SHD-3121A", 1 },
	{ "SAMSUNG SHD-3122A", 1 },
	{ "SAMSUNG SHD-3172A", 1 },

/*	{ "ST51080A", 4 },
 *	{ "ST51270A", 4 },
 *	{ "ST31220A", 4 },
 *	{ "ST31640A", 4 },
 *	{ "ST32140A", 4 },
 *	{ "ST3780A",  4 },
 */
	{ "ST5660A",  3 },
	{ "ST3660A",  3 },
	{ "ST3630A",  3 },
	{ "ST3655A",  3 },
	{ "ST3391A",  3 },
	{ "ST3390A",  1 },
	{ "ST3600A",  1 },
	{ "ST3290A",  0 },
	{ "ST3144A",  0 },
	{ "ST3491A",  1 },	/* reports 3, should be 1 or 2 (depending on */	
				/* drive) according to Seagates FIND-ATA program */

	{ "QUANTUM ELS127A", 0 },
	{ "QUANTUM ELS170A", 0 },
	{ "QUANTUM LPS240A", 0 },
	{ "QUANTUM LPS210A", 3 },
	{ "QUANTUM LPS270A", 3 },
	{ "QUANTUM LPS365A", 3 },
	{ "QUANTUM LPS540A", 3 },
	{ "QUANTUM LIGHTNING 540A", 3 },
	{ "QUANTUM LIGHTNING 730A", 3 },

        { "QUANTUM FIREBALL_540", 3 }, /* Older Quantum Fireballs don't work */
        { "QUANTUM FIREBALL_640", 3 }, 
        { "QUANTUM FIREBALL_1080", 3 },
        { "QUANTUM FIREBALL_1280", 3 },
	{ NULL,	0 }
};

/*
 * This routine searches the ide_pio_blacklist for an entry
 * matching the start/whole of the supplied model name.
 *
 * Returns -1 if no match found.
 * Otherwise returns the recommended PIO mode from ide_pio_blacklist[].
 */
int ide_scan_pio_blacklist (char *model)
{
	struct ide_pio_info *p;

	for (p = ide_pio_blacklist; p->name != NULL; p++) {
		if (strncmp(p->name, model, strlen(p->name)) == 0)
			return p->pio;
	}
	return -1;
}

/*
 * This routine returns the recommended PIO settings for a given drive,
 * based on the drive->id information and the ide_pio_blacklist[].
 * This is used by most chipset support modules when "auto-tuning".
 */

/*
 * Drive PIO mode auto selection
 */
byte ide_get_best_pio_mode (ide_drive_t *drive, byte mode_wanted, byte max_mode, ide_pio_data_t *d)
{
	int pio_mode;
	int cycle_time = 0;
	int use_iordy = 0;
	struct hd_driveid* id = drive->id;
	int overridden  = 0;
	int blacklisted = 0;

	if (mode_wanted != 255) {
		pio_mode = mode_wanted;
	} else if (!drive->id) {
		pio_mode = 0;
	} else if ((pio_mode = ide_scan_pio_blacklist(id->model)) != -1) {
		overridden = 1;
		blacklisted = 1;
		use_iordy = (pio_mode > 2);
	} else {
		pio_mode = id->tPIO;
		if (pio_mode > 2) {	/* 2 is maximum allowed tPIO value */
			pio_mode = 2;
			overridden = 1;
		}
		if (id->field_valid & 2) {	  /* drive implements ATA2? */
			if (id->capability & 8) { /* drive supports use_iordy? */
				use_iordy = 1;
				cycle_time = id->eide_pio_iordy;
				if (id->eide_pio_modes & 7) {
					overridden = 0;
					if (id->eide_pio_modes & 4)
						pio_mode = 5;
					else if (id->eide_pio_modes & 2)
						pio_mode = 4;
					else
						pio_mode = 3;
				}
			} else {
				cycle_time = id->eide_pio;
			}
		}

#if 0
		if (drive->id->major_rev_num & 0x0004) printk("ATA-2 ");
#endif

		/*
		 * Conservative "downgrade" for all pre-ATA2 drives
		 */
		if (pio_mode && pio_mode < 4) {
			pio_mode--;
			overridden = 1;
#if 0
			use_iordy = (pio_mode > 2);
#endif
			if (cycle_time && cycle_time < ide_pio_timings[pio_mode].cycle_time)
				cycle_time = 0; /* use standard timing */
		}
	}
	if (pio_mode > max_mode) {
		pio_mode = max_mode;
		cycle_time = 0;
	}
	if (d) {
		d->pio_mode = pio_mode;
		d->cycle_time = cycle_time ? cycle_time : ide_pio_timings[pio_mode].cycle_time;
		d->use_iordy = use_iordy;
		d->overridden = overridden;
		d->blacklisted = blacklisted;
	}
	return pio_mode;
}

#endif /* _IDE_C */
#endif /* CONFIG_BLK_DEV_IDE_MODES */
#endif /* _IDE_MODES_H */
