/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef	FSYS_ZFS

#include <fsimage_grub.h>
#include <fsimage_priv.h>
#include <stdio.h>
#include <inttypes.h>
#include "mb_info.h"


#undef filemax
#undef filepos
#undef errnum


#define	MAXNAMELEN	256
#define	MAXPATHLEN	1024

/**** START FROM disk_io.c ****/
char current_rootpool[MAXNAMELEN];
char current_bootfs[MAXNAMELEN];
uint64_t current_bootfs_obj;
char current_bootpath[MAXPATHLEN];
char current_devid[MAXPATHLEN];
int is_zfs_mount;
unsigned long best_drive;
unsigned long best_part;
int find_best_root;
unsigned long part_length;
/**** END FROM disk_io.c ****/

uint64_t filemax;
uint64_t filepos;

struct multiboot_info mbi;
fsi_file_t *zfs_ffi;
int errnum;
char *bootstring = NULL;

extern int zfs_mount(void);
extern int zfs_open(char *filename);
extern int zfs_read(char *buf, int len);

#define	ZFS_SCRATCH_SIZE	0x400000
#define	FSI_MOS_SHIFT	10
#define	FSI_MOS_MASK	((1 << FSI_MOS_SHIFT) - 1)
unsigned char fsi_mos_buf[ZFS_SCRATCH_SIZE + FSI_MOS_MASK + 1];

#define	FSI_MOS_ALIGN(addr)	(((uintptr_t)addr + FSI_MOS_MASK) & \
				~FSI_MOS_MASK)
#define	FSI_MOS(buf)  		((FSI_MOS_ALIGN(buf) + \
				ZFS_SCRATCH_SIZE - 0x100000) >> FSI_MOS_SHIFT)

static int
fsi_zfs_mount(fsi_file_t *ffi, const char *options)
{
	zfs_ffi = ffi;
	mbi.mem_upper = FSI_MOS(fsi_mos_buf);

	/* If an boot filesystem is passed in, set it to current_bootfs */
	if (options != NULL) {
		if (strlen(options) < MAXNAMELEN) {
			strcpy(current_bootfs, options);
		}
	}

	return (zfs_mount());
}

static int
fsi_zfs_open(fsi_file_t *ffi, char *filename)
{
	char *fsi_bootstring;
	uint64_t *fmax;
	uint64_t *fpos;
	int rc;

	zfs_ffi = ffi;
	fmax = fsig_filemax(ffi);
	fpos = fsig_filepos(ffi);

	rc = zfs_open(filename);
	if (rc != 1) {
		return (rc);
	}

	*fmax = filemax;
	*fpos = filepos;

	if (bootstring == NULL) {
		rc = asprintf(&bootstring,
			      "zfs-bootfs=%s/%"PRIu64",bootpath='%s'",
			      current_rootpool, current_bootfs_obj,
			      current_bootpath);
		if (rc == -1) {
			return (rc);
		}
		fsi_bootstring = fsi_bootstring_alloc(ffi->ff_fsi,
		    strlen(bootstring) + 1);
		strcpy(fsi_bootstring, bootstring);
	}

	return (rc);
}

static int
fsi_zfs_read(fsi_file_t *ffi, char *buf, int len)
{
	uint64_t *fpos;
	int rc;

	zfs_ffi = ffi;
	fpos = fsig_filepos(ffi);
	filepos = *fpos;
	rc = zfs_read(buf, len);
	*fpos = filepos;

	return (rc);
}


fsi_plugin_ops_t *
fsi_init_plugin(int version, fsi_plugin_t *fp, const char **name)
{
       static fsig_plugin_ops_t ops = {
               FSIMAGE_PLUGIN_VERSION,
               .fpo_mount = fsi_zfs_mount,
               .fpo_dir = fsi_zfs_open,
               .fpo_read = fsi_zfs_read,
       };

       *name = "zfs";
       return (fsig_init(fp, &ops));
}

#endif /* FSYS_ZFS */
