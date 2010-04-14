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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _FSI_ZFS_H
#define _FSI_ZFS_H

#ifdef  FSYS_ZFS

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <fsimage_grub.h>


/*** START FROM shared.h ****/
#include "mb_info.h"

/* Boot signature related defines for the findroot command */
#define	BOOTSIGN_DIR	"/boot/grub/bootsign"
#define	BOOTSIGN_BACKUP	"/etc/bootsign"

/* Maybe redirect memory requests through grub_scratch_mem. */
#define	RAW_ADDR(x)	(x)
#define	RAW_SEG(x)	(x)

/* ZFS will use the top 4 Meg of physical memory (below 4Gig) for sratch */
#define	ZFS_SCRATCH_SIZE	0x400000

#define	MAXPATHLEN	1024
#define	MAXNAMELEN	256
#define	MIN(x, y)	((x) < (y) ? (x) : (y))

#define	MAXUINT		0xFFFFFFFF

#undef NULL
#define NULL         ((void *) 0)

#define grub_printf printf
#define grub_strcmp strcmp
#define grub_strncmp strncmp
#define grub_strstr strstr
#define grub_strlen strlen
#define grub_memmove memmove

extern char current_bootpath[MAXPATHLEN];
extern char current_rootpool[MAXNAMELEN];
extern char current_bootfs[MAXNAMELEN];
extern uint64_t current_bootfs_obj;
extern char current_devid[MAXPATHLEN];
extern int is_zfs_mount;
extern unsigned long best_drive;
extern unsigned long best_part;
extern int find_best_root;

extern unsigned long part_length;

#undef	filemax
#undef	filepos
extern uint64_t filemax;
extern uint64_t filepos;

extern struct multiboot_info mbi;

/*** END FROM shared.h ***/

#ifdef	__linux__
typedef unsigned char	uchar_t;
#endif

typedef struct fsi_file *fsi_file_handle_t;
extern fsi_file_handle_t zfs_ffi;
extern int fsig_devread(fsi_file_handle_t, unsigned int, unsigned int,
    unsigned int, char *);

#undef	devread
#define devread(a, b, c, d)	fsig_devread(zfs_ffi, a, b, c, d)

#undef	errnum
extern int errnum;

#endif  /* FSI_ZFS */

#endif /* !_FSI_ZFS_H */

