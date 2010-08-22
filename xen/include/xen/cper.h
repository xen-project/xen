/*
 * UEFI Common Platform Error Record
 *
 * Copyright (C) 2010, Intel Corp.
 *	Author: Huang Ying <ying.huang@intel.com>
 *	Ported by: Liu, Jinsong <jinsong.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef LINUX_CPER_H
#define LINUX_CPER_H

#include <xen/types.h>

typedef struct {
	__u8 b[16];
} uuid_le;

/* CPER record signature and the size */
#define CPER_SIG_RECORD				"CPER"
#define CPER_SIG_SIZE				4
/* Used in signature_end field in struct cper_record_header */
#define CPER_SIG_END				0xffffffff

/*
 * All tables and structs must be byte-packed to match CPER
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)

struct cper_record_header {
	char	signature[CPER_SIG_SIZE];	/* must be CPER_SIG_RECORD */
	__u16	revision;			/* must be CPER_RECORD_REV */
	__u32	signature_end;			/* must be CPER_SIG_END */
	__u16	section_count;
	__u32	error_severity;
	__u32	validation_bits;
	__u32	record_length;
	__u64	timestamp;
	uuid_le	platform_id;
	uuid_le	partition_id;
	uuid_le	creator_id;
	uuid_le	notification_type;
	__u64	record_id;
	__u32	flags;
	__u64	persistence_information;
	__u8	reserved[12];			/* must be zero */
};

struct cper_section_descriptor {
	__u32	section_offset;		/* Offset in bytes of the
					 *  section body from the base
					 *  of the record header */
	__u32	section_length;
	__u16	revision;		/* must be CPER_RECORD_REV */
	__u8	validation_bits;
	__u8	reserved;		/* must be zero */
	__u32	flags;
	uuid_le	section_type;
	uuid_le	fru_id;
	__u32	section_severity;
	__u8	fru_text[20];
};

/* Reset to default packing */
#pragma pack()

#endif
