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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LINUX_CPER_H
#define LINUX_CPER_H

#include <xen/types.h>
#include <xen/string.h>
#include <xen/time.h>

typedef struct {
	uint8_t b[16];
} uuid_le;

static inline int uuid_le_cmp(const uuid_le u1, const uuid_le u2)
{
        return memcmp(&u1, &u2, sizeof(uuid_le));
}

static inline uint64_t cper_next_record_id(void)
{
	static uint64_t record_id;

	if (!record_id)
		record_id = (uint64_t)get_sec() << 32;

	return ++record_id;
}

#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
((uuid_le)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})

/* CPER record signature and the size */
#define CPER_SIG_RECORD				"CPER"
#define CPER_SIG_SIZE				4
/* Used in signature_end field in struct cper_record_header */
#define CPER_SIG_END				0xffffffffU

/*
 * CPER record header revision, used in revision field in struct
 * cper_record_header
 */
#define CPER_RECORD_REV				0x0100

/*
 * Severity difinition for error_severity in struct cper_record_header
 * and section_severity in struct cper_section_descriptor
 */
#define CPER_SER_RECOVERABLE			0x0
#define CPER_SER_FATAL				0x1
#define CPER_SER_CORRECTED			0x2
#define CPER_SER_INFORMATIONAL			0x3

/*
 * Notification type used to generate error record, used in
 * notification_type in struct cper_record_header
 *
 * Corrected Machine Check
 */
#define CPER_NOTIFY_CMC							\
	UUID_LE(0x2DCE8BB1U, 0xBDD7, 0x450e, 0xB9, 0xAD, 0x9C, 0xF4,	\
		0xEB, 0xD4, 0xF8, 0x90)
/* Corrected Platform Error */
#define CPER_NOTIFY_CPE							\
	UUID_LE(0x4E292F96U, 0xD843, 0x4a55, 0xA8, 0xC2, 0xD4, 0x81,	\
		0xF2, 0x7E, 0xBE, 0xEE)
/* Machine Check Exception */
#define CPER_NOTIFY_MCE							\
	UUID_LE(0xE8F56FFEU, 0x919C, 0x4cc5, 0xBA, 0x88, 0x65, 0xAB,	\
		0xE1, 0x49, 0x13, 0xBB)
/* PCI Express Error */
#define CPER_NOTIFY_PCIE						\
	UUID_LE(0xCF93C01FU, 0x1A16, 0x4dfc, 0xB8, 0xBC, 0x9C, 0x4D,	\
		0xAF, 0x67, 0xC1, 0x04)
/* INIT Record (for IPF) */
#define CPER_NOTIFY_INIT						\
	UUID_LE(0xCC5263E8U, 0x9308, 0x454a, 0x89, 0xD0, 0x34, 0x0B,	\
		0xD3, 0x9B, 0xC9, 0x8E)
/* Non-Maskable Interrupt */
#define CPER_NOTIFY_NMI							\
	UUID_LE(0x5BAD89FFU, 0xB7E6, 0x42c9, 0x81, 0x4A, 0xCF, 0x24,	\
		0x85, 0xD6, 0xE9, 0x8A)
/* BOOT Error Record */
#define CPER_NOTIFY_BOOT						\
	UUID_LE(0x3D61A466U, 0xAB40, 0x409a, 0xA6, 0x98, 0xF3, 0x62,	\
		0xD4, 0x64, 0xB3, 0x8F)
/* DMA Remapping Error */
#define CPER_NOTIFY_DMAR						\
	UUID_LE(0x667DD791U, 0xC6B3, 0x4c27, 0x8A, 0x6B, 0x0F, 0x8E,	\
		0x72, 0x2D, 0xEB, 0x41)

/*
 * Flags bits definitions for flags in struct cper_record_header
 * If set, the error has been recovered
 */
#define CPER_HW_ERROR_FLAGS_RECOVERED		0x1
/* If set, the error is for previous boot */
#define CPER_HW_ERROR_FLAGS_PREVERR		0x2
/* If set, the error is injected for testing */
#define CPER_HW_ERROR_FLAGS_SIMULATED		0x4

/*
 * CPER section header revision, used in revision field in struct
 * cper_section_descriptor
 */
#define CPER_SEC_REV				0x0100

/*
 * Validation bits difinition for validation_bits in struct
 * cper_section_descriptor. If set, corresponding fields in struct
 * cper_section_descriptor contain valid information.
 *
 * corresponds fru_id
 */
#define CPER_SEC_VALID_FRU_ID			0x1
/* corresponds fru_text */
#define CPER_SEC_VALID_FRU_TEXT			0x2

/*
 * Flags bits definitions for flags in struct cper_section_descriptor
 *
 * If set, the section is associated with the error condition
 * directly, and should be focused on
 */
#define CPER_SEC_PRIMARY			0x0001

/*
 * All tables and structs must be byte-packed to match CPER
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)

struct cper_record_header {
	char	signature[CPER_SIG_SIZE];	/* must be CPER_SIG_RECORD */
	uint16_t revision;			/* must be CPER_RECORD_REV */
	uint32_t signature_end;			/* must be CPER_SIG_END */
	uint16_t section_count;
	uint32_t error_severity;
	uint32_t validation_bits;
	uint32_t record_length;
	uint64_t timestamp;
	uuid_le	platform_id;
	uuid_le	partition_id;
	uuid_le	creator_id;
	uuid_le	notification_type;
	uint64_t record_id;
	uint32_t flags;
	uint64_t persistence_information;
	uint8_t reserved[12];			/* must be zero */
};

struct cper_section_descriptor {
	uint32_t section_offset;	/* Offset in bytes of the
					 *  section body from the base
					 *  of the record header */
	uint32_t section_length;
	uint16_t revision;		/* must be CPER_RECORD_REV */
	uint8_t	validation_bits;
	uint8_t	reserved;		/* must be zero */
	uint32_t flags;
	uuid_le	section_type;
	uuid_le	fru_id;
	uint32_t section_severity;
	uint8_t	fru_text[20];
};

/* Reset to default packing */
#pragma pack()

#endif
