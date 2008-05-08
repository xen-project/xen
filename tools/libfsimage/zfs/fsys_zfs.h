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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _FSYS_ZFS_H
#define	_FSYS_ZFS_H

#include <fsimage_grub.h>
#include <fsimage_priv.h>

#include "zfs-include/zfs.h"
#include "zfs-include/dmu.h"
#include "zfs-include/spa.h"
#include "zfs-include/zio.h"
#include "zfs-include/zio_checksum.h"
#include "zfs-include/vdev_impl.h"
#include "zfs-include/zap_impl.h"
#include "zfs-include/zap_leaf.h"
#include "zfs-include/uberblock_impl.h"
#include "zfs-include/dnode.h"
#include "zfs-include/dsl_dir.h"
#include "zfs-include/zfs_acl.h"
#include "zfs-include/zfs_znode.h"
#include "zfs-include/dsl_dataset.h"
#include "zfs-include/zil.h"
#include "zfs-include/dmu_objset.h"

/*
 * Global Memory addresses to store MOS and DNODE data
 */
#define	MOS		((dnode_phys_t *)(((zfs_bootarea_t *) \
			    (ffi->ff_fsi->f_data))->zfs_data))
#define	DNODE		(MOS+1) /* move sizeof(dnode_phys_t) bytes */
#define	ZFS_SCRATCH	((char *)(DNODE+1))

#define	MAXNAMELEN	256

typedef struct zfs_bootarea {
	char zfs_current_bootpath[MAXNAMELEN];
	char zfs_current_rootpool[MAXNAMELEN];
	char zfs_current_bootfs[MAXNAMELEN];
	uint64_t zfs_current_bootfs_obj;
	int zfs_open;

	/* cache for a file block of the currently zfs_open()-ed file */
	void *zfs_file_buf;
	uint64_t zfs_file_start;
	uint64_t zfs_file_end;

	/* cache for a dnode block */
	dnode_phys_t *zfs_dnode_buf;
	dnode_phys_t *zfs_dnode_mdn;
	uint64_t zfs_dnode_start;
	uint64_t zfs_dnode_end;

	char *zfs_stackbase;
	char zfs_data[0x400000];
} zfs_bootarea_t;

/*
 * Verify dnode type.
 * Can only be used in functions returning non-0 for failure.
 */
#define	VERIFY_DN_TYPE(dnp, type) \
	if (type && (dnp)->dn_type != type) { \
		return (ERR_FSYS_CORRUPT); \
	}

/*
 * Verify object set type.
 * Can only be used in functions returning 0 for failure.
 */
#define	VERIFY_OS_TYPE(osp, type) \
	if (type && (osp)->os_type != type) { \
		errnum = ERR_FSYS_CORRUPT; \
		return (0); \
	}

#define	ZPOOL_PROP_BOOTFS		"bootfs"

/* General macros */
#define	BSWAP_8(x)	((x) & 0xff)
#define	BSWAP_16(x)	((BSWAP_8(x) << 8) | BSWAP_8((x) >> 8))
#define	BSWAP_32(x)	((BSWAP_16(x) << 16) | BSWAP_16((x) >> 16))
#define	BSWAP_64(x)	((BSWAP_32(x) << 32) | BSWAP_32((x) >> 32))
#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))

/*
 * XXX Match these macro up with real zfs once we have nvlist support so that we
 * can support large sector disks.
 */
#define	UBERBLOCK_SIZE		(1ULL << UBERBLOCK_SHIFT)
#undef	offsetof
#define	offsetof(t, m)   (size_t)(&(((t *)0)->m))
#define	VDEV_UBERBLOCK_SHIFT	UBERBLOCK_SHIFT
#define	VDEV_UBERBLOCK_OFFSET(n) \
offsetof(vdev_label_t, vl_uberblock[(n) << VDEV_UBERBLOCK_SHIFT])

typedef struct uberblock uberblock_t;

/* XXX Uberblock_phys_t is no longer in the kernel zfs */
typedef struct uberblock_phys {
	uberblock_t	ubp_uberblock;
	char		ubp_pad[UBERBLOCK_SIZE - sizeof (uberblock_t) -
				sizeof (zio_block_tail_t)];
	zio_block_tail_t ubp_zbt;
} uberblock_phys_t;

/*
 * Macros to get fields in a bp or DVA.
 */
#define	P2PHASE(x, align)		((x) & ((align) - 1))
#define	DVA_OFFSET_TO_PHYS_SECTOR(offset) \
	((offset + VDEV_LABEL_START_SIZE) >> SPA_MINBLOCKSHIFT)

/*
 * For nvlist manipulation. (from nvpair.h)
 */
#define	NV_ENCODE_NATIVE	0
#define	NV_ENCODE_XDR		1
#define	HOST_ENDIAN		1	/* for x86 machine */
#define	DATA_TYPE_UINT64	8
#define	DATA_TYPE_STRING	9
#define	DATA_TYPE_NVLIST	19
#define	DATA_TYPE_NVLIST_ARRAY	20

/*
 * Decompression Entry - lzjb
 */
#ifndef	NBBY
#define	NBBY	8
#endif

typedef int zfs_decomp_func_t(void *s_start, void *d_start, size_t s_len,
			size_t d_len);
typedef struct decomp_entry {
	char *name;
	zfs_decomp_func_t *decomp_func;
} decomp_entry_t;

/*
 * FAT ZAP data structures
 */
#define	ZFS_CRC64_POLY 0xC96C5795D7870F42ULL /* ECMA-182, reflected form */
#define	ZAP_HASH_IDX(hash, n)	(((n) == 0) ? 0 : ((hash) >> (64 - (n))))
#define	CHAIN_END	0xffff	/* end of the chunk chain */

/*
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

#define	ZAP_LEAF_HASH_SHIFT(bs)	(bs - 5)
#define	ZAP_LEAF_HASH_NUMENTRIES(bs) (1 << ZAP_LEAF_HASH_SHIFT(bs))
#define	LEAF_HASH(bs, h) \
	((ZAP_LEAF_HASH_NUMENTRIES(bs)-1) & \
	((h) >> (64 - ZAP_LEAF_HASH_SHIFT(bs)-l->l_hdr.lh_prefix_len)))

/*
 * The amount of space available for chunks is:
 * block size shift - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
#define	ZAP_LEAF_NUMCHUNKS(bs) \
	(((1<<bs) - 2*ZAP_LEAF_HASH_NUMENTRIES(bs)) / \
	ZAP_LEAF_CHUNKSIZE - 2)

/*
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
#define	ZAP_LEAF_CHUNK(l, bs, idx) \
	((zap_leaf_chunk_t *)(l->l_hash + ZAP_LEAF_HASH_NUMENTRIES(bs)))[idx]
#define	ZAP_LEAF_ENTRY(l, bs, idx) (&ZAP_LEAF_CHUNK(l, bs, idx).l_entry)

extern void fletcher_2_native(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_2_byteswap(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_4_native(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_4_byteswap(const void *, uint64_t, zio_cksum_t *);
extern void zio_checksum_SHA256(const void *, uint64_t, zio_cksum_t *);
extern int lzjb_decompress(void *, void *, size_t, size_t);

#endif /* !_FSYS_ZFS_H */
