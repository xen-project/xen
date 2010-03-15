/*
 * Block driver for the QCOW version 2 format
 *
 * Copyright (c) 2004-2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <zlib.h>
#include "aes.h"
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tapdisk.h"
#include "tapaio.h"
#include "bswap.h"
#include "blk.h"

#define USE_AIO

#define qemu_malloc malloc
#define qemu_mallocz(size) calloc(1, size)
#define qemu_free free

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE     0 
#endif

#define BLOCK_FLAG_ENCRYPT 1

/*
  Differences with QCOW:

  - Support for multiple incremental snapshots.
  - Memory management by reference counts.
  - Clusters which have a reference count of one have the bit
	QCOW_OFLAG_COPIED to optimize write performance.
  - Size of compressed clusters is stored in sectors to reduce bit usage
	in the cluster offsets.
  - Support for storing additional data (such as the VM state) in the
	snapshots.
  - If a backing store is used, the cluster size is not constrained
	(could be backported to QCOW).
  - L2 tables have always a size of one cluster.
*/

//#define DEBUG_ALLOC
//#define DEBUG_ALLOC2

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define QCOW_VERSION 2

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES	1

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED	  (1LL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED (1LL << 62)

#define REFCOUNT_SHIFT 1 /* refcount size is 2 bytes */

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

typedef struct QCowHeader {
	uint32_t magic;
	uint32_t version;
	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	uint32_t cluster_bits;
	uint64_t size; /* in bytes */

	uint32_t crypt_method;
	uint32_t l1_size; /* XXX: save number of clusters instead ? */
	uint64_t l1_table_offset;
	uint64_t refcount_table_offset;
	uint32_t refcount_table_clusters;
	uint32_t nb_snapshots;
	uint64_t snapshots_offset;
} QCowHeader;

typedef struct __attribute__((packed)) QCowSnapshotHeader {
	/* header is 8 byte aligned */
	uint64_t l1_table_offset;

	uint32_t l1_size;
	uint16_t id_str_size;
	uint16_t name_size;

	uint32_t date_sec;
	uint32_t date_nsec;

	uint64_t vm_clock_nsec;

	uint32_t vm_state_size;
	uint32_t extra_data_size; /* for extension */
	/* extra data follows */
	/* id_str follows */
	/* name follows  */
} QCowSnapshotHeader;

#define L2_CACHE_SIZE 16

typedef struct QCowSnapshot {
	uint64_t l1_table_offset;
	uint32_t l1_size;
	char *id_str;
	char *name;
	uint32_t vm_state_size;
	uint32_t date_sec;
	uint32_t date_nsec;
	uint64_t vm_clock_nsec;
} QCowSnapshot;

typedef struct BDRVQcowState {

	/* blktap additions */
	int fd;
	int poll_pipe[2]; /* dummy fd for polling on */
	char* name;
	int encrypted;
	char backing_file[1024];
	struct disk_driver* backing_hd;

	int64_t total_sectors;

	tap_aio_context_t async;

	/* Original qemu variables */
	int cluster_bits;
	int cluster_size;
	int cluster_sectors;
	int l2_bits;
	int l2_size;
	int l1_size;
	int l1_vm_state_index;
	int csize_shift;
	int csize_mask;
	uint64_t cluster_offset_mask;
	uint64_t l1_table_offset;
	uint64_t *l1_table;
	uint64_t *l2_cache;
	uint64_t l2_cache_offsets[L2_CACHE_SIZE];
	uint32_t l2_cache_counts[L2_CACHE_SIZE];
	uint8_t *cluster_cache;
	uint8_t *cluster_data;
	uint64_t cluster_cache_offset;

	uint64_t *refcount_table;
	uint64_t refcount_table_offset;
	uint32_t refcount_table_size;
	uint64_t refcount_block_cache_offset;
	uint16_t *refcount_block_cache;
	int64_t free_cluster_index;
	int64_t free_byte_offset;

	uint32_t crypt_method; /* current crypt method, 0 if no key yet */
	uint32_t crypt_method_header;
	AES_KEY aes_encrypt_key;
	AES_KEY aes_decrypt_key;
	uint64_t snapshots_offset;
	int snapshots_size;
	int nb_snapshots;
	QCowSnapshot *snapshots;
} BDRVQcowState;

static int decompress_cluster(BDRVQcowState *s, uint64_t cluster_offset);
static int qcow_read(struct disk_driver *bs, uint64_t sector_num,
		uint8_t *buf, int nb_sectors);

static int qcow_read_snapshots(struct disk_driver *bs);
static void qcow_free_snapshots(struct disk_driver *bs);

static int refcount_init(struct disk_driver *bs);
static void refcount_close(struct disk_driver *bs);
static int get_refcount(struct disk_driver *bs, int64_t cluster_index);
static int update_cluster_refcount(struct disk_driver *bs,
		int64_t cluster_index,
		int addend);
static void update_refcount(struct disk_driver *bs,
		int64_t offset, int64_t length,
		int addend);
static int64_t alloc_clusters(struct disk_driver *bs, int64_t size);
static int64_t alloc_bytes(struct disk_driver *bs, int size);
static void free_clusters(struct disk_driver *bs,
		int64_t offset, int64_t size);
#ifdef DEBUG_ALLOC
static void check_refcounts(struct disk_driver *bs);
#endif

static int qcow_sync_read(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *prv);

/**
 * Read with byte offsets
 */
static int bdrv_pread(int fd, int64_t offset, void *buf, int count)
{
	int ret;

	if (lseek(fd, offset, SEEK_SET) == -1) {
		DPRINTF("bdrv_pread failed seek (%#"PRIx64").\n", offset);
		return -1;
	}

	ret =  read(fd, buf, count);
	if (ret < 0) {
		if (lseek(fd, 0, SEEK_END) >= offset) {
			DPRINTF("bdrv_pread read failed (%#"PRIx64", END = %#"PRIx64").\n", 
					offset, lseek(fd, 0, SEEK_END));
			return -1;
		}

		/* Read beyond end of file. Reading zeros. */
		memset(buf, 0, count);
		ret = count;
	} else if (ret < count) {
		/* Read beyond end of file. Filling up with zeros. */
		memset(buf + ret, 0, count - ret);
		ret = count;
	}
	return ret;
}

/**
 * Write with byte offsets
 */
static int bdrv_pwrite(int fd, int64_t offset, const void *buf, int count)
{
	if (lseek(fd, offset, SEEK_SET) == -1) {
		DPRINTF("bdrv_pwrite failed seek (%#"PRIx64").\n", offset);
		return -1;
	}

	return write(fd, buf, count);
}


/**
 * Read with sector offsets
 */
static int bdrv_read(int fd, int64_t offset, void *buf, int count)
{
	return bdrv_pread(fd, 512 * offset, buf, 512 * count);
}

/**
 * Write with sector offsets
 */
static int bdrv_write(int fd, int64_t offset, const void *buf, int count)
{
	return bdrv_pwrite(fd, 512 * offset, buf, count);
}


static int qcow_probe(const uint8_t *buf, int buf_size, const char *filename)
{
	const QCowHeader *cow_header = (const void *)buf;

	if (buf_size >= sizeof(QCowHeader) &&
		be32_to_cpu(cow_header->magic) == QCOW_MAGIC &&
		be32_to_cpu(cow_header->version) == QCOW_VERSION)
		return 100;
	else
		return 0;
}

static int qcow_open(struct disk_driver *bs, const char *filename, td_flag_t flags)
{
	BDRVQcowState *s = bs->private;
	int len, i, shift, ret, max_aio_reqs;
	QCowHeader header;

	int fd, o_flags;
	
	o_flags = O_LARGEFILE | ((flags == TD_RDONLY) ? O_RDONLY : O_RDWR);

	DPRINTF("Opening %s\n", filename);
	fd = open(filename, o_flags);
	if (fd < 0) {
		DPRINTF("Unable to open %s (%d)\n", filename, 0 - errno);
		return -1;
	}

	s->fd = fd;
	if (asprintf(&s->name,"%s", filename) == -1) {
		close(fd);
		return -1;
	}

	ret = read(fd, &header, sizeof(header));
	if (ret != sizeof(header)) {
		DPRINTF("  ret = %d, errno = %d\n", ret, errno);
		goto fail;
	}

	be32_to_cpus(&header.magic);
	be32_to_cpus(&header.version);
	be64_to_cpus(&header.backing_file_offset);
	be32_to_cpus(&header.backing_file_size);
	be64_to_cpus(&header.size);
	be32_to_cpus(&header.cluster_bits);
	be32_to_cpus(&header.crypt_method);
	be64_to_cpus(&header.l1_table_offset);
	be32_to_cpus(&header.l1_size);
	be64_to_cpus(&header.refcount_table_offset);
	be32_to_cpus(&header.refcount_table_clusters);
	be64_to_cpus(&header.snapshots_offset);
	be32_to_cpus(&header.nb_snapshots);

	if (header.magic != QCOW_MAGIC || header.version != QCOW_VERSION)
		goto fail;

	if (header.size <= 1 ||
		header.cluster_bits < 9 ||
		header.cluster_bits > 16)
		goto fail;
	
	s->crypt_method = 0;
	if (header.crypt_method > QCOW_CRYPT_AES)
		goto fail;
	s->crypt_method_header = header.crypt_method;
	if (s->crypt_method_header)
		s->encrypted = 1;
	s->cluster_bits = header.cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = s->cluster_bits - 3; /* L2 is always one cluster */
	s->l2_size = 1 << s->l2_bits;
	s->total_sectors = header.size / 512;
	s->csize_shift = (62 - (s->cluster_bits - 8));
	s->csize_mask = (1 << (s->cluster_bits - 8)) - 1;
	s->cluster_offset_mask = (1LL << s->csize_shift) - 1;
	s->refcount_table_offset = header.refcount_table_offset;
	s->refcount_table_size =
		header.refcount_table_clusters << (s->cluster_bits - 3);

	s->snapshots_offset = header.snapshots_offset;
	s->nb_snapshots = header.nb_snapshots;

//	  DPRINTF("-- cluster_bits/size/sectors = %d/%d/%d\n",
//		  s->cluster_bits, s->cluster_size, s->cluster_sectors);
//	  DPRINTF("-- l2_bits/sizes = %d/%d\n",
//		  s->l2_bits, s->l2_size);

	/* Set sector size and number */
	bs->td_state->sector_size = 512;
	bs->td_state->size = header.size / 512;
	bs->td_state->info = 0;

	/* read the level 1 table */
	s->l1_size = header.l1_size;
	shift = s->cluster_bits + s->l2_bits;
	s->l1_vm_state_index = (header.size + (1LL << shift) - 1) >> shift;
	/* the L1 table must contain at least enough entries to put
	   header.size bytes */
	if (s->l1_size < s->l1_vm_state_index) {
		DPRINTF("L1 table tooo small\n");
		goto fail;
	}
	s->l1_table_offset = header.l1_table_offset;

	s->l1_table = qemu_malloc(s->l1_size * sizeof(uint64_t));
	if (!s->l1_table)
		goto fail;


	if (lseek(fd, s->l1_table_offset, SEEK_SET) == -1)
		goto fail;

	if (read(fd, s->l1_table, s->l1_size * sizeof(uint64_t)) !=
			s->l1_size * sizeof(uint64_t)) {

		DPRINTF("Could not read L1 table\n");
		goto fail;
	}

	for(i = 0;i < s->l1_size; i++) {
		be64_to_cpus(&s->l1_table[i]);
	}
	/* alloc L2 cache */
	s->l2_cache = qemu_malloc(s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
	if (!s->l2_cache)
		goto fail;
	s->cluster_cache = qemu_malloc(s->cluster_size);
	if (!s->cluster_cache)
		goto fail;
	/* one more sector for decompressed data alignment */
	s->cluster_data = qemu_malloc(s->cluster_size + 512);
	if (!s->cluster_data)
		goto fail;
	s->cluster_cache_offset = -1;

	if (refcount_init(bs) < 0)
		goto fail;
		
	/* read the backing file name */
	s->backing_file[0] = '\0';
	if (header.backing_file_offset != 0) {
		len = header.backing_file_size;
		if (len > 1023)
			len = 1023;

		if (lseek(fd, header.backing_file_offset, SEEK_SET) == -1) {
			DPRINTF("Could not lseek to %#"PRIx64"\n", header.backing_file_offset);
			goto fail;
		}

		if (read(fd, s->backing_file, len) != len) {
			DPRINTF("Could not read %#x bytes from %#"PRIx64": %s\n",
				len, header.backing_file_offset,
				strerror(errno));
			goto fail;
		}

		s->backing_file[len] = '\0';
	}

#if 0
	s->backing_hd = NULL;
	if (qcow_read_snapshots(bs) < 0) {
		DPRINTF("Could not read backing files\n");
		goto fail;
	}
#endif

#ifdef DEBUG_ALLOC
	check_refcounts(bs);
#endif
	
	/* Initialize fds */
	for(i = 0; i < MAX_IOFD; i++)
		bs->io_fd[i] = 0;

#ifdef USE_AIO
	/* Initialize AIO */

	/* A segment (i.e. a page) can span multiple clusters */
	max_aio_reqs = ((getpagesize() / s->cluster_size) + 1) *
		MAX_SEGMENTS_PER_REQ * MAX_REQUESTS;

	if (tap_aio_init(&s->async, bs->td_state->size, max_aio_reqs)) {
		DPRINTF("Unable to initialise AIO state\n");
		tap_aio_free(&s->async);
		goto fail;
	}

	bs->io_fd[0] = s->async.aio_ctx.pollfd; 
#else	
	/* Synchronous IO */
	if (pipe(s->poll_pipe)) 
		goto fail;

	bs->io_fd[0] = s->poll_pipe[0];
#endif

	return 0;

 fail:
	DPRINTF("qcow_open failed\n");

#ifdef USE_AIO	
	tap_aio_free(&s->async);
#endif

	qcow_free_snapshots(bs);
	refcount_close(bs);
	qemu_free(s->l1_table);
	qemu_free(s->l2_cache);
	qemu_free(s->cluster_cache);
	qemu_free(s->cluster_data);
	close(fd);
	return -1;
}

static int qcow_set_key(struct disk_driver *bs, const char *key)
{
	BDRVQcowState *s = bs->private;
	uint8_t keybuf[16];
	int len, i;

	memset(keybuf, 0, 16);
	len = strlen(key);
	if (len > 16)
		len = 16;
	/* XXX: we could compress the chars to 7 bits to increase
	   entropy */
	for(i = 0;i < len;i++) {
		keybuf[i] = key[i];
	}
	s->crypt_method = s->crypt_method_header;

	if (AES_set_encrypt_key(keybuf, 128, &s->aes_encrypt_key) != 0)
		return -1;
	if (AES_set_decrypt_key(keybuf, 128, &s->aes_decrypt_key) != 0)
		return -1;
#if 0
	/* test */
	{
		uint8_t in[16];
		uint8_t out[16];
		uint8_t tmp[16];
		for(i=0;i<16;i++)
			in[i] = i;
		AES_encrypt(in, tmp, &s->aes_encrypt_key);
		AES_decrypt(tmp, out, &s->aes_decrypt_key);
		for(i = 0; i < 16; i++)
			printf(" %02x", tmp[i]);
		printf("\n");
		for(i = 0; i < 16; i++)
			printf(" %02x", out[i]);
		printf("\n");
	}
#endif
	return 0;
}

/* The crypt function is compatible with the linux cryptoloop
   algorithm for < 4 GB images. NOTE: out_buf == in_buf is
   supported */
static void encrypt_sectors(BDRVQcowState *s, int64_t sector_num,
		uint8_t *out_buf, const uint8_t *in_buf,
		int nb_sectors, int enc,
		const AES_KEY *key)
{
	union {
		uint64_t ll[2];
		uint8_t b[16];
	} ivec;
	int i;

	for(i = 0; i < nb_sectors; i++) {
		ivec.ll[0] = cpu_to_le64(sector_num);
		ivec.ll[1] = 0;
		AES_cbc_encrypt(in_buf, out_buf, 512, key,
						ivec.b, enc);
		sector_num++;
		in_buf += 512;
		out_buf += 512;
	}
}

static int copy_sectors(struct disk_driver *bs, uint64_t start_sect,
		uint64_t cluster_offset, int n_start, int n_end)
{
	BDRVQcowState *s = bs->private;
	int n, ret;
	
	n = n_end - n_start;
	if (n <= 0)
		return 0;

	ret = qcow_read(bs, start_sect + n_start, s->cluster_data, n);

	if (ret < 0)
		return ret;
	if (s->crypt_method) {
		encrypt_sectors(s, start_sect + n_start,
				s->cluster_data,
				s->cluster_data, n, 1,
				&s->aes_encrypt_key);
	}


	ret = bdrv_pwrite(s->fd, cluster_offset + 512*n_start, s->cluster_data, n*512);

	if (ret < 0)
		return ret;
	return 0;
}

static void l2_cache_reset(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;

	memset(s->l2_cache, 0, s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_offsets, 0, L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_counts, 0, L2_CACHE_SIZE * sizeof(uint32_t));
}

static inline int l2_cache_new_entry(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	uint32_t min_count;
	int min_index, i;

	/* find a new entry in the least used one */
	min_index = 0;
	min_count = 0xffffffff;
	for(i = 0; i < L2_CACHE_SIZE; i++) {
		if (s->l2_cache_counts[i] < min_count) {
			min_count = s->l2_cache_counts[i];
			min_index = i;
		}
	}
	return min_index;
}

static int64_t align_offset(int64_t offset, int n)
{
	offset = (offset + n - 1) & ~(n - 1);
	return offset;
}

static int grow_l1_table(struct disk_driver *bs, int min_size)
{
	BDRVQcowState *s = bs->private;
	int new_l1_size, new_l1_size2, ret, i;
	uint64_t *new_l1_table;
	uint64_t new_l1_table_offset;
	uint64_t data64;
	uint32_t data32;

	new_l1_size = s->l1_size;
	if (min_size <= new_l1_size)
		return 0;
	while (min_size > new_l1_size) {
		new_l1_size = (new_l1_size * 3 + 1) / 2;
	}

#ifdef DEBUG_ALLOC2
	DPRINTF("grow l1_table from %d to %d\n", s->l1_size, new_l1_size);
#endif

	new_l1_size2 = sizeof(uint64_t) * new_l1_size;
	new_l1_table = qemu_mallocz(new_l1_size2);
	if (!new_l1_table)
		return -ENOMEM;
	memcpy(new_l1_table, s->l1_table, s->l1_size * sizeof(uint64_t));

	/* write new table (align to cluster) */
	new_l1_table_offset = alloc_clusters(bs, new_l1_size2);

	for(i = 0; i < s->l1_size; i++)
		new_l1_table[i] = cpu_to_be64(new_l1_table[i]);


	if (lseek(s->fd, new_l1_table_offset, SEEK_SET) == -1)
		goto fail;

	ret = write(s->fd, new_l1_table, new_l1_size2);
	if (ret != new_l1_size2)
		goto fail;


	for(i = 0; i < s->l1_size; i++)
		new_l1_table[i] = be64_to_cpu(new_l1_table[i]);

	/* set new table */
	data64 = cpu_to_be64(new_l1_table_offset);

	if (lseek(s->fd, offsetof(QCowHeader, l1_table_offset), SEEK_SET) == -1)
		goto fail;

	if (write(s->fd, &data64, sizeof(data64)) != sizeof(data64))
		goto fail;

	data32 = cpu_to_be32(new_l1_size);

	if (bdrv_pwrite(s->fd, offsetof(QCowHeader, l1_size),
					&data32, sizeof(data32)) != sizeof(data32))
		goto fail;
	qemu_free(s->l1_table);
	free_clusters(bs, s->l1_table_offset, s->l1_size * sizeof(uint64_t));
	s->l1_table_offset = new_l1_table_offset;
	s->l1_table = new_l1_table;
	s->l1_size = new_l1_size;
	return 0;
 fail:
	qemu_free(s->l1_table);
	return -EIO;
}

/* 'allocate' is:
 *
 * 0 not to allocate.
 *
 * 1 to allocate a normal cluster (for sector indexes 'n_start' to
 * 'n_end')
 *
 * 2 to allocate a compressed cluster of size
 * 'compressed_size'. 'compressed_size' must be > 0 and <
 * cluster_size
 *
 * return 0 if not allocated.
 */
static uint64_t get_cluster_offset(struct disk_driver *bs,
		uint64_t offset, int allocate,
		int compressed_size,
		int n_start, int n_end)
{
	BDRVQcowState *s = bs->private;
	int min_index, i, j, l1_index, l2_index, ret;
	uint64_t l2_offset, *l2_table, cluster_offset, tmp, old_l2_offset;

	l1_index = offset >> (s->l2_bits + s->cluster_bits);
	if (l1_index >= s->l1_size) {
		/* outside l1 table is allowed: we grow the table if needed */
		if (!allocate)
			return 0;

		if (grow_l1_table(bs, l1_index + 1) < 0) {
			DPRINTF("Could not grow L1 table");
			return 0;
		}
	}

	l2_offset = s->l1_table[l1_index];
	if (!l2_offset) {
		if (!allocate)
			return 0;

	l2_allocate:
		old_l2_offset = l2_offset;
		/* allocate a new l2 entry */
		l2_offset = alloc_clusters(bs, s->l2_size * sizeof(uint64_t));
		
		/* update the L1 entry */
		s->l1_table[l1_index] = l2_offset | QCOW_OFLAG_COPIED;
		tmp = cpu_to_be64(l2_offset | QCOW_OFLAG_COPIED);
		if (bdrv_pwrite(s->fd, s->l1_table_offset + l1_index * sizeof(tmp),
						&tmp, sizeof(tmp)) != sizeof(tmp))
			return 0;
		min_index = l2_cache_new_entry(bs);
		l2_table = s->l2_cache + (min_index << s->l2_bits);

		if (old_l2_offset == 0) {
			memset(l2_table, 0, s->l2_size * sizeof(uint64_t));
		} else {
			if (bdrv_pread(s->fd, old_l2_offset,
						   l2_table, s->l2_size * sizeof(uint64_t)) !=
				s->l2_size * sizeof(uint64_t))
				return 0;
		}
		if (bdrv_pwrite(s->fd, l2_offset,
						l2_table, s->l2_size * sizeof(uint64_t)) !=
			s->l2_size * sizeof(uint64_t))
			return 0;
	} else {
		if (!(l2_offset & QCOW_OFLAG_COPIED)) {
			if (allocate) {
				free_clusters(bs, l2_offset, s->l2_size * sizeof(uint64_t));
				goto l2_allocate;
			}
		} else {
			l2_offset &= ~QCOW_OFLAG_COPIED;
		}
		for(i = 0; i < L2_CACHE_SIZE; i++) {
			if (l2_offset == s->l2_cache_offsets[i]) {
				/* increment the hit count */
				if (++s->l2_cache_counts[i] == 0xffffffff) {
					for(j = 0; j < L2_CACHE_SIZE; j++) {
						s->l2_cache_counts[j] >>= 1;
					}
				}
				l2_table = s->l2_cache + (i << s->l2_bits);
				goto found;
			}
		}
		/* not found: load a new entry in the least used one */
		min_index = l2_cache_new_entry(bs);
		l2_table = s->l2_cache + (min_index << s->l2_bits);

		if (bdrv_pread(s->fd, l2_offset, l2_table, s->l2_size * sizeof(uint64_t)) !=
			s->l2_size * sizeof(uint64_t))
		{
			DPRINTF("Could not read L2 table");
			return 0;
		}
	}
	s->l2_cache_offsets[min_index] = l2_offset;
	s->l2_cache_counts[min_index] = 1;
found:
	l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);

	cluster_offset = be64_to_cpu(l2_table[l2_index]);
	if (!cluster_offset) {
		if (!allocate) {
			return cluster_offset;
		}
	} else if (!(cluster_offset & QCOW_OFLAG_COPIED)) {
		if (!allocate)
			return cluster_offset;
		/* free the cluster */
		if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			int nb_csectors;
			nb_csectors = ((cluster_offset >> s->csize_shift) &
					s->csize_mask) + 1;
			free_clusters(bs, (cluster_offset & s->cluster_offset_mask) & ~511,
					nb_csectors * 512);
		} else {
			free_clusters(bs, cluster_offset, s->cluster_size);
		}
	} else {
		cluster_offset &= ~QCOW_OFLAG_COPIED;
		return cluster_offset;
	}
	if (allocate == 1) {
		/* allocate a new cluster */
		cluster_offset = alloc_clusters(bs, s->cluster_size);

		/* we must initialize the cluster content which won't be
		   written */
		if ((n_end - n_start) < s->cluster_sectors) {
			uint64_t start_sect;

			start_sect = (offset & ~(s->cluster_size - 1)) >> 9;
			ret = copy_sectors(bs, start_sect,
					cluster_offset, 0, n_start);
			if (ret < 0)
				return 0;
			ret = copy_sectors(bs, start_sect,
					cluster_offset, n_end, s->cluster_sectors);
			if (ret < 0)
				return 0;
		}
		tmp = cpu_to_be64(cluster_offset | QCOW_OFLAG_COPIED);
	} else {
		int nb_csectors;
		cluster_offset = alloc_bytes(bs, compressed_size);
		nb_csectors = ((cluster_offset + compressed_size - 1) >> 9) -
			(cluster_offset >> 9);
		cluster_offset |= QCOW_OFLAG_COMPRESSED |
			((uint64_t)nb_csectors << s->csize_shift);
		/* compressed clusters never have the copied flag */
		tmp = cpu_to_be64(cluster_offset);
	}
	/* update L2 table */
	l2_table[l2_index] = tmp;

	if (bdrv_pwrite(s->fd, l2_offset + l2_index * sizeof(tmp), &tmp, sizeof(tmp)) != sizeof(tmp))
		return 0;
	return cluster_offset;
}

static int qcow_is_allocated(struct disk_driver *bs, int64_t sector_num,
		int nb_sectors, int *pnum)
{
	BDRVQcowState *s = bs->private;
	int index_in_cluster, n;
	uint64_t cluster_offset;

	cluster_offset = get_cluster_offset(bs, sector_num << 9, 0, 0, 0, 0);
	index_in_cluster = sector_num & (s->cluster_sectors - 1);
	n = s->cluster_sectors - index_in_cluster;
	if (n > nb_sectors)
		n = nb_sectors;
	*pnum = n;
	return (cluster_offset != 0);
}

static int decompress_buffer(uint8_t *out_buf, int out_buf_size,
		const uint8_t *buf, int buf_size)
{
	z_stream strm1, *strm = &strm1;
	int ret, out_len;

	memset(strm, 0, sizeof(*strm));

	strm->next_in = (uint8_t *)buf;
	strm->avail_in = buf_size;
	strm->next_out = out_buf;
	strm->avail_out = out_buf_size;

	ret = inflateInit2(strm, -12);
	if (ret != Z_OK)
		return -1;
	ret = inflate(strm, Z_FINISH);
	out_len = strm->next_out - out_buf;
	if ((ret != Z_STREAM_END && ret != Z_BUF_ERROR) ||
		out_len != out_buf_size) {
		inflateEnd(strm);
		return -1;
	}
	inflateEnd(strm);
	return 0;
}

static int decompress_cluster(BDRVQcowState *s, uint64_t cluster_offset)
{
	int ret, csize, nb_csectors, sector_offset;
	uint64_t coffset;

	coffset = cluster_offset & s->cluster_offset_mask;
	if (s->cluster_cache_offset != coffset) {
		nb_csectors = ((cluster_offset >> s->csize_shift) & s->csize_mask) + 1;
		sector_offset = coffset & 511;
		csize = nb_csectors * 512 - sector_offset;
		ret = bdrv_read(s->fd, coffset >> 9, s->cluster_data, nb_csectors);
		if (ret < 0) {
			return -1;
		}
		if (decompress_buffer(s->cluster_cache, s->cluster_size,
							  s->cluster_data + sector_offset, csize) < 0) {
			return -1;
		}
		s->cluster_cache_offset = coffset;
	}
	return 0;
}

/* handle reading after the end of the backing file */
static int backing_read1(struct disk_driver *bs,
		int64_t sector_num, uint8_t *buf, int nb_sectors)
{
	int n1;
	BDRVQcowState* s = bs->private;

	if ((sector_num + nb_sectors) <= s->total_sectors)
		return nb_sectors;
	if (sector_num >= s->total_sectors)
		n1 = 0;
	else
		n1 = s->total_sectors - sector_num;
	memset(buf + n1 * 512, 0, 512 * (nb_sectors - n1));
	return n1;
}

/**
 * Reads a number of sectors from the image (synchronous)
 */
static int qcow_read(struct disk_driver *bs, uint64_t sector_num,
		uint8_t *buf, int nb_sectors)
{
	BDRVQcowState *s = bs->private;
	int ret, index_in_cluster, n, n1;
	uint64_t cluster_offset;

	while (nb_sectors > 0) {
		cluster_offset = get_cluster_offset(bs, sector_num << 9, 0, 0, 0, 0);
		index_in_cluster = sector_num & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;
		if (!cluster_offset) {

			if (bs->next) {

				/* Read from backing file */
				struct disk_driver *parent = bs->next;

				ret = qcow_sync_read(parent, sector_num, 
						nb_sectors, (char*) buf, NULL, 0, NULL);

#if 0		
				/* read from the base image */
				n1 = backing_read1(s->backing_hd, sector_num, buf, n);
				if (n1 > 0) {
					ret = bdrv_read(((BDRVQcowState*) s->backing_hd)->fd, sector_num, buf, n1);
					if (ret < 0) {
						DPRINTF("read from backing file failed: ret = %d; errno = %d\n", ret, errno);
						return -1;
					}
				}
#endif
			} else {
				memset(buf, 0, 512 * n);
			}
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			if (decompress_cluster(s, cluster_offset) < 0) {
				DPRINTF("read/decompression failed: errno = %d\n", errno);
				return -1;
			}
			memcpy(buf, s->cluster_cache + index_in_cluster * 512, 512 * n);
		} else {
			ret = bdrv_pread(s->fd, cluster_offset + index_in_cluster * 512, buf, n * 512);
			if (ret != n * 512) {
				DPRINTF("read failed: ret = %d != n * 512 = %d; errno = %d\n", ret, n * 512, errno);
				DPRINTF("  cluster_offset = %"PRIx64", index = %d; sector_num = %"PRId64"", cluster_offset, index_in_cluster, sector_num);
				return -1;
			}

			if (s->crypt_method) {
				encrypt_sectors(s, sector_num, buf, buf, n, 0,
						&s->aes_decrypt_key);
			}
		}
		nb_sectors -= n;
		sector_num += n;
		buf += n * 512;
	}
	return 0;
}

/**
 * Writes a number of sectors to the image (synchronous)
 */
static int qcow_write(struct disk_driver *bs, uint64_t sector_num,
		const uint8_t *buf, int nb_sectors)
{
	BDRVQcowState *s = bs->private;
	int ret, index_in_cluster, n;
	uint64_t cluster_offset;

	while (nb_sectors > 0) {
		index_in_cluster = sector_num & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;
		cluster_offset = get_cluster_offset(bs, sector_num << 9, 1, 0,
											index_in_cluster,
											index_in_cluster + n);
		if (!cluster_offset) {
			DPRINTF("qcow_write: cluster_offset == 0\n");
			DPRINTF("  index = %d; sector_num = %"PRId64"\n", 
				index_in_cluster, sector_num);
			return -1;
		}

		if (s->crypt_method) {
			encrypt_sectors(s, sector_num, s->cluster_data, buf, n, 1,
					&s->aes_encrypt_key);
			ret = bdrv_pwrite(s->fd, cluster_offset + index_in_cluster * 512,
					s->cluster_data, n * 512);
		} else {
			ret = bdrv_pwrite(s->fd, cluster_offset + index_in_cluster * 512, buf, n * 512);
		}
		if (ret != n * 512) {
			DPRINTF("write failed: ret = %d != n * 512 = %d; errno = %d\n", ret, n * 512, errno);
			DPRINTF("  cluster_offset = %"PRIx64", index = %d; sector_num = %"PRId64"\n", cluster_offset, index_in_cluster, sector_num);
			return -1;
		}

		nb_sectors -= n;
		sector_num += n;
		buf += n * 512;
	}
	s->cluster_cache_offset = -1; /* disable compressed cache */
	return 0;
}



#ifdef USE_AIO

/*
 * QCOW2 specific AIO functions
 */

static int qcow_queue_read(struct disk_driver *bs, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *private)
{
	BDRVQcowState *s = bs->private;
	int i, index_in_cluster, n, ret;
	int rsp = 0;
	uint64_t cluster_offset;

	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++) 
		if (!tap_aio_can_lock(&s->async, sector + i)) 
			return cb(bs, -EBUSY, sector, nb_sectors, id, private);

	while (nb_sectors > 0) {
		
		cluster_offset = get_cluster_offset(bs, sector << 9, 0, 0, 0, 0);
				
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->async.iocb_free_count == 0 || !tap_aio_lock(&s->async, sector)) 
			return cb(bs, -EBUSY, sector, nb_sectors, id, private);

		if (!cluster_offset) {

			/* The requested sector is not allocated */
			tap_aio_unlock(&s->async, sector);
			ret = cb(bs, BLK_NOT_ALLOCATED, 
					sector, n, id, private);
			if (ret == -EBUSY) {
				/* mark remainder of request
				 * as busy and try again later */
				return cb(bs, -EBUSY, sector + n,
						nb_sectors - n, id, private);
			} else {
				rsp += ret;
			}

		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {

			/* sync read for compressed clusters */
			tap_aio_unlock(&s->async, sector);
			if (decompress_cluster(s, cluster_offset) < 0) {
				rsp += cb(bs, -EIO, sector, nb_sectors, id, private);
				goto done;
			}
			memcpy(buf, s->cluster_cache + index_in_cluster * 512, 
					512 * n);
			rsp += cb(bs, 0, sector, n, id, private);

		} else {

			/* async read */
			tap_aio_read(&s->async, s->fd, n * 512, 
					(cluster_offset + index_in_cluster * 512),
					buf, cb, id, sector, private);
		}

		/* Prepare for next sector to read */
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}

done:
	return rsp;

}

static int qcow_queue_write(struct disk_driver *bs, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *private)
{
	BDRVQcowState *s = bs->private;
	int i, n, index_in_cluster;
	uint64_t cluster_offset;
	const uint8_t *src_buf;
		
	
	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++) 
		if (!tap_aio_can_lock(&s->async, sector + i)) 
			return cb(bs, -EBUSY, sector, nb_sectors, id, private);


	while (nb_sectors > 0) {
				
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->async.iocb_free_count == 0 || !tap_aio_lock(&s->async, sector))
			return cb(bs, -EBUSY, sector, nb_sectors, id, private);


		cluster_offset = get_cluster_offset(bs, sector << 9, 1, 0,
				index_in_cluster, 
				index_in_cluster+n);

		if (!cluster_offset) {
			DPRINTF("Ooops, no write cluster offset!\n");
			tap_aio_unlock(&s->async, sector);
			return cb(bs, -EIO, sector, nb_sectors, id, private);
		}


		// TODO Encryption

		tap_aio_write(&s->async, s->fd, n * 512, 
				(cluster_offset + index_in_cluster*512),
				buf, cb, id, sector, private);

		/* Prepare for next sector to write */
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}

		
	s->cluster_cache_offset = -1; /* disable compressed cache */

	return 0;
}


#endif /* USE_AIO */


static int qcow_close(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	
#ifdef USE_AIO	
	io_destroy(s->async.aio_ctx.aio_ctx);
	tap_aio_free(&s->async);
#else		
	close(s->poll_pipe[0]);
	close(s->poll_pipe[1]);
#endif		

	qemu_free(s->l1_table);
	qemu_free(s->l2_cache);
	qemu_free(s->cluster_cache);
	qemu_free(s->cluster_data);
	refcount_close(bs);
	return close(s->fd);
}

/* XXX: use std qcow open function ? */
typedef struct QCowCreateState {
	int cluster_size;
	int cluster_bits;
	uint16_t *refcount_block;
	uint64_t *refcount_table;
	int64_t l1_table_offset;
	int64_t refcount_table_offset;
	int64_t refcount_block_offset;
} QCowCreateState;

static void create_refcount_update(QCowCreateState *s,
		int64_t offset, int64_t size)
{
	int refcount;
	int64_t start, last, cluster_offset;
	uint16_t *p;

	start = offset & ~(s->cluster_size - 1);
	last = (offset + size - 1)	& ~(s->cluster_size - 1);
	for(cluster_offset = start; cluster_offset <= last;
		cluster_offset += s->cluster_size) {
		p = &s->refcount_block[cluster_offset >> s->cluster_bits];
		refcount = be16_to_cpu(*p);
		refcount++;
		*p = cpu_to_be16(refcount);
	}
}

static int qcow_submit(struct disk_driver *bs)
{
	struct BDRVQcowState *s = (struct BDRVQcowState*) bs->private;

	fsync(s->fd);
	return tap_aio_submit(&s->async);
}


/*********************************************************/
/* snapshot support */


static void qcow_free_snapshots(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	int i;

	for(i = 0; i < s->nb_snapshots; i++) {
		qemu_free(s->snapshots[i].name);
		qemu_free(s->snapshots[i].id_str);
	}
	qemu_free(s->snapshots);
	s->snapshots = NULL;
	s->nb_snapshots = 0;
}

static int qcow_read_snapshots(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	QCowSnapshotHeader h;
	QCowSnapshot *sn;
	int i, id_str_size, name_size;
	int64_t offset;
	uint32_t extra_data_size;

	offset = s->snapshots_offset;
	s->snapshots = qemu_mallocz(s->nb_snapshots * sizeof(QCowSnapshot));
	if (!s->snapshots)
		goto fail;
	for(i = 0; i < s->nb_snapshots; i++) {
		offset = align_offset(offset, 8);
		if (bdrv_pread(s->fd, offset, &h, sizeof(h)) != sizeof(h))
			goto fail;
		offset += sizeof(h);
		sn = s->snapshots + i;
		sn->l1_table_offset = be64_to_cpu(h.l1_table_offset);
		sn->l1_size = be32_to_cpu(h.l1_size);
		sn->vm_state_size = be32_to_cpu(h.vm_state_size);
		sn->date_sec = be32_to_cpu(h.date_sec);
		sn->date_nsec = be32_to_cpu(h.date_nsec);
		sn->vm_clock_nsec = be64_to_cpu(h.vm_clock_nsec);
		extra_data_size = be32_to_cpu(h.extra_data_size);

		id_str_size = be16_to_cpu(h.id_str_size);
		name_size = be16_to_cpu(h.name_size);

		offset += extra_data_size;

		sn->id_str = qemu_malloc(id_str_size + 1);
		if (!sn->id_str)
			goto fail;
		if (bdrv_pread(s->fd, offset, sn->id_str, id_str_size) != id_str_size)
			goto fail;
		offset += id_str_size;
		sn->id_str[id_str_size] = '\0';

		sn->name = qemu_malloc(name_size + 1);
		if (!sn->name)
			goto fail;
		if (bdrv_pread(s->fd, offset, sn->name, name_size) != name_size)
			goto fail;
		offset += name_size;
		sn->name[name_size] = '\0';
	}
	s->snapshots_size = offset - s->snapshots_offset;
	return 0;
fail:
	qcow_free_snapshots(bs);
	return -1;
}


/*********************************************************/
/* refcount handling */

static int refcount_init(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	int ret, refcount_table_size2, i;

	s->refcount_block_cache = qemu_malloc(s->cluster_size);
	if (!s->refcount_block_cache)
		goto fail;
	refcount_table_size2 = s->refcount_table_size * sizeof(uint64_t);
	s->refcount_table = qemu_malloc(refcount_table_size2);
	if (!s->refcount_table)
		goto fail;
	if (s->refcount_table_size > 0) {
		ret = bdrv_pread(s->fd, s->refcount_table_offset,
				s->refcount_table, refcount_table_size2);
		if (ret != refcount_table_size2)
			goto fail;
		for(i = 0; i < s->refcount_table_size; i++)
			be64_to_cpus(&s->refcount_table[i]);
	}
	return 0;
 fail:
	return -ENOMEM;
}

static void refcount_close(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	qemu_free(s->refcount_block_cache);
	qemu_free(s->refcount_table);
}


static int load_refcount_block(struct disk_driver *bs,
		int64_t refcount_block_offset)
{
	BDRVQcowState *s = bs->private;
	int ret;
	ret = bdrv_pread(s->fd, refcount_block_offset, s->refcount_block_cache,
			s->cluster_size);
	if (ret != s->cluster_size)
		return -EIO;
	s->refcount_block_cache_offset = refcount_block_offset;
	return 0;
}

static int get_refcount(struct disk_driver *bs, int64_t cluster_index)
{
	BDRVQcowState *s = bs->private;
	int refcount_table_index, block_index;
	int64_t refcount_block_offset;

	refcount_table_index = cluster_index >> (s->cluster_bits - REFCOUNT_SHIFT);
	if (refcount_table_index >= s->refcount_table_size)
		return 0;
	refcount_block_offset = s->refcount_table[refcount_table_index];
	if (!refcount_block_offset)
		return 0;
	if (refcount_block_offset != s->refcount_block_cache_offset) {
		/* better than nothing: return allocated if read error */
		if (load_refcount_block(bs, refcount_block_offset) < 0)
			return 1;
	}
	block_index = cluster_index &
		((1 << (s->cluster_bits - REFCOUNT_SHIFT)) - 1);
	return be16_to_cpu(s->refcount_block_cache[block_index]);
}

/* return < 0 if error */
static int64_t alloc_clusters_noref(struct disk_driver *bs, int64_t size)
{
	BDRVQcowState *s = bs->private;
	int i, nb_clusters;

	nb_clusters = (size + s->cluster_size - 1) >> s->cluster_bits;
	for(;;) {
		if (get_refcount(bs, s->free_cluster_index) == 0) {
			s->free_cluster_index++;
			for(i = 1; i < nb_clusters; i++) {
				if (get_refcount(bs, s->free_cluster_index) != 0)
					goto not_found;
				s->free_cluster_index++;
			}

#ifdef DEBUG_ALLOC2
			DPRINTF("alloc_clusters: size=%ld -> %ld\n",
				   size,
				   (s->free_cluster_index - nb_clusters) << s->cluster_bits);
#endif

			return (s->free_cluster_index - nb_clusters) << s->cluster_bits;
		} else {
		not_found:
			s->free_cluster_index++;
		}
	}
}

static int64_t alloc_clusters(struct disk_driver *bs, int64_t size)
{
	int64_t offset;

	offset = alloc_clusters_noref(bs, size);
	update_refcount(bs, offset, size, 1);
	return offset;
}

/* only used to allocate compressed sectors. We try to allocate
   contiguous sectors. size must be <= cluster_size */
static int64_t alloc_bytes(struct disk_driver *bs, int size)
{
	BDRVQcowState *s = bs->private;
	int64_t offset, cluster_offset;
	int free_in_cluster;

	assert(size > 0 && size <= s->cluster_size);
	if (s->free_byte_offset == 0) {
		s->free_byte_offset = alloc_clusters(bs, s->cluster_size);
	}
redo:
	free_in_cluster = s->cluster_size -
		(s->free_byte_offset & (s->cluster_size - 1));
	if (size <= free_in_cluster) {
		/* enough space in current cluster */
		offset = s->free_byte_offset;
		s->free_byte_offset += size;
		free_in_cluster -= size;
		if (free_in_cluster == 0)
			s->free_byte_offset = 0;
		if ((offset & (s->cluster_size - 1)) != 0)
			update_cluster_refcount(bs, offset >> s->cluster_bits, 1);
	} else {
		offset = alloc_clusters(bs, s->cluster_size);
		cluster_offset = s->free_byte_offset & ~(s->cluster_size - 1);
		if ((cluster_offset + s->cluster_size) == offset) {
			/* we are lucky: contiguous data */
			offset = s->free_byte_offset;
			update_cluster_refcount(bs, offset >> s->cluster_bits, 1);
			s->free_byte_offset += size;
		} else {
			s->free_byte_offset = offset;
			goto redo;
		}
	}
	return offset;
}

static void free_clusters(struct disk_driver *bs,
		int64_t offset, int64_t size)
{
	update_refcount(bs, offset, size, -1);
}

static int grow_refcount_table(struct disk_driver *bs, int min_size)
{
	BDRVQcowState *s = bs->private;
	int new_table_size, new_table_size2, refcount_table_clusters, i, ret;
	uint64_t *new_table;
	int64_t table_offset;
	uint64_t data64;
	uint32_t data32;
	int old_table_size;
	int64_t old_table_offset;

	if (min_size <= s->refcount_table_size)
		return 0;
	
	/* compute new table size */
	refcount_table_clusters = s->refcount_table_size >> (s->cluster_bits - 3);
	for(;;) {
		if (refcount_table_clusters == 0) {
			refcount_table_clusters = 1;
		} else {
			refcount_table_clusters = (refcount_table_clusters * 3 + 1) / 2;
		}
		new_table_size = refcount_table_clusters << (s->cluster_bits - 3);
		if (min_size <= new_table_size)
			break;
	}

#ifdef DEBUG_ALLOC2
	printf("grow_refcount_table from %d to %d\n",
		   s->refcount_table_size,
		   new_table_size);
#endif
	new_table_size2 = new_table_size * sizeof(uint64_t);
	new_table = qemu_mallocz(new_table_size2);
	if (!new_table)
		return -ENOMEM;
	memcpy(new_table, s->refcount_table,
		   s->refcount_table_size * sizeof(uint64_t));
	for(i = 0; i < s->refcount_table_size; i++)
		cpu_to_be64s(&new_table[i]);
	/* Note: we cannot update the refcount now to avoid recursion */
	table_offset = alloc_clusters_noref(bs, new_table_size2);
	ret = bdrv_pwrite(s->fd, table_offset, new_table, new_table_size2);
	if (ret != new_table_size2)
		goto fail;
	for(i = 0; i < s->refcount_table_size; i++)
		be64_to_cpus(&new_table[i]);

	data64 = cpu_to_be64(table_offset);
	if (bdrv_pwrite(s->fd, offsetof(QCowHeader, refcount_table_offset),
					&data64, sizeof(data64)) != sizeof(data64))
		goto fail;
	data32 = cpu_to_be32(refcount_table_clusters);
	if (bdrv_pwrite(s->fd, offsetof(QCowHeader, refcount_table_clusters),
					&data32, sizeof(data32)) != sizeof(data32))
		goto fail;
	qemu_free(s->refcount_table);
	old_table_offset = s->refcount_table_offset;
	old_table_size = s->refcount_table_size;
	s->refcount_table = new_table;
	s->refcount_table_size = new_table_size;
	s->refcount_table_offset = table_offset;

	update_refcount(bs, table_offset, new_table_size2, 1);
	free_clusters(bs, old_table_offset, old_table_size * sizeof(uint64_t));
	return 0;
 fail:
	free_clusters(bs, table_offset, new_table_size2);
	qemu_free(new_table);
	return -EIO;
}

/* addend must be 1 or -1 */
/* XXX: cache several refcount block clusters ? */
static int update_cluster_refcount(struct disk_driver *bs,
		int64_t cluster_index,
		int addend)
{
	BDRVQcowState *s = bs->private;
	int64_t offset, refcount_block_offset;
	int ret, refcount_table_index, block_index, refcount;
	uint64_t data64;

	refcount_table_index = cluster_index >> (s->cluster_bits - REFCOUNT_SHIFT);
	if (refcount_table_index >= s->refcount_table_size) {
		if (addend < 0)
			return -EINVAL;
		ret = grow_refcount_table(bs, refcount_table_index + 1);
		if (ret < 0)
			return ret;
	}
	refcount_block_offset = s->refcount_table[refcount_table_index];
	if (!refcount_block_offset) {
		if (addend < 0)
			return -EINVAL;
		/* create a new refcount block */
		/* Note: we cannot update the refcount now to avoid recursion */
		offset = alloc_clusters_noref(bs, s->cluster_size);
		memset(s->refcount_block_cache, 0, s->cluster_size);
		ret = bdrv_pwrite(s->fd, offset, s->refcount_block_cache, s->cluster_size);
		if (ret != s->cluster_size)
			return -EINVAL;
		s->refcount_table[refcount_table_index] = offset;
		data64 = cpu_to_be64(offset);
		ret = bdrv_pwrite(s->fd, s->refcount_table_offset +
						  refcount_table_index * sizeof(uint64_t),
						  &data64, sizeof(data64));
		if (ret != sizeof(data64))
			return -EINVAL;

		refcount_block_offset = offset;
		s->refcount_block_cache_offset = offset;
		update_refcount(bs, offset, s->cluster_size, 1);
	} else {
		if (refcount_block_offset != s->refcount_block_cache_offset) {
			if (load_refcount_block(bs, refcount_block_offset) < 0)
				return -EIO;
		}
	}
	/* we can update the count and save it */
	block_index = cluster_index &
		((1 << (s->cluster_bits - REFCOUNT_SHIFT)) - 1);
	refcount = be16_to_cpu(s->refcount_block_cache[block_index]);
	refcount += addend;
	if (refcount < 0 || refcount > 0xffff)
		return -EINVAL;
	if (refcount == 0 && cluster_index < s->free_cluster_index) {
		s->free_cluster_index = cluster_index;
	}
	s->refcount_block_cache[block_index] = cpu_to_be16(refcount);
	if (bdrv_pwrite(s->fd,
					refcount_block_offset + (block_index << REFCOUNT_SHIFT),
					&s->refcount_block_cache[block_index], 2) != 2)
		return -EIO;
	return refcount;
}

static void update_refcount(struct disk_driver *bs,
		int64_t offset, int64_t length,
		int addend)
{
	BDRVQcowState *s = bs->private;
	int64_t start, last, cluster_offset;

#ifdef DEBUG_ALLOC2
	printf("update_refcount: offset=%lld size=%lld addend=%d\n",
		   offset, length, addend);
#endif
	if (length <= 0)
		return;
	start = offset & ~(s->cluster_size - 1);
	last = (offset + length - 1) & ~(s->cluster_size - 1);
	for(cluster_offset = start; cluster_offset <= last;
		cluster_offset += s->cluster_size) {
		update_cluster_refcount(bs, cluster_offset >> s->cluster_bits, addend);
	}
}

#ifdef DEBUG_ALLOC
static void inc_refcounts(struct disk_driver *bs,
		uint16_t *refcount_table,
		int refcount_table_size,
		int64_t offset, int64_t size)
{
	BDRVQcowState *s = bs->private;
	int64_t start, last, cluster_offset;
	int k;

	if (size <= 0)
		return;

	start = offset & ~(s->cluster_size - 1);
	last = (offset + size - 1) & ~(s->cluster_size - 1);
	for(cluster_offset = start; cluster_offset <= last;
		cluster_offset += s->cluster_size) {
		k = cluster_offset >> s->cluster_bits;
		if (k < 0 || k >= refcount_table_size) {
			printf("ERROR: invalid cluster offset=0x%llx\n", cluster_offset);
		} else {
			if (++refcount_table[k] == 0) {
				printf("ERROR: overflow cluster offset=0x%llx\n", cluster_offset);
			}
		}
	}
}

static int check_refcounts_l1(struct disk_driver *bs,
		uint16_t *refcount_table,
		int refcount_table_size,
		int64_t l1_table_offset, int l1_size,
		int check_copied)
{
	BDRVQcowState *s = bs->private;
	uint64_t *l1_table, *l2_table, l2_offset, offset, l1_size2;
	int l2_size, i, j, nb_csectors, refcount;

	l2_table = NULL;
	l1_size2 = l1_size * sizeof(uint64_t);

	inc_refcounts(bs, refcount_table, refcount_table_size,
				  l1_table_offset, l1_size2);

	l1_table = qemu_malloc(l1_size2);
	if (!l1_table)
		goto fail;
	if (bdrv_pread(s->fd, l1_table_offset,
				   l1_table, l1_size2) != l1_size2)
		goto fail;
	for(i = 0;i < l1_size; i++)
		be64_to_cpus(&l1_table[i]);

	l2_size = s->l2_size * sizeof(uint64_t);
	l2_table = qemu_malloc(l2_size);
	if (!l2_table)
		goto fail;
	for(i = 0; i < l1_size; i++) {
		l2_offset = l1_table[i];
		if (l2_offset) {
			if (check_copied) {
				refcount = get_refcount(bs, (l2_offset & ~QCOW_OFLAG_COPIED) >> s->cluster_bits);
				if ((refcount == 1) != ((l2_offset & QCOW_OFLAG_COPIED) != 0)) {
					printf("ERROR OFLAG_COPIED: l2_offset=%llx refcount=%d\n",
						   l2_offset, refcount);
				}
			}
			l2_offset &= ~QCOW_OFLAG_COPIED;
			if (bdrv_pread(s->fd, l2_offset, l2_table, l2_size) != l2_size)
				goto fail;
			for(j = 0; j < s->l2_size; j++) {
				offset = be64_to_cpu(l2_table[j]);
				if (offset != 0) {
					if (offset & QCOW_OFLAG_COMPRESSED) {
						if (offset & QCOW_OFLAG_COPIED) {
							printf("ERROR: cluster %lld: copied flag must never be set for compressed clusters\n",
								   offset >> s->cluster_bits);
							offset &= ~QCOW_OFLAG_COPIED;
						}
						nb_csectors = ((offset >> s->csize_shift) &
									   s->csize_mask) + 1;
						offset &= s->cluster_offset_mask;
						inc_refcounts(bs, refcount_table,
								refcount_table_size,
								offset & ~511, nb_csectors * 512);
					} else {
						if (check_copied) {
							refcount = get_refcount(bs, (offset & ~QCOW_OFLAG_COPIED) >> s->cluster_bits);
							if ((refcount == 1) != ((offset & QCOW_OFLAG_COPIED) != 0)) {
								printf("ERROR OFLAG_COPIED: offset=%llx refcount=%d\n",
									   offset, refcount);
							}
						}
						offset &= ~QCOW_OFLAG_COPIED;
						inc_refcounts(bs, refcount_table,
								refcount_table_size,
								offset, s->cluster_size);
					}
				}
			}
			inc_refcounts(bs, refcount_table,
					refcount_table_size,
					l2_offset,
					s->cluster_size);
		}
	}
	qemu_free(l1_table);
	qemu_free(l2_table);
	return 0;
 fail:
	printf("ERROR: I/O error in check_refcounts_l1\n");
	qemu_free(l1_table);
	qemu_free(l2_table);
	return -EIO;
}

static void check_refcounts(struct disk_driver *bs)
{
	BDRVQcowState *s = bs->private;
	int64_t size;
	int nb_clusters, refcount1, refcount2, i;
	QCowSnapshot *sn;
	uint16_t *refcount_table;

	size = bdrv_getlength(s->fd);
	nb_clusters = (size + s->cluster_size - 1) >> s->cluster_bits;
	refcount_table = qemu_mallocz(nb_clusters * sizeof(uint16_t));

	/* header */
	inc_refcounts(bs, refcount_table, nb_clusters,
			0, s->cluster_size);

	check_refcounts_l1(bs, refcount_table, nb_clusters,
			s->l1_table_offset, s->l1_size, 1);

	/* snapshots */
	for(i = 0; i < s->nb_snapshots; i++) {
		sn = s->snapshots + i;
		check_refcounts_l1(bs, refcount_table, nb_clusters,
						   sn->l1_table_offset, sn->l1_size, 0);
	}
	inc_refcounts(bs, refcount_table, nb_clusters,
				  s->snapshots_offset, s->snapshots_size);

	/* refcount data */
	inc_refcounts(bs, refcount_table, nb_clusters,
			s->refcount_table_offset,
			s->refcount_table_size * sizeof(uint64_t));

	for(i = 0; i < s->refcount_table_size; i++) {
		int64_t offset;
		offset = s->refcount_table[i];
		if (offset != 0) {
			inc_refcounts(bs, refcount_table, nb_clusters,
					offset, s->cluster_size);
		}
	}

	/* compare ref counts */
	for(i = 0; i < nb_clusters; i++) {
		refcount1 = get_refcount(bs, i);
		refcount2 = refcount_table[i];
		if (refcount1 != refcount2)
			printf("ERROR cluster %d refcount=%d reference=%d\n",
				   i, refcount1, refcount2);
	}

	qemu_free(refcount_table);
}
#endif


/**
 * Wrapper for synchronous read.
 * This function is called when not using AIO at all (#undef USE_AIO) or
 * for accessing the backing file.
 */
static int qcow_sync_read(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *prv)
{
	int ret = qcow_read(dd, sector, (uint8_t*) buf, nb_sectors);

	if (cb != NULL) {
		return cb(dd, (ret < 0) ? ret : 0, sector, nb_sectors, id, prv);
	} else {
		return ret;
	}
}

#ifndef USE_AIO
/**
 * Wrapper for synchronous write
 */
static int qcow_sync_write(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *prv)
{
	int ret = qcow_write(dd, sector, (uint8_t*) buf, nb_sectors);
	
	return cb(dd, (ret < 0) ? ret : 0, sector, nb_sectors, id, prv);
}
#endif



#ifndef USE_AIO

static int qcow_do_callbacks(struct disk_driver *dd, int sid)
{
	return 1;
}

#else

static int qcow_do_callbacks(struct disk_driver *dd, int sid)
{
	int ret, i, nr_events, rsp = 0,*ptr;
	struct io_event *ep;
	struct BDRVQcowState *prv = (struct BDRVQcowState*)dd->private;

	if (sid > MAX_IOFD) return 1;

	nr_events = tap_aio_get_events(&prv->async.aio_ctx);

repeat:
	for (ep = prv->async.aio_events, i = nr_events; i-- > 0; ep++) {
		struct iocb		   *io	= ep->obj;
		struct pending_aio *pio;

		pio = &prv->async.pending_aio[(long)io->data];

		tap_aio_unlock(&prv->async, pio->sector);

		if (prv->crypt_method)
			encrypt_sectors(prv, pio->sector, 
					(unsigned char *)pio->buf, 
					(unsigned char *)pio->buf, 
					pio->nb_sectors, 0, 
					&prv->aes_decrypt_key);

		rsp += pio->cb(dd, ep->res == io->u.c.nbytes ? 0 : 1, 
			pio->sector, pio->nb_sectors,
			pio->id, pio->private);

		prv->async.iocb_free[prv->async.iocb_free_count++] = io;
	}

	if (nr_events) {
		nr_events = tap_aio_more_events(&prv->async.aio_ctx);
		goto repeat;
	}

	tap_aio_continue(&prv->async.aio_ctx);

	return rsp;
}

#endif	

static int get_filesize(char *filename, uint64_t *size, struct stat *st)
{
	int fd;
	QCowHeader header;

	/*Set to the backing file size*/
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, &header, sizeof(header)) < sizeof(header)) {
		close(fd);
		return -1;
	}
	close(fd);
	
	be32_to_cpus(&header.magic);
	be32_to_cpus(&header.version);
	be64_to_cpus(&header.size);
	if (header.magic == QCOW_MAGIC && header.version == QCOW_VERSION) {
		*size = header.size >> SECTOR_SHIFT;
		return 0;
	}

	if(S_ISBLK(st->st_mode)) {
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			return -1;
		if (blk_getimagesize(fd, size) != 0) {
			close(fd);
			return -1;
		}
		close(fd);
	} else *size = (st->st_size >> SECTOR_SHIFT);	
	return 0;
}

/**
 * @return 
 *	   0 if parent id successfully retrieved;
 *	   TD_NO_PARENT if no parent exists;
 *	   -errno on error
 */
static int qcow_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	struct BDRVQcowState* s = (struct BDRVQcowState*) dd->private;

	if (s->backing_file[0] == '\0')
		return TD_NO_PARENT;

	id->name = strdup(s->backing_file);
	id->drivertype = DISK_TYPE_AIO;

	return 0;
}

static int qcow_validate_parent(struct disk_driver *child, 
		struct disk_driver *parent, td_flag_t flags)
{
	struct stat stats;
	uint64_t psize, csize;
	
	if (stat(parent->name, &stats))
		return -EINVAL;
	if (get_filesize(parent->name, &psize, &stats))
		return -EINVAL;

	if (stat(child->name, &stats))
		return -EINVAL;
	if (get_filesize(child->name, &csize, &stats))
		return -EINVAL;

	if (csize != psize)
		return -EINVAL;

	return 0;
}

int qcow2_create(const char *filename, uint64_t total_size,
                      const char *backing_file, int flags)
{
    int fd, header_size, backing_filename_len, l1_size, i, shift, l2_bits;
    int ret = 0;
    QCowHeader header;
    uint64_t tmp, offset;
    QCowCreateState s1, *s = &s1;

    memset(s, 0, sizeof(*s));

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd < 0)
        return -1;
    memset(&header, 0, sizeof(header));
    header.magic = cpu_to_be32(QCOW_MAGIC);
    header.version = cpu_to_be32(QCOW_VERSION);
    header.size = cpu_to_be64(total_size * 512);
    header_size = sizeof(header);
    backing_filename_len = 0;
    if (backing_file) {
        header.backing_file_offset = cpu_to_be64(header_size);
        backing_filename_len = strlen(backing_file);
        header.backing_file_size = cpu_to_be32(backing_filename_len);
        header_size += backing_filename_len;
    }
    s->cluster_bits = 12;  /* 4 KB clusters */
    s->cluster_size = 1 << s->cluster_bits;
    header.cluster_bits = cpu_to_be32(s->cluster_bits);
    header_size = (header_size + 7) & ~7;
    if (flags & BLOCK_FLAG_ENCRYPT) {
        header.crypt_method = cpu_to_be32(QCOW_CRYPT_AES);
    } else {
        header.crypt_method = cpu_to_be32(QCOW_CRYPT_NONE);
    }
    l2_bits = s->cluster_bits - 3;
    shift = s->cluster_bits + l2_bits;
    l1_size = (((total_size * 512) + (1LL << shift) - 1) >> shift);
    offset = align_offset(header_size, s->cluster_size);
    s->l1_table_offset = offset;
    header.l1_table_offset = cpu_to_be64(s->l1_table_offset);
    header.l1_size = cpu_to_be32(l1_size);
    offset += align_offset(l1_size * sizeof(uint64_t), s->cluster_size);

    s->refcount_table = qemu_mallocz(s->cluster_size);
    s->refcount_block = qemu_mallocz(s->cluster_size);

    s->refcount_table_offset = offset;
    header.refcount_table_offset = cpu_to_be64(offset);
    header.refcount_table_clusters = cpu_to_be32(1);
    offset += s->cluster_size;

    s->refcount_table[0] = cpu_to_be64(offset);
    s->refcount_block_offset = offset;
    offset += s->cluster_size;

    /* update refcounts */
    create_refcount_update(s, 0, header_size);
    create_refcount_update(s, s->l1_table_offset, l1_size * sizeof(uint64_t));
    create_refcount_update(s, s->refcount_table_offset, s->cluster_size);
    create_refcount_update(s, s->refcount_block_offset, s->cluster_size);

    /* write all the data */
    ret = write(fd, &header, sizeof(header));
    if (ret < 0)
        goto out;
    if (backing_file) {
        ret = write(fd, backing_file, backing_filename_len);
        if (ret < 0)
            goto out;
    }
    lseek(fd, s->l1_table_offset, SEEK_SET);
    tmp = 0;
    for(i = 0;i < l1_size; i++) {
        ret = write(fd, &tmp, sizeof(tmp));
        if (ret < 0)
            goto out;
    }
    lseek(fd, s->refcount_table_offset, SEEK_SET);
    ret = write(fd, s->refcount_table, s->cluster_size);
    if (ret < 0)
        goto out;

    lseek(fd, s->refcount_block_offset, SEEK_SET);
    ret = write(fd, s->refcount_block, s->cluster_size);
    if (ret < 0)
        goto out;
    ret = 0;

  out:
    qemu_free(s->refcount_table);
    qemu_free(s->refcount_block);
    close(fd);
    return ret;
}



struct tap_disk tapdisk_qcow2 = {
	"qcow2",
	sizeof(BDRVQcowState),
	qcow_open,
#ifdef USE_AIO
	qcow_queue_read,
	qcow_queue_write,
#else
	qcow_sync_read,
	qcow_sync_write,
#endif
	qcow_submit,
	qcow_close,
	qcow_do_callbacks,
	qcow_get_parent_id,
	qcow_validate_parent
};
