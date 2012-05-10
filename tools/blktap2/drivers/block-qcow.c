/* block-qcow.c
 *
 * Asynchronous Qemu copy-on-write disk implementation.
 * Code based on the Qemu implementation
 * (see copyright notice below)
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 *
 */

/*
 * Block driver for the QCOW format
 * 
 * Copyright (c) 2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files(the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <zlib.h>
#include <inttypes.h>
#include <libaio.h>
#include <limits.h>
#include "bswap.h"
#include "aes.h"
#include "md5.h"

#include "tapdisk.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-disktype.h"
#include "qcow.h"
#include "blk.h"
#include "atomicio.h"

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE     0
#endif

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

struct pending_aio {
        td_callback_t cb;
        int id;
        void *private;
	int nb_sectors;
	char *buf;
	uint64_t sector;
};

#undef IOCB_IDX
#define IOCB_IDX(_s, _io) ((_io) - (_s)->iocb_list)

#define ZERO_TEST(_b) (_b | 0x00)

struct qcow_request {
	td_request_t         treq;
	struct tiocb         tiocb;
	struct tdqcow_state  *state;
};

static int decompress_cluster(struct tdqcow_state *s, uint64_t cluster_offset);

uint32_t gen_cksum(char *ptr, int len)
{
  int i;
  uint32_t md[4];

  /* Generate checksum */
  md5_sum((const uint8_t*)ptr, len, (uint8_t*)md);

  return md[0];
}

static void free_aio_state(struct tdqcow_state* s)
{
	free(s->aio_requests);
	free(s->aio_free_list);
}

static int init_aio_state(td_driver_t *driver)
{
	int i, ret;
	td_disk_info_t *bs = &(driver->info);
	struct tdqcow_state   *s  = (struct tdqcow_state *)driver->data;
	
        // A segment (i.e. a page) can span multiple clusters
        s->max_aio_reqs = ((getpagesize() / s->cluster_size) + 1) *
	  MAX_SEGMENTS_PER_REQ * MAX_REQUESTS;

	s->aio_free_count = s->max_aio_reqs;

	if (!(s->aio_requests  = calloc(s->max_aio_reqs, sizeof(struct qcow_request))) || 
	    !(s->aio_free_list = calloc(s->max_aio_reqs, sizeof(struct qcow_request)))) {
	    DPRINTF("Failed to allocate AIO structs (max_aio_reqs = %d)\n",
		    s->max_aio_reqs);
	    goto fail;
	}

	for (i = 0; i < s->max_aio_reqs; i++)
		s->aio_free_list[i] = &s->aio_requests[i];

        DPRINTF("AIO state initialised\n");

        return 0;
 fail:
	return -1;
}

int get_filesize(char *filename, uint64_t *size, struct stat *st)
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
	be64_to_cpus(&header.size);
	if (header.magic == QCOW_MAGIC) {
		*size = header.size >> SECTOR_SHIFT;
		return 0;
	}

	if(S_ISBLK(st->st_mode)) {
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			return -1;
		if (blk_getimagesize(fd, size) != 0) {
			printf("Unable to get Block device size\n");
			close(fd);
			return -1;
		}
		close(fd);
	} else *size = (st->st_size >> SECTOR_SHIFT);	
	return 0;
}

static int qcow_set_key(struct tdqcow_state *s, const char *key)
{
	uint8_t keybuf[16];
	int len, i;
	
	memset(keybuf, 0, 16);
	len = strlen(key);
	if (len > 16)
		len = 16;
	/* XXX: we could compress the chars to 7 bits to increase
	   entropy */
	for (i = 0; i < len; i++) {
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
		for (i=0; i<16; i++)
			in[i] = i;
		AES_encrypt(in, tmp, &s->aes_encrypt_key);
		AES_decrypt(tmp, out, &s->aes_decrypt_key);
		for (i = 0; i < 16; i++)
			DPRINTF(" %02x", tmp[i]);
		DPRINTF("\n");
		for (i = 0; i < 16; i++)
			DPRINTF(" %02x", out[i]);
		DPRINTF("\n");
	}
#endif
	return 0;
}

void tdqcow_complete(void *arg, struct tiocb *tiocb, int err)
{
	struct qcow_request *aio = (struct qcow_request *)arg;
	struct tdqcow_state *s = aio->state;

	td_complete_request(aio->treq, err);

	s->aio_free_list[s->aio_free_count++] = aio;
}

static void async_read(td_driver_t *driver, td_request_t treq)
{
	int size;
	uint64_t offset;
	struct qcow_request *aio;
	struct tdqcow_state *prv;

	prv    = (struct tdqcow_state *)driver->data;
	size   = treq.secs * driver->info.sector_size;
	offset = treq.sec  * (uint64_t)driver->info.sector_size;

	if (prv->aio_free_count == 0)
		goto fail;

	aio        = prv->aio_free_list[--prv->aio_free_count];
	aio->treq  = treq;
	aio->state = prv;

	td_prep_read(&aio->tiocb, prv->fd, treq.buf,
		     size, offset, tdqcow_complete, aio);
	td_queue_tiocb(driver, &aio->tiocb);

	return;

fail:
	td_complete_request(treq, -EBUSY);
}

static void async_write(td_driver_t *driver, td_request_t treq)
{
	int size;
	uint64_t offset;
	struct qcow_request *aio;
	struct tdqcow_state *prv;

	prv     = (struct tdqcow_state *)driver->data;
	size    = treq.secs * driver->info.sector_size;
	offset  = treq.sec  * (uint64_t)driver->info.sector_size;

	if (prv->aio_free_count == 0)
		goto fail;

	aio        = prv->aio_free_list[--prv->aio_free_count];
	aio->treq  = treq;
	aio->state = prv;

	td_prep_write(&aio->tiocb, prv->fd, treq.buf,
		      size, offset, tdqcow_complete, aio);
	td_queue_tiocb(driver, &aio->tiocb);

	return;

fail:
	td_complete_request(treq, -EBUSY);
}

/* 
 * The crypt function is compatible with the linux cryptoloop
 * algorithm for < 4 GB images. NOTE: out_buf == in_buf is
 * supported .
 */
static void encrypt_sectors(struct tdqcow_state *s, int64_t sector_num,
                            uint8_t *out_buf, const uint8_t *in_buf,
                            int nb_sectors, int enc,
                            const AES_KEY *key)
{
	union {
		uint64_t ll[2];
		uint8_t b[16];
	} ivec;
	int i;
	
	for (i = 0; i < nb_sectors; i++) {
		ivec.ll[0] = cpu_to_le64(sector_num);
		ivec.ll[1] = 0;
		AES_cbc_encrypt(in_buf, out_buf, 512, key, 
				ivec.b, enc);
		sector_num++;
		in_buf += 512;
		out_buf += 512;
	}
}

int qtruncate(int fd, off_t length, int sparse)
{
	int ret, i; 
	int current = 0, rem = 0;
	uint64_t sectors;
	struct stat st;
	char *buf;

	/* If length is greater than the current file len
	 * we synchronously write zeroes to the end of the 
	 * file, otherwise we truncate the length down
	 */
	ret = fstat(fd, &st);
	if (ret == -1) 
		return -1;
	if (S_ISBLK(st.st_mode))
		return 0;

	sectors = (length + DEFAULT_SECTOR_SIZE - 1)/DEFAULT_SECTOR_SIZE;
	current = (st.st_size + DEFAULT_SECTOR_SIZE - 1)/DEFAULT_SECTOR_SIZE;
	rem     = st.st_size % DEFAULT_SECTOR_SIZE;

	/* If we are extending this file, we write zeros to the end --
	 * this tries to ensure that the extents allocated wind up being
	 * contiguous on disk.
	 */
	if(st.st_size < sectors * DEFAULT_SECTOR_SIZE) {
		/*We are extending the file*/
		if ((ret = posix_memalign((void **)&buf, 
					  512, DEFAULT_SECTOR_SIZE))) {
			DPRINTF("posix_memalign failed: %d\n", ret);
			return -1;
		}
		memset(buf, 0x00, DEFAULT_SECTOR_SIZE);
		if (lseek(fd, 0, SEEK_END)==-1) {
			DPRINTF("Lseek EOF failed (%d), internal error\n",
				errno);
			free(buf);
			return -1;
		}
		if (rem) {
			ret = write(fd, buf, rem);
			if (ret != rem) {
				DPRINTF("write failed: ret = %d, err = %s\n",
					ret, strerror(errno));
				free(buf);
				return -1;
			}
		}
		for (i = current; i < sectors; i++ ) {
			ret = write(fd, buf, DEFAULT_SECTOR_SIZE);
			if (ret != DEFAULT_SECTOR_SIZE) {
				DPRINTF("write failed: ret = %d, err = %s\n",
					ret, strerror(errno));
				free(buf);
				return -1;
			}
		}
		free(buf);
	} else if(sparse && (st.st_size > sectors * DEFAULT_SECTOR_SIZE))
		if (ftruncate(fd, (off_t)sectors * DEFAULT_SECTOR_SIZE)==-1) {
			DPRINTF("Ftruncate failed (%s)\n", strerror(errno));
			return -1;
		}
	return 0;
}

/* 'allocate' is:
 *
 * 0 to not allocate.
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
static uint64_t get_cluster_offset(struct tdqcow_state *s,
                                   uint64_t offset, int allocate,
                                   int compressed_size,
                                   int n_start, int n_end)
{
	int min_index, i, j, l1_index, l2_index, l2_sector, l1_sector;
	char *tmp_ptr2, *l2_ptr, *l1_ptr;
	uint64_t *tmp_ptr;
	uint64_t l2_offset, *l2_table, cluster_offset, tmp;
	uint32_t min_count;
	int new_l2_table;

	/*Check L1 table for the extent offset*/
	l1_index = offset >> (s->l2_bits + s->cluster_bits);
	l2_offset = s->l1_table[l1_index];
	new_l2_table = 0;
	if (!l2_offset) {
		if (!allocate)
			return 0;
		/* 
		 * allocating a new l2 entry + extent 
		 * at the end of the file, we must also
		 * update the L1 entry safely.
		 */
		l2_offset = s->fd_end;

		/* round to cluster size */
		l2_offset = (l2_offset + s->cluster_size - 1) 
			& ~(s->cluster_size - 1);

		/* update the L1 entry */
		s->l1_table[l1_index] = l2_offset;
		
		/*Truncate file for L2 table 
		 *(initialised to zero in case we crash)*/
		if (qtruncate(s->fd, 
			      l2_offset + (s->l2_size * sizeof(uint64_t)),
			      s->sparse) != 0) {
			DPRINTF("ERROR truncating file\n");
			return 0;
		}
		s->fd_end = l2_offset + (s->l2_size * sizeof(uint64_t));

		/*Update the L1 table entry on disk
                 * (for O_DIRECT we write 4KByte blocks)*/
		l1_sector = (l1_index * sizeof(uint64_t)) >> 12;
		l1_ptr = (char *)s->l1_table + (l1_sector << 12);

		if (posix_memalign((void **)&tmp_ptr, 4096, 4096) != 0) {
			DPRINTF("ERROR allocating memory for L1 table\n");
		}
		memcpy(tmp_ptr, l1_ptr, 4096);

		/* Convert block to write to big endian */
		for(i = 0; i < 4096 / sizeof(uint64_t); i++) {
			cpu_to_be64s(&tmp_ptr[i]);
		}

		/*
		 * Issue non-asynchronous L1 write.
		 * For safety, we must ensure that
		 * entry is written before blocks.
		 */
		lseek(s->fd, s->l1_table_offset + (l1_sector << 12), SEEK_SET);
		if (write(s->fd, tmp_ptr, 4096) != 4096) {
			free(tmp_ptr);
		 	return 0;
		}
		free(tmp_ptr);

		new_l2_table = 1;
		goto cache_miss;
	} else if (s->min_cluster_alloc == s->l2_size) {
		/*Fast-track the request*/
		cluster_offset = l2_offset + (s->l2_size * sizeof(uint64_t));
		l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
		return cluster_offset + (l2_index * s->cluster_size);
	}

	/*Check to see if L2 entry is already cached*/
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (l2_offset == s->l2_cache_offsets[i]) {
			/* increment the hit count */
			if (++s->l2_cache_counts[i] == 0xffffffff) {
				for (j = 0; j < L2_CACHE_SIZE; j++) {
					s->l2_cache_counts[j] >>= 1;
				}
			}
			l2_table = s->l2_cache + (i << s->l2_bits);
			goto found;
		}
	}

cache_miss:
	/* not found: load a new entry in the least used one */
	min_index = 0;
	min_count = 0xffffffff;
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (s->l2_cache_counts[i] < min_count) {
			min_count = s->l2_cache_counts[i];
			min_index = i;
		}
	}
	l2_table = s->l2_cache + (min_index << s->l2_bits);

	/*If extent pre-allocated, read table from disk, 
	 *otherwise write new table to disk*/
	if (new_l2_table) {
		/*Should we allocate the whole extent? Adjustable parameter.*/
		if (s->cluster_alloc == s->l2_size) {
			cluster_offset = l2_offset + 
				(s->l2_size * sizeof(uint64_t));
			cluster_offset = (cluster_offset + s->cluster_size - 1)
				& ~(s->cluster_size - 1);
			if (qtruncate(s->fd, cluster_offset + 
				  (s->cluster_size * s->l2_size), 
				      s->sparse) != 0) {
				DPRINTF("ERROR truncating file\n");
				return 0;
			}
			s->fd_end = cluster_offset + 
				(s->cluster_size * s->l2_size);
			for (i = 0; i < s->l2_size; i++) {
				l2_table[i] = cpu_to_be64(cluster_offset + 
							  (i*s->cluster_size));
			}  
		} else memset(l2_table, 0, s->l2_size * sizeof(uint64_t));

		lseek(s->fd, l2_offset, SEEK_SET);
		if (write(s->fd, l2_table, s->l2_size * sizeof(uint64_t)) !=
		   s->l2_size * sizeof(uint64_t))
			return 0;
	} else {
		lseek(s->fd, l2_offset, SEEK_SET);
		if (read(s->fd, l2_table, s->l2_size * sizeof(uint64_t)) != 
		    s->l2_size * sizeof(uint64_t))
			return 0;
	}
	
	/*Update the cache entries*/ 
	s->l2_cache_offsets[min_index] = l2_offset;
	s->l2_cache_counts[min_index] = 1;

found:
	/*The extent is split into 's->l2_size' blocks of 
	 *size 's->cluster_size'*/
	l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
	cluster_offset = be64_to_cpu(l2_table[l2_index]);

	if (!cluster_offset || 
	    ((cluster_offset & QCOW_OFLAG_COMPRESSED) && allocate == 1) ) {
		if (!allocate)
			return 0;
		
		if ((cluster_offset & QCOW_OFLAG_COMPRESSED) &&
		    (n_end - n_start) < s->cluster_sectors) {
			/* cluster is already allocated but compressed, we must
			   decompress it in the case it is not completely
			   overwritten */
			if (decompress_cluster(s, cluster_offset) < 0)
				return 0;
			cluster_offset = lseek(s->fd, s->fd_end, SEEK_SET);
			cluster_offset = (cluster_offset + s->cluster_size - 1)
				& ~(s->cluster_size - 1);
			/* write the cluster content - not asynchronous */
			lseek(s->fd, cluster_offset, SEEK_SET);
			if (write(s->fd, s->cluster_cache, s->cluster_size) != 
			    s->cluster_size)
			    return -1;
		} else {
			/* allocate a new cluster */
			cluster_offset = lseek(s->fd, s->fd_end, SEEK_SET);
			if (allocate == 1) {
				/* round to cluster size */
				cluster_offset = 
					(cluster_offset + s->cluster_size - 1) 
					& ~(s->cluster_size - 1);
				if (qtruncate(s->fd, cluster_offset + 
					      s->cluster_size, s->sparse)!=0) {
					DPRINTF("ERROR truncating file\n");
					return 0;
				}
				s->fd_end = (cluster_offset + s->cluster_size);
				/* if encrypted, we must initialize the cluster
				   content which won't be written */
				if (s->crypt_method && 
				    (n_end - n_start) < s->cluster_sectors) {
					uint64_t start_sect;
					start_sect = (offset & 
						      ~(s->cluster_size - 1)) 
							      >> 9;
					memset(s->cluster_data + 512, 
					       0xaa, 512);
					for (i = 0; i < s->cluster_sectors;i++)
					{
						if (i < n_start || i >= n_end) 
						{
							encrypt_sectors(s, start_sect + i, 
									s->cluster_data, 
									s->cluster_data + 512, 1, 1,
									&s->aes_encrypt_key);
							lseek(s->fd, cluster_offset + i * 512, SEEK_SET);
							if (write(s->fd, s->cluster_data, 512) != 512)
								return -1;
						}
					}
				}
			} else {
				cluster_offset |= QCOW_OFLAG_COMPRESSED | 
					(uint64_t)compressed_size 
						<< (63 - s->cluster_bits);
			}
		}
		/* update L2 table */
		tmp = cpu_to_be64(cluster_offset);
		l2_table[l2_index] = tmp;

		/*For IO_DIRECT we write 4KByte blocks*/
		l2_sector = (l2_index * sizeof(uint64_t)) >> 12;
		l2_ptr = (char *)l2_table + (l2_sector << 12);
		
		if (posix_memalign((void **)&tmp_ptr2, 4096, 4096) != 0) {
			DPRINTF("ERROR allocating memory for L1 table\n");
		}
		memcpy(tmp_ptr2, l2_ptr, 4096);
		lseek(s->fd, l2_offset + (l2_sector << 12), SEEK_SET);
		if (write(s->fd, tmp_ptr2, 4096) != 4096) {
			free(tmp_ptr2);
			return -1;
		}
		free(tmp_ptr2);
	}
	return cluster_offset;
}

static int qcow_is_allocated(struct tdqcow_state *s, int64_t sector_num,
                             int nb_sectors, int *pnum)
{
	int index_in_cluster, n;
	uint64_t cluster_offset;

	cluster_offset = get_cluster_offset(s, sector_num << 9, 0, 0, 0, 0);
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
	if ( (ret != Z_STREAM_END && ret != Z_BUF_ERROR) ||
	    (out_len != out_buf_size) ) {
		inflateEnd(strm);
		return -1;
	}
	inflateEnd(strm);
	return 0;
}
                              
static int decompress_cluster(struct tdqcow_state *s, uint64_t cluster_offset)
{
	int ret, csize;
	uint64_t coffset;

	coffset = cluster_offset & s->cluster_offset_mask;
	if (s->cluster_cache_offset != coffset) {
		csize = cluster_offset >> (63 - s->cluster_bits);
		csize &= (s->cluster_size - 1);
		lseek(s->fd, coffset, SEEK_SET);
		ret = read(s->fd, s->cluster_data, csize);
		if (ret != csize) 
			return -1;
		if (decompress_buffer(s->cluster_cache, s->cluster_size,
				      s->cluster_data, csize) < 0) {
			return -1;
		}
		s->cluster_cache_offset = coffset;
	}
	return 0;
}

static int
tdqcow_read_header(int fd, QCowHeader *header)
{
	int err;
	char *buf;
	struct stat st;
	size_t size, expected;

	memset(header, 0, sizeof(*header));

	err = fstat(fd, &st);
	if (err)
		return -errno;

	err = lseek(fd, 0, SEEK_SET);
	if (err == (off_t)-1)
		return -errno;

	size = (sizeof(*header) + 511) & ~511;
	err = posix_memalign((void **)&buf, 512, size);
	if (err)
		return err;

	expected = size;
	if (st.st_size < size)
		expected = st.st_size;

	errno = 0;
	err = read(fd, buf, size);
	if (err != expected) {
		err = (errno ? -errno : -EIO);
		goto out;
	}

	memcpy(header, buf, sizeof(*header));
	be32_to_cpus(&header->magic);
	be32_to_cpus(&header->version);
	be64_to_cpus(&header->backing_file_offset);
	be32_to_cpus(&header->backing_file_size);
	be32_to_cpus(&header->mtime);
	be64_to_cpus(&header->size);
	be32_to_cpus(&header->crypt_method);
	be64_to_cpus(&header->l1_table_offset);

	err = 0;

out:
	free(buf);
	return err;
}

static int
tdqcow_load_l1_table(struct tdqcow_state *s, QCowHeader *header)
{
	char *buf;
	struct stat st;
	size_t expected;
	int i, err, shift;
	QCowHeader_ext *exthdr;
	uint32_t l1_table_bytes, l1_table_block, l1_table_size;

	buf         = NULL;
	s->l1_table = NULL;

	shift = s->cluster_bits + s->l2_bits;

	s->l1_size = (header->size + (1LL << shift) - 1) >> shift;
	s->l1_table_offset = header->l1_table_offset;

	s->min_cluster_alloc = 1; /* default */

	l1_table_bytes = s->l1_size * sizeof(uint64_t);
	l1_table_size  = (l1_table_bytes + 4095) & ~4095;
	l1_table_block = (l1_table_bytes + s->l1_table_offset + 4095) & ~4095;

	DPRINTF("L1 Table offset detected: %"PRIu64", size %d (%d)\n",
		(uint64_t)s->l1_table_offset,
		(int) (s->l1_size * sizeof(uint64_t)), 
		l1_table_size);

	err = fstat(s->fd, &st);
	if (err) {
		err = -errno;
		goto out;
	}

	err = lseek(s->fd, 0, SEEK_SET);
	if (err == (off_t)-1) {
		err = -errno;
		goto out;
	}

	err = posix_memalign((void **)&buf, 512, l1_table_block);
	if (err) {
		buf = NULL;
		goto out;
	}

	err = posix_memalign((void **)&s->l1_table, 4096, l1_table_size);
	if (err) {
		s->l1_table = NULL;
		goto out;
	}

	memset(buf, 0, l1_table_block);
	memset(s->l1_table, 0, l1_table_size);

	expected = l1_table_block;
	if (st.st_size < l1_table_block)
		expected = st.st_size;

	errno = 0;
	err = read(s->fd, buf, l1_table_block);
	if (err != expected) {
		err = (errno ? -errno : -EIO);
		goto out;
	}

	memcpy(s->l1_table, buf + s->l1_table_offset, l1_table_size);
	exthdr = (QCowHeader_ext *)(buf + sizeof(QCowHeader));

	/* check for xen extended header */
	if (s->l1_table_offset % 4096 == 0 &&
	    be32_to_cpu(exthdr->xmagic) == XEN_MAGIC) {
		uint32_t flags = be32_to_cpu(exthdr->flags);
		uint32_t cksum = be32_to_cpu(exthdr->cksum);

		/*
		 * Try to detect old tapdisk images. They have to be fixed
		 * because they use big endian rather than native endian for
		 * the L1 table.  After this block, the l1 table will
		 * definitely be in BIG endian.
		 */
		if (!(flags & EXTHDR_L1_BIG_ENDIAN)) {
			DPRINTF("qcow: converting to big endian L1 table\n");

			/* convert to big endian */
			for (i = 0; i < s->l1_size; i++)
				cpu_to_be64s(&s->l1_table[i]);

			flags |= EXTHDR_L1_BIG_ENDIAN;
			exthdr->flags = cpu_to_be32(flags);

			memcpy(buf + s->l1_table_offset,
			       s->l1_table, l1_table_size);
			
			err = lseek(s->fd, 0, SEEK_SET);
			if (err == (off_t)-1) {
				err = -errno;
				goto out;
			}

			err = atomicio(vwrite, s->fd, buf, l1_table_block);
			if (err != l1_table_block) {
				err = -errno;
				goto out;
			}
		}

		/* check the L1 table checksum */
		if (cksum != gen_cksum((char *)s->l1_table,
				       s->l1_size * sizeof(uint64_t)))
			DPRINTF("qcow: bad L1 checksum\n");
		else {
			s->extended = 1;
			s->sparse = (be32_to_cpu(exthdr->flags) & SPARSE_FILE);
			s->min_cluster_alloc =
				be32_to_cpu(exthdr->min_cluster_alloc);
		}
	}

	/* convert L1 table to native endian for operation */
	for (i = 0; i < s->l1_size; i++)
		be64_to_cpus(&s->l1_table[i]);

	err = 0;

out:
	if (err) {
		free(buf);
		free(s->l1_table);
		s->l1_table = NULL;
	}
	return err;
}

/* Open the disk file and initialize qcow state. */
int tdqcow_open (td_driver_t *driver, const char *name, td_flag_t flags)
{
	int fd, len, i, ret, size, o_flags;
	td_disk_info_t *bs = &(driver->info);
	struct tdqcow_state   *s  = (struct tdqcow_state *)driver->data;
	QCowHeader header;
	uint64_t final_cluster = 0;

 	DPRINTF("QCOW: Opening %s\n", name);

	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags == TD_OPEN_RDONLY) ? O_RDONLY : O_RDWR);
	fd = open(name, o_flags);
	if (fd < 0) {
		DPRINTF("Unable to open %s (%d)\n", name, -errno);
		return -1;
	}

	s->fd = fd;
	s->name = strdup(name);
	if (!s->name)
		goto fail;

	if (tdqcow_read_header(fd, &header))
		goto fail;

	if (header.magic != QCOW_MAGIC)
		goto fail;

	switch (header.version) {
	case QCOW_VERSION:
		break;
	case 2:
	  //TODO: Port qcow2 to new blktap framework.
	  //		close(fd);
	  //		dd->drv = &tapdisk_qcow2;
	  //		return dd->drv->td_open(dd, name, flags);
	  goto fail;
	default:
		goto fail;
	}

	if (header.size <= 1 || header.cluster_bits < 9)
		goto fail;
	if (header.crypt_method > QCOW_CRYPT_AES)
		goto fail;
	s->crypt_method_header = header.crypt_method;
	if (s->crypt_method_header)
		s->encrypted = 1;
	s->cluster_bits = header.cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = header.l2_bits;
	s->l2_size = 1 << s->l2_bits;
	s->cluster_alloc = s->l2_size;
	bs->size = header.size / 512;
	s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;
	s->backing_file_offset = header.backing_file_offset;
	s->backing_file_size   = header.backing_file_size;

	/* allocate and load l1 table */
	if (tdqcow_load_l1_table(s, &header))
		goto fail;

	/* alloc L2 cache */
	size = s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t);
	ret = posix_memalign((void **)&s->l2_cache, 4096, size);
	if(ret != 0) goto fail;

	size = s->cluster_size;
	ret = posix_memalign((void **)&s->cluster_cache, 4096, size);
	if(ret != 0) goto fail;

	ret = posix_memalign((void **)&s->cluster_data, 4096, size);
	if(ret != 0) goto fail;
	s->cluster_cache_offset = -1;

	if (s->backing_file_offset != 0)
		s->cluster_alloc = 1; /*Cannot use pre-alloc*/

        bs->sector_size = 512;
        bs->info = 0;

	for(i = 0; i < s->l1_size; i++)
		if (s->l1_table[i] > final_cluster)
			final_cluster = s->l1_table[i];

	if (init_aio_state(driver)!=0) {
	  DPRINTF("Unable to initialise AIO state\n");
	  free_aio_state(s);
	  goto fail;
	}

	if (!final_cluster)
		s->fd_end = s->l1_table_offset +
			((s->l1_size * sizeof(uint64_t) + 4095) & ~4095);
	else {
		s->fd_end = lseek(fd, 0, SEEK_END);
		if (s->fd_end == (off_t)-1)
			goto fail;
	}

	return 0;
	
fail:
	DPRINTF("QCOW Open failed\n");

	free_aio_state(s);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(fd);
	return -1;
}

void tdqcow_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdqcow_state   *s  = (struct tdqcow_state *)driver->data;
	int ret = 0, index_in_cluster, n, i;
	uint64_t cluster_offset, sector, nb_sectors;
	struct qcow_prv* prv;
	td_request_t clone = treq;
	char* buf = treq.buf;

	sector     = treq.sec;
	nb_sectors = treq.secs;

	/*We store a local record of the request*/
	while (nb_sectors > 0) {
		cluster_offset = 
			get_cluster_offset(s, sector << 9, 0, 0, 0, 0);
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->aio_free_count == 0) {
			td_complete_request(treq, -EBUSY);
			return;
		}
		
		if(!cluster_offset) {
            int i;
            /* Forward entire request if possible. */
            for(i=0; i<nb_sectors; i++)
                if(get_cluster_offset(s, (sector+i) << 9, 0, 0, 0, 0))
                    goto coalesce_failed;
            treq.buf  = buf;
            treq.sec  = sector;
            treq.secs = nb_sectors;
			td_forward_request(treq);
            return;
coalesce_failed:            
			treq.buf  = buf;
			treq.sec  = sector;
			treq.secs = n;
			td_forward_request(treq);

		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			if (decompress_cluster(s, cluster_offset) < 0) {
				td_complete_request(treq, -EIO);
				goto done;
			}
			memcpy(buf, s->cluster_cache + index_in_cluster * 512, 
			       512 * n);
			
			treq.buf  = buf;
			treq.sec  = sector;
			treq.secs = n;
			td_complete_request(treq, 0);
		} else {
		  clone.buf  = buf;
		  clone.sec  = (cluster_offset>>9)+index_in_cluster;
		  clone.secs = n;
		  async_read(driver, clone);
		}
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
done:
	return;
}

void tdqcow_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdqcow_state   *s  = (struct tdqcow_state *)driver->data;
	int ret = 0, index_in_cluster, n, i;
	uint64_t cluster_offset, sector, nb_sectors;
	td_callback_t cb;
	struct qcow_prv* prv;
	char* buf = treq.buf;
	td_request_t clone=treq;

	sector     = treq.sec;
	nb_sectors = treq.secs;
		   
	/*We store a local record of the request*/
	while (nb_sectors > 0) {
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->aio_free_count == 0) {
			td_complete_request(treq, -EBUSY);
			return;
		}

		cluster_offset = get_cluster_offset(s, sector << 9, 1, 0,
						    index_in_cluster, 
						    index_in_cluster+n);
		if (!cluster_offset) {
			DPRINTF("Ooops, no write cluster offset!\n");
			td_complete_request(treq, -EIO);
			return;
		}

		if (s->crypt_method) {
			encrypt_sectors(s, sector, s->cluster_data, 
					(unsigned char *)buf, n, 1,
					&s->aes_encrypt_key);

			clone.buf  = buf;
			clone.sec  = (cluster_offset>>9) + index_in_cluster;
			clone.secs = n;
			async_write(driver, clone);
		} else {
		  clone.buf  = buf;
		  clone.sec  = (cluster_offset>>9) + index_in_cluster;
		  clone.secs = n;

		  async_write(driver, clone);
		}
		
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
	s->cluster_cache_offset = -1; /* disable compressed cache */

	return;
}

static int
tdqcow_update_checksum(struct tdqcow_state *s)
{
	int i, fd, err;
	uint32_t offset, cksum, out;

	if (!s->extended)
		return 0;

	fd = open(s->name, O_WRONLY | O_LARGEFILE); /* open without O_DIRECT */
	if (fd == -1) {
		err = errno;
		goto out;
	}

	offset = sizeof(QCowHeader) + offsetof(QCowHeader_ext, cksum);
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
		err = errno;
		goto out;
	}

	/* convert to big endian for checksum */
	for (i = 0; i < s->l1_size; i++)
		cpu_to_be64s(&s->l1_table[i]);

	cksum = gen_cksum((char *)s->l1_table, s->l1_size * sizeof(uint64_t));

	/* and back again... */
	for (i = 0; i < s->l1_size; i++)
		be64_to_cpus(&s->l1_table[i]);

	DPRINTF("Writing cksum: %d", cksum);

	out = cpu_to_be32(cksum);
	if (write(fd, &out, sizeof(out)) != sizeof(out)) {
		err = errno;
		goto out;
	}

	err = 0;

out:
	if (err)
		DPRINTF("failed to update checksum: %d\n", err);
	if (fd != -1)
		close(fd);
	return err;
}
 		
int tdqcow_close(td_driver_t *driver)
{
	struct tdqcow_state *s = (struct tdqcow_state *)driver->data;

	/*Update the hdr cksum*/
	tdqcow_update_checksum(s);

	free_aio_state(s);
	free(s->name);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(s->fd);	
	return 0;
}

int qcow_create(const char *filename, uint64_t total_size,
		const char *backing_file, int sparse)
{
	int fd, header_size, backing_filename_len, l1_size, i;
	int shift, length, adjust, flags = 0, ret = 0;
	QCowHeader header;
	QCowHeader_ext exthdr;
	char backing_filename[PATH_MAX], *ptr;
	uint64_t tmp, size, total_length;
	struct stat st;

	DPRINTF("Qcow_create: size %"PRIu64"\n",total_size);

	fd = open(filename, 
		  O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_LARGEFILE,
		  0644);
	if (fd < 0)
		return -1;

	memset(&header, 0, sizeof(header));
	header.magic = cpu_to_be32(QCOW_MAGIC);
	header.version = cpu_to_be32(QCOW_VERSION);

	/*Create extended header fields*/
	exthdr.xmagic = cpu_to_be32(XEN_MAGIC);

	header_size = sizeof(header) + sizeof(QCowHeader_ext);
	backing_filename_len = 0;
	size = (total_size >> SECTOR_SHIFT);
	if (backing_file) {
		if (strcmp(backing_file, "fat:")) {
			const char *p;
			/* XXX: this is a hack: we do not attempt to 
			 *check for URL like syntax */
			p = strchr(backing_file, ':');
			if (p && (p - backing_file) >= 2) {
				/* URL like but exclude "c:" like filenames */
				strncpy(backing_filename, backing_file,
					sizeof(backing_filename));
			} else {
				if (realpath(backing_file, backing_filename) == NULL ||
				    stat(backing_filename, &st) != 0) {
					return -1;
				}
			}
			header.backing_file_offset = cpu_to_be64(header_size);
			backing_filename_len = strlen(backing_filename);
			header.backing_file_size = cpu_to_be32(
				backing_filename_len);
			header_size += backing_filename_len;
			
			/*Set to the backing file size*/
			if(get_filesize(backing_filename, &size, &st)) {
				return -1;
			}
			DPRINTF("Backing file size detected: %"PRId64" sectors" 
				"(total %"PRId64" [%"PRId64" MB])\n", 
				size, 
				(uint64_t)(size << SECTOR_SHIFT), 
				(uint64_t)(size >> 11));
		} else {
			backing_file = NULL;
			DPRINTF("Setting file size: %"PRId64" (total %"PRId64")\n", 
				total_size, 
				(uint64_t) (total_size << SECTOR_SHIFT));
		}
		header.mtime = cpu_to_be32(st.st_mtime);
		header.cluster_bits = 9; /* 512 byte cluster to avoid copying
					    unmodifyed sectors */
		header.l2_bits = 12; /* 32 KB L2 tables */
		exthdr.min_cluster_alloc = cpu_to_be32(1);
	} else {
		DPRINTF("Setting file size: %"PRId64" sectors" 
			"(total %"PRId64" [%"PRId64" MB])\n", 
			size, 
			(uint64_t) (size << SECTOR_SHIFT), 
			(uint64_t) (size >> 11));
		header.cluster_bits = 12; /* 4 KB clusters */
		header.l2_bits = 9; /* 4 KB L2 tables */
		exthdr.min_cluster_alloc = cpu_to_be32(1 << 9);
	}
	/*Set the header size value*/
	header.size = cpu_to_be64(size * 512);
	
	header_size = (header_size + 7) & ~7;
	if (header_size % 4096 > 0) {
		header_size = ((header_size >> 12) + 1) << 12;
	}

	shift = header.cluster_bits + header.l2_bits;
	l1_size = ((size * 512) + (1LL << shift) - 1) >> shift;

	header.l1_table_offset = cpu_to_be64(header_size);
	DPRINTF("L1 Table offset: %d, size %d\n",
		header_size,
		(int)(l1_size * sizeof(uint64_t)));
	header.crypt_method = cpu_to_be32(QCOW_CRYPT_NONE);

	ptr = calloc(1, l1_size * sizeof(uint64_t));
	exthdr.cksum = cpu_to_be32(gen_cksum(ptr, l1_size * sizeof(uint64_t)));
	printf("Created cksum: %d\n",exthdr.cksum);
	free(ptr);

	/*adjust file length to system page size boundary*/
	length = ROUNDUP(header_size + (l1_size * sizeof(uint64_t)),
		getpagesize());
	if (qtruncate(fd, length, 0)!=0) {
		DPRINTF("ERROR truncating file\n");
		return -1;
	}

	if (sparse == 0) {
		/*Filesize is length+l1_size*(1 << s->l2_bits)+(size*512)*/
		total_length = length + (l1_size * (1 << 9)) + (size * 512);
		if (qtruncate(fd, total_length, 0)!=0) {
                        DPRINTF("ERROR truncating file\n");
                        return -1;
		}
		printf("File truncated to length %"PRIu64"\n",total_length);
	} else
		flags = SPARSE_FILE;

	flags |= EXTHDR_L1_BIG_ENDIAN;
	exthdr.flags = cpu_to_be32(flags);
	
	/* write all the data */
	lseek(fd, 0, SEEK_SET);
	ret += write(fd, &header, sizeof(header));
	ret += write(fd, &exthdr, sizeof(exthdr));
	if (backing_file)
		ret += write(fd, backing_filename, backing_filename_len);

	lseek(fd, header_size, SEEK_SET);
	tmp = 0;
	for (i = 0;i < l1_size; i++) {
		ret += write(fd, &tmp, sizeof(tmp));
	}

	close(fd);

	return 0;
}

static int qcow_make_empty(struct tdqcow_state *s)
{
	uint32_t l1_length = s->l1_size * sizeof(uint64_t);

	memset(s->l1_table, 0, l1_length);
	lseek(s->fd, s->l1_table_offset, SEEK_SET);
	if (write(s->fd, s->l1_table, l1_length) < 0)
		return -1;
	if (qtruncate(s->fd, s->l1_table_offset + l1_length, s->sparse)!=0) {
		DPRINTF("ERROR truncating file\n");
		return -1;
	}

	memset(s->l2_cache, 0, s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_offsets, 0, L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_counts, 0, L2_CACHE_SIZE * sizeof(uint32_t));

	return 0;
}

static int qcow_get_cluster_size(struct tdqcow_state *s)
{
	return s->cluster_size;
}

/* XXX: put compressed sectors first, then all the cluster aligned
   tables to avoid losing bytes in alignment */
static int qcow_compress_cluster(struct tdqcow_state *s, int64_t sector_num, 
                          const uint8_t *buf)
{
	z_stream strm;
	int ret, out_len;
	uint8_t *out_buf;
	uint64_t cluster_offset;

	out_buf = malloc(s->cluster_size + (s->cluster_size / 1000) + 128);
	if (!out_buf)
		return -1;

	/* best compression, small window, no zlib header */
	memset(&strm, 0, sizeof(strm));
	ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
			   Z_DEFLATED, -12, 
			   9, Z_DEFAULT_STRATEGY);
	if (ret != 0) {
		free(out_buf);
		return -1;
	}

	strm.avail_in = s->cluster_size;
	strm.next_in = (uint8_t *)buf;
	strm.avail_out = s->cluster_size;
	strm.next_out = out_buf;

	ret = deflate(&strm, Z_FINISH);
	if (ret != Z_STREAM_END && ret != Z_OK) {
		free(out_buf);
		deflateEnd(&strm);
		return -1;
	}
	out_len = strm.next_out - out_buf;

	deflateEnd(&strm);

	if (ret != Z_STREAM_END || out_len >= s->cluster_size) {
		/* could not compress: write normal cluster */
		//tdqcow_queue_write(bs, sector_num, buf, s->cluster_sectors);
	} else {
		cluster_offset = get_cluster_offset(s, sector_num << 9, 2, 
                                            out_len, 0, 0);
		cluster_offset &= s->cluster_offset_mask;
		lseek(s->fd, cluster_offset, SEEK_SET);
		if (write(s->fd, out_buf, out_len) != out_len) {
			free(out_buf);
			return -1;
		}
	}
	
	free(out_buf);
	return 0;
}

static int
tdqcow_get_image_type(const char *file, int *type)
{
	int fd;
	size_t size;
	QCowHeader header;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -errno;

	size = read(fd, &header, sizeof(header));
	close(fd);
	if (size != sizeof(header))
		return (errno ? -errno : -EIO);

	be32_to_cpus(&header.magic);
	if (header.magic == QCOW_MAGIC)
		*type = DISK_TYPE_QCOW;
	else
		*type = DISK_TYPE_AIO;

	return 0;
}

int tdqcow_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	off_t off;
	char *buf, *filename;
	int len, secs, type = 0, err = -EINVAL;
	struct tdqcow_state *child  = (struct tdqcow_state *)driver->data;

	if (!child->backing_file_offset)
		return TD_NO_PARENT;

	/* read the backing file name */
	len  = child->backing_file_size;
	off  = child->backing_file_offset - (child->backing_file_offset % 512);
	secs = (len + (child->backing_file_offset - off) + 511) >> 9;

	if (posix_memalign((void **)&buf, 512, secs << 9)) 
		return -1;

	if (lseek(child->fd, off, SEEK_SET) == (off_t)-1)
		goto out;

	if (read(child->fd, buf, secs << 9) != secs << 9)
		goto out;
	filename       = buf + (child->backing_file_offset - off);
	filename[len]  = '\0';

	if (tdqcow_get_image_type(filename, &type))
		goto out;

	id->name       = strdup(filename);
	id->drivertype = type;
	err            = 0;
 out:
	free(buf);
	return err;
}

int tdqcow_validate_parent(td_driver_t *driver,
			  td_driver_t *pdriver, td_flag_t flags)
{
	struct stat stats;
	uint64_t psize, csize;
	struct tdqcow_state *c = (struct tdqcow_state *)driver->data;
	struct tdqcow_state *p = (struct tdqcow_state *)pdriver->data;
	
	if (stat(p->name, &stats))
		return -EINVAL;
	if (get_filesize(p->name, &psize, &stats))
		return -EINVAL;

	if (stat(c->name, &stats))
		return -EINVAL;
	if (get_filesize(c->name, &csize, &stats))
		return -EINVAL;

	if (csize != psize)
		return -EINVAL;

	return 0;
}

struct tap_disk tapdisk_qcow = {
	.disk_type           = "tapdisk_qcow",
	.flags              = 0,
	.private_data_size   = sizeof(struct tdqcow_state),
	.td_open             = tdqcow_open,
	.td_close            = tdqcow_close,
	.td_queue_read       = tdqcow_queue_read,
	.td_queue_write      = tdqcow_queue_write,
	.td_get_parent_id    = tdqcow_get_parent_id,
	.td_validate_parent  = tdqcow_validate_parent,
	.td_debug           = NULL,
};
