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
#include "bswap.h"
#include "aes.h"
#include "tapdisk.h"
#include "tapaio.h"
#include "blk.h"

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

#define ROUNDUP(l, s) \
({ \
    (uint64_t)( \
        ((l) + ((s) - 1)) - (((l) + ((s) - 1)) % (s))); \
})

#undef IOCB_IDX
#define IOCB_IDX(_s, _io) ((_io) - (_s)->iocb_list)

#define ZERO_TEST(_b) (_b | 0x00)

/**************************************************************/
/* QEMU COW block driver with compression and encryption support */

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define XEN_MAGIC  (('X' << 24) | ('E' << 16) | ('N' << 8) | 0xfb)
#define QCOW_VERSION 1

#define QCOW_CRYPT_NONE 0x00
#define QCOW_CRYPT_AES  0x01

#define QCOW_OFLAG_COMPRESSED (1LL << 63)
#define SPARSE_FILE 0x01
#define EXTHDR_L1_BIG_ENDIAN 0x02

#ifndef O_BINARY
#define O_BINARY 0
#endif

typedef struct QCowHeader {
	uint32_t magic;
	uint32_t version;
	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	uint32_t mtime;
	uint64_t size; /* in bytes */
	uint8_t cluster_bits;
	uint8_t l2_bits;
	uint32_t crypt_method;
	uint64_t l1_table_offset;
} QCowHeader;

/*Extended header for Xen enhancements*/
typedef struct QCowHeader_ext {
        uint32_t xmagic;
        uint32_t cksum;
        uint32_t min_cluster_alloc;
        uint32_t flags;
} QCowHeader_ext;

#define L2_CACHE_SIZE 16  /*Fixed allocation in Qemu*/

struct tdqcow_state {
        int fd;                        /*Main Qcow file descriptor */
	uint64_t fd_end;               /*Store a local record of file length */
	char *name;                    /*Record of the filename*/
	uint32_t backing_file_size;
	uint64_t backing_file_offset;
	int encrypted;                 /*File contents are encrypted or plain*/
	int cluster_bits;              /*Determines length of cluster as 
					*indicated by file hdr*/
	int cluster_size;              /*Length of cluster*/
	int cluster_sectors;           /*Number of sectors per cluster*/
	int cluster_alloc;             /*Blktap fix for allocating full 
					*extents*/
	int min_cluster_alloc;         /*Blktap historical extent alloc*/
	int sparse;                    /*Indicates whether to preserve sparseness*/
	int l2_bits;                   /*Size of L2 table entry*/
	int l2_size;                   /*Full table size*/
	int l1_size;                   /*L1 table size*/
	uint64_t cluster_offset_mask;    
	uint64_t l1_table_offset;      /*L1 table offset from beginning of 
					*file*/
	uint64_t *l1_table;            /*L1 table entries*/
	uint64_t *l2_cache;            /*We maintain a cache of size 
					*L2_CACHE_SIZE of most read entries*/
	uint64_t l2_cache_offsets[L2_CACHE_SIZE];     /*L2 cache entries*/
	uint32_t l2_cache_counts[L2_CACHE_SIZE];      /*Cache access record*/
	uint8_t *cluster_cache;          
	uint8_t *cluster_data;
	uint64_t cluster_cache_offset; /**/
	uint32_t crypt_method;         /*current crypt method, 0 if no 
					*key yet */
	uint32_t crypt_method_header;  /**/
	AES_KEY aes_encrypt_key;       /*AES key*/
	AES_KEY aes_decrypt_key;       /*AES key*/
        
	/* libaio state */
	tap_aio_context_t	aio;
};

static int decompress_cluster(struct tdqcow_state *s, uint64_t cluster_offset);

#ifdef USE_GCRYPT

#include <gcrypt.h>

static uint32_t gen_cksum(char *ptr, int len)
{
	int i;
	uint32_t md[4];

	/* Convert L1 table to big endian */
	for(i = 0; i < len / sizeof(uint64_t); i++) {
		cpu_to_be64s(&((uint64_t*) ptr)[i]);
	}

	/* Generate checksum */
	gcry_md_hash_buffer(GCRY_MD_MD5, md, ptr, len);

	/* Convert L1 table back to native endianess */
	for(i = 0; i < len / sizeof(uint64_t); i++) {
		be64_to_cpus(&((uint64_t*) ptr)[i]);
	}

	return md[0];
}

#else /* use libcrypto */

#include <openssl/md5.h>

static uint32_t gen_cksum(char *ptr, int len)
{
	int i;
	unsigned char *md;
	uint32_t ret;

	md = malloc(MD5_DIGEST_LENGTH);
	if(!md) return 0;

	/* Convert L1 table to big endian */
	for(i = 0; i < len / sizeof(uint64_t); i++) {
		cpu_to_be64s(&((uint64_t*) ptr)[i]);
	}

	/* Generate checksum */
	if (MD5((unsigned char *)ptr, len, md) != md)
		ret = 0;
	else
		memcpy(&ret, md, sizeof(uint32_t));

	/* Convert L1 table back to native endianess */
	for(i = 0; i < len / sizeof(uint64_t); i++) {
		be64_to_cpus(&((uint64_t*) ptr)[i]);
	}

	free(md);
	return ret;
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

static int qtruncate(int fd, off_t length, int sparse)
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
		tmp = cpu_to_be64(l2_offset);
		
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

static void init_cluster_cache(struct disk_driver *dd)
{
	struct td_state     *bs = dd->td_state;
	struct tdqcow_state *s  = (struct tdqcow_state *)dd->private;
	uint32_t count = 0;
	int i, cluster_entries;

	cluster_entries = s->cluster_size / 512;
	DPRINTF("Initialising Cluster cache, %d sectors per cluster (%d cluster size)\n",
		cluster_entries, s->cluster_size);

	for (i = 0; i < bs->size; i += cluster_entries) {
		if (get_cluster_offset(s, i << 9, 0, 0, 0, 1)) count++;
		if (count >= L2_CACHE_SIZE) return;
	}
	DPRINTF("Finished cluster initialisation, added %d entries\n", count);
	return;
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

static inline void init_fds(struct disk_driver *dd)
{
	int i;
	struct tdqcow_state *s = (struct tdqcow_state *)dd->private;

	for(i = 0; i < MAX_IOFD; i++) 
		dd->io_fd[i] = 0;

	dd->io_fd[0] = s->aio.aio_ctx.pollfd;
}

/* Open the disk file and initialize qcow state. */
static int tdqcow_open (struct disk_driver *dd, const char *name, td_flag_t flags)
{
	int fd, len, i, shift, ret, size, l1_table_size, o_flags, l1_table_block;
	int max_aio_reqs;
	struct td_state     *bs = dd->td_state;
	struct tdqcow_state *s  = (struct tdqcow_state *)dd->private;
	char *buf, *buf2;
	QCowHeader *header;
	QCowHeader_ext *exthdr;
	uint32_t cksum;
	uint64_t final_cluster = 0;

 	DPRINTF("QCOW: Opening %s\n",name);

	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags == TD_RDONLY) ? O_RDONLY : O_RDWR);
	fd = open(name, o_flags);
	if (fd < 0) {
		DPRINTF("Unable to open %s (%d)\n",name,0 - errno);
		return -1;
	}

	s->fd = fd;
	if (asprintf(&s->name,"%s", name) == -1) {
		close(fd);
		return -1;
	}

	ASSERT(sizeof(QCowHeader) + sizeof(QCowHeader_ext) < 512);

	ret = posix_memalign((void **)&buf, 512, 512);
	if (ret != 0) goto fail;

	if (read(fd, buf, 512) != 512)
		goto fail;

	header = (QCowHeader *)buf;
	be32_to_cpus(&header->magic);
	be32_to_cpus(&header->version);
	be64_to_cpus(&header->backing_file_offset);
	be32_to_cpus(&header->backing_file_size);
	be32_to_cpus(&header->mtime);
	be64_to_cpus(&header->size);
	be32_to_cpus(&header->crypt_method);
	be64_to_cpus(&header->l1_table_offset);

	if (header->magic != QCOW_MAGIC)
		goto fail;

	switch (header->version) {
	case QCOW_VERSION:
		break;
	case 2:
		close(fd);
		dd->drv = &tapdisk_qcow2;
		return dd->drv->td_open(dd, name, flags);
	default:
		goto fail;
	}

	if (header->size <= 1 || header->cluster_bits < 9)
		goto fail;
	if (header->crypt_method > QCOW_CRYPT_AES)
		goto fail;
	s->crypt_method_header = header->crypt_method;
	if (s->crypt_method_header)
		s->encrypted = 1;
	s->cluster_bits = header->cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = header->l2_bits;
	s->l2_size = 1 << s->l2_bits;
	s->cluster_alloc = s->l2_size;
	bs->size = header->size / 512;
	s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;
	s->backing_file_offset = header->backing_file_offset;
	s->backing_file_size   = header->backing_file_size;

	/* read the level 1 table */
	shift = s->cluster_bits + s->l2_bits;
	s->l1_size = ROUNDUP(header->size, 1LL << shift);
	
	s->l1_table_offset = header->l1_table_offset;

	/*allocate a 4Kbyte multiple of memory*/
	l1_table_size = s->l1_size * sizeof(uint64_t);
	if (l1_table_size % 4096 > 0) {
		l1_table_size = ROUNDUP(l1_table_size, 4096);
	}
	ret = posix_memalign((void **)&s->l1_table, 4096, l1_table_size);
	if (ret != 0) goto fail;

	memset(s->l1_table, 0x00, l1_table_size);

	DPRINTF("L1 Table offset detected: %llu, size %d (%d)\n",
		(long long)s->l1_table_offset,
		(int) (s->l1_size * sizeof(uint64_t)), 
		l1_table_size);

	lseek(fd, 0, SEEK_SET);
	l1_table_block = l1_table_size + s->l1_table_offset;
	l1_table_block = ROUNDUP(l1_table_block, 512);
	ret = posix_memalign((void **)&buf2, 4096, l1_table_block);
	if (ret != 0) goto fail;
	if (read(fd, buf2, l1_table_block) < l1_table_size + s->l1_table_offset)
		goto fail;
	memcpy(s->l1_table, buf2 + s->l1_table_offset, l1_table_size);

	for(i = 0; i < s->l1_size; i++) {
		be64_to_cpus(&s->l1_table[i]);
		//DPRINTF("L1[%d] => %llu\n", i, s->l1_table[i]);
		if (s->l1_table[i] > final_cluster)
			final_cluster = s->l1_table[i];
	}

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
	
	/*Detect min_cluster_alloc*/
	s->min_cluster_alloc = 1; /*Default*/
	if (s->backing_file_offset == 0 && s->l1_table_offset % 4096 == 0) {
		/*We test to see if the xen magic # exists*/
		exthdr = (QCowHeader_ext *)(buf + sizeof(QCowHeader));
		be32_to_cpus(&exthdr->xmagic);
		if(exthdr->xmagic != XEN_MAGIC) 
			goto end_xenhdr;
	
		be32_to_cpus(&exthdr->flags);
		/* Try to detect old tapdisk images. They have to be fixed because 
		 * they don't use big endian but native endianess for the L1 table */
		if ((exthdr->flags & EXTHDR_L1_BIG_ENDIAN) == 0) {
			QCowHeader_ext *tmphdr = (QCowHeader_ext *)(buf2 + sizeof(QCowHeader));
			/* 
			   The image is broken. Fix it. The L1 table has already been 
			   byte-swapped, so we can write it to the image file as it is
			   currently in memory. Then swap it back to native endianess
			   for operation.
			 */

			/* Change ENDIAN flag and copy it to store buffer */
			exthdr->flags |= EXTHDR_L1_BIG_ENDIAN;
			tmphdr->flags = cpu_to_be32(exthdr->flags);


			DPRINTF("qcow: Converting image to big endian L1 table\n");

			memcpy(buf2 + s->l1_table_offset, s->l1_table, l1_table_size);
			lseek(fd, 0, SEEK_SET);
			if (write(fd, buf2, l1_table_block) < 
				l1_table_size + s->l1_table_offset) {
				DPRINTF("qcow: Failed to write new L1 table\n");
				goto fail;
			}

			for(i = 0;i < s->l1_size; i++) {
				cpu_to_be64s(&s->l1_table[i]);
			}

		}

		/*Finally check the L1 table cksum*/
		be32_to_cpus(&exthdr->cksum);
		cksum = gen_cksum((char *)s->l1_table, 
				  s->l1_size * sizeof(uint64_t));
		if(exthdr->cksum != cksum)
			goto end_xenhdr;
			
		be32_to_cpus(&exthdr->min_cluster_alloc);
		s->sparse = (exthdr->flags & SPARSE_FILE);
		s->min_cluster_alloc = exthdr->min_cluster_alloc; 
	}

 end_xenhdr:
 	
	/* A segment (i.e. a page) can span multiple clusters */
	max_aio_reqs = ((getpagesize() / s->cluster_size) + 1) *
		MAX_SEGMENTS_PER_REQ * MAX_REQUESTS;

	if (tap_aio_init(&s->aio, bs->size, max_aio_reqs)!=0) {
		DPRINTF("Unable to initialise AIO state\n");
                tap_aio_free(&s->aio);
		goto fail;
	}
	init_fds(dd);

	if (!final_cluster)
		s->fd_end = l1_table_block;
	else {
		s->fd_end = lseek(fd, 0, SEEK_END);
		if (s->fd_end == (off_t)-1)
			goto fail;
	}

	return 0;
	
fail:
	DPRINTF("QCOW Open failed\n");
	tap_aio_free(&s->aio);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(fd);
	return -1;
}

static int tdqcow_queue_read(struct disk_driver *dd, uint64_t sector,
		      int nb_sectors, char *buf, td_callback_t cb,
		      int id, void *private)
{
	struct tdqcow_state *s = (struct tdqcow_state *)dd->private;
	int ret = 0, index_in_cluster, n, i, rsp = 0;
	uint64_t cluster_offset, sec, nr_secs;

	sec     = sector;
	nr_secs = nb_sectors;

	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++) 
		if (!tap_aio_can_lock(&s->aio, sector + i)) 
			return cb(dd, -EBUSY, sector, nb_sectors, id, private);

	/*We store a local record of the request*/
	while (nb_sectors > 0) {
		cluster_offset = 
			get_cluster_offset(s, sector << 9, 0, 0, 0, 0);
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->aio.iocb_free_count == 0 || !tap_aio_lock(&s->aio, sector)) 
			return cb(dd, -EBUSY, sector, nb_sectors, id, private);
		
		if(!cluster_offset) {
			tap_aio_unlock(&s->aio, sector);
			ret = cb(dd, BLK_NOT_ALLOCATED, 
				 sector, n, id, private);
			if (ret == -EBUSY) {
				/* mark remainder of request
				 * as busy and try again later */
				return cb(dd, -EBUSY, sector + n,
					  nb_sectors - n, id, private);
			} else
				rsp += ret;
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			tap_aio_unlock(&s->aio, sector);
			if (decompress_cluster(s, cluster_offset) < 0) {
				rsp += cb(dd, -EIO, sector, 
					  nb_sectors, id, private);
				goto done;
			}
			memcpy(buf, s->cluster_cache + index_in_cluster * 512, 
			       512 * n);
			rsp += cb(dd, 0, sector, n, id, private);
		} else {
			tap_aio_read(&s->aio, s->fd, n * 512, 
				   (cluster_offset + index_in_cluster * 512),
				   buf, cb, id, sector, private);
		}
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
done:
	return rsp;
}

static int tdqcow_queue_write(struct disk_driver *dd, uint64_t sector,
		       int nb_sectors, char *buf, td_callback_t cb,
		       int id, void *private)
{
	struct tdqcow_state *s = (struct tdqcow_state *)dd->private;
	int ret = 0, index_in_cluster, n, i;
	uint64_t cluster_offset, sec, nr_secs;

	sec     = sector;
	nr_secs = nb_sectors;

	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++)
		if (!tap_aio_can_lock(&s->aio, sector + i))  
			return cb(dd, -EBUSY, sector, nb_sectors, id, private);
		   
	/*We store a local record of the request*/
	while (nb_sectors > 0) {
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->aio.iocb_free_count == 0 || !tap_aio_lock(&s->aio, sector))
			return cb(dd, -EBUSY, sector, nb_sectors, id, private);

		cluster_offset = get_cluster_offset(s, sector << 9, 1, 0,
						    index_in_cluster, 
						    index_in_cluster+n);
		if (!cluster_offset) {
			DPRINTF("Ooops, no write cluster offset!\n");
			tap_aio_unlock(&s->aio, sector);
			return cb(dd, -EIO, sector, nb_sectors, id, private);
		}

		if (s->crypt_method) {
			encrypt_sectors(s, sector, s->cluster_data, 
					(unsigned char *)buf, n, 1,
					&s->aes_encrypt_key);
			tap_aio_write(&s->aio, s->fd, n * 512, 
				    (cluster_offset + index_in_cluster*512),
				    (char *)s->cluster_data, cb, id, sector, 
				    private);
		} else {
			tap_aio_write(&s->aio, s->fd, n * 512, 
				    (cluster_offset + index_in_cluster*512),
				    buf, cb, id, sector, private);
		}
		
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
	s->cluster_cache_offset = -1; /* disable compressed cache */

	return 0;
}
 		
static int tdqcow_submit(struct disk_driver *dd)
{
        struct tdqcow_state *prv = (struct tdqcow_state *)dd->private;

	return tap_aio_submit(&prv->aio);
}

static int tdqcow_close(struct disk_driver *dd)
{
	struct tdqcow_state *s = (struct tdqcow_state *)dd->private;
	uint32_t cksum, out;
	int fd, offset;

	/*Update the hdr cksum*/
	if(s->min_cluster_alloc == s->l2_size) {
		cksum = gen_cksum((char *)s->l1_table, s->l1_size * sizeof(uint64_t));
		printf("Writing cksum: %d",cksum);
		fd = open(s->name, O_WRONLY | O_LARGEFILE); /*Open without O_DIRECT*/
		offset = sizeof(QCowHeader) + sizeof(uint32_t);
		lseek(fd, offset, SEEK_SET);
		out = cpu_to_be32(cksum);
		if (write(fd, &out, sizeof(uint32_t))) ;
		close(fd);
	}

	io_destroy(s->aio.aio_ctx.aio_ctx);
	free(s->name);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(s->fd);	
	return 0;
}

static int tdqcow_do_callbacks(struct disk_driver *dd, int sid)
{
        int ret, i, nr_events, rsp = 0,*ptr;
        struct io_event *ep;
        struct tdqcow_state *prv = (struct tdqcow_state *)dd->private;

        if (sid > MAX_IOFD) return 1;

        nr_events = tap_aio_get_events(&prv->aio.aio_ctx);
repeat:
        for (ep = prv->aio.aio_events, i = nr_events; i-- > 0; ep++) {
                struct iocb        *io  = ep->obj;
                struct pending_aio *pio;

                pio = &prv->aio.pending_aio[(long)io->data];

		tap_aio_unlock(&prv->aio, pio->sector);

		if (prv->crypt_method)
			encrypt_sectors(prv, pio->sector, 
					(unsigned char *)pio->buf, 
					(unsigned char *)pio->buf, 
					pio->nb_sectors, 0, 
					&prv->aes_decrypt_key);

		rsp += pio->cb(dd, ep->res == io->u.c.nbytes ? 0 : 1, 
			       pio->sector, pio->nb_sectors,
			       pio->id, pio->private);

                prv->aio.iocb_free[prv->aio.iocb_free_count++] = io;
        }

        if (nr_events) {
                nr_events = tap_aio_more_events(&prv->aio.aio_ctx);
                goto repeat;
        }

        tap_aio_continue(&prv->aio.aio_ctx);

        return rsp;
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

	DPRINTF("Qcow_create: size %llu\n",(long long unsigned)total_size);

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
			DPRINTF("Backing file size detected: %lld sectors" 
				"(total %lld [%lld MB])\n", 
				(long long)size, 
				(long long)(size << SECTOR_SHIFT), 
				(long long)(size >> 11));
		} else {
			backing_file = NULL;
			DPRINTF("Setting file size: %lld (total %lld)\n", 
				(long long) total_size, 
				(long long) (total_size << SECTOR_SHIFT));
		}
		header.mtime = cpu_to_be32(st.st_mtime);
		header.cluster_bits = 9; /* 512 byte cluster to avoid copying
					    unmodifyed sectors */
		header.l2_bits = 12; /* 32 KB L2 tables */
		exthdr.min_cluster_alloc = cpu_to_be32(1);
	} else {
		DPRINTF("Setting file size: %lld sectors" 
			"(total %lld [%lld MB])\n", 
			(long long) size, 
			(long long) (size << SECTOR_SHIFT), 
			(long long) (size >> 11));
		header.cluster_bits = 12; /* 4 KB clusters */
		header.l2_bits = 9; /* 4 KB L2 tables */
		exthdr.min_cluster_alloc = cpu_to_be32(1 << 9);
	}
	/*Set the header size value*/
	header.size = cpu_to_be64(size * 512);
	
	header_size = (header_size + 7) & ~7;
	if (header_size % 4096 > 0) {
		header_size = ROUNDUP(header_size, 4096);
	}

	shift = header.cluster_bits + header.l2_bits;
	l1_size = ROUNDUP(size * 512, 1LL << shift);

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

static int tdqcow_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	off_t off;
	char *buf, *filename;
	int len, secs, err = -EINVAL;
	struct tdqcow_state *child  = (struct tdqcow_state *)dd->private;

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

	id->name       = strdup(filename);
	id->drivertype = DISK_TYPE_AIO;
	err            = 0;
 out:
	free(buf);
	return err;
}

static int tdqcow_validate_parent(struct disk_driver *child,
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

struct tap_disk tapdisk_qcow = {
	.disk_type           = "tapdisk_qcow",
	.private_data_size   = sizeof(struct tdqcow_state),
	.td_open             = tdqcow_open,
	.td_queue_read       = tdqcow_queue_read,
	.td_queue_write      = tdqcow_queue_write,
	.td_submit           = tdqcow_submit,
	.td_close            = tdqcow_close,
	.td_do_callbacks     = tdqcow_do_callbacks,
	.td_get_parent_id    = tdqcow_get_parent_id,
	.td_validate_parent  = tdqcow_validate_parent
};
