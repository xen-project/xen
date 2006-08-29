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
#include <linux/fs.h>
#include <string.h>
#include <zlib.h>
#include <inttypes.h>
#include <libaio.h>
#include <openssl/md5.h>
#include "bswap.h"
#include "aes.h"
#include "tapdisk.h"

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif


/******AIO DEFINES******/
#define REQUEST_ASYNC_FD 1
#define MAX_QCOW_IDS  0xFFFF
#define MAX_AIO_REQS (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)

struct pending_aio {
        td_callback_t cb;
        int id;
        void *private;
	int nb_sectors;
	char *buf;
	uint64_t sector;
	int qcow_idx;
};

#define IOCB_IDX(_s, _io) ((_io) - (_s)->iocb_list)

#define ZERO_TEST(_b) (_b | 0x00)

/**************************************************************/
/* QEMU COW block driver with compression and encryption support */

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define XEN_MAGIC  (('X' << 24) | ('E' << 16) | ('N' << 8) | 0xfb)
#define QCOW_VERSION 1

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1

#define QCOW_OFLAG_COMPRESSED (1LL << 63)

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
} QCowHeader_ext;

#define L2_CACHE_SIZE 16  /*Fixed allocation in Qemu*/

struct tdqcow_state {
        int fd;                        /*Main Qcow file descriptor */
	uint64_t fd_end;               /*Store a local record of file length */
	int bfd;                       /*Backing file descriptor*/
	char *name;                    /*Record of the filename*/
	int poll_pipe[2];              /*dummy fd for polling on */
	int encrypted;                 /*File contents are encrypted or plain*/
	int cluster_bits;              /*Determines length of cluster as 
					*indicated by file hdr*/
	int cluster_size;              /*Length of cluster*/
	int cluster_sectors;           /*Number of sectors per cluster*/
	int cluster_alloc;             /*Blktap fix for allocating full 
					*extents*/
	int min_cluster_alloc;         /*Blktap historical extent alloc*/
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
	uint8_t *sector_lock;          /*Locking bitmap for AIO reads/writes*/
	uint64_t cluster_cache_offset; /**/
	uint32_t crypt_method;         /*current crypt method, 0 if no 
					*key yet */
	uint32_t crypt_method_header;  /**/
	AES_KEY aes_encrypt_key;       /*AES key*/
	AES_KEY aes_decrypt_key;       /*AES key*/
        /* libaio state */
        io_context_t       aio_ctx;
	int		   nr_reqs [MAX_QCOW_IDS];
        struct iocb        iocb_list  [MAX_AIO_REQS];
        struct iocb       *iocb_free  [MAX_AIO_REQS];
        struct pending_aio pending_aio[MAX_AIO_REQS];
        int                iocb_free_count;
        struct iocb       *iocb_queue[MAX_AIO_REQS];
        int                iocb_queued;
        int                poll_fd;      /* NB: we require aio_poll support */
        struct io_event    aio_events[MAX_AIO_REQS];
};

static int decompress_cluster(struct tdqcow_state *s, uint64_t cluster_offset);

static int init_aio_state(struct td_state *bs)
{
        int i;
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
        long     ioidx;

        /*Initialize Locking bitmap*/
	s->sector_lock = calloc(1, bs->size);
	
	if (!s->sector_lock) {
		DPRINTF("Failed to allocate sector lock\n");
		goto fail;
	}

        /* Initialize AIO */
        s->iocb_free_count = MAX_AIO_REQS;
        s->iocb_queued     = 0;

        /*Signal kernel to create Poll FD for Asyc completion events*/
        s->aio_ctx = (io_context_t) REQUEST_ASYNC_FD;   
        s->poll_fd = io_setup(MAX_AIO_REQS, &s->aio_ctx);

	if (s->poll_fd < 0) {
                if (s->poll_fd == -EAGAIN) {
                        DPRINTF("Couldn't setup AIO context.  If you are "
                                "trying to concurrently use a large number "
                                "of blktap-based disks, you may need to "
                                "increase the system-wide aio request limit. "
                                "(e.g. 'echo echo 1048576 > /proc/sys/fs/"
                                "aio-max-nr')\n");
                } else {
                        DPRINTF("Couldn't get fd for AIO poll support.  This "
                                "is probably because your kernel does not "
                                "have the aio-poll patch applied.\n");
                }
		goto fail;
	}

        for (i=0;i<MAX_AIO_REQS;i++)
                s->iocb_free[i] = &s->iocb_list[i];
	for (i=0;i<MAX_QCOW_IDS;i++)
		s->nr_reqs[i] = 0;
        DPRINTF("AIO state initialised\n");

        return 0;

 fail:
	return -1;
}

/*
 *Test if block is zero. 
 * Return: 
 *       1 for TRUE
 *       0 for FALSE
 */
static inline int IS_ZERO(char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		/*if not zero, return false*/
		if (ZERO_TEST(*(buf + i))) return 0; 
	}
	return 1;
}

static uint32_t gen_cksum(char *ptr, int len)
{
	unsigned char *md;
	uint32_t ret;

	md = malloc(MD5_DIGEST_LENGTH);

	if(!md) return 0;

	if (MD5((unsigned char *)ptr, len, md) != md) return 0;

	memcpy(&ret, md, sizeof(uint32_t));
	free(md);
	return ret;
}

static int qcow_set_key(struct td_state *bs, const char *key)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
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

static int async_read(struct tdqcow_state *s, int fd, int size, 
		     uint64_t offset,
		     char *buf, td_callback_t cb,
		     int id, uint64_t sector, int qcow_idx, void *private)
{
        struct   iocb *io;
        struct   pending_aio *pio;
	long     ioidx;

        io = s->iocb_free[--s->iocb_free_count];

        ioidx = IOCB_IDX(s, io);
        pio = &s->pending_aio[ioidx];
        pio->cb = cb;
        pio->id = id;
        pio->private = private;
	pio->nb_sectors = size/512;
	pio->buf = buf;
	pio->sector = sector;
	pio->qcow_idx = qcow_idx;

        io_prep_pread(io, fd, buf, size, offset);
        io->data = (void *)ioidx;

        s->iocb_queue[s->iocb_queued++] = io;

        return 1;
}

static int async_write(struct tdqcow_state *s, int fd, int size, 
		     uint64_t offset,
		     char *buf, td_callback_t cb,
		      int id, uint64_t sector, int qcow_idx, void *private)
{
        struct   iocb *io;
        struct   pending_aio *pio;
	long     ioidx;

        io = s->iocb_free[--s->iocb_free_count];

        ioidx = IOCB_IDX(s, io);
        pio = &s->pending_aio[ioidx];
        pio->cb = cb;
        pio->id = id;
        pio->private = private;
	pio->nb_sectors = size/512;
	pio->buf = buf;
	pio->sector = sector;
	pio->qcow_idx = qcow_idx;

        io_prep_pwrite(io, fd, buf, size, offset);
        io->data = (void *)ioidx;

        s->iocb_queue[s->iocb_queued++] = io;

        return 1;
}

/*TODO: Fix sector span!*/
static int aio_can_lock(struct tdqcow_state *s, uint64_t sector)
{
	return (s->sector_lock[sector] ? 0 : 1);
}

static int aio_lock(struct tdqcow_state *s, uint64_t sector)
{
	return ++s->sector_lock[sector];
}

static void aio_unlock(struct tdqcow_state *s, uint64_t sector)
{
	if (!s->sector_lock[sector]) return;

	--s->sector_lock[sector];
	return;
}

/*TODO - Use a freelist*/
static int get_free_idx(struct tdqcow_state *s)
{
	int i;
	
	for(i = 0; i < MAX_QCOW_IDS; i++) {
		if(s->nr_reqs[i] == 0) return i;
	}
	return -1;
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
static uint64_t get_cluster_offset(struct td_state *bs,
                                   uint64_t offset, int allocate,
                                   int compressed_size,
                                   int n_start, int n_end)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	int min_index, i, j, l1_index, l2_index, l2_sector, l1_sector;
	char *tmp_ptr, *tmp_ptr2, *l2_ptr, *l1_ptr;
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
		ftruncate(s->fd, l2_offset + (s->l2_size * sizeof(uint64_t)));
		s->fd_end += (s->l2_size * sizeof(uint64_t));

		/*Update the L1 table entry on disk
                 * (for O_DIRECT we write 4KByte blocks)*/
		l1_sector = (l1_index * sizeof(uint64_t)) >> 12;
		l1_ptr = (char *)s->l1_table + (l1_sector << 12);

		if (posix_memalign((void **)&tmp_ptr, 4096, 4096) != 0) {
			DPRINTF("ERROR allocating memory for L1 table\n");
		}
		memcpy(tmp_ptr, l1_ptr, 4096);

		/*
		 * Issue non-asynchronous L1 write.
		 * For safety, we must ensure that
		 * entry is written before blocks.
		 */
		lseek(s->fd, s->l1_table_offset + (l1_sector << 12), SEEK_SET);
		if (write(s->fd, tmp_ptr, 4096) != 4096)
			return 0;
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
			ftruncate(s->fd, cluster_offset + 
				  (s->cluster_size * s->l2_size));
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
			cluster_offset = lseek(s->fd, 0, SEEK_END);
			cluster_offset = (cluster_offset + s->cluster_size - 1)
				& ~(s->cluster_size - 1);
			/* write the cluster content - not asynchronous */
			lseek(s->fd, cluster_offset, SEEK_SET);
			if (write(s->fd, s->cluster_cache, s->cluster_size) != 
			    s->cluster_size)
			    return -1;
		} else {
			/* allocate a new cluster */
			cluster_offset = lseek(s->fd, 0, SEEK_END);
			if (allocate == 1) {
				/* round to cluster size */
				cluster_offset = 
					(cluster_offset + s->cluster_size - 1) 
					& ~(s->cluster_size - 1);
				ftruncate(s->fd, cluster_offset + 
					  s->cluster_size);
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
		aio_lock(s, offset >> 9);
		async_write(s, s->fd, 4096, l2_offset + (l2_sector << 12), 
			    tmp_ptr2, 0, -2, offset >> 9, 0, NULL);
	}
	return cluster_offset;
}

static void init_cluster_cache(struct td_state *bs)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	uint32_t count = 0;
	int i, cluster_entries;

	cluster_entries = s->cluster_size / 512;
	DPRINTF("Initialising Cluster cache, %d sectors per cluster (%d cluster size)\n",
		cluster_entries, s->cluster_size);

	for (i = 0; i < bs->size; i += cluster_entries) {
		if (get_cluster_offset(bs, i << 9, 0, 0, 0, 1)) count++;
		if (count >= L2_CACHE_SIZE) return;
	}
	DPRINTF("Finished cluster initialisation, added %d entries\n", count);
	return;
}

static int qcow_is_allocated(struct td_state *bs, int64_t sector_num, 
                             int nb_sectors, int *pnum)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;

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

/* Open the disk file and initialize qcow state. */
int tdqcow_open (struct td_state *bs, const char *name)
{
	int fd, len, i, shift, ret, size, l1_table_size;
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	char *buf;
	QCowHeader *header;
	QCowHeader_ext *exthdr;
	uint32_t cksum;

 	DPRINTF("QCOW: Opening %s\n",name);
	/* set up a pipe so that we can hand back a poll fd that won't fire.*/
	ret = pipe(s->poll_pipe);
	if (ret != 0)
		return (0 - errno);

	fd = open(name, O_RDWR | O_DIRECT | O_LARGEFILE);
	if (fd < 0) {
		DPRINTF("Unable to open %s (%d)\n",name,0 - errno);
		return -1;
	}

	s->fd = fd;
	asprintf(&s->name,"%s", name);

	ASSERT(sizeof(header) < 512);

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
   
	if (header->magic != QCOW_MAGIC || header->version > QCOW_VERSION)
		goto fail;
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
	
	/* read the level 1 table */
	shift = s->cluster_bits + s->l2_bits;
	s->l1_size = (header->size + (1LL << shift) - 1) >> shift;
	
	s->l1_table_offset = header->l1_table_offset;

	/*allocate a 4Kbyte multiple of memory*/
	l1_table_size = s->l1_size * sizeof(uint64_t);
	if (l1_table_size % 4096 > 0) {
		l1_table_size = ((l1_table_size >> 12) + 1) << 12;
	}
	ret = posix_memalign((void **)&s->l1_table, 4096, l1_table_size);
	if (ret != 0) goto fail;
	memset(s->l1_table, 0x00, l1_table_size);

	DPRINTF("L1 Table offset detected: %llu, size %d (%d)\n",
		(long long)s->l1_table_offset,
		(int) (s->l1_size * sizeof(uint64_t)), 
		l1_table_size);

	lseek(fd, s->l1_table_offset, SEEK_SET);
	if (read(fd, s->l1_table, l1_table_size) != l1_table_size)
		goto fail;
/*	for(i = 0;i < s->l1_size; i++) {
		//be64_to_cpus(&s->l1_table[i]);
		DPRINTF("L1[%d] => %llu\n", i, s->l1_table[i]);
		}*/

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

	/* read the backing file name */
	s->bfd = -1;
	if (header->backing_file_offset != 0) {
		DPRINTF("Reading backing file data\n");
		len = header->backing_file_size;
		if (len > 1023)
			len = 1023;

                /*TODO - Fix read size for O_DIRECT and use original fd!*/
		fd = open(name, O_RDONLY | O_LARGEFILE);

		lseek(fd, header->backing_file_offset, SEEK_SET);
		if (read(fd, bs->backing_file, len) != len)
			goto fail;
		bs->backing_file[len] = '\0';
		close(fd);
		/***********************************/

		/*Open backing file*/
		fd = open(bs->backing_file, O_RDONLY | O_DIRECT | O_LARGEFILE);
		if (fd < 0) {
			DPRINTF("Unable to open backing file: %s\n",
				bs->backing_file);
			goto fail;
		}
		s->bfd = fd;
		s->cluster_alloc = 1; /*Cannot use pre-alloc*/
	}

        bs->sector_size = 512;
        bs->info = 0;
	
	/*Detect min_cluster_alloc*/
	s->min_cluster_alloc = 1; /*Default*/
	if (s->bfd == -1 && (s->l1_table_offset % 4096 == 0) ) {
		/*We test to see if the xen magic # exists*/
		exthdr = (QCowHeader_ext *)(buf + sizeof(QCowHeader));
		be32_to_cpus(&exthdr->xmagic);
		if(exthdr->xmagic != XEN_MAGIC) 
			goto end_xenhdr;

		/*Finally check the L1 table cksum*/
		be32_to_cpus(&exthdr->cksum);
		cksum = gen_cksum((char *)s->l1_table, s->l1_size * sizeof(uint64_t));
		if(exthdr->cksum != cksum)
			goto end_xenhdr;
			
		be32_to_cpus(&exthdr->min_cluster_alloc);
		s->min_cluster_alloc = exthdr->min_cluster_alloc; 
	}

 end_xenhdr:
	if (init_aio_state(bs)!=0) {
		DPRINTF("Unable to initialise AIO state\n");
		goto fail;
	}
	s->fd_end = lseek(s->fd, 0, SEEK_END);

	return 0;
	
fail:
	DPRINTF("QCOW Open failed\n");
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(fd);
	return -1;
}

 int tdqcow_queue_read(struct td_state *bs, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	int ret = 0, index_in_cluster, n, i, qcow_idx, asubmit = 0;
	uint64_t cluster_offset;

	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++)
		if (!aio_can_lock(s, sector + i)) {
			DPRINTF("AIO_CAN_LOCK failed [%llu]\n", 
				(long long) sector + i);
			return -EBUSY;
		}
	
	/*We store a local record of the request*/
	qcow_idx = get_free_idx(s);
	while (nb_sectors > 0) {
		cluster_offset = 
			get_cluster_offset(bs, sector << 9, 0, 0, 0, 0);
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->iocb_free_count == 0 || !aio_lock(s, sector)) {
			DPRINTF("AIO_LOCK or iocb_free_count (%d) failed" 
				"[%llu]\n", s->iocb_free_count, 
				(long long) sector);
			return -ENOMEM;
		}
		
		if (!cluster_offset && (s->bfd > 0)) {
			s->nr_reqs[qcow_idx]++;
			asubmit += async_read(s, s->bfd, n * 512, sector << 9, 
					      buf, cb, id, sector, 
					      qcow_idx, private);
		} else if(!cluster_offset) {
			memset(buf, 0, 512 * n);
			aio_unlock(s, sector);
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			if (decompress_cluster(s, cluster_offset) < 0) {
				ret = -1;
				goto done;
			}
			memcpy(buf, s->cluster_cache + index_in_cluster * 512, 
			       512 * n);
		} else {			
			s->nr_reqs[qcow_idx]++;
			asubmit += async_read(s, s->fd, n * 512, 
					      (cluster_offset + 
					       index_in_cluster * 512), 
					      buf, cb, id, sector, 
					      qcow_idx, private);
		}
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
done:
        /*Callback if no async requests outstanding*/
        if (!asubmit) return cb(bs, ret == -1 ? -1 : 0, id, private);

	return 0;
}

 int tdqcow_queue_write(struct td_state *bs, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	int ret = 0, index_in_cluster, n, i, qcow_idx, asubmit = 0;
	uint64_t cluster_offset;

	/*Check we can get a lock*/
	for (i = 0; i < nb_sectors; i++)
		if (!aio_can_lock(s, sector + i))  {
			DPRINTF("AIO_CAN_LOCK failed [%llu]\n", 
				(long long) (sector + i));
			return -EBUSY;
		}
		   
	/*We store a local record of the request*/
	qcow_idx = get_free_idx(s);	
	while (nb_sectors > 0) {
		index_in_cluster = sector & (s->cluster_sectors - 1);
		n = s->cluster_sectors - index_in_cluster;
		if (n > nb_sectors)
			n = nb_sectors;

		if (s->iocb_free_count == 0 || !aio_lock(s, sector)){
			DPRINTF("AIO_LOCK or iocb_free_count (%d) failed" 
				"[%llu]\n", s->iocb_free_count, 
				(long long) sector);
			return -ENOMEM;
		}

		if (!IS_ZERO(buf,n * 512)) {

			cluster_offset = get_cluster_offset(bs, sector << 9, 
							    1, 0, 
							    index_in_cluster, 
							    index_in_cluster+n
				);
			if (!cluster_offset) {
				DPRINTF("Ooops, no write cluster offset!\n");
				ret = -1;
				goto done;
			}

			if (s->crypt_method) {
				encrypt_sectors(s, sector, s->cluster_data, 
						(unsigned char *)buf, n, 1,
						&s->aes_encrypt_key);
				s->nr_reqs[qcow_idx]++;
				asubmit += async_write(s, s->fd, n * 512, 
						       (cluster_offset + 
							index_in_cluster*512), 
						       (char *)s->cluster_data,
						       cb, id, sector, 
						       qcow_idx, private);
			} else {
				s->nr_reqs[qcow_idx]++;
				asubmit += async_write(s, s->fd, n * 512, 
						       (cluster_offset + 
							index_in_cluster*512),
						       buf, cb, id, sector, 
						       qcow_idx, private);
			}
		} else {
			/*Write data contains zeros, but we must check to see 
			  if cluster already allocated*/
			cluster_offset = get_cluster_offset(bs, sector << 9, 
							    0, 0, 
							    index_in_cluster, 
							    index_in_cluster+n
				);	
			if(cluster_offset) {
				if (s->crypt_method) {
					encrypt_sectors(s, sector, 
							s->cluster_data, 
							(unsigned char *)buf, 
							n, 1,
							&s->aes_encrypt_key);
					s->nr_reqs[qcow_idx]++;
					asubmit += async_write(s, s->fd, 
							       n * 512, 
							       (cluster_offset+
								index_in_cluster * 512), 
							       (char *)s->cluster_data, cb, id, sector, 
							       qcow_idx, private);
				} else {
					s->nr_reqs[qcow_idx]++;
					asubmit += async_write(s, s->fd, n*512,
							       cluster_offset + index_in_cluster * 512, 
							       buf, cb, id, sector, 
							       qcow_idx, private);
				}
			}
			else aio_unlock(s, sector);
		}
		nb_sectors -= n;
		sector += n;
		buf += n * 512;
	}
	s->cluster_cache_offset = -1; /* disable compressed cache */

done:
	/*Callback if no async requests outstanding*/
        if (!asubmit) return cb(bs, ret == -1 ? -1 : 0, id, private);

	return 0;
}
 		
int tdqcow_submit(struct td_state *bs)
{
        int ret;
        struct   tdqcow_state *prv = (struct tdqcow_state *)bs->private;

        ret = io_submit(prv->aio_ctx, prv->iocb_queued, prv->iocb_queue);

        /* XXX: TODO: Handle error conditions here. */

        /* Success case: */
        prv->iocb_queued = 0;

        return ret;
}


int *tdqcow_get_fd(struct td_state *bs)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	int *fds, i;

	fds = malloc(sizeof(int) * MAX_IOFD);
	/*initialise the FD array*/
	for(i=0;i<MAX_IOFD;i++) fds[i] = 0;

	fds[0] = s->poll_fd;
	return fds;
}

int tdqcow_close(struct td_state *bs)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
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
		write(fd, &out, sizeof(uint32_t));
		close(fd);
	}

	free(s->name);
	free(s->l1_table);
	free(s->l2_cache);
	free(s->cluster_cache);
	free(s->cluster_data);
	close(s->fd);	
	return 0;
}

int tdqcow_do_callbacks(struct td_state *s, int sid)
{
        int ret, i, rsp = 0,*ptr;
        struct io_event *ep;
        struct tdqcow_state *prv = (struct tdqcow_state *)s->private;

        if (sid > MAX_IOFD) return 1;
	
	/* Non-blocking test for completed io. */
        ret = io_getevents(prv->aio_ctx, 0, MAX_AIO_REQS, prv->aio_events,
                           NULL);

        for (ep=prv->aio_events, i = ret; i-->0; ep++) {
                struct iocb        *io  = ep->obj;
                struct pending_aio *pio;

                pio = &prv->pending_aio[(long)io->data];

                if (ep->res != io->u.c.nbytes) {
                        /* TODO: handle this case better. */
			ptr = (int *)&ep->res;
                        DPRINTF("AIO did less than I asked it to "
				"[%lu,%lu,%d]\n", 
				ep->res, io->u.c.nbytes, *ptr);
                }
		aio_unlock(prv, pio->sector);
		if (pio->id >= 0) {
			if (prv->crypt_method)
				encrypt_sectors(prv, pio->sector, 
						(unsigned char *)pio->buf, 
						(unsigned char *)pio->buf, 
						pio->nb_sectors, 0, 
						&prv->aes_decrypt_key);
			prv->nr_reqs[pio->qcow_idx]--;
			if (prv->nr_reqs[pio->qcow_idx] == 0) 
				rsp += pio->cb(s, ep->res2, pio->id, 
					       pio->private);
		} else if (pio->id == -2) free(pio->buf);

                prv->iocb_free[prv->iocb_free_count++] = io;
        }
        return rsp;
}

int qcow_create(const char *filename, uint64_t total_size,
                      const char *backing_file, int flags)
{
	int fd, header_size, backing_filename_len, l1_size, i;
	int shift, length, adjust, ret = 0;
	QCowHeader header;
	QCowHeader_ext exthdr;
	char backing_filename[1024], *ptr;
	uint64_t tmp, size;
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
				realpath(backing_file, backing_filename);
				if (stat(backing_filename, &st) != 0) {
					return -1;
				}
			}
			header.backing_file_offset = cpu_to_be64(header_size);
			backing_filename_len = strlen(backing_filename);
			header.backing_file_size = cpu_to_be32(
				backing_filename_len);
			header_size += backing_filename_len;
			
			/*Set to the backing file size*/
			size = (st.st_size >> SECTOR_SHIFT);
			DPRINTF("Backing file size detected: %lld sectors" 
				"(total %lld [%lld MB])\n", 
				(long long)total_size, 
				(long long)(total_size << SECTOR_SHIFT), 
				(long long)(total_size >> 11));
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
		header_size = ((header_size >> 12) + 1) << 12;
	}

	shift = header.cluster_bits + header.l2_bits;
	l1_size = ((size * 512) + (1LL << shift) - 1) >> shift;

	header.l1_table_offset = cpu_to_be64(header_size);
	DPRINTF("L1 Table offset: %d, size %d\n",
		header_size,
		(int)(l1_size * sizeof(uint64_t)));
	if (flags) {
		header.crypt_method = cpu_to_be32(QCOW_CRYPT_AES);
	} else {
		header.crypt_method = cpu_to_be32(QCOW_CRYPT_NONE);
	}

	ptr = calloc(1, l1_size * sizeof(uint64_t));
	exthdr.cksum = cpu_to_be32(gen_cksum(ptr, l1_size * sizeof(uint64_t)));
	printf("Created cksum: %d\n",exthdr.cksum);
	free(ptr);
	
	/* write all the data */
	ret += write(fd, &header, sizeof(header));
	ret += write(fd, &exthdr, sizeof(exthdr));
	if (backing_file) {
		ret += write(fd, backing_filename, backing_filename_len);
	}
	lseek(fd, header_size, SEEK_SET);
	tmp = 0;
	for (i = 0;i < l1_size; i++) {
		ret += write(fd, &tmp, sizeof(tmp));
	}

	/*adjust file length to 4 KByte boundary*/
	length = header_size + l1_size * sizeof(uint64_t);
	if (length % 4096 > 0) {
		length = ((length >> 12) + 1) << 12;
		ftruncate(fd, length);
		DPRINTF("Adjusted filelength to %d for 4 "
			"Kbyte alignment\n",length);
	}

	close(fd);

	return 0;
}

int qcow_make_empty(struct td_state *bs)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
	uint32_t l1_length = s->l1_size * sizeof(uint64_t);

	memset(s->l1_table, 0, l1_length);
	lseek(s->fd, s->l1_table_offset, SEEK_SET);
	if (write(s->fd, s->l1_table, l1_length) < 0)
		return -1;
	ftruncate(s->fd, s->l1_table_offset + l1_length);

	memset(s->l2_cache, 0, s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_offsets, 0, L2_CACHE_SIZE * sizeof(uint64_t));
	memset(s->l2_cache_counts, 0, L2_CACHE_SIZE * sizeof(uint32_t));

	return 0;
}

int qcow_get_cluster_size(struct td_state *bs)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;

	return s->cluster_size;
}

/* XXX: put compressed sectors first, then all the cluster aligned
   tables to avoid losing bytes in alignment */
int qcow_compress_cluster(struct td_state *bs, int64_t sector_num, 
                          const uint8_t *buf)
{
	struct tdqcow_state *s = (struct tdqcow_state *)bs->private;
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
		cluster_offset = get_cluster_offset(bs, sector_num << 9, 2, 
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

struct tap_disk tapdisk_qcow = {
	"tapdisk_qcow",
	sizeof(struct tdqcow_state),
	tdqcow_open,
	tdqcow_queue_read,
	tdqcow_queue_write,
	tdqcow_submit,
	tdqcow_get_fd,
	tdqcow_close,
	tdqcow_do_callbacks,
};

