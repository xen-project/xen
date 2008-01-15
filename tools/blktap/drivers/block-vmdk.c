/* block-vmdk.c
 *
 * VMware Disk format implementation.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 *
 * This is largely the same as the vmdk driver in Qemu, I've just twisted it
 * to match our interfaces.  The original (BSDish) Copyright message appears 
 * below:
 */
 
/*
 * Block driver for the VMDK format
 * 
 * Copyright (c) 2004 Fabrice Bellard
 * Copyright (c) 2005 Filip Navara
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include "tapdisk.h"
#include "bswap.h"

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif

#define safer_free(_x)       \
  do {                       \
  	if (NULL != _x) {    \
  		free(_x);    \
  		(_x) = NULL; \
  	}                    \
  } while (0) ;

#define VMDK3_MAGIC (('C' << 24) | ('O' << 16) | ('W' << 8) | 'D')
#define VMDK4_MAGIC (('K' << 24) | ('D' << 16) | ('M' << 8) | 'V')

typedef struct {
    uint32_t version;
    uint32_t flags;
    uint32_t disk_sectors;
    uint32_t granularity;
    uint32_t l1dir_offset;
    uint32_t l1dir_size;
    uint32_t file_sectors;
    uint32_t cylinders;
    uint32_t heads;
    uint32_t sectors_per_track;
} VMDK3Header;

typedef struct {
    uint32_t version;
    uint32_t flags;
    int64_t capacity;
    int64_t granularity;
    int64_t desc_offset;
    int64_t desc_size;
    int32_t num_gtes_per_gte;
    int64_t rgd_offset;
    int64_t gd_offset;
    int64_t grain_offset;
    char filler[1];
    char check_bytes[4];
} __attribute__((packed)) VMDK4Header;

#define L2_CACHE_SIZE 16

struct tdvmdk_state {
        int fd;
	int poll_pipe[2]; /* dummy fd for polling on */
	
    	unsigned int l1_size;
    	int64_t l1_table_offset;
    	int64_t l1_backup_table_offset;
    	uint32_t l1_entry_sectors;
    	unsigned int l2_size;
	
    	uint32_t *l1_table;
    	uint32_t *l1_backup_table;
    	uint32_t *l2_cache;
    	uint32_t l2_cache_offsets[L2_CACHE_SIZE];
    	uint32_t l2_cache_counts[L2_CACHE_SIZE];
    	
    	unsigned int cluster_sectors;
};

static inline void init_fds(struct disk_driver *dd)
{
        int i;
	struct tdvmdk_state *prv = (struct tdvmdk_state *)dd->private;

        for (i = 0; i < MAX_IOFD; i++)
		dd->io_fd[i] = 0;

        dd->io_fd[0] = prv->poll_pipe[0];
}

/* Open the disk file and initialize aio state. */
static int tdvmdk_open (struct disk_driver *dd, 
			const char *name, td_flag_t flags)
{
	int ret, fd;
    	int l1_size, i, o_flags;
    	uint32_t magic;
	struct td_state     *s   = dd->td_state;
	struct tdvmdk_state *prv = (struct tdvmdk_state *)dd->private;

	/* set up a pipe so that we can hand back a poll fd that won't fire.*/
	ret = pipe(prv->poll_pipe);
	if (ret != 0)
		return -1;
	
	/* Open the file */
	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags == TD_RDONLY) ? O_RDONLY : O_RDWR);
        fd = open(name, o_flags); 

        if ( (fd == -1) && (errno == EINVAL) ) {

                /* Maybe O_DIRECT isn't supported. */
		o_flags &= ~O_DIRECT;
                fd = open(name, o_flags);
                if (fd != -1) DPRINTF("WARNING: Accessing image without"
                                     "O_DIRECT! (%s)\n", name);

        } else if (fd != -1) DPRINTF("open(%s) with O_DIRECT\n", name);
	
        if (fd == -1) {
		DPRINTF("Unable to open [%s]!\n",name);
        	ret = 0 - errno;
        	return -1;
        }
        
        prv->fd = fd;
        
        /* Grok the vmdk header. */
    	if ((ret = read(fd, &magic, sizeof(magic))) != sizeof(magic))
        	goto fail;
    	magic = be32_to_cpu(magic);
    	if (magic == VMDK3_MAGIC) {
        	VMDK3Header header;
        	if (read(fd, &header, sizeof(header)) != 
            		sizeof(header)) 
            		goto fail;
        	prv->cluster_sectors = le32_to_cpu(header.granularity);
        	prv->l2_size = 1 << 9;
        	prv->l1_size = 1 << 6;
        	s->size = le32_to_cpu(header.disk_sectors);
        	prv->l1_table_offset = le32_to_cpu(header.l1dir_offset) << 9;
        	prv->l1_backup_table_offset = 0;
        	prv->l1_entry_sectors = prv->l2_size * prv->cluster_sectors;
    	} else if (magic == VMDK4_MAGIC) {
        	VMDK4Header header;
        
        	if (read(fd, &header, sizeof(header)) != sizeof(header))
            		goto fail;
        	s->size = le32_to_cpu(header.capacity);
        	prv->cluster_sectors = le32_to_cpu(header.granularity);
        	prv->l2_size = le32_to_cpu(header.num_gtes_per_gte);
        	prv->l1_entry_sectors = prv->l2_size * prv->cluster_sectors;
        	if (prv->l1_entry_sectors <= 0)
            		goto fail;
        	prv->l1_size = (s->size + prv->l1_entry_sectors - 1) 
            		       / prv->l1_entry_sectors;
        	prv->l1_table_offset = le64_to_cpu(header.rgd_offset) << 9;
        	prv->l1_backup_table_offset = 
        		le64_to_cpu(header.gd_offset) << 9;
    	} else {
        	goto fail;
    	}
    	/* read the L1 table */
    	l1_size = prv->l1_size * sizeof(uint32_t);
    	prv->l1_table = malloc(l1_size);
    	if (!prv->l1_table)
        	goto fail;
    	if (lseek(fd, prv->l1_table_offset, SEEK_SET) == -1)
        	goto fail;
    	if (read(fd, prv->l1_table, l1_size) != l1_size)
        	goto fail;
    	for (i = 0; i < prv->l1_size; i++) {
        	le32_to_cpus(&prv->l1_table[i]);
    	}

    	if (prv->l1_backup_table_offset) {
        	prv->l1_backup_table = malloc(l1_size);
        	if (!prv->l1_backup_table)
            		goto fail;
        	if (lseek(fd, prv->l1_backup_table_offset, SEEK_SET) == -1)
            		goto fail;
        	if (read(fd, prv->l1_backup_table, l1_size) != l1_size)
            		goto fail;
        	for(i = 0; i < prv->l1_size; i++) {
            		le32_to_cpus(&prv->l1_backup_table[i]);
        	}
    	}

    	prv->l2_cache = malloc(prv->l2_size * L2_CACHE_SIZE *sizeof(uint32_t));
    	if (!prv->l2_cache)
        	goto fail;
    	prv->fd = fd;
	init_fds(dd);
	DPRINTF("VMDK File opened successfully\n");
    	return 0;
	
fail:
	DPRINTF("VMDK File open failed.\n"); 
   	safer_free(prv->l1_backup_table);
    	free(prv->l1_table);
    	free(prv->l2_cache);
    	close(fd);
	return -1;
}

static uint64_t get_cluster_offset(struct tdvmdk_state *prv, 
                                   uint64_t offset, int allocate)
{
    	unsigned int l1_index, l2_offset, l2_index;
    	int min_index, i, j;
    	uint32_t min_count, *l2_table, tmp;
    	uint64_t cluster_offset;
    
    	l1_index = (offset >> 9) / prv->l1_entry_sectors;
    	if (l1_index >= prv->l1_size)
        	return 0;
    	l2_offset = prv->l1_table[l1_index];
    	if (!l2_offset)
        	return 0;
    	for (i = 0; i < L2_CACHE_SIZE; i++) {
        	if (l2_offset == prv->l2_cache_offsets[i]) {
            		/* increment the hit count */
            		if (++prv->l2_cache_counts[i] == 0xffffffff) {
	                	for(j = 0; j < L2_CACHE_SIZE; j++) {
	                    		prv->l2_cache_counts[j] >>= 1;
	                	}
            		}
            		l2_table = prv->l2_cache + (i * prv->l2_size);
            		goto found;
        	}
    	}
    	/* not found: load a new entry in the least used one */
    	min_index = 0;
    	min_count = 0xffffffff;
    	for (i = 0; i < L2_CACHE_SIZE; i++) {
        	if (prv->l2_cache_counts[i] < min_count) {
            		min_count = prv->l2_cache_counts[i];
            		min_index = i;
        	}
    	}
    	l2_table = prv->l2_cache + (min_index * prv->l2_size);
    	lseek(prv->fd, (int64_t)l2_offset * 512, SEEK_SET);
    	if (read(prv->fd, l2_table, prv->l2_size * sizeof(uint32_t)) != 
        	 prv->l2_size * sizeof(uint32_t))
        	return 0;
    	prv->l2_cache_offsets[min_index] = l2_offset;
    	prv->l2_cache_counts[min_index] = 1;
 found:
    	l2_index = ((offset >> 9) / prv->cluster_sectors) % prv->l2_size;
    	cluster_offset = le32_to_cpu(l2_table[l2_index]);
    	if (!cluster_offset) {
        	if (!allocate)
            		return 0;
        	cluster_offset = lseek(prv->fd, 0, SEEK_END);
        	if (ftruncate(prv->fd, cluster_offset + 
			      (prv->cluster_sectors << 9)))
			return 0;
        	cluster_offset >>= 9;
        	/* update L2 table */
        	tmp = cpu_to_le32(cluster_offset);
        	l2_table[l2_index] = tmp;
        	lseek(prv->fd, ((int64_t)l2_offset * 512) + 
        	      (l2_index * sizeof(tmp)), SEEK_SET);
        	if (write(prv->fd, &tmp, sizeof(tmp)) != sizeof(tmp))
            		return 0;
        	/* update backup L2 table */
        	if (prv->l1_backup_table_offset != 0) {
            		l2_offset = prv->l1_backup_table[l1_index];
            	lseek(prv->fd, ((int64_t)l2_offset * 512) + 
            		(l2_index * sizeof(tmp)), SEEK_SET);
            	if (write(prv->fd, &tmp, sizeof(tmp)) != sizeof(tmp))
                	return 0;
        	}
    	}
    	cluster_offset <<= 9;
    	return cluster_offset;
}

static int tdvmdk_queue_read(struct disk_driver *dd, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct tdvmdk_state *prv = (struct tdvmdk_state *)dd->private;
    	int index_in_cluster, n;
    	uint64_t cluster_offset;
    	int ret = 0;

    	while (nb_sectors > 0) {
        	cluster_offset = get_cluster_offset(prv, sector << 9, 0);
        	index_in_cluster = sector % prv->cluster_sectors;
        	n = prv->cluster_sectors - index_in_cluster;
        	if (n > nb_sectors)
            		n = nb_sectors;
        	if (!cluster_offset) {
            		memset(buf, 0, 512 * n);
        	} else {
            		lseek(prv->fd, cluster_offset + index_in_cluster * 512,
            	      	      SEEK_SET);
            		ret = read(prv->fd, buf, n * 512);
            		if (ret != n * 512) {
                		ret = -1;
                		goto done;
            		}
        	}
        	nb_sectors -= n;
        	sector     += n;
        	buf += n * 512;
    	}
done:
	return cb(dd, ret == -1 ? -1 : 0, sector, nb_sectors, id, private);
}

static  int tdvmdk_queue_write(struct disk_driver *dd, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct tdvmdk_state *prv = (struct tdvmdk_state *)dd->private;
    	int index_in_cluster, n;
    	uint64_t cluster_offset;
    	int ret = 0;

    	while (nb_sectors > 0) {
        	index_in_cluster = sector & (prv->cluster_sectors - 1);
        	n = prv->cluster_sectors - index_in_cluster;
        	if (n > nb_sectors)
            		n = nb_sectors;
        	cluster_offset = get_cluster_offset(prv, sector << 9, 1);
        	if (!cluster_offset) {
            		ret = -1;
            		goto done;
        	}
        	lseek(prv->fd, cluster_offset + index_in_cluster * 512, 
        	      SEEK_SET);
        	ret = write(prv->fd, buf, n * 512);
        	if (ret != n * 512) {
            		ret = -1;
            		goto done;
        	}
        	nb_sectors -= n;
        	sector     += n;
        	buf += n * 512;
    	}
done:
	return cb(dd, ret == -1 ? -1 : 0, sector, nb_sectors, id, private);
}
 		
static int tdvmdk_submit(struct disk_driver *dd)
{
	return 0;	
}

static int tdvmdk_close(struct disk_driver *dd)
{
	struct tdvmdk_state *prv = (struct tdvmdk_state *)dd->private;
	
    	safer_free(prv->l1_table);
    	safer_free(prv->l1_backup_table);
    	safer_free(prv->l2_cache);
    	close(prv->fd);
	close(prv->poll_pipe[0]);
	close(prv->poll_pipe[1]);
	return 0;
}

static int tdvmdk_do_callbacks(struct disk_driver *dd, int sid)
{
	/* always ask for a kick */
	return 1;
}

static int tdvmdk_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	return TD_NO_PARENT;
}

static int tdvmdk_validate_parent(struct disk_driver *dd, 
				  struct disk_driver *parent, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_vmdk = {
	.disk_type           = "tapdisk_vmdk",
	.private_data_size   = sizeof(struct tdvmdk_state),
	.td_open             = tdvmdk_open,
	.td_queue_read       = tdvmdk_queue_read,
	.td_queue_write      = tdvmdk_queue_write,
	.td_submit           = tdvmdk_submit,
	.td_close            = tdvmdk_close,
	.td_do_callbacks     = tdvmdk_do_callbacks,
	.td_get_parent_id    = tdvmdk_get_parent_id,
	.td_validate_parent  = tdvmdk_validate_parent
};
