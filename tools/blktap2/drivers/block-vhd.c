/* 
 * Copyright (c) 2008, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * A note on write transactions:
 * Writes that require updating the BAT or bitmaps cannot be signaled
 * as complete until all updates have reached disk.  Transactions are
 * used to ensure proper ordering in these cases.  The two types of
 * transactions are as follows:
 *   - Bitmap updates only: data writes that require updates to the same
 *     bitmap are grouped in a transaction.  Only after all data writes
 *     in a transaction complete does the bitmap write commence.  Only
 *     after the bitmap write finishes are the data writes signalled as
 *     complete.
 *   - BAT and bitmap updates: data writes are grouped in transactions
 *     as above, but a special extra write is included in the transaction,
 *     which zeros out the newly allocated bitmap on disk.  When the data
 *     writes and the zero-bitmap write complete, the BAT and bitmap writes
 *     are started in parallel.  The transaction is completed only after both
 *     the BAT and bitmap writes successfully return.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>    /* for memset.                                 */
#include <libaio.h>
#include <sys/mman.h>

#include "libvhd.h"
#include "tapdisk.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-disktype.h"

unsigned int SPB;

#define DEBUGGING   2
#define ASSERTING   1
#define MICROSOFT_COMPAT

#define VHD_BATMAP_MAX_RETRIES 10

#define __TRACE(s)							\
	do {								\
		DBG(TLOG_DBG, "%s: QUEUED: %" PRIu64 ", COMPLETED: %"	\
		    PRIu64", RETURNED: %" PRIu64 ", DATA_ALLOCATED: "	\
		    "%lu, BBLK: 0x%04x\n",				\
		    s->vhd.file, s->queued, s->completed, s->returned,	\
		    VHD_REQS_DATA - s->vreq_free_count,			\
		    s->bat.pbw_blk);					\
	} while(0)

#define __ASSERT(_p)							\
	if (!(_p)) {							\
		DPRINTF("%s:%d: FAILED ASSERTION: '%s'\n",		\
			__FILE__, __LINE__, #_p);			\
		DBG(TLOG_WARN, "%s:%d: FAILED ASSERTION: '%s'\n",	\
		    __FILE__, __LINE__, #_p);				\
		tlog_flush();						\
		abort();                                                \
	}

#if (DEBUGGING == 1)
  #define DBG(level, _f, _a...)      DPRINTF(_f, ##_a)
  #define ERR(err, _f, _a...)        DPRINTF("ERROR: %d: " _f, err, ##_a)
  #define TRACE(s)                   ((void)0)
#elif (DEBUGGING == 2)
  #define DBG(level, _f, _a...)      tlog_write(level, _f, ##_a)
  #define ERR(err, _f, _a...)	     tlog_error(err, _f, ##_a)
  #define TRACE(s)                   __TRACE(s)
#else
  #define DBG(level, _f, _a...)      ((void)0)
  #define ERR(err, _f, _a...)        ((void)0)
  #define TRACE(s)                   ((void)0)
#endif

#if (ASSERTING == 1)
  #define ASSERT(_p)                 __ASSERT(_p)
#else
  #define ASSERT(_p)                 ((void)0)
#endif

/******VHD DEFINES******/
#define VHD_CACHE_SIZE               32

#define VHD_REQS_DATA                TAPDISK_DATA_REQUESTS
#define VHD_REQS_META                (VHD_CACHE_SIZE + 2)
#define VHD_REQS_TOTAL               (VHD_REQS_DATA + VHD_REQS_META)

#define VHD_OP_BAT_WRITE             0
#define VHD_OP_DATA_READ             1
#define VHD_OP_DATA_WRITE            2
#define VHD_OP_BITMAP_READ           3
#define VHD_OP_BITMAP_WRITE          4
#define VHD_OP_ZERO_BM_WRITE         5

#define VHD_BM_BAT_LOCKED            0
#define VHD_BM_BAT_CLEAR             1
#define VHD_BM_BIT_CLEAR             2
#define VHD_BM_BIT_SET               3
#define VHD_BM_NOT_CACHED            4
#define VHD_BM_READ_PENDING          5

#define VHD_FLAG_OPEN_RDONLY         1
#define VHD_FLAG_OPEN_NO_CACHE       2
#define VHD_FLAG_OPEN_QUIET          4
#define VHD_FLAG_OPEN_STRICT         8
#define VHD_FLAG_OPEN_QUERY          16
#define VHD_FLAG_OPEN_PREALLOCATE    32

#define VHD_FLAG_BAT_LOCKED          1
#define VHD_FLAG_BAT_WRITE_STARTED   2

#define VHD_FLAG_BM_UPDATE_BAT       1
#define VHD_FLAG_BM_WRITE_PENDING    2
#define VHD_FLAG_BM_READ_PENDING     4
#define VHD_FLAG_BM_LOCKED           8

#define VHD_FLAG_REQ_UPDATE_BAT      1
#define VHD_FLAG_REQ_UPDATE_BITMAP   2
#define VHD_FLAG_REQ_QUEUED          4
#define VHD_FLAG_REQ_FINISHED        8

#define VHD_FLAG_TX_LIVE             1
#define VHD_FLAG_TX_UPDATE_BAT       2

typedef uint8_t vhd_flag_t;

struct vhd_state;
struct vhd_request;

struct vhd_req_list {
	struct vhd_request       *head;
	struct vhd_request       *tail;
};

struct vhd_transaction {
	int                       error;
	int                       closed;
	int                       started;
	int                       finished;
	vhd_flag_t                status;
	struct vhd_req_list       requests;
};

struct vhd_request {
	int                       error;
	uint8_t                   op;
	vhd_flag_t                flags;
	td_request_t              treq;
	struct tiocb              tiocb;
	struct vhd_state         *state;
	struct vhd_request       *next;
	struct vhd_transaction   *tx;
};

struct vhd_bat_state {
	vhd_bat_t                 bat;
	vhd_batmap_t              batmap;
	vhd_flag_t                status;
	uint32_t                  pbw_blk;     /* blk num of pending write */
	uint64_t                  pbw_offset;  /* file offset of same */
	struct vhd_request        req;         /* for writing bat table */
	struct vhd_request        zero_req;    /* for initializing bitmaps */
	char                     *bat_buf;
};

struct vhd_bitmap {
	u32                       blk;
	u64                       seqno;       /* lru sequence number */
	vhd_flag_t                status;

	char                     *map;         /* map should only be modified
					        * in finish_bitmap_write */
	char                     *shadow;      /* in-memory bitmap changes are 
					        * made to shadow and copied to
					        * map only after having been
					        * flushed to disk */
	struct vhd_transaction    tx;          /* transaction data structure
						* encapsulating data, bitmap, 
						* and bat writes */
	struct vhd_req_list       queue;       /* data writes waiting for next
						* transaction */
	struct vhd_req_list       waiting;     /* pending requests that cannot
					        * be serviced until this bitmap
					        * is read from disk */
	struct vhd_request        req;
};

struct vhd_state {
	vhd_flag_t                flags;

        /* VHD stuff */
	vhd_context_t             vhd;
	u32                       spp;         /* sectors per page */
        u32                       spb;         /* sectors per block */
        u64                       next_db;     /* pointer to the next 
						* (unallocated) datablock */

	struct vhd_bat_state      bat;

	u64                       bm_lru;      /* lru sequence number */
	u32                       bm_secs;     /* size of bitmap, in sectors */
	struct vhd_bitmap        *bitmap[VHD_CACHE_SIZE];

	int                       bm_free_count;
	struct vhd_bitmap        *bitmap_free[VHD_CACHE_SIZE];
	struct vhd_bitmap         bitmap_list[VHD_CACHE_SIZE];

	int                       vreq_free_count;
	struct vhd_request       *vreq_free[VHD_REQS_DATA];
	struct vhd_request        vreq_list[VHD_REQS_DATA];

	td_driver_t              *driver;

	uint64_t                  queued;
	uint64_t                  completed;
	uint64_t                  returned;
	uint64_t                  reads;
	uint64_t                  read_size;
	uint64_t                  writes;
	uint64_t                  write_size;
};

#define test_vhd_flag(word, flag)  ((word) & (flag))
#define set_vhd_flag(word, flag)   ((word) |= (flag))
#define clear_vhd_flag(word, flag) ((word) &= ~(flag))

#define bat_entry(s, blk)          ((s)->bat.bat.bat[(blk)])

static void vhd_complete(void *, struct tiocb *, int);
static void finish_data_transaction(struct vhd_state *, struct vhd_bitmap *);

static struct vhd_state  *_vhd_master;
static unsigned long      _vhd_zsize;
static char              *_vhd_zeros;

static int
vhd_initialize(struct vhd_state *s)
{
	if (_vhd_zeros)
		return 0;

	_vhd_zsize = 2 * getpagesize();
	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_PREALLOCATE))
		_vhd_zsize += VHD_BLOCK_SIZE;

	_vhd_zeros = mmap(0, _vhd_zsize, PROT_READ,
			  MAP_SHARED | MAP_ANON, -1, 0);
	if (_vhd_zeros == MAP_FAILED) {
		EPRINTF("vhd_initialize failed: %d\n", -errno);
		_vhd_zeros = NULL;
		_vhd_zsize = 0;
		return -errno;
	}

	_vhd_master = s;
	return 0;
}

static void
vhd_free(struct vhd_state *s)
{
	if (_vhd_master != s || !_vhd_zeros)
		return;

	munmap(_vhd_zeros, _vhd_zsize);
	_vhd_zsize  = 0;
	_vhd_zeros  = NULL;
	_vhd_master = NULL;
}

static char *
_get_vhd_zeros(const char *func, unsigned long size)
{
	if (!_vhd_zeros || _vhd_zsize < size) {
		EPRINTF("invalid zero request from %s: %lu, %lu, %p\n",
			func, size, _vhd_zsize, _vhd_zeros);
		ASSERT(0);
	}

	return _vhd_zeros;
}

#define vhd_zeros(size)	_get_vhd_zeros(__func__, size)

static inline void
set_batmap(struct vhd_state *s, uint32_t blk)
{
	if (s->bat.batmap.map) {
		vhd_batmap_set(&s->vhd, &s->bat.batmap, blk);
		DBG(TLOG_DBG, "block 0x%x completely full\n", blk);
	}
}

static inline int
test_batmap(struct vhd_state *s, uint32_t blk)
{
	if (!s->bat.batmap.map)
		return 0;
	return vhd_batmap_test(&s->vhd, &s->bat.batmap, blk);
}

static int
vhd_kill_footer(struct vhd_state *s)
{
	int err;
	off_t end;
	char *zeros;

	if (s->vhd.footer.type == HD_TYPE_FIXED)
		return 0;

	err = posix_memalign((void **)&zeros, 512, 512);
	if (err)
		return -err;

	err = 1;
	memset(zeros, 0xc7c7c7c7, 512);

	if ((end = lseek(s->vhd.fd, 0, SEEK_END)) == -1)
		goto fail;

	if (lseek(s->vhd.fd, (end - 512), SEEK_SET) == -1)
		goto fail;

	if (write(s->vhd.fd, zeros, 512) != 512)
		goto fail;

	err = 0;

 fail:
	free(zeros);
	if (err)
		return (errno ? -errno : -EIO);
	return 0;
}

static inline int
find_next_free_block(struct vhd_state *s)
{
	int err;
	off_t eom;
	uint32_t i, entry;

	err = vhd_end_of_headers(&s->vhd, &eom);
	if (err)
		return err;

	s->next_db = secs_round_up(eom);

	for (i = 0; i < s->bat.bat.entries; i++) {
		entry = bat_entry(s, i);
		if (entry != DD_BLK_UNUSED && entry >= s->next_db)
			s->next_db = entry + s->spb + s->bm_secs;
	}

	return 0;
}

static void
vhd_free_bat(struct vhd_state *s)
{
	free(s->bat.bat.bat);
	free(s->bat.batmap.map);
	free(s->bat.bat_buf);
	memset(&s->bat, 0, sizeof(struct vhd_bat));
}

static int
vhd_initialize_bat(struct vhd_state *s)
{
	int err, psize, batmap_required, i;

	memset(&s->bat, 0, sizeof(struct vhd_bat));

	psize = getpagesize();

	err = vhd_read_bat(&s->vhd, &s->bat.bat);
	if (err) {
		EPRINTF("%s: reading bat: %d\n", s->vhd.file, err);
		return err;
	}

	batmap_required = 1;
	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_RDONLY)) {
		batmap_required = 0;
	} else {
		err = find_next_free_block(s);
		if (err)
			goto fail;
	}

	if (vhd_has_batmap(&s->vhd)) {
		for (i = 0; i < VHD_BATMAP_MAX_RETRIES; i++) {
			err = vhd_read_batmap(&s->vhd, &s->bat.batmap);
			if (err) {
				EPRINTF("%s: reading batmap: %d\n",
						s->vhd.file, err);
				if (batmap_required)
					goto fail;
			} else {
				break;
			}
		}
		if (err)
			EPRINTF("%s: ignoring non-critical batmap error\n",
					s->vhd.file);
	}

	err = posix_memalign((void **)&s->bat.bat_buf,
			     VHD_SECTOR_SIZE, VHD_SECTOR_SIZE);
	if (err) {
		s->bat.bat_buf = NULL;
		goto fail;
	}

	return 0;

fail:
	vhd_free_bat(s);
	return err;
}

static void
vhd_free_bitmap_cache(struct vhd_state *s)
{
	int i;
	struct vhd_bitmap *bm;

	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		bm = s->bitmap_list + i;
		free(bm->map);
		free(bm->shadow);
		s->bitmap_free[i] = NULL;
	}

	memset(s->bitmap_list, 0, sizeof(struct vhd_bitmap) * VHD_CACHE_SIZE);
}

static int
vhd_initialize_bitmap_cache(struct vhd_state *s)
{
	int i, err, map_size;
	struct vhd_bitmap *bm;

	memset(s->bitmap_list, 0, sizeof(struct vhd_bitmap) * VHD_CACHE_SIZE);

	s->bm_lru        = 0;
	map_size         = vhd_sectors_to_bytes(s->bm_secs);
	s->bm_free_count = VHD_CACHE_SIZE;

	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		bm = s->bitmap_list + i;

		err = posix_memalign((void **)&bm->map, 512, map_size);
		if (err) {
			bm->map = NULL;
			goto fail;
		}

		err = posix_memalign((void **)&bm->shadow, 512, map_size);
		if (err) {
			bm->shadow = NULL;
			goto fail;
		}

		memset(bm->map, 0, map_size);
		memset(bm->shadow, 0, map_size);
		s->bitmap_free[i] = bm;
	}

	return 0;

fail:
	vhd_free_bitmap_cache(s);
	return err;
}

static int
vhd_initialize_dynamic_disk(struct vhd_state *s)
{
	int err;

	err = vhd_get_header(&s->vhd);
	if (err) {
		if (!test_vhd_flag(s->flags, VHD_FLAG_OPEN_QUIET))
			EPRINTF("Error reading VHD DD header.\n");
		return err;
	}

	if (s->vhd.header.hdr_ver != 0x00010000) {
		EPRINTF("unsupported header version! (0x%x)\n",
			s->vhd.header.hdr_ver);
		return -EINVAL;
	}

	s->spp     = getpagesize() >> VHD_SECTOR_SHIFT;
	s->spb     = s->vhd.header.block_size >> VHD_SECTOR_SHIFT;
	s->bm_secs = secs_round_up_no_zero(s->spb >> 3);

	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_NO_CACHE))
		return 0;

	err = vhd_initialize_bat(s);
	if (err)
		return err;

	err = vhd_initialize_bitmap_cache(s);
	if (err) {
		vhd_free_bat(s);
		return err;
	}

	return 0;
}

static int
vhd_check_version(struct vhd_state *s)
{
	if (strncmp(s->vhd.footer.crtr_app, "tap", 3))
		return 0;

	if (s->vhd.footer.crtr_ver > VHD_CURRENT_VERSION) {
		if (!test_vhd_flag(s->flags, VHD_FLAG_OPEN_QUIET))
			EPRINTF("WARNING: %s vhd creator version 0x%08x, "
				"but only versions up to 0x%08x are "
				"supported for IO\n", s->vhd.file,
				s->vhd.footer.crtr_ver, VHD_CURRENT_VERSION);

		return -EINVAL;
	}

	return 0;
}

static void
vhd_log_open(struct vhd_state *s)
{
	char buf[5];
	uint32_t i, allocated, full;

	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_QUIET))
		return;

	snprintf(buf, sizeof(buf), "%s", s->vhd.footer.crtr_app);
	if (!vhd_type_dynamic(&s->vhd)) {
		DPRINTF("%s version: %s 0x%08x\n",
			s->vhd.file, buf, s->vhd.footer.crtr_ver);
		return;
	}

	allocated = 0;
	full      = 0;

	for (i = 0; i < s->bat.bat.entries; i++) {
		if (bat_entry(s, i) != DD_BLK_UNUSED)
			allocated++;
		if (test_batmap(s, i))
			full++;
	}

	DPRINTF("%s version: %s 0x%08x, b: %u, a: %u, f: %u, n: %"PRIu64"\n",
		s->vhd.file, buf, s->vhd.footer.crtr_ver, s->bat.bat.entries,
		allocated, full, s->next_db);
}

static int
__vhd_open(td_driver_t *driver, const char *name, vhd_flag_t flags)
{
        int i, o_flags, err;
	struct vhd_state *s;

        DBG(TLOG_INFO, "vhd_open: %s\n", name);
	if (test_vhd_flag(flags, VHD_FLAG_OPEN_STRICT))
		libvhd_set_log_level(1);

	s = (struct vhd_state *)driver->data;
	memset(s, 0, sizeof(struct vhd_state));

	s->flags  = flags;
	s->driver = driver;

	err = vhd_initialize(s);
	if (err)
		return err;

	o_flags = ((test_vhd_flag(flags, VHD_FLAG_OPEN_RDONLY)) ? 
		   VHD_OPEN_RDONLY : VHD_OPEN_RDWR);

	err = vhd_open(&s->vhd, name, o_flags);
	if (err) {
		libvhd_set_log_level(1);
		err = vhd_open(&s->vhd, name, o_flags);
		if (err) {
			EPRINTF("Unable to open [%s] (%d)!\n", name, err);
			return err;
		}
	}

	err = vhd_check_version(s);
	if (err)
		goto fail;

	s->spb = s->spp = 1;

	if (vhd_type_dynamic(&s->vhd)) {
		err = vhd_initialize_dynamic_disk(s);
		if (err)
			goto fail;
	}

	vhd_log_open(s);

	SPB = s->spb;

	s->vreq_free_count = VHD_REQS_DATA;
	for (i = 0; i < VHD_REQS_DATA; i++)
		s->vreq_free[i] = s->vreq_list + i;

	driver->info.size        = s->vhd.footer.curr_size >> VHD_SECTOR_SHIFT;
	driver->info.sector_size = VHD_SECTOR_SIZE;
	driver->info.info        = 0;

        DBG(TLOG_INFO, "vhd_open: done (sz:%"PRIu64", sct:%"PRIu64
            ", inf:%u)\n",
	    driver->info.size, driver->info.sector_size, driver->info.info);

	if (test_vhd_flag(flags, VHD_FLAG_OPEN_STRICT) && 
	    !test_vhd_flag(flags, VHD_FLAG_OPEN_RDONLY)) {
		err = vhd_kill_footer(s);
		if (err) {
			DPRINTF("ERROR killing footer: %d\n", err);
			goto fail;
		}
		s->writes++;
	}

        return 0;

 fail:
	vhd_free_bat(s);
	vhd_free_bitmap_cache(s);
	vhd_close(&s->vhd);
	vhd_free(s);
	return err;
}

static int
_vhd_open(td_driver_t *driver, const char *name, td_flag_t flags)
{
	vhd_flag_t vhd_flags = 0;

	if (flags & TD_OPEN_RDONLY)
		vhd_flags |= VHD_FLAG_OPEN_RDONLY;
	if (flags & TD_OPEN_QUIET)
		vhd_flags |= VHD_FLAG_OPEN_QUIET;
	if (flags & TD_OPEN_STRICT)
		vhd_flags |= VHD_FLAG_OPEN_STRICT;
	if (flags & TD_OPEN_QUERY)
		vhd_flags |= (VHD_FLAG_OPEN_QUERY  |
			      VHD_FLAG_OPEN_QUIET  |
			      VHD_FLAG_OPEN_RDONLY |
			      VHD_FLAG_OPEN_NO_CACHE);

	/* pre-allocate for all but NFS and LVM storage */
	if (driver->storage != TAPDISK_STORAGE_TYPE_NFS &&
	    driver->storage != TAPDISK_STORAGE_TYPE_LVM)
		vhd_flags |= VHD_FLAG_OPEN_PREALLOCATE;

	return __vhd_open(driver, name, vhd_flags);
}

static void
vhd_log_close(struct vhd_state *s)
{
	uint32_t i, allocated, full;

	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_QUIET))
		return;

	allocated = 0;
	full      = 0;

	for (i = 0; i < s->bat.bat.entries; i++) {
		if (bat_entry(s, i) != DD_BLK_UNUSED)
			allocated++;
		if (test_batmap(s, i))
			full++;
	}

	DPRINTF("%s: b: %u, a: %u, f: %u, n: %"PRIu64"\n",
		s->vhd.file, s->bat.bat.entries, allocated, full, s->next_db);
}

static int
_vhd_close(td_driver_t *driver)
{
	int err;
	struct vhd_state *s;
	struct vhd_bitmap *bm;
	
	DBG(TLOG_WARN, "vhd_close\n");
	s = (struct vhd_state *)driver->data;

	/* don't write footer if tapdisk is read-only */
	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_RDONLY))
		goto free;
	
	/* 
	 * write footer if:
	 *   - we killed it on open (opened with strict) 
	 *   - we've written data since opening
	 */
	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_STRICT) || s->writes) {
		memcpy(&s->vhd.bat, &s->bat.bat, sizeof(vhd_bat_t));
		err = vhd_write_footer(&s->vhd, &s->vhd.footer);
		memset(&s->vhd.bat, 0, sizeof(vhd_bat_t));

		if (err)
			EPRINTF("writing %s footer: %d\n", s->vhd.file, err);

		if (!vhd_has_batmap(&s->vhd))
			goto free;

		err = vhd_write_batmap(&s->vhd, &s->bat.batmap);
		if (err)
			EPRINTF("writing %s batmap: %d\n", s->vhd.file, err);
	}

 free:
	vhd_log_close(s);
	vhd_free_bat(s);
	vhd_free_bitmap_cache(s);
	vhd_close(&s->vhd);
	vhd_free(s);

	memset(s, 0, sizeof(struct vhd_state));

	return 0;
}

int
vhd_validate_parent(td_driver_t *child_driver,
		    td_driver_t *parent_driver, td_flag_t flags)
{
	uint32_t status;
	struct stat stats;
	struct vhd_state *child  = (struct vhd_state *)child_driver->data;
	struct vhd_state *parent;

	if (parent_driver->type != DISK_TYPE_VHD) {
		if (child_driver->type != DISK_TYPE_VHD)
			return -EINVAL;
		if (child->vhd.footer.type != HD_TYPE_DIFF)
			return -EINVAL;
		if (!vhd_parent_raw(&child->vhd))
			return -EINVAL;
		return 0;
	}

	parent = (struct vhd_state *)parent_driver->data;

	/* 
	 * This check removed because of cases like:
	 *   - parent VHD marked as 'hidden'
	 *   - parent VHD modified during coalesce
	 */
	/*
	if (stat(parent->vhd.file, &stats)) {
		DPRINTF("ERROR stating parent file %s\n", parent->vhd.file);
		return -errno;
	}

	if (child->hdr.prt_ts != vhd_time(stats.st_mtime)) {
		DPRINTF("ERROR: parent file has been modified since "
			"snapshot.  Child image no longer valid.\n");
		return -EINVAL;
	}
	*/

	if (vhd_uuid_compare(&child->vhd.header.prt_uuid, &parent->vhd.footer.uuid)) {
		DPRINTF("ERROR: %s: %s, %s: parent uuid has changed since "
			"snapshot.  Child image no longer valid.\n",
			__func__, child->vhd.file, parent->vhd.file);
		return -EINVAL;
	}

	/* TODO: compare sizes */
	
	return 0;
}

int
vhd_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	int err;
	char *parent;
	struct vhd_state *s;

	DBG(TLOG_DBG, "\n");
	memset(id, 0, sizeof(td_disk_id_t));

	s = (struct vhd_state *)driver->data;

	if (s->vhd.footer.type != HD_TYPE_DIFF)
		return TD_NO_PARENT;

	err = vhd_parent_locator_get(&s->vhd, &parent);
	if (err)
		return err;

	id->name       = parent;
	id->drivertype = DISK_TYPE_VHD;
	if (vhd_parent_raw(&s->vhd)) {
		DPRINTF("VHD: parent is raw\n");
		id->drivertype = DISK_TYPE_AIO;
	}
	return 0;
}

static inline void
clear_req_list(struct vhd_req_list *list)
{
	list->head = list->tail = NULL;
}

static inline void
add_to_tail(struct vhd_req_list *list, struct vhd_request *e)
{
	if (!list->head) 
		list->head = list->tail = e;
	else 
		list->tail = list->tail->next = e;
}

static inline int
remove_from_req_list(struct vhd_req_list *list, struct vhd_request *e)
{
	struct vhd_request *i = list->head;

	if (list->head == e) {
		if (list->tail == e)
			clear_req_list(list);
		else
			list->head = list->head->next;
		return 0;
	}

	while (i->next) {
		if (i->next == e) {
			if (list->tail == e) {
				i->next = NULL;
				list->tail = i;
			} else
				i->next = i->next->next;
			return 0;
		}
		i = i->next;
	}

	return -EINVAL;
}

static inline void
init_vhd_request(struct vhd_state *s, struct vhd_request *req)
{
	memset(req, 0, sizeof(struct vhd_request));
	req->state = s;
}

static inline void
init_tx(struct vhd_transaction *tx)
{
	memset(tx, 0, sizeof(struct vhd_transaction));
}

static inline void
add_to_transaction(struct vhd_transaction *tx, struct vhd_request *r)
{
	ASSERT(!tx->closed);

	r->tx = tx;
	tx->started++;
	add_to_tail(&tx->requests, r);
	set_vhd_flag(tx->status, VHD_FLAG_TX_LIVE);

	DBG(TLOG_DBG, "blk: 0x%04"PRIx64", lsec: 0x%08"PRIx64", tx: %p, "
	    "started: %d, finished: %d, status: %u\n",
	    r->treq.sec / SPB, r->treq.sec, tx,
	    tx->started, tx->finished, tx->status);
}

static inline int
transaction_completed(struct vhd_transaction *tx)
{
	return (tx->started == tx->finished);
}

static inline void
init_bat(struct vhd_state *s)
{
	s->bat.req.tx     = NULL;
	s->bat.req.next   = NULL;
	s->bat.req.error  = 0;
	s->bat.pbw_blk    = 0;
	s->bat.pbw_offset = 0;
	s->bat.status     = 0;
}

static inline void
lock_bat(struct vhd_state *s)
{
	set_vhd_flag(s->bat.status, VHD_FLAG_BAT_LOCKED);
}

static inline void
unlock_bat(struct vhd_state *s)
{
	clear_vhd_flag(s->bat.status, VHD_FLAG_BAT_LOCKED);
}

static inline int
bat_locked(struct vhd_state *s)
{
	return test_vhd_flag(s->bat.status, VHD_FLAG_BAT_LOCKED);
}

static inline void
init_vhd_bitmap(struct vhd_state *s, struct vhd_bitmap *bm)
{
	bm->blk    = 0;
	bm->seqno  = 0;
	bm->status = 0;
	init_tx(&bm->tx);
	clear_req_list(&bm->queue);
	clear_req_list(&bm->waiting);
	memset(bm->map, 0, vhd_sectors_to_bytes(s->bm_secs));
	memset(bm->shadow, 0, vhd_sectors_to_bytes(s->bm_secs));
	init_vhd_request(s, &bm->req);
}

static inline struct vhd_bitmap *
get_bitmap(struct vhd_state *s, uint32_t block)
{
	int i;
	struct vhd_bitmap *bm;

	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		bm = s->bitmap[i];
		if (bm && bm->blk == block)
			return bm;
	}

	return NULL;
}

static inline void
lock_bitmap(struct vhd_bitmap *bm)
{
	set_vhd_flag(bm->status, VHD_FLAG_BM_LOCKED);
}

static inline void
unlock_bitmap(struct vhd_bitmap *bm)
{
	clear_vhd_flag(bm->status, VHD_FLAG_BM_LOCKED);
}

static inline int
bitmap_locked(struct vhd_bitmap *bm)
{
	return test_vhd_flag(bm->status, VHD_FLAG_BM_LOCKED);
}

static inline int
bitmap_valid(struct vhd_bitmap *bm)
{
	return !test_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING);
}

static inline int
bitmap_in_use(struct vhd_bitmap *bm)
{
	return (test_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING)  ||
		test_vhd_flag(bm->status, VHD_FLAG_BM_WRITE_PENDING) ||
		test_vhd_flag(bm->tx.status, VHD_FLAG_TX_UPDATE_BAT) ||
		bm->waiting.head || bm->tx.requests.head || bm->queue.head);
}

static inline int
bitmap_full(struct vhd_state *s, struct vhd_bitmap *bm)
{
	int i, n;

	n = s->spb >> 3;
	for (i = 0; i < n; i++)
		if (bm->map[i] != (char)0xFF)
			return 0;

	DBG(TLOG_DBG, "bitmap 0x%04x full\n", bm->blk);
	return 1;
}

static struct vhd_bitmap *
remove_lru_bitmap(struct vhd_state *s)
{
	int i, idx = 0;
	u64 seq = s->bm_lru;
	struct vhd_bitmap *bm, *lru = NULL;

	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		bm = s->bitmap[i];
		if (bm && bm->seqno < seq && !bitmap_locked(bm)) {
			idx = i;
			lru = bm;
			seq = lru->seqno;
		}
	}

	if (lru) {
		s->bitmap[idx] = NULL;
		ASSERT(!bitmap_in_use(lru));
	}

	return  lru;
}

static int
alloc_vhd_bitmap(struct vhd_state *s, struct vhd_bitmap **bitmap, uint32_t blk)
{
	struct vhd_bitmap *bm;
	
	*bitmap = NULL;

	if (s->bm_free_count > 0) {
		bm = s->bitmap_free[--s->bm_free_count];
	} else {
		bm = remove_lru_bitmap(s);
		if (!bm)
			return -EBUSY;
	}

	init_vhd_bitmap(s, bm);
	bm->blk = blk;
	*bitmap = bm;

	return 0;
}

static inline uint64_t
__bitmap_lru_seqno(struct vhd_state *s)
{
	int i;
	struct vhd_bitmap *bm;

	if (s->bm_lru == 0xffffffff) {
		s->bm_lru = 0;
		for (i = 0; i < VHD_CACHE_SIZE; i++) {
			bm = s->bitmap[i];
			if (bm) {
				bm->seqno >>= 1;
				if (bm->seqno > s->bm_lru)
					s->bm_lru = bm->seqno;
			}
		}
	}

	return ++s->bm_lru;
}

static inline void
touch_bitmap(struct vhd_state *s, struct vhd_bitmap *bm)
{
	bm->seqno = __bitmap_lru_seqno(s);
}

static inline void
install_bitmap(struct vhd_state *s, struct vhd_bitmap *bm)
{
	int i;
	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		if (!s->bitmap[i]) {
			touch_bitmap(s, bm);
			s->bitmap[i] = bm;
			return;
		}
	}

	ASSERT(0);
}

static inline void
free_vhd_bitmap(struct vhd_state *s, struct vhd_bitmap *bm)
{
	int i;

	for (i = 0; i < VHD_CACHE_SIZE; i++)
		if (s->bitmap[i] == bm)
			break;

	ASSERT(!bitmap_locked(bm));
	ASSERT(!bitmap_in_use(bm));
	ASSERT(i < VHD_CACHE_SIZE);

	s->bitmap[i] = NULL;
	s->bitmap_free[s->bm_free_count++] = bm;
}

static int
read_bitmap_cache(struct vhd_state *s, uint64_t sector, uint8_t op)
{
	u32 blk, sec;
	struct vhd_bitmap *bm;

	/* in fixed disks, every block is present */
	if (s->vhd.footer.type == HD_TYPE_FIXED) 
		return VHD_BM_BIT_SET;

	blk = sector / s->spb;
	sec = sector % s->spb;

	if (blk > s->vhd.header.max_bat_size) {
		DPRINTF("ERROR: sec %"PRIu64" out of range, op = %d\n",
			sector, op);
		return -EINVAL;
	}

	if (bat_entry(s, blk) == DD_BLK_UNUSED) {
		if (op == VHD_OP_DATA_WRITE &&
		    s->bat.pbw_blk != blk && bat_locked(s))
			return VHD_BM_BAT_LOCKED;

		return VHD_BM_BAT_CLEAR;
	}

	if (test_batmap(s, blk)) {
		DBG(TLOG_DBG, "batmap set for 0x%04x\n", blk);
		return VHD_BM_BIT_SET;
	}

	bm = get_bitmap(s, blk);
	if (!bm)
		return VHD_BM_NOT_CACHED;

	/* bump lru count */
	touch_bitmap(s, bm);

	if (test_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING))
		return VHD_BM_READ_PENDING;

	return ((vhd_bitmap_test(&s->vhd, bm->map, sec)) ? 
		VHD_BM_BIT_SET : VHD_BM_BIT_CLEAR);
}

static int
read_bitmap_cache_span(struct vhd_state *s, 
		       uint64_t sector, int nr_secs, int value)
{
	int ret;
	u32 blk, sec;
	struct vhd_bitmap *bm;

	/* in fixed disks, every block is present */
	if (s->vhd.footer.type == HD_TYPE_FIXED) 
		return nr_secs;

	sec = sector % s->spb;
	blk = sector / s->spb;

	if (test_batmap(s, blk))
		return MIN(nr_secs, s->spb - sec);

	bm  = get_bitmap(s, blk);
	
	ASSERT(bm && bitmap_valid(bm));

	for (ret = 0; sec < s->spb && ret < nr_secs; sec++, ret++)
		if (vhd_bitmap_test(&s->vhd, bm->map, sec) != value)
			break;

	return ret;
}

static inline struct vhd_request *
alloc_vhd_request(struct vhd_state *s)
{
	struct vhd_request *req = NULL;
	
	if (s->vreq_free_count > 0) {
		req = s->vreq_free[--s->vreq_free_count];
		ASSERT(req->treq.secs == 0);
		init_vhd_request(s, req);
		return req;
	}

	return NULL;
}

static inline void
free_vhd_request(struct vhd_state *s, struct vhd_request *req)
{
	memset(req, 0, sizeof(struct vhd_request));
	s->vreq_free[s->vreq_free_count++] = req;
}

static inline void
aio_read(struct vhd_state *s, struct vhd_request *req, uint64_t offset)
{
	struct tiocb *tiocb = &req->tiocb;

	td_prep_read(tiocb, s->vhd.fd, req->treq.buf,
		     vhd_sectors_to_bytes(req->treq.secs),
		     offset, vhd_complete, req);
	td_queue_tiocb(s->driver, tiocb);

	s->queued++;
	s->reads++;
	s->read_size += req->treq.secs;
	TRACE(s);
}

static inline void
aio_write(struct vhd_state *s, struct vhd_request *req, uint64_t offset)
{
	struct tiocb *tiocb = &req->tiocb;

	td_prep_write(tiocb, s->vhd.fd, req->treq.buf,
		      vhd_sectors_to_bytes(req->treq.secs),
		      offset, vhd_complete, req);
	td_queue_tiocb(s->driver, tiocb);

	s->queued++;
	s->writes++;
	s->write_size += req->treq.secs;
	TRACE(s);
}

static inline uint64_t
reserve_new_block(struct vhd_state *s, uint32_t blk)
{
	int gap = 0;

	ASSERT(!test_vhd_flag(s->bat.status, VHD_FLAG_BAT_WRITE_STARTED));

	/* data region of segment should begin on page boundary */
	if ((s->next_db + s->bm_secs) % s->spp)
		gap = (s->spp - ((s->next_db + s->bm_secs) % s->spp));

	s->bat.pbw_blk    = blk;
	s->bat.pbw_offset = s->next_db + gap;

	return s->next_db;
}

static int
schedule_bat_write(struct vhd_state *s)
{
	int i;
	u32 blk;
	char *buf;
	u64 offset;
	struct vhd_request *req;

	ASSERT(bat_locked(s));

	req = &s->bat.req;
	buf = s->bat.bat_buf;
	blk = s->bat.pbw_blk;

	init_vhd_request(s, req);
	memcpy(buf, &bat_entry(s, blk - (blk % 128)), 512);

	((u32 *)buf)[blk % 128] = s->bat.pbw_offset;

	for (i = 0; i < 128; i++)
		BE32_OUT(&((u32 *)buf)[i]);

	offset         = s->vhd.header.table_offset + (blk - (blk % 128)) * 4;
	req->treq.secs = 1;
	req->treq.buf  = buf;
	req->op        = VHD_OP_BAT_WRITE;
	req->next      = NULL;

	aio_write(s, req, offset);
	set_vhd_flag(s->bat.status, VHD_FLAG_BAT_WRITE_STARTED);

	DBG(TLOG_DBG, "blk: 0x%04x, pbwo: 0x%08"PRIx64", "
	    "table_offset: 0x%08"PRIx64"\n", blk, s->bat.pbw_offset, offset);

	return 0;
}

static void
schedule_zero_bm_write(struct vhd_state *s,
		       struct vhd_bitmap *bm, uint64_t lb_end)
{
	uint64_t offset;
	struct vhd_request *req = &s->bat.zero_req;

	init_vhd_request(s, req);

	offset         = vhd_sectors_to_bytes(lb_end);
	req->op        = VHD_OP_ZERO_BM_WRITE;
	req->treq.sec  = s->bat.pbw_blk * s->spb;
	req->treq.secs = (s->bat.pbw_offset - lb_end) + s->bm_secs;
	req->treq.buf  = vhd_zeros(vhd_sectors_to_bytes(req->treq.secs));
	req->next      = NULL;

	DBG(TLOG_DBG, "blk: 0x%04x, writing zero bitmap at 0x%08"PRIx64"\n",
	    s->bat.pbw_blk, offset);

	lock_bitmap(bm);
	add_to_transaction(&bm->tx, req);
	aio_write(s, req, offset);
}

static int
update_bat(struct vhd_state *s, uint32_t blk)
{
	int err;
	uint64_t lb_end;
	struct vhd_bitmap *bm;

	ASSERT(bat_entry(s, blk) == DD_BLK_UNUSED);
	
	if (bat_locked(s)) {
		ASSERT(s->bat.pbw_blk == blk);
		return 0;
	}

	/* empty bitmap could already be in
	 * cache if earlier bat update failed */
	bm = get_bitmap(s, blk);
	if (!bm) {
		/* install empty bitmap in cache */
		err = alloc_vhd_bitmap(s, &bm, blk);
		if (err) 
			return err;

		install_bitmap(s, bm);
	}

	lock_bat(s);
	lb_end = reserve_new_block(s, blk);
	schedule_zero_bm_write(s, bm, lb_end);
	set_vhd_flag(bm->tx.status, VHD_FLAG_TX_UPDATE_BAT);

	return 0;
}

static int
allocate_block(struct vhd_state *s, uint32_t blk)
{
	char *zeros;
	int err, gap;
	uint64_t offset, size;
	struct vhd_bitmap *bm;

	ASSERT(bat_entry(s, blk) == DD_BLK_UNUSED);

	if (bat_locked(s)) {
		ASSERT(s->bat.pbw_blk == blk);
		if (s->bat.req.error)
			return -EBUSY;
		return 0;
	}

	gap            = 0;
	s->bat.pbw_blk = blk;
	offset         = vhd_sectors_to_bytes(s->next_db);

	/* data region of segment should begin on page boundary */
	if ((s->next_db + s->bm_secs) % s->spp) {
		gap = (s->spp - ((s->next_db + s->bm_secs) % s->spp));
		s->next_db += gap;
	}

	s->bat.pbw_offset = s->next_db;

	DBG(TLOG_DBG, "blk: 0x%04x, pbwo: 0x%08"PRIx64"\n",
	    blk, s->bat.pbw_offset);

	if (lseek(s->vhd.fd, offset, SEEK_SET) == (off_t)-1) {
		ERR(errno, "lseek failed\n");
		return -errno;
	}

	size = vhd_sectors_to_bytes(s->spb + s->bm_secs + gap);
	err  = write(s->vhd.fd, vhd_zeros(size), size);
	if (err != size) {
		err = (err == -1 ? -errno : -EIO);
		ERR(err, "write failed");
		return err;
	}

	/* empty bitmap could already be in
	 * cache if earlier bat update failed */
	bm = get_bitmap(s, blk);
	if (!bm) {
		/* install empty bitmap in cache */
		err = alloc_vhd_bitmap(s, &bm, blk);
		if (err) 
			return err;

		install_bitmap(s, bm);
	}

	lock_bat(s);
	lock_bitmap(bm);
	schedule_bat_write(s);
	add_to_transaction(&bm->tx, &s->bat.req);

	return 0;
}

static int 
schedule_data_read(struct vhd_state *s, td_request_t treq, vhd_flag_t flags)
{
	u64 offset;
	u32 blk = 0, sec = 0;
	struct vhd_bitmap  *bm;
	struct vhd_request *req;

	if (s->vhd.footer.type == HD_TYPE_FIXED) {
		offset = vhd_sectors_to_bytes(treq.sec);
		goto make_request;
	}

	blk    = treq.sec / s->spb;
	sec    = treq.sec % s->spb;
	bm     = get_bitmap(s, blk);
	offset = bat_entry(s, blk);

	ASSERT(offset != DD_BLK_UNUSED);
	ASSERT(test_batmap(s, blk) || (bm && bitmap_valid(bm)));

	offset += s->bm_secs + sec;
	offset  = vhd_sectors_to_bytes(offset);

 make_request:
	req = alloc_vhd_request(s);
	if (!req) 
		return -EBUSY;

	req->treq  = treq;
	req->flags = flags;
	req->op    = VHD_OP_DATA_READ;
	req->next  = NULL;

	aio_read(s, req, offset);

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", blk: 0x%04x, sec: 0x%04x, "
	    "nr_secs: 0x%04x, offset: 0x%08"PRIx64", flags: 0x%08x, buf: %p\n",
	    s->vhd.file, treq.sec, blk, sec, treq.secs, offset, req->flags,
	    treq.buf);

	return 0;
}

static int
schedule_data_write(struct vhd_state *s, td_request_t treq, vhd_flag_t flags)
{
	int err;
	u64 offset;
	u32 blk = 0, sec = 0;
	struct vhd_bitmap  *bm = NULL;
	struct vhd_request *req;

	if (s->vhd.footer.type == HD_TYPE_FIXED) {
		offset = vhd_sectors_to_bytes(treq.sec);
		goto make_request;
	}

	blk    = treq.sec / s->spb;
	sec    = treq.sec % s->spb;
	offset = bat_entry(s, blk);

	if (test_vhd_flag(flags, VHD_FLAG_REQ_UPDATE_BAT)) {
		if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_PREALLOCATE))
			err = allocate_block(s, blk);
		else
			err = update_bat(s, blk);

		if (err)
			return err;

		offset = s->bat.pbw_offset;
	}

	offset += s->bm_secs + sec;
	offset  = vhd_sectors_to_bytes(offset);

 make_request:
	req = alloc_vhd_request(s);
	if (!req)
		return -EBUSY;

	req->treq  = treq;
	req->flags = flags;
	req->op    = VHD_OP_DATA_WRITE;
	req->next  = NULL;

	if (test_vhd_flag(flags, VHD_FLAG_REQ_UPDATE_BITMAP)) {
		bm = get_bitmap(s, blk);
		ASSERT(bm && bitmap_valid(bm));
		lock_bitmap(bm);

		if (bm->tx.closed) {
			add_to_tail(&bm->queue, req);
			set_vhd_flag(req->flags, VHD_FLAG_REQ_QUEUED);
		} else
			add_to_transaction(&bm->tx, req);
	}

	aio_write(s, req, offset);

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", blk: 0x%04x, sec: 0x%04x, "
	    "nr_secs: 0x%04x, offset: 0x%08"PRIx64", flags: 0x%08x\n",
	    s->vhd.file, treq.sec, blk, sec, treq.secs, offset, req->flags);

	return 0;
}

static int 
schedule_bitmap_read(struct vhd_state *s, uint32_t blk)
{
	int err;
	u64 offset;
	struct vhd_bitmap  *bm;
	struct vhd_request *req = NULL;

	ASSERT(vhd_type_dynamic(&s->vhd));

	offset = bat_entry(s, blk);

	ASSERT(offset != DD_BLK_UNUSED);
	ASSERT(!get_bitmap(s, blk));

	offset = vhd_sectors_to_bytes(offset);

	err = alloc_vhd_bitmap(s, &bm, blk);
	if (err)
		return err;

	req = &bm->req;
	init_vhd_request(s, req);

	req->treq.sec  = blk * s->spb;
	req->treq.secs = s->bm_secs;
	req->treq.buf  = bm->map;
	req->treq.cb   = NULL;
	req->op        = VHD_OP_BITMAP_READ;
	req->next      = NULL;

	aio_read(s, req, offset);
	lock_bitmap(bm);
	install_bitmap(s, bm);
	set_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING);

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", blk: 0x%04x, nr_secs: 0x%04x, "
	    "offset: 0x%08"PRIx64"\n", s->vhd.file, req->treq.sec, blk,
	    req->treq.secs, offset);

	return 0;
}

static void
schedule_bitmap_write(struct vhd_state *s, uint32_t blk)
{
	u64 offset;
	struct vhd_bitmap  *bm;
	struct vhd_request *req;

	bm     = get_bitmap(s, blk);
	offset = bat_entry(s, blk);

	ASSERT(vhd_type_dynamic(&s->vhd));
	ASSERT(bm && bitmap_valid(bm) &&
	       !test_vhd_flag(bm->status, VHD_FLAG_BM_WRITE_PENDING));

	if (offset == DD_BLK_UNUSED) {
		ASSERT(bat_locked(s) && s->bat.pbw_blk == blk);
		offset = s->bat.pbw_offset;
	}
	
	offset = vhd_sectors_to_bytes(offset);

	req = &bm->req;
	init_vhd_request(s, req);

	req->treq.sec  = blk * s->spb;
	req->treq.secs = s->bm_secs;
	req->treq.buf  = bm->shadow;
	req->treq.cb   = NULL;
	req->op        = VHD_OP_BITMAP_WRITE;
	req->next      = NULL;

	aio_write(s, req, offset);
	lock_bitmap(bm);
	touch_bitmap(s, bm);     /* bump lru count */
	set_vhd_flag(bm->status, VHD_FLAG_BM_WRITE_PENDING);

	DBG(TLOG_DBG, "%s: blk: 0x%04x, sec: 0x%08"PRIx64", nr_secs: 0x%04x, "
	    "offset: 0x%"PRIx64"\n", s->vhd.file, blk, req->treq.sec,
	    req->treq.secs, offset);
}

/* 
 * queued requests will be submitted once the bitmap
 * describing them is read and the requests are validated. 
 */
static int
__vhd_queue_request(struct vhd_state *s, uint8_t op, td_request_t treq)
{
	u32 blk;
	struct vhd_bitmap  *bm;
	struct vhd_request *req;

	ASSERT(vhd_type_dynamic(&s->vhd));

	blk = treq.sec / s->spb;
	bm  = get_bitmap(s, blk);

	ASSERT(bm && test_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING));

	req = alloc_vhd_request(s);
	if (!req)
		return -EBUSY;

	req->treq = treq;
	req->op   = op;
	req->next = NULL;

	add_to_tail(&bm->waiting, req);
	lock_bitmap(bm);

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", blk: 0x%04x nr_secs: 0x%04x, "
	    "op: %u\n", s->vhd.file, treq.sec, blk, treq.secs, op);

	TRACE(s);
	return 0;
}

static void
vhd_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct vhd_state *s = (struct vhd_state *)driver->data;

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", secs: 0x%04x (seg: %d)\n",
	    s->vhd.file, treq.sec, treq.secs, treq.sidx);

	while (treq.secs) {
		int err;
		td_request_t clone;

		err   = 0;
		clone = treq;

		switch (read_bitmap_cache(s, clone.sec, VHD_OP_DATA_READ)) {
		case -EINVAL:
			err = -EINVAL;
			goto fail;

		case VHD_BM_BAT_CLEAR:
			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			td_forward_request(clone);
			break;

		case VHD_BM_BIT_CLEAR:
			clone.secs = read_bitmap_cache_span(s, clone.sec, clone.secs, 0);
			td_forward_request(clone);
			break;

		case VHD_BM_BIT_SET:
			clone.secs = read_bitmap_cache_span(s, clone.sec, clone.secs, 1);
			err = schedule_data_read(s, clone, 0);
			if (err)
				goto fail;
			break;

		case VHD_BM_NOT_CACHED:
			err = schedule_bitmap_read(s, clone.sec / s->spb);
			if (err)
				goto fail;

			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			err = __vhd_queue_request(s, VHD_OP_DATA_READ, clone);
			if (err)
				goto fail;
			break;

		case VHD_BM_READ_PENDING:
			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			err = __vhd_queue_request(s, VHD_OP_DATA_READ, clone);
			if (err)
				goto fail;
			break;

		case VHD_BM_BAT_LOCKED:
		default:
			ASSERT(0);
			break;
		}

		treq.sec  += clone.secs;
		treq.secs -= clone.secs;
		treq.buf  += vhd_sectors_to_bytes(clone.secs);
		continue;

	fail:
		clone.secs = treq.secs;
		td_complete_request(clone, err);
		break;
	}
}

static void
vhd_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct vhd_state *s = (struct vhd_state *)driver->data;

	DBG(TLOG_DBG, "%s: lsec: 0x%08"PRIx64", secs: 0x%04x, (seg: %d)\n",
	    s->vhd.file, treq.sec, treq.secs, treq.sidx);

	while (treq.secs) {
		int err;
		uint8_t flags;
		td_request_t clone;

		err   = 0;
		flags = 0;
		clone = treq;

		switch (read_bitmap_cache(s, clone.sec, VHD_OP_DATA_WRITE)) {
		case -EINVAL:
			err = -EINVAL;
			goto fail;

		case VHD_BM_BAT_LOCKED:
			err = -EBUSY;
			clone.blocked = 1;
			goto fail;

		case VHD_BM_BAT_CLEAR:
			flags      = (VHD_FLAG_REQ_UPDATE_BAT |
				      VHD_FLAG_REQ_UPDATE_BITMAP);
			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			err        = schedule_data_write(s, clone, flags);
			if (err)
				goto fail;
			break;

		case VHD_BM_BIT_CLEAR:
			flags      = VHD_FLAG_REQ_UPDATE_BITMAP;
			clone.secs = read_bitmap_cache_span(s, clone.sec, clone.secs, 0);
			err        = schedule_data_write(s, clone, flags);
			if (err)
				goto fail;
			break;

		case VHD_BM_BIT_SET:
			clone.secs = read_bitmap_cache_span(s, clone.sec, clone.secs, 1);
			err = schedule_data_write(s, clone, 0);
			if (err)
				goto fail;
			break;

		case VHD_BM_NOT_CACHED:
			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			err = schedule_bitmap_read(s, clone.sec / s->spb);
			if (err)
				goto fail;

			err = __vhd_queue_request(s, VHD_OP_DATA_WRITE, clone);
			if (err)
				goto fail;
			break;

		case VHD_BM_READ_PENDING:
			clone.secs = MIN(clone.secs, s->spb - (clone.sec % s->spb));
			err = __vhd_queue_request(s, VHD_OP_DATA_WRITE, clone);
			if (err)
				goto fail;
			break;

		default:
			ASSERT(0);
			break;
		}

		treq.sec  += clone.secs;
		treq.secs -= clone.secs;
		treq.buf  += vhd_sectors_to_bytes(clone.secs);
		continue;

	fail:
		clone.secs = treq.secs;
		td_complete_request(clone, err);
		break;
	}
}

static inline void
signal_completion(struct vhd_request *list, int error)
{
	struct vhd_state *s;
	struct vhd_request *r, *next;

	if (!list)
		return;

	r = list;
	s = list->state;

	while (r) {
		int err;

		err  = (error ? error : r->error);
		next = r->next;
		td_complete_request(r->treq, err);
		DBG(TLOG_DBG, "lsec: 0x%08"PRIx64", blk: 0x%04"PRIx64", "
		    "err: %d\n", r->treq.sec, r->treq.sec / s->spb, err);
		free_vhd_request(s, r);
		r    = next;

		s->returned++;
		TRACE(s);
	}
}

static void
start_new_bitmap_transaction(struct vhd_state *s, struct vhd_bitmap *bm)
{
	int i, error = 0;
	struct vhd_transaction *tx;
	struct vhd_request *r, *next;

	if (!bm->queue.head)
		return;

	DBG(TLOG_DBG, "blk: 0x%04x\n", bm->blk);

	r  = bm->queue.head;
	tx = &bm->tx;
	clear_req_list(&bm->queue);

	if (r && bat_entry(s, bm->blk) == DD_BLK_UNUSED)
		tx->error = -EIO;

	while (r) {
		next    = r->next;
		r->next = NULL;
		clear_vhd_flag(r->flags, VHD_FLAG_REQ_QUEUED);

		add_to_transaction(tx, r);
		if (test_vhd_flag(r->flags, VHD_FLAG_REQ_FINISHED)) {
			tx->finished++;
			if (!r->error) {
				u32 sec = r->treq.sec % s->spb;
				for (i = 0; i < r->treq.secs; i++)
					vhd_bitmap_set(&s->vhd,
						       bm->shadow, sec + i);
			}
		}
		r = next;
	}

	/* perhaps all the queued writes already completed? */
	if (tx->started && transaction_completed(tx))
		finish_data_transaction(s, bm);
}

static void
finish_bat_transaction(struct vhd_state *s, struct vhd_bitmap *bm)
{
	struct vhd_transaction *tx = &bm->tx;

	if (!bat_locked(s))
		return;

	if (s->bat.pbw_blk != bm->blk)
		return;

	if (!s->bat.req.error)
		goto release;

	if (!test_vhd_flag(tx->status, VHD_FLAG_TX_LIVE))
		goto release;

	tx->closed = 1;
	return;

 release:
	DBG(TLOG_DBG, "blk: 0x%04x\n", bm->blk);
	unlock_bat(s);
	init_bat(s);
}

static void
finish_bitmap_transaction(struct vhd_state *s,
			  struct vhd_bitmap *bm, int error)
{
	int map_size;
	struct vhd_transaction *tx = &bm->tx;

	DBG(TLOG_DBG, "blk: 0x%04x, err: %d\n", bm->blk, error);
	tx->error = (tx->error ? tx->error : error);
	map_size  = vhd_sectors_to_bytes(s->bm_secs);

	if (!test_vhd_flag(s->flags, VHD_FLAG_OPEN_PREALLOCATE)) {
		if (test_vhd_flag(tx->status, VHD_FLAG_TX_UPDATE_BAT)) {
			/* still waiting for bat write */
			ASSERT(bm->blk == s->bat.pbw_blk);
			ASSERT(test_vhd_flag(s->bat.status, 
					     VHD_FLAG_BAT_WRITE_STARTED));
			s->bat.req.tx = tx;
			return;
		}
	}

	if (tx->error) {
		/* undo changes to shadow */
		memcpy(bm->shadow, bm->map, map_size);
	} else {
		/* complete atomic write */
		memcpy(bm->map, bm->shadow, map_size);
		if (!test_batmap(s, bm->blk) && bitmap_full(s, bm))
			set_batmap(s, bm->blk);
	}

	/* transaction done; signal completions */
	signal_completion(tx->requests.head, tx->error);
	init_tx(tx);
	start_new_bitmap_transaction(s, bm);

	if (!bitmap_in_use(bm))
		unlock_bitmap(bm);

	finish_bat_transaction(s, bm);
}

static void
finish_data_transaction(struct vhd_state *s, struct vhd_bitmap *bm)
{
	struct vhd_transaction *tx = &bm->tx;

	DBG(TLOG_DBG, "blk: 0x%04x\n", bm->blk);

	tx->closed = 1;

	if (!tx->error)
		return schedule_bitmap_write(s, bm->blk);

	return finish_bitmap_transaction(s, bm, 0);
}

static void
finish_bat_write(struct vhd_request *req)
{
	struct vhd_bitmap *bm;
	struct vhd_transaction *tx;
	struct vhd_state *s = req->state;

	s->returned++;
	TRACE(s);

	bm = get_bitmap(s, s->bat.pbw_blk);

	DBG(TLOG_DBG, "blk 0x%04x, pbwo: 0x%08"PRIx64", err %d\n",
	    s->bat.pbw_blk, s->bat.pbw_offset, req->error);
	ASSERT(bm && bitmap_valid(bm));
	ASSERT(bat_locked(s) &&
	       test_vhd_flag(s->bat.status, VHD_FLAG_BAT_WRITE_STARTED));

	tx = &bm->tx;
	ASSERT(test_vhd_flag(tx->status, VHD_FLAG_TX_LIVE));

	if (!req->error) {
		bat_entry(s, s->bat.pbw_blk) = s->bat.pbw_offset;
		s->next_db = s->bat.pbw_offset + s->spb + s->bm_secs;
	} else
		tx->error = req->error;

	if (test_vhd_flag(s->flags, VHD_FLAG_OPEN_PREALLOCATE)) {
		tx->finished++;
		remove_from_req_list(&tx->requests, req);
		if (transaction_completed(tx))
			finish_data_transaction(s, bm);
	} else {
		clear_vhd_flag(tx->status, VHD_FLAG_TX_UPDATE_BAT);
		if (s->bat.req.tx)
			finish_bitmap_transaction(s, bm, req->error);
	}

	finish_bat_transaction(s, bm);
}

static void
finish_zero_bm_write(struct vhd_request *req)
{
	u32 blk;
	struct vhd_bitmap *bm;
	struct vhd_transaction *tx = req->tx;
	struct vhd_state *s = req->state;

	s->returned++;
	TRACE(s);

	blk = req->treq.sec / s->spb;
	bm  = get_bitmap(s, blk);

	DBG(TLOG_DBG, "blk: 0x%04x\n", blk);
	ASSERT(bat_locked(s));
	ASSERT(s->bat.pbw_blk == blk);
	ASSERT(bm && bitmap_valid(bm) && bitmap_locked(bm));

	tx->finished++;
	remove_from_req_list(&tx->requests, req);

	if (req->error) {
		unlock_bat(s);
		init_bat(s);
		tx->error = req->error;
		clear_vhd_flag(tx->status, VHD_FLAG_TX_UPDATE_BAT);
	} else
		schedule_bat_write(s);

	if (transaction_completed(tx))
		finish_data_transaction(s, bm);
}

static void
finish_bitmap_read(struct vhd_request *req)
{
	u32 blk;
	struct vhd_bitmap  *bm;
	struct vhd_request *r, *next;
	struct vhd_state   *s = req->state;

	s->returned++;
	TRACE(s);

	blk = req->treq.sec / s->spb;
	bm  = get_bitmap(s, blk);

	DBG(TLOG_DBG, "blk: 0x%04x\n", blk);
	ASSERT(bm && test_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING));

	r = bm->waiting.head;
	clear_req_list(&bm->waiting);
	clear_vhd_flag(bm->status, VHD_FLAG_BM_READ_PENDING);

	if (!req->error) {
		memcpy(bm->shadow, bm->map, vhd_sectors_to_bytes(s->bm_secs));

		while (r) {
			struct vhd_request tmp;

			tmp  = *r;
			next =  r->next;
			free_vhd_request(s, r);

			ASSERT(tmp.op == VHD_OP_DATA_READ || 
			       tmp.op == VHD_OP_DATA_WRITE);

			if (tmp.op == VHD_OP_DATA_READ)
				vhd_queue_read(s->driver, tmp.treq);
			else if (tmp.op == VHD_OP_DATA_WRITE)
				vhd_queue_write(s->driver, tmp.treq);

			r = next;
		}
	} else {
		int err = req->error;
		unlock_bitmap(bm);
		free_vhd_bitmap(s, bm);
		return signal_completion(r, err);
	}

	if (!bitmap_in_use(bm))
		unlock_bitmap(bm);
}

static void
finish_bitmap_write(struct vhd_request *req)
{
	u32 blk;
	struct vhd_bitmap  *bm;
	struct vhd_transaction *tx;
	struct vhd_state *s = req->state;

	s->returned++;
	TRACE(s);

	blk = req->treq.sec / s->spb;
	bm  = get_bitmap(s, blk);
	tx  = &bm->tx;

	DBG(TLOG_DBG, "blk: 0x%04x, started: %d, finished: %d\n",
	    blk, tx->started, tx->finished);
	ASSERT(tx->closed);
	ASSERT(bm && bitmap_valid(bm));
	ASSERT(test_vhd_flag(bm->status, VHD_FLAG_BM_WRITE_PENDING));

	clear_vhd_flag(bm->status, VHD_FLAG_BM_WRITE_PENDING);

	finish_bitmap_transaction(s, bm, req->error);
}

static void
finish_data_read(struct vhd_request *req)
{
	struct vhd_state *s = req->state;

	DBG(TLOG_DBG, "lsec 0x%08"PRIx64", blk: 0x%04"PRIx64"\n", 
	    req->treq.sec, req->treq.sec / s->spb);
	signal_completion(req, 0);
}

static void
finish_data_write(struct vhd_request *req)
{
	int i;
	struct vhd_transaction *tx = req->tx;
	struct vhd_state *s = (struct vhd_state *)req->state;

	set_vhd_flag(req->flags, VHD_FLAG_REQ_FINISHED);

	if (tx) {
		u32 blk, sec;
		struct vhd_bitmap *bm;

		blk = req->treq.sec / s->spb;
		sec = req->treq.sec % s->spb;
		bm  = get_bitmap(s, blk);

		ASSERT(bm && bitmap_valid(bm) && bitmap_locked(bm));

		tx->finished++;

		DBG(TLOG_DBG, "lsec: 0x%08"PRIx64", blk: 0x04%"PRIx64", "
		    "tx->started: %d, tx->finished: %d\n", req->treq.sec,
		    req->treq.sec / s->spb, tx->started, tx->finished);

		if (!req->error)
			for (i = 0; i < req->treq.secs; i++)
				vhd_bitmap_set(&s->vhd, bm->shadow,  sec + i);

		if (transaction_completed(tx))
			finish_data_transaction(s, bm);

	} else if (!test_vhd_flag(req->flags, VHD_FLAG_REQ_QUEUED)) {
		ASSERT(!req->next);
		DBG(TLOG_DBG, "lsec: 0x%08"PRIx64", blk: 0x%04"PRIx64"\n", 
		    req->treq.sec, req->treq.sec / s->spb);
		signal_completion(req, 0);
	}
}

void
vhd_complete(void *arg, struct tiocb *tiocb, int err)
{
	struct vhd_request *req = (struct vhd_request *)arg;
	struct vhd_state *s = req->state;
	struct iocb *io = &tiocb->iocb;

	s->completed++;
	TRACE(s);

	req->error = err;

	if (req->error)
		ERR(req->error, "%s: op: %u, lsec: %"PRIu64", secs: %u, "
		    "nbytes: %lu, blk: %"PRIu64", blk_offset: %u",
		    s->vhd.file, req->op, req->treq.sec, req->treq.secs,
		    io->u.c.nbytes, req->treq.sec / s->spb,
		    bat_entry(s, req->treq.sec / s->spb));

	switch (req->op) {
	case VHD_OP_DATA_READ:
		finish_data_read(req);
		break;

	case VHD_OP_DATA_WRITE:
		finish_data_write(req);
		break;

	case VHD_OP_BITMAP_READ:
		finish_bitmap_read(req);
		break;

	case VHD_OP_BITMAP_WRITE:
		finish_bitmap_write(req);
		break;

	case VHD_OP_ZERO_BM_WRITE:
		finish_zero_bm_write(req);
		break;

	case VHD_OP_BAT_WRITE:
		finish_bat_write(req);
		break;

	default:
		ASSERT(0);
		break;
	}
}

void 
vhd_debug(td_driver_t *driver)
{
	int i;
	struct vhd_state *s = (struct vhd_state *)driver->data;

	DBG(TLOG_WARN, "%s: QUEUED: 0x%08"PRIx64", COMPLETED: 0x%08"PRIx64", "
	    "RETURNED: 0x%08"PRIx64"\n", s->vhd.file, s->queued, s->completed,
	    s->returned);
	DBG(TLOG_WARN, "WRITES: 0x%08"PRIx64", AVG_WRITE_SIZE: %f\n",
	    s->writes, (s->writes ? ((float)s->write_size / s->writes) : 0.0));
	DBG(TLOG_WARN, "READS: 0x%08"PRIx64", AVG_READ_SIZE: %f\n",
	    s->reads, (s->reads ? ((float)s->read_size / s->reads) : 0.0));

	DBG(TLOG_WARN, "ALLOCATED REQUESTS: (%lu total)\n", VHD_REQS_DATA);
	for (i = 0; i < VHD_REQS_DATA; i++) {
		struct vhd_request *r = &s->vreq_list[i];
		td_request_t *t       = &r->treq;
		if (t->secs)
			DBG(TLOG_WARN, "%d: id: 0x%04"PRIx64", err: %d, op: %d,"
			    " lsec: 0x%08"PRIx64", flags: %d, this: %p, "
			    "next: %p, tx: %p\n", i, t->id, r->error, r->op,
			    t->sec, r->flags, r, r->next, r->tx);
	}

	DBG(TLOG_WARN, "BITMAP CACHE:\n");
	for (i = 0; i < VHD_CACHE_SIZE; i++) {
		int qnum = 0, wnum = 0, rnum = 0;
		struct vhd_bitmap *bm = s->bitmap[i];
		struct vhd_transaction *tx;
		struct vhd_request *r;

		if (!bm)
			continue;

		tx = &bm->tx;
		r = bm->queue.head;
		while (r) {
			qnum++;
			r = r->next;
		}

		r = bm->waiting.head;
		while (r) {
			wnum++;
			r = r->next;
		}

		r = tx->requests.head;
		while (r) {
			rnum++;
			r = r->next;
		}

		DBG(TLOG_WARN, "%d: blk: 0x%04x, status: 0x%08x, q: %p, qnum: %d, w: %p, "
		    "wnum: %d, locked: %d, in use: %d, tx: %p, tx_error: %d, "
		    "started: %d, finished: %d, status: %u, reqs: %p, nreqs: %d\n",
		    i, bm->blk, bm->status, bm->queue.head, qnum, bm->waiting.head,
		    wnum, bitmap_locked(bm), bitmap_in_use(bm), tx, tx->error,
		    tx->started, tx->finished, tx->status, tx->requests.head, rnum);
	}

	DBG(TLOG_WARN, "BAT: status: 0x%08x, pbw_blk: 0x%04x, "
	    "pbw_off: 0x%08"PRIx64", tx: %p\n", s->bat.status, s->bat.pbw_blk,
	    s->bat.pbw_offset, s->bat.req.tx);

/*
	for (i = 0; i < s->hdr.max_bat_size; i++)
		DPRINTF("%d: %u\n", i, s->bat.bat[i]);
*/
}

struct tap_disk tapdisk_vhd = {
	.disk_type          = "tapdisk_vhd",
	.flags              = 0,
	.private_data_size  = sizeof(struct vhd_state),
	.td_open            = _vhd_open,
	.td_close           = _vhd_close,
	.td_queue_read      = vhd_queue_read,
	.td_queue_write     = vhd_queue_write,
	.td_get_parent_id   = vhd_get_parent_id,
	.td_validate_parent = vhd_validate_parent,
	.td_debug           = vhd_debug,
};
