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
 */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef MEMSHR
#include <memshr.h>
#endif

#include "tapdisk-image.h"
#include "tapdisk-driver.h"
#include "tapdisk-server.h"

#define ERR(_err, _f, _a...) tlog_error(_err, _f, ##_a)

td_image_t *
tapdisk_image_allocate(const char *file, int type, int storage,
		       td_flag_t flags, void *private)
{
	int err;
	td_image_t *image;

	image = calloc(1, sizeof(td_image_t));
	if (!image)
		return NULL;

	err = tapdisk_namedup(&image->name, file);
	if (err) {
		free(image);
		return NULL;
	}

	image->type      = type;
	image->flags     = flags;
	image->storage   = storage;
	image->private   = private;
#ifdef MEMSHR
	image->memshr_id = memshr_vbd_image_get(file);
#endif
	INIT_LIST_HEAD(&image->next);

	return image;
}

void
tapdisk_image_free(td_image_t *image)
{
	if (!image)
		return;

	list_del(&image->next);

#ifdef MEMSHR
	memshr_vbd_image_put(image->memshr_id);
#endif
	free(image->name);
	tapdisk_driver_free(image->driver);
	free(image);
}

int
tapdisk_image_check_td_request(td_image_t *image, td_request_t treq)
{
	int rdonly;
	td_driver_t *driver;
	td_disk_info_t *info;

	driver = image->driver;
	if (!driver)
		return -ENODEV;

	info   = &driver->info;
	rdonly = td_flag_test(image->flags, TD_OPEN_RDONLY);

	if (treq.op != TD_OP_READ && treq.op != TD_OP_WRITE)
		goto fail;

	if (treq.op == TD_OP_WRITE && rdonly)
		goto fail;

	if (treq.secs <= 0 || treq.sec + treq.secs > info->size)
		goto fail;

	return 0;

fail:
	ERR(-EINVAL, "bad td request on %s (%s, %"PRIu64"): %d at %"PRIu64,
	    image->name, (rdonly ? "ro" : "rw"), info->size, treq.op,
	    treq.sec + treq.secs);
	return -EINVAL;

}

int
tapdisk_image_check_ring_request(td_image_t *image, blkif_request_t *req)
{
	td_driver_t *driver;
	td_disk_info_t *info;
	int i, psize, rdonly;
	uint64_t nsects, total;

	driver = image->driver;
	if (!driver)
		return -ENODEV;

	nsects = 0;
	total  = 0;
	info   = &driver->info;

	rdonly = td_flag_test(image->flags, TD_OPEN_RDONLY);

	if (req->operation != BLKIF_OP_READ &&
	    req->operation != BLKIF_OP_WRITE)
		goto fail;

	if (req->operation == BLKIF_OP_WRITE && rdonly)
		goto fail;

	if (!req->nr_segments || req->nr_segments > MAX_SEGMENTS_PER_REQ)
		goto fail;

	total = 0;
	psize = getpagesize();

	for (i = 0; i < req->nr_segments; i++) {
		nsects = req->seg[i].last_sect - req->seg[i].first_sect + 1;
		
		if (req->seg[i].last_sect >= psize >> 9 || nsects <= 0)
			goto fail;

		total += nsects;
	}

	if (req->sector_number + nsects > info->size)
		goto fail;

	return 0;

fail:
	ERR(-EINVAL, "bad request on %s (%s, %"PRIu64"): id: %"PRIu64": %d at %"PRIu64,
	    image->name, (rdonly ? "ro" : "rw"), info->size, req->id,
	    req->operation, req->sector_number + total);
	return -EINVAL;
}
