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
#ifndef _TAPDISK_VBD_H_
#define _TAPDISK_VBD_H_

#include <sys/time.h>
#include <xenctrl.h>
#include <xen/io/blkif.h>

#include "tapdisk.h"
#include "scheduler.h"
#include "tapdisk-image.h"

#define TD_VBD_MAX_RETRIES          100
#define TD_VBD_RETRY_INTERVAL       1

#define TD_VBD_DEAD                 0x0001
#define TD_VBD_CLOSED               0x0002
#define TD_VBD_QUIESCE_REQUESTED    0x0004
#define TD_VBD_QUIESCED             0x0008
#define TD_VBD_PAUSE_REQUESTED      0x0010
#define TD_VBD_PAUSED               0x0020
#define TD_VBD_SHUTDOWN_REQUESTED   0x0040
#define TD_VBD_LOCKING              0x0080
#define TD_VBD_RETRY_NEEDED         0x0100
#define TD_VBD_LOG_DROPPED          0x0200

typedef struct td_ring              td_ring_t;
typedef struct td_vbd_request       td_vbd_request_t;
typedef struct td_vbd_driver_info   td_vbd_driver_info_t;
typedef struct td_vbd_handle        td_vbd_t;
typedef void (*td_vbd_cb_t)        (void *, blkif_response_t *);

struct td_ring {
	int                         fd;
	char                       *mem;
	blkif_sring_t              *sring;
	blkif_back_ring_t           fe_ring;
	unsigned long               vstart;
};

struct td_vbd_request {
	blkif_request_t             req;
	int16_t                     status;

	int                         error;
	int                         blocked; /* blocked on a dependency */
	int                         submitting;
	int                         secs_pending;
	int                         num_retries;
	struct timeval              last_try;

	td_vbd_t                   *vbd;
	struct list_head            next;
};

struct td_vbd_driver_info {
	char                       *params;
	int                         type;
	struct list_head            next;
};

struct td_vbd_handle {
	char                       *name;

	td_uuid_t                   uuid;
	int                         minor;

	struct list_head            driver_stack;

	int                         storage;

	uint8_t                     reopened;
	uint8_t                     reactivated;
	td_flag_t                   flags;
	td_flag_t                   state;

	struct list_head            images;

	struct list_head            new_requests;
	struct list_head            pending_requests;
	struct list_head            failed_requests;
	struct list_head            completed_requests;

	td_vbd_request_t            request_list[MAX_REQUESTS];

	td_ring_t                   ring;
	event_id_t                  ring_event_id;

	td_vbd_cb_t                 callback;
	void                       *argument;

	struct list_head            next;

	struct timeval              ts;

	uint64_t                    received;
	uint64_t                    returned;
	uint64_t                    kicked;
	uint64_t                    secs_pending;
	uint64_t                    retries;
	uint64_t                    errors;
};

#define tapdisk_vbd_for_each_request(vreq, tmp, list)	                \
	list_for_each_entry_safe((vreq), (tmp), (list), next)

#define tapdisk_vbd_for_each_image(vbd, image, tmp)			\
	list_for_each_entry_safe((image), (tmp), &(vbd)->images, next)

static inline void
tapdisk_vbd_move_request(td_vbd_request_t *vreq, struct list_head *dest)
{
	list_del(&vreq->next);
	INIT_LIST_HEAD(&vreq->next);
	list_add_tail(&vreq->next, dest);
}

static inline void
tapdisk_vbd_add_image(td_vbd_t *vbd, td_image_t *image)
{
	list_add_tail(&image->next, &vbd->images);
}

static inline int
tapdisk_vbd_is_last_image(td_vbd_t *vbd, td_image_t *image)
{
	return list_is_last(&image->next, &vbd->images);
}

td_image_t *
tapdisk_vbd_first_image(td_vbd_t *vbd);

static inline td_image_t *
tapdisk_vbd_last_image(td_vbd_t *vbd)
{
	return list_entry(vbd->images.prev, td_image_t, next);
}

static inline td_image_t *
tapdisk_vbd_next_image(td_image_t *image)
{
	return list_entry(image->next.next, td_image_t, next);
}

td_vbd_t *tapdisk_vbd_create(td_uuid_t);
int tapdisk_vbd_initialize(td_uuid_t);
void tapdisk_vbd_set_callback(td_vbd_t *, td_vbd_cb_t, void *);
int tapdisk_vbd_parse_stack(td_vbd_t *vbd, const char *path);
int tapdisk_vbd_open(td_vbd_t *, const char *, uint16_t,
		     uint16_t, int, const char *, td_flag_t);
int tapdisk_vbd_close(td_vbd_t *);
void tapdisk_vbd_free(td_vbd_t *);
void tapdisk_vbd_free_stack(td_vbd_t *);

int tapdisk_vbd_open_stack(td_vbd_t *, uint16_t, td_flag_t);
int tapdisk_vbd_open_vdi(td_vbd_t *, const char *,
			 uint16_t, uint16_t, td_flag_t);
void tapdisk_vbd_close_vdi(td_vbd_t *);

int tapdisk_vbd_attach(td_vbd_t *, const char *, int);
void tapdisk_vbd_detach(td_vbd_t *);

void tapdisk_vbd_forward_request(td_request_t);

int tapdisk_vbd_get_image_info(td_vbd_t *, image_t *);
int tapdisk_vbd_queue_ready(td_vbd_t *);
int tapdisk_vbd_retry_needed(td_vbd_t *);
int tapdisk_vbd_quiesce_queue(td_vbd_t *);
int tapdisk_vbd_start_queue(td_vbd_t *);
int tapdisk_vbd_issue_requests(td_vbd_t *);
int tapdisk_vbd_kill_queue(td_vbd_t *);
int tapdisk_vbd_pause(td_vbd_t *);
int tapdisk_vbd_resume(td_vbd_t *, const char *, uint16_t);
int tapdisk_vbd_kick(td_vbd_t *);
void tapdisk_vbd_check_state(td_vbd_t *);
void tapdisk_vbd_check_progress(td_vbd_t *);
void tapdisk_vbd_debug(td_vbd_t *);

void tapdisk_vbd_complete_vbd_request(td_vbd_t *, td_vbd_request_t *);

#endif
