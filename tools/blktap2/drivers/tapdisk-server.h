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
#ifndef _TAPDISK_SERVER_H_
#define _TAPDISK_SERVER_H_

#include "list.h"
#include "tapdisk-vbd.h"
#include "tapdisk-queue.h"

struct tap_disk *tapdisk_server_find_driver_interface(int);

td_image_t *tapdisk_server_get_shared_image(td_image_t *);

struct list_head *tapdisk_server_get_all_vbds(void);
td_vbd_t *tapdisk_server_get_vbd(td_uuid_t);
void tapdisk_server_add_vbd(td_vbd_t *);
void tapdisk_server_remove_vbd(td_vbd_t *);

void tapdisk_server_queue_tiocb(struct tiocb *);

void tapdisk_server_check_state(void);

event_id_t tapdisk_server_register_event(char, int, int, event_cb_t, void *);
void tapdisk_server_unregister_event(event_id_t);
void tapdisk_server_set_max_timeout(int);

int tapdisk_server_init(void);
int tapdisk_server_initialize(void);
int tapdisk_server_complete(void);
int tapdisk_server_run(void);
void tapdisk_server_iterate(void);

#define TAPDISK_TIOCBS              (TAPDISK_DATA_REQUESTS + 50)

typedef struct tapdisk_server {
	int                          run;
	struct list_head             vbds;
	scheduler_t                  scheduler;
	struct tqueue                aio_queue;
} tapdisk_server_t;

#endif
