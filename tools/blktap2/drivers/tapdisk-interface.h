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
#ifndef _TAPDISK_INTERFACE_H_
#define _TAPDISK_INTERFACE_H_

#include "tapdisk.h"
#include "tapdisk-queue.h"

int td_open(td_image_t *);
int __td_open(td_image_t *, td_disk_info_t *);
int td_load(td_image_t *);
int td_close(td_image_t *);
int td_get_parent_id(td_image_t *, td_disk_id_t *);
int td_validate_parent(td_image_t *, td_image_t *);

void td_queue_write(td_image_t *, td_request_t);
void td_queue_read(td_image_t *, td_request_t);
void td_forward_request(td_request_t);
void td_complete_request(td_request_t, int);

void td_debug(td_image_t *);

void td_queue_tiocb(td_driver_t *, struct tiocb *);
void td_prep_read(struct tiocb *, int, char *, size_t,
		  long long, td_queue_callback_t, void *);
void td_prep_write(struct tiocb *, int, char *, size_t,
		   long long, td_queue_callback_t, void *);

#endif
