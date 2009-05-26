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

#ifndef __IO_OPTIMIZE_H__
#define __IO_OPTIMIZE_H__

#include <libaio.h>

struct opio;

struct opio_list {
	struct opio        *head;
	struct opio        *tail;
};

struct opio {
	char               *buf;
	unsigned long       nbytes;
	long long           offset;
	void               *data;
	struct iocb        *iocb;
	struct io_event     event;
	struct opio        *head;
	struct opio        *next;
	struct opio_list    list;
};

struct opioctx {
	int                 num_opios;
	int                 free_opio_cnt;
	struct opio        *opios;
	struct opio       **free_opios;
	struct iocb       **iocb_queue;
	struct io_event    *event_queue;
};

int opio_init(struct opioctx *ctx, int num_iocbs);
void opio_free(struct opioctx *ctx);
int io_merge(struct opioctx *ctx, struct iocb **queue, int num);
int io_split(struct opioctx *ctx, struct io_event *events, int num);
int io_expand_iocbs(struct opioctx *ctx, struct iocb **queue, int idx, int num);

#endif
