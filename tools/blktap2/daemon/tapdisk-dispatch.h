/* Copyright (c) 2008, XenSource Inc.
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
#ifndef _TAPDISK_DISPATCH_H_
#define _TAPDISK_DISPATCH_H_

#include "xs_api.h"
#include "blktaplib.h"
#include "tapdisk-message.h"

struct tapdisk_channel {
	int                       state;

	int                       read_fd;
	int                       write_fd;
	int                       blktap_fd;
	int                       channel_id;

	char                      mode;
	char                      shared;
	char                      open;
	unsigned int              domid;
	unsigned int              busid;
	unsigned int              major;
	unsigned int              minor;
	unsigned int              storage;
	unsigned int              drivertype;
	uint16_t                  cookie;
	pid_t                     tapdisk_pid;

	/*
	 * special accounting needed to handle pause
	 * requests received before tapdisk process is ready
	 */
	char                      connected;
	char                      pause_needed;

	char                     *path;
	char                     *frontpath;
	char                     *params;
	char                     *vdi_path;
	char                     *uuid_str;
	char                     *pause_str;
	char                     *pause_done_str;
	char                     *shutdown_str;
	char                     *share_tapdisk_str;

	image_t                   image;

	struct list_head          list;
	struct xenbus_watch       pause_watch;
	struct xenbus_watch       shutdown_watch;

	struct xs_handle         *xsh;
};

typedef struct tapdisk_channel tapdisk_channel_t;

int strsep_len(const char *str, char c, unsigned int len);
int make_blktap_device(char *devname, int major, int minor, int perm);

int tapdisk_channel_open(tapdisk_channel_t **,
			 char *node, struct xs_handle *,
			 int blktap_fd, uint16_t cookie);
void tapdisk_channel_close(tapdisk_channel_t *);

void tapdisk_daemon_find_channel(tapdisk_channel_t *);
void tapdisk_daemon_close_channel(tapdisk_channel_t *);

int tapdisk_channel_receive_message(tapdisk_channel_t *, tapdisk_message_t *);

#endif
