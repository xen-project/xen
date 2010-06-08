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
#ifndef _BLKTAP_2_H_
#define _BLKTAP_2_H_

#define BLKTAP2_MAX_MESSAGE_LEN        256

#define BLKTAP2_RING_MESSAGE_PAUSE     1
#define BLKTAP2_RING_MESSAGE_RESUME    2
#define BLKTAP2_RING_MESSAGE_CLOSE     3

#define BLKTAP2_IOCTL_KICK_FE          1
#define BLKTAP2_IOCTL_ALLOC_TAP        200
#define BLKTAP2_IOCTL_FREE_TAP         201
#define BLKTAP2_IOCTL_CREATE_DEVICE    202
#define BLKTAP2_IOCTL_SET_PARAMS       203
#define BLKTAP2_IOCTL_PAUSE            204
#define BLKTAP2_IOCTL_REOPEN           205
#define BLKTAP2_IOCTL_RESUME           206

#define BLKTAP2_SYSFS_DIR              "/sys/class/blktap2"
#define BLKTAP2_CONTROL_NAME           "blktap-control"
#define BLKTAP2_CONTROL_DIR            "/var/run/"BLKTAP2_CONTROL_NAME
#define BLKTAP2_CONTROL_SOCKET         "ctl"
#define BLKTAP2_DIRECTORY              "/dev/xen/blktap-2"
#define BLKTAP2_CONTROL_DEVICE         BLKTAP2_DIRECTORY"/control"
#define BLKTAP2_RING_DEVICE            BLKTAP2_DIRECTORY"/blktap"
#define BLKTAP2_IO_DEVICE              BLKTAP2_DIRECTORY"/tapdev"

struct blktap2_handle {
	unsigned int                   ring;
	unsigned int                   device;
	unsigned int                   minor;
};

struct blktap2_params {
	char                           name[BLKTAP2_MAX_MESSAGE_LEN];
	unsigned long long             capacity;
	unsigned long                  sector_size;
};

#endif
