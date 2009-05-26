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

/* log.h: API for writelog communication */

#ifndef __LOG_H__
#define __LOG_H__ 1

#include <inttypes.h>

#include <xen/io/ring.h>
/* for wmb et al */
#include <xenctrl.h>

#define LOGCMD_SHMP  "shmp"
#define LOGCMD_PEEK  "peek"
#define LOGCMD_CLEAR "clrw"
#define LOGCMD_GET   "getw"
#define LOGCMD_KICK  "kick"

#define CTLRSPLEN_SHMP  256
#define CTLRSPLEN_PEEK  4
#define CTLRSPLEN_CLEAR 4
#define CTLRSPLEN_GET   4
#define CTLRSPLEN_KICK  0

/* shmregion is arbitrarily capped at 8 megs for a minimum of
 * 64 MB of data per read (if there are no contiguous regions)
 * In the off-chance that there is more dirty data, multiple
 * reads must be done */
#define SHMSIZE (8 * 1024 * 1024)
#define SRINGSIZE 4096

/* The shared memory region is split up into 3 subregions:
 * The first half is reserved for the dirty bitmap log.
 * The second half begins with 1 page for read request descriptors,
 * followed by a big area for supplying read data.
 */
static inline void* bmstart(void* shm)
{
  return shm;
}

static inline void* bmend(void* shm)
{
  return shm + SHMSIZE/2;
}

static inline void* sringstart(void* shm)
{
  return bmend(shm);
}

static inline void* sdatastart(void* shm)
{
  return sringstart(shm) + SRINGSIZE;
}

static inline void* sdataend(void* shm)
{
  return shm + SHMSIZE;
}

/* format for messages between log client and server */
struct log_ctlmsg {
  char msg[4];
  char params[16];
};

/* extent descriptor */
struct disk_range {
  uint64_t sector;
  uint32_t count;
};

/* dirty write logging space. This is an extent ring at the front,
 * full of disk_ranges plus a pointer into the data area */
/* I think I'd rather have the header in front of each data section to
 * avoid having two separate spaces that can run out, but then I'd either
 * lose page alignment on the data blocks or spend an entire page on the
 * header */

struct log_extent {
  uint64_t sector;
  uint32_t count;
  uint32_t offset; /* offset from start of data area to start of extent */
};

/* struct above should be 16 bytes, or 256 extents/page */

typedef struct log_extent log_request_t;
typedef struct log_extent log_response_t;

DEFINE_RING_TYPES(log, log_request_t, log_response_t);

#define LOG_HEADER_PAGES 4

#endif
