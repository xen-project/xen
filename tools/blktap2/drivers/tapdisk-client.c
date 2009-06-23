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

/* client harness for tapdisk log */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "log.h"

#define BDPRINTF(_f, _a...) fprintf (stderr, "log: " _f "\n", ## _a)

#define BWPRINTF(_f, _a...) fprintf (stderr, "log: " _f "\n", ## _a)

struct writelog {
  char* shmpath;
  uint32_t shmsize;
  void* shm;

  /* next unprocessed item in the writelog */
  void* cur;
  unsigned int inflight;

  /* pointer to start and end of free data space for requests */
  void* dhd;
  void* dtl;

  log_sring_t* sring;
  log_front_ring_t fring;
};

/* bytes free on the data ring */
static inline unsigned int dring_avail(struct writelog* wl)
{
  /* one byte reserved to distinguish empty from full */
  if (wl->dhd == wl->dtl)
    return sdataend(wl->shm) - sdatastart(wl->shm) - 1;

  if (wl->dhd < wl->dtl)
    return wl->dtl - wl->dhd - 1;

  return (sdataend(wl->shm) - wl->dhd) + (wl->dtl - sdatastart(wl->shm)) - 1;
}

/* advance ring pointer by len bytes */
static inline void* dring_advance(struct writelog* wl, void* start, size_t len)
{
  void* next;
  int dsz = sdataend(wl->shm) - sdatastart(wl->shm);

  next = start + (len % dsz);
  if (next > sdataend(wl->shm))
    next -= dsz;

  return next;
}

static void usage(void)
{
  fprintf(stderr, "usage: tapdisk-client <sock>\n");
}

/* returns socket file descriptor */
static int tdctl_open(const char* sockpath)
{
  struct sockaddr_un saddr;
  int fd;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    BWPRINTF("error creating socket: %s", strerror(errno));
    return -1;
  }

  memset(&saddr, 0, sizeof(saddr));
  saddr.sun_family = AF_UNIX;
  memcpy(saddr.sun_path, sockpath, strlen(sockpath));

  if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    BWPRINTF("error connecting to socket %s: %s", sockpath, strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static int ctl_talk(int fd, struct log_ctlmsg* msg, char* rsp, int rsplen)
{
  int rc;

  if ((rc = write(fd, msg, sizeof(*msg))) < 0) {
    BWPRINTF("error sending ctl request: %s", strerror(errno));
    return -1;
  } else if (rc < sizeof(*msg)) {
    BWPRINTF("short ctl write (%d/%zd bytes)", rc, sizeof(*msg));
    return -1;
  }

  if (!rsplen)
    return 0;

  if ((rc = read(fd, rsp, rsplen)) < 0) {
    BWPRINTF("error reading ctl response: %s", strerror(errno));
    return -1;
  } else if (rc < rsplen) {
    BWPRINTF("short ctl read (%d/%d bytes)", rc, rsplen);
    return -1;
  }

  return 0;
}

static int ctl_get_shmem(int fd, struct writelog* wl)
{
  struct log_ctlmsg req;
  char rsp[CTLRSPLEN_SHMP + 1];
  int rc;

  memset(&req, 0, sizeof(req));
  memset(rsp, 0, sizeof(rsp));

  memcpy(req.msg, LOGCMD_SHMP, 4);
  if ((rc = ctl_talk(fd, &req, rsp, CTLRSPLEN_SHMP)) < 0) {
    BWPRINTF("error getting shared memory parameters");
    return -1;
  }

  memcpy(&wl->shmsize, rsp, sizeof(wl->shmsize));
  wl->shmpath = strdup(rsp + sizeof(wl->shmsize));

  BDPRINTF("shared memory parameters: size: %u, path: %s",
	   wl->shmsize, wl->shmpath);

  return 0;
}

static void ctlmsg_init(struct log_ctlmsg* msg, const char* cmd)
{
  memset(msg, 0, sizeof(*msg));
  memcpy(msg->msg, cmd, 4);
}

static int ctl_get_writes(int fd)
{
  struct log_ctlmsg req;
  char rsp[CTLRSPLEN_GET];
  int rc;

  ctlmsg_init(&req, LOGCMD_GET);

  if ((rc = ctl_talk(fd, &req, rsp, CTLRSPLEN_GET)) < 0) {
    BWPRINTF("error getting writes");
    return -1;
  }

  return 0;
}

static int ctl_peek_writes(int fd)
{
  struct log_ctlmsg req;
  char rsp[CTLRSPLEN_PEEK];
  int rc;

  ctlmsg_init(&req, LOGCMD_PEEK);

  if ((rc = ctl_talk(fd, &req, rsp, CTLRSPLEN_PEEK)) < 0) {
    BWPRINTF("error peeking writes");
    return -1;
  }

  return 0;
}

/* submit pending requests */
static int ctl_kick(int fd)
{
  struct log_ctlmsg req;
  int rc;

  ctlmsg_init(&req, LOGCMD_KICK);

  if ((rc = ctl_talk(fd, &req, NULL, 0)) < 0) {
    BWPRINTF("error kicking ring");
    return -1;
  }

  return 0;
}

static int ctl_clear_writes(int fd)
{
  struct log_ctlmsg req;
  char rsp[CTLRSPLEN_CLEAR];
  int rc;

  ctlmsg_init(&req, LOGCMD_CLEAR);

  if ((rc = ctl_talk(fd, &req, rsp, CTLRSPLEN_CLEAR)) < 0) {
    BWPRINTF("error clearing writes");
    return -1;
  }

  return 0;
}

static int writelog_map(struct writelog* wl)
{
  int fd;
  void* shm;

  if ((fd = shm_open(wl->shmpath, O_RDWR, 0750)) < 0) {
    BWPRINTF("could not open shared memory at %s: %s", wl->shmpath,
	     strerror(errno));
    return -1;
  }

  wl->shm = mmap(NULL, wl->shmsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (wl->shm == MAP_FAILED) {
    BWPRINTF("could not mmap write log shm: %s", strerror(errno));
    return -1;
  }
  wl->cur = wl->shm;
  wl->inflight = 0;
  wl->dhd = wl->dtl = sdatastart(wl->shm);

  BDPRINTF("shm cookie: 0x%x, data size: %u", *((uint32_t*)wl->shm),
	   dring_avail(wl));

  wl->sring = sringstart(wl->shm);
  /* need some thought about what to do on reconnect */
  FRONT_RING_INIT(&wl->fring, wl->sring, SRINGSIZE);

  return 0;
}

static int writelog_dump(struct writelog* wl)
{
  struct disk_range* range = wl->shm;

  for (range = wl->shm; (void*)range < bmend(wl->shm); range++) {
    if (!range->count)
      break;

    BDPRINTF("dirty extent: %"PRIu64":%u",
	     range->sector, range->count);
  }

  return 0;
}

/* walk dirty map and enqueue read requests.
 * returns:  0 when entire bitmap has been enqueued,
 *           1 when the ring is full
 *          -1 on error
 */
static int writelog_enqueue_requests(struct writelog* wl)
{
  struct disk_range* range = wl->shm;
  log_request_t* req;

  for (range = wl->cur; (void*)range < bmend(wl->shm); range++) {
    if (!range->count)
      break;

    if (RING_FULL(&wl->fring))
	break;

    /* insert range into request stream */
    /* 1. get next request slot from ring */
    /* 2. ensure enough shm space is available */
    
    BDPRINTF("enqueueing dirty extent: %"PRIu64":%u (ring space: %d/%d)",
	     range->sector, range->count, RING_FREE_REQUESTS(&wl->fring),
	     RING_SIZE(&wl->fring));

    req = RING_GET_REQUEST(&wl->fring, wl->fring.req_prod_pvt);

    req->sector = range->sector;
    req->count = range->count;
    /* ... */
    req->offset = 0;

    wl->fring.req_prod_pvt++;
    wl->inflight++;
  }

  wl->cur = range;

  if (range->count)
    return 1;

  return 0;
}

static int writelog_dequeue_responses(struct writelog* wl)
{
  RING_IDX rstart, rend;
  log_response_t rsp;

  rstart = wl->fring.rsp_cons;
  rend = wl->sring->rsp_prod;

  BDPRINTF("ring kicked (start = %u, end = %u)", rstart, rend);

  while (rstart != rend) {
    memcpy(&rsp, RING_GET_RESPONSE(&wl->fring, rstart), sizeof(rsp));
    BDPRINTF("ctl: read response %"PRIu64":%u", rsp.sector, rsp.count);
    wl->fring.rsp_cons = ++rstart;
    wl->inflight--;
  }

  return 0;
}

static int writelog_free(struct writelog* wl)
{
  if (wl->shmpath) {
    free(wl->shmpath);
    wl->shmpath = NULL;
  }
  if (wl->shm) {
    munmap(wl->shm, wl->shmsize);
    wl->shm = NULL;
  }

  return 0;
}

int get_writes(struct writelog* wl, int fd, int peek)
{
  int rc;

  if (peek)
    rc = ctl_peek_writes(fd);
  else
    rc = ctl_get_writes(fd);

  if (rc < 0)
    return rc;

  wl->cur = wl->shm;

  return 0;
}

int await_responses(struct writelog* wl, int fd)
{
  struct log_ctlmsg msg;
  int rc;

  /* sit on socket waiting for kick */
  if ((rc = read(fd, &msg, sizeof(msg))) < 0) {
    BWPRINTF("error reading from control socket: %s", strerror(errno));
    return -1;
  } else if (!rc) {
    BWPRINTF("EOF on control socket");
    return -1;
  } else if (rc < sizeof(msg)) {
	  BWPRINTF("short reply (%d/%d bytes)", rc, (int) sizeof(msg));
    return -1;
  }

  if (strncmp(msg.msg, LOGCMD_KICK, 4)) {
    BWPRINTF("Unknown message received: %.4s", msg.msg);
    return -1;
  }

  if (writelog_dequeue_responses(wl) < 0)
    return -1;

  return 0;
}

/* read_loop:
 * 1. extract dirty bitmap
 * 2. feed as much as possible onto ring
 * 3. kick
 * 4. as responses come back, feed more of the dirty bitmap
 *    into the ring
 * 5. when entire bitmap has been queued, go to 1?
 */
int read_loop(struct writelog* wl, int fd)
{
  int rc;

  if (get_writes(wl, fd, 1) < 0)
    return -1;
  writelog_dump(wl);

  do {
    rc = writelog_enqueue_requests(wl);

    if (RING_FREE_REQUESTS(&wl->fring) < RING_SIZE(&wl->fring))
      RING_PUSH_REQUESTS(&wl->fring);
    if (ctl_kick(fd) < 0)
      return -1;

    /* collect responses */
    if (wl->inflight && await_responses(wl, fd) < 0)
      return -1;
  } while (rc > 0);

  return rc;
}

int main(int argc, char* argv[])
{
  int fd;
  struct writelog wl;
  char cmd;

  if (argc < 2) {
    usage();
    return 1;
  }

  if (argc < 3)
    cmd = 'p';
  else
    cmd = argv[2][0];
    
  fd = tdctl_open(argv[1]);

  if (ctl_get_shmem(fd, &wl) < 0)
    return 1;

  if (writelog_map(&wl) < 0) {
    BWPRINTF("Error mapping write log: %s", strerror(errno));
    return 1;
  }

  switch (cmd) {
  case 'p':
    if (get_writes(&wl, fd, 1) < 0)
      return 1;
    writelog_dump(&wl);
    break;
  case 'c':
    if (ctl_clear_writes(fd) < 0)
      return 1;
    break;
  case 'g':
    if (get_writes(&wl, fd, 0) < 0)
      return 1;
    writelog_dump(&wl);
    break;
  case 'r':
    if (read_loop(&wl, fd) < 0)
      return 1;
    break;
  default:
    usage();
    return 1;
  }

  writelog_free(&wl);
  close(fd);

  return 0;
}
