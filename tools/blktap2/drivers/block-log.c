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

/* Driver to sit on top of another disk and log writes, in order
 * to synchronize two distinct disks
 *
 * On receipt of a control request it can export a list of dirty
 * sectors in the following format:
 * struct writerange {
 *   u64 sector;
 *   u32 count;
 * }
 * terminated by { 0, 0 }
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "xc_bitops.h"
#include "log.h"
#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"

#define MAX_CONNECTIONS 1

typedef struct poll_fd {
  int          fd;
  event_id_t   id;
} poll_fd_t;

struct tdlog_state {
  uint64_t     size;

  void*        writelog;

  char*        ctlpath;
  poll_fd_t    ctl;

  int          connected;
  poll_fd_t    connections[MAX_CONNECTIONS];

  char*        shmpath;
  void*        shm;

  log_sring_t* sring;
  log_back_ring_t bring;
};

#define BDPRINTF(_f, _a...) syslog (LOG_DEBUG, "log: " _f "\n", ## _a)

#define BWPRINTF(_f, _a...) syslog (LOG_WARNING, "log: " _f "\n", ## _a)

static void ctl_accept(event_id_t, char, void *);
static void ctl_request(event_id_t, char, void *);

/* -- write log -- */

/* large flat bitmaps don't scale particularly well either in size or scan
 * time, but they'll do for now */

static int writelog_create(struct tdlog_state *s)
{
  uint64_t bmsize;

  bmsize = bitmap_size(s->size);

  BDPRINTF("allocating %"PRIu64" bytes for dirty bitmap", bmsize);

  s->writelog = bitmap_alloc(s->size);
  if (!s->writelog) {
    BWPRINTF("could not allocate dirty bitmap of size %"PRIu64, bmsize);
    return -1;
  }

  return 0;
}

static int writelog_free(struct tdlog_state *s)
{
  if (s->writelog)
    free(s->writelog);

  return 0;
}

static int writelog_set(struct tdlog_state* s, uint64_t sector, int count)
{
  int i;

  for (i = 0; i < count; i++) 
    set_bit(sector + i, s->writelog);

  return 0;
}

/* if end is 0, clear to end of disk */
int writelog_clear(struct tdlog_state* s, uint64_t start, uint64_t end)
{
  if (!end)
    end = s->size;

  /* clear to word boundaries */
  while (BITMAP_SHIFT(start))
    clear_bit(start++, s->writelog);
  while (BITMAP_SHIFT(end))
    clear_bit(end--, s->writelog);

  memset(s->writelog + start / BITS_PER_LONG, 0, (end - start) >> 3);

  return 0;
}

/* returns last block exported (may not be end of disk if shm region
 * overflows) */
static uint64_t writelog_export(struct tdlog_state* s)
{
  struct disk_range* range = s->shm;
  uint64_t i = 0;

  BDPRINTF("sector count: %"PRIu64, s->size);

  for (i = 0; i < s->size; i++) {
    if (test_bit(i, s->writelog)) {
      /* range start */
      range->sector = i;
      range->count = 1;
      /* find end */
      for (i++; i < s->size && test_bit(i, s->writelog); i++)
	range->count++;

      BDPRINTF("export: dirty extent %"PRIu64":%u",
	       range->sector, range->count);
      range++;

      /* out of space in shared memory region */
      if ((void*)range >= bmend(s->shm)) {
	BDPRINTF("out of space in shm region at sector %"PRIu64, i);
	return i;
      }

      /* undo forloop increment */
      i--;
    }
  }

  /* NULL-terminate range list */
  range->sector = 0;
  range->count = 0;

  return i;
}

/* -- communication channel -- */

/* remove FS special characters in up to len bytes of path */
static inline void path_escape(char* path, size_t len) {
  int i;

  for (i = 0; i < len && path[i]; i++)
    if (strchr(":/", path[i]))
      path[i] = '_';
}

static char* ctl_makepath(const char* name, const char* ext)
{
  char* res;
  char *file;

  file = strrchr(name, '/');
  if (!file) {
    BWPRINTF("invalid name %s\n", name);
    return NULL;
  }

  if (asprintf(&res, BLKTAP_CTRL_DIR "/log_%s.%s", file, ext) < 0) {
    BWPRINTF("could not allocate path");
    return NULL;
  }

  path_escape(res + strlen(BLKTAP_CTRL_DIR) + 5, strlen(file));

  return res;
}

static int shmem_open(struct tdlog_state* s, const char* name)
{
  int i, l, fd;

  /* device name -> path */
  if (asprintf(&s->shmpath, "/log_%s.wlog", name) < 0) {
    BWPRINTF("could not allocate shm path");
    return -1;
  }

  path_escape(s->shmpath + 5, strlen(name));

  if ((fd = shm_open(s->shmpath, O_CREAT|O_RDWR, 0750)) < 0) {
    BWPRINTF("could not open shared memory file %s: %s", s->shmpath,
	     strerror(errno));
    goto err;
  }
  if (ftruncate(fd, SHMSIZE) < 0) {
    BWPRINTF("error truncating shmem to size %u", SHMSIZE);
    close(fd);
    goto err;
  }

  s->shm = mmap(NULL, SHMSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (s->shm == MAP_FAILED) {
    BWPRINTF("could not mmap write log shm: %s", strerror(errno));
    goto err;
  }
  return 0;

  err:
  s->shm = NULL;
  free(s->shmpath);
  s->shmpath = NULL;
  return -1;
}

static int shmem_close(struct tdlog_state* s)
{
  if (s->shm) {
    munmap(s->shm, SHMSIZE);
    s->shm = NULL;
  }

  if (s->shmpath) {
    shm_unlink(s->shmpath);
    s->shmpath = NULL;
  }

  return 0;
}

/* control socket */

static int ctl_open(struct tdlog_state* s, const char* name)
{
  struct sockaddr_un saddr;

  if (!(s->ctlpath = ctl_makepath(name, "ctl")))
    return -1;

  if ((s->ctl.fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    BWPRINTF("error opening control socket: %s", strerror(errno));
    goto err;
  }

  memset(&saddr, 0, sizeof(saddr));
  saddr.sun_family = AF_UNIX;
  memcpy(saddr.sun_path, s->ctlpath, strlen(s->ctlpath));
  if (unlink(s->ctlpath) && errno != ENOENT) {
    BWPRINTF("error unlinking old socket path %s: %s", s->ctlpath,
	     strerror(errno));
    goto err_sock;
  }
    
  if (bind(s->ctl.fd, (const struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    BWPRINTF("error binding control socket to %s: %s", s->ctlpath,
	     strerror(errno));
    goto err_sock;
  }

  if (listen(s->ctl.fd, 1) < 0) {
    BWPRINTF("error listening on control socket: %s", strerror(errno));
    goto err_sock;
  }

  s->ctl.id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					    s->ctl.fd, 0, ctl_accept, s);
  if (s->ctl.id < 0) {
    BWPRINTF("error register event handler: %s", strerror(s->ctl.id));
    goto err_sock;
  }

  return 0;

  err_sock:
  close(s->ctl.fd);
  s->ctl.fd = -1;
  err:
  free(s->ctlpath);
  s->ctlpath = NULL;

  return -1;
}

static int ctl_close(struct tdlog_state* s)
{
  while (s->connected) {
    s->connected--;
    tapdisk_server_unregister_event(s->connections[s->connected].id);
    close(s->connections[s->connected].fd);
    s->connections[s->connected].fd = -1;
    s->connections[s->connected].id = 0;
  }

  if (s->ctl.fd >= 0) {
    tapdisk_server_unregister_event(s->ctl.id);
    close(s->ctl.fd);
    s->ctl.fd = -1;
    s->ctl.id = 0;
  }

  if (s->ctlpath) {
    unlink(s->ctlpath);
    free(s->ctlpath);
    s->ctlpath = NULL;
  }

  /* XXX this must be fixed once requests are actually in flight */
  /* could just drain the existing ring here first */
  if (s->sring) {
    SHARED_RING_INIT(s->sring);
    BACK_RING_INIT(&s->bring, s->sring, SRINGSIZE);
  }

  return 0;
}

/* walk list of open sockets, close matching fd */
static int ctl_close_sock(struct tdlog_state* s, int fd)
{
  int i;

  for (i = 0; i < s->connected; i++) {
    if (s->connections[i].fd == fd) {
      tapdisk_server_unregister_event(s->connections[i].id);
      close(s->connections[i].fd);
      s->connections[i].fd = -1;
      s->connections[i].id = 0;
      s->connected--;
      return 0;
    }
  }

  BWPRINTF("requested to close unknown socket %d", fd);
  return -1;
}

static void ctl_accept(event_id_t id, char mode, void *private)
{
  struct tdlog_state* s = (struct tdlog_state *)private;
  int fd;
  event_id_t cid;

  if ((fd = accept(s->ctl.fd, NULL, NULL)) < 0) {
    BWPRINTF("error accepting control connection: %s", strerror(errno));
    return;
  }

  if (s->connected) {
    BWPRINTF("control session in progress, closing new connection");
    close(fd);
    return;
  }

  cid = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
				      fd, 0, ctl_request, s);
  if (cid < 0) {
    BWPRINTF("error registering connection event handler: %s", strerror(cid));
    close(fd);
    return;
  }

  s->connections[s->connected].fd = fd;
  s->connections[s->connected].id = cid;
  s->connected++;
}

/* response format: 4 bytes shmsize, 0-terminated path */
static int ctl_get_shmpath(struct tdlog_state* s, int fd)
{
  char msg[CTLRSPLEN_SHMP + 1];
  uint32_t sz;
  int rc;

  BDPRINTF("ctl: sending shared memory parameters (size: %u, path: %s)",
	   SHMSIZE, s->shmpath);

  /* TMP: sanity-check shm */
  sz = 0xdeadbeef;
  memcpy(s->shm, &sz, sizeof(sz));

  sz = SHMSIZE;
  memcpy(msg, &sz, sizeof(sz));
  snprintf(msg + sizeof(sz), sizeof(msg) - sizeof(sz), "%s", s->shmpath);
  if ((rc = write(fd, msg, CTLRSPLEN_SHMP)) < 0) {
    BWPRINTF("error writing shmpath: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int ctl_peek_writes(struct tdlog_state* s, int fd)
{
  int rc;

  BDPRINTF("ctl: peeking bitmap");

  writelog_export(s);

  if ((rc = write(fd, "done", CTLRSPLEN_PEEK)) < 0) {
    BWPRINTF("error writing peek ack: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int ctl_clear_writes(struct tdlog_state* s, int fd)
{
  int rc;

  BDPRINTF("ctl: clearing bitmap");

  writelog_clear(s, 0, 0);

  if ((rc = write(fd, "done", CTLRSPLEN_CLEAR)) < 0) {
    BWPRINTF("error writing clear ack: %s", strerror(errno));
    return -1;
  }

  return 0;
}

/* get dirty bitmap and clear it atomically */
static int ctl_get_writes(struct tdlog_state* s, int fd)
{
  int rc;

  BDPRINTF("ctl: getting bitmap");

  writelog_export(s);
  writelog_clear(s, 0, 0);

  if ((rc = write(fd, "done", CTLRSPLEN_GET)) < 0) {
    BWPRINTF("error writing get ack: %s", strerror(errno));
    return -1;
  }

  return 0;
}

/* get requests from ring */
static int ctl_kick(struct tdlog_state* s, int fd)
{
  RING_IDX reqstart, reqend;
  log_request_t req;

  /* XXX testing */
  RING_IDX rspstart, rspend;
  log_response_t rsp;
  struct log_ctlmsg msg;
  int rc;

  reqstart = s->bring.req_cons;
  reqend = s->sring->req_prod;

  xen_mb();
  BDPRINTF("ctl: ring kicked (start = %u, end = %u)", reqstart, reqend);

  while (reqstart != reqend) {
    /* XXX actually submit these! */
    RING_COPY_REQUEST(&s->bring, reqstart, &req);
    BDPRINTF("ctl: read request %"PRIu64":%u", req.sector, req.count);
    s->bring.req_cons = ++reqstart;

    rsp.sector = req.sector;
    rsp.count = req.count;
    memcpy(RING_GET_RESPONSE(&s->bring, s->bring.rsp_prod_pvt), &rsp,
	   sizeof(rsp));
    s->bring.rsp_prod_pvt++;
  }

  RING_PUSH_RESPONSES(&s->bring);
  memset(&msg, 0, sizeof(msg));
  memcpy(msg.msg, LOGCMD_KICK, 4);
  if ((rc = write(fd, &msg, sizeof(msg))) < 0) {
    BWPRINTF("error sending notify: %s", strerror(errno));
    return -1;
  } else if (rc < sizeof(msg)) {
    BWPRINTF("short notify write (%d/%zd)", rc, sizeof(msg));
    return -1;
  }

  return 0;
}

static int ctl_do_request(struct tdlog_state* s, int fd, struct log_ctlmsg* msg)
{
  if (!strncmp(msg->msg, LOGCMD_SHMP, 4)) {
    return ctl_get_shmpath(s, fd);
  } else if (!strncmp(msg->msg, LOGCMD_PEEK, 4)) {
    return ctl_peek_writes(s, fd);
  } else if (!strncmp(msg->msg, LOGCMD_CLEAR, 4)) {
    return ctl_clear_writes(s, fd);
  } else if (!strncmp(msg->msg, LOGCMD_GET, 4)) {
    return ctl_get_writes(s, fd);
  } else if (!strncmp(msg->msg, LOGCMD_KICK, 4)) {
    return ctl_kick(s, fd);
  }

  BWPRINTF("unknown control request %.4s", msg->msg);
  return -1;
}

static inline int ctl_find_connection(struct tdlog_state *s, event_id_t id)
{
  int i;

  for (i = 0; i < s->connected; i++)
    if (s->connections[i].id == id)
      return s->connections[i].fd;

  BWPRINTF("unrecognized event callback id %d", id);
  return -1;
}

static void ctl_request(event_id_t id, char mode, void *private)
{
  struct tdlog_state* s = (struct tdlog_state*)private;
  struct log_ctlmsg msg;
  int rc, i, fd = -1;

  fd = ctl_find_connection(s, id);
  if (fd == -1)
    return;

  if ((rc = read(fd, &msg, sizeof(msg))) < 0) {
    BWPRINTF("error reading from ctl socket %d, closing: %s", fd,
	     strerror(errno));
    ctl_close_sock(s, fd);
    return;
  } else if (rc == 0) {
    BDPRINTF("ctl_request: EOF, closing socket");
    ctl_close_sock(s, fd);
    return;
  } else if (rc < sizeof(msg)) {
    BWPRINTF("short request received (%d/%zd bytes), ignoring", rc,
	     sizeof(msg));
    return;
  }

  ctl_do_request(s, fd, &msg);
}

/* -- interface -- */

static int tdlog_close(td_driver_t*);

static int tdlog_open(td_driver_t* driver, const char* name, td_flag_t flags)
{
  struct tdlog_state* s = (struct tdlog_state*)driver->data;
  int rc;

  memset(s, 0, sizeof(*s));

  s->size = driver->info.size;

  if ((rc = writelog_create(s))) {
    tdlog_close(driver);
    return rc;
  }
  if ((rc = shmem_open(s, name))) {
    tdlog_close(driver);
    return rc;
  }
  if ((rc = ctl_open(s, name))) {
    tdlog_close(driver);
    return rc;
  }

  s->sring = (log_sring_t*)sringstart(s->shm);
  SHARED_RING_INIT(s->sring);
  BACK_RING_INIT(&s->bring, s->sring, SRINGSIZE);

  BDPRINTF("opened ctl socket");

  return 0;
}

static int tdlog_close(td_driver_t* driver)
{
  struct tdlog_state* s = (struct tdlog_state*)driver->data;

  ctl_close(s);
  shmem_close(s);
  writelog_free(s);

  return 0;
}

static void tdlog_queue_read(td_driver_t* driver, td_request_t treq)
{
  td_forward_request(treq);
}

static void tdlog_queue_write(td_driver_t* driver, td_request_t treq)
{
  struct tdlog_state* s = (struct tdlog_state*)driver->data;
  int rc;

  writelog_set(s, treq.sec, treq.secs);
  td_forward_request(treq);
}

static int tdlog_get_parent_id(td_driver_t* driver, td_disk_id_t* id)
{
  return -EINVAL;
}

static int tdlog_validate_parent(td_driver_t *driver,
				 td_driver_t *parent, td_flag_t flags)
{
  return 0;
}

struct tap_disk tapdisk_log = {
  .disk_type          = "tapdisk_log",
  .private_data_size  = sizeof(struct tdlog_state),
  .flags              = 0,
  .td_open            = tdlog_open,
  .td_close           = tdlog_close,
  .td_queue_read      = tdlog_queue_read,
  .td_queue_write     = tdlog_queue_write,
  .td_get_parent_id   = tdlog_get_parent_id,
  .td_validate_parent = tdlog_validate_parent,
};
