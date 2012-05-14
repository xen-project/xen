/* block-remus.c
 *
 * This disk sends all writes to a backup via a network interface before
 * passing them to an underlying device.
 * The backup is a bit more complicated:
 *  1. It applies all incoming writes to a ramdisk.
 *  2. When a checkpoint request arrives, it moves the ramdisk to
 *     a committing state and uses a new ramdisk for subsequent writes.
 *     It also acknowledges the request, to let the sender know it can
 *     release output.
 *  3. The ramdisk flushes its contents to the underlying driver.
 *  4. At failover, the backup waits for the in-flight ramdisk (if any) to
 *     drain before letting the domain be activated.
 *
 * The driver determines whether it is the client or server by attempting
 * to bind to the replication address. If the address is not local,
 * the driver acts as client.
 *
 * The following messages are defined for the replication stream:
 * 1. write request
 *    "wreq"      4
 *    num_sectors 4
 *    sector      8
 *    buffer      (num_sectors * sector_size)
 * 2. submit request (may be used as a barrier
 *    "sreq"      4
 * 3. commit request
 *    "creq"      4
 * After a commit request, the client must wait for a competion message:
 * 4. completion
 *    "done"      4
 */

/* due to architectural choices in tapdisk, block-buffer is forced to
 * reimplement some code which is meant to be private */
#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "hashtable.h"
#include "hashtable_itr.h"
#include "hashtable_utility.h"

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/stat.h>

/* timeout for reads and writes in ms */
#define HEARTBEAT_MS 1000
#define RAMDISK_HASHSIZE 128

/* connect retry timeout (seconds) */
#define REMUS_CONNRETRY_TIMEOUT 10

#define RPRINTF(_f, _a...) syslog (LOG_DEBUG, "remus: " _f, ## _a)

enum tdremus_mode {
	mode_invalid = 0,
	mode_unprotected,
	mode_primary,
	mode_backup
};

struct tdremus_req {
	uint64_t sector;
	int nb_sectors;
	char buf[4096];
};

struct req_ring {
	/* waste one slot to distinguish between empty and full */
	struct tdremus_req requests[MAX_REQUESTS * 2 + 1];
	unsigned int head;
	unsigned int tail;
};

/* TODO: This isn't very pretty, but to properly generate our own treqs (needed
 * by the backup) we need to know our td_vbt_t and td_image_t (blktap2
 * internals). As a proper fix, we should consider extending the tapdisk
 * interface with a td_create_request() function, or something similar.
 *
 * For now, we just grab the vbd in the td_open() command, and the td_image_t
 * from the first read request.
 */
td_vbd_t *device_vbd = NULL;
td_image_t *remus_image = NULL;
struct tap_disk tapdisk_remus;

struct ramdisk {
	size_t sector_size;
	struct hashtable* h;
	/* when a ramdisk is flushed, h is given a new empty hash for writes
	 * while the old ramdisk (prev) is drained asynchronously.
	 */
	struct hashtable* prev;
	/* count of outstanding requests to the base driver */
	size_t inflight;
	/* prev holds the requests to be flushed, while inprogress holds
	 * requests being flushed. When requests complete, they are removed
	 * from inprogress.
	 * Whenever a new flush is merged with ongoing flush (i.e, prev),
	 * we have to make sure that none of the new requests overlap with
	 * ones in "inprogress". If it does, keep it back in prev and dont issue
	 * IO until the current one finishes. If we allow this IO to proceed,
	 * we might end up with two "overlapping" requests in the disk's queue and
	 * the disk may not offer any guarantee on which one is written first.
	 * IOW, make sure we dont create a write-after-write time ordering constraint.
	 * 
	 */
	struct hashtable* inprogress;
};

/* the ramdisk intercepts the original callback for reads and writes.
 * This holds the original data. */
/* Might be worth making this a static array in struct ramdisk to avoid
 * a malloc per request */

struct tdremus_state;

struct ramdisk_cbdata {
	td_callback_t cb;
	void* private;
	char* buf;
	struct tdremus_state* state;
};

struct ramdisk_write_cbdata {
	struct tdremus_state* state;
	char* buf;
};

typedef void (*queue_rw_t) (td_driver_t *driver, td_request_t treq);

/* poll_fd type for blktap2 fd system. taken from block_log.c */
typedef struct poll_fd {
	int        fd;
	event_id_t id;
} poll_fd_t;

struct tdremus_state {
//  struct tap_disk* driver;
	void* driver_data;

  /* XXX: this is needed so that the server can perform operations on
   * the driver from the stream_fd event handler. fix this. */
	td_driver_t *tdremus_driver;

	/* TODO: we may wish to replace these two FIFOs with a unix socket */
	char*     ctl_path; /* receive flush instruction here */
	poll_fd_t ctl_fd;     /* io_fd slot for control FIFO */
	char*     msg_path; /* output completion message here */
	poll_fd_t msg_fd;

  /* replication host */
	struct sockaddr_in sa;
	poll_fd_t server_fd;    /* server listen port */
	poll_fd_t stream_fd;     /* replication channel */

	/* queue write requests, batch-replicate at submit */
	struct req_ring write_ring;

	/* ramdisk data*/
	struct ramdisk ramdisk;

	/* mode methods */
	enum tdremus_mode mode;
	int (*queue_flush)(td_driver_t *driver);
};

typedef struct tdremus_wire {
	uint32_t op;
	uint64_t id;
	uint64_t sec;
	uint32_t secs;
} tdremus_wire_t;

#define TDREMUS_READ "rreq"
#define TDREMUS_WRITE "wreq"
#define TDREMUS_SUBMIT "sreq"
#define TDREMUS_COMMIT "creq"
#define TDREMUS_DONE "done"
#define TDREMUS_FAIL "fail"

/* primary read/write functions */
static void primary_queue_read(td_driver_t *driver, td_request_t treq);
static void primary_queue_write(td_driver_t *driver, td_request_t treq);

/* backup read/write functions */
static void backup_queue_read(td_driver_t *driver, td_request_t treq);
static void backup_queue_write(td_driver_t *driver, td_request_t treq);

/* unpritected read/write functions */
static void unprotected_queue_read(td_driver_t *driver, td_request_t treq);
static void unprotected_queue_write(td_driver_t *driver, td_request_t treq);

static int tdremus_close(td_driver_t *driver);

static int switch_mode(td_driver_t *driver, enum tdremus_mode mode);
static int ctl_respond(struct tdremus_state *s, const char *response);

/* ring functions */
static inline unsigned int ring_next(struct req_ring* ring, unsigned int pos)
{
	if (++pos >= MAX_REQUESTS * 2 + 1)
		return 0;

	return pos;
}

static inline int ring_isempty(struct req_ring* ring)
{
	return ring->head == ring->tail;
}

static inline int ring_isfull(struct req_ring* ring)
{
	return ring_next(ring, ring->tail) == ring->head;
}
/* Prototype declarations */
static int ramdisk_flush(td_driver_t *driver, struct tdremus_state* s);

/* functions to create and sumbit treq's */

static void
replicated_write_callback(td_request_t treq, int err)
{
	struct tdremus_state *s = (struct tdremus_state *) treq.cb_data;
	td_vbd_request_t *vreq;
	int i;
	uint64_t start;
	vreq = (td_vbd_request_t *) treq.private;

	/* the write failed for now, lets panic. this is very bad */
	if (err) {
		RPRINTF("ramdisk write failed, disk image is not consistent\n");
		exit(-1);
	}

	/* The write succeeded. let's pull the vreq off whatever request list
	 * it is on and free() it */
	list_del(&vreq->next);
	free(vreq);

	s->ramdisk.inflight--;
	start = treq.sec;
	for (i = 0; i < treq.secs; i++) {
		hashtable_remove(s->ramdisk.inprogress, &start);
		start++;
	}
	free(treq.buf);

	if (!s->ramdisk.inflight && !s->ramdisk.prev) {
		/* TODO: the ramdisk has been flushed */
	}
}

static inline int
create_write_request(struct tdremus_state *state, td_sector_t sec, int secs, char *buf)
{
	td_request_t treq;
	td_vbd_request_t *vreq;

	treq.op      = TD_OP_WRITE;
	treq.buf     = buf;
	treq.sec     = sec;
	treq.secs    = secs;
	treq.image   = remus_image;
	treq.cb      = replicated_write_callback;
	treq.cb_data = state;
	treq.id      = 0;
	treq.sidx    = 0;

	vreq         = calloc(1, sizeof(td_vbd_request_t));
	treq.private = vreq;

	if(!vreq)
		return -1;

	vreq->submitting = 1;
	INIT_LIST_HEAD(&vreq->next);
	tapdisk_vbd_move_request(treq.private, &device_vbd->pending_requests);

	/* TODO:
	 * we should probably leave it up to the caller to forward the request */
	td_forward_request(treq);

	vreq->submitting--;

	return 0;
}


/* http://www.concentric.net/~Ttwang/tech/inthash.htm */
static unsigned int uint64_hash(void* k)
{
	uint64_t key = *(uint64_t*)k;

	key = (~key) + (key << 18);
	key = key ^ (key >> 31);
	key = key * 21;
	key = key ^ (key >> 11);
	key = key + (key << 6);
	key = key ^ (key >> 22);

	return (unsigned int)key;
}

static int rd_hash_equal(void* k1, void* k2)
{
	uint64_t key1, key2;

	key1 = *(uint64_t*)k1;
	key2 = *(uint64_t*)k2;

	return key1 == key2;
}

static int ramdisk_read(struct ramdisk* ramdisk, uint64_t sector,
			int nb_sectors, char* buf)
{
	int i;
	char* v;
	uint64_t key;

	for (i = 0; i < nb_sectors; i++) {
		key = sector + i;
		/* check whether it is queued in a previous flush request */
		if (!(ramdisk->prev && (v = hashtable_search(ramdisk->prev, &key)))) {
			/* check whether it is an ongoing flush */
			if (!(ramdisk->inprogress && (v = hashtable_search(ramdisk->inprogress, &key))))
				return -1;
		}
		memcpy(buf + i * ramdisk->sector_size, v, ramdisk->sector_size);
	}

	return 0;
}

static int ramdisk_write_hash(struct hashtable* h, uint64_t sector, char* buf,
			      size_t len)
{
	char* v;
	uint64_t* key;

	if ((v = hashtable_search(h, &sector))) {
		memcpy(v, buf, len);
		return 0;
	}

	if (!(v = malloc(len))) {
		DPRINTF("ramdisk_write_hash: malloc failed\n");
		return -1;
	}
	memcpy(v, buf, len);
	if (!(key = malloc(sizeof(*key)))) {
		DPRINTF("ramdisk_write_hash: error allocating key\n");
		free(v);
		return -1;
	}
	*key = sector;
	if (!hashtable_insert(h, key, v)) {
		DPRINTF("ramdisk_write_hash failed on sector %" PRIu64 "\n", sector);
		free(key);
		free(v);
		return -1;
	}

	return 0;
}

static inline int ramdisk_write(struct ramdisk* ramdisk, uint64_t sector,
				int nb_sectors, char* buf)
{
	int i, rc;

	for (i = 0; i < nb_sectors; i++) {
		rc = ramdisk_write_hash(ramdisk->h, sector + i,
					buf + i * ramdisk->sector_size,
					ramdisk->sector_size);
		if (rc)
			return rc;
	}

	return 0;
}

static int uint64_compare(const void* k1, const void* k2)
{
	uint64_t u1 = *(uint64_t*)k1;
	uint64_t u2 = *(uint64_t*)k2;

	/* u1 - u2 is unsigned */
	return u1 < u2 ? -1 : u1 > u2 ? 1 : 0;
}

/* set psectors to an array of the sector numbers in the hash, returning
 * the number of entries (or -1 on error) */
static int ramdisk_get_sectors(struct hashtable* h, uint64_t** psectors)
{
	struct hashtable_itr* itr;
	uint64_t* sectors;
	int count;

	if (!(count = hashtable_count(h)))
		return 0;

	if (!(*psectors = malloc(count * sizeof(uint64_t)))) {
		DPRINTF("ramdisk_get_sectors: error allocating sector map\n");
		return -1;
	}
	sectors = *psectors;

	itr = hashtable_iterator(h);
	count = 0;
	do {
		sectors[count++] = *(uint64_t*)hashtable_iterator_key(itr);
	} while (hashtable_iterator_advance(itr));
	free(itr);

	return count;
}

/*
  return -1 for OOM
  return -2 for merge lookup failure
  return -3 for WAW race
  return 0 on success.
*/
static int merge_requests(struct ramdisk* ramdisk, uint64_t start,
			size_t count, char **mergedbuf)
{
	char* buf;
	char* sector;
	int i;
	uint64_t *key;
	int rc = 0;

	if (!(buf = valloc(count * ramdisk->sector_size))) {
		DPRINTF("merge_request: allocation failed\n");
		return -1;
	}

	for (i = 0; i < count; i++) {
		if (!(sector = hashtable_search(ramdisk->prev, &start))) {
			DPRINTF("merge_request: lookup failed on %"PRIu64"\n", start);
			free(buf);
			rc = -2;
			goto fail;
		}

		/* Check inprogress requests to avoid waw non-determinism */
		if (hashtable_search(ramdisk->inprogress, &start)) {
			DPRINTF("merge_request: WAR RACE on %"PRIu64"\n", start);
			free(buf);
			rc = -3;
			goto fail;
		}
		/* Insert req into inprogress (brief period of duplication of hash entries until
		 * they are removed from prev. Read tracking would not be reading wrong entries)
		 */
		if (!(key = malloc(sizeof(*key)))) {
			DPRINTF("%s: error allocating key\n", __FUNCTION__);
			free(buf);			
			rc = -1;
			goto fail;
		}
		*key = start;
		if (!hashtable_insert(ramdisk->inprogress, key, NULL)) {
			DPRINTF("%s failed to insert sector %" PRIu64 " into inprogress hash\n", 
				__FUNCTION__, start);
			free(key);
			free(buf);
			rc = -1;
			goto fail;
		}
		memcpy(buf + i * ramdisk->sector_size, sector, ramdisk->sector_size);
		start++;
	}

	*mergedbuf = buf;
	return 0;
fail:
	for (start--; i >0; i--, start--)
		hashtable_remove(ramdisk->inprogress, &start);
	return rc;
}

/* The underlying driver may not handle having the whole ramdisk queued at
 * once. We queue what we can and let the callbacks attempt to queue more. */
/* NOTE: may be called from callback, while dd->private still belongs to
 * the underlying driver */
static int ramdisk_flush(td_driver_t *driver, struct tdremus_state* s)
{
	uint64_t* sectors;
	char* buf = NULL;
	uint64_t base, batchlen;
	int i, j, count = 0;

	// RPRINTF("ramdisk flush\n");

	if ((count = ramdisk_get_sectors(s->ramdisk.prev, &sectors)) <= 0)
		return count;

	/* Create the inprogress table if empty */
	if (!s->ramdisk.inprogress)
		s->ramdisk.inprogress = create_hashtable(RAMDISK_HASHSIZE,
							uint64_hash,
							rd_hash_equal);
	
	/*
	  RPRINTF("ramdisk: flushing %d sectors\n", count);
	*/

	/* sort and merge sectors to improve disk performance */
	qsort(sectors, count, sizeof(*sectors), uint64_compare);

	for (i = 0; i < count;) {
		base = sectors[i++];
		while (i < count && sectors[i] == sectors[i-1] + 1)
			i++;
		batchlen = sectors[i-1] - base + 1;

		j = merge_requests(&s->ramdisk, base, batchlen, &buf);
			
		if (j) {
			RPRINTF("ramdisk_flush: merge_requests failed:%s\n",
				j == -1? "OOM": (j==-2? "missing sector" : "WAW race"));
			if (j == -3) continue;
			free(sectors);
			return -1;
		}

		/* NOTE: create_write_request() creates a treq AND forwards it down
		 * the driver chain */
		// RPRINTF("forwarding write request at %" PRIu64 ", length: %" PRIu64 "\n", base, batchlen);
		create_write_request(s, base, batchlen, buf);
		//RPRINTF("write request at %" PRIu64 ", length: %" PRIu64 " forwarded\n", base, batchlen);

		s->ramdisk.inflight++;

		for (j = 0; j < batchlen; j++) {
			buf = hashtable_search(s->ramdisk.prev, &base);
			free(buf);
			hashtable_remove(s->ramdisk.prev, &base);
			base++;
		}
	}

	if (!hashtable_count(s->ramdisk.prev)) {
		/* everything is in flight */
		hashtable_destroy(s->ramdisk.prev, 0);
		s->ramdisk.prev = NULL;
	}

	free(sectors);

	// RPRINTF("ramdisk flush done\n");
	return 0;
}

/* flush ramdisk contents to disk */
static int ramdisk_start_flush(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	uint64_t* key;
	char* buf;
	int rc = 0;
	int i, j, count, batchlen;
	uint64_t* sectors;

	if (!hashtable_count(s->ramdisk.h)) {
		/*
		  RPRINTF("Nothing to flush\n");
		*/
		return 0;
	}

	if (s->ramdisk.prev) {
		/* a flush request issued while a previous flush is still in progress
		 * will merge with the previous request. If you want the previous
		 * request to be consistent, wait for it to complete. */
		if ((count = ramdisk_get_sectors(s->ramdisk.h, &sectors)) < 0)
			return count;

		for (i = 0; i < count; i++) {
			buf = hashtable_search(s->ramdisk.h, sectors + i);
			ramdisk_write_hash(s->ramdisk.prev, sectors[i], buf,
					   s->ramdisk.sector_size);
		}
		free(sectors);

		hashtable_destroy (s->ramdisk.h, 0);
	} else
		s->ramdisk.prev = s->ramdisk.h;

	/* We create a new hashtable so that new writes can be performed before
	 * the old hashtable is completely drained. */
	s->ramdisk.h = create_hashtable(RAMDISK_HASHSIZE, uint64_hash,
					rd_hash_equal);

	return ramdisk_flush(driver, s);
}


static int ramdisk_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	if (s->ramdisk.h) {
		RPRINTF("ramdisk already allocated\n");
		return 0;
	}

	s->ramdisk.sector_size = driver->info.sector_size;
	s->ramdisk.h = create_hashtable(RAMDISK_HASHSIZE, uint64_hash,
					rd_hash_equal);

	DPRINTF("Ramdisk started, %zu bytes/sector\n", s->ramdisk.sector_size);

	return 0;
}

/* common client/server functions */
/* mayberead: Time out after a certain interval. */
static int mread(int fd, void* buf, size_t len)
{
	fd_set rfds;
	int rc;
	size_t cur = 0;
	struct timeval tv = {
		.tv_sec = HEARTBEAT_MS / 1000,
		.tv_usec = (HEARTBEAT_MS % 1000) * 1000
	};

	if (!len)
		return 0;

	/* read first. Only select if read is incomplete. */
	rc = read(fd, buf, len);
	while (rc < 0 || cur + rc < len) {
		if (!rc) {
			RPRINTF("end-of-file");
			return -1;
		}
		if (rc < 0 && errno != EAGAIN) {
			RPRINTF("error during read: %s\n", strerror(errno));
			return -1;
		}
		if (rc > 0)
			cur += rc;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		if (!(rc = select(fd + 1, &rfds, NULL, NULL, &tv))) {
			RPRINTF("time out during read\n");
			return -1;
		} else if (rc < 0) {
			RPRINTF("error during select: %d\n", errno);
			return -1;
		}
		rc = read(fd, buf + cur, len - cur);
	}
	/*
	  RPRINTF("read %d bytes\n", cur + rc);
	*/

	return 0;
}

static int mwrite(int fd, void* buf, size_t len)
{
	fd_set wfds;
	size_t cur = 0;
	int rc;
	struct timeval tv = {
		.tv_sec = HEARTBEAT_MS / 1000,
		.tv_usec = (HEARTBEAT_MS % 1000) * 1000
	};

	if (!len)
		return 0;

	/* read first. Only select if read is incomplete. */
	rc = write(fd, buf, len);
	while (rc < 0 || cur + rc < len) {
		if (!rc) {
			RPRINTF("end-of-file");
			return -1;
		}
		if (rc < 0 && errno != EAGAIN) {
			RPRINTF("error during write: %s\n", strerror(errno));
			return -1;
		}
		if (rc > 0)
			cur += rc;

		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);
		if (!(rc = select(fd + 1, NULL, &wfds, NULL, &tv))) {
			RPRINTF("time out during write\n");
			return -1;
		} else if (rc < 0) {
			RPRINTF("error during select: %d\n", errno);
			return -1;
		}
		rc = write(fd, buf + cur, len - cur);
	}
	/*
	  RPRINTF("wrote %d bytes\n", cur + rc);
	*/

	return 0;
	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);
	select(fd + 1, NULL, &wfds, NULL, &tv);
}


static void inline close_stream_fd(struct tdremus_state *s)
{
	/* XXX: -2 is magic. replace with macro perhaps? */
	tapdisk_server_unregister_event(s->stream_fd.id);
	close(s->stream_fd.fd);
	s->stream_fd.fd = -2;
}

/* primary functions */
static void remus_client_event(event_id_t, char mode, void *private);
static void remus_connect_event(event_id_t id, char mode, void *private);
static void remus_retry_connect_event(event_id_t id, char mode, void *private);

static int primary_do_connect(struct tdremus_state *state)
{
	event_id_t id;
	int fd;
	int rc;
	int flags;

	RPRINTF("client connecting to %s:%d...\n", inet_ntoa(state->sa.sin_addr), ntohs(state->sa.sin_port));

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		RPRINTF("could not create client socket: %d\n", errno);
		return -1;
	}

	/* make socket nonblocking */
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;

	/* once we have created the socket and populated the address, we can now start
	 * our non-blocking connect. rather than duplicating code we trigger a timeout
	 * on the socket fd, which calls out nonblocking connect code
	 */
	if((id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT, fd, 0, remus_retry_connect_event, state)) < 0) {
		RPRINTF("error registering timeout client connection event handler: %s\n", strerror(id));
		/* TODO: we leak a fd here */
		return -1;
	}
	state->stream_fd.fd = fd;
	state->stream_fd.id = id;
	return 0;
}

static int primary_blocking_connect(struct tdremus_state *state)
{
	int fd;
	int id;
	int rc;
	int flags;

	RPRINTF("client connecting to %s:%d...\n", inet_ntoa(state->sa.sin_addr), ntohs(state->sa.sin_port));

	if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		RPRINTF("could not create client socket: %d\n", errno);
		return -1;
	}

	do {
		if ((rc = connect(fd, (struct sockaddr *)&state->sa,
		    sizeof(state->sa))) < 0)
		{
			if (errno == ECONNREFUSED) {
				RPRINTF("connection refused -- retrying in 1 second\n");
				sleep(1);
			} else {
				RPRINTF("connection failed: %d\n", errno);
				close(fd);
				return -1;
			}
		}
	} while (rc < 0);

	RPRINTF("client connected\n");

	/* make socket nonblocking */
	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		RPRINTF("error making socket nonblocking\n");
		close(fd);
		return -1;
	}

	if((id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, fd, 0, remus_client_event, state)) < 0) {
		RPRINTF("error registering client event handler: %s\n", strerror(id));
		close(fd);
		return -1;
	}

	state->stream_fd.fd = fd;
	state->stream_fd.id = id;
	return 0;
}

/* on read, just pass request through */
static void primary_queue_read(td_driver_t *driver, td_request_t treq)
{
	/* just pass read through */
	td_forward_request(treq);
}

/* TODO:
 * The primary uses mwrite() to write the contents of a write request to the
 * backup. This effectively blocks until all data has been copied into a system
 * buffer or a timeout has occured. We may wish to instead use tapdisk's
 * nonblocking i/o interface, tapdisk_server_register_event(), to set timeouts
 * and write data in an asynchronous fashion.
 */
static void primary_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	char header[sizeof(uint32_t) + sizeof(uint64_t)];
	uint32_t *sectors = (uint32_t *)header;
	uint64_t *sector = (uint64_t *)(header + sizeof(uint32_t));

	// RPRINTF("write: stream_fd.fd: %d\n", s->stream_fd.fd);

	/* -1 means we haven't connected yet, -2 means the connection was lost */
	if(s->stream_fd.fd == -1) {
		RPRINTF("connecting to backup...\n");
		primary_blocking_connect(s);
	}

	*sectors = treq.secs;
	*sector = treq.sec;

	if (mwrite(s->stream_fd.fd, TDREMUS_WRITE, strlen(TDREMUS_WRITE)) < 0)
		goto fail;
	if (mwrite(s->stream_fd.fd, header, sizeof(header)) < 0)
		goto fail;

	if (mwrite(s->stream_fd.fd, treq.buf, treq.secs * driver->info.sector_size) < 0)
		goto fail;

	td_forward_request(treq);

	return;

 fail:
	/* switch to unprotected mode and tell tapdisk to retry */
	RPRINTF("write request replication failed, switching to unprotected mode");
	switch_mode(s->tdremus_driver, mode_unprotected);
	td_complete_request(treq, -EBUSY);
}


static int client_flush(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	// RPRINTF("committing output\n");

	if (s->stream_fd.fd == -1)
		/* connection not yet established, nothing to flush */
		return 0;

	if (mwrite(s->stream_fd.fd, TDREMUS_COMMIT, strlen(TDREMUS_COMMIT)) < 0) {
		RPRINTF("error flushing output");
		close_stream_fd(s);
		return -1;
	}

	return 0;
}

static int server_flush(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	/* 
	 * Nothing to flush in beginning.
	 */
	if (!s->ramdisk.prev)
		return 0;
	/* Try to flush any remaining requests */
	return ramdisk_flush(driver, s);	
}

static int primary_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("activating client mode\n");

	tapdisk_remus.td_queue_read = primary_queue_read;
	tapdisk_remus.td_queue_write = primary_queue_write;
	s->queue_flush = client_flush;

	s->stream_fd.fd = -1;
	s->stream_fd.id = -1;

	return 0;
}

/* timeout callback */
static void remus_retry_connect_event(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;

	/* do a non-blocking connect */
	if (connect(s->stream_fd.fd, (struct sockaddr *)&s->sa, sizeof(s->sa))
	    && errno != EINPROGRESS)
	{
		if(errno == ECONNREFUSED || errno == ENETUNREACH || errno == EAGAIN || errno == ECONNABORTED)
		{
			/* try again in a second */
			tapdisk_server_unregister_event(s->stream_fd.id);
			if((id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT, s->stream_fd.fd, REMUS_CONNRETRY_TIMEOUT, remus_retry_connect_event, s)) < 0) {
				RPRINTF("error registering timeout client connection event handler: %s\n", strerror(id));
				return;
			}
			s->stream_fd.id = id;
		}
		else
		{
			/* not recoverable */
			RPRINTF("error connection to server %s\n", strerror(errno));
			return;
		}
	}
	else
	{
		/* the connect returned EINPROGRESS (nonblocking connect) we must wait for the fd to be writeable to determine if the connect worked */

		tapdisk_server_unregister_event(s->stream_fd.id);
		if((id = tapdisk_server_register_event(SCHEDULER_POLL_WRITE_FD, s->stream_fd.fd, 0, remus_connect_event, s)) < 0) {
			RPRINTF("error registering client connection event handler: %s\n", strerror(id));
			return;
		}
		s->stream_fd.id = id;
	}
}

/* callback when nonblocking connect() is finished */
/* called only by primary in unprotected state */
static void remus_connect_event(event_id_t id, char mode, void *private)
{
	int socket_errno;
	socklen_t socket_errno_size;
	struct tdremus_state *s = (struct tdremus_state *)private;

	/* check to se if the connect succeeded */
	socket_errno_size = sizeof(socket_errno);
	if (getsockopt(s->stream_fd.fd, SOL_SOCKET, SO_ERROR, &socket_errno, &socket_errno_size)) {
		RPRINTF("error getting socket errno\n");
		return;
	}

	RPRINTF("socket connect returned %d\n", socket_errno);

	if(socket_errno)
	{
		/* the connect did not succeed */

		if(socket_errno == ECONNREFUSED || socket_errno == ENETUNREACH || socket_errno == ETIMEDOUT
		   || socket_errno == ECONNABORTED || socket_errno == EAGAIN)
		{
			/* we can probably assume that the backup is down. just try again later */
			tapdisk_server_unregister_event(s->stream_fd.id);
			if((id = tapdisk_server_register_event(SCHEDULER_POLL_TIMEOUT, s->stream_fd.fd, REMUS_CONNRETRY_TIMEOUT, remus_retry_connect_event, s)) < 0) {
				RPRINTF("error registering timeout client connection event handler: %s\n", strerror(id));
				return;
			}
			s->stream_fd.id = id;
		}
		else
		{
			RPRINTF("socket connect returned %d, giving up\n", socket_errno);
		}
	}
	else
	{
		/* the connect succeeded */

		/* unregister this function and register a new event handler */
		tapdisk_server_unregister_event(s->stream_fd.id);
		if((id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, s->stream_fd.fd, 0, remus_client_event, s)) < 0) {
			RPRINTF("error registering client event handler: %s\n", strerror(id));
			return;
		}
		s->stream_fd.id = id;

		/* switch from unprotected to protected client */
		switch_mode(s->tdremus_driver, mode_primary);
	}
}


/* we install this event handler on the primary once we have connected to the backup */
/* wait for "done" message to commit checkpoint */
static void remus_client_event(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	char req[5];
	int rc;

	if (mread(s->stream_fd.fd, req, sizeof(req) - 1) < 0) {
		/* replication stream closed or otherwise broken (timeout, reset, &c) */
		RPRINTF("error reading from backup\n");
		close_stream_fd(s);
		return;
	}

	req[4] = '\0';

	if (!strcmp(req, TDREMUS_DONE))
		/* checkpoint committed, inform msg_fd */
		ctl_respond(s, TDREMUS_DONE);
	else {
		RPRINTF("received unknown message: %s\n", req);
		close_stream_fd(s);
	}

	return;
}

/* backup functions */
static void remus_server_event(event_id_t id, char mode, void *private);

/* returns the socket that receives write requests */
static void remus_server_accept(event_id_t id, char mode, void* private)
{
	struct tdremus_state* s = (struct tdremus_state *) private;

	int stream_fd;
	event_id_t cid;

	/* XXX: add address-based black/white list */
	if ((stream_fd = accept(s->server_fd.fd, NULL, NULL)) < 0) {
		RPRINTF("error accepting connection: %d\n", errno);
		return;
	}

	/* TODO: check to see if we are already replicating. if so just close the
	 * connection (or do something smarter) */
	RPRINTF("server accepted connection\n");

	/* add tapdisk event for replication stream */
	cid = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, stream_fd, 0,
					    remus_server_event, s);

	if(cid < 0) {
		RPRINTF("error registering connection event handler: %s\n", strerror(errno));
		close(stream_fd);
		return;
	}

	/* store replication file descriptor */
	s->stream_fd.fd = stream_fd;
	s->stream_fd.id = cid;
}

/* returns -2 if EADDRNOTAVAIL */
static int remus_bind(struct tdremus_state* s)
{
//  struct sockaddr_in sa;
	int opt;
	int rc = -1;

	if ((s->server_fd.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		RPRINTF("could not create server socket: %d\n", errno);
		return rc;
	}
	opt = 1;
	if (setsockopt(s->server_fd.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		RPRINTF("Error setting REUSEADDR on %d: %d\n", s->server_fd.fd, errno);

	if (bind(s->server_fd.fd, (struct sockaddr *)&s->sa, sizeof(s->sa)) < 0) {
		RPRINTF("could not bind server socket %d to %s:%d: %d %s\n", s->server_fd.fd,
			inet_ntoa(s->sa.sin_addr), ntohs(s->sa.sin_port), errno, strerror(errno));
		if (errno != EADDRINUSE)
			rc = -2;
		goto err_sfd;
	}
	if (listen(s->server_fd.fd, 10)) {
		RPRINTF("could not listen on socket: %d\n", errno);
		goto err_sfd;
	}

	/* The socket s now bound to the address and listening so we may now register
   * the fd with tapdisk */

	if((s->server_fd.id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
							    s->server_fd.fd, 0,
							    remus_server_accept, s)) < 0) {
		RPRINTF("error registering server connection event handler: %s",
			strerror(s->server_fd.id));
		goto err_sfd;
	}

	return 0;

 err_sfd:
	close(s->server_fd.fd);
	s->server_fd.fd = -1;

	return rc;
}

/* wait for latest checkpoint to be applied */
static inline int server_writes_inflight(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	if (!s->ramdisk.inflight && !s->ramdisk.prev)
		return 0;

	return 1;
}

/* Due to block device prefetching this code may be called on the server side
 * during normal replication. In this case we must return EBUSY, otherwise the
 * domain may be started with stale data.
 */
void backup_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int i;
	if(!remus_image)
		remus_image = treq.image;
	
	/* check if this read is queued in any currently ongoing flush */
	if (ramdisk_read(&s->ramdisk, treq.sec, treq.secs, treq.buf)) {
		/* TODO: Add to pending read hash */
		td_forward_request(treq);
	} else {
		/* complete the request */
		td_complete_request(treq, 0);
	}
}

/* see above */
void backup_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* on a server write, we know the domain has failed over. we must change our
	 * state to unprotected and then have the unprotected queue_write function
	 * handle the write
	 */

	switch_mode(driver, mode_unprotected);
	/* TODO: call the appropriate write function rather than return EBUSY */
	td_complete_request(treq, -EBUSY);
}

static int backup_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int fd;

	if (ramdisk_start(driver) < 0)
		return -1;

	tapdisk_remus.td_queue_read = backup_queue_read;
	tapdisk_remus.td_queue_write = backup_queue_write;
	s->queue_flush = server_flush;
	/* TODO set flush function */
	return 0;
}

static int server_do_wreq(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	static tdremus_wire_t twreq;
	char buf[4096];
	int len, rc;

	char header[sizeof(uint32_t) + sizeof(uint64_t)];
	uint32_t *sectors = (uint32_t *) header;
	uint64_t *sector =  (uint64_t *) &header[sizeof(uint32_t)];

	// RPRINTF("received write request\n");

	if (mread(s->stream_fd.fd, header, sizeof(header)) < 0)
		goto err;

	len = *sectors * driver->info.sector_size;

	//RPRINTF("writing %d sectors (%d bytes) starting at %" PRIu64 "\n", *sectors, len,
	// *sector);

	if (len > sizeof(buf)) {
		/* freak out! */
		RPRINTF("write request too large: %d/%u\n", len, (unsigned)sizeof(buf));
		return -1;
	}

	if (mread(s->stream_fd.fd, buf, len) < 0)
		goto err;

	if (ramdisk_write(&s->ramdisk, *sector, *sectors, buf) < 0)
		goto err;

	return 0;

 err:
	/* should start failover */
	RPRINTF("backup write request error\n");
	close_stream_fd(s);

	return -1;
}

static int server_do_sreq(td_driver_t *driver)
{
	/*
	  RPRINTF("submit request received\n");
  */

	return 0;
}

/* at this point, the server can start applying the most recent
 * ramdisk. */
static int server_do_creq(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	// RPRINTF("committing buffer\n");

	ramdisk_start_flush(driver);

	/* XXX this message should not be sent until flush completes! */
	if (write(s->stream_fd.fd, TDREMUS_DONE, strlen(TDREMUS_DONE)) != 4)
		return -1;

	return 0;
}


/* called when data is pending in s->rfd */
static void remus_server_event(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	td_driver_t *driver = s->tdremus_driver;
	char req[5];

	// RPRINTF("replication data waiting\n");

	/* TODO: add a get_connection_by_event_id() function.
	 * for now we can assume that the fd is s->stream_fd */

	if (mread(s->stream_fd.fd, req, sizeof(req) - 1) < 0) {
		RPRINTF("error reading server event, activating backup\n");
		switch_mode(driver, mode_unprotected);
		return;
	}

	req[4] = '\0';

	if (!strcmp(req, TDREMUS_WRITE))
		server_do_wreq(driver);
	else if (!strcmp(req, TDREMUS_SUBMIT))
		server_do_sreq(driver);
	else if (!strcmp(req, TDREMUS_COMMIT))
		server_do_creq(driver);
	else
		RPRINTF("unknown request received: %s\n", req);

	return;

}

/* unprotected */

void unprotected_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* wait for previous ramdisk to flush  before servicing reads */
	if (server_writes_inflight(driver)) {
		/* for now lets just return EBUSY.
		 * if there are any left-over requests in prev,
		 * kick em again.
		 */
		if(!s->ramdisk.inflight) /* nothing in inprogress */
			ramdisk_flush(driver, s);

		td_complete_request(treq, -EBUSY);
	}
	else {
		/* here we just pass reads through */
		td_forward_request(treq);
	}
}

/* For a recoverable remus solution we need to log unprotected writes here */
void unprotected_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* wait for previous ramdisk to flush */
	if (server_writes_inflight(driver)) {
		RPRINTF("queue_write: waiting for queue to drain");
		if(!s->ramdisk.inflight) /* nothing in inprogress. Kick prev */
			ramdisk_flush(driver, s);
		td_complete_request(treq, -EBUSY);
	}
	else {
		// RPRINTF("servicing write request on backup\n");
		/* NOTE: DRBD style bitmap tracking could go here */
		td_forward_request(treq);
	}
}

static int unprotected_start(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("failure detected, activating passthrough\n");

	/* close the server socket */
	close_stream_fd(s);

	/* unregister the replication stream */
	tapdisk_server_unregister_event(s->server_fd.id);

	/* close the replication stream */
	close(s->server_fd.fd);
	s->server_fd.fd = -1;

	/* install the unprotected read/write handlers */
	tapdisk_remus.td_queue_read = unprotected_queue_read;
	tapdisk_remus.td_queue_write = unprotected_queue_write;

	return 0;
}


/* control */

static inline int resolve_address(const char* addr, struct in_addr* ia)
{
	struct hostent* he;
	uint32_t ip;

	if (!(he = gethostbyname(addr))) {
		RPRINTF("error resolving %s: %d\n", addr, h_errno);
		return -1;
	}

	if (!he->h_addr_list[0]) {
		RPRINTF("no address found for %s\n", addr);
		return -1;
	}

	/* network byte order */
	ip = *((uint32_t**)he->h_addr_list)[0];
	ia->s_addr = ip;

	return 0;
}

static int get_args(td_driver_t *driver, const char* name)
{
	struct tdremus_state *state = (struct tdremus_state *)driver->data;
	char* host;
	char* port;
//  char* driver_str;
//  char* parent;
//  int type;
//  char* path;
//  unsigned long ulport;
//  int i;
//  struct sockaddr_in server_addr_in;

	int gai_status;
	int valid_addr;
	struct addrinfo gai_hints;
	struct addrinfo *servinfo, *servinfo_itr;

	memset(&gai_hints, 0, sizeof gai_hints);
	gai_hints.ai_family = AF_UNSPEC;
	gai_hints.ai_socktype = SOCK_STREAM;

	port = strchr(name, ':');
	if (!port) {
		RPRINTF("missing host in %s\n", name);
		return -ENOENT;
	}
	if (!(host = strndup(name, port - name))) {
		RPRINTF("unable to allocate host\n");
		return -ENOMEM;
	}
	port++;

	if ((gai_status = getaddrinfo(host, port, &gai_hints, &servinfo)) != 0) {
		RPRINTF("getaddrinfo error: %s\n", gai_strerror(gai_status));
		return -ENOENT;
	}

	/* TODO: do something smarter here */
	valid_addr = 0;
	for(servinfo_itr = servinfo; servinfo_itr != NULL; servinfo_itr = servinfo_itr->ai_next) {
		void *addr;
		char *ipver;

		if (servinfo_itr->ai_family == AF_INET) {
			valid_addr = 1;
			memset(&state->sa, 0, sizeof(state->sa));
			state->sa = *(struct sockaddr_in *)servinfo_itr->ai_addr;
			break;
		}
	}
	freeaddrinfo(servinfo);

	if (!valid_addr)
		return -ENOENT;

	RPRINTF("host: %s, port: %d\n", inet_ntoa(state->sa.sin_addr), ntohs(state->sa.sin_port));

	return 0;
}

static int switch_mode(td_driver_t *driver, enum tdremus_mode mode)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int rc;

	if (mode == s->mode)
		return 0;

	if (s->queue_flush)
		if ((rc = s->queue_flush(driver)) < 0) {
			// fall back to unprotected mode on error
			RPRINTF("switch_mode: error flushing queue (old: %d, new: %d)", s->mode, mode);
			mode = mode_unprotected;
		}

	if (mode == mode_unprotected)
		rc = unprotected_start(driver);
	else if (mode == mode_primary)
		rc = primary_start(driver);
	else if (mode == mode_backup)
		rc = backup_start(driver);
	else {
		RPRINTF("unknown mode requested: %d\n", mode);
		rc = -1;
	}

	if (!rc)
		s->mode = mode;

	return rc;
}

static void ctl_request(event_id_t id, char mode, void *private)
{
	struct tdremus_state *s = (struct tdremus_state *)private;
	td_driver_t *driver = s->tdremus_driver;
	char msg[80];
	int rc;

	// RPRINTF("data waiting on control fifo\n");

	if (!(rc = read(s->ctl_fd.fd, msg, sizeof(msg) - 1 /* append nul */))) {
		RPRINTF("0-byte read received, reopening FIFO\n");
		/*TODO: we may have to unregister/re-register with tapdisk_server */
		close(s->ctl_fd.fd);
		RPRINTF("FIFO closed\n");
		if ((s->ctl_fd.fd = open(s->ctl_path, O_RDWR)) < 0) {
			RPRINTF("error reopening FIFO: %d\n", errno);
		}
		return;
	}

	if (rc < 0) {
		RPRINTF("error reading from FIFO: %d\n", errno);
		return;
	}

	/* TODO: need to get driver somehow */
	msg[rc] = '\0';
	if (!strncmp(msg, "flush", 5)) {
		if (s->queue_flush)
			if ((rc = s->queue_flush(driver))) {
				RPRINTF("error passing flush request to backup");
				ctl_respond(s, TDREMUS_FAIL);
			}
	} else {
		RPRINTF("unknown command: %s\n", msg);
	}
}

static int ctl_respond(struct tdremus_state *s, const char *response)
{
	int rc;

	if ((rc = write(s->msg_fd.fd, response, strlen(response))) < 0) {
		RPRINTF("error writing notification: %d\n", errno);
		close(s->msg_fd.fd);
		if ((s->msg_fd.fd = open(s->msg_path, O_RDWR)) < 0)
			RPRINTF("error reopening FIFO: %d\n", errno);
	}

	return rc;
}

/* must be called after the underlying driver has been initialized */
static int ctl_open(td_driver_t *driver, const char* name)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int i, l;

	/* first we must ensure that BLKTAP_CTRL_DIR exists */
	if (mkdir(BLKTAP_CTRL_DIR, 0755) && errno != EEXIST)
	{
		DPRINTF("error creating directory %s: %d\n", BLKTAP_CTRL_DIR, errno);
		return -1;
	}

	/* use the device name to create the control fifo path */
	if (asprintf(&s->ctl_path, BLKTAP_CTRL_DIR "/remus_%s", name) < 0)
		return -1;
	/* scrub fifo pathname  */
	for (i = strlen(BLKTAP_CTRL_DIR) + 1, l = strlen(s->ctl_path); i < l; i++) {
		if (strchr(":/", s->ctl_path[i]))
			s->ctl_path[i] = '_';
	}
	if (asprintf(&s->msg_path, "%s.msg", s->ctl_path) < 0)
		goto err_ctlfifo;

	if (mkfifo(s->ctl_path, S_IRWXU|S_IRWXG|S_IRWXO) && errno != EEXIST) {
		RPRINTF("error creating control FIFO %s: %d\n", s->ctl_path, errno);
		goto err_msgfifo;
	}

	if (mkfifo(s->msg_path, S_IRWXU|S_IRWXG|S_IRWXO) && errno != EEXIST) {
		RPRINTF("error creating message FIFO %s: %d\n", s->msg_path, errno);
		goto err_msgfifo;
	}

	/* RDWR so that fd doesn't block select when no writer is present */
	if ((s->ctl_fd.fd = open(s->ctl_path, O_RDWR)) < 0) {
		RPRINTF("error opening control FIFO %s: %d\n", s->ctl_path, errno);
		goto err_msgfifo;
	}

	if ((s->msg_fd.fd = open(s->msg_path, O_RDWR)) < 0) {
		RPRINTF("error opening message FIFO %s: %d\n", s->msg_path, errno);
		goto err_openctlfifo;
	}

	RPRINTF("control FIFO %s\n", s->ctl_path);
	RPRINTF("message FIFO %s\n", s->msg_path);

	return 0;

 err_openctlfifo:
	close(s->ctl_fd.fd);
 err_msgfifo:
	free(s->msg_path);
	s->msg_path = NULL;
 err_ctlfifo:
	free(s->ctl_path);
	s->ctl_path = NULL;
	return -1;
}

static void ctl_close(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	/* TODO: close *all* connections */

	if(s->ctl_fd.fd)
		close(s->ctl_fd.fd);

	if (s->ctl_path) {
		unlink(s->ctl_path);
		free(s->ctl_path);
		s->ctl_path = NULL;
	}
	if (s->msg_path) {
		unlink(s->msg_path);
		free(s->msg_path);
		s->msg_path = NULL;
	}
}

static int ctl_register(struct tdremus_state *s)
{
	RPRINTF("registering ctl fifo\n");

	/* register ctl fd */
	s->ctl_fd.id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD, s->ctl_fd.fd, 0, ctl_request, s);

	if (s->ctl_fd.id < 0) {
		RPRINTF("error registering ctrl FIFO %s: %d\n", s->ctl_path, s->ctl_fd.id);
		return -1;
	}

	return 0;
}

/* interface */

static int tdremus_open(td_driver_t *driver, const char *name,
			td_flag_t flags)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;
	int rc;

	RPRINTF("opening %s\n", name);

	/* first we need to get the underlying vbd for this driver stack. To do so we
	 * need to know the vbd's id. Fortunately, for tapdisk2 this is hard-coded as
	 * 0 (see tapdisk2.c)
	 */
	device_vbd = tapdisk_server_get_vbd(0);

	memset(s, 0, sizeof(*s));
	s->server_fd.fd = -1;
	s->stream_fd.fd = -1;
	s->ctl_fd.fd = -1;
	s->msg_fd.fd = -1;

	/* TODO: this is only needed so that the server can send writes down
	 * the driver stack from the stream_fd event handler */
	s->tdremus_driver = driver;

	/* parse name to get info etc */
	if ((rc = get_args(driver, name)))
		return rc;

	if ((rc = ctl_open(driver, name))) {
		RPRINTF("error setting up control channel\n");
		free(s->driver_data);
		return rc;
	}

	if ((rc = ctl_register(s))) {
		RPRINTF("error registering control channel\n");
		free(s->driver_data);
		return rc;
	}

	if (!(rc = remus_bind(s)))
		rc = switch_mode(driver, mode_backup);
	else if (rc == -2)
		rc = switch_mode(driver, mode_primary);

	if (!rc)
		return 0;

	tdremus_close(driver);
	return -EIO;
}

static int tdremus_close(td_driver_t *driver)
{
	struct tdremus_state *s = (struct tdremus_state *)driver->data;

	RPRINTF("closing\n");
	if (s->ramdisk.inprogress)
		hashtable_destroy(s->ramdisk.inprogress, 0);
	
	if (s->driver_data) {
		free(s->driver_data);
		s->driver_data = NULL;
	}
	if (s->server_fd.fd >= 0) {
		close(s->server_fd.fd);
		s->server_fd.fd = -1;
	}
	if (s->stream_fd.fd >= 0)
		close_stream_fd(s);

	ctl_close(driver);

	return 0;
}

static int tdremus_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	/* we shouldn't have a parent... for now */
	return -EINVAL;
}

static int tdremus_validate_parent(td_driver_t *driver,
				   td_driver_t *pdriver, td_flag_t flags)
{
	return 0;
}

struct tap_disk tapdisk_remus = {
	.disk_type          = "tapdisk_remus",
	.private_data_size  = sizeof(struct tdremus_state),
	.td_open            = tdremus_open,
	.td_queue_read      = unprotected_queue_read,
	.td_queue_write     = unprotected_queue_write,
	.td_close           = tdremus_close,
	.td_get_parent_id   = tdremus_get_parent_id,
	.td_validate_parent = tdremus_validate_parent,
	.td_debug           = NULL,
};
