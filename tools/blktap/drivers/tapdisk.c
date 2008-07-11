/* tapdisk.c
 *
 * separate disk process, spawned by blktapctrl. Inherits code from driver 
 * plugins
 * 
 * Copyright (c) 2005 Julian Chesterfield and Andrew Warfield.
 *
 */

#define MSG_SIZE 4096
#define TAPDISK

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <err.h>
#include <poll.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include "blktaplib.h"
#include "tapdisk.h"

#if 1                                                                        
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif 

#define INPUT 0
#define OUTPUT 1

static int maxfds, fds[2], run = 1;

static pid_t process;
int connected_disks = 0;
fd_list_entry_t *fd_start = NULL;

int do_cow_read(struct disk_driver *dd, blkif_request_t *req, 
		int sidx, uint64_t sector, int nr_secs);

#define td_for_each_disk(tds, drv) \
        for (drv = tds->disks; drv != NULL; drv = drv->next)

static void usage(void) 
{
	fprintf(stderr, "blktap-utils: v1.0.0\n");
	fprintf(stderr, "usage: tapdisk <READ fifo> <WRITE fifo>\n");
        exit(-1);
}

static void daemonize(void)
{
	int i;

	if (getppid()==1) return; /* already a daemon */
	if (fork() != 0) exit(0);

#if 0
	/*Set new program session ID and close all descriptors*/
	setsid();
	for (i = getdtablesize(); i >= 0; --i) close(i);

	/*Send all I/O to /dev/null */
	i = open("/dev/null",O_RDWR);
	dup(i); 
	dup(i);
#endif
	return;
}

static void free_driver(struct disk_driver *d)
{
	if (d->name)
		free(d->name);
	if (d->private)
		free(d->private);
	free(d);
}

static void unmap_disk(struct td_state *s)
{
	tapdev_info_t *info = s->ring_info;
	struct disk_driver *dd, *tmp;
	fd_list_entry_t *entry;

	dd = s->disks;
	while (dd) {
		tmp = dd->next;
		dd->drv->td_close(dd);
		free_driver(dd);
		dd = tmp;
	}

	if (info != NULL && info->mem > 0)
	        munmap(info->mem, getpagesize() * BLKTAP_MMAP_REGION_SIZE);

	entry = s->fd_entry;
	*entry->pprev = entry->next;
	if (entry->next)
		entry->next->pprev = entry->pprev;

	close(info->fd);

	free(s->fd_entry);
	free(s->blkif);
	free(s->ring_info);
	free(s);

	return;
}

static void sig_handler(int sig)
{
	/*Received signal to close. If no disks are active, we close app.*/

	if (connected_disks < 1) run = 0;	
}

static inline int LOCAL_FD_SET(fd_set *readfds)
{
	fd_list_entry_t *ptr;
	struct disk_driver *dd;

	ptr = fd_start;
	while (ptr != NULL) {
		if (ptr->tap_fd) {
			FD_SET(ptr->tap_fd, readfds);
			td_for_each_disk(ptr->s, dd) {
				if (dd->io_fd[READ]) 
					FD_SET(dd->io_fd[READ], readfds);
				maxfds = (dd->io_fd[READ] > maxfds ? 
					  dd->io_fd[READ] : maxfds);
			}
			maxfds = (ptr->tap_fd > maxfds ? ptr->tap_fd : maxfds);
		}
		ptr = ptr->next;
	}

	return 0;
}

static inline fd_list_entry_t *add_fd_entry(int tap_fd, struct td_state *s)
{
	fd_list_entry_t **pprev, *entry;
	int i;

	DPRINTF("Adding fd_list_entry\n");

	/*Add to linked list*/
	s->fd_entry   = entry = malloc(sizeof(fd_list_entry_t));
	entry->tap_fd = tap_fd;
	entry->s      = s;
	entry->next   = NULL;

	pprev = &fd_start;
	while (*pprev != NULL)
		pprev = &(*pprev)->next;

	*pprev = entry;
	entry->pprev = pprev;

	return entry;
}

static inline struct td_state *get_state(int cookie)
{
	fd_list_entry_t *ptr;

	ptr = fd_start;
	while (ptr != NULL) {
		if (ptr->cookie == cookie) return ptr->s;
		ptr = ptr->next;
	}
	return NULL;
}

static struct tap_disk *get_driver(int drivertype)
{
	/* blktapctrl has passed us the driver type */

	return dtypes[drivertype]->drv;
}

static struct td_state *state_init(void)
{
	int i;
	struct td_state *s;
	blkif_t *blkif;

	s = malloc(sizeof(struct td_state));
	blkif = s->blkif = malloc(sizeof(blkif_t));
	s->ring_info = calloc(1, sizeof(tapdev_info_t));

	for (i = 0; i < MAX_REQUESTS; i++) {
		blkif->pending_list[i].secs_pending = 0;
		blkif->pending_list[i].submitting = 0;
	}

	return s;
}

static int map_new_dev(struct td_state *s, int minor)
{
	int tap_fd;
	tapdev_info_t *info = s->ring_info;
	char *devname;
	fd_list_entry_t *ptr;
	int page_size;

	if (asprintf(&devname,"%s/%s%d", BLKTAP_DEV_DIR, BLKTAP_DEV_NAME, minor) == -1)
		return -1;
	tap_fd = open(devname, O_RDWR);
	if (tap_fd == -1) 
	{
		DPRINTF("open failed on dev %s!",devname);
		goto fail;
	} 
	info->fd = tap_fd;

	/*Map the shared memory*/
	page_size = getpagesize();
	info->mem = mmap(0, page_size * BLKTAP_MMAP_REGION_SIZE, 
			  PROT_READ | PROT_WRITE, MAP_SHARED, info->fd, 0);
	if ((long int)info->mem == -1) 
	{
		DPRINTF("mmap failed on dev %s!\n",devname);
		goto fail;
	}

	/* assign the rings to the mapped memory */ 
	info->sring = (blkif_sring_t *)((unsigned long)info->mem);
	BACK_RING_INIT(&info->fe_ring, info->sring, page_size);
	
	info->vstart = 
	        (unsigned long)info->mem + (BLKTAP_RING_PAGES * page_size);

	ioctl(info->fd, BLKTAP_IOCTL_SENDPID, process );
	ioctl(info->fd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_INTERPOSE );
	free(devname);

	/*Update the fd entry*/
	ptr = fd_start;
	while (ptr != NULL) {
		if (s == ptr->s) {
			ptr->tap_fd = tap_fd;
			break;
		}
		ptr = ptr->next;
	}	

	return minor;

 fail:
	free(devname);
	return -1;
}

static struct disk_driver *disk_init(struct td_state *s, 
				     struct tap_disk *drv, 
				     char *name, td_flag_t flags)
{
	struct disk_driver *dd;

	dd = calloc(1, sizeof(struct disk_driver));
	if (!dd)
		return NULL;
	
	dd->private = malloc(drv->private_data_size);
	if (!dd->private) {
		free(dd);
		return NULL;
	}

	dd->drv      = drv;
	dd->td_state = s;
	dd->name     = name;
	dd->flags    = flags;

	return dd;
}

static int open_disk(struct td_state *s, 
		     struct tap_disk *drv, char *path, td_flag_t flags)
{
	int err;
	char *dup;
	td_flag_t pflags;
	struct disk_id id;
	struct disk_driver *d;

	dup = strdup(path);
	if (!dup)
		return -ENOMEM;

	memset(&id, 0, sizeof(struct disk_id));
	s->disks = d = disk_init(s, drv, dup, flags);
	if (!d)
		return -ENOMEM;

	err = drv->td_open(d, path, flags);
	if (err) {
		free_driver(d);
		s->disks = NULL;
		return -ENOMEM;
	}
	pflags = flags | TD_RDONLY;

	/* load backing files as necessary */
	while ((err = d->drv->td_get_parent_id(d, &id)) == 0) {
		struct disk_driver *new;
		
		if (id.drivertype > MAX_DISK_TYPES || 
		    !get_driver(id.drivertype) || !id.name)
			goto fail;

		dup = strdup(id.name);
		if (!dup)
			goto fail;

		new = disk_init(s, get_driver(id.drivertype), dup, pflags);
		if (!new)
			goto fail;

		err = new->drv->td_open(new, new->name, pflags);
		if (err)
			goto fail;

		err = d->drv->td_validate_parent(d, new, 0);
		if (err) {
			d->next = new;
			goto fail;
		}

		d = d->next = new;
		free(id.name);
	}

	s->info |= ((flags & TD_RDONLY) ? VDISK_READONLY : 0);

	if (err >= 0)
		return 0;

 fail:
	DPRINTF("failed opening disk\n");
	if (id.name)
		free(id.name);
	d = s->disks;
	while (d) {
		struct disk_driver *tmp = d->next;
		d->drv->td_close(d);
		free_driver(d);
		d = tmp;
	}
	s->disks = NULL;
	return -1;
}

static int read_msg(char *buf)
{
	int length, len, msglen, tap_fd, *io_fd;
	char *ptr, *path;
	image_t *img;
	msg_hdr_t *msg;
	msg_newdev_t *msg_dev;
	msg_pid_t *msg_pid;
	struct tap_disk *drv;
	int ret = -1;
	struct td_state *s = NULL;
	fd_list_entry_t *entry;

	length = read(fds[READ], buf, MSG_SIZE);

	if (length > 0 && length >= sizeof(msg_hdr_t)) 
	{
		msg = (msg_hdr_t *)buf;
		DPRINTF("Tapdisk: Received msg, len %d, type %d, UID %d\n",
			length,msg->type,msg->cookie);

		switch (msg->type) {
		case CTLMSG_PARAMS: 			
			ptr = buf + sizeof(msg_hdr_t);
			len = (length - sizeof(msg_hdr_t));
			path = calloc(1, len);
			
			memcpy(path, ptr, len); 
			DPRINTF("Received CTLMSG_PARAMS: [%s]\n", path);

			/*Assign driver*/
			drv = get_driver(msg->drivertype);
			if (drv == NULL)
				goto params_done;
				
			DPRINTF("Loaded driver: name [%s], type [%d]\n",
				drv->disk_type, msg->drivertype);

			/* Allocate the disk structs */
			s = state_init();
			if (s == NULL)
				goto params_done;

			/*Open file*/
			ret = open_disk(s, drv, path, 
					((msg->readonly) ? TD_RDONLY : 0));
			if (ret)
				goto params_done;

			entry = add_fd_entry(0, s);
			entry->cookie = msg->cookie;
			DPRINTF("Entered cookie %d\n", entry->cookie);
			
			memset(buf, 0x00, MSG_SIZE); 
			
		params_done:
			if (ret == 0) {
				msglen = sizeof(msg_hdr_t) + sizeof(image_t);
				msg->type = CTLMSG_IMG;
				img = (image_t *)(buf + sizeof(msg_hdr_t));
				img->size = s->size;
				img->secsize = s->sector_size;
				img->info = s->info;
			} else {
				msglen = sizeof(msg_hdr_t);
				msg->type = CTLMSG_IMG_FAIL;
				msg->len = msglen;
			}
			len = write(fds[WRITE], buf, msglen);
			free(path);
			return 1;
			
		case CTLMSG_NEWDEV:
			msg_dev = (msg_newdev_t *)(buf + sizeof(msg_hdr_t));

			s = get_state(msg->cookie);
			DPRINTF("Retrieving state, cookie %d.....[%s]\n",
				msg->cookie, (s == NULL ? "FAIL":"OK"));
			if (s != NULL) {
				ret = ((map_new_dev(s, msg_dev->devnum) 
					== msg_dev->devnum ? 0: -1));
				connected_disks++;
			}	

			memset(buf, 0x00, MSG_SIZE); 
			msglen = sizeof(msg_hdr_t);
			msg->type = (ret == 0 ? CTLMSG_NEWDEV_RSP 
				              : CTLMSG_NEWDEV_FAIL);
			msg->len = msglen;

			len = write(fds[WRITE], buf, msglen);
			return 1;

		case CTLMSG_CLOSE:
			s = get_state(msg->cookie);
			if (s) unmap_disk(s);
			
			connected_disks--;
			sig_handler(SIGINT);

			return 1;			

		case CTLMSG_PID:
			memset(buf, 0x00, MSG_SIZE);
			msglen = sizeof(msg_hdr_t) + sizeof(msg_pid_t);
			msg->type = CTLMSG_PID_RSP;
			msg->len = msglen;

			msg_pid = (msg_pid_t *)(buf + sizeof(msg_hdr_t));
			process = getpid();
			msg_pid->pid = process;

			len = write(fds[WRITE], buf, msglen);
			return 1;

		default:
			return 0;
		}
	}
	return 0;
}

static inline int write_rsp_to_ring(struct td_state *s, blkif_response_t *rsp)
{
	tapdev_info_t *info = s->ring_info;
	blkif_response_t *rsp_d;
	
	rsp_d = RING_GET_RESPONSE(&info->fe_ring, info->fe_ring.rsp_prod_pvt);
	memcpy(rsp_d, rsp, sizeof(blkif_response_t));
	info->fe_ring.rsp_prod_pvt++;
	
	return 0;
}

static inline void kick_responses(struct td_state *s)
{
	tapdev_info_t *info = s->ring_info;

	if (info->fe_ring.rsp_prod_pvt != info->fe_ring.sring->rsp_prod) 
	{
		RING_PUSH_RESPONSES(&info->fe_ring);
		ioctl(info->fd, BLKTAP_IOCTL_KICK_FE);
	}
}

static void io_done(struct disk_driver *dd, int sid)
{
	struct tap_disk *drv = dd->drv;

	if (!run) return; /*We have received signal to close*/

	if (sid > MAX_IOFD || drv->td_do_callbacks(dd, sid) > 0)
		kick_responses(dd->td_state);

	return;
}

static inline uint64_t
segment_start(blkif_request_t *req, int sidx)
{
	int i;
	uint64_t start = req->sector_number;

	for (i = 0; i < sidx; i++) 
		start += (req->seg[i].last_sect - req->seg[i].first_sect + 1);

	return start;
}

uint64_t sends, responds;
static int send_responses(struct disk_driver *dd, int res, 
		   uint64_t sector, int nr_secs, int idx, void *private)
{
	pending_req_t   *preq;
	blkif_request_t *req;
	int responses_queued = 0;
	struct td_state *s = dd->td_state;
	blkif_t *blkif = s->blkif;
	int sidx = (int)(long)private, secs_done = nr_secs;

	if ( (idx > MAX_REQUESTS-1) )
	{
		DPRINTF("invalid index returned(%u)!\n", idx);
		return 0;
	}
	preq = &blkif->pending_list[idx];
	req  = &preq->req;

	if (res == BLK_NOT_ALLOCATED) {
		res = do_cow_read(dd, req, sidx, sector, nr_secs);
		if (res >= 0) {
			secs_done = res;
			res = 0;
		} else
			secs_done = 0;
	}

	preq->secs_pending -= secs_done;

	if (res == -EBUSY && preq->submitting) 
		return -EBUSY;  /* propagate -EBUSY back to higher layers */
	if (res) 
		preq->status = BLKIF_RSP_ERROR;
	
	if (!preq->submitting && preq->secs_pending == 0) 
	{
		blkif_request_t tmp;
		blkif_response_t *rsp;

		tmp = preq->req;
		rsp = (blkif_response_t *)req;
		
		rsp->id = tmp.id;
		rsp->operation = tmp.operation;
		rsp->status = preq->status;
		
		write_rsp_to_ring(s, rsp);
		responses_queued++;
	}
	return responses_queued;
}

int do_cow_read(struct disk_driver *dd, blkif_request_t *req, 
		int sidx, uint64_t sector, int nr_secs)
{
	char *page;
	int ret, early;
	uint64_t seg_start, seg_end;
	struct td_state  *s = dd->td_state;
	tapdev_info_t *info = s->ring_info;
	struct disk_driver *parent = dd->next;
	
	seg_start = segment_start(req, sidx);
	seg_end   = seg_start + req->seg[sidx].last_sect + 1;
	
	ASSERT(sector >= seg_start && sector + nr_secs <= seg_end);

	page  = (char *)MMAP_VADDR(info->vstart, 
				   (unsigned long)req->id, sidx);
	page += (req->seg[sidx].first_sect << SECTOR_SHIFT);
	page += ((sector - seg_start) << SECTOR_SHIFT);

	if (!parent) {
		memset(page, 0, nr_secs << SECTOR_SHIFT);
		return nr_secs;
	}

	/* reissue request to backing file */
	ret = parent->drv->td_queue_read(parent, sector, nr_secs,
					 page, send_responses, 
					 req->id, (void *)(long)sidx);
	if (ret > 0)
		parent->early += ret;

	return ((ret >= 0) ? 0 : ret);
}

static void get_io_request(struct td_state *s)
{
	RING_IDX          rp, rc, j, i;
	blkif_request_t  *req;
	int idx, nsects, ret;
	uint64_t sector_nr;
	char *page;
	int early = 0; /* count early completions */
	struct disk_driver *dd = s->disks;
	struct tap_disk *drv   = dd->drv;
	blkif_t *blkif = s->blkif;
	tapdev_info_t *info = s->ring_info;
	int page_size = getpagesize();

	if (!run) return; /*We have received signal to close*/

	rp = info->fe_ring.sring->req_prod; 
	xen_rmb();
	for (j = info->fe_ring.req_cons; j != rp; j++)
	{
		int done = 0, start_seg = 0; 

		req = NULL;
		req = RING_GET_REQUEST(&info->fe_ring, j);
		++info->fe_ring.req_cons;
		
		if (req == NULL) continue;

		idx = req->id;

		if (info->busy.req) {
			/* continue where we left off last time */
			ASSERT(info->busy.req == req);
			start_seg = info->busy.seg_idx;
			sector_nr = segment_start(req, start_seg);
			info->busy.seg_idx = 0;
			info->busy.req     = NULL;
		} else {
			ASSERT(blkif->pending_list[idx].secs_pending == 0);
			memcpy(&blkif->pending_list[idx].req, 
			       req, sizeof(*req));
			blkif->pending_list[idx].status = BLKIF_RSP_OKAY;
			blkif->pending_list[idx].submitting = 1;
			sector_nr = req->sector_number;
		}

		if ((dd->flags & TD_RDONLY) && 
		    (req->operation == BLKIF_OP_WRITE)) {
			blkif->pending_list[idx].status = BLKIF_RSP_ERROR;
			goto send_response;
		}

		for (i = start_seg; i < req->nr_segments; i++) {
			nsects = req->seg[i].last_sect - 
				 req->seg[i].first_sect + 1;
	
			if ((req->seg[i].last_sect >= page_size >> 9) ||
			    (nsects <= 0))
				continue;

			page  = (char *)MMAP_VADDR(info->vstart, 
						   (unsigned long)req->id, i);
			page += (req->seg[i].first_sect << SECTOR_SHIFT);

			if (sector_nr >= s->size) {
				DPRINTF("Sector request failed:\n");
				DPRINTF("%s request, idx [%d,%d] size [%llu], "
					"sector [%llu,%llu]\n",
					(req->operation == BLKIF_OP_WRITE ? 
					 "WRITE" : "READ"),
					idx,i,
					(long long unsigned) 
						nsects<<SECTOR_SHIFT,
					(long long unsigned) 
						sector_nr<<SECTOR_SHIFT,
					(long long unsigned) sector_nr);
				continue;
			}

			blkif->pending_list[idx].secs_pending += nsects;

			switch (req->operation) 
			{
			case BLKIF_OP_WRITE:
				ret = drv->td_queue_write(dd, sector_nr,
							  nsects, page, 
							  send_responses,
							  idx, (void *)(long)i);
				if (ret > 0) dd->early += ret;
				else if (ret == -EBUSY) {
					/* put req back on queue */
					--info->fe_ring.req_cons;
					info->busy.req     = req;
					info->busy.seg_idx = i;
					goto out;
				}
				break;
			case BLKIF_OP_READ:
				ret = drv->td_queue_read(dd, sector_nr,
							 nsects, page, 
							 send_responses,
							 idx, (void *)(long)i);
				if (ret > 0) dd->early += ret;
				else if (ret == -EBUSY) {
					/* put req back on queue */
					--info->fe_ring.req_cons;
					info->busy.req     = req;
					info->busy.seg_idx = i;
					goto out;
				}
				break;
			default:
				DPRINTF("Unknown block operation\n");
				break;
			}
			sector_nr += nsects;
		}
	send_response:
		blkif->pending_list[idx].submitting = 0;
		/* force write_rsp_to_ring for synchronous case */
		if (blkif->pending_list[idx].secs_pending == 0)
			dd->early += send_responses(dd, 0, 0, 0, idx, 
						    (void *)(long)0);
	}

 out:
	/*Batch done*/
	td_for_each_disk(s, dd) {
		dd->early += dd->drv->td_submit(dd);
		if (dd->early > 0) {
			io_done(dd, MAX_IOFD + 1);
			dd->early = 0;
		}
	}

	return;
}

int main(int argc, char *argv[])
{
	int len, msglen, ret;
	char *p, *buf;
	fd_set readfds, writefds;	
	fd_list_entry_t *ptr;
	struct td_state *s;
	char openlogbuf[128];

	if (argc != 3) usage();

	daemonize();

	snprintf(openlogbuf, sizeof(openlogbuf), "TAPDISK[%d]", getpid());
	openlog(openlogbuf, LOG_CONS|LOG_ODELAY, LOG_DAEMON);
	/*Setup signal handlers*/
	signal (SIGBUS, sig_handler);
	signal (SIGINT, sig_handler);

	/*Open the control channel*/
	fds[READ]  = open(argv[1],O_RDWR|O_NONBLOCK);
	fds[WRITE] = open(argv[2],O_RDWR|O_NONBLOCK);

	if ( (fds[READ] < 0) || (fds[WRITE] < 0) ) 
	{
		DPRINTF("FD open failed [%d,%d]\n", fds[READ], fds[WRITE]);
		exit(-1);
	}

	buf = calloc(MSG_SIZE, 1);

	if (buf == NULL) 
        {
		DPRINTF("ERROR: allocating memory.\n");
		exit(-1);
	}

	while (run) 
        {
		ret = 0;
		FD_ZERO(&readfds);
		FD_SET(fds[READ], &readfds);
		maxfds = fds[READ];

		/*Set all tap fds*/
		LOCAL_FD_SET(&readfds);

		/*Wait for incoming messages*/
		ret = select(maxfds + 1, &readfds, (fd_set *) 0, 
			     (fd_set *) 0, NULL);

		if (ret > 0) 
		{
			ptr = fd_start;
			while (ptr != NULL) {
				int progress_made = 0;
				struct disk_driver *dd;
				tapdev_info_t *info = ptr->s->ring_info;

				td_for_each_disk(ptr->s, dd) {
					if (dd->io_fd[READ] &&
					    FD_ISSET(dd->io_fd[READ], 
						     &readfds)) {
						io_done(dd, READ);
						progress_made = 1;
					}
				}

				/* completed io from above may have 
				 * queued new requests on chained disks */
				if (progress_made) {
					td_for_each_disk(ptr->s, dd) {
						dd->early += 
							dd->drv->td_submit(dd);
						if (dd->early > 0) {
							io_done(dd, 
								MAX_IOFD + 1);
							dd->early = 0;
						}
					}
				}

				if (FD_ISSET(ptr->tap_fd, &readfds) ||
				    (info->busy.req && progress_made))
					get_io_request(ptr->s);

				ptr = ptr->next;
			}

			if (FD_ISSET(fds[READ], &readfds))
				read_msg(buf);
		}
	}
	free(buf);
	close(fds[READ]);
	close(fds[WRITE]);

	ptr = fd_start;
	while (ptr != NULL) {
		s = ptr->s;
		unmap_disk(s);
		close(ptr->tap_fd);
		ptr = ptr->next;
	}
	closelog();

	return 0;
}
