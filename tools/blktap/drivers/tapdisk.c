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
#include <linux/fs.h>
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

void usage(void) 
{
	fprintf(stderr, "blktap-utils: v1.0.0\n");
	fprintf(stderr, "usage: tapdisk <READ fifo> <WRITE fifo>\n");
        exit(-1);
}

void daemonize(void)
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

static void unmap_disk(struct td_state *s)
{
	tapdev_info_t *info = s->ring_info;
	struct tap_disk *drv = s->drv;
	fd_list_entry_t *entry;

	drv->td_close(s);

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
        free(s->private);
	free(s);

	return;

}

void sig_handler(int sig)
{
	/*Received signal to close. If no disks are active, we close app.*/

	if (connected_disks < 1) run = 0;	
}

static inline int LOCAL_FD_SET(fd_set *readfds)
{
	fd_list_entry_t *ptr;

	ptr = fd_start;
	while (ptr != NULL) {
		if (ptr->tap_fd) {
			FD_SET(ptr->tap_fd, readfds);
			if (ptr->io_fd[READ]) 
				FD_SET(ptr->io_fd[READ], readfds);
			maxfds = (ptr->io_fd[READ] > maxfds ? 
					ptr->io_fd[READ]: maxfds);
			maxfds = (ptr->tap_fd > maxfds ? ptr->tap_fd: maxfds);
		}
		ptr = ptr->next;
	}

	return 0;
}

static inline fd_list_entry_t *add_fd_entry(
	int tap_fd, int io_fd[MAX_IOFD], struct td_state *s)
{
	fd_list_entry_t **pprev, *entry;
	int i;

	DPRINTF("Adding fd_list_entry\n");

	/*Add to linked list*/
	s->fd_entry = entry = malloc(sizeof(fd_list_entry_t));
	entry->tap_fd = tap_fd;
	for (i = 0; i < MAX_IOFD; i++)
		entry->io_fd[i] = io_fd[i];
	entry->s = s;
	entry->next = NULL;

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
	s->ring_info = malloc(sizeof(tapdev_info_t));

	for (i = 0; i < MAX_REQUESTS; i++)
		blkif->pending_list[i].count = 0;

	return s;
}

static int map_new_dev(struct td_state *s, int minor)
{
	int tap_fd;
	tapdev_info_t *info = s->ring_info;
	char *devname;
	fd_list_entry_t *ptr;
	int page_size;

	asprintf(&devname,"%s/%s%d", BLKTAP_DEV_DIR, BLKTAP_DEV_NAME, minor);
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

			s->drv = drv;
			s->private = malloc(drv->private_data_size);
			if (s->private == NULL) {
				free(s);
				goto params_done;
			}

			/*Open file*/
			ret = drv->td_open(s, path);
			io_fd = drv->td_get_fd(s);

			entry = add_fd_entry(0, io_fd, s);
			entry->cookie = msg->cookie;
			DPRINTF("Entered cookie %d\n",entry->cookie);
			
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
			DPRINTF("Retrieving state, cookie %d.....[%s]\n",msg->cookie, (s == NULL ? "FAIL":"OK"));
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
	wmb();
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

void io_done(struct td_state *s, int sid)
{
	struct tap_disk *drv = s->drv;

	if (!run) return; /*We have received signal to close*/

	if (drv->td_do_callbacks(s, sid) > 0) kick_responses(s);

	return;
}

int send_responses(struct td_state *s, int res, int idx, void *private)
{
	blkif_request_t *req;
	int responses_queued = 0;
	blkif_t *blkif = s->blkif;

	req   = &blkif->pending_list[idx].req;
			
	if ( (idx > MAX_REQUESTS-1) || 
	    (blkif->pending_list[idx].count == 0) )
	{
		DPRINTF("invalid index returned(%u)!\n", idx);
		return 0;
	}
	
	if (res != 0) {
		DPRINTF("*** request error %d! \n", res);
		return 0;
	}

	blkif->pending_list[idx].count--;
	
	if (blkif->pending_list[idx].count == 0) 
	{
		blkif_request_t tmp;
		blkif_response_t *rsp;
		
		tmp = blkif->pending_list[idx].req;
		rsp = (blkif_response_t *)req;
		
		rsp->id = tmp.id;
		rsp->operation = tmp.operation;
		rsp->status = blkif->pending_list[idx].status;
		
		write_rsp_to_ring(s, rsp);
		responses_queued++;
	}
	return responses_queued;
}

static void get_io_request(struct td_state *s)
{
	RING_IDX          rp, rc, j, i, ret;
	blkif_request_t  *req;
	int idx, nsects;
	uint64_t sector_nr;
	char *page;
	int early = 0; /* count early completions */
	struct tap_disk *drv = s->drv;
	blkif_t *blkif = s->blkif;
	tapdev_info_t *info = s->ring_info;
	int page_size = getpagesize();

	if (!run) return; /*We have received signal to close*/

	rp = info->fe_ring.sring->req_prod; 
	rmb();
	for (j = info->fe_ring.req_cons; j != rp; j++)
	{
		int done = 0; 

		req = NULL;
		req = RING_GET_REQUEST(&info->fe_ring, j);
		++info->fe_ring.req_cons;
		
		if (req == NULL) continue;
		
		idx = req->id;
		ASSERT(blkif->pending_list[idx].count == 0);
		memcpy(&blkif->pending_list[idx].req, req, sizeof(*req));
		blkif->pending_list[idx].status = BLKIF_RSP_OKAY;
		blkif->pending_list[idx].count = req->nr_segments;

		sector_nr = req->sector_number;

		for (i = 0; i < req->nr_segments; i++) {
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
			
			switch (req->operation) 
			{
			case BLKIF_OP_WRITE:
				ret = drv->td_queue_write(s, sector_nr,
						nsects, page, send_responses, 
						idx, NULL);
				if (ret > 0) early += ret;
				else if (ret == -EBUSY) {
					/*
					 * TODO: Sector is locked         *
					 * Need to put req back on queue  *
					 */
				}
				break;
			case BLKIF_OP_READ:
				ret = drv->td_queue_read(s, sector_nr,
						nsects, page, send_responses, 
						idx, NULL);
				if (ret > 0) early += ret;
				else if (ret == -EBUSY) {
					/*
					 * TODO: Sector is locked         *
					 * Need to put req back on queue  *
					 */
				}
				break;
			default:
				DPRINTF("Unknown block operation\n");
				break;
			}
			sector_nr += nsects;
		}
	}

	/*Batch done*/
	drv->td_submit(s);
	
	if (early > 0) 
		io_done(s,10);
		
	return;
}

int main(int argc, char *argv[])
{
	int len, msglen, ret;
	char *p, *buf;
	fd_set readfds, writefds;	
	fd_list_entry_t *ptr;
	struct tap_disk *drv;
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
	fds[READ] = open(argv[1],O_RDWR|O_NONBLOCK);
	fds[WRITE] = open(argv[2],O_RDWR|O_NONBLOCK);

	if ( (fds[READ] < 0) || (fds[WRITE] < 0) ) 
	{
		DPRINTF("FD open failed [%d,%d]\n",fds[READ], fds[WRITE]);
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
				if (FD_ISSET(ptr->tap_fd, &readfds)) 
					get_io_request(ptr->s);
				if (ptr->io_fd[READ] && 
						FD_ISSET(ptr->io_fd[READ], &readfds)) 
					io_done(ptr->s, READ);

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
		drv = s->drv;

		unmap_disk(s);
		drv->td_close(s);
		free(s->private);
		free(s->blkif);
		free(s->ring_info);
		free(s);
		close(ptr->tap_fd);
		ptr = ptr->next;
	}
	closelog();

	return 0;
}
