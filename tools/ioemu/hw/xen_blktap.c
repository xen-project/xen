/* xen_blktap.c
 *
 * Interface to blktapctrl to allow use of qemu block drivers with blktap.
 * This file is based on tools/blktap/drivers/tapdisk.c
 * 
 * Copyright (c) 2005 Julian Chesterfield and Andrew Warfield.
 * Copyright (c) 2008 Kevin Wolf
 */

/*
 * There are several communication channels which are used by this interface:
 *
 *   - A pair of pipes for receiving and sending general control messages
 *     (qemu-read-N and qemu-writeN in /var/run/tap, where N is the domain ID).
 *     These control messages are handled by handle_blktap_ctrlmsg().
 *
 *   - One file descriptor per attached disk (/dev/xen/blktapN) for disk
 *     specific control messages. A callback is triggered on this fd if there
 *     is a new IO request. The callback function is handle_blktap_iomsg().
 *
 *   - A shared ring for each attached disk containing the actual IO requests 
 *     and responses. Whenever handle_blktap_iomsg() is triggered it processes
 *     the requests on this ring.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "vl.h"
#include "blktaplib.h"
#include "xen_blktap.h"
#include "block_int.h"

#define MSG_SIZE 4096

#define BLKTAP_CTRL_DIR "/var/run/tap"

/* If enabled, print debug messages to stderr */
#if 1
#define DPRINTF(_f, _a...) fprintf(stderr, __FILE__ ":%d: " _f, __LINE__, ##_a)
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#if 1                                                                        
#define ASSERT(_p) \
    if ( !(_p) ) { DPRINTF("Assertion '%s' failed, line %d, file %s\n", #_p , \
        __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif 


extern int domid;

int read_fd;
int write_fd;

static pid_t process;
fd_list_entry_t *fd_start = NULL;

static void handle_blktap_iomsg(void* private);

struct aiocb_info {
	struct td_state	*s;
	uint64_t sector;
	int nr_secs;
	int idx;
	long i;
};

static void unmap_disk(struct td_state *s)
{
	tapdev_info_t *info = s->ring_info;
	fd_list_entry_t *entry;
	
	bdrv_close(s->bs);

	if (info != NULL && info->mem > 0)
	        munmap(info->mem, getpagesize() * BLKTAP_MMAP_REGION_SIZE);

	entry = s->fd_entry;
	*entry->pprev = entry->next;
	if (entry->next)
		entry->next->pprev = entry->pprev;

	qemu_set_fd_handler2(info->fd, NULL, NULL, NULL, NULL);
	close(info->fd);

	free(s->fd_entry);
	free(s->blkif);
	free(s->ring_info);
	free(s);

	return;
}

static inline fd_list_entry_t *add_fd_entry(int tap_fd, struct td_state *s)
{
	fd_list_entry_t **pprev, *entry;

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
		DPRINTF("open failed on dev %s!\n",devname);
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

			/* Setup fd_handler for qemu main loop */
			DPRINTF("set tap_fd = %d\n", tap_fd);
			qemu_set_fd_handler2(tap_fd, NULL, &handle_blktap_iomsg, NULL, s);

			break;
		}
		ptr = ptr->next;
	}	


	DPRINTF("map_new_dev = %d\n", minor);
	return minor;

 fail:
	free(devname);
	return -1;
}

static int open_disk(struct td_state *s, char *path, int readonly)
{
	struct disk_id id;
	BlockDriverState* bs;

	DPRINTF("Opening %s\n", path);
	bs = calloc(1, sizeof(*bs));

	memset(&id, 0, sizeof(struct disk_id));

	if (bdrv_open(bs, path, 0) != 0) {
		fprintf(stderr, "Could not open image file %s\n", path);
		return -ENOMEM;
	}

	s->bs = bs;
	s->flags = readonly ? TD_RDONLY : 0;
	s->size = bs->total_sectors;
	s->sector_size = 512;

	s->info = ((s->flags & TD_RDONLY) ? VDISK_READONLY : 0);

	return 0;
}

static inline void write_rsp_to_ring(struct td_state *s, blkif_response_t *rsp)
{
	tapdev_info_t *info = s->ring_info;
	blkif_response_t *rsp_d;
	
	rsp_d = RING_GET_RESPONSE(&info->fe_ring, info->fe_ring.rsp_prod_pvt);
	memcpy(rsp_d, rsp, sizeof(blkif_response_t));
	info->fe_ring.rsp_prod_pvt++;
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

static int send_responses(struct td_state *s, int res, 
		   uint64_t sector, int nr_secs, int idx, void *private)
{
	pending_req_t   *preq;
	blkif_request_t *req;
	int responses_queued = 0;
	blkif_t *blkif = s->blkif;
	int secs_done = nr_secs;

	if ( (idx > MAX_REQUESTS-1) )
	{
		DPRINTF("invalid index returned(%u)!\n", idx);
		return 0;
	}
	preq = &blkif->pending_list[idx];
	req  = &preq->req;

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

		kick_responses(s);
	}
	
	return responses_queued;
}

static void qemu_send_responses(void* opaque, int ret)
{
	struct aiocb_info* info = opaque;

	if (ret != 0) {
		DPRINTF("ERROR: ret = %d (%s)\n", ret, strerror(-ret));
	}

	send_responses(info->s, ret, info->sector, info->nr_secs, 
		info->idx, (void*) info->i);
	free(info);
}

/**
 * Callback function for the IO message pipe. Reads requests from the ring
 * and processes them (call qemu read/write functions).
 *
 * The private parameter points to the struct td_state representing the
 * disk the request is targeted at.
 */
static void handle_blktap_iomsg(void* private)
{
	struct td_state* s = private;

	RING_IDX          rp, j, i;
	blkif_request_t  *req;
	int idx, nsects, ret;
	uint64_t sector_nr;
	uint8_t *page;
	blkif_t *blkif = s->blkif;
	tapdev_info_t *info = s->ring_info;
	int page_size = getpagesize();

	struct aiocb_info *aiocb_info;

	if (info->fe_ring.sring == NULL) {
		DPRINTF("  sring == NULL, ignoring IO request\n");
		return;
	}

	rp = info->fe_ring.sring->req_prod; 
	xen_rmb();

	for (j = info->fe_ring.req_cons; j != rp; j++)
	{
		int start_seg = 0; 

		req = NULL;
		req = RING_GET_REQUEST(&info->fe_ring, j);
		++info->fe_ring.req_cons;
		
		if (req == NULL)
			continue;

		idx = req->id;

		ASSERT(blkif->pending_list[idx].secs_pending == 0);
		memcpy(&blkif->pending_list[idx].req, req, sizeof(*req));
		blkif->pending_list[idx].status = BLKIF_RSP_OKAY;
		blkif->pending_list[idx].submitting = 1;
		sector_nr = req->sector_number;

		/* Don't allow writes on readonly devices */
		if ((s->flags & TD_RDONLY) && 
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

			page  = (uint8_t*) MMAP_VADDR(info->vstart, 
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
				aiocb_info = malloc(sizeof(*aiocb_info));

				aiocb_info->s = s;
				aiocb_info->sector = sector_nr;
				aiocb_info->nr_secs = nsects;
				aiocb_info->idx = idx;
				aiocb_info->i = i;

				ret = (NULL == bdrv_aio_write(s->bs, sector_nr,
							  page, nsects,
							  qemu_send_responses,
							  aiocb_info));

				if (ret) {
					blkif->pending_list[idx].status = BLKIF_RSP_ERROR;
					DPRINTF("ERROR: bdrv_write() == NULL\n");
					goto send_response;
				}
				break;

			case BLKIF_OP_READ:
				aiocb_info = malloc(sizeof(*aiocb_info));

				aiocb_info->s = s;
				aiocb_info->sector = sector_nr;
				aiocb_info->nr_secs = nsects;
				aiocb_info->idx = idx;
				aiocb_info->i = i;

				ret = (NULL == bdrv_aio_read(s->bs, sector_nr,
							 page, nsects,
							 qemu_send_responses,
							 aiocb_info));

				if (ret) {
					blkif->pending_list[idx].status = BLKIF_RSP_ERROR;
					DPRINTF("ERROR: bdrv_read() == NULL\n");
					goto send_response;
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
			send_responses(s, 0, 0, 0, idx, (void *)(long)0);
	}
}

/**
 * Callback function for the qemu-read pipe. Reads and processes control 
 * message from the pipe.
 *
 * The parameter private is unused.
 */
static void handle_blktap_ctrlmsg(void* private)
{
	int length, len, msglen;
	char *ptr, *path;
	image_t *img;
	msg_hdr_t *msg;
	msg_newdev_t *msg_dev;
	msg_pid_t *msg_pid;
	int ret = -1;
	struct td_state *s = NULL;
	fd_list_entry_t *entry;

	char buf[MSG_SIZE];

	length = read(read_fd, buf, MSG_SIZE);

	if (length > 0 && length >= sizeof(msg_hdr_t)) 
	{
		msg = (msg_hdr_t *)buf;
		DPRINTF("blktap: Received msg, len %d, type %d, UID %d\n",
			length,msg->type,msg->cookie);

		switch (msg->type) {
		case CTLMSG_PARAMS: 			
			ptr = buf + sizeof(msg_hdr_t);
			len = (length - sizeof(msg_hdr_t));
			path = calloc(1, len + 1);
			
			memcpy(path, ptr, len); 
			DPRINTF("Received CTLMSG_PARAMS: [%s]\n", path);

			/* Allocate the disk structs */
			s = state_init();

			/*Open file*/
			if (s == NULL || open_disk(s, path, msg->readonly)) {
				msglen = sizeof(msg_hdr_t);
				msg->type = CTLMSG_IMG_FAIL;
				msg->len = msglen;
			} else {
				entry = add_fd_entry(0, s);
				entry->cookie = msg->cookie;
				DPRINTF("Entered cookie %d\n", entry->cookie);
				
				memset(buf, 0x00, MSG_SIZE); 
			
				msglen = sizeof(msg_hdr_t) + sizeof(image_t);
				msg->type = CTLMSG_IMG;
				img = (image_t *)(buf + sizeof(msg_hdr_t));
				img->size = s->size;
				img->secsize = s->sector_size;
				img->info = s->info;
				DPRINTF("Writing (size, secsize, info) = "
					"(%#" PRIx64 ", %#" PRIx64 ", %d)\n",
					s->size, s->sector_size, s->info);
			}
			len = write(write_fd, buf, msglen);
			free(path);
			break;
			
		case CTLMSG_NEWDEV:
			msg_dev = (msg_newdev_t *)(buf + sizeof(msg_hdr_t));

			s = get_state(msg->cookie);
			DPRINTF("Retrieving state, cookie %d.....[%s]\n",
				msg->cookie, (s == NULL ? "FAIL":"OK"));
			if (s != NULL) {
				ret = ((map_new_dev(s, msg_dev->devnum) 
					== msg_dev->devnum ? 0: -1));
			}	

			memset(buf, 0x00, MSG_SIZE); 
			msglen = sizeof(msg_hdr_t);
			msg->type = (ret == 0 ? CTLMSG_NEWDEV_RSP 
				              : CTLMSG_NEWDEV_FAIL);
			msg->len = msglen;

			len = write(write_fd, buf, msglen);
			break;

		case CTLMSG_CLOSE:
			s = get_state(msg->cookie);
			if (s) unmap_disk(s);
			break;			

		case CTLMSG_PID:
			memset(buf, 0x00, MSG_SIZE);
			msglen = sizeof(msg_hdr_t) + sizeof(msg_pid_t);
			msg->type = CTLMSG_PID_RSP;
			msg->len = msglen;

			msg_pid = (msg_pid_t *)(buf + sizeof(msg_hdr_t));
			process = getpid();
			msg_pid->pid = process;

			len = write(write_fd, buf, msglen);
			break;

		default:
			break;
		}
	}
}

/**
 * Opens a control socket, i.e. a pipe to communicate with blktapctrl.
 *
 * Returns the file descriptor number for the pipe; -1 in error case
 */
static int open_ctrl_socket(char *devname)
{
	int ret;
	int ipc_fd;

	if (mkdir(BLKTAP_CTRL_DIR, 0755) == 0)
		DPRINTF("Created %s directory\n", BLKTAP_CTRL_DIR);

	ret = mkfifo(devname,S_IRWXU|S_IRWXG|S_IRWXO);
	if ( (ret != 0) && (errno != EEXIST) ) {
		DPRINTF("ERROR: pipe failed (%d)\n", errno);
		return -1;
	}

	ipc_fd = open(devname,O_RDWR|O_NONBLOCK);

	if (ipc_fd < 0) {
		DPRINTF("FD open failed\n");
		return -1;
	}

	return ipc_fd;
}

/**
 * Unmaps all disks and closes their pipes
 */
void shutdown_blktap(void)
{
	fd_list_entry_t *ptr;
	struct td_state *s;
	char *devname;

	DPRINTF("Shutdown blktap\n");

	/* Unmap all disks */
	ptr = fd_start;
	while (ptr != NULL) {
		s = ptr->s;
		unmap_disk(s);
		close(ptr->tap_fd);
		ptr = ptr->next;
	}

	/* Delete control pipes */
	if (asprintf(&devname, BLKTAP_CTRL_DIR "/qemu-read-%d", domid) >= 0) {
		DPRINTF("Delete %s\n", devname);
		if (unlink(devname))
			DPRINTF("Could not delete: %s\n", strerror(errno));
		free(devname);
	}
	
	if (asprintf(&devname, BLKTAP_CTRL_DIR "/qemu-write-%d", domid) >= 0) {	
		DPRINTF("Delete %s\n", devname);
		if (unlink(devname))
			DPRINTF("Could not delete: %s\n", strerror(errno));
		free(devname);
	}
}

/**
 * Initialize the blktap interface, i.e. open a pair of pipes in /var/run/tap
 * and register a fd handler.
 *
 * Returns 0 on success.
 */
int init_blktap(void)
{
	char* devname;	

	DPRINTF("Init blktap pipes\n");

	/* Open the read pipe */
	if (asprintf(&devname, BLKTAP_CTRL_DIR "/qemu-read-%d", domid) >= 0) {	
		read_fd = open_ctrl_socket(devname);		
		free(devname);
		
		if (read_fd == -1) {
			fprintf(stderr, "Could not open %s/qemu-read-%d\n",
				BLKTAP_CTRL_DIR, domid);
			return -1;
		}
	}
	
	/* Open the write pipe */
	if (asprintf(&devname, BLKTAP_CTRL_DIR "/qemu-write-%d", domid) >= 0) {
		write_fd = open_ctrl_socket(devname);
		free(devname);
		
		if (write_fd == -1) {
			fprintf(stderr, "Could not open %s/qemu-write-%d\n",
				BLKTAP_CTRL_DIR, domid);
			close(read_fd);
			return -1;
		}
	}

	/* Attach a handler to the read pipe (called from qemu main loop) */
	qemu_set_fd_handler2(read_fd, NULL, &handle_blktap_ctrlmsg, NULL, NULL);

	/* Register handler to clean up when the domain is destroyed */
	atexit(&shutdown_blktap);

	return 0;
}
