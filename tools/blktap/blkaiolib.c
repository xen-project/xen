/* blkaiolib.c
 *
 * file/device image-backed block device -- using linux libaio.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * Xend has been modified to use an amorfs:[fsid] disk tag.
 * This will show up as device type (maj:240,min:0) = 61440.
 *
 * The fsid is placed in the sec_start field of the disk extent.
 *
 * NOTE: This doesn't work.  Grrr.
 */

#define _GNU_SOURCE
#define __USE_LARGEFILE64

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <db.h>       
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <unistd.h>
#include <errno.h>
#include <libaio.h>
#include <pthread.h>
#include <time.h>
#include "blktaplib.h"

//#define TMP_IMAGE_FILE_NAME "/dev/sda1"
#define TMP_IMAGE_FILE_NAME "fc3.image"

#define MAX_DOMS              1024
#define MAX_IMGNAME_LEN        255
#define AMORFS_DEV           61440
#define MAX_REQUESTS            64 /* must be synced with the blkif drivers. */
#define MAX_SEGMENTS_PER_REQ    11
#define SECTOR_SHIFT             9
#define MAX_AIO_REQS   (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)
                                                                                
#if 1
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif
           
#if 1                                                                        
#define ASSERT(_p) \
    if ( !(_p) ) { printf("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif                                                                     

char dbg_page[4096];

typedef struct {
    /* These need to turn into an array/rbtree for multi-disk support. */
    int  fd;
    u64  fsid;
    char imgname[MAX_IMGNAME_LEN];
    blkif_vdev_t   vdevice;
} image_t;

/* Note on pending_reqs: I assume all reqs are queued before they start to 
 * get filled.  so count of 0 is an unused record.
 */
typedef struct {
    blkif_request_t  req;
    int              count;
} pending_req_t;

static pending_req_t    pending_list[MAX_REQUESTS];
image_t                *images[MAX_DOMS];

static io_context_t  ctx;
static struct iocb  *iocb_free[MAX_AIO_REQS];
static int           iocb_free_count;

/* ---[ Notification mecahnism ]--------------------------------------- */

enum { 
    READ   = 0,
    WRITE  = 1
};

static int aio_notify[2];
static volatile int aio_listening = 0;

static struct io_event aio_events[MAX_AIO_REQS];
static int             aio_event_count = 0;

/* this is commented out in libaio.h for some reason. */
extern int io_queue_wait(io_context_t ctx, struct timespec *timeout);

static void *notifier_thread(void *arg)
{
    int ret; 
    int msg = 0x00feeb00;
    
    printf("Notifier thread started.\n");
    for (;;) {
        //if ((aio_listening) && ((ret = io_queue_wait(ctx, 0)) == 0)) {
        if ((aio_listening) && 
           ((ret = io_getevents(ctx, 1, MAX_AIO_REQS, aio_events, 0)) > 0)) {
            aio_event_count = ret;
            printf("[Notifying! (%d)]\n", aio_event_count);
            aio_listening = 0;
            write(aio_notify[WRITE], &msg, sizeof(msg));
            fsync(aio_notify[WRITE]);
        } else {
            if (aio_listening)
                printf("[io_queue_wait error! %d]\n", errno);
            usleep(1000); /* Not ready to read. */
        }
    }
}

/* -------------------------------------------------------------------- */

int aio_control(control_msg_t *msg)
{
    domid_t  domid;
    DB      *db;
    int      ret;
    
    if (msg->type != CMSG_BLKIF_BE) 
    {
        printf("***\nUNEXPECTED CTRL MSG MAJOR TYPE(%d)\n***\n", msg->type);
        return 0;
    }
    
    switch(msg->subtype)
    {
    case CMSG_BLKIF_BE_CREATE:
        if ( msg->length != sizeof(blkif_be_create_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_CREATE(d:%d,h:%d)\n",
                ((blkif_be_create_t *)msg->msg)->domid,
                ((blkif_be_create_t *)msg->msg)->blkif_handle);
        domid = ((blkif_be_create_t *)msg->msg)->domid;
        if (images[domid] != NULL) {
            printf("attempt to connect from an existing dom!\n");
            return 0;
        }
        
        images[domid] = (image_t *)malloc(sizeof(image_t));
        if (images[domid] == NULL) {
            printf("error allocating image record.\n");
            return 0;
        }
        
        images[domid]->fd  = -1;
        images[domid]->fsid = 0;
        
        printf("Image connected.\n");
        break;   
        
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_be_destroy_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_DESTROY(d:%d,h:%d)\n",
                ((blkif_be_destroy_t *)msg->msg)->domid,
                ((blkif_be_destroy_t *)msg->msg)->blkif_handle);
        
        domid = ((blkif_be_destroy_t *)msg->msg)->domid;
        if (images[domid] != NULL) {
            if (images[domid]->fd != -1)
                close( images[domid]->fd );
            free( images[domid] );
            images[domid] = NULL;
        }
        break;  
    case CMSG_BLKIF_BE_VBD_GROW:
    {
        blkif_be_vbd_grow_t *grow;
        
        if ( msg->length != sizeof(blkif_be_vbd_grow_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_VBD_GROW(d:%d,h:%d,v:%d)\n",
                ((blkif_be_vbd_grow_t *)msg->msg)->domid,
                ((blkif_be_vbd_grow_t *)msg->msg)->blkif_handle,
                ((blkif_be_vbd_grow_t *)msg->msg)->vdevice);
        printf("              Extent: sec_start: %llu sec_len: %llu, dev: %d\n",
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.sector_start,
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.sector_length,
                ((blkif_be_vbd_grow_t *)msg->msg)->extent.device);
        grow = (blkif_be_vbd_grow_t *)msg->msg;
        domid = grow->domid;
        if (images[domid] == NULL) {
            printf("VBD_GROW on unconnected domain!\n");
            return 0;
        }
        
        if (grow->extent.device != AMORFS_DEV) {
            printf("VBD_GROW on non-amorfs device!\n");
            return 0;
        }
        
        /* TODO: config support for arbitrary image files/modes. */
        sprintf(images[domid]->imgname, TMP_IMAGE_FILE_NAME);
        
        images[domid]->fsid   = grow->extent.sector_start;
        images[domid]->vdevice = grow->vdevice; 
        images[domid]->fd = open(TMP_IMAGE_FILE_NAME, 
                O_RDWR | O_DIRECT | O_LARGEFILE);
        if (images[domid]->fd < 0) {
            printf("Couldn't open image file! %d\n", errno);
            return 0;
        }
        
        printf("Image file opened. (%s)\n", images[domid]->imgname);
        break;
    }    
    }
    return 0;
parse_error:
    printf("Bad control message!\n");
    return 0;
    
create_failed:
    /* TODO: close the db ref. */
    return 0;
}    
 
int aio_request(blkif_request_t *req)
{
    int fd;
    u64 sector;
    char *spage, *dpage;
    int ret, i, idx;
    blkif_response_t *rsp;
    domid_t dom = ID_TO_DOM(req->id);
    
    if ((images[dom] == NULL) || (images[dom]->fd == -1)) {
        printf("Data request for unknown domain!!! %d\n", dom);
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = req->operation;
        rsp->status = BLKIF_RSP_ERROR;
        return BLKTAP_RESPOND;
    }
    
    fd = images[dom]->fd;
    
    switch (req->operation) 
    {
    case BLKIF_OP_PROBE:
    {
        struct stat stat;
        vdisk_t *img_info;
        
        
        /* We expect one buffer only. */
        if ( req->nr_segments != 1 )
            goto err;
                                                                                
        /* Make sure the buffer is page-sized. */
        if ( (blkif_first_sect(req->frame_and_sects[0]) != 0) ||
             (blkif_last_sect (req->frame_and_sects[0]) != 7) )
            goto err;

        /* loop for multiple images would start here. */
        
        ret = fstat(fd, &stat);
        if (ret != 0) {
            printf("Couldn't stat image in PROBE!\n");
            goto err;
        }
        
        img_info = (vdisk_t *)MMAP_VADDR(ID_TO_IDX(req->id), 0);
        img_info[0].device   = images[dom]->vdevice;
        img_info[0].info     = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;
        img_info[0].capacity = (stat.st_size >> SECTOR_SHIFT);
        
        if (img_info[0].capacity == 0)
            img_info[0].capacity = ((u64)1 << 63); // xend does this too.
        
        DPRINTF("iPROBE! device: 0x%04x capacity: %llu\n", img_info[0].device,
                img_info[0].capacity);
        
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_PROBE;
        rsp->status = 1; /* number of disks */
        
        return  BLKTAP_RESPOND;
    }    
    case BLKIF_OP_WRITE:
    {
        unsigned long size;
        struct iocb *io;
        struct iocb *ioq[MAX_SEGMENTS_PER_REQ]; 
        
        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector = req->sector_number + (8*i);
            
            size = blkif_last_sect (req->frame_and_sects[i]) -
                   blkif_first_sect(req->frame_and_sects[i]) + 1;
            
            DPRINTF("iWRITE: sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << SECTOR_SHIFT));
                        
            spage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            spage += blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;
            
            /*convert size and sector to byte offsets */
            size   <<= SECTOR_SHIFT;
            sector <<= SECTOR_SHIFT;
            
            io = iocb_free[--iocb_free_count];
            io_prep_pwrite(io, fd, spage, size, sector);
            io->data = (void *)idx;
            ioq[i] = io;
        }
        
        ret = io_submit(ctx, req->nr_segments, ioq);
        if (ret < 0)
            printf("BADNESS: io_submit error! (%d)\n", errno);
        
        pending_list[idx].count = req->nr_segments;
        
        return BLKTAP_STOLEN;
        
    }
    case BLKIF_OP_READ:
    {
        unsigned long size;
        struct iocb *io;
        struct iocb *ioq[MAX_SEGMENTS_PER_REQ]; 
        
        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector  = req->sector_number + (8*i);
            
            size = blkif_last_sect (req->frame_and_sects[i]) -
                   blkif_first_sect(req->frame_and_sects[i]) + 1;
            
            dpage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            dpage += blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;
            
            
            DPRINTF("iREAD : sec_nr: %10llu sec: %10llu (%1lu,%1lu) "
                    "pos: %15lu dpage: %p\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << SECTOR_SHIFT), dpage);
            
            /*convert size and sector to byte offsets */
            size   <<= SECTOR_SHIFT;
            sector <<= SECTOR_SHIFT;
            
            io = iocb_free[--iocb_free_count];
            
            io_prep_pread(io, fd, dpage, size, sector);
            io->data = (void *)idx;
            
            ioq[i] = io;
        }
        
        ret = io_submit(ctx, req->nr_segments, ioq);
        if (ret < 0)
            printf("BADNESS: io_submit error! (%d)\n", errno);
        
        
        return BLKTAP_STOLEN;
        
    }
    }
    
    printf("Unknown block operation!\n");
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = req->operation;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}


int aio_pollhook(int fd)
{
    struct io_event *ep;
    int n, ret, idx;
    blkif_request_t *req;
    blkif_response_t *rsp;
    
    DPRINTF("aio_hook(): \n");
    
    for (ep = aio_events; aio_event_count-- > 0; ep++) {
        struct iocb *io = ep->obj;
        idx = (int) ep->data;
        
        if ((idx > MAX_REQUESTS-1) || (pending_list[idx].count == 0)){
            printf("gnbd returned a bad cookie (%u)!\n", idx);
            break;
        }
        
        if ((int)ep->res < 0) printf("aio request error! (%d,%d)\n", 
            (int)ep->res, (int)ep->res2);
        
        pending_list[idx].count--;
        iocb_free[iocb_free_count++] = io;
        
        if (pending_list[idx].count == 0) {
            blkif_request_t tmp = pending_list[idx].req;
            rsp = (blkif_response_t *)&pending_list[idx].req;
            rsp->id = tmp.id;
            rsp->operation = tmp.operation;
            rsp->status = BLKIF_RSP_OKAY;
            blktap_inject_response(rsp);
        }
    }
    
    printf("pollhook done!\n");
    
    read(aio_notify[READ], &idx, sizeof(idx));
    aio_listening = 1;
    
    return 0;
}

/* the image library terminates the request stream. _resp is a noop. */
int aio_response(blkif_response_t *rsp)
{   
    return BLKTAP_PASS;
}

void aio_init(void)
{
    int i, rc;
    pthread_t p;
    
    for (i = 0; i < MAX_DOMS; i++)
        images[i] = NULL;
    
    for (i = 0; i < MAX_REQUESTS; i++)
        pending_list[i].count = 0; 
    
    memset(&ctx, 0, sizeof(ctx));
    rc = io_queue_init(MAX_AIO_REQS, &ctx);
    if (rc != 0) {
        printf("queue_init failed! (%d)\n", rc);
        exit(0);
    }
    
    for (i=0; i<MAX_AIO_REQS; i++) {
        if (!(iocb_free[i] = (struct iocb *)malloc(sizeof(struct iocb)))) {
            printf("error allocating iocb array\n");
            exit(0);
        }
        iocb_free_count = i;
    }
    
    rc = pipe(aio_notify);
    if (rc != 0) {
        printf("pipe failed! (%d)\n", errno);
        exit(0);
    }
    
    rc = pthread_create(&p, NULL, notifier_thread, NULL);
    if (rc != 0) {
        printf("pthread_create failed! (%d)\n", errno);
        exit(0);
    }
    
    aio_listening = 1;
    
    blktap_attach_poll(aio_notify[READ], POLLIN, aio_pollhook);
}

