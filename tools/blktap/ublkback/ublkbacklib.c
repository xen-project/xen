/* ublkbacklib.c
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
#include <err.h>
#include "blktaplib.h"

/* XXXX:  */
/* Current code just mounts this file/device to any requests that come in. */
//#define TMP_IMAGE_FILE_NAME "/dev/sda1"
#define TMP_IMAGE_FILE_NAME "fc3.image"

#define MAX_REQUESTS            64 /* must be synced with the blkif drivers. */
#define MAX_SEGMENTS_PER_REQ    11
#define SECTOR_SHIFT             9
#define MAX_AIO_REQS   (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)

#if 0
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

/* Note on pending_reqs: I assume all reqs are queued before they start to 
 * get filled.  so count of 0 is an unused record.
 */
typedef struct {
    blkif_request_t  req;
    blkif_t         *blkif;
    int              count;
} pending_req_t;

static pending_req_t    pending_list[MAX_REQUESTS];
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
static pthread_mutex_t notifier_sem = PTHREAD_MUTEX_INITIALIZER;

static struct io_event aio_events[MAX_AIO_REQS];
static int             aio_event_count = 0;

/* this is commented out in libaio.h for some reason. */
extern int io_queue_wait(io_context_t ctx, struct timespec *timeout);

static void *notifier_thread(void *arg)
{
    int ret; 
    int msg = 0x00feeb00;
    
    DPRINTF("Notifier thread started.\n");
    for (;;) {
        pthread_mutex_lock(&notifier_sem);
        if ((ret = io_getevents(ctx, 1, MAX_AIO_REQS, aio_events, 0)) > 0) {
            aio_event_count = ret;
            write(aio_notify[WRITE], &msg, sizeof(msg));
        } else {
                printf("[io_queue_wait error! %d]\n", errno);
                pthread_mutex_unlock(&notifier_sem);
        }
    }
}

/* --- Talking to xenstore: ------------------------------------------- */

int ublkback_request(blkif_t *blkif, blkif_request_t *req, int batch_done);
int ublkback_response(blkif_t *blkif, blkif_response_t *rsp, int batch_done);

typedef struct image {
    /* These need to turn into an array/rbtree for multi-disk support. */
    int  fd;
    uint64_t  fsid;
    blkif_vdev_t   vdevice;
    long int size;
    long int secsize;
    long int info;
} image_t;

long int ublkback_get_size(blkif_t *blkif)
{
    image_t *img = (image_t *)blkif->prv;
    return img->size;
}

long int ublkback_get_secsize(blkif_t *blkif)
{
    image_t *img = (image_t *)blkif->prv;
    return img->secsize;
}

unsigned ublkback_get_info(blkif_t *blkif)
{
    image_t *img = (image_t *)blkif->prv;
    return img->info;
}

static struct blkif_ops ublkback_ops = {
    get_size:    ublkback_get_size,
    get_secsize: ublkback_get_secsize,
    get_info:    ublkback_get_info,
};

int ublkback_new_blkif(blkif_t *blkif)
{
    image_t *image;
    struct stat stat;
    int ret;

    image = (image_t *)malloc(sizeof(image_t));
    if (image == NULL) {
        printf("error allocating image record.\n");
        return -ENOMEM;
    }

    /* Open it. */
    image->fd = open(TMP_IMAGE_FILE_NAME, 
                     O_RDWR | O_DIRECT | O_LARGEFILE);

    if ((image->fd < 0) && (errno == EINVAL)) {
        /* Maybe O_DIRECT isn't supported. */
        warn("open() failed on '%s', trying again without O_DIRECT",
               TMP_IMAGE_FILE_NAME);
        image->fd = open(TMP_IMAGE_FILE_NAME, O_RDWR | O_LARGEFILE);
    }

    if (image->fd < 0) {
        warn("Couldn't open image file!");
        free(image);
        return -EINVAL;
    }

    /* Size it. */
    ret = fstat(image->fd, &stat);
    if (ret != 0) {
        printf("Couldn't stat image in PROBE!");
        return -EINVAL;
    }
    
    image->size = (stat.st_size >> SECTOR_SHIFT);

    /* TODO: IOCTL to get size of raw device. */
/*
  ret = ioctl(img->fd, BLKGETSIZE, &blksize);
  if (ret != 0) {
  printf("Couldn't ioctl image in PROBE!\n");
  goto err;
  }
*/
    if (image->size == 0)
        image->size =((uint64_t) 16836057);
    image->secsize = 512;
    image->info = 0;

    /* Register the hooks */
    blkif_register_request_hook(blkif, "Ublkback req.", ublkback_request);
    blkif_register_response_hook(blkif, "Ublkback resp.", ublkback_response);


    printf(">X<Created a new blkif! pdev was %ld, but you got %s\n", 
           blkif->pdev, TMP_IMAGE_FILE_NAME);

    blkif->ops = &ublkback_ops;
    blkif->prv = (void *)image;

    return 0;
}


/* --- Moving the bits: ----------------------------------------------- */

static int batch_count = 0;
int ublkback_request(blkif_t *blkif, blkif_request_t *req, int batch_done)
{
    int fd;
    uint64_t sector;
    char *spage, *dpage;
    int ret, i, idx;
    blkif_response_t *rsp;
    domid_t dom = ID_TO_DOM(req->id);
    static struct iocb *ioq[MAX_SEGMENTS_PER_REQ*MAX_REQUESTS]; 
    static int io_idx = 0;
    struct iocb *io;
    image_t *img;

    img = (image_t *)blkif->prv;
    fd = img->fd;

    switch (req->operation) 
    {
    case BLKIF_OP_WRITE:
    {
        unsigned long size;

        batch_count++;

        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        pending_list[idx].blkif = blkif;
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector = req->sector_number + (8*i);
            
            size = req->seg[i].last_sect - req->seg[i].first_sect + 1;
            
            if (req->seg[i].first_sect != 0)
                DPRINTF("iWR: sec_nr: %10llu sec: %10llu (%1lu,%1lu) "
                        "pos: %15lu\n",
                        req->sector_number, sector, 
                        req->seg[i].first_sect, req->seg[i].last_sect,
                        (long)(sector << SECTOR_SHIFT));
                        
            spage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            spage += req->seg[i].first_sect << SECTOR_SHIFT;
            
            /*convert size and sector to byte offsets */
            size   <<= SECTOR_SHIFT;
            sector <<= SECTOR_SHIFT;
            
            io = iocb_free[--iocb_free_count];
            io_prep_pwrite(io, fd, spage, size, sector);
            io->data = (void *)idx;
            //ioq[i] = io;
            ioq[io_idx++] = io;
        }

        if (batch_done) {
            ret = io_submit(ctx, io_idx, ioq);
            batch_count = 0;
            if (ret < 0)
                printf("BADNESS: io_submit error! (%d)\n", errno);
            io_idx = 0;
        }
        
        return BLKTAP_STOLEN;
        
    }
    case BLKIF_OP_READ:
    {
        unsigned long size;
        
        batch_count++;
        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        pending_list[idx].blkif = blkif;
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector  = req->sector_number + (8*i);
            
            size = req->seg[i].last_sect - req->seg[i].first_sect + 1;

            dpage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            dpage += req->seg[i].first_sect << SECTOR_SHIFT;
            
            if (req->seg[i].first_sect != 0)
                DPRINTF("iRD : sec_nr: %10llu sec: %10llu (%1lu,%1lu) "
                        "pos: %15lu dpage: %p\n", 
                        req->sector_number, sector, 
                        req->seg[i].first_sect, req->seg[i].last_sect,
                        (long)(sector << SECTOR_SHIFT), dpage);
            
            /*convert size and sector to byte offsets */
            size   <<= SECTOR_SHIFT;
            sector <<= SECTOR_SHIFT;
            

            /*
             * NB: Looks like AIO now has non-page aligned support, this path 
             * can probably be removed...  Only really used for hunting
             * superblocks anyway... ;)
             */
            if ( ((unsigned long)dpage % PAGE_SIZE) != 0 ) {
                /* AIO to raw devices must be page aligned, so do this read
                 * synchronously.  The OS is probably just looking for 
                 * a superblock or something, so this won't hurt performance. 
                 */
                int ret;

                printf("Slow path block read.\n");
                /* Question: do in-progress aio ops modify the file cursor? */
                ret = lseek(fd, sector, SEEK_SET);
                if (ret == (off_t)-1)
                    printf("lseek failed!\n");
                ret = read(fd, dpage, size);
                if (ret < 0)
                    printf("read problem (%d)\n", ret);
                printf("|\n|\n| read: %lld, %lu, %d\n|\n|\n", sector, size, ret);

                /* not an async request any more... */
                pending_list[idx].count--;

                rsp = (blkif_response_t *)req;
                rsp->id = req->id;
                rsp->operation = BLKIF_OP_READ;
                rsp->status = BLKIF_RSP_OKAY;
                return BLKTAP_RESPOND;  
                /* Doh -- need to flush aio if this is end-of-batch */
            }

            io = iocb_free[--iocb_free_count];
            
            io_prep_pread(io, fd, dpage, size, sector);
            io->data = (void *)idx;
            
            ioq[io_idx++] = io;
            //ioq[i] = io;
        }
        
        if (batch_done) {
            ret = io_submit(ctx, io_idx, ioq);
            batch_count = 0;
            if (ret < 0)
                printf("BADNESS: io_submit error! (%d)\n", errno);
            io_idx = 0;
        }
        
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


int ublkback_pollhook(int fd)
{
    struct io_event *ep;
    int n, ret, idx;
    blkif_request_t *req;
    blkif_response_t *rsp;
    int responses_queued = 0;
    int pages=0;
    
    for (ep = aio_events; aio_event_count-- > 0; ep++) {
        struct iocb *io = ep->obj;
        idx = (int) ep->data;
        
        if ((idx > MAX_REQUESTS-1) || (pending_list[idx].count == 0)){
            printf("invalid index returned(%u)!\n", idx);
            break;
        }
        
        if ((int)ep->res < 0) 
            printf("***\n***aio request error! (%d,%d)\n***\n", 
                   (int)ep->res, (int)ep->res2);
        
        pending_list[idx].count--;
        iocb_free[iocb_free_count++] = io;
        pages++;

        if (pending_list[idx].count == 0) {
            blkif_request_t tmp = pending_list[idx].req;
            rsp = (blkif_response_t *)&pending_list[idx].req;
            rsp->id = tmp.id;
            rsp->operation = tmp.operation;
            rsp->status = BLKIF_RSP_OKAY;
            blkif_inject_response(pending_list[idx].blkif, rsp);
            responses_queued++;
        }
    }

    if (responses_queued) {
        blktap_kick_responses();
    }
    
    read(aio_notify[READ], &idx, sizeof(idx));
    aio_listening = 1;
    pthread_mutex_unlock(&notifier_sem);
    
    return 0;
}

/* the image library terminates the request stream. _resp is a noop. */
int ublkback_response(blkif_t *blkif, blkif_response_t *rsp, int batch_done)
{   
    return BLKTAP_PASS;
}

void ublkback_init(void)
{
    int i, rc;
    pthread_t p;
    
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
    
    blktap_attach_poll(aio_notify[READ], POLLIN, ublkback_pollhook);
}

