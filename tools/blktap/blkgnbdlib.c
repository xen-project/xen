/* blkgnbdlib.c
 *
 * gnbd image-backed block device.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * Xend has been modified to use an amorfs:[fsid] disk tag.
 * This will show up as device type (maj:240,min:0) = 61440.
 *
 * The fsid is placed in the sec_start field of the disk extent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <db.h>       
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include "blktaplib.h"
#include "libgnbd/libgnbd.h"

#define GNBD_SERVER  "skirmish.cl.cam.ac.uk"
#define GNBD_CLIENT  "pengi-0.xeno.cl.cam.ac.uk"
#define GNBD_MOUNT   "fc2_akw27"
#define GNBD_PORT    0x38e7

#define MAX_DOMS        1024
#define MAX_IMGNAME_LEN  255
#define AMORFS_DEV     61440
#define MAX_REQUESTS      64 /* must be synced with the blkif drivers. */
#define SECTOR_SHIFT       9
                                                                                
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

#define GH_DISCONNECTED 0
#define GH_PROBEWAITING 1
#define GH_CONNECTED    2

typedef struct {
    /* These need to turn into an array/rbtree for multi-disk support. */
    struct gnbd_handle *gh;
    int          gh_state;
    int          probe_idx; /* This really needs cleaning up after hotos. */
    int          fd;
    u64          fsid;
    char         gnbdname[MAX_IMGNAME_LEN];
    blkif_vdev_t vdevice;
} gnbd_t;

/* Note on pending_reqs: I assume all reqs are queued before they start to 
 * get filled.  so count of 0 is an unused record.
 */
typedef struct {
    blkif_request_t  req;
    int              count;
} pending_req_t;

static gnbd_t          *gnbds[MAX_DOMS];
static pending_req_t    pending_list[MAX_REQUESTS];
static int              pending_count = 0; /* debugging */


gnbd_t *get_gnbd_by_fd(int fd)
{
    /* this is a linear scan for the moment.  nees to be cleaned up for
       multi-disk support. */
    
    int i;
    
    for (i=0; i< MAX_DOMS; i++) 
        if ((gnbds[i] != NULL) && (gnbds[i]->fd == fd))
            return gnbds[i];
    
    return NULL;
}

int gnbd_pollhook(int fd);

int gnbd_control(control_msg_t *msg)
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
        if (gnbds[domid] != NULL) {
            printf("attempt to connect from an existing dom!\n");
            return 0;
        }
        
        gnbds[domid] = (gnbd_t *)malloc(sizeof(gnbd_t));
        if (gnbds[domid] == NULL) {
            printf("error allocating gnbd record.\n");
            return 0;
        }
        
        gnbds[domid]->gh  = NULL;
        gnbds[domid]->fsid = 0;
        
        break;   
        
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_be_destroy_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_DESTROY(d:%d,h:%d)\n",
                ((blkif_be_destroy_t *)msg->msg)->domid,
                ((blkif_be_destroy_t *)msg->msg)->blkif_handle);
        
        domid = ((blkif_be_destroy_t *)msg->msg)->domid;
        if (gnbds[domid] != NULL) {
            if (gnbds[domid]->gh != NULL) {
                blktap_detach_poll(gnbds[domid]->fd);
                free(gnbds[domid]->gh); /* XXX: Need a gnbd close call! */;
            }
            free( gnbds[domid] );
            gnbds[domid] = NULL;
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
        if (gnbds[domid] == NULL) {
            printf("VBD_GROW on unconnected domain!\n");
            return 0;
        }
        
        if (grow->extent.device != AMORFS_DEV) {
            printf("VBD_GROW on non-amorfs device!\n");
            return 0;
        }
        
        /* TODO: config support for arbitrary gnbd files/modes. */
        sprintf(gnbds[domid]->gnbdname, GNBD_MOUNT);
        
        gnbds[domid]->fsid   = grow->extent.sector_start;
        gnbds[domid]->vdevice = grow->vdevice; 
        gnbds[domid]->gh_state = GH_DISCONNECTED;
        gnbds[domid]->gh = gnbd_setup(GNBD_SERVER, GNBD_PORT, 
            gnbds[domid]->gnbdname, GNBD_CLIENT);
        if (gnbds[domid]->gh == NULL) { 
            printf("Couldn't connect to gnbd mount!!\n");
            return 0;
        }
        gnbds[domid]->fd = gnbd_fd(gnbds[domid]->gh);
        blktap_attach_poll(gnbds[domid]->fd, POLLIN, gnbd_pollhook);
        
        printf("gnbd mount connected. (%s)\n", gnbds[domid]->gnbdname);
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
 
static int gnbd_blkif_probe(blkif_request_t *req, gnbd_t *gnbd)
{
    int fd;
    struct stat stat;
    vdisk_t *gnbd_info;
    blkif_response_t *rsp;

    /* We expect one buffer only. */
    if ( req->nr_segments != 1 )
        goto err;

    /* Make sure the buffer is page-sized. */
    if ( (blkif_first_sect(req->frame_and_sects[0]) != 0) ||
         (blkif_last_sect (req->frame_and_sects[0]) != 7) )
        goto err;

    /* loop for multiple gnbds would start here. */

    gnbd_info = (vdisk_t *)MMAP_VADDR(ID_TO_IDX(req->id), 0);
    gnbd_info[0].device   = gnbd->vdevice;
    gnbd_info[0].info     = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;
    gnbd_info[0].capacity = gnbd_sectors(gnbd->gh);

    printf("[SECTORS] %llu", gnbd_info[0].capacity);

    //if (gnbd_info[0].capacity == 0)
    //    gnbd_info[0].capacity = ((u64)1 << 63); // xend does this too.

    DPRINTF("iPROBE! device: 0x%04x capacity: %llu\n", gnbd_info[0].device,
            gnbd_info[0].capacity);

    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_PROBE;
    rsp->status = 1; /* number of disks */

    return  BLKTAP_RESPOND;
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = req->operation;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}

int gnbd_request(blkif_request_t *req)
{
    struct gnbd_handle *gh;
    u64 sector;
    char *spage, *dpage;
    int ret, i, idx;
    blkif_response_t *rsp;
    domid_t dom = ID_TO_DOM(req->id);
    
    if ((gnbds[dom] == NULL) || (gnbds[dom]->gh == NULL)) {
        printf("Data request for unknown domain!!! %d\n", dom);
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = req->operation;
        rsp->status = BLKIF_RSP_ERROR;
        return BLKTAP_RESPOND;
    }
    
    gh = gnbds[dom]->gh;
    
    switch (req->operation) 
    {
    case BLKIF_OP_PROBE:
    {
        printf("PROBE!\n");
        if ( gnbds[dom]->gh_state == GH_PROBEWAITING ) {
            printf("Already have a PROBE outstanding!\n");
            goto err;
        }
        
        if ( gnbds[dom]->gh_state == GH_DISCONNECTED )
        {
            /* need to defer until we are connected. */
            printf("Deferring PROBE!\n");
            idx = ID_TO_IDX(req->id);
            memcpy(&pending_list[idx].req, req, sizeof(*req));
            ASSERT(pending_list[idx].count == 0);
            pending_list[idx].count = 1;
            
            gnbds[dom]->probe_idx = idx;
            gnbds[dom]->gh_state  = GH_PROBEWAITING;

            return BLKTAP_STOLEN;
        }
            
        
        return gnbd_blkif_probe(req, gnbds[dom]);
    }    
    case BLKIF_OP_WRITE:
    {
        unsigned long size;
        
        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        pending_count++; /* dbg */
        
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
            
            ret = gnbd_write(gh, sector, size, spage, (unsigned long)idx);
            if (ret) {
                printf("gnbd error on WRITE\n");
                goto err;
            }
        }
//printf("[WR] < %lu\n", (unsigned long)idx);
        
        return BLKTAP_STOLEN;
    }
    case BLKIF_OP_READ:
    {
        unsigned long size;
        
        idx = ID_TO_IDX(req->id);
        ASSERT(pending_list[idx].count == 0);
        memcpy(&pending_list[idx].req, req, sizeof(*req));
        pending_list[idx].count = req->nr_segments;
        pending_count++; /* dbg */
            
        for (i = 0; i < req->nr_segments; i++) {
            
            sector  = req->sector_number + (8*i);
            
            size = blkif_last_sect (req->frame_and_sects[i]) -
                   blkif_first_sect(req->frame_and_sects[i]) + 1;
            
            DPRINTF("iREAD : sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << SECTOR_SHIFT));
            
            dpage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            dpage += blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;
            
            ret = gnbd_read(gh, sector, size, dpage, (unsigned long)idx);
            if (ret) {
                printf("gnbd error on READ\n");
                goto err;
            }
            
        }
//printf("[RD] < %lu\n", (unsigned long)idx);
        
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

/* the gnbd library terminates the request stream. _resp is a noop. */
int gnbd_response(blkif_response_t *rsp)
{   
    return BLKTAP_PASS;
}

int gnbd_pollhook(int fd)
{
    int err;
    struct gnbd_handle *gh;
    blkif_request_t *req;
    blkif_response_t *rsp;
    unsigned long idx;
    
    gnbd_t *gnbd = get_gnbd_by_fd(fd);
    
    if (gnbd == NULL) {
        printf("GNBD badness: got poll hook on unknown device. (%d)\n", fd);
        return -1;
    }
    gh = gnbd->gh;
    err = gnbd_reply(gh);
    switch (err) {
    case GNBD_LOGIN_DONE:
        if (gnbd->gh_state == GH_PROBEWAITING) {
            req = (blkif_request_t *)&pending_list[gnbd->probe_idx].req;
            printf("[!] Sending deferred PROBE!\n");
            gnbd_blkif_probe(req, gnbd);
            pending_list[gnbd->probe_idx].count = 0;
            rsp = (blkif_response_t *)req;
            blktap_inject_response(rsp);
        }
        gnbd->gh_state = GH_CONNECTED;
        printf("GNBD_LOGIN_DONE (%d)\n", fd); 
        break;

    case GNBD_REQUEST_DONE: /* switch to idx */
        idx = gnbd_finished_request(gh);
        req = (blkif_request_t *)&pending_list[idx].req;
        if ((idx > MAX_REQUESTS-1) || (pending_list[idx].count == 0)){
            printf("gnbd returned a bad cookie (%lu)!\n", idx);
            break;
        }
        
        pending_list[idx].count--;
        
        if (pending_list[idx].count == 0) {
            blkif_request_t tmp = *req;
            pending_count--; /* dbg */
            rsp = (blkif_response_t *)req;
            rsp->id = tmp.id;
            rsp->operation = tmp.operation;
            rsp->status = BLKIF_RSP_OKAY;
            blktap_inject_response(rsp);
/*
if (rsp->operation == BLKIF_OP_READ) {
printf("[RD] > %lu (%d pndg)\n", (unsigned long)idx, pending_count);
} else if (rsp->operation == BLKIF_OP_WRITE) {
printf("[WR] > %lu (%d pndg)\n", (unsigned long)idx, pending_count);
} else  {
printf("[??] > %lu (%d pndg)\n", (unsigned long)idx, pending_count);
}
*/
        }
        break;
        
    case GNBD_CONTINUE:
        break;
        
    case 0:
        break;
        
    default:
        printf("gnbd_reply error");
        break;
    }
    return 0;
}

void gnbd_init(void)
{   
    int i;
    
    for (i = 0; i < MAX_DOMS; i++)
        gnbds[i] = NULL;
    
    for (i = 0; i < MAX_REQUESTS; i++)
        pending_list[i].count = 0; 
    
    printf("GNBD image plugin initialized\n");
}

