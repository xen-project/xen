/* blkimglib.c
 *
 * file image-backed block device.
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
#include "blktaplib.h"

//#define TMP_IMAGE_FILE_NAME "/dev/sda1"
#define TMP_IMAGE_FILE_NAME "fc3.image"

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
                                                                                

typedef struct {
    /* These need to turn into an array/rbtree for multi-disk support. */
    FILE *img;
    u64  fsid;
    char imgname[MAX_IMGNAME_LEN];
    blkif_vdev_t   vdevice;
} image_t;

image_t         *images[MAX_DOMS];
blkif_request_t *reread_list[MAX_REQUESTS];

int image_control(control_msg_t *msg)
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
        
        images[domid]->img  = NULL;
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
            if (images[domid]->img != NULL)
                fclose( images[domid]->img );
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
        images[domid]->img = fopen64(TMP_IMAGE_FILE_NAME, "r+");
        if (images[domid]->img == NULL) { 
            printf("Couldn't open image file!\n");
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
 
int image_request(blkif_request_t *req)
{
    FILE *img;
    u64 sector;
    char *spage, *dpage;
    int ret, i, idx;
    blkif_response_t *rsp;
    domid_t dom = ID_TO_DOM(req->id);
    
    if ((images[dom] == NULL) || (images[dom]->img == NULL)) {
        printf("Data request for unknown domain!!! %d\n", dom);
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = req->operation;
        rsp->status = BLKIF_RSP_ERROR;
        return BLKTAP_RESPOND;
    }
    
    img = images[dom]->img;
    
    switch (req->operation) 
    {
    case BLKIF_OP_PROBE:
    {
        int fd;
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
        
        fd = fileno(img);
        if (fd == -1) {
            printf("Couldn't get image fd in PROBE!\n");
            goto err;
        }
        
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
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector = req->sector_number + (8*i);
            
            size = blkif_last_sect (req->frame_and_sects[i]) -
                   blkif_first_sect(req->frame_and_sects[i]) + 1;
            
            ret = fseeko64(img, (off_t)(sector << SECTOR_SHIFT), SEEK_SET);
            if (ret != 0) {
                printf("fseek error on WRITE\n");
                goto err;
            }
            
            DPRINTF("iWRITE: sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << SECTOR_SHIFT));
                        
            spage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            spage += blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;
            ret = fwrite(spage, size << SECTOR_SHIFT, 1, img);
            if (ret != 1) {
                printf("fwrite error on WRITE (%d)\n", errno);
                goto err;
            }
        }
        
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_WRITE;
        rsp->status = BLKIF_RSP_OKAY;
        
        return BLKTAP_RESPOND;
    }
    case BLKIF_OP_READ:
    {
        unsigned long size;
        
        for (i = 0; i < req->nr_segments; i++) {
            
            sector  = req->sector_number + (8*i);
            
            size = blkif_last_sect (req->frame_and_sects[i]) -
                   blkif_first_sect(req->frame_and_sects[i]) + 1;
            
            ret = fseeko64(img, (off_t)(sector << SECTOR_SHIFT), SEEK_SET);
            if (ret != 0) {
                printf("fseek error on READ\n");
                goto err;
            }
        
            DPRINTF("iREAD : sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << SECTOR_SHIFT));
            
            dpage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            dpage += blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;
            ret = fread(dpage, size << SECTOR_SHIFT, 1, img);
            if (ret != 1) {
                printf("fread error on READ\n");
                goto err;
            }
        }

        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_READ;
        rsp->status = BLKIF_RSP_OKAY;
        return BLKTAP_RESPOND;
    }
    }
    
    printf("Unknow block operation!\n");
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = req->operation;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}

/* the image library terminates the request stream. _resp is a noop. */
int image_response(blkif_response_t *rsp)
{   
    return BLKTAP_PASS;
}

void image_init(void)
{
    int i;
    
    for (i = 0; i < MAX_DOMS; i++)
        images[i] = NULL;
}

