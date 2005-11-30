/**************************************************************************
 * 
 * parallax.c
 *
 * The Parallax Storage Server
 *
 */
 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "blktaplib.h"
#include "blockstore.h"
#include "vdi.h"
#include "block-async.h"
#include "requests-async.h"

#define PARALLAX_DEV     61440
#define SECTS_PER_NODE   8


#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* ------[ session records ]----------------------------------------------- */

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) (((int)(_d)^(int)(_h))&(BLKIF_HASHSZ-1))

#define VDI_HASHSZ 16
#define VDI_HASH(_vd) ((((_vd)>>8)^(_vd))&(VDI_HASHSZ-1))

typedef struct blkif {
    domid_t       domid;
    unsigned int  handle;
    enum { DISCONNECTED, DISCONNECTING, CONNECTED } status;
    vdi_t        *vdi_hash[VDI_HASHSZ];
    struct blkif *hash_next;
} blkif_t;

static blkif_t      *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
    if ( handle != 0 )
        printf("blktap/parallax don't currently support non-0 dev handles!\n");
    
    blkif_t *blkif = blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif != NULL) && 
            ((blkif->domid != domid) || (blkif->handle != handle)) )
        blkif = blkif->hash_next;
    return blkif;
}

vdi_t *blkif_get_vdi(blkif_t *blkif, blkif_vdev_t device)
{
    vdi_t *vdi = blkif->vdi_hash[VDI_HASH(device)];
    
    while ((vdi != NULL) && (vdi->vdevice != device))
        vdi = vdi->next;
    
    return vdi;
}

/* ------[ control message handling ]-------------------------------------- */

void blkif_create(blkif_be_create_t *create)
{
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;
    blkif_t     **pblkif, *blkif;

    DPRINTF("parallax (blkif_create): create is %p\n", create); 
    
    if ( (blkif = (blkif_t *)malloc(sizeof(blkif_t))) == NULL )
    {
        DPRINTF("Could not create blkif: out of memory\n");
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid  = domid;
    blkif->handle = handle;
    blkif->status = DISCONNECTED;

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif != NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            DPRINTF("Could not create blkif: already exists (%d,%d)\n",
                domid, handle);
            create->status = BLKIF_BE_STATUS_INTERFACE_EXISTS;
            free(blkif);
            return;
        }
        pblkif = &(*pblkif)->hash_next;
    }

    blkif->hash_next = *pblkif;
    *pblkif = blkif;

    DPRINTF("Successfully created blkif\n");
    create->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_destroy(blkif_be_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->blkif_handle;
    blkif_t     **pblkif, *blkif;

    DPRINTF("parallax (blkif_destroy): destroy is %p\n", destroy); 
    
    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif = *pblkif) != NULL )
    {
        if ( (blkif->domid == domid) && (blkif->handle == handle) )
        {
            if ( blkif->status != DISCONNECTED )
                goto still_connected;
            goto destroy;
        }
        pblkif = &blkif->hash_next;
    }

    destroy->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
    return;

 still_connected:
    destroy->status = BLKIF_BE_STATUS_INTERFACE_CONNECTED;
    return;

 destroy:
    *pblkif = blkif->hash_next;
    free(blkif);
    destroy->status = BLKIF_BE_STATUS_OKAY;
}

void vbd_create(blkif_be_vbd_create_t *create)
{
    blkif_t            *blkif;
    vdi_t              *vdi, **vdip;
    blkif_vdev_t        vdevice = create->vdevice;

    DPRINTF("parallax (vbd_create): create=%p\n", create); 
    
    blkif = blkif_find_by_handle(create->domid, create->blkif_handle);
    if ( blkif == NULL )
    {
        DPRINTF("vbd_create attempted for non-existent blkif (%u,%u)\n", 
                create->domid, create->blkif_handle); 
        create->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    /* VDI identifier is in grow->extent.sector_start */
    DPRINTF("vbd_create: create->dev_handle (id) is %lx\n", 
            (unsigned long)create->dev_handle);

    vdi = vdi_get(create->dev_handle);
    if (vdi == NULL)
    {
        printf("parallax (vbd_create): VDI %lx not found.\n",
               (unsigned long)create->dev_handle);
        create->status = BLKIF_BE_STATUS_VBD_NOT_FOUND;
        return;
    }
    
    vdi->next = NULL;
    vdi->vdevice = vdevice;
    vdip = &blkif->vdi_hash[VDI_HASH(vdevice)];
    while (*vdip != NULL)
        vdip = &(*vdip)->next;
    *vdip = vdi;
    
    DPRINTF("blkif_create succeeded\n"); 
    create->status = BLKIF_BE_STATUS_OKAY;
}

void vbd_destroy(blkif_be_vbd_destroy_t *destroy)
{
    blkif_t            *blkif;
    vdi_t              *vdi, **vdip;
    blkif_vdev_t        vdevice = destroy->vdevice;
    
    blkif = blkif_find_by_handle(destroy->domid, destroy->blkif_handle);
    if ( blkif == NULL )
    {
        DPRINTF("vbd_destroy attempted for non-existent blkif (%u,%u)\n", 
                destroy->domid, destroy->blkif_handle); 
        destroy->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    vdip = &blkif->vdi_hash[VDI_HASH(vdevice)];
    while ((*vdip != NULL) && ((*vdip)->vdevice != vdevice))
        vdip = &(*vdip)->next;

    if (*vdip != NULL) 
    {
        vdi = *vdip;
        *vdip = vdi->next;
        vdi_put(vdi);
    }
        
}

int parallax_control(control_msg_t *msg)
{
    domid_t  domid;
    int      ret;

    DPRINTF("parallax_control: msg is %p\n", msg); 
    
    if (msg->type != CMSG_BLKIF_BE) 
    {
        printf("Unexpected control message (%d)\n", msg->type);
        return 0;
    }
    
    switch(msg->subtype)
    {
    case CMSG_BLKIF_BE_CREATE:
        if ( msg->length != sizeof(blkif_be_create_t) )
            goto parse_error;
        blkif_create((blkif_be_create_t *)msg->msg);
        break;   
        
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_be_destroy_t) )
            goto parse_error;
        blkif_destroy((blkif_be_destroy_t *)msg->msg);
        break;  
        
    case CMSG_BLKIF_BE_VBD_CREATE:
        if ( msg->length != sizeof(blkif_be_vbd_create_t) )
            goto parse_error;
        vbd_create((blkif_be_vbd_create_t *)msg->msg);
        break;
        
    case CMSG_BLKIF_BE_VBD_DESTROY:
        if ( msg->length != sizeof(blkif_be_vbd_destroy_t) )
            goto parse_error;
        vbd_destroy((blkif_be_vbd_destroy_t *)msg->msg);
        break;

    case CMSG_BLKIF_BE_CONNECT:
    case CMSG_BLKIF_BE_DISCONNECT:
        /* we don't manage the device channel, the tap does. */
        break;

    default:
        goto parse_error;
    }
    return 0;
parse_error:
    printf("Bad control message!\n");
    return 0;
    
}    

int parallax_probe(blkif_request_t *req, blkif_t *blkif)
{
    blkif_response_t *rsp;
    vdisk_t *img_info;
    vdi_t *vdi;
    int i, nr_vdis = 0; 

    DPRINTF("parallax_probe: req=%p, blkif=%p\n", req, blkif); 

    /* We expect one buffer only. */
    if ( req->nr_segments != 1 )
      goto err;

    /* Make sure the buffer is page-sized. */
    if ( (req->seg[0].first_sect != 0) || (req->seg[0].last_sect != 7) )
      goto err;

    /* fill the list of devices */
    for (i=0; i<VDI_HASHSZ; i++) {
        vdi = blkif->vdi_hash[i];
        while (vdi) {
            img_info = (vdisk_t *)MMAP_VADDR(ID_TO_IDX(req->id), 0);
            img_info[nr_vdis].device   = vdi->vdevice;
            img_info[nr_vdis].info     = 0;
            /* The -1 here accounts for the LSB in the radix tree */
            img_info[nr_vdis].capacity = 
                    ((1LL << (VDI_HEIGHT-1)) * SECTS_PER_NODE);
            nr_vdis++;
            vdi = vdi->next;
        }
    }

    
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_PROBE;
    rsp->status = nr_vdis; /* number of disks */

    DPRINTF("parallax_probe: send positive response (nr_vdis=%d)\n", nr_vdis);
    return  BLKTAP_RESPOND;
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_PROBE;
    rsp->status = BLKIF_RSP_ERROR;
    
    DPRINTF("parallax_probe: send error response\n"); 
    return BLKTAP_RESPOND;  
}

typedef struct {
    blkif_request_t *req;
    int              count;
    int              error;
    pthread_mutex_t  mutex;
} pending_t;

#define MAX_REQUESTS 64
pending_t pending_list[MAX_REQUESTS];

struct cb_param {
    pending_t *pent;
    int       segment;
    uint64_t       sector; 
    uint64_t       vblock; /* for debug printing -- can be removed. */
};

static void read_cb(struct io_ret r, void *in_param)
{
    struct cb_param *param = (struct cb_param *)in_param;
    pending_t *p = param->pent;
    int segment = param->segment;
    blkif_request_t *req = p->req;
    unsigned long size, offset, start;
    char *dpage, *spage;
	
    spage  = IO_BLOCK(r);
    if (spage == NULL) { p->error++; goto finish; }
    dpage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), segment);
    
    /* Calculate read size and offset within the read block. */

    offset = (param->sector << SECTOR_SHIFT) % BLOCK_SIZE;
    size = (req->seg[segment].last_sect - req->seg[segment].first_sect + 1) <<
        SECTOR_SHIFT;
    start = req->seg[segment].first_sect << SECTOR_SHIFT;

    DPRINTF("ParallaxRead: sect: %lld (%ld,%ld),  "
            "vblock %llx, "
            "size %lx\n", 
            param->sector,
            p->req->seg[segment].first_sect,
            p->req->seg[segment].last_sect,
            param->vblock, size); 

    memcpy(dpage + start, spage + offset, size);
    freeblock(spage);
    
    /* Done the read.  Now update the pending record. */
 finish:
    pthread_mutex_lock(&p->mutex);
    p->count--;
    
    if (p->count == 0) {
    	blkif_response_t *rsp;
    	
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_READ;
    	if (p->error == 0) {
            rsp->status = BLKIF_RSP_OKAY;
    	} else {
            rsp->status = BLKIF_RSP_ERROR;
    	}
        blktap_inject_response(rsp);       
    }
    
    pthread_mutex_unlock(&p->mutex);
	
    free(param); /* TODO: replace with cached alloc/dealloc */
}	

int parallax_read(blkif_request_t *req, blkif_t *blkif)
{
    blkif_response_t *rsp;
    uint64_t vblock, gblock;
    vdi_t *vdi;
    uint64_t sector;
    int i;
    char *dpage, *spage;
    pending_t *pent;

    vdi = blkif_get_vdi(blkif, req->device);
    
    if ( vdi == NULL )
        goto err;
        
    pent = &pending_list[ID_TO_IDX(req->id)];
    pent->count = req->nr_segments;
    pent->req = req;
    pthread_mutex_init(&pent->mutex, NULL);
    
    for (i = 0; i < req->nr_segments; i++) {
        pthread_t tid;
        int ret;
        struct cb_param *p;
        
        /* Round the requested segment to a block address. */
        sector  = req->sector_number + (8*i);
        vblock = (sector << SECTOR_SHIFT) >> BLOCK_SHIFT;
        
        /* TODO: Replace this call to malloc with a cached allocation */
        p = (struct cb_param *)malloc(sizeof(struct cb_param));
        p->pent = pent;
        p->sector = sector; 
        p->segment = i;     
        p->vblock = vblock; /* dbg */
        
        /* Get that block from the store. */
        vdi_read(vdi, vblock, read_cb, (void *)p);    
    }
    
    return BLKTAP_STOLEN;

err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_READ;
    rsp->status = BLKIF_RSP_ERROR;
    
    return BLKTAP_RESPOND;  
}

static void write_cb(struct io_ret r, void *in_param)
{
    struct cb_param *param = (struct cb_param *)in_param;
    pending_t *p = param->pent;
    blkif_request_t *req = p->req;
    
    /* catch errors from the block code. */
    if (IO_INT(r) < 0) p->error++;
    
    pthread_mutex_lock(&p->mutex);
    p->count--;
    
    if (p->count == 0) {
    	blkif_response_t *rsp;
    	
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_WRITE;
    	if (p->error == 0) {
            rsp->status = BLKIF_RSP_OKAY;
    	} else {
            rsp->status = BLKIF_RSP_ERROR;
    	}
        blktap_inject_response(rsp);       
    }
    
    pthread_mutex_unlock(&p->mutex);
	
    free(param); /* TODO: replace with cached alloc/dealloc */
}

int parallax_write(blkif_request_t *req, blkif_t *blkif)
{
    blkif_response_t *rsp;
    uint64_t sector;
    int i, writable = 0;
    uint64_t vblock, gblock;
    char *spage;
    unsigned long size, offset, start;
    vdi_t *vdi;
    pending_t *pent;

    vdi = blkif_get_vdi(blkif, req->device);
    
    if ( vdi == NULL )
        goto err;
        
    pent = &pending_list[ID_TO_IDX(req->id)];
    pent->count = req->nr_segments;
    pent->req = req;
    pthread_mutex_init(&pent->mutex, NULL);
    
    for (i = 0; i < req->nr_segments; i++) {
        struct cb_param *p;
        
        spage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
        
        /* Round the requested segment to a block address. */
        
        sector  = req->sector_number + (8*i);
        vblock = (sector << SECTOR_SHIFT) >> BLOCK_SHIFT;
        
        /* Calculate read size and offset within the read block. */
        
        offset = (sector << SECTOR_SHIFT) % BLOCK_SIZE;
        size = (req->seg[i].last_sect - req->seg[i].first_sect + 1) <<
            SECTOR_SHIFT;
        start = req->seg[i].first_sect << SECTOR_SHIFT;

        DPRINTF("ParallaxWrite: sect: %lld (%ld,%ld),  "
                "vblock %llx, gblock %llx, "
                "size %lx\n", 
                sector, 
                req->seg[i].first_sect, req->seg[i].last_sect,
                vblock, gblock, size); 
      
        /* XXX: For now we just freak out if they try to write a   */
        /* non block-sized, block-aligned page.                    */
        
        if ((offset != 0) || (size != BLOCK_SIZE) || (start != 0)) {
            printf("]\n] STRANGE WRITE!\n]\n");
            goto err;
        }
        
        /* TODO: Replace this call to malloc with a cached allocation */
        p = (struct cb_param *)malloc(sizeof(struct cb_param));
        p->pent = pent;
        p->sector = sector; 
        p->segment = i;     
        p->vblock = vblock; /* dbg */
        
        /* Issue the write to the store. */
        vdi_write(vdi, vblock, spage, write_cb, (void *)p);
    }

    return BLKTAP_STOLEN;

err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_WRITE;
    rsp->status = BLKIF_RSP_ERROR;
    
    return BLKTAP_RESPOND;  
}

int parallax_request(blkif_request_t *req)
{
    blkif_response_t *rsp;
    domid_t  dom   = ID_TO_DOM(req->id);
    blkif_t *blkif = blkif_find_by_handle(dom, 0);
    
    if (blkif == NULL)
        goto err;
    
    if ( req->operation == BLKIF_OP_PROBE ) {
        
        return parallax_probe(req, blkif);
        
    } else if ( req->operation == BLKIF_OP_READ ) {
        
        return parallax_read(req, blkif);
        
    } else if ( req->operation == BLKIF_OP_WRITE ) {
        
        return parallax_write(req, blkif);
        
    } else {
        printf("Unknown request message type!\n");
        /* Unknown operation */
        goto err;
    }
    
err:
    rsp = (blkif_response_t *)req;
    rsp->operation = req->operation;
    rsp->id = req->id;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}

void __init_parallax(void) 
{
    memset(blkif_hash, 0, sizeof(blkif_hash));
}



int main(int argc, char *argv[])
{
    DPRINTF("parallax: starting.\n"); 
    __init_blockstore();
    DPRINTF("parallax: initialized blockstore...\n"); 
    init_block_async();
    DPRINTF("parallax: initialized async blocks...\n"); 
    __init_vdi();
    DPRINTF("parallax: initialized vdi registry etc...\n"); 
    __init_parallax();
    DPRINTF("parallax: initialized local stuff..\n"); 

    blktap_register_ctrl_hook("parallax_control", parallax_control);
    blktap_register_request_hook("parallax_request", parallax_request);
    DPRINTF("parallax: added ctrl + request hooks, starting listen...\n"); 
    blktap_listen();
    
    return 0;
}
