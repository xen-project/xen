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
#include "parallax-threaded.h"

#define PARALLAX_DEV     61440


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
/*
    spin_lock_init(&blkif->vbd_lock);
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 0);
*/
    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif != NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            DPRINTF("Could not create blkif: already exists\n");
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
    /* destroy_all_vbds(blkif); */
    free(blkif);
    destroy->status = BLKIF_BE_STATUS_OKAY;
}

void vbd_grow(blkif_be_vbd_grow_t *grow) 
{
    blkif_t            *blkif;
    vdi_t              *vdi, **vdip;
    blkif_vdev_t        vdevice = grow->vdevice;

    DPRINTF("parallax (vbd_grow): grow=%p\n", grow); 
    
    blkif = blkif_find_by_handle(grow->domid, grow->blkif_handle);
    if ( blkif == NULL )
    {
        DPRINTF("vbd_grow attempted for non-existent blkif (%u,%u)\n", 
                grow->domid, grow->blkif_handle); 
        grow->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    /* VDI identifier is in grow->extent.sector_start */
    DPRINTF("vbd_grow: grow->extent.sector_start (id) is %llx\n", 
            grow->extent.sector_start);

    vdi = vdi_get(grow->extent.sector_start);
    if (vdi == NULL)
    {
        printf("parallax (vbd_grow): VDI %llx not found.\n",
               grow->extent.sector_start);
        grow->status = BLKIF_BE_STATUS_VBD_NOT_FOUND;
        return;
    }
    
    vdi->next = NULL;
    vdi->vdevice = vdevice;
    vdip = &blkif->vdi_hash[VDI_HASH(vdevice)];
    while (*vdip != NULL)
        vdip = &(*vdip)->next;
    *vdip = vdi;
    
    DPRINTF("vbd_grow: happy return!\n"); 
    grow->status = BLKIF_BE_STATUS_OKAY;
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
        
    case CMSG_BLKIF_BE_VBD_GROW:
        if ( msg->length != sizeof(blkif_be_vbd_grow_t) )
            goto parse_error;
        vbd_grow((blkif_be_vbd_grow_t *)msg->msg);
        break;
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
    if ( (blkif_first_sect(req->frame_and_sects[0]) != 0) ||
       (blkif_last_sect (req->frame_and_sects[0]) != 7) )
      goto err;

    /* fill the list of devices */
    for (i=0; i<VDI_HASHSZ; i++) {
        vdi = blkif->vdi_hash[i];
        while (vdi) {
            img_info = (vdisk_t *)MMAP_VADDR(ID_TO_IDX(req->id), 0);
            img_info[nr_vdis].device   = vdi->vdevice;
            img_info[nr_vdis].info     = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;
            /* The -2 here accounts for the LSB in the radix tree */
            img_info[nr_vdis].capacity = 
                    ((1LL << (VDI_HEIGHT-2)) >> SECTOR_SHIFT);
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
    pthread_mutex_t  mutex;
} pending_t;

#define MAX_REQUESTS 64
pending_t pending_list[MAX_REQUESTS];

typedef struct  {
    vdi_t           *vdi;
    blkif_request_t *req;
    int              segment;
    pending_t       *pent;
} readseg_params_t;

#define DISPATCH_SIZE 1024UL
#define DISPATCH_MASK (DISPATCH_SIZE-1)
readseg_params_t dispatch_list[DISPATCH_SIZE];
unsigned long dprod = 0, dcons = 0;
pthread_mutex_t dispatch_mutex;
pthread_cond_t  dispatch_cond;

void *read_segment(void *param)
{
    readseg_params_t *p;
    u64 vblock, gblock, sector;
    char *dpage, *spage;
    unsigned long size, start, offset;
    blkif_response_t *rsp;
    int tid;
    
unsigned long dc, dp;
  
#ifdef NOTHREADS
#else
    /* Set this thread's tid. */
    tid = *(int *)param;
    free(param);

    pthread_setspecific(tid_key, (void *)tid);

    printf("My tid is %d.\n", (int)pthread_getspecific(tid_key));
start:
    pthread_mutex_lock(&dispatch_mutex);
    while (dprod == dcons)
        pthread_cond_wait(&dispatch_cond, &dispatch_mutex);
    
    if (dprod == dcons) {
        /* unnecessary wakeup. */
        pthread_mutex_unlock(&dispatch_mutex);
        goto start;
    }
#endif
dc = dcons;
dp = dprod;

    p = &dispatch_list[dcons & DISPATCH_MASK];
    dcons++;
#ifdef NOTHREADS
#else
    pthread_mutex_unlock(&dispatch_mutex);
#endif    
    dpage  = (char *)MMAP_VADDR(ID_TO_IDX(p->req->id), p->segment);

    /* Round the requested segment to a block address. */

    sector  = p->req->sector_number + (8*p->segment);
    vblock = (sector << SECTOR_SHIFT) >> BLOCK_SHIFT;

    /* Get that block from the store. */

    gblock = vdi_lookup_block(p->vdi, vblock, NULL);

    /* Calculate read size and offset within the read block. */

    offset = (sector << SECTOR_SHIFT) % BLOCK_SIZE;
    size = ( blkif_last_sect (p->req->frame_and_sects[p->segment]) -
             blkif_first_sect(p->req->frame_and_sects[p->segment]) + 1
           ) << SECTOR_SHIFT;
    start = blkif_first_sect(p->req->frame_and_sects[p->segment]) 
            << SECTOR_SHIFT;

    /* If the block does not exist in the store, return zeros. */
    /* Otherwise, copy that region to the guest page.          */

//    printf("      : (%p, %d, %d) (%d) [c:%lu,p:%lu]\n", 
//            p->req, ID_TO_IDX(p->req->id), p->segment,
//            p->pent->count, dc, dp);
    
    DPRINTF("ParallaxRead: sect: %lld (%ld,%ld),  "
            "vblock %llx, gblock %llx, "
            "size %lx\n", 
            sector, blkif_first_sect(p->req->frame_and_sects[p->segment]),
            blkif_last_sect (p->req->frame_and_sects[p->segment]),
            vblock, gblock, size); 

    if ( gblock == 0 ) {

        memset(dpage + start, '\0', size);

    } else {

        spage = readblock(gblock);

        if (spage == NULL) {
            printf("Error reading gblock from store: %Ld\n", gblock);
            goto err;
        }

        memcpy(dpage + start, spage + offset, size);

        freeblock(spage);
    }
    
    
    /* Done the read.  Now update the pending record. */
    
    pthread_mutex_lock(&p->pent->mutex);
    p->pent->count--;
    
    if (p->pent->count == 0) {
        
//    printf("FINISH: (%d, %d)\n", ID_TO_IDX(p->req->id), p->segment);
        rsp = (blkif_response_t *)p->req;
        rsp->id = p->req->id;
        rsp->operation = BLKIF_OP_READ;
        rsp->status = BLKIF_RSP_OKAY;

        blktap_inject_response(rsp);       
    }
    
    pthread_mutex_unlock(&p->pent->mutex);
    
#ifdef NOTHREADS
    return NULL;
#else
    goto start;
#endif
                
err:
    printf("I am screwed!\n");
#ifdef NOTHREADS
    return NULL;
#else
    goto start;
#endif
}


int parallax_read(blkif_request_t *req, blkif_t *blkif)
{
    blkif_response_t *rsp;
    unsigned long size, offset, start;
    u64 sector;
    u64 vblock, gblock;
    vdi_t *vdi;
    int i;
    char *dpage, *spage;
    pending_t *pent;
    readseg_params_t *params;

    vdi = blkif_get_vdi(blkif, req->device);
    
    if ( vdi == NULL )
        goto err;

//    printf("START : (%p, %d, %d)\n", req, ID_TO_IDX(req->id), req->nr_segments);
    
    pent = &pending_list[ID_TO_IDX(req->id)];
    pent->count = req->nr_segments;
    pent->req = req;
    pthread_mutex_init(&pent->mutex, NULL);
       
    
    for (i = 0; i < req->nr_segments; i++) {
        pthread_t tid;
        int ret;

        params = &dispatch_list[dprod & DISPATCH_MASK];
        params->pent = pent;
        params->vdi  = vdi;
        params->req  = req;         
        params->segment = i;
        wmb();
        dprod++;
        
        pthread_mutex_lock(&dispatch_mutex);
        pthread_cond_signal(&dispatch_cond);
        pthread_mutex_unlock(&dispatch_mutex);
#ifdef NOTHREADS        
        read_segment(NULL);
#endif        
        
    }
    
    
    

    return BLKTAP_STOLEN;

err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_READ;
    rsp->status = BLKIF_RSP_ERROR;
    
    return BLKTAP_RESPOND;  
}

int parallax_write(blkif_request_t *req, blkif_t *blkif)
{
    blkif_response_t *rsp;
    u64 sector;
    int i, writable = 0;
    u64 vblock, gblock;
    char *spage;
    unsigned long size, offset, start;
    vdi_t *vdi;

    vdi = blkif_get_vdi(blkif, req->device);
    
    if ( vdi == NULL )
        goto err;
    
    for (i = 0; i < req->nr_segments; i++) {
            
        spage  = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
        
        /* Round the requested segment to a block address. */
        
        sector  = req->sector_number + (8*i);
        vblock = (sector << SECTOR_SHIFT) >> BLOCK_SHIFT;
        
        /* Get that block from the store. */
        
        gblock   = vdi_lookup_block(vdi, vblock, &writable);
        
        /* Calculate read size and offset within the read block. */
        
        offset = (sector << SECTOR_SHIFT) % BLOCK_SIZE;
        size = ( blkif_last_sect (req->frame_and_sects[i]) -
                 blkif_first_sect(req->frame_and_sects[i]) + 1
               ) << SECTOR_SHIFT;
        start = blkif_first_sect(req->frame_and_sects[i]) << SECTOR_SHIFT;

        DPRINTF("ParallaxWrite: sect: %lld (%ld,%ld),  "
                "vblock %llx, gblock %llx, "
                "size %lx\n", 
                sector, blkif_first_sect(req->frame_and_sects[i]),
                blkif_last_sect (req->frame_and_sects[i]),
                vblock, gblock, size); 
        
        /* XXX: For now we just freak out if they try to write a   */
        /* non block-sized, block-aligned page.                    */
        
        if ((offset != 0) || (size != BLOCK_SIZE) || (start != 0)) {
            printf("]\n] STRANGE WRITE!\n]\n");
            goto err;
        }

        if (( gblock == 0 ) || ( writable == 0 )) {
         
            gblock = allocblock(spage);
            vdi_update_block(vdi, vblock, gblock);
            
        } else {
            
            /* write-in-place, no need to change mappings. */
            writeblock(gblock, spage);
            
        }

    }

    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = BLKIF_OP_WRITE;
    rsp->status = BLKIF_RSP_OKAY;

    return BLKTAP_RESPOND;
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

    //DPRINTF("parallax_request: req=%p, dom=%d, blkif=%p\n", req, dom, blkif); 
    
    if (blkif == NULL)
        goto err;
    
    if ( req->operation == BLKIF_OP_PROBE ) {
        
        return parallax_probe(req, blkif);
        
    } else if ( req->operation == BLKIF_OP_READ ) {
        
        return parallax_read(req, blkif);
        
    } else if ( req->operation == BLKIF_OP_WRITE ) {
        
        return parallax_write(req, blkif);
        
    } else {
        /* Unknown operation */
        goto err;
    }
    
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = req->operation;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}

void __init_parallax(void) 
{
    memset(blkif_hash, 0, sizeof(blkif_hash));
}



int main(int argc, char *argv[])
{
    pthread_t read_pool[READ_POOL_SIZE];
    int i, tid=0;
    
    DPRINTF("parallax: starting.\n"); 
    __init_blockstore();
    DPRINTF("parallax: initialized blockstore...\n"); 
    __init_vdi();
    DPRINTF("parallax: initialized vdi registry etc...\n"); 
    __init_parallax();
    DPRINTF("parallax: initialized local stuff..\n"); 

    
    pthread_mutex_init(&dispatch_mutex, NULL);
    pthread_cond_init(&dispatch_cond, NULL);
    
    pthread_key_create(&tid_key, NULL);
    tid = 0;
    
#ifdef NOTHREADS
#else
    for (i=0; i < READ_POOL_SIZE; i++) {
        int ret, *t;
        t = (int *)malloc(sizeof(int));
        *t = tid++;
        ret = pthread_create(&read_pool[i], NULL, read_segment, t);
        if (ret != 0) printf("Error starting thread %d\n", i);
    }
#endif
    
    pthread_setspecific(tid_key, (void *)tid);
    
    printf("*My tid is %d.\n", (int)pthread_getspecific(tid_key));
    
    blktap_register_ctrl_hook("parallax_control", parallax_control);
    blktap_register_request_hook("parallax_request", parallax_request);
    DPRINTF("parallax: added ctrl + request hooks, starting listen...\n"); 
    blktap_listen();
    
    return 0;
}
