/* blkcowlib.c
 *
 * copy on write a block device.  in a really inefficient way.
 * 
 * (c) 2004 Andrew Warfield.
 *
 * This uses whatever backend the tap is attached to as the read-only
 * underlay -- for the moment.
 *
 * Xend has been modified to use an amorfs:[fsid] disk tag.
 * This will show up as device type (maj:240,min:0) = 61440.
 *
 * The fsid is placed in the sec_start field of the disk extent,
 * the cow plugin uses this to identify a unique overlay.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <db.h>
#include "blktaplib.h"

#define MAX_DOMS        1024
#define MAX_DBNAME_LEN   255
#define AMORFS_DEV     61440
#define MAX_REQUESTS      64 /* must be synced with the blkif drivers. */
                                                                                
#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif
    
/* Berkeley db has different params for open() after 4.1 */
#ifndef DB_VERSION_MAJOR
# define DB_VERSION_MAJOR 1
#endif /* DB_VERSION_MAJOR */
#ifndef DB_VERSION_MINOR
# define DB_VERSION_MINOR 0
#endif /* DB_VERSION_MINOR */

typedef struct {
    DB   *db;
    u64  fsid;
    char dbname[MAX_DBNAME_LEN];
} cow_t;

cow_t           *cows[MAX_DOMS];
blkif_request_t *reread_list[MAX_REQUESTS];

int cow_control(control_msg_t *msg)
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
        if (cows[domid] != NULL) {
            printf("attempt to connect from an existing dom!\n");
            return 0;
        }
        
        cows[domid] = (cow_t *)malloc(sizeof(cow_t));
        if (cows[domid] == NULL) {
            printf("error allocating cow.\n");
            return 0;
        }
        
        cows[domid]->db   = NULL;
        cows[domid]->fsid = 0;
        
        printf("COW connected.\n");
        break;   
        
    case CMSG_BLKIF_BE_DESTROY:
        if ( msg->length != sizeof(blkif_be_destroy_t) )
            goto parse_error;
        printf("[CONTROL_MSG] CMSG_BLKIF_BE_DESTROY(d:%d,h:%d)\n",
                ((blkif_be_destroy_t *)msg->msg)->domid,
                ((blkif_be_destroy_t *)msg->msg)->blkif_handle);
        
        domid = ((blkif_be_destroy_t *)msg->msg)->domid;
        if (cows[domid] != NULL) {
            if (cows[domid]->db != NULL)
                cows[domid]->db->close(cows[domid]->db, 0);
            free(cows[domid]);
            cows[domid] = NULL;
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
        if (cows[domid] == NULL) {
            printf("VBD_GROW on unconnected domain!\n");
            return 0;
        }
        
        if (grow->extent.device != AMORFS_DEV) {
            printf("VBD_GROW on non-amorfs device!\n");
            return 0;
        }
        
        sprintf(&cows[domid]->dbname[0], "%020llu.db",
                grow->extent.sector_start);
        
        cows[domid]->fsid = grow->extent.sector_start;
            
        if ((ret = db_create(&db, NULL, 0)) != 0) {
            fprintf(stderr, "db_create: %s\n", db_strerror(ret));
            return 0;
        }
        
        
#if DB_VERSION_MAJOR < 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR < 1)

        if ((ret = db->open( db, cows[domid]->dbname, NULL, DB_BTREE, 
                DB_CREATE, 0664)) != 0) {
            
#else /* DB_VERSION >= 4.1 */
        
        if ((ret = db->open( db, NULL, cows[domid]->dbname, NULL, DB_BTREE, 
                DB_CREATE, 0664)) != 0) {
            
#endif /* DB_VERSION < 4.1 */

            db->err(db, ret, "%s", cows[domid]->dbname);
            goto create_failed;
        }
        cows[domid]->db = db;
        printf("Overlay db opened. (%s)\n", cows[domid]->dbname);
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
 
int cow_request(blkif_request_t *req)
{
    DB *db;
    DBT key, data;
    u64 sector;
    char *spage, *dpage;
    int ret, i, idx;
    blkif_response_t *rsp;
    domid_t dom = ID_TO_DOM(req->id);
    
    if ((cows[dom] == NULL) || (cows[dom]->db == NULL)) {
        printf("Data request for unknown domain!!! %d\n", dom);
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = req->operation;
        rsp->status = BLKIF_RSP_ERROR;
        return BLKTAP_RESPOND;
    }
    
    db = cows[dom]->db;
    
    switch (req->operation) 
    {
    case BLKIF_OP_PROBE:
/* debug -- delete */
idx = ID_TO_IDX(req->id);
reread_list[idx] = (blkif_request_t *)malloc(sizeof(*req));
memcpy(reread_list[idx], req, sizeof(*req));
        return  BLKTAP_PASS;
        
    case BLKIF_OP_WRITE:
        for (i = 0; i < req->nr_segments; i++) {
            memset(&key, 0, sizeof(key));
	    memset(&data, 0, sizeof(data));
            
            sector = req->sector_number + (8*i);
            key.data = &sector;
            key.size = sizeof(sector);
            
            spage = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
            data.data = spage;
            data.size = PAGE_SIZE;
            
            
            DPRINTF("cWRITE: sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << 9));
            
            if ((ret = db->put(db, NULL, &key, &data, 0)) == 0)
                DPRINTF("db: %lld: key stored.\n", *((u64 *)key.data));
            else {
                db->err(db, ret, "DB->put");
                goto err;
            }
        }
        
        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_WRITE;
        rsp->status = BLKIF_RSP_OKAY;
        
        return BLKTAP_RESPOND;

    case BLKIF_OP_READ:
        for (i = 0; i < req->nr_segments; i++) {
            memset(&key, 0, sizeof(key));
	    memset(&data, 0, sizeof(data));
            
            sector = req->sector_number + (8*i);
            key.data = &sector;
            key.size = sizeof(sector);
            
            DPRINTF("cREAD: sec_nr: %10llu sec: %10llu (%1lu,%1lu) pos: %15lu\n", 
                    req->sector_number, sector, 
                    blkif_first_sect(req->frame_and_sects[i]),
                    blkif_last_sect (req->frame_and_sects[i]),
                    (long)(sector << 9));

            if ((ret = db->get(db, NULL, &key, &data, 0)) == 0) {
                DPRINTF("db: %llu: key retrieved (req).\n",
                    *((u64 *)key.data));
                
                dpage = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
                spage = data.data;
                memcpy(dpage, spage, PAGE_SIZE);

            } else if (ret == DB_NOTFOUND) {
                idx = ID_TO_IDX(req->id);
                if (idx > MAX_REQUESTS) {
                    printf("Bad index!\n");
                    goto err;
                }
                if (reread_list[idx] != NULL) {
                    printf("Dupe index!\n");
                    goto err;
                }
                reread_list[idx] = (blkif_request_t *)malloc(sizeof(*req));
                memcpy(reread_list[idx], req, sizeof(*req));
                return BLKTAP_PASS;
            } else {
                db->err(db, ret, "DB->get");
                goto err;
            }
        }


        rsp = (blkif_response_t *)req;
        rsp->id = req->id;
        rsp->operation = BLKIF_OP_READ;
        rsp->status = BLKIF_RSP_OKAY;
        return BLKTAP_RESPOND;
    }
    
    printf("Unknow block operation!\n");
    return BLKTAP_PASS;
err:
    rsp = (blkif_response_t *)req;
    rsp->id = req->id;
    rsp->operation = req->operation;
    rsp->status = BLKIF_RSP_ERROR;
    return BLKTAP_RESPOND;  
}

int cow_response(blkif_response_t *rsp)
{   
    blkif_request_t *req;
    int i, ret;
    DB *db;
    DBT key, data;
    u64 sector;
    char *spage, *dpage;
    int idx = ID_TO_IDX(rsp->id);
    domid_t dom;
    
    /* don't touch erroring responses. */
    if (rsp->status == BLKIF_RSP_ERROR)
        return BLKTAP_PASS;
    
    if ((rsp->operation == BLKIF_OP_READ) && (reread_list[idx] != NULL))
    {
        req = reread_list[idx];
        dom = ID_TO_DOM(req->id);

        if ((cows[dom] == NULL) || (cows[dom]->db == NULL)) {
            printf("Response from unknown domain!!! Very badness! %d\n", dom);
            return BLKTAP_PASS;
        }
    
        db = cows[dom]->db;
        
        for (i = 0; i < req->nr_segments; i++) {
            memset(&key, 0, sizeof(key));
	    memset(&data, 0, sizeof(data));
            
            sector = req->sector_number + (8*i);
            key.data = &sector;
            key.size = sizeof(sector);
            
            if ((ret = db->get(db, NULL, &key, &data, 0)) == 0) {
                printf("db: %llu: key retrieved (rsp).\n",
                    *((u64 *)key.data));
                
                dpage = (char *)MMAP_VADDR(ID_TO_IDX(req->id), i);
                spage = data.data;
                memcpy(dpage, spage, PAGE_SIZE);

            } else if (ret == DB_NOTFOUND) {
                continue; /* We read this from disk. */
            } else {
                db->err(db, ret, "DB->get");
                goto err;
            }
        }
        free(reread_list[idx]);
        reread_list[idx] = NULL;
    }
    
    if (rsp->operation == BLKIF_OP_PROBE) {
        
        vdisk_t *img_info;
        
        req = reread_list[idx];
        img_info = (vdisk_t *)(char *)MMAP_VADDR(ID_TO_IDX(req->id), 0);
        for (i =0; i < rsp->status; i++) 
            printf("PROBE (%d) device: 0x%04x capacity: %llu, info: 0x%04x\n", 
                    i,
                    img_info[0].device,
                    img_info[0].capacity,
                    img_info[0].info);
        free(reread_list[idx]);
        reread_list[idx] = NULL;
    }
    
err:
    return BLKTAP_PASS;
}

void cow_init(void)
{
    int i;
    
    for (i = 0; i < MAX_DOMS; i++)
        cows[i] = NULL;
    
    for (i = 0; i < MAX_REQUESTS; i++)
        reread_list[MAX_REQUESTS] = NULL;
}

