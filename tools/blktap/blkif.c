/*
 * blkif.c
 * 
 * The blkif interface for blktap.  A blkif describes an in-use virtual disk.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <err.h>

#include "blktaplib.h"

#if 1
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) (((int)(_d)^(int)(_h))&(BLKIF_HASHSZ-1))

static blkif_t      *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
    blkif_t *blkif = blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif != NULL) && 
            ((blkif->domid != domid) || (blkif->handle != handle)) )
        blkif = blkif->hash_next;
    return blkif;
}

blkif_t *alloc_blkif(domid_t domid)
{
    blkif_t *blkif;

    blkif = (blkif_t *)malloc(sizeof(blkif_t));
    if (!blkif)
        return NULL;

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid = domid;

    return blkif;
}

static int (*new_blkif_hook)(blkif_t *blkif) = NULL;
void register_new_blkif_hook(int (*fn)(blkif_t *blkif))
{
    new_blkif_hook = fn;
}

int blkif_init(blkif_t *blkif, long int handle, long int pdev, 
               long int readonly)
{
    domid_t domid;
    blkif_t **pblkif;
    
    if (blkif == NULL)
        return -EINVAL;

    domid = blkif->domid;
    blkif->handle   = handle;
    blkif->pdev     = pdev;
    blkif->readonly = readonly;

    /*
     * Call out to the new_blkif_hook. The tap application should define this,
     * and it should return having set blkif->ops
     * 
     */
    if (new_blkif_hook == NULL)
    {
        warn("Probe detected a new blkif, but no new_blkif_hook!");
        return -1;
    }
    new_blkif_hook(blkif);

    /* Now wire it in. */
    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif != NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            DPRINTF("Could not create blkif: already exists\n");
            return -1;
        }
        pblkif = &(*pblkif)->hash_next;
    }
    blkif->hash_next = NULL;
    *pblkif = blkif;

    return 0;
}

void free_blkif(blkif_t *blkif)
{
    blkif_t **pblkif, *curs;
    
    pblkif = &blkif_hash[BLKIF_HASH(blkif->domid, blkif->handle)];
    while ( (curs = *pblkif) != NULL )
    {
        if ( blkif == curs )
        {
            *pblkif = curs->hash_next;
        }
        pblkif = &curs->hash_next;
    }
    free(blkif);
}

void blkif_register_request_hook(blkif_t *blkif, char *name, 
                                 int (*rh)(blkif_t *, blkif_request_t *, int)) 
{
    request_hook_t *rh_ent, **c;
    
    rh_ent = (request_hook_t *)malloc(sizeof(request_hook_t));
    if (!rh_ent) 
    {
        warn("couldn't allocate a new hook");
        return;
    }
    
    rh_ent->func  = rh;
    rh_ent->next = NULL;
    if (asprintf(&rh_ent->name, "%s", name) == -1)
    {
        free(rh_ent);
        warn("couldn't allocate a new hook name");
        return;
    }
    
    c = &blkif->request_hook_chain;
    while (*c != NULL) {
        c = &(*c)->next;
    }
    *c = rh_ent;
}

void blkif_register_response_hook(blkif_t *blkif, char *name, 
                                  int (*rh)(blkif_t *, blkif_response_t *, int)) 
{
    response_hook_t *rh_ent, **c;
    
    rh_ent = (response_hook_t *)malloc(sizeof(response_hook_t));
    if (!rh_ent) 
    { 
        warn("couldn't allocate a new hook");
        return;
    }
    
    rh_ent->func  = rh;
    rh_ent->next = NULL;
    if (asprintf(&rh_ent->name, "%s", name) == -1)
    {
        free(rh_ent);
        warn("couldn't allocate a new hook name");
        return;
    }
    
    c = &blkif->response_hook_chain;
    while (*c != NULL) {
        c = &(*c)->next;
    }
    *c = rh_ent;
}

void blkif_print_hooks(blkif_t *blkif)
{
    request_hook_t  *req_hook;
    response_hook_t *rsp_hook;
    
    DPRINTF("Request Hooks:\n");
    req_hook = blkif->request_hook_chain;
    while (req_hook != NULL)
    {
        DPRINTF("  [0x%p] %s\n", req_hook->func, req_hook->name);
        req_hook = req_hook->next;
    }
    
    DPRINTF("Response Hooks:\n");
    rsp_hook = blkif->response_hook_chain;
    while (rsp_hook != NULL)
    {
        DPRINTF("  [0x%p] %s\n", rsp_hook->func, rsp_hook->name);
        rsp_hook = rsp_hook->next;
    }
}


long int vbd_size(blkif_t *blkif)
{
    return 1000000000;
}

long int vbd_secsize(blkif_t *blkif)
{
    return 512;
}

unsigned vbd_info(blkif_t *blkif)
{
    return 0;
}


void __init_blkif(void)
{    
    memset(blkif_hash, 0, sizeof(blkif_hash));
}
