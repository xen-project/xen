/**************************************************************************
 * 
 * snaplog.c
 *
 * Snapshot log on-disk data structure.
 *
 */
 
 /* VDI histories are made from chains of snapshot logs.  These logs record 
  * the (radix) root and timestamp of individual snapshots.
  *
  * creation of a new VDI involves 'forking' a snapshot log, by creating a 
  * new, empty log (in a new VDI) and parenting it off of a record in an 
  * existing snapshot log.
  *
  * snapshot log blocks have at most one writer.
  */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "blockstore.h"
#include "snaplog.h"



snap_block_t *snap_get_block(u64 block)
{
    snap_block_t *blk = (snap_block_t *)readblock(block);
    
    if ( blk == NULL)
        return NULL;
    if ( blk->hdr.magic != SNAP_MAGIC ) {
        freeblock(blk);
        return NULL;
    }
    
    return blk;
}
    
int snap_get_id(snap_id_t *id, snap_rec_t *target)
{
    snap_block_t *blk;
    
    if ( id == NULL )
        return -1;
    
    blk = snap_get_block(id->block);
    
    if ( blk == NULL ) 
        return -1;
    
    if ( id->index > blk->hdr.nr_entries ) {
        freeblock(blk);
        return -1;
    }
    
    *target = blk->snaps[id->index];
    freeblock(blk);
    return 0;
}

int __snap_block_create(snap_id_t *parent_id, snap_id_t *fork_id,
                                  snap_id_t *new_id)
{
    snap_rec_t parent_rec, fork_rec;
    snap_block_t *blk, *pblk;
    /*
    if ( (parent_id != NULL) && (snap_get_id(parent_id, &parent_rec) != 0) )
        return -1;    
    
    if ( (fork_id != NULL) && (snap_get_id(fork_id, &fork_rec) != 0) )
        return -1;   
*/
    blk = (snap_block_t *)newblock();
    blk->hdr.magic  = SNAP_MAGIC;
    blk->hdr.nr_entries  = 0;
    blk->hdr.log_entries = 0;
    blk->hdr.immutable   = 0;
    
    if (   (parent_id  != NULL) 
        && (parent_id->block != fork_id->block) 
        && (parent_id->block != 0)) {
        
        pblk = snap_get_block(parent_id->block);
        blk->hdr.log_entries = pblk->hdr.log_entries;
        freeblock(pblk);
    }
    
    if (parent_id != NULL) {
        blk->hdr.parent_block = *parent_id;
        blk->hdr.fork_block   = *fork_id;
    } else {
        blk->hdr.parent_block = null_snap_id;
        blk->hdr.fork_block   = null_snap_id;
    }
    
    new_id->index = 0;
    new_id->block = allocblock(blk);
    if (new_id->block == 0)
        return -1;
    
    return 0;
}

int snap_block_create(snap_id_t *parent_id, snap_id_t *new_id)
{
    return __snap_block_create(parent_id, parent_id, new_id);
}

int snap_append(snap_id_t *old_id, snap_rec_t *rec, snap_id_t *new_id)
{
    snap_id_t id = *old_id;
    snap_block_t *blk = snap_get_block(id.block);
    
    if ( blk->hdr.immutable != 0 ) {
        printf("Attempt to snap an immutable snap block!\n");
        return -1;
    }
    
    new_id->block = id.block;
    
    if (blk->hdr.nr_entries == SNAPS_PER_BLOCK) {
        int ret;
        
        id.index--; /* make id point to the last full record */
        
        ret = __snap_block_create(&id, &blk->hdr.fork_block, new_id);
        if ( ret != 0 ) {
            freeblock(blk);
            return -1;
        }
        
        blk->hdr.immutable = 1;
        writeblock(id.block, blk);
        freeblock(blk);
        blk = snap_get_block(new_id->block);
        id = *new_id;
    }
    
    blk->snaps[blk->hdr.nr_entries] = *rec;
    blk->hdr.nr_entries++;
    blk->hdr.log_entries++;
    new_id->index = blk->hdr.nr_entries;
    //printf("snap: %u %u\n", blk->hdr.nr_entries, blk->hdr.log_entries);
    writeblock(id.block, blk);
    freeblock(blk);
    return 0;
}

void snap_print_history(snap_id_t *snap_id)
{
    snap_id_t id = *snap_id;
    unsigned int idx = id.index;
    snap_block_t *new_blk, *blk = snap_get_block(id.block);
    
    while ( blk ) {
        printf("[Snap block %Ld]:\n", id.block);
        do {
            printf("   %03u: root: %Ld ts: %ld.%ld\n", idx, 
                    blk->snaps[idx].radix_root,
                    blk->snaps[idx].timestamp.tv_sec,
                    blk->snaps[idx].timestamp.tv_usec);
        } while (idx-- != 0);
        
        id = blk->hdr.parent_block;
        if (id.block != 0) {
            new_blk = snap_get_block(id.block);
        }
        freeblock(blk);
        blk = new_blk;
    }
}
