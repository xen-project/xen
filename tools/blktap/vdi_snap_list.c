/**************************************************************************
 * 
 * vdi_snap_list.c
 *
 * Print a list of snapshots for the specified vdi.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"

int main(int argc, char *argv[])
{
    vdi_t        *vdi;
    u64           id;
    int           i, max_snaps = -1;
    snap_block_t *blk;
    snap_id_t     sid;
    char         *t;
    
    __init_blockstore();
    __init_vdi();
    
    if ( argc == 1 ) {
        printf("usage: %s <VDI id> [max snaps]\n", argv[0]);
        exit(-1);
    }
    
    id = (u64) atoll(argv[1]);
    
    if ( argc > 2 ) {
        max_snaps = atoi(argv[2]);
    }
    
    vdi = vdi_get(id);
    
    if ( vdi == NULL ) {
        printf("couldn't find the requested VDI.\n");
        freeblock(vdi);
        exit(-1);
    }
    
    sid = vdi->snap;
    sid.index--;
    
    //printf("%6s%4s%21s %12s\n", "Block", "idx", "timestamp", "radix root");
    printf("%6s%4s%37s %12s\n", "Block", "idx", "timestamp", "radix root");
     
    while (sid.block != 0) {
        blk = snap_get_block(sid.block);
        for (i = sid.index; i >= 0; i--) {
            if ( max_snaps == 0  ) {
                freeblock(blk);
                goto done;
            }
            t = ctime(&blk->snaps[i].timestamp.tv_sec);
            t[strlen(t)-1] = '\0';
            //printf("%6Ld%4u%14lu.%06lu %12Ld\n",
            printf("%6Ld%4u%30s %06lu %12Ld\n",
                    sid.block, i, 
                    //blk->snaps[i].timestamp.tv_sec,
                    t,
                    blk->snaps[i].timestamp.tv_usec,
                    blk->snaps[i].radix_root);
            if ( max_snaps != -1 ) 
                max_snaps--;
        }
        sid = blk->hdr.parent_block;
        freeblock(blk);
    }
done:            
    return 0;
}
