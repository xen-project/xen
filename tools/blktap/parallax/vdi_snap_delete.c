/**************************************************************************
 * 
 * vdi_snap_delete.c
 *
 * Delete a snapshot.
 *
 * This is not finished:  right now it takes a snap n and calls 
 * snap_collapse(n,n+1).
 *
 * TODO: support for non-consecutive, non-same-block snaps
 *       Avoid forking probs.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "blockstore.h"
#include "snaplog.h"
#include "radix.h"
#include "vdi.h"

int main(int argc, char *argv[])
{
    snap_id_t    id, c_id;
    int ret;
    
    __init_blockstore();
    __init_vdi();
    
    if ( argc != 3 ) {
        printf("usage: %s <snap block> <snap idx>\n", argv[0]);
        exit(-1);
    }
    
    id.block   = (u64)          atoll(argv[1]);
    id.index   = (unsigned int) atol (argv[2]);
    
    c_id = id;
    c_id.index++;
    
    ret = snap_collapse(VDI_HEIGHT, &id, &c_id);
    
    printf("Freed %d blocks.\n", ret);
    
    return 0;
}
