/**************************************************************************
 * 
 * vdi_snap.c
 *
 * Snapshot a vdi.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"

int main(int argc, char *argv[])
{
    vdi_t  *vdi;
    u64     id;
    
    __init_blockstore();
    __init_vdi();
    
    if ( argc == 1 ) {
        printf("usage: %s <VDI id>\n", argv[0]);
        exit(-1);
    }
    
    id = (u64) atoll(argv[1]);
    
    vdi = vdi_get(id);
    
    if ( vdi == NULL ) {
        printf("couldn't find the requested VDI.\n");
        freeblock(vdi);
        exit(-1);
    }
    
    vdi_snapshot(vdi);
    
    return 0;
}
