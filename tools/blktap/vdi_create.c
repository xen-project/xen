/**************************************************************************
 * 
 * vdi_create.c
 *
 * Create a new vdi.
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
    vdi_t       *vdi;
    char         name[VDI_NAME_SZ] = "";
    snap_id_t    id;
    int          from_snap = 0;
    
    __init_blockstore();
    __init_vdi();
    
    if ( argc == 1 ) {
        printf("usage: %s <VDI Name> [<snap block> <snap idx>]\n", argv[0]);
        exit(-1);
    }
    
    strncpy( name, argv[1], VDI_NAME_SZ);
    name[VDI_NAME_SZ] = '\0';    
    
    if ( argc > 3 ) {
        id.block   = (u64)          atoll(argv[2]);
        id.index   = (unsigned int) atol (argv[3]);
        from_snap  = 1;
    }
    
    vdi = vdi_create( from_snap ? &id : NULL, name);
    
    if ( vdi == NULL ) {
        printf("Failed to create VDI!\n");
        freeblock(vdi);
        exit(-1);
    }
    
    freeblock(vdi);
    
    return (0);
}
