/**************************************************************************
 * 
 * vdi_list.c
 *
 * Print a list of VDIs on the block store.
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
    vdi_registry_t *reg;
    vdi_t *vdi;
    int i;
    
    __init_blockstore();
    __init_vdi();
    
    reg = get_vdi_registry();
    
    if ( reg == NULL ) {
        printf("couldn't get VDI registry.\n");
        exit(-1);
    }
    
    for (i=0; i < reg->nr_vdis; i++) {
        vdi = vdi_get(i);
        
        if ( vdi != NULL ) {
            
            printf("%10Ld %60s\n", vdi->id, vdi->name);
            freeblock(vdi);
            
        }
    }
    
    freeblock(reg);
    
    return 0;
}
