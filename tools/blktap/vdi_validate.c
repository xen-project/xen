/**************************************************************************
 * 
 * vdi_validate.c
 *
 * Intended to sanity-check vm_fill and the underlying vdi code.
 *
 * Block-by-block compare of a vdi with a file/device on the disk.
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "blockstore.h"
#include "radix.h"
#include "vdi.h"

int main(int argc, char *argv[])
{
    vdi_t       *vdi;
    u64          id;
    int          fd;
    struct stat  st;
    u64          tot_size;
    char         spage[BLOCK_SIZE], *dpage;
    char        *vpage;
    u64          vblock = 0, count=0;
    
    __init_blockstore();
    __init_vdi();
    
    if ( argc < 3 ) {
        printf("usage: %s <VDI id> <filename>\n", argv[0]);
        exit(-1);
    }
        
    id = (u64) atoll(argv[1]);
    
    vdi = vdi_get( id );
    
    if ( vdi == NULL ) {
        printf("Failed to retreive VDI %Ld!\n", id);
        exit(-1);
    }
    
    fd = open(argv[2], O_RDONLY | O_LARGEFILE);
    
    if (fd < 0) {
        printf("Couldn't open %s!\n", argv[2]);
        exit(-1);
    }
    
    if ( fstat(fd, &st) != 0 ) {
        printf("Couldn't stat %s!\n", argv[2]);
        exit(-1);
    }
    
    tot_size = (u64) st.st_size;
    printf("Testing VDI %Ld (%Ld bytes).\n", id, tot_size);
    
    printf("           ");
    while ( ( count = read(fd, spage, BLOCK_SIZE) ) > 0 ) {
        u64 gblock = 0;
        
        gblock = vdi_lookup_block(vdi, vblock, NULL);
        
        if (gblock == 0) {
            printf("\n\nfound an unmapped VDI block (%Ld)\n", vblock);
            exit(0);
        }
        
        dpage = readblock(gblock);
        
        if (memcmp(spage, dpage, BLOCK_SIZE) != 0) {
            printf("\n\nblocks don't match! (%Ld)\n", vblock);
            exit(0);
        }
        
        freeblock(dpage);
        
        vblock++;
        printf("\b\b\b\b\b\b\b\b\b\b\b%011Ld", vblock);
        fflush(stdout);
    }
    printf("\n");
    
    printf("VDI %Ld looks good!\n", id);
    
    freeblock(vdi);
    
    return (0);
}
