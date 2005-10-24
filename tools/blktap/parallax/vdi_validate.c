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
#include "requests-async.h"

int main(int argc, char *argv[])
{
    vdi_t       *vdi;
    uint64_t          id;
    int          fd;
    struct stat  st;
    uint64_t          tot_size;
    char         spage[BLOCK_SIZE], *dpage;
    char        *vpage;
    uint64_t          vblock = 0, count=0;
    
    __init_blockstore();
    init_block_async();
    __init_vdi();
    
    if ( argc < 3 ) {
        printf("usage: %s <VDI id> <filename>\n", argv[0]);
        exit(-1);
    }
        
    id = (uint64_t) atoll(argv[1]);
    
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
    
    tot_size = (uint64_t) st.st_size;
    printf("Testing VDI %Ld (%Ld bytes).\n", id, tot_size);
    
    printf("           ");
    while ( ( count = read(fd, spage, BLOCK_SIZE) ) > 0 ) {

        dpage = vdi_read_s(vdi, vblock);

        if (dpage == NULL) {
            printf("\n\nfound an unmapped VDI block (%Ld)\n", vblock);
            exit(0);
        }

        if (memcmp(spage, dpage, BLOCK_SIZE) != 0) {
            printf("\n\nblocks don't match! (%Ld)\n", vblock);
            exit(0);
        }
        
        freeblock(dpage);
        
        vblock++;
        if ((vblock % 1024) == 0) {
            printf("\b\b\b\b\b\b\b\b\b\b\b%011Ld", vblock);
            fflush(stdout);
        }
    }
    printf("\n");
    
    printf("VDI %Ld looks good!\n", id);
    
    freeblock(vdi);
    
    return (0);
}
