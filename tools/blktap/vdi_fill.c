/**************************************************************************
 * 
 * vdi_fill.c
 *
 * Hoover a file or device into a vdi.
 * You must first create the vdi with vdi_create.
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
    char         spage[BLOCK_SIZE];
    char        *dpage;
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
    printf("Filling VDI %Ld with %Ld bytes.\n", id, tot_size);
    
    printf("%011Ld blocks total\n", tot_size / BLOCK_SIZE);    
    printf("           ");
    while ( ( count = read(fd, spage, BLOCK_SIZE) ) > 0 ) {
        u64 gblock = 0;
        
        gblock = allocblock(spage);
        vdi_update_block(vdi, vblock, gblock);
        
        vblock++;
        if ((vblock % 512) == 0)
        printf("\b\b\b\b\b\b\b\b\b\b\b%011Ld", vblock);
        fflush(stdout);
    }
    printf("\n");
    
    freeblock(vdi);
    
    return (0);
}
