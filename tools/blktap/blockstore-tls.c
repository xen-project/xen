/**************************************************************************
 * 
 * blockstore.c
 *
 * Simple block store interface
 *
 */
 
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "blockstore.h"
#include "parallax-threaded.h"

/*static int block_fp = -1;*/
 
static int fd_list[READ_POOL_SIZE+1];
 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */

void *readblock(u64 id) 
{
    void *block;
    int tid = (int)pthread_getspecific(tid_key);
    
    if (lseek64(fd_list[tid], ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        printf ("%Ld\n", (id - 1) * BLOCK_SIZE);
        perror("readblock lseek");
        goto err;
    }
    if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        goto err;
    }
    if (read(fd_list[tid], block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("readblock read");
        free(block);
        goto err;
    }
    return block;
    
err:
    return NULL;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(u64 id, void *block) 
{
    int tid = (int)pthread_getspecific(tid_key);
    
    if (lseek64(fd_list[tid], ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        perror("writeblock lseek");
        goto err;
    }
    if (write(fd_list[tid], block, BLOCK_SIZE) < 0) {
        perror("writeblock write");
        goto err;
    }
    return 0;

err:
    return -1;
}

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */

u64 allocblock(void *block) 
{
    u64 lb;
    off64_t pos;
    int tid = (int)pthread_getspecific(tid_key);

    pos = lseek64(fd_list[tid], 0, SEEK_END);
    if (pos == (off64_t)-1) {
        perror("allocblock lseek");
        goto err;
    }
    if (pos % BLOCK_SIZE != 0) {
        fprintf(stderr, "file size not multiple of %d\n", BLOCK_SIZE);
        goto err;
    }
    if (write(fd_list[tid], block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("allocblock write");
        goto err;
    }
    lb = pos / BLOCK_SIZE + 1;
    
    return lb;
    
err:
    return 0;
    
}


/**
 * newblock: get a new in-memory block set to zeros
 *
 *   @return: pointer to new block, NULL on error
 */
void *newblock() 
{
    void *block = malloc(BLOCK_SIZE);
    if (block == NULL) {
        perror("newblock");
        return NULL;
    }
    memset(block, 0, BLOCK_SIZE);
    return block;
}


/**
 * freeblock: unallocate an in-memory block
 *   @id: block id (zero if this is only in-memory)
 *   @block: block to be freed
 */
void freeblock(void *block) 
{
    if (block != NULL)
        free(block);
}


int __init_blockstore(void)
{
    int i;
    
    for (i=0; i<(READ_POOL_SIZE+1); i++) {
        
        fd_list[i] = open("blockstore.dat", 
                O_RDWR | O_CREAT | O_LARGEFILE, 0644);

        if (fd_list[i] < 0) {
            perror("open");
            return -1;
        }
    }
    return 0;
}
