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
#include <sys/types.h>
#include <sys/stat.h>
#include "blockstore.h"

static int block_fp = -1;
 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */

void *readblock(u64 id) {
    void *block;
    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        printf ("%Ld\n", (id - 1) * BLOCK_SIZE);
        perror("readblock lseek");
        return NULL;
    }
    if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        return NULL;
    }
    if (read(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("readblock read");
        free(block);
        return NULL;
    }
    return block;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(u64 id, void *block) {
    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        perror("writeblock lseek");
        return -1;
    }
    if (write(block_fp, block, BLOCK_SIZE) < 0) {
        perror("writeblock write");
        return -1;
    }
    return 0;
}

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */
static u64 lastblock = 0;

u64 allocblock(void *block) {
    u64 lb;
    off64_t pos = lseek64(block_fp, 0, SEEK_END);
    if (pos == (off64_t)-1) {
        perror("allocblock lseek");
        return 0;
    }
    if (pos % BLOCK_SIZE != 0) {
        fprintf(stderr, "file size not multiple of %d\n", BLOCK_SIZE);
        return 0;
    }
    if (write(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("allocblock write");
        return 0;
    }
    lb = pos / BLOCK_SIZE + 1;
    
    if (lb <= lastblock)
        printf("[*** %Ld alredy allocated! ***]\n", lb);
    
    lastblock = lb;
    return lb;
}


/**
 * newblock: get a new in-memory block set to zeros
 *
 *   @return: pointer to new block, NULL on error
 */
void *newblock() {
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
void freeblock(void *block) {
    if (block != NULL)
        free(block);
}


int __init_blockstore(void)
{
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return -1;
    }
    
    return 0;
}
