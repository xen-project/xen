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
#include "parallax-threaded.h"

/*static int block_fp = -1;*/
 
static int fd_list[READ_POOL_SIZE+1];
 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *
 *   @return: pointer to block, NULL on error
 */

void *readblock(u64 id) {
    void *block;
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDONLY | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return NULL;
    }
    
    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        printf ("%Ld ", id);
        printf ("%Ld\n", (id - 1) * BLOCK_SIZE);
        perror("readblock lseek");
        goto err;
    }
    if ((block = malloc(BLOCK_SIZE)) == NULL) {
        perror("readblock malloc");
        goto err;
    }
    if (read(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("readblock read");
        free(block);
        goto err;
    }
    close(block_fp);
    return block;
    
err:
    close(block_fp);
    return NULL;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(u64 id, void *block) {
    
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return -1;
    }

    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        perror("writeblock lseek");
        goto err;
    }
    if (write(block_fp, block, BLOCK_SIZE) < 0) {
        perror("writeblock write");
        goto err;
    }
    close(block_fp);
    return 0;

err:
    close(block_fp);
    return -1;
}

/**
 * allocblock: write a new block to disk
 *   @block: pointer to block
 *
 *   @return: new id of block on disk
 */

u64 allocblock(void *block) {
    u64 lb;
    off64_t pos;
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return 0;
    }

    pos = lseek64(block_fp, 0, SEEK_END);
    if (pos == (off64_t)-1) {
        perror("allocblock lseek");
        goto err;
    }
    if (pos % BLOCK_SIZE != 0) {
        fprintf(stderr, "file size not multiple of %d\n", BLOCK_SIZE);
        goto err;
    }
    if (write(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("allocblock write");
        goto err;
    }
    lb = pos / BLOCK_SIZE + 1;
//printf("alloc(%Ld)\n", lb);
    close(block_fp);
    return lb;
    
err:
    close(block_fp);
    return 0;
    
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

static freeblock_t *new_freeblock(void)
{
    freeblock_t *fb;
    
    fb = newblock();
    
    if (fb == NULL) return NULL;
    
    fb->magic = FREEBLOCK_MAGIC;
    fb->next  = 0ULL;
    fb->count = 0ULL;
    memset(fb->list, 0, sizeof fb->list);
    
    return fb;
}

void releaseblock(u64 id)
{
    blockstore_super_t *bs_super;
    freeblock_t *fl_current;
    
    /* get superblock */
    bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
    
    /* get freeblock_current */
    if (bs_super->freelist_current == 0ULL) 
    {
        fl_current = new_freeblock();
        bs_super->freelist_current = allocblock(fl_current);
        writeblock(BLOCKSTORE_SUPER, bs_super);
    } else {
        fl_current = readblock(bs_super->freelist_current);
    }
    
    /* if full, chain to superblock and allocate new current */
    
    if (fl_current->count == FREEBLOCK_SIZE) {
        fl_current->next = bs_super->freelist_full;
        writeblock(bs_super->freelist_current, fl_current);
        bs_super->freelist_full = bs_super->freelist_current;
        freeblock(fl_current);
        fl_current = new_freeblock();
        bs_super->freelist_current = allocblock(fl_current);
        writeblock(BLOCKSTORE_SUPER, bs_super);
    }
    
    /* append id to current */
    fl_current->list[fl_current->count++] = id;
    writeblock(bs_super->freelist_current, fl_current);
    
    freeblock(fl_current);
    freeblock(bs_super);
    
    
}

/* freelist debug functions: */
void freelist_count(int print_each)
{
    blockstore_super_t *bs_super;
    freeblock_t *fb;
    u64 total = 0, next;
    
    bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
    
    if (bs_super->freelist_current == 0ULL) {
        printf("freelist is empty!\n");
        return;
    }
    
    fb = readblock(bs_super->freelist_current);
    printf("%Ld entires on current.\n", fb->count);
    total += fb->count;
    if (print_each == 1)
    {
        int i;
        for (i=0; i< fb->count; i++)
            printf("  %Ld\n", fb->list[i]);
    }
    
    freeblock(fb);
    
    if (bs_super->freelist_full == 0ULL) {
        printf("freelist_full is empty!\n");
        return;
    }
    
    next = bs_super->freelist_full;
    for (;;) {
        fb = readblock(next);
        total += fb->count;
        if (print_each == 1)
        {
            int i;
            for (i=0; i< fb->count; i++)
                printf("  %Ld\n", fb->list[i]);
        }
        next = fb->next;
        freeblock(fb);
        if (next == 0ULL) break;
    }
    printf("Total of %Ld ids on freelist.\n", total);
}

int __init_blockstore(void)
{
    int i;
    blockstore_super_t *bs_super;
    u64 ret;
    int block_fp;
    
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        exit(-1);
    }
    
    if (lseek(block_fp, 0, SEEK_END) == 0) {
        bs_super = newblock();
        bs_super->magic            = BLOCKSTORE_MAGIC;
        bs_super->freelist_full    = 0LL;
        bs_super->freelist_current = 0LL;
        
        ret = allocblock(bs_super);
        
        freeblock(bs_super);
    } else {
        bs_super = (blockstore_super_t *) readblock(BLOCKSTORE_SUPER);
        if (bs_super->magic != BLOCKSTORE_MAGIC)
        {
            printf("BLOCKSTORE IS CORRUPT! (no magic in superblock!)\n");
            exit(-1);
        }
        freeblock(bs_super);
    }
        
    close(block_fp);
        
    
    /*
    for (i=0; i<(READ_POOL_SIZE+1); i++) {
        
        fd_list[i] =  open("blockstore.dat", 
                O_RDWR | O_CREAT | O_LARGEFILE, 0644);

        if (fd_list[i] < 0) {
            perror("open");
            return -1;
        }
    }
    */
    return 0;
}
