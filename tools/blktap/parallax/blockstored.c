/**************************************************************************
 * 
 * blockstored.c
 *
 * Block store daemon.
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include "blockstore.h"

//#define BSDEBUG

int readblock_into(uint64_t id, void *block);

int open_socket(uint16_t port) {
    
    struct sockaddr_in sn;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Bad socket");
        return -1;
    }
    memset(&sn, 0, sizeof(sn));
    sn.sin_family = AF_INET;
    sn.sin_port = htons(port);
    sn.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&sn, sizeof(sn)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

static int block_fp = -1;
static int bssock = -1;

int send_reply(struct sockaddr_in *peer, void *buffer, int len) {

    int rc;
    
#ifdef BSDEBUG
    fprintf(stdout, "TX: %u bytes op=%u id=0x%llx\n",
            len, ((bsmsg_t *)buffer)->hdr.operation, ((bsmsg_t *)buffer)->hdr.id);
#endif
    rc = sendto(bssock, buffer, len, 0, (struct sockaddr *)peer, sizeof(*peer));
    if (rc < 0) {
        perror("send_reply");
        return 1;
    }


    return 0;
}

static bsmsg_t msgbuf;

void service_loop(void) {

    for (;;) {
        int rc, len;
        struct sockaddr_in from;
        size_t slen = sizeof(from);
        uint64_t bid;

        len = recvfrom(bssock, (void *)&msgbuf, sizeof(msgbuf), 0,
                       (struct sockaddr *)&from, &slen);

        if (len < 0) {
            perror("recvfrom");
            continue;
        }

        if (len < MSGBUFSIZE_OP) {
            fprintf(stderr, "Short packet.\n");
            continue;
        }

#ifdef BSDEBUG
        fprintf(stdout, "RX: %u bytes op=%u id=0x%llx\n",
                len, msgbuf.hdr.operation, msgbuf.hdr.id);
#endif

        switch (msgbuf.hdr.operation) {
        case BSOP_READBLOCK:
            if (len < MSGBUFSIZE_ID) {
                fprintf(stderr, "Short packet (readblock %u).\n", len);
                continue;
            }
            rc = readblock_into(msgbuf.hdr.id, msgbuf.block);
            if (rc < 0) {
                fprintf(stderr, "readblock error\n");
                msgbuf.hdr.flags = BSOP_FLAG_ERROR;
                send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_ID);
                continue;
            }
            msgbuf.hdr.flags = 0;
            send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_BLOCK);
            break;
        case BSOP_WRITEBLOCK:
            if (len < MSGBUFSIZE_BLOCK) {
                fprintf(stderr, "Short packet (writeblock %u).\n", len);
                continue;
            }
            rc = writeblock(msgbuf.hdr.id, msgbuf.block);
            if (rc < 0) {
                fprintf(stderr, "writeblock error\n");
                msgbuf.hdr.flags = BSOP_FLAG_ERROR;
                send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_ID);
                continue;
            }
            msgbuf.hdr.flags = 0;
            send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_ID);
            break;
        case BSOP_ALLOCBLOCK:
            if (len < MSGBUFSIZE_BLOCK) {
                fprintf(stderr, "Short packet (allocblock %u).\n", len);
                continue;
            }
            bid = allocblock(msgbuf.block);
            if (bid == ALLOCFAIL) {
                fprintf(stderr, "allocblock error\n");
                msgbuf.hdr.flags = BSOP_FLAG_ERROR;
                send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_ID);
                continue;
            }
            msgbuf.hdr.id = bid;
            msgbuf.hdr.flags = 0;
            send_reply(&from, (void *)&msgbuf, MSGBUFSIZE_ID);
            break;
        }

    }
}
 
/**
 * readblock: read a block from disk
 *   @id: block id to read
 *   @block: pointer to buffer to receive block
 *
 *   @return: 0 if OK, other on error
 */

int readblock_into(uint64_t id, void *block) {
    if (lseek64(block_fp, ((off64_t) id - 1LL) * BLOCK_SIZE, SEEK_SET) < 0) {
        printf ("%Ld\n", (id - 1) * BLOCK_SIZE);
        perror("readblock lseek");
        return -1;
    }
    if (read(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("readblock read");
        return -1;
    }
    return 0;
}

/**
 * writeblock: write an existing block to disk
 *   @id: block id
 *   @block: pointer to block
 *
 *   @return: zero on success, -1 on failure
 */
int writeblock(uint64_t id, void *block) {
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
static uint64_t lastblock = 0;

uint64_t allocblock(void *block) {
    uint64_t lb;
    off64_t pos;

    retry:
    pos = lseek64(block_fp, 0, SEEK_END);
    if (pos == (off64_t)-1) {
        perror("allocblock lseek");
        return ALLOCFAIL;
    }
    if (pos % BLOCK_SIZE != 0) {
        fprintf(stderr, "file size not multiple of %d\n", BLOCK_SIZE);
        return ALLOCFAIL;
    }
    if (write(block_fp, block, BLOCK_SIZE) != BLOCK_SIZE) {
        perror("allocblock write");
        return ALLOCFAIL;
    }
    lb = pos / BLOCK_SIZE + 1;

#ifdef BS_ALLOC_HACK
    if (lb < BS_ALLOC_SKIP)
        goto retry;
#endif
    
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
void *newblock(void) {
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
        free(block);
}


int main(int argc, char **argv)
{
    block_fp = open("blockstore.dat", O_RDWR | O_CREAT | O_LARGEFILE, 0644);

    if (block_fp < 0) {
        perror("open");
        return -1;
    }

    bssock = open_socket(BLOCKSTORED_PORT);
    if (bssock < 0) {
        return -1;
    }

    service_loop();
    
    close(bssock);

    return 0;
}
