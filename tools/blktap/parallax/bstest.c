/**************************************************************************
 * 
 * bstest.c
 *
 * Block store daemon test program.
 *
 * usage: bstest <host>|X {r|w|a} ID 
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
#include <netdb.h>
#include <errno.h>
#include "blockstore.h"

int direct(char *host, u32 op, u64 id, int len) {
    struct sockaddr_in sn, peer;
    int sock;
    bsmsg_t msgbuf;
    int rc, slen;
    struct hostent *addr;

    addr = gethostbyname(host);
    if (!addr) {
        perror("bad hostname");
        exit(1);
    }
    peer.sin_family = addr->h_addrtype;
    peer.sin_port = htons(BLOCKSTORED_PORT);
    peer.sin_addr.s_addr =  ((struct in_addr *)(addr->h_addr))->s_addr;
    fprintf(stderr, "Sending to: %u.%u.%u.%u\n",
            (unsigned int)(unsigned char)addr->h_addr[0],
            (unsigned int)(unsigned char)addr->h_addr[1],
            (unsigned int)(unsigned char)addr->h_addr[2],
            (unsigned int)(unsigned char)addr->h_addr[3]);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Bad socket");
        exit(1);
    }
    memset(&sn, 0, sizeof(sn));
    sn.sin_family = AF_INET;
    sn.sin_port = htons(BLOCKSTORED_PORT);
    sn.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&sn, sizeof(sn)) < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }

    memset((void *)&msgbuf, 0, sizeof(msgbuf));
    msgbuf.operation = op;
    msgbuf.id = id;

    rc = sendto(sock, (void *)&msgbuf, len, 0,
                (struct sockaddr *)&peer, sizeof(peer));
    if (rc < 0) {
        perror("sendto");
        exit(1);
    }

    slen = sizeof(peer);
    len = recvfrom(sock, (void *)&msgbuf, sizeof(msgbuf), 0,
                   (struct sockaddr *)&peer, &slen);
    if (len < 0) {
        perror("recvfrom");
        exit(1);
    }

    printf("Reply %u bytes:\n", len);
    if (len >= MSGBUFSIZE_OP)
        printf("  operation: %u\n", msgbuf.operation);
    if (len >= MSGBUFSIZE_FLAGS)
        printf("  flags: 0x%x\n", msgbuf.flags);
    if (len >= MSGBUFSIZE_ID)
        printf("  id: %llu\n", msgbuf.id);
    if (len >= (MSGBUFSIZE_ID + 4))
        printf("  data: %02x %02x %02x %02x...\n",
               (unsigned int)msgbuf.block[0],
               (unsigned int)msgbuf.block[1],
               (unsigned int)msgbuf.block[2],
               (unsigned int)msgbuf.block[3]);
    
    if (sock > 0)
        close(sock);
   
    return 0;
}

int main (int argc, char **argv) {

    u32 op = 0;
    u64 id = 0;
    int len = 0, rc;
    void *block;

    if (argc < 3) {
        fprintf(stderr, "usage: bstest <host>|X {r|w|a} ID\n");
        return 1;
    }

    switch (argv[2][0]) {
    case 'r':
    case 'R':
        op = BSOP_READBLOCK;
        len = MSGBUFSIZE_ID;
        break;
    case 'w':
    case 'W':
        op = BSOP_WRITEBLOCK;
        len = MSGBUFSIZE_BLOCK;
        break;
    case 'a':
    case 'A':
        op = BSOP_ALLOCBLOCK;
        len = MSGBUFSIZE_BLOCK;
        break;
    default:
        fprintf(stderr, "Unknown action '%s'.\n", argv[2]);
        return 1;
    }

    if (argc >= 4)
        id = atoll(argv[3]);

    if (strcmp(argv[1], "X") == 0) {
        rc = __init_blockstore();
        if (rc < 0) {
            fprintf(stderr, "blockstore init failed.\n");
            return 1;
        }
        switch(op) {
        case BSOP_READBLOCK:
            block = readblock(id);
            if (block) {
                printf("data: %02x %02x %02x %02x...\n",
                       (unsigned int)((unsigned char*)block)[0],
                       (unsigned int)((unsigned char*)block)[1],
                       (unsigned int)((unsigned char*)block)[2],
                       (unsigned int)((unsigned char*)block)[3]);
            }
            break;
        case BSOP_WRITEBLOCK:
            block = malloc(BLOCK_SIZE);
            if (!block) {
                perror("bstest malloc");
                return 1;
            }
            memset(block, 0, BLOCK_SIZE);
            rc = writeblock(id, block);
            if (rc != 0) {
                printf("error\n");
            }
            else {
                printf("OK\n");
            }
            break;
        case BSOP_ALLOCBLOCK:
            block = malloc(BLOCK_SIZE);
            if (!block) {
                perror("bstest malloc");
                return 1;
            }
            memset(block, 0, BLOCK_SIZE);
            id = allocblock_hint(block, id);
            if (id == 0) {
                printf("error\n");
            }
            else {
                printf("ID: %llu\n", id);
            }
            break;
        }
    }
    else {
        direct(argv[1], op, id, len);
    }


    return 0;
}
