/* Remote utility routines for the remote server for GDB.
   Copyright (C) 2008
   Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; If not, see <http://www.gnu.org/licenses/>.  */
/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/* This module handles communication with remote gdb.  courtesy 
 * of gdbserver remote-utils.c */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "gx.h"


extern int gx_remote_dbg;

static int remote_fd;


/* Returns: 0 success. -1 failure */
static int
do_tcp(char *port_str)
{
    int port;
    struct sockaddr_in sockaddr;
    socklen_t tmp;
    int sock_fd;

    port = atoi(port_str);

    sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        gxprt("ERROR: failed socket open. errno:%d\n", errno);
        return -1;
    }

    /* Allow rapid reuse of this port. */
    tmp = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp,sizeof(tmp));

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = PF_INET;
    sockaddr.sin_port = htons (port);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock_fd, (struct sockaddr *) &sockaddr, sizeof (sockaddr))
        || listen (sock_fd, 1)) {
        gxprt("ERROR: can't bind address. errno:%d\n", errno);
        close(sock_fd);
        return -1;
    }
    printf("Listening on port %d\n", port);

    tmp = sizeof(sockaddr);
    remote_fd = accept(sock_fd, (struct sockaddr *) &sockaddr, &tmp);
    if (remote_fd == -1) {
        gxprt("ERROR: accept failed. errno:%d\n", errno);
        close(sock_fd);
        return -1;
    }

    /* Enable TCP keep alive process. */
    tmp = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&tmp,sizeof(tmp));

    /* Tell TCP not to delay small packets.  This greatly speeds up
     * interactive response. */
    tmp = 1;
    setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, 
               (char *)&tmp, sizeof(tmp));

    close(sock_fd);           /* No longer need this */

    signal(SIGPIPE, SIG_IGN); /* If we don't do this, then gdbserver simply
                               * exits when the remote side dies.  */

    /* Convert IP address to string */
    printf("Remote debugging from host %s\n", inet_ntoa(sockaddr.sin_addr));

    return 0;
}

/* 
 * Open a connection for remote gdb on the given port number
 * Returns: 0 for success. -1 for failure 
 */
int
gx_remote_open(char *portnum_str)
{
    int save_fcntl_flags;
  
    if (do_tcp(portnum_str) == -1) {
        close(remote_fd);
        return -1;
    }

#if defined(F_SETFL) && defined (FASYNC)
    save_fcntl_flags = fcntl(remote_fd, F_GETFL, 0);
    fcntl(remote_fd, F_SETFL, save_fcntl_flags | FASYNC);
#if defined (F_SETOWN)
    fcntl (remote_fd, F_SETOWN, getpid ());
#endif
#endif
    return 0;
}

void
gx_remote_close(void)
{
    close(remote_fd);
}


/* Returns next char from remote gdb.  -1 if error.  */
static int
readchar(void)
{
    static char buf[BUFSIZ];
    static int bufcnt = 0;
    static char *bufp;
    uint64_t ll;

    if (bufcnt-- > 0)
        return *bufp++ & 0x7f;

    bufcnt = read(remote_fd, buf, sizeof (buf));
    ll = *(uint64_t *)buf;
    if (bufcnt <= 0) {
        if (bufcnt == 0)
            gxprt("readchar: Got EOF\n");
        else
            perror ("readchar");
        return -1;
    }
    bufp = buf;
    bufcnt--;
    return *bufp++ & 0x7f;
}

/* Read a packet from the remote machine, with error checking,
 * and store it in buf.  
 * Returns:  length of packet, or negative int if error. 
 */
int
gx_getpkt (char *buf)
{
    char *bp;
    unsigned char csum, c1, c2;
    int c;
        
    while (1) {
        csum = 0;
        
        while (1) {
            c = readchar();
            if (c == '$')
                break;

            if (gx_remote_dbg)
                gxprt("[getpkt: discarding char '%c']\n", c);
            if (c < 0)
                return -1;
        }
        
        bp = buf;
        while (1) {
            c = readchar ();
            if (c < 0)
                return -1;
            if (c == '#')
                break;
            *bp++ = c;
            csum += c;
        }
        *bp = 0;
        
        c1 = gx_fromhex(readchar());
        c2 = gx_fromhex(readchar());
        
        if (csum == (c1 << 4) + c2)
            break;
        
        gxprt("Bad checksum, sentsum=0x%x, csum=0x%x, buf=%s\n",
              (c1 << 4) + c2, csum, buf);
        if (write(remote_fd, "-", 1) != 1) {
            perror("write");
            return -1;
        }
    }
    if (gx_remote_dbg) {
        gxprt("getpkt (\"%s\");  [sending ack] \n", buf);
    }
        
    if (write(remote_fd, "+", 1) != 1) {
        perror("write");
        return -1;
    }
        
    if (gx_remote_dbg) {
        gxprt("[sent ack]\n");
    }
    return bp - buf;
}

void
gx_reply_ok(char *buf)
{
    buf[0] = 'O';
    buf[1] = 'K';
    buf[2] = '\0';
}

/* ENN error */
void
gx_reply_error(char *buf)
{
    buf[0] = 'E';
    buf[1] = '0';
    buf[2] = '1';
    buf[3] = '\0';
}

/* 
 * Send a packet to the remote machine, with error checking.
 * The data of the packet is in buf.  
 * Returns: >= 0 on success, -1 otherwise. 
 */
int
gx_putpkt (char *buf)
{
    int i;
    unsigned char csum = 0;
    char *buf2;
    char buf3[1];
    int cnt = strlen (buf);
    char *p;

    buf2 = malloc(8192);

    /* Copy the packet into buffer buf2, encapsulating it
     * and giving it a checksum.  */

    p = buf2;
    *p++ = '$';

    for (i = 0; i < cnt; i++) {
        csum += buf[i];
        *p++ = buf[i];
    }
    *p++ = '#';
    *p++ = gx_tohex((csum >> 4) & 0xf);
    *p++ = gx_tohex(csum & 0xf);

    *p = '\0';

    /* Send it over and over until we get a positive ack.  */

    do {
        int cc;

        if (write(remote_fd, buf2, p - buf2) != p - buf2) {
            perror("putpkt(write)");
            free(buf2);
            return -1;
        }
        if (gx_remote_dbg)
            gxprt("putpkt (\"%s\"); [looking for ack]\n", buf2);

        cc = read(remote_fd, buf3, 1);
        if (gx_remote_dbg)
            gxprt("[received '%c' (0x%x)]\n", buf3[0], buf3[0]);

        if (cc <= 0) {
            if (cc == 0)
                gxprt("putpkt(read): Got EOF\n");
            else
                gxprt("putpkt(read)");
            free(buf2);
            return -1;
        }
        /* Check for an input interrupt while we're here.  */
        if (buf3[0] == '\003')
            gxprt("WARN: need to send SIGINT in putpkt\n");

    } while (buf3[0] != '+');

    free(buf2);
    return 1;                       /* Success! */
}

