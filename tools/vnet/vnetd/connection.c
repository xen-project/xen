/*
 * Copyright (C) 2003 - 2004 Mike Wray <mike.wray@hp.com>.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "allocate.h"
#include "connection.h"
#include "file_stream.h"
#include "socket_stream.h"

#define DEBUG
#undef DEBUG
#define MODULE_NAME "conn"
#include "debug.h"

/** Initialize a file stream from a file desciptor.
 *
 * @param fd file descriptor
 * @param mode file mode
 * @param buffered make the stream buffered if 1, unbuffered if 0
 * @param io return parameter for the stream
 * @return 0 on success, error code otherwise
 */
static int stream_init(int fd, const char *mode, int buffered, IOStream **io){
    int err = 0;
    *io = file_stream_fdopen(fd, mode);
    if(!*io){
        err = -errno;
        perror("fdopen");
        goto exit;
    }
    if(!buffered){
        // Make unbuffered.
        err = file_stream_setvbuf(*io, NULL, _IONBF, 0);
        if(err){
            err = -errno;
            perror("setvbuf");
            goto exit;
        }
    }
  exit:
    if(err && *io){
        IOStream_close(*io);
        *io = NULL;
    }
    return err;
}

ConnList * ConnList_add(Conn *conn, ConnList *l){
    ConnList *v;
    v = ALLOCATE(ConnList);
    v->conn = conn;
    v->next =l;
    return v;
}

Conn *Conn_new(int (*fn)(Conn *), void *data){
    Conn *conn;
    conn = ALLOCATE(Conn);
    conn->fn = fn;
    conn->data = data;
    return conn;
}

int Conn_handle(Conn *conn){
    int err = 0;
    dprintf(">\n");
    if(conn->fn){
        err = conn->fn(conn);
    } else {
        dprintf("> no handler\n");
        err = -ENOSYS;
    }
    if(err < 0){
        Conn_close(conn);
    }
    dprintf("< err=%d\n", err);
    return err;
}
    
/** Initialize a connection.
 *
 * @param conn connection
 * @param sock socket
 * @param ipaddr ip address
 * @return 0 on success, error code otherwise
 */
int Conn_init(Conn *conn, int sock, int type, struct sockaddr_in addr){
    int err = 0;
    conn->addr = addr;
    conn->type = type;
    conn->sock = sock;
    if(type == SOCK_STREAM){
        err = stream_init(sock, "r", 0, &conn->in);
        if(err) goto exit;
        err = stream_init(sock, "w", 0, &conn->out);
        if(err) goto exit;
    } else {
        conn->in = socket_stream_new(sock);
        conn->out = socket_stream_new(sock);
        socket_stream_set_addr(conn->out, &addr);
    }
  exit:
    if(err) eprintf("< err=%d\n", err);
    return err;
}

/** Open a connection.
 *
 * @param conn connection
 * @param socktype socket type
 * @param ipaddr ip address to connect to
 * @param port port
 * @return 0 on success, error code otherwise
 */
int Conn_connect(Conn *conn, int socktype, struct in_addr ipaddr, uint16_t port){
    int err = 0;
    int sock;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    socklen_t addr_n = sizeof(addr_in);
    dprintf("> addr=%s:%d\n", inet_ntoa(ipaddr), ntohs(port));
    sock = socket(AF_INET, socktype, 0);
    if(sock < 0){
        err = -errno;
        goto exit;
    }
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr = ipaddr;
    addr_in.sin_port = port;
    err = connect(sock, addr, addr_n);
    if(err) goto exit;
    err = Conn_init(conn, sock, socktype, addr_in);
  exit:
    if(err) eprintf("< err=%d\n", err);
    return err;
}

/** Close a connection.
 *
 * @param conn connection
 */
void Conn_close(Conn *conn){
    if(!conn) return;
    if(conn->in) IOStream_close(conn->in);
    if(conn->out) IOStream_close(conn->out);
    shutdown(conn->sock, 2);
}
