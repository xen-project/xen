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
#ifndef _VNET_CONNECTION_H_
#define _VNET_CONNECTION_H_

#include <netinet/in.h>

#include "iostream.h"

/** A connection.
 * The underlying transport is a socket. 
 * Contains in and out streams using the socket.
 */
typedef struct Conn {
    struct sockaddr_in addr;
    int sock;
    int type;
    IOStream *in;
    IOStream *out;
    int (*fn)(struct Conn *);
    void *data;
} Conn;

typedef struct ConnList {
    Conn *conn;
    struct ConnList *next;
} ConnList;

extern ConnList * ConnList_add(Conn *conn, ConnList *l);
    
extern Conn * Conn_new(int (*fn)(struct Conn *), void *data);
extern int Conn_init(Conn *conn, int sock, int type, struct sockaddr_in addr);
extern int Conn_connect(Conn *conn, int type, struct in_addr ipaddr, uint16_t port);
extern int Conn_handle(Conn *conn);
extern void Conn_close(Conn *conn);

#endif /* ! _VNET_CONNECTION_H_ */
