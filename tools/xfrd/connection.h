/* $Id: connection.h,v 1.1 2003/10/17 15:48:43 mjw Exp $ */
#ifndef _VFC_CONNECTION_H_
#define _VFC_CONNECTION_H_

#include <netinet/in.h>

#include "iostream.h"

/** A connection.
 * The underlying transport is a socket. 
 * Contains in and out streams using the socket.
 */
typedef struct Conn {
    struct sockaddr_in addr;
    int sock;
    IOStream *in;
    IOStream *out;
} Conn;

enum {
    CONN_NOBUFFER=1,
    CONN_READ_COMPRESS=2,
    CONN_WRITE_COMPRESS=4,
};
    
extern int Conn_read_header(int sock, int *flags);
extern int Conn_write_header(int sock, int flags);
extern int Conn_init(Conn *conn, int flags, int sock, struct sockaddr_in addr);
extern int Conn_connect(Conn *conn, int flags, struct in_addr ipaddr, uint16_t port);
extern void Conn_close(Conn *conn);

#endif /* ! _VFC_CONNECTION_H_ */
