/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>.
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
/** @file
 *
 * Vnetd tcp messages:
 *
 * - varp request: request care-of-addr for a vif.
 *       If know answer, reply. If not broadcast locally.
 *
 * - varp announce: reply to a varp request.
 *       If a (local) request is pending, remember and broadcast locally.
 *
 * - vnet subscribe: indicate there are local vifs in a vnet (use varp announce?).
 *
 * - vnet forward: tunneled broadcast packet to rebroadcast.
 *       Broadcast locally (if there are vifs in the vnet).
 *
 *
 * Vnetd udp messages (varp):
 *
 * - local varp request:
 *       If know and vif is non-local, reply.
 *       If know and vif is local, do nothing (but announce will reset).
 *       If have entry saying is local and no-one answers - remove (? or rely on entry timeout).
 *       If don't know and there is no (quick) local reply, forward to peers.
 *
 * - remote varp request:
 *       If know, reply.
 *       If don't know, query locally (and queue request).
 *
 * - varp announce: remember and adjust vnet subscriptions.
 *       Forward to peers if a request is pending.
 *
 * Vnetd broadcast messages (tunneling):
 *
 * - etherip: forward to peers (on the right vnets)
 *
 * - esp: forward to peers (on the right vnets)
 *
 *
 * For etherip can tell the vnet from the header (in clear).
 * But for esp can't. So should use mcast to define? Or always some clear header?
 *
 * Make ssl on tcp connections optional.
 *
 * So far have been assuming esp for security.
 * But could use vnetd to forward and use ssl on the connection.
 * But has usual probs with efficiency.
 * However, should 'just work' if the coa for the vif has been set
 * to the vnetd. How? Vnetd configured to act as gateway for 
 * some peers? Then would rewrite varp announce to itself and forward
 * traffic to peer.
 *
 * Simplify - make each vnetd have one peer?
 * If need to link more subnets, add vnetds?
 *
 * Need requests table for each tcp conn (incoming).
 * - entries we want to resolve (and fwd the answer).
 *
 * Need requests table for the udp socket.
 * - entries we want to resolve (and return the answer).
 *
 * Need table of entries we know.
 * - from caching local announce
 * - from caching announce reply to forwarded request
 *
 * Problem with replying to requests from the cache - if the cache
 * is out of date we reply with incorrect data. So if a VM migrates
 * we will advertise the old location until it times out.
 *
 * So should probably not reply out of the cache at all - but always
 * query for the answer. Could query direct to old location if
 * entry is valid the first time, and broadcast if no reply in timeout.
 * Causes delay if migrated - may as well broadcast.
 *
 * Need to watch out for query loops. If have 3 vnetds A,B,C and
 * A gets a query, forwards to B and C. B forwards to C, which
 * forwards to A, and on forever. So if have an entry that has been
 * probed, do not forward it when get another query for it.
 *
 * @author Mike Wray <mike.wray@hpl.hp.com>
 */


#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>

//#include </usr/include/linux/ip.h> // For struct iphdr;
#include <linux/ip.h> // For struct iphdr;

#include <linux/if_ether.h>
#include "if_etherip.h"
#include "if_varp.h"

#include "allocate.h"

#include "vnetd.h"
#include "file_stream.h"
#include "string_stream.h"
#include "socket_stream.h"
#include "sys_net.h"

#include "enum.h"
#include "sxpr.h"

#include "marshal.h"
#include "connection.h"
#include "select.h"
#include "timer.h"
#include "vcache.h"

int create_socket(int socktype, uint32_t saddr, uint32_t port, int flags, Conn **val);

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/** Socket flags. */
enum {
    VSOCK_REUSE=1,
    VSOCK_BIND=2,
    VSOCK_CONNECT=4,
    VSOCK_BROADCAST=8,
    VSOCK_MULTICAST=16,
 };

#define PROGRAM      "vnetd"
#define VERSION      "0.1"

#define MODULE_NAME  PROGRAM
#define DEBUG
#undef DEBUG
#include "debug.h"

#define OPT_PORT     'p'
#define KEY_PORT     "port"
#define DOC_PORT     "<port>\n\t" PROGRAM " UDP port (as a number or service name)"

#define OPT_ADDR     'm'
#define KEY_ADDR     "mcaddr"
#define DOC_ADDR     "<address>\n\t" PROGRAM " multicast address"

#define OPT_PEER     'r'
#define KEY_PEER     "peer"
#define DOC_PEER     "<peer>\n\t Peer " PROGRAM " to connect to (IP address or hostname)"

#define OPT_FILE     'f'
#define KEY_FILE     "file"
#define DOC_FILE     "<file>\n\t Configuration file to load"

#define OPT_CTRL     'c'
#define KEY_CTRL     "control"
#define DOC_CTRL     "<port>\n\t " PROGRAM " control port (as a number or service name)"

#define OPT_HELP     'h'
#define KEY_HELP     "help"
#define DOC_HELP     "\n\tprint help"

#define OPT_VERSION  'v'
#define KEY_VERSION  "version"
#define DOC_VERSION  "\n\tprint version"

#define OPT_VERBOSE  'V'
#define KEY_VERBOSE  "verbose"
#define DOC_VERBOSE  "\n\tverbose flag"

/** Print a usage message.
 * Prints to stdout if err is zero, and exits with 0.
 * Prints to stderr if err is non-zero, and exits with 1.
 *
 * @param err error code
 */
static void usage(int err){
    FILE *out = (err ? stderr : stdout);

    fprintf(out, "Usage: %s [options]\n", PROGRAM);
    fprintf(out, "-%c, --%s %s\n", OPT_ADDR,     KEY_ADDR,     DOC_ADDR);
    fprintf(out, "-%c, --%s %s\n", OPT_PORT,     KEY_PORT,     DOC_PORT);
    fprintf(out, "-%c, --%s %s\n", OPT_PEER,     KEY_PEER,     DOC_PEER);
    fprintf(out, "-%c, --%s %s\n", OPT_VERBOSE,  KEY_VERBOSE,  DOC_VERBOSE);
    fprintf(out, "-%c, --%s %s\n", OPT_VERSION,  KEY_VERSION,  DOC_VERSION);
    fprintf(out, "-%c, --%s %s\n", OPT_HELP,     KEY_HELP,     DOC_HELP);
    exit(err ? 1 : 0);
}

/** Short options. Options followed by ':' take an argument. */
static char *short_opts = (char[]){
    OPT_ADDR,     ':',
    OPT_PORT,     ':',
    OPT_PEER,     ':',
    OPT_HELP,
    OPT_VERSION,
    OPT_VERBOSE,
    0 };

/** Long options. */
static struct option const long_opts[] = {
    { KEY_ADDR,     required_argument, NULL, OPT_ADDR     },
    { KEY_PORT,     required_argument, NULL, OPT_PORT     },
    { KEY_PEER,     required_argument, NULL, OPT_PEER     },
    { KEY_HELP,     no_argument,       NULL, OPT_HELP     },
    { KEY_VERSION,  no_argument,       NULL, OPT_VERSION  },
    { KEY_VERBOSE,  no_argument,       NULL, OPT_VERBOSE  },
    { NULL,         0,                 NULL, 0            }
};

/** Get address of vnetd. So we can ignore broadcast traffic
 * we sent ourselves.
 *
 * @param addr
 * @return 0 on success, error code otherwise
 */
int get_self_addr(struct sockaddr_in *addr){
    int err = 0;
    char hostname[1024] = {};
    unsigned long saddr;
 
    //dprintf(">\n");
    err = gethostname(hostname, sizeof(hostname) -1);
    if(err) goto exit;
    err = get_host_address(hostname, &saddr);
    if(err == 0){ err = -ENOENT;  goto exit; }
    err = 0;
    addr->sin_addr.s_addr = saddr;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Marshal a message.
 *
 * @param io destination
 * @param msg message
 * @return number of bytes written, or negative error code
 */
int VnetMsg_marshal(IOStream *io, VnetMsg *msg){
    int err = 0;
    int hdr_n = sizeof(VnetMsgHdr);

    err = marshal_uint16(io, msg->hdr.id);
    if(err < 0) goto exit;
    err = marshal_uint16(io, msg->hdr.opcode);
    if(err < 0) goto exit;
    switch(msg->hdr.id){
    case VNET_VARP_ID:
        err = marshal_bytes(io, ((char*)msg) + hdr_n, sizeof(VarpHdr) - hdr_n);
        break;
    case VNET_FWD_ID:
        err = marshal_uint16(io, msg->fwd.protocol);
        if(err < 0) goto exit;
        err = marshal_uint16(io, msg->fwd.len);
        if(err < 0) goto exit;
        err = marshal_bytes(io, msg->fwd.data, msg->fwd.len);
        break;
    default:
        err = -EINVAL;
        break;
    }
  exit:
    return err;
}

/** Unmarshal a message.
 *
 * @param io source
 * @param msg message to unmarshal into
 * @return number of bytes read, or negative error code
 */
int VnetMsg_unmarshal(IOStream *io, VnetMsg *msg){
    int err = 0;
    int hdr_n = sizeof(VnetMsgHdr);

    dprintf("> id\n");
    err = unmarshal_uint16(io, &msg->hdr.id);
    if(err < 0) goto exit;
    dprintf("> opcode\n");
    err = unmarshal_uint16(io, &msg->hdr.opcode);
    if(err < 0) goto exit;
    switch(msg->hdr.id){
    case VNET_VARP_ID:
        msg->hdr.opcode = htons(msg->hdr.opcode);
        dprintf("> varp hdr_n=%d varphdr=%d\n", hdr_n, sizeof(VarpHdr));
        err = unmarshal_bytes(io, ((char*)msg) + hdr_n, sizeof(VarpHdr) - hdr_n);
        break;
    case VNET_FWD_ID:
        dprintf("> forward\n");
        err = unmarshal_uint16(io, &msg->fwd.protocol);
        if(err < 0) goto exit;
        dprintf("> forward len\n");
        err = unmarshal_uint16(io, &msg->fwd.len);
        if(err < 0) goto exit;
        dprintf("> forward bytes\n");
        err = unmarshal_bytes(io, msg->fwd.data, msg->fwd.len);
        break;
    default:
        wprintf("> Invalid id %d\n", msg->hdr.id);
        err = -EINVAL;
        break;
    }
  exit:
    dprintf("< err=%d \n", err);
    return err;
}

Vnetd _vnetd = {};
Vnetd *vnetd = &_vnetd;

/** Counter for timer alarms.
 */
static unsigned timer_alarms = 0;

/** Set vnetd defaults.
 *
 * @param vnetd vnetd
 */
void vnetd_set_defaults(Vnetd *vnetd){
    *vnetd = (Vnetd){};
    vnetd->port = htons(VNETD_PORT);
    vnetd->peer_port = vnetd->port; //htons(VNETD_PEER_PORT);
    vnetd->verbose = FALSE;
    vnetd->peers = ONULL;
    vnetd->mcast_addr.sin_addr.s_addr = VARP_MCAST_ADDR;
    vnetd->mcast_addr.sin_port = vnetd->port;
}

uint32_t vnetd_mcast_addr(Vnetd *vnetd){
    return vnetd->mcast_addr.sin_addr.s_addr;
}

uint16_t vnetd_mcast_port(Vnetd *vnetd){
    return vnetd->mcast_addr.sin_port;
}

/** Add a connection to a peer.
 *
 * @param vnetd vnetd
 * @param conn connection
 */
void connections_add(Vnetd *vnetd, Conn *conn){
    vnetd->connections = ConnList_add(conn, vnetd->connections);
}

/** Delete a connection to a peer.
 *
 * @param vnetd vnetd
 * @param conn connection
 */
void connections_del(Vnetd *vnetd, Conn *conn){
    ConnList *prev, *curr, *next;
    for(prev = NULL, curr = vnetd->connections; curr; prev = curr, curr = next){
        next = curr->next;
        if(curr->conn == conn){
            if(prev){
                prev->next = curr->next;
            } else {
                vnetd->connections = curr->next;
            }
        }
    }
}

/** Close all connections to peers.
 *
 * @param vnetd vnetd
 */
void connections_close_all(Vnetd *vnetd){
    ConnList *l;
    for(l = vnetd->connections; l; l = l->next){
        Conn_close(l->conn);
    }
    vnetd->connections = NULL;
}

/** Add peer connections to a select set.
 *
 * @param vnetd vnetd
 * @param set select set
 */
void connections_select(Vnetd *vnetd, SelectSet *set){
    ConnList *l;
    for(l = vnetd->connections; l; l = l->next){
        SelectSet_add_read(set, l->conn->sock);
    }
}

/** Handle peer connections according to a select set.
 *
 * @param vnetd vnetd
 * @param set indicates ready connections
 */
void connections_handle(Vnetd *vnetd, SelectSet *set){
    ConnList *prev, *curr, *next;
    Conn *conn;
    for(prev = NULL, curr = vnetd->connections; curr; prev = curr, curr = next){
        next = curr->next;
        conn = curr->conn;
        if(FD_ISSET(conn->sock, &set->rd)){
            int conn_err;
            conn_err = Conn_handle(conn);
            if(conn_err){
                if(prev){
                    prev->next = curr->next;
                } else {
                    vnetd->connections = curr->next;
                }
            }
        }
    }
}

/** Forward a message from a peer onto the local subnet.
 *
 * @param vnetd vnetd
 * @param vmsg message
 * @return 0 on success, error code otherwise
 */
int vnetd_forward_local(Vnetd *vnetd, VnetMsg *vmsg){
    int err = 0;
    int sock = 0;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    socklen_t addr_n = sizeof(addr_in);

    dprintf(">\n");
    switch(vmsg->fwd.protocol){
    case IPPROTO_ESP:
        dprintf("> ESP\n");
        sock = vnetd->esp_sock; break;
    case IPPROTO_ETHERIP:
        dprintf("> Etherip\n");
        sock = vnetd->etherip_sock; break;
    default:
        err = -EINVAL;
        goto exit;
    }
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr = vnetd->mcast_addr.sin_addr;
    addr_in.sin_port = htons(vmsg->fwd.protocol);
    dprintf("> send dst=%s protocol=%d len=%d\n",
            inet_ntoa(addr_in.sin_addr), vmsg->fwd.protocol, vmsg->fwd.len);
    err = sendto(sock, vmsg->fwd.data, vmsg->fwd.len, 0, addr, addr_n);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Forward a message to a peer.
 *
 * @param conn peer connection
 * @param protocol message protocol
 * @param data message data
 * @param data_n message size
 * @return 0 on success, error code otherwise
 */
int vnetd_forward_peer(Conn *conn, int protocol, void *data, int data_n){
    int err = 0;
    IOStream _io, *io = &_io;
    StringData sdata;
    char buf[1600];

    dprintf("> addr=%s protocol=%d n=%d\n",
            inet_ntoa(conn->addr.sin_addr), protocol, data_n);
    string_stream_init(io, &sdata, buf, sizeof(buf));
    dprintf("> 10\n");
    err = marshal_uint16(io, VNET_FWD_ID);
    if(err < 0) goto exit;
    dprintf("> 20\n");
    err = marshal_uint16(io, 0);
    if(err < 0) goto exit;
    dprintf("> 30\n");
    err = marshal_uint16(io, protocol);
    if(err < 0) goto exit;
    dprintf("> 40\n");
    err = marshal_uint16(io, data_n);
    if(err < 0) goto exit;
    dprintf("> 50\n");
    err = marshal_bytes(io, data, data_n);
    if(err < 0) goto exit;
    dprintf("> 60 bytes=%d\n", IOStream_get_written(io));
    err = IOStream_write(conn->out, buf, IOStream_get_written(io));
    IOStream_flush(conn->out);
  exit:
    if(err < 0) perror(__FUNCTION__);
    dprintf("< err=%d\n", err);
    return err;
}

/** Forward a message to all peers.
 *
 * @param vnetd vnetd
 * @param protocol message protocol
 * @param data message data
 * @param data_n message size
 * @return 0 on success, error code otherwise
 */
int vnetd_forward_peers(Vnetd *vnetd, int protocol, void *data, int data_n){
    int err = 0;
    ConnList *curr, *next;

    dprintf(">\n");
    for(curr = vnetd->connections; curr; curr = next){
        next = curr->next;
        vnetd_forward_peer(curr->conn, protocol, data, data_n);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Handler for a peer connection.
 * Reads a VnetMsg from the connection and handles it.
 *
 * @param conn peer connection
 * @return 0 on success, error code otherwise
 */
int conn_handle_fn(Conn *conn){
    int err = 0;
    VnetMsg *vmsg = ALLOCATE(VnetMsg);
    IPMessage *msg = NULL;

    dprintf("> addr=%s port=%u\n",
            inet_ntoa(conn->addr.sin_addr),
            ntohs(conn->addr.sin_port));
    err = VnetMsg_unmarshal(conn->in, vmsg);
    if(err < 0){
        wprintf("> Unmarshal error %d\n", err);
        goto exit;
    }
    switch(vmsg->hdr.id){
    case VNET_VARP_ID:
        dprintf("> Got varp message\n");
        msg = ALLOCATE(IPMessage);
        msg->conn = conn;
        msg->saddr = conn->addr;
        msg->data = vmsg;
        err = vcache_handle_message(msg, 0);
        err = 0;
        break;
    case VNET_FWD_ID:
        dprintf("> Got forward message\n");
        err = vnetd_forward_local(vnetd, vmsg);
        err = 0;
        break;
    default:
        wprintf("> Invalid id=%d\n", vmsg->hdr.id);
        err = -EINVAL;
        break;
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Accept an incoming tcp connection from a peer vnetd.
 *
 * @param sock tcp socket
 * @return 0 on success, error code otherwise
 */
int vnetd_accept(Vnetd *vnetd, Conn *conn){
    Conn *new_conn = NULL;
    struct sockaddr_in peer_in;
    struct sockaddr *peer = (struct sockaddr *)&peer_in;
    socklen_t peer_n = sizeof(peer_in);
    int peersock;
    int err = 0;
    
    //dprintf(">\n");
    new_conn = Conn_new(conn_handle_fn, vnetd);
    //dprintf("> accept...\n");
    peersock = accept(conn->sock, peer, &peer_n);
    //dprintf("> accept=%d\n", peersock);
    if(peersock < 0){
        perror("accept");
        err = -errno;
        goto exit;
    }
    iprintf("> Accepted connection from %s:%d\n",
            inet_ntoa(peer_in.sin_addr), htons(peer_in.sin_port));
    err = Conn_init(new_conn, peersock, SOCK_STREAM, peer_in);
    if(err) goto exit;
    connections_add(vnetd, new_conn);
  exit:
    if(err){
        Conn_close(new_conn);
    }
    if(err < 0) wprintf("< err=%d\n", err);
    return err;
}

/** Connect to a peer vnetd.
 *
 * @param vnetd vnetd
 * @param addr address
 * @param port port
 * @return 0 on success, error code otherwise
 */
int vnetd_connect(Vnetd *vnetd, struct in_addr addr, uint16_t port){
    Conn *conn = NULL;
    int err = 0;

    //dprintf(">\n");
    conn = Conn_new(conn_handle_fn, vnetd);
    err = Conn_connect(conn, SOCK_STREAM, addr, port);
    if(err) goto exit;
    connections_add(vnetd, conn);
  exit:
    if(err){
        Conn_close(conn);
    }
    //dprintf(" < err=%d\n", err);
    return err;
}

/** Handle a message on the udp socket.
 * Expecting to see VARP messages only.
 *
 * @param sock udp socket
 * @return 0 on success, error code otherwise
 */
int vnetd_handle_udp(Vnetd *vnetd, Conn *conn){
    int err = 0, rcv = 0;
    struct sockaddr_in self_in;
    struct sockaddr_in peer_in;
    struct sockaddr *peer = (struct sockaddr *)&peer_in;
    socklen_t peer_n = sizeof(peer_in);
    VnetMsg *vmsg = NULL;
    void *data;
    int data_n;
    int flags = 0;
    IPMessage *msg = NULL;

    //dprintf(">\n");
    self_in = vnetd->addr;
    vmsg = ALLOCATE(VnetMsg);
    data = &vmsg->varp.varph;
    data_n = sizeof(VarpHdr);
    rcv = recvfrom(conn->sock, data, data_n, flags, peer, &peer_n);
    if(rcv < 0){
        err = rcv;
        goto exit;
    }
    dprintf("> Received %d bytes from %s:%d\n",
            rcv, inet_ntoa(peer_in.sin_addr), htons(peer_in.sin_port));
    if(rcv != data_n){
        err = -EINVAL;
        goto exit;
    }
    if(peer_in.sin_addr.s_addr == self_in.sin_addr.s_addr){
        //dprintf("> Ignoring message from self.\n");
        goto exit;
    }
    msg = ALLOCATE(IPMessage);
    msg->conn = conn;
    msg->saddr = peer_in;
    msg->data = vmsg;

    err = vcache_handle_message(msg, 1);
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Handle a message on a raw socket.
 * Only deals with etherip and esp.
 * Forwards messages to peers.
 *
 * @param vnetd vnetd
 * @param sock socket
 * @param protocol protocol
 * @return 0 on success, error code otherwise
 */
int vnetd_handle_protocol(Vnetd *vnetd, int sock, int protocol){
    int err = 0, rcv = 0;
    struct sockaddr_in self_in;
    struct sockaddr_in peer_in;
    struct sockaddr *peer = (struct sockaddr *)&peer_in;
    socklen_t peer_n = sizeof(peer_in);
    uint8_t buf[VNET_FWD_MAX];
    int buf_n = sizeof(buf);
    char *data, *end;
    int flags = 0;
    struct iphdr *iph = NULL;

    //dprintf(">\n");
    self_in = vnetd->addr;
    rcv = recvfrom(sock, buf, buf_n, flags, peer, &peer_n);
    if(rcv < 0){
        err = rcv;
        goto exit;
    }
    dprintf("> Received %d bytes from %s protocol=%d\n",
            rcv, inet_ntoa(peer_in.sin_addr), protocol);
    if(rcv < sizeof(struct iphdr)){
        wprintf("> Message too short for IP header\n");
        err = -EINVAL;
        goto exit;
    }
    if(peer_in.sin_addr.s_addr == self_in.sin_addr.s_addr){
        dprintf("> Ignoring message from self.\n");
        goto exit;
    }
    data = buf;
    end = buf + rcv;
    iph = (void*)data;
    data += (iph->ihl << 2);
    vnetd_forward_peers(vnetd, protocol, data, end - data);
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Socket select loop.
 * Accepts connections on the tcp socket and handles
 * messages on the other sockets.
 *
 * @return 0 on success, error code otherwise
 */
int vnetd_select(Vnetd *vnetd){
    int err = 0;
    SelectSet set = {};
    while(1){
        SelectSet_zero(&set);
        SelectSet_add_read(&set, vnetd->udp_conn->sock);
        SelectSet_add_read(&set, vnetd->bcast_conn->sock);
        SelectSet_add_read(&set, vnetd->etherip_sock);
        SelectSet_add_read(&set, vnetd->esp_sock);
        SelectSet_add_read(&set, vnetd->listen_conn->sock);
        connections_select(vnetd, &set);
        err = SelectSet_select(&set, NULL);
        if(err == 0) continue;
        if(err < 0){
            if(errno == EINTR){
                if(timer_alarms){
                    timer_alarms = 0;
                    process_timers();
                }
                continue;
            }
            perror("select");
            goto exit;
        }
        if(FD_ISSET(vnetd->udp_conn->sock, &set.rd)){
            vnetd_handle_udp(vnetd, vnetd->udp_conn);
        }
        if(FD_ISSET(vnetd->bcast_conn->sock, &set.rd)){
            vnetd_handle_udp(vnetd, vnetd->bcast_conn);
        }
        if(FD_ISSET(vnetd->etherip_sock, &set.rd)){
            vnetd_handle_protocol(vnetd, vnetd->etherip_sock, IPPROTO_ETHERIP);
        }
        if(FD_ISSET(vnetd->esp_sock, &set.rd)){
            vnetd_handle_protocol(vnetd, vnetd->esp_sock, IPPROTO_ESP);
        }
        connections_handle(vnetd, &set);
        if(FD_ISSET(vnetd->listen_conn->sock, &set.rd)){
            vnetd_accept(vnetd, vnetd->listen_conn);
        }
    }
  exit:
    return err;
}

/** Set socket option to reuse address.
 */
int setsock_reuse(int sock, int reuse){
    int err = 0;
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if(err < 0){
        err = -errno;
        perror("setsockopt SO_REUSEADDR");
    }
    return err;
}

/** Set socket broadcast option.
 */
int setsock_broadcast(int sock, int bcast){
    int err = 0;
    err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
    if(err < 0){
        err = -errno;
        perror("setsockopt SO_BROADCAST");
    }
    return err;
}

/** Join a socket to a multicast group.
 */
int setsock_multicast(int sock, uint32_t saddr){
    int err = 0;
    struct ip_mreqn mreq = {};
    int mloop = 0;
    // See 'man 7 ip' for these options.
    mreq.imr_multiaddr.s_addr = saddr;       // IP multicast address.
    mreq.imr_address = vnetd->addr.sin_addr; // Interface IP address.
    mreq.imr_ifindex = 0;                    // Interface index (0 means any).
    err = setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, &mloop, sizeof(mloop));
    if(err < 0){
        err = -errno;
        perror("setsockopt IP_MULTICAST_LOOP");
        goto exit;
    }
    err = setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if(err < 0){
        err = -errno;
        perror("setsockopt IP_ADD_MEMBERSHIP");
        goto exit;
    }
  exit:
    return err;
}

/** Set a socket's multicast ttl (default is 1).
 */
int setsock_multicast_ttl(int sock, uint8_t ttl){
    int err = 0;
    err = setsockopt(sock, SOL_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if(err < 0){
        err = -errno;
        perror("setsockopt IP_MULTICAST_TTL");
    }
    return err;
}


char * socket_flags(int flags){
    static char s[6];
    int i = 0;
    s[i++] = (flags & VSOCK_CONNECT   ? 'c' : '-');
    s[i++] = (flags & VSOCK_BIND      ? 'b' : '-');
    s[i++] = (flags & VSOCK_REUSE     ? 'r' : '-');
    s[i++] = (flags & VSOCK_BROADCAST ? 'B' : '-');
    s[i++] = (flags & VSOCK_MULTICAST ? 'M' : '-');
    s[i++] = '\0';
    return s;
}

/** Create a socket.
 * The flags can include VSOCK_REUSE, VSOCK_BROADCAST, VSOCK_CONNECT.
 *
 * @param socktype socket type
 * @param saddr address
 * @param port port
 * @param flags flags
 * @param val return value for the socket connection
 * @return 0 on success, error code otherwise
 */
int create_socket(int socktype, uint32_t saddr, uint32_t port, int flags, Conn **val){
    int err = 0;
    int sock = 0;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    socklen_t addr_n = sizeof(addr_in);
    Conn *conn = NULL;
    int reuse, bcast;

    //dprintf(">\n");
    reuse = (flags & VSOCK_REUSE);
    bcast = (flags & VSOCK_BROADCAST);
    addr_in.sin_family      = AF_INET;
    addr_in.sin_addr.s_addr = saddr;
    addr_in.sin_port        = port;
    dprintf("> flags=%s addr=%s port=%d\n", socket_flags(flags),
            inet_ntoa(addr_in.sin_addr), ntohs(addr_in.sin_port));

    sock = socket(AF_INET, socktype, 0);
    if(sock < 0){
        err = -errno;
        goto exit;
    }
    if(reuse){
        err = setsock_reuse(sock, reuse);
        if(err < 0) goto exit;
    }
    if(bcast){
        err = setsock_broadcast(sock, bcast);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_MULTICAST){
        err = setsock_multicast(sock, saddr);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_CONNECT){
        err = connect(sock, addr, addr_n);
        if(err < 0){
            err = -errno;
            perror("connect");
            goto exit;
        }
    }
    if(flags & VSOCK_BIND){
        err = bind(sock, addr, addr_n);
        if(err < 0){
            err = -errno;
            perror("bind");
            goto exit;
        }
    }
    conn = Conn_new(NULL, NULL);
    Conn_init(conn, sock, socktype, addr_in);
    {
        struct sockaddr_in self = {};
        socklen_t self_n;
        getsockname(conn->sock, (struct sockaddr *)&self, &self_n);
        dprintf("> sockname sock=%d addr=%s port=%d\n",
                conn->sock, inet_ntoa(self.sin_addr), ntohs(self.sin_port));
    }
  exit:
    *val = (err ? NULL : conn);
    //dprintf("< err=%d\n", err);
    return err;
}

/** Create the tcp listen socket.
 *
 * @param vnetd program arguments
 * @param val return value for the socket
 * @return 0 on success, error code otherwise
 */
int vnetd_listen_conn(Vnetd *vnetd, Conn **val){
    int err = 0;
    int flags = VSOCK_BIND | VSOCK_REUSE;
    //dprintf(">\n");
    err = create_socket(SOCK_STREAM, INADDR_ANY, vnetd->peer_port, flags, val);
    if(err) goto exit;
    err = listen((*val)->sock, 5);
    if(err < 0){
        err = -errno;
        perror("listen");
        goto exit;
    }
  exit:
    if(err && *val){
        Conn_close(*val);
        *val = NULL;
    }
    //dprintf("< err=%d\n", err);
    return err;
}

/** Create the udp socket.
 *
 * @param vnetd program arguments
 * @param val return value for the socket
 * @return 0 on success, error code otherwise
 */
int vnetd_udp_conn(Vnetd *vnetd, Conn **val){
    int err = 0;
    uint32_t addr = INADDR_ANY;
    uint16_t port = vnetd->port;
    int flags = VSOCK_BIND | VSOCK_REUSE;
    err = create_socket(SOCK_DGRAM, addr, port, flags, val);
    return err;
}

/** Create the broadcast socket.
 *
 * @param vnetd program arguments
 * @param val return value for the socket
 * @return 0 on success, error code otherwise
 */
int vnetd_broadcast_conn(Vnetd *vnetd, Conn **val){
    int err = 0;
    uint32_t addr = vnetd_mcast_addr(vnetd);
    uint16_t port = vnetd_mcast_port(vnetd);
    int flags = VSOCK_REUSE;
    int multicast = IN_MULTICAST(ntohl(addr));
    
    flags |= VSOCK_MULTICAST;
    flags |= VSOCK_BROADCAST;

    err = create_socket(SOCK_DGRAM, addr, port, flags, val);
    if(err < 0) goto exit;
    if(multicast){
        err = setsock_multicast_ttl((*val)->sock, 1);
        if(err < 0) goto exit;
    }
    if(0){
        struct sockaddr * addr = (struct sockaddr *)&vnetd->addr;
        socklen_t addr_n = sizeof(vnetd->addr);
        dprintf("> sock=%d bind addr=%s:%d\n",
                (*val)->sock, inet_ntoa(vnetd->addr.sin_addr), ntohs(vnetd->addr.sin_port));
        err = bind((*val)->sock, addr, addr_n);
        if(err < 0){
            err = -errno;
            perror("bind");
            goto exit;
        }
    }
    if(0){
        struct sockaddr_in self = {};
        socklen_t self_n;
        getsockname((*val)->sock, (struct sockaddr *)&self, &self_n);
        dprintf("> sockname sock=%d addr=%s port=%d\n",
                (*val)->sock, inet_ntoa(self.sin_addr), ntohs(self.sin_port));
    }
  exit:
    return err;
}

/** Type for signal handling functions. */
typedef void SignalAction(int code, siginfo_t *info, void *data);

/** Handle SIGCHLD by getting child exit status.
 * This prevents child processes being defunct.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
static void sigaction_SIGCHLD(int code, siginfo_t *info, void *data){
    int status;
    pid_t pid;
    pid = wait(&status);
    dprintf("> child pid=%d status=%d\n", pid, status);
}

/** Handle SIGPIPE.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
static void sigaction_SIGPIPE(int code, siginfo_t *info, void *data){
    dprintf("> SIGPIPE\n");
}

/** Handle SIGALRM.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
static void sigaction_SIGALRM(int code, siginfo_t *info, void *data){
    //dprintf("> SIGALRM\n");
    timer_alarms++;
}

/** Install a handler for a signal.
 *
 * @param signum signal
 * @param action handler
 * @return 0 on success, error code otherwise
 */
static int catch_signal(int signum, SignalAction *action){
    int err = 0;
    struct sigaction sig = {};
    sig.sa_sigaction = action;
    sig.sa_flags = SA_SIGINFO;
    err = sigaction(signum, &sig, NULL);
    if(err){
        perror("sigaction");
    }
    return err;
}    

/** Create a raw socket.
 *
 * @param protocol protocol
 * @param flags flags
 * @param sock return value for the socket
 */
int vnetd_raw_socket(int protocol, int flags, uint32_t mcaddr, int *sock){
    int err;
    int bcast = (flags & VSOCK_BROADCAST);
    //dprintf("> protocol=%d\n", protocol);
    err = *sock = socket(AF_INET, SOCK_RAW, protocol);
    if(err < 0){
        err = -errno;
        perror("socket");
        goto exit;
    }
    if(bcast){
        err = setsock_broadcast(*sock, bcast);
        if(err < 0) goto exit;
    }
    if(flags & VSOCK_MULTICAST){
        err = setsock_multicast(*sock, mcaddr);
        if(err < 0) goto exit;
    }
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Connect to peer vnetds.
 *
 * @param vnetd vnetd
 * @return 0 on success, error code otherwise
 */
int vnetd_peers(Vnetd *vnetd){
    int err =0;
    Sxpr x, l;
    struct in_addr addr = {};
    for(l = vnetd->peers; CONSP(l); l = CDR(l)){
        x = CAR(l);
        addr.s_addr = OBJ_INT(x);
        vnetd_connect(vnetd, addr, vnetd->peer_port);
    }
    return err;
}

/** Vnet daemon main program.
 *
 * @param vnetd program arguments
 * @return 0 on success, error code otherwise
 */
int vnetd_main(Vnetd *vnetd){
    int err = 0;

    //dprintf(">\n");
    err = get_self_addr(&vnetd->addr);
    vnetd->addr.sin_port = vnetd->port;
    iprintf("> VNETD\n");
    iprintf("> addr=%s port=%u\n",
            inet_ntoa(vnetd->addr.sin_addr), htons(vnetd->port));
    iprintf("> mcaddr=%s port=%u\n",
            inet_ntoa(vnetd->mcast_addr.sin_addr), htons(vnetd->port));
    iprintf("> peers port=%u ", htons(vnetd->peer_port));
    objprint(iostdout, vnetd->peers, 0); printf("\n");
    
    err = vcache_init();
    err = vnetd_peers(vnetd);

    catch_signal(SIGCHLD,sigaction_SIGCHLD);
    catch_signal(SIGPIPE,sigaction_SIGPIPE);
    catch_signal(SIGALRM,sigaction_SIGALRM); 
    err  = vnetd_listen_conn(vnetd, &vnetd->listen_conn);
    if(err < 0) goto exit;
    err = vnetd_udp_conn(vnetd, &vnetd->udp_conn);
    if(err < 0) goto exit;
    err = vnetd_broadcast_conn(vnetd, &vnetd->bcast_conn);
    if(err < 0) goto exit;
    { 
        int flags = VSOCK_BROADCAST | VSOCK_MULTICAST;
        uint32_t mcaddr = vnetd->mcast_addr.sin_addr.s_addr;

        err = vnetd_raw_socket(IPPROTO_ETHERIP, flags, mcaddr, &vnetd->etherip_sock);
        if(err < 0) goto exit;
        err = vnetd_raw_socket(IPPROTO_ESP, flags, mcaddr, &vnetd->esp_sock);
        if(err < 0) goto exit;
    }
    err = vnetd_select(vnetd);
  exit:
    Conn_close(vnetd->listen_conn);
    Conn_close(vnetd->udp_conn);
    Conn_close(vnetd->bcast_conn);
    connections_close_all(vnetd);
    close(vnetd->etherip_sock);
    close(vnetd->esp_sock);
    //dprintf("< err=%d\n", err);
    return err;
}

/** Parse command-line arguments and call the vnetd main program.
 *
 * @param arg argument count
 * @param argv arguments
 * @return 0 on success, 1 otherwise
 */
extern int main(int argc, char *argv[]){
    int err = 0;
    int key = 0;
    int long_index = 0;

    vnetd_set_defaults(vnetd);
    while(1){
	key = getopt_long(argc, argv, short_opts, long_opts, &long_index);
	if(key == -1) break;
	switch(key){
        case OPT_ADDR:{
            unsigned long addr;
            err = get_host_address(optarg, &addr);
            if(err) goto exit;
            vnetd->mcast_addr.sin_addr.s_addr = addr;
            break; }
        case OPT_PORT:
            err = convert_service_to_port(optarg, &vnetd->port);
            if(err) goto exit;
            break;
        case OPT_PEER:{
            unsigned long addr;
            err = get_host_address(optarg, &addr);
            if(err) goto exit;
            //cons_push(&vnetd->peers, mkaddress(addr));
            cons_push(&vnetd->peers, mkint(addr));
            break; }
	case OPT_HELP:
	    usage(0);
	    break;
	case OPT_VERBOSE:
	    vnetd->verbose = TRUE;
	    break;
	case OPT_VERSION:
            iprintf("> %s %s\n", PROGRAM, VERSION);
            exit(0);
	    break;
	default:
	    usage(EINVAL);
	    break;
	}
    }
    err = vnetd_main(vnetd);
  exit:
    if(err && key > 0){
        eprintf("> Error in arg %c\n", key);
    }
    return (err ? 1 : 0);
}
