/* xcs.c 
 *
 * xcs - Xen Control Switch
 *
 * Copyright (c) 2004, Andrew Warfield
 */
 
/*

  Things we need to select on in xcs:
  
  1. Events arriving on /dev/evtchn
  
    These will kick a function to read everything off the fd, and scan the
    associated control message rings, resulting in notifications sent on
    data channels to connected clients.
    
  2. New TCP connections on XCS_PORT.
  
    These will either be control (intially) or associated data connections.
    
    Control connections will instantiate or rebind to an existing connnection
    struct.  The control channel is used to configure what events will be 
    received on an associated data channel.  These two channels are split
    out because the control channel is synchronous, all messages will return
    a result from XCS.  The data channel is effectively asynchronous, events
    may arrive in the middle of a control message exchange.  Additionally, 
    Having two TCP connections allows the client side to have a blocking
    listen loop for data messages, while independently interacting on the 
    control channel at other places in the code.
    
    Data connections attach to an existing control struct, using a session
    id that is passed during the control connect.  There is currently a 
    one-to-one relationship between data and control channels, but there
    could just as easily be many data channels, if there were a set of 
    clients with identical interests, or if you wanted to trace an existing
    client's data traffic.
    
 3. Messages arriving on open TCP connections.
    There are three types of open connections:
     
    3a. Messages arriving on open control channel file descriptors.
 
        [description of the control protocol here]
 
    3b. Messages arriving on open data channel file descriptors.
 
        [description of the data protocol here]
        
    3c. Messages arriving on (new) unbound connections.
    
        A connection must issue a XCS_CONNECT message to specify what
        it is, after which the connection is moved into one of the above 
        two groups.
 
 Additionally, we need a periodic timer to do housekeeping.
 
 4. Every XCS_GC_INTERVAL seconds, we need to clean up outstanding state. 
    Specifically, we garbage collect any sessions (connection_t structs)
    that have been unconnected for a period of time (XCS_SESSION_TIMEOUT), 
    and close any connections that have been openned, but not connected
    as a control or data connection (XCS_UFD_TIMEOUT).

*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include "xcs.h"

#undef fd_max
#define fd_max(x,y) ((x) > (y) ? (x) : (y))

/* ------[ Control channel interfaces ]------------------------------------*/

static control_channel_t *cc_list[NR_EVENT_CHANNELS];
static int *dom_port_map = 0;
static int dom_port_map_size = 0;

static void map_dom_to_port(u32 dom, int port)
{
    if (dom >= dom_port_map_size) {
        dom_port_map = (int *)realloc(dom_port_map,
                                      (dom + 256) * sizeof(dom_port_map[0]));

        if (dom_port_map == NULL) {
            perror("realloc(dom_port_map)");
            exit(1);
        }

        for (; dom_port_map_size < dom + 10; dom_port_map_size++) {
            dom_port_map[dom_port_map_size] = -1;
        }
    }

    dom_port_map[dom] = port;
}

static int dom_to_port(u32 dom) 
{
    if (dom >= dom_port_map_size) return -1;

    return dom_port_map[dom];
}

static void init_interfaces(void)
{
    memset(cc_list, 0, sizeof cc_list);
}

static control_channel_t *add_interface(u32 dom, int local_port, 
                                        int remote_port)
{
    control_channel_t *cc=NULL, *oldcc;
    int ret;
    
    if (cc_list[dom_to_port(dom)] != NULL)
    {
        return(cc_list[dom_to_port(dom)]);
    }
    
    if (cc_list[local_port] == NULL) 
    {
        cc = ctrl_chan_new(dom, local_port, remote_port);
    }
    
    if (cc == NULL)
        return NULL;
    
    DPRINTF("added a new interface: dom: %u (l:%d,r:%d): %p\n",
            dom, local_port, remote_port, cc);
    DPRINTF("added a new interface: dom: %u (l:%d,r:%d): %p\n",
            dom, cc->local_port, cc->remote_port, cc);
    
    if ((ret = evtchn_bind(cc->local_port)) != 0)
    {
        DPRINTF("Got control interface, but couldn't bind evtchan!(%d)\n", ret);
        ctrl_chan_free(cc);
        return NULL;
    }
    
    if ( cc_list[cc->local_port] != NULL )
    {
        oldcc = cc_list[cc->local_port];
        
        if ((oldcc->remote_dom != cc->remote_dom) ||
            (oldcc->remote_port != cc->remote_port))
        {
            DPRINTF("CC conflict! (port: %d, old dom: %u, new dom: %u)\n",
                    cc->local_port, oldcc->remote_dom, cc->remote_dom);
            map_dom_to_port(oldcc->remote_dom, -1);
            ctrl_chan_free(cc_list[cc->local_port]);
        }
    }
     
    cc_list[cc->local_port] = cc;
    map_dom_to_port(cc->remote_dom, cc->local_port);
    cc->type = CC_TYPE_INTERDOMAIN;
    cc->ref_count = 0;
    return cc;
}

control_channel_t *add_virq(int virq)
{
    control_channel_t *cc;
    int virq_port;
    
    if (ctrl_chan_bind_virq(virq, &virq_port) == -1)
        return NULL;
    
    if ((cc_list[virq_port]       != NULL) && 
        (cc_list[virq_port]->type != CC_TYPE_VIRQ))
        return NULL; 
    
    if ((cc_list[virq_port]       != NULL) && 
        (cc_list[virq_port]->type == CC_TYPE_VIRQ))
        return cc_list[virq_port]; 
    
    cc = (control_channel_t *)malloc(sizeof(control_channel_t));
    if ( cc == NULL ) return NULL;

    cc->type       = CC_TYPE_VIRQ;
    cc->local_port = virq_port;
    cc->virq       = virq;
    
    return cc;
}

void get_interface(control_channel_t *cc)
{
    if (cc != NULL)
        cc->ref_count++;
}
    
void put_interface(control_channel_t *cc)
{
    if (cc != NULL)
    {
        cc->ref_count--;
        if (cc->ref_count <= 0)
        {
            DPRINTF("Freeing cc on port %d.\n", cc->local_port);
            (void)evtchn_unbind(cc->local_port);
            ctrl_chan_free(cc);
        }
    }
}

/* ------[ Simple helpers ]------------------------------------------------*/

/* listen_socket() is straight from paul sheer's useful select_tut manpage. */
static int listen_socket (char *listen_path) 
{
    struct sockaddr_un a;
    int s;
    int yes;

    if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) 
    {
        perror ("socket");
        return -1;
    }
    
    yes = 1;

    memset (&a, 0, sizeof (a));
    a.sun_family = AF_UNIX;
    strcpy(a.sun_path, listen_path);

    /* remove an old socket if it exists. */
    unlink(listen_path);

    if (bind(s, (struct sockaddr *) &a, sizeof (a)) < 0) 
    {
        fprintf (stderr, "bind('%s'): %s\n", listen_path, strerror(errno));
        close (s);
        return -1;
    }
    printf ("accepting connections on path %s\n", listen_path);
    listen (s, 10);
    return s;
}

/* ------[ Message handlers ]----------------------------------------------*/

#define NO_CHANGE     0
#define CONNECTED     1
#define DISCONNECTED  2
int handle_connect_msg( xcs_msg_t *msg, int fd )
{
    xcs_connect_msg_t *cmsg = &msg->u.connect;
    connection_t *con;
    int ret = NO_CHANGE;
    
    switch (msg->type)
    {
        case XCS_CONNECT_CTRL:
        {
            if ( cmsg->session_id == 0 )
            {
                con = connection_new();
                if ( con == NULL)
                {
                    msg->result = XCS_RSLT_FAILED;
                    break;
                }
                msg->result      = XCS_RSLT_OK;
                cmsg->session_id = con->id;
                con->ctrl_fd     = fd;
                ret = CONNECTED;
                DPRINTF("New control connection\n");
                break;
            }

            con = get_con_by_session(cmsg->session_id);
            if ( con == NULL )
            {
                msg->result = XCS_RSLT_BADSESSION;
                break;
            }
            if ( con->ctrl_fd != -1 )
            {
                msg->result = XCS_RSLT_CONINUSE;
                break;
            }
            con->ctrl_fd   = fd;
            msg->result   = XCS_RSLT_OK;
            ret = CONNECTED;
            DPRINTF("Rebound to control connection\n");
            break;
        }
        case XCS_CONNECT_DATA:
        {
            con = get_con_by_session(cmsg->session_id);
            if ( con == NULL )
            {
                msg->result = XCS_RSLT_BADSESSION;
                break;
            }
            if ( con->data_fd != -1 )
            {
                msg->result = XCS_RSLT_CONINUSE;
                break;
            }
            con->data_fd   = fd;
            msg->result   = XCS_RSLT_OK;
            ret = CONNECTED;
            DPRINTF("Attached data connection\n");
            break;

        }
        case XCS_CONNECT_BYE:
        {
            close ( fd );
            ret = DISCONNECTED;
            break;
        }
    }   
    
    return ret;
}

int handle_control_message( connection_t *con, xcs_msg_t *msg )
{
    int ret;
    int reply_needed = 1;
            
    DPRINTF("Got message, type %u.\n", msg->type);

    switch (msg->type)
    {
        case XCS_MSG_BIND:
        {
            xcs_bind_msg_t *bmsg = &msg->u.bind;

            if ( ! BIND_MSG_VALID(bmsg) )
            {
                msg->result = XCS_RSLT_BADREQUEST;
                break;
            }
            
            ret = xcs_bind(con, bmsg->port, bmsg->type);
            if (ret == 0) {
                msg->result = XCS_RSLT_OK;
            } else {
                msg->result = XCS_RSLT_FAILED;
            }
            break;
        }
        case XCS_MSG_UNBIND:
        {
            xcs_bind_msg_t *bmsg = &msg->u.bind;

            if ( ! BIND_MSG_VALID(bmsg) )
            {
                msg->result = XCS_RSLT_BADREQUEST;
                break;
            }
            
            ret = xcs_unbind(con, bmsg->port, bmsg->type);
            if (ret == 0) {
                msg->result = XCS_RSLT_OK;
            } else {
                msg->result = XCS_RSLT_FAILED;
            }
            break;
        }    
        case XCS_VIRQ_BIND:
        {
            control_channel_t *cc;
            xcs_virq_msg_t *vmsg = &msg->u.virq;
            if ( ! VIRQ_MSG_VALID(vmsg) )
            {
                msg->result = XCS_RSLT_BADREQUEST;
                break;
            }

            cc = add_virq(vmsg->virq);
            if (cc == NULL)
            {
                msg->result = XCS_RSLT_FAILED;
                break;
            }
            ret = xcs_bind(con, cc->local_port, TYPE_VIRQ);
            if (ret == 0) {
                vmsg->port   = cc->local_port;
                msg->result  = XCS_RSLT_OK;
            } else {
                msg->result = XCS_RSLT_FAILED;
            }
            break;
        }

        case XCS_CIF_NEW_CC:
        {
            control_channel_t *cc;
            xcs_interface_msg_t *imsg = &msg->u.interface;

            if ( ! INTERFACE_MSG_VALID(imsg) )
            {
                msg->result = XCS_RSLT_BADREQUEST;
                break;
            }

            cc = add_interface(imsg->dom, imsg->local_port, imsg->remote_port);
            if (cc != NULL) {
                get_interface(cc);
                msg->result       = XCS_RSLT_OK;
                imsg->local_port  = cc->local_port;
                imsg->remote_port = cc->remote_port;
            } else {
                msg->result = XCS_RSLT_FAILED;
            }
            break;
        }

        case XCS_CIF_FREE_CC:
        {
            control_channel_t *cc;
            xcs_interface_msg_t *imsg = &msg->u.interface;

            if ( ! INTERFACE_MSG_VALID(imsg) )
            {
                msg->result = XCS_RSLT_BADREQUEST;
                break;
            }

            cc = add_interface(imsg->dom, imsg->local_port, imsg->remote_port);
            if (cc != NULL) {
                put_interface(cc);
            } 
            msg->result       = XCS_RSLT_OK;
            break;
        }
    }
    return reply_needed;
}

void handle_data_message( connection_t *con, xcs_msg_t *msg )
{
    control_channel_t *cc;
    xcs_control_msg_t *cmsg = &msg->u.control;
    int port;
    
    switch (msg->type)
    {
    case XCS_REQUEST:
        if ( cmsg->remote_dom > MAX_DOMS )
            break;
        
        port = dom_to_port(cmsg->remote_dom);
        if (port == -1) break;
        cc = cc_list[port];
        if ((cc != NULL) && ( cc->type == CC_TYPE_INTERDOMAIN ))
        {
            DPRINTF("DN:REQ: dom:%d port: %d type: %d\n", 
                    cc->remote_dom, cc->local_port, 
                    cmsg->msg.type);
            ctrl_chan_write_request(cc, cmsg);
            ctrl_chan_notify(cc);
        } else {
            DPRINTF("tried to send a REQ to a null cc\n.");
        }
        break;

    case XCS_RESPONSE:
        if ( cmsg->remote_dom > MAX_DOMS )
            break;
        
        port = dom_to_port(cmsg->remote_dom);
        if (port == -1) break;
        cc = cc_list[port];
        if ((cc != NULL) && ( cc->type == CC_TYPE_INTERDOMAIN ))
        {
            DPRINTF("DN:RSP: dom:%d port: %d type: %d\n", 
                    cc->remote_dom, cc->local_port, 
                    cmsg->msg.type);
            ctrl_chan_write_response(cc, cmsg);
            ctrl_chan_notify(cc);
        }
        break;

    case XCS_VIRQ:
        if ( !(PORT_VALID(cmsg->local_port)) )
            break;
            
        cc = cc_list[cmsg->local_port];
        
        if ((cc != NULL) && ( cc->type == CC_TYPE_VIRQ ))
        {
            DPRINTF("DN:VIRQ:  virq: %d port: %d\n", 
                    cc->virq, cc->local_port);
            ctrl_chan_notify(cc);
        }
        break;
    }
}
    
/* ------[ Control interface handler ]-------------------------------------*/

/* passed as a function pointer to the lookup. */
void send_kmsg(connection_t *c, void *arg)
{
    xcs_msg_t *msg = (xcs_msg_t *)arg;

    DPRINTF("       -> CONNECTION %d\n", c->data_fd);
    if (c->data_fd > 0)
    {
      send(c->data_fd, msg, sizeof(xcs_msg_t), 0);
    }
}

int handle_ctrl_if(void)
{
    control_channel_t *cc;
    control_msg_t     *msg;
    xcs_msg_t          kmsg;
    int                chan, ret;
    
    DPRINTF("Event thread kicked!\n");
again:
    while ((chan = evtchn_read()) > 0)
    {
        evtchn_unmask(chan);
        cc = cc_list[chan];
        if (cc_list[chan] == NULL) {
            DPRINTF("event from unknown channel (%d)\n", chan);
            continue;
        }

        if ( cc_list[chan]->type == CC_TYPE_VIRQ )
        {
            DPRINTF("UP:VIRQ: virq:%d port: %d\n",
                    cc->virq, cc->local_port);
            kmsg.type = XCS_VIRQ;
            kmsg.u.control.local_port = cc->local_port;
            xcs_lookup(cc->local_port, TYPE_VIRQ, send_kmsg, &kmsg);
            continue;
        }

        while (ctrl_chan_request_to_read(cc))
        {
            msg = &kmsg.u.control.msg;
            kmsg.type = XCS_REQUEST;
            kmsg.u.control.remote_dom = cc->remote_dom;
            kmsg.u.control.local_port = cc->local_port;
            ret = ctrl_chan_read_request(cc, &kmsg.u.control);
            DPRINTF("UP:REQ: dom:%d port: %d type: %d len: %d\n", 
                    cc->remote_dom, cc->local_port, 
                    msg->type, msg->length);
            if (ret == 0)
                xcs_lookup(cc->local_port, msg->type, send_kmsg, &kmsg);
        }

        while (ctrl_chan_response_to_read(cc))
        {
            msg = &kmsg.u.control.msg;
            kmsg.type = XCS_RESPONSE;
            kmsg.u.control.remote_dom = cc->remote_dom;
            kmsg.u.control.local_port = cc->local_port;
            ret = ctrl_chan_read_response(cc, &kmsg.u.control);
            DPRINTF("UP:RSP: dom:%d port: %d type: %d len: %d\n", 
                    cc->remote_dom, cc->local_port, 
                    msg->type, msg->length);
            if (ret == 0)
                xcs_lookup(cc->local_port, msg->type, send_kmsg, &kmsg);
        }
    }
    
    if (chan == -EINTR)
        goto again;
    
    return chan;
}

  
/* ------[ Main xcs code / big select loop ]-------------------------------*/

                
typedef struct unbound_fd_st {
    int                   fd;
    struct timeval        born;
    struct unbound_fd_st *next;
} unbound_fd_t;

/* This makes ufd point to the next entry in the list, so need to   *
 * break/continue if called while iterating.                        */
void delete_ufd(unbound_fd_t **ufd)
{
    unbound_fd_t *del_ufd;
    
    del_ufd = *ufd;
    *ufd    = (*ufd)->next;
    free( del_ufd );
}

void gc_ufd_list( unbound_fd_t **ufd )
{
    struct timeval now, delta;
    
    gettimeofday(&now, NULL);
    
    while ( *ufd != NULL )
    {
        timersub(&now, &(*ufd)->born, &delta);
        if (delta.tv_sec > XCS_UFD_TIMEOUT)
        {
            DPRINTF("GC-UFD: closing fd: %d\n", (*ufd)->fd);
            close((*ufd)->fd);
            delete_ufd(ufd);
            continue;
        }
        ufd = &(*ufd)->next;
    }
}

int main (int argc, char *argv[])
{
    int listen_fd, evtchn_fd;
    unbound_fd_t *unbound_fd_list = NULL, **ufd;
    struct timeval timeout = { XCS_GC_INTERVAL, 0 };
    connection_t **con;

    /* Initialize xc and event connections. */
    if (ctrl_chan_init() != 0)
    {
        printf("Couldn't open conneciton to libxc.\n");
        exit(-1);
    }
    
    if ((evtchn_fd = evtchn_open()) < 0)
    {
        printf("Couldn't open event channel driver interface.\n");
        exit(-1);
    }
   
    /* Initialize control interfaces, bindings. */
    init_interfaces();
    init_bindings();
    
    listen_fd = listen_socket(XCS_SUN_PATH);
   
    /* detach from our controlling tty so that a shell does hang waiting for
       stopped jobs. */
    /* we should use getopt() here */

    if (!(argc == 2 && !strcmp(argv[1], "-i"))) {
	pid_t pid = fork();
	int fd;

	if (pid == -1) {
		perror("fork()");
	} else if (pid) {
		exit(0);
	}

    	setsid();
	close(2);
	close(1);
	close(0);
	fd = open("/dev/null", O_RDWR);
	dup(fd);
	dup(fd);
    }
 
    for (;;)
    {
        int n = 0, ret;
        fd_set rd, wr, er;
        FD_ZERO ( &rd );
        FD_ZERO ( &wr );
        FD_ZERO ( &er );
        
        /* TCP listen fd: */
        FD_SET ( listen_fd, &rd );
        n = fd_max ( n, listen_fd );
        
        /* Evtchn fd: */
        FD_SET ( evtchn_fd, &rd );
        n = fd_max ( n, evtchn_fd );
        
        /* unbound connection fds: */
        ufd = &unbound_fd_list;
        while ((*ufd) != NULL) 
        {
            FD_SET ( (*ufd)->fd, &rd );
            n = fd_max ( n, (*ufd)->fd );
            ufd = &(*ufd)->next;
        }
        
        /* control and data fds: */
        con = &connection_list;
        while ((*con) != NULL)
        {
            if ((*con)->ctrl_fd > 0)
            {
                FD_SET ( (*con)->ctrl_fd, &rd );
                n = fd_max ( n, (*con)->ctrl_fd );
            }
            if ((*con)->data_fd > 0)
            {
                FD_SET ( (*con)->data_fd, &rd );
                n = fd_max ( n, (*con)->data_fd );
            }
            con = &(*con)->next;
        }
        
        ret = select ( n + 1, &rd, &wr, &er, &timeout );
        
        if ( (timeout.tv_sec == 0) && (timeout.tv_usec == 0) )
        {
            gc_ufd_list(&unbound_fd_list);
            gc_connection_list();
            timeout.tv_sec = XCS_GC_INTERVAL;
        }
        
        if ( (ret == -1) && (errno == EINTR) )
            continue;
        if ( ret < 0 )
        {
            perror ("select()");
            exit(-1);
        }
        
        /* CASE 1: Events arriving on /dev/evtchn. */
        
        if ( FD_ISSET (evtchn_fd, &rd ))
            handle_ctrl_if();
        
        /* CASE 2: New connection on the listen port. */
        if ( FD_ISSET ( listen_fd, &rd ))
        {
            struct sockaddr_un remote_addr;
            int size;
            memset (&remote_addr, 0, sizeof (remote_addr));
            size = sizeof remote_addr;
            ret = accept(listen_fd, (struct sockaddr *)&remote_addr, &size);
            if ( ret < 0 )
            {
                perror("accept()");
            } else {
                unbound_fd_t *new_ufd;
                
                new_ufd = (unbound_fd_t *)malloc(sizeof(*new_ufd));
                
                if (new_ufd != NULL)
                {
                    gettimeofday(&new_ufd->born, NULL);
                    new_ufd->fd     = ret;
                    new_ufd->next   = unbound_fd_list;
                    unbound_fd_list = new_ufd; 
                } else {
                    perror("malloc unbound connection");
                    close(ret);
                }
            }
        }
        
        /* CASE 3a: Handle messages on control connections. */
        
        con = &connection_list;
        while ( *con != NULL )
        {
            if ( ((*con)->ctrl_fd > 0) && (FD_ISSET((*con)->ctrl_fd, &rd)) )
            {
                xcs_msg_t msg;
                memset (&msg, 0, sizeof(msg));
                ret = read( (*con)->ctrl_fd, &msg, sizeof(msg) );
                
                if ( ret < 0 )
                {
                    perror("reading ctrl fd.");
                } else if ( ret == 0 )
                {
                    DPRINTF("Control connection dropped.\n");
                    close ( (*con)->ctrl_fd );
                    (*con)->ctrl_fd = -1;
                    gettimeofday(&(*con)->disconnect_time, NULL);
                } else 
                {
                    if ( ret != sizeof(msg) )
                    {
                        DPRINTF("Unexpected frame size!\n");
                        continue;
                    }
                    
                    ret = handle_control_message( *con, &msg );
                    
                    if ( ret == 1 )
                        send( (*con)->ctrl_fd, &msg, sizeof(msg), 0 );
                }
            }
            con = &(*con)->next;
        }
        
        /* CASE 3b: Handle messages on data connections. */
        
        con = &connection_list;
        while ( *con != NULL )
        {
            if ( ((*con)->data_fd > 0) && (FD_ISSET((*con)->data_fd, &rd)) )
            {
                xcs_msg_t msg;
                memset (&msg, 0, sizeof(msg));
                ret = read( (*con)->data_fd, &msg, sizeof(msg) );
                
                if ( ret < 0 )
                {
                    perror("reading data fd.");
                } else if ( ret == 0 )
                {
                    DPRINTF("Data connection dropped.\n");
                    close ( (*con)->data_fd );
                    (*con)->data_fd = -1;
                    gettimeofday(&(*con)->disconnect_time, NULL);
                } else 
                {
                    if ( ret != sizeof(msg) )
                    {
                        DPRINTF("Unexpected frame size!\n");
                        continue;
                    }
                    
                    handle_data_message( *con, &msg );
                }
            }
            con = &(*con)->next;
        }
        
        /* CASE 3c: Handle messages arriving on unbound connections. */
        ufd = &unbound_fd_list;
        while ((*ufd) != NULL)
        {
            if ( FD_ISSET( (*ufd)->fd, &rd ) )
            {
                xcs_msg_t msg;
                memset (&msg, 0, sizeof(msg));
                ret = read( (*ufd)->fd, &msg, sizeof(msg) );
                
                if ( ret == 0 )
                {
                    close ( (*ufd)->fd );
                    delete_ufd(ufd);
                    continue; /* we just advanced ufd */
                } else {
                    if ( ret != sizeof(msg) )
                    {
                        DPRINTF("Unexpected frame size!\n");
                        continue;
                    }
                    
                    ret = handle_connect_msg( &msg, (*ufd)->fd );
                    
                    if ( (ret == CONNECTED) || (ret == NO_CHANGE) )
                        send( (*ufd)->fd, &msg, sizeof(msg), 0 );
                    
                    if ( (ret = CONNECTED) || (ret = DISCONNECTED) )
                    {
                        delete_ufd( ufd );
                        continue;
                    }
                }
            }
            ufd = &(*ufd)->next;
        }
    }
}

