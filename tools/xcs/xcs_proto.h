/* xcs_proto.h
 *
 * protocol interfaces for the control interface switch (xcs).
 *
 * (c) 2004, Andrew Warfield
 *
 */

#ifndef  __XCS_PROTO_H__
#define  __XCS_PROTO_H__

#define XCS_SUN_PATH     "/var/xen/xcs_socket"

/* xcs message types: */
#define XCS_CONNECT_CTRL       0 /* This is a control connection.     */
#define XCS_CONNECT_DATA       1 /* This is a data connection.        */
#define XCS_CONNECT_BYE        2 /* Terminate a session.              */
#define XCS_MSG_BIND           3 /* Register for a message type.      */
#define XCS_MSG_UNBIND         4 /* Unregister for a message type.    */
#define XCS_VIRQ_BIND          5 /* Register for a virq.              */
#define XCS_MSG_WRITELOCK      6 /* Writelock a (dom,type) pair.      */
#define XCS_CIF_NEW_CC         7 /* Create a new control channel.     */
#define XCS_CIF_FREE_CC        8 /* Create a new control channel.     */
#define XCS_REQUEST            9 /* This is a request message.        */
#define XCS_RESPONSE          10 /* this is a response Message.       */
#define XCS_VIRQ              11 /* this is a virq notification.      */

/* xcs result values: */
#define XCS_RSLT_OK            0
#define XCS_RSLT_FAILED        1 /* something bad happened.           */
#define XCS_RSLT_ARECONNECTED  2 /* attempt to over connect.          */
#define XCS_RSLT_BADSESSION    3 /* request for unknown session id.   */
#define XCS_RSLT_NOSESSION     4 /* tried to do something before NEW. */
#define XCS_RSLT_CONINUSE      5 /* Requested connection is taken.    */
#define XCS_RSLT_BADREQUEST    6 /* Request message didn't validate.  */

/* Binding wildcards */
#define PORT_WILDCARD  0xefffffff
#define TYPE_WILDCARD  0xffff
#define TYPE_VIRQ      0xfffe

typedef struct {
    u32 session_id;
} xcs_connect_msg_t;

typedef struct {
    int port;
    u16 type;  
} xcs_bind_msg_t;

typedef struct {
    int port;
    u16 virq;  
} xcs_virq_msg_t;

typedef struct {
    u32 dom;
    int local_port;
    int remote_port;
} xcs_interface_msg_t;

typedef struct {
    u32           remote_dom;
    int           local_port;
    control_msg_t msg;
} xcs_control_msg_t;

typedef struct {
    u32 type;
    u32 result;
    union {
        xcs_connect_msg_t   connect;   /* These are xcs ctrl message types */
        xcs_bind_msg_t      bind;
        xcs_virq_msg_t      virq;
        xcs_interface_msg_t interface;
        
        xcs_control_msg_t   control;   /* These are xcs data message types */
    } PACKED u;
} xcs_msg_t;

/* message validation macros. */
#define PORT_VALID(_p)                                                 \
    ( (((_p) >= 0) && ((_p) < NR_EVENT_CHANNELS))                      \
    || ((_p) == PORT_WILDCARD) )

#define TYPE_VALID(_t)                                                 \
    (  ((_t) < 256)                                                    \
    || ((_t) == TYPE_VIRQ)                                             \
    || ((_t) == TYPE_WILDCARD) )

#define BIND_MSG_VALID(_b)                                             \
    ( PORT_VALID((_b)->port) && TYPE_VALID((_b)->type) )
    
/* Port is overwritten, and we don't currently validate the requested virq. */
#define VIRQ_MSG_VALID(_v) ( 1 )
    
/* Interfaces may return with ports of -1, but may not be requested as such */
#define INTERFACE_MSG_VALID(_i)                                        \
    ( PORT_VALID((_i)->local_port) && PORT_VALID((_i)->remote_port) )

#endif /* __XCS_PROTO_H__ */
