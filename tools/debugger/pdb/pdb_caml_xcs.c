/*
 * xcs stuff
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * this is responsible for establishing the initial connection
 * between a backend domain and the pdb server.
 *
 * liberated from xu.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <xenctrl.h>

#include <xen/xen.h>
#include <xen/io/domain_controller.h>

#include <arpa/inet.h>
#include <xcs_proto.h>

#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

static int control_fd = -1;

#include "pdb_module.h"
#include "pdb_caml_xen.h"

void *map_ring(uint32_t dom, unsigned long mfn );

/*
 * xcs_initialize_ring : int -> int32 -> int32
 *
 * initialize a communications ring
 * (probably belongs in a different file :)
 */

value
xcs_initialize_ring (value domain, value ring)
{
    CAMLparam2(domain, ring);
    int my_domain = Int_val(domain);
    unsigned long my_ring = Int32_val(ring);

    pdb_front_ring_t *front_ring;
    pdb_sring_t *sring;

    front_ring = (pdb_front_ring_t *)malloc(sizeof(pdb_front_ring_t));
    if ( front_ring == NULL )
    {
        printf("(pdb) xcs initialize ring: malloc failed.\n");  fflush(stdout);
        failwith("xcs initialize ring: malloc");
    }

    sring = map_ring(my_domain, my_ring);
    if ( sring == NULL )
    {
        printf("(pdb) xcs initialize ring: map ring failed.\n");fflush(stdout);
        failwith("xcs initialize ring: map ring");
    }
    FRONT_RING_INIT(front_ring, sring, PAGE_SIZE);

    CAMLreturn(caml_copy_int32((unsigned long)front_ring));
}


/*
 * xcs_write_message : Unix.file_descr -> xcs_message -> unit
 *
 * ack a packet
 */
value
xcs_write_message (value data_fd, value msg)
{
    CAMLparam2(data_fd, msg);
    int my_data_fd = Int_val(data_fd);
    xcs_msg_t my_msg;
    pdb_connection_p conn;

    my_msg.type = XCS_REQUEST;
    my_msg.u.control.remote_dom = Int_val(Field(msg,0));
    my_msg.u.control.msg.type = CMSG_DEBUG;
    my_msg.u.control.msg.subtype = CMSG_DEBUG_CONNECTION_STATUS;
    my_msg.u.control.msg.id = 0;
    my_msg.u.control.msg.length = sizeof(pdb_connection_t);

    conn = (pdb_connection_p)my_msg.u.control.msg.msg;

    conn->status = Int_val(Field(msg,1));
    conn->ring = Int32_val(Field(msg,2));
    conn->evtchn = Int_val(Field(msg,3));
        
    send(my_data_fd, &my_msg, sizeof(xcs_msg_t), 0);                  /* ack */

    CAMLreturn(Val_unit);
}

/*
 * xcs_read_message : Unix.file_descr -> xcs_message
 *
 * read pending data on xcs socket.
 */

value
xcs_read_message (value data_fd)
{
    CAMLparam1(data_fd);
    CAMLlocal1(result);
    int my_data_fd = Int_val(data_fd);
    xcs_msg_t msg;

    if ( read(my_data_fd, &msg, sizeof(xcs_msg_t)) < 0 )
    {
        perror("read");
        failwith("xcs message: read");
    }

    switch (msg.type)
    {
    case XCS_REQUEST :
    {
        pdb_connection_p conn;

        if ( msg.u.control.msg.type != CMSG_DEBUG ||
             msg.u.control.msg.subtype != CMSG_DEBUG_CONNECTION_STATUS )
        {
            printf("bogus message type: %d %d\n", 
                   msg.u.control.msg.type, msg.u.control.msg.subtype);
            failwith("xcs message: invalid message type");
        }

        conn = (pdb_connection_p) msg.u.control.msg.msg;
        
        result = caml_alloc_tuple(4);                               /* FIXME */
        Store_field(result, 0, Val_int(msg.u.control.remote_dom)); /* domain */
        Store_field(result, 1, Val_int(conn->status));             /* status */
        Store_field(result, 2, caml_copy_int32(conn->ring));         /* ring */
        Store_field(result, 3, Val_int(0));                   /* OUT: evtchn */

        break;
    }
    case XCS_RESPONSE :
    {
        printf("[XCS RESPONSE]  type: %d, remote_dom: %d\n", 
               msg.type, msg.u.control.remote_dom);
        printf("strange.  we never initiate messages, so what is the ");
        printf("domain responding to?\n");
        failwith ("xcs message: resonse");
        break;
    }
    default:
    {
        printf("[XCS IGNORE] type: %d\n", msg.type);
        failwith ("xcs message: unknown");
        break;
    }
    }

    CAMLreturn(result);
}

/*
 * xcs_connect : string -> int -> Unix.file_descr
 */

value
xcs_connect (value path, value msg_type)
{
    CAMLparam2(path, msg_type);
    char *my_path = String_val(path);
    int my_msg_type = Int_val(msg_type);
    struct sockaddr_un addr;
    uint32_t session_id = 0;
    int data_fd;
    int ret, len;
    xcs_msg_t msg;

    /* setup control channel connection to xcs */

    control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( control_fd < 0 )
    {
        printf("error creating xcs socket!\n");
        goto fail;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, my_path);
    len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;

    ret = connect(control_fd, (struct sockaddr *)&addr, len);
    if (ret < 0) 
    {
        printf("error connecting to xcs (ctrl)! (%d)\n", errno);
        goto ctrl_fd_fail;
    }
            
    msg.type = XCS_CONNECT_CTRL;
    msg.u.connect.session_id = session_id;
    send(control_fd, &msg, sizeof(xcs_msg_t), 0);
    /* bug: this should have a timeout & error! */
    read(control_fd, &msg, sizeof(xcs_msg_t));
    
    if (msg.result != XCS_RSLT_OK)
    {
        printf("error connecting xcs control channel!\n");
        goto ctrl_fd_fail;
    }
    session_id = msg.u.connect.session_id;


    /* setup data channel connection to xcs */
    
    data_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( data_fd < 0 )
    {
        printf("error creating xcs data socket!\n");
        goto ctrl_fd_fail;
    }
    
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, my_path);
    len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;
    
    ret = connect(data_fd, (struct sockaddr *)&addr, len);
    if (ret < 0) 
    {
        printf("error connecting to xcs (data)! (%d)\n", errno);
        goto data_fd_fail;
    }

    msg.type = XCS_CONNECT_DATA;
    msg.u.connect.session_id = session_id;
    send(data_fd, &msg, sizeof(xcs_msg_t), 0);
    read(data_fd, &msg, sizeof(xcs_msg_t));                      /* same bug */
    
    if ( msg.result != XCS_RSLT_OK )
    {
        printf("error connecting xcs control channel!\n");
        goto ctrl_fd_fail;
    }



    /* now request all messages of a particular type */

    msg.type = XCS_MSG_BIND;
    msg.u.bind.port = PORT_WILDCARD;
    msg.u.bind.type = my_msg_type;
    send(control_fd, &msg, sizeof(xcs_msg_t), 0);
    read(control_fd, &msg, sizeof(xcs_msg_t));                /* still buggy */

    if (msg.result != XCS_RSLT_OK) {
        printf ("error: MSG BIND\n");
	goto bind_fail;
    }

    CAMLreturn(Val_int(data_fd));

bind_fail:
data_fd_fail: 
    close(data_fd);  
    
ctrl_fd_fail:
    close(control_fd);
     
fail:
    failwith("xcs connection error");             /* should be more explicit */
}


/* xcs_disconnect: Unix.file_descr -> unit */

value
xcs_disconnect (value data_fd)
{
    CAMLparam1(data_fd);

    int my_data_fd = Int_val(data_fd);

    close(my_data_fd);
    close(control_fd);
    control_fd = -1;

    CAMLreturn(Val_unit);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

