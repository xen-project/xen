/******************************************************************************
 * utils.c
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <xc.h>

#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include <xen/linux/privcmd.h>

#define XENPKG "xen.lowlevel.xu"

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

/* NB. The following should be kept in sync with the kernel's evtchn driver. */
#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 201
/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET  _IO('E', 1)
/* EVTCHN_BIND: Bind to teh specified event-channel port. */
#define EVTCHN_BIND   _IO('E', 2)
/* EVTCHN_UNBIND: Unbind from the specified event-channel port. */
#define EVTCHN_UNBIND _IO('E', 3)

/* Size of a machine page frame. */
#define PAGE_SIZE 4096

/* Set the close-on-exec flag on a file descriptor.  Doesn't currently bother
 * to check for errors. */
/*
static void set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);

    if ( flags < 0 )
	return;

    flags |= FD_CLOEXEC;
    fcntl(fd, F_SETFD, flags);
}
*/
/*
 * *********************** XCS INTERFACE ***********************
 */

#include <arpa/inet.h>
#include <xcs_proto.h>

static int xcs_ctrl_fd = -1; /* control connection to the xcs server. */
static int xcs_data_fd = -1; /*    data connection to the xcs server. */
static u32 xcs_session_id = 0;

static int xcs_ctrl_send(xcs_msg_t *msg);
static int xcs_ctrl_read(xcs_msg_t *msg);
static int xcs_data_send(xcs_msg_t *msg);
static int xcs_data_read(xcs_msg_t *msg);

static int xcs_connect(char *path)
{
    struct sockaddr_un addr;
    int ret, len, flags;
    xcs_msg_t msg;

    if (xcs_data_fd != -1) /* already connected */
        return 0;
    
    xcs_ctrl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (xcs_ctrl_fd < 0)
    {
        printf("error creating xcs socket!\n");
        goto fail;
    }
    
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;

    ret = connect(xcs_ctrl_fd, (struct sockaddr *)&addr, len);
    if (ret < 0) 
    {
        printf("error connecting to xcs(ctrl)! (%d)\n", errno);
        goto ctrl_fd_fail;
    }

    /*set_cloexec(xcs_ctrl_fd);*/
            
    msg.type = XCS_CONNECT_CTRL;
    msg.u.connect.session_id = xcs_session_id;
    xcs_ctrl_send(&msg);
    xcs_ctrl_read(&msg); /* TODO: timeout + error! */
    
    if (msg.result != XCS_RSLT_OK)
    {
        printf("error connecting xcs control channel!\n");
        goto ctrl_fd_fail;
    }
    xcs_session_id = msg.u.connect.session_id;
    
    /* now the data connection. */
    xcs_data_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (xcs_data_fd < 0)
    {
        printf("error creating xcs data socket!\n");
        goto ctrl_fd_fail;
    }
    
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    len = sizeof(addr.sun_family) + strlen(addr.sun_path) + 1;
    
    ret = connect(xcs_data_fd, (struct sockaddr *)&addr, len);
    if (ret < 0) 
    {
        printf("error connecting to xcs(data)! (%d)\n", errno);
        goto data_fd_fail;
    }

    //set_cloexec(xcs_data_fd);
    msg.type = XCS_CONNECT_DATA;
    msg.u.connect.session_id = xcs_session_id;
    xcs_data_send(&msg);
    xcs_data_read(&msg); /* TODO: timeout + error! */
    
    if (msg.result != XCS_RSLT_OK)
    {
        printf("error connecting xcs control channel!\n");
        goto ctrl_fd_fail;
    }
    
    if ( ((flags = fcntl(xcs_data_fd, F_GETFL, 0)) < 0) ||
        (fcntl(xcs_data_fd, F_SETFL, flags | O_NONBLOCK) < 0) )
    {
        printf("Unable to set non-blocking status on data socket.");
        goto data_fd_fail;
    }
    
    return 0;

data_fd_fail: 
    close(xcs_data_fd);  
    xcs_data_fd = -1;  
    
ctrl_fd_fail:
    close(xcs_ctrl_fd);
    xcs_ctrl_fd = -1; 
     
fail:
    return -1;
    
}

static void xcs_disconnect(void)
{
    close(xcs_data_fd);
    xcs_data_fd = -1;
    close(xcs_ctrl_fd);
    xcs_ctrl_fd = -1;
}

static int xcs_ctrl_read(xcs_msg_t *msg)
{
    int ret;
    
    ret = read(xcs_ctrl_fd, msg, sizeof(xcs_msg_t));
    return ret;
}

static int xcs_ctrl_send(xcs_msg_t *msg)
{
    int ret;
    
    ret = send(xcs_ctrl_fd, msg, sizeof(xcs_msg_t), 0);
    return ret;
}

static int xcs_data_read(xcs_msg_t *msg)
{
    int ret;
    
    ret = read(xcs_data_fd, msg, sizeof(xcs_msg_t));
    return ret;
}

static int xcs_data_send(xcs_msg_t *msg)
{
    int ret;
    
    ret = send(xcs_data_fd, msg, sizeof(xcs_msg_t), 0);
    return ret;
}


typedef struct kme_st {
    xcs_msg_t         msg;
    struct kme_st    *next;
} xcs_msg_ent_t;
    

#define XCS_RING_SIZE 64
static xcs_msg_ent_t *req_ring[64];
static unsigned req_prod = 0;
static unsigned req_cons = 0;

static xcs_msg_ent_t *rsp_ring[64];
static unsigned rsp_prod = 0;
static unsigned rsp_cons = 0;

#define REQ_RING_ENT(_idx) (req_ring[(_idx) % XCS_RING_SIZE])
#define RSP_RING_ENT(_idx) (rsp_ring[(_idx) % XCS_RING_SIZE]) 
#define REQ_RING_FULL ( req_prod - req_cons == XCS_RING_SIZE )
#define RSP_RING_FULL ( rsp_prod - rsp_cons == XCS_RING_SIZE )
#define REQ_RING_EMPTY ( req_prod == req_cons )
#define RSP_RING_EMPTY ( rsp_prod == rsp_cons )
/*
 * *********************** NOTIFIER ***********************
 */

typedef struct {
    PyObject_HEAD;
    int evtchn_fd;
} xu_notifier_object;

static PyObject *xu_notifier_read(PyObject *self, PyObject *args)
{
    xcs_msg_ent_t *ent;
    int ret;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;
         
    while ((!REQ_RING_FULL) && (!RSP_RING_FULL))
    {
        ent = (xcs_msg_ent_t *)malloc(sizeof(xcs_msg_ent_t));
        ret = xcs_data_read(&ent->msg);

        if (ret == -1)
        {
            free(ent);
            if ( errno == EINTR )
                continue;
            if ( errno == EAGAIN )
                break;
            return PyErr_SetFromErrno(PyExc_IOError);
        }
        
        switch (ent->msg.type)
        {
        case XCS_REQUEST:
            REQ_RING_ENT(req_prod) = ent;
            req_prod++;
            continue;

        case XCS_RESPONSE:
            RSP_RING_ENT(rsp_prod) = ent;
            rsp_prod++;
            continue;
            
        case XCS_VIRQ:
            ret = ent->msg.u.control.local_port;
            free(ent);
            return PyInt_FromLong(ret);

        default:
            /*printf("Throwing away xcs msg type: %u\n", ent->msg.type);*/
            free(ent);
        }
    }
    
    if (!REQ_RING_EMPTY) 
    {
        return PyInt_FromLong(REQ_RING_ENT(req_cons)->msg.u.control.local_port); 
    }
    
    if (!RSP_RING_EMPTY) 
    {
        return PyInt_FromLong(RSP_RING_ENT(rsp_cons)->msg.u.control.local_port); 
    }
    
    Py_INCREF(Py_None);
    return Py_None;
}

/* this is now a NOOP */
static PyObject *xu_notifier_unmask(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

/* this is now a NOOP */
static PyObject *xu_notifier_bind(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_notifier_bind_virq(PyObject *self, 
            PyObject *args, PyObject *kwds)
{
    int virq;
    xcs_msg_t kmsg;

    static char *kwd_list[] = { "virq", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &virq) )
        return NULL;
    
    kmsg.type = XCS_VIRQ_BIND;
    kmsg.u.virq.virq  = virq;
    xcs_ctrl_send(&kmsg);
    xcs_ctrl_read(&kmsg);
    
    if ( kmsg.result != XCS_RSLT_OK )
    {  
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    return PyInt_FromLong(kmsg.u.virq.port);
}

static PyObject *xu_notifier_virq_send(PyObject *self, 
            PyObject *args, PyObject *kwds)
{
    int port;
    xcs_msg_t kmsg;

    static char *kwd_list[] = { "port", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &port) )
        return NULL;
    
    kmsg.type = XCS_VIRQ;
    kmsg.u.control.local_port  = port;
    xcs_ctrl_send(&kmsg);
    xcs_ctrl_read(&kmsg);
    
    if ( kmsg.result != XCS_RSLT_OK )
    {  
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    return PyInt_FromLong(kmsg.u.virq.port);
}

/* this is now a NOOP */
static PyObject *xu_notifier_unbind(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_notifier_fileno(PyObject *self, PyObject *args)
{
    return PyInt_FromLong(xcs_data_fd);
}

static PyMethodDef xu_notifier_methods[] = {
    { "read",
      (PyCFunction)xu_notifier_read,
      METH_VARARGS,
      "Read a @port with pending notifications.\n" },

    { "unmask", 
      (PyCFunction)xu_notifier_unmask,
      METH_VARARGS,
      "Unmask notifications for a @port.\n" },

    { "bind", 
      (PyCFunction)xu_notifier_bind,
      METH_VARARGS,
      "Get notifications for a @port.\n" },

    { "unbind", 
      (PyCFunction)xu_notifier_unbind,
      METH_VARARGS,
      "No longer get notifications for a @port.\n" },
      
    { "bind_virq",
      (PyCFunction)xu_notifier_bind_virq,
      METH_VARARGS | METH_KEYWORDS,
      "Get notifications for a virq.\n" 
      " virq [int]: VIRQ to bind.\n\n" },
      
    { "virq_send",
      (PyCFunction)xu_notifier_virq_send,
      METH_VARARGS | METH_KEYWORDS,
      "Fire a virq notification.\n" 
      " port [int]: port that VIRQ is bound to.\n\n" },

    { "fileno", 
      (PyCFunction)xu_notifier_fileno,
      METH_VARARGS,
      "Return the file descriptor for the notification channel.\n" },

    { NULL, NULL, 0, NULL }
};

staticforward PyTypeObject xu_notifier_type;

/* connect to xcs if we aren't already, and return a dummy object. */
static PyObject *xu_notifier_new(PyObject *self, PyObject *args)
{
    xu_notifier_object *xun;
    int i;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    xun = PyObject_New(xu_notifier_object, &xu_notifier_type);

    for (i = 0; i < XCS_RING_SIZE; i++) 
        REQ_RING_ENT(i) = RSP_RING_ENT(i) = NULL;
    
    (void)xcs_connect(XCS_SUN_PATH);
    

    return (PyObject *)xun;
}

static PyObject *xu_notifier_getattr(PyObject *obj, char *name)
{
    return Py_FindMethod(xu_notifier_methods, obj, name);
}

static void xu_notifier_dealloc(PyObject *self)
{
    xcs_disconnect();
    PyObject_Del(self);
}

static PyTypeObject xu_notifier_type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "notifier",
    sizeof(xu_notifier_object),
    0,
    xu_notifier_dealloc, /* tp_dealloc     */
    NULL,                /* tp_print       */
    xu_notifier_getattr, /* tp_getattr     */
    NULL,                /* tp_setattr     */
    NULL,                /* tp_compare     */
    NULL,                /* tp_repr        */
    NULL,                /* tp_as_number   */
    NULL,                /* tp_as_sequence */
    NULL,                /* tp_as_mapping  */
    NULL                 /* tp_hash        */
};



/*
 * *********************** MESSAGE ***********************
 */

#define TYPE(_x,_y) (((_x)<<8)|(_y))

#define P2C(_struct, _field, _ctype)                                      \
    do {                                                                  \
        PyObject *obj;                                                    \
        if ( (obj = PyDict_GetItemString(payload, #_field)) != NULL )     \
        {                                                                 \
            if ( PyInt_Check(obj) )                                       \
            {                                                             \
                ((_struct *)&xum->msg.msg[0])->_field =                   \
                  (_ctype)PyInt_AsLong(obj);                              \
                dict_items_parsed++;                                      \
            }                                                             \
            else if ( PyLong_Check(obj) )                                 \
            {                                                             \
                ((_struct *)&xum->msg.msg[0])->_field =                   \
                  (_ctype)PyLong_AsUnsignedLongLong(obj);                 \
                dict_items_parsed++;                                      \
            }                                                             \
        }                                                                 \
        xum->msg.length = sizeof(_struct);                                \
    } while ( 0 )

/** Set a char[] field in a struct from a Python string.
 * Can't do this in P2C because of the typing.
 */
#define P2CSTRING(_struct, _field)                                        \
    do {                                                                  \
        PyObject *obj;                                                    \
        if ( (obj = PyDict_GetItemString(payload, #_field)) != NULL )     \
        {                                                                 \
            if ( PyString_Check(obj) )                                    \
            {                                                             \
                _struct * _cobj = (_struct *)&xum->msg.msg[0];            \
                int _field_n = sizeof(_cobj->_field);                     \
                memset(_cobj->_field, 0, _field_n);                       \
                strncpy(_cobj->_field,                                    \
                        PyString_AsString(obj),                           \
                        _field_n - 1);                                    \
                dict_items_parsed++;                                      \
            }                                                             \
        }                                                                 \
        xum->msg.length = sizeof(_struct);                                \
    } while ( 0 )

#define C2P(_struct, _field, _pytype, _ctype)                             \
    do {                                                                  \
        PyObject *obj = Py ## _pytype ## _From ## _ctype                  \
                        (((_struct *)&xum->msg.msg[0])->_field);          \
        if ( dict == NULL ) dict = PyDict_New();                          \
        PyDict_SetItemString(dict, #_field, obj);                         \
    } while ( 0 )

#define PSTR2CHAR(_struct, _field)                                        \
 do {                                                                     \
     PyObject *obj;                                                       \
        if ( (obj = PyDict_GetItemString(payload, #_field)) != NULL )     \
        {                                                                 \
            if ( PyString_Check(obj) )                                    \
            {                                                             \
                char *buffer = PyString_AsString(obj);                    \
                                                                          \
                strcpy(((_struct *)&xum->msg.msg[0])->_field,             \
                        buffer);                                          \
                /* Should complain about length - think later */          \
                dict_items_parsed++;                                      \
            }                                                             \
        }                                                                 \
        xum->msg.length = sizeof(_struct);                                \
 } while ( 0 )

typedef struct {
    PyObject_HEAD;
    control_msg_t msg;
} xu_message_object;

static PyObject *xu_message_append_payload(PyObject *self, PyObject *args)
{
    xu_message_object *xum = (xu_message_object *)self;
    char *str;
    int len;

    if ( !PyArg_ParseTuple(args, "s#", &str, &len) )
        return NULL;

    if ( (len + xum->msg.length) > sizeof(xum->msg.msg) )
    {
        PyErr_SetString(PyExc_RuntimeError, "out of space in control message");
        return NULL;
    }

    memcpy(&xum->msg.msg[xum->msg.length], str, len);
    xum->msg.length += len;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_message_set_response_fields(PyObject *self, PyObject *args)
{
    xu_message_object *xum = (xu_message_object *)self;
    PyObject *payload;
    int dict_items_parsed = 0;

    if ( !PyArg_ParseTuple(args, "O", &payload) )
        return NULL;

    if ( !PyDict_Check(payload) )
    {
        PyErr_SetString(PyExc_TypeError, "payload is not a dictionary");
        return NULL;
    }

    switch ( TYPE(xum->msg.type, xum->msg.subtype) )
    {
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_DRIVER_STATUS):
        P2C(blkif_fe_driver_status_t, max_handle, u32);
        break;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_DRIVER_STATUS):
        P2C(netif_fe_driver_status_t, max_handle, u32);
        break;
    }

    if ( dict_items_parsed != PyDict_Size(payload) )
    {
        PyErr_SetString(PyExc_TypeError, "payload contains bad items");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_message_get_payload(PyObject *self, PyObject *args)
{
    xu_message_object *xum = (xu_message_object *)self;
    PyObject *dict = NULL;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    switch ( TYPE(xum->msg.type, xum->msg.subtype) )
    {
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_STATUS):
        C2P(blkif_fe_interface_status_t, handle, Int, Long);
        C2P(blkif_fe_interface_status_t, status, Int, Long);
        C2P(blkif_fe_interface_status_t, evtchn, Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_DRIVER_STATUS):
        C2P(blkif_fe_driver_status_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_CONNECT):
        C2P(blkif_fe_interface_connect_t, handle,      Int, Long);
        C2P(blkif_fe_interface_connect_t, shmem_frame, Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_DISCONNECT):
        C2P(blkif_fe_interface_disconnect_t, handle, Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_CREATE):
        C2P(blkif_be_create_t, domid,        Int, Long);
        C2P(blkif_be_create_t, blkif_handle, Int, Long);
        C2P(blkif_be_create_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DESTROY):
        C2P(blkif_be_destroy_t, domid,        Int, Long);
        C2P(blkif_be_destroy_t, blkif_handle, Int, Long);
        C2P(blkif_be_destroy_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_CONNECT):
        C2P(blkif_be_connect_t, domid,        Int, Long);
        C2P(blkif_be_connect_t, blkif_handle, Int, Long);
        C2P(blkif_be_connect_t, shmem_frame,  Int, Long);
        C2P(blkif_be_connect_t, evtchn,       Int, Long);
        C2P(blkif_be_connect_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DISCONNECT):
        C2P(blkif_be_disconnect_t, domid,        Int, Long);
        C2P(blkif_be_disconnect_t, blkif_handle, Int, Long);
        C2P(blkif_be_disconnect_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE):
        C2P(blkif_be_vbd_create_t, domid,        Int, Long);
        C2P(blkif_be_vbd_create_t, blkif_handle, Int, Long);
        C2P(blkif_be_vbd_create_t, pdevice,      Int, Long);
        C2P(blkif_be_vbd_create_t, vdevice,      Int, Long);
        C2P(blkif_be_vbd_create_t, readonly,     Int, Long);
        C2P(blkif_be_vbd_create_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_DESTROY):
        C2P(blkif_be_vbd_destroy_t, domid,        Int, Long);
        C2P(blkif_be_vbd_destroy_t, blkif_handle, Int, Long);
        C2P(blkif_be_vbd_destroy_t, vdevice,      Int, Long);
        C2P(blkif_be_vbd_destroy_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DRIVER_STATUS):
        C2P(blkif_be_driver_status_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_STATUS):
        C2P(netif_fe_interface_status_t, handle, Int, Long);
        C2P(netif_fe_interface_status_t, status, Int, Long);
        C2P(netif_fe_interface_status_t, evtchn, Int, Long);
        C2P(netif_fe_interface_status_t, mac[0], Int, Long);
        C2P(netif_fe_interface_status_t, mac[1], Int, Long);
        C2P(netif_fe_interface_status_t, mac[2], Int, Long);
        C2P(netif_fe_interface_status_t, mac[3], Int, Long);
        C2P(netif_fe_interface_status_t, mac[4], Int, Long);
        C2P(netif_fe_interface_status_t, mac[5], Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_DRIVER_STATUS):
        C2P(netif_fe_driver_status_t, status,        Int, Long);
        C2P(netif_fe_driver_status_t, max_handle,    Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_CONNECT):
        C2P(netif_fe_interface_connect_t, handle,         Int, Long);
        C2P(netif_fe_interface_connect_t, tx_shmem_frame, Int, Long);
        C2P(netif_fe_interface_connect_t, rx_shmem_frame, Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_DISCONNECT):
        C2P(netif_fe_interface_disconnect_t, handle, Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CREATE):
        C2P(netif_be_create_t, domid,        Int, Long);
        C2P(netif_be_create_t, netif_handle, Int, Long);
        C2P(netif_be_create_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_DESTROY):
        C2P(netif_be_destroy_t, domid,        Int, Long);
        C2P(netif_be_destroy_t, netif_handle, Int, Long);
        C2P(netif_be_destroy_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CREDITLIMIT):
        C2P(netif_be_creditlimit_t, domid,        Int, Long);
        C2P(netif_be_creditlimit_t, netif_handle, Int, Long);
        C2P(netif_be_creditlimit_t, credit_bytes, Int, Long);
        C2P(netif_be_creditlimit_t, period_usec,  Int, Long);
        C2P(netif_be_creditlimit_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CONNECT):
        C2P(netif_be_connect_t, domid,          Int, Long);
        C2P(netif_be_connect_t, netif_handle,   Int, Long);
        C2P(netif_be_connect_t, tx_shmem_frame, Int, Long);
        C2P(netif_be_connect_t, rx_shmem_frame, Int, Long);
        C2P(netif_be_connect_t, evtchn,         Int, Long);
        C2P(netif_be_connect_t, status,         Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_DISCONNECT):
        C2P(netif_be_disconnect_t, domid,        Int, Long);
        C2P(netif_be_disconnect_t, netif_handle, Int, Long);
        C2P(netif_be_disconnect_t, status,       Int, Long);
        return dict;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_DRIVER_STATUS):
        C2P(netif_be_driver_status_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED):
        C2P(usbif_fe_interface_status_changed_t, status, Int, Long);
        C2P(usbif_fe_interface_status_changed_t, evtchn, Int, Long);
        C2P(usbif_fe_interface_status_changed_t, domid, Int, Long);
        C2P(usbif_fe_interface_status_changed_t, bandwidth, Int, Long);
	C2P(usbif_fe_interface_status_changed_t, num_ports, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_DRIVER_STATUS_CHANGED):
        C2P(usbif_fe_driver_status_changed_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_CONNECT):
        C2P(usbif_fe_interface_connect_t, shmem_frame, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_DISCONNECT):
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CREATE):
        C2P(usbif_be_create_t, domid, Int, Long);
        C2P(usbif_be_create_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DESTROY):
        C2P(usbif_be_destroy_t, domid, Int, Long);
        C2P(usbif_be_destroy_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CONNECT):
        C2P(usbif_be_connect_t, domid, Int, Long);
        C2P(usbif_be_connect_t, shmem_frame, Int, Long);
        C2P(usbif_be_connect_t, evtchn, Int, Long);
        C2P(usbif_be_connect_t, bandwidth, Int, Long);
        C2P(usbif_be_connect_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DISCONNECT):
        C2P(usbif_be_disconnect_t, domid, Int, Long);
        C2P(usbif_be_disconnect_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DRIVER_STATUS_CHANGED):
        C2P(usbif_be_driver_status_changed_t, status, Int, Long);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CLAIM_PORT):
        C2P(usbif_be_claim_port_t, domid, Int, Long);
        C2P(usbif_be_claim_port_t, usbif_port, Int, Long);
        C2P(usbif_be_claim_port_t, status, Int, Long);
        C2P(usbif_be_claim_port_t, path, String, String);
        return dict;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_RELEASE_PORT):
        C2P(usbif_be_release_port_t, path, String, String);
        return dict;
    case TYPE(CMSG_MEM_REQUEST, CMSG_MEM_REQUEST_SET):
        C2P(mem_request_t, target, Int, Long);
        C2P(mem_request_t, status, Int, Long);
        return dict;
    }

    return PyString_FromStringAndSize((char *)xum->msg.msg, xum->msg.length);
}

static PyObject *xu_message_get_header(PyObject *self, PyObject *args)
{
    xu_message_object *xum = (xu_message_object *)self;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    return Py_BuildValue("{s:i,s:i,s:i}",
                         "type",    xum->msg.type,
                         "subtype", xum->msg.subtype,
                         "id",      xum->msg.id);
}

static PyMethodDef xu_message_methods[] = {
    { "append_payload", 
      (PyCFunction)xu_message_append_payload,
      METH_VARARGS,
      "Append @str to the message payload.\n" },

    { "set_response_fields",
      (PyCFunction)xu_message_set_response_fields,
      METH_VARARGS,
      "Fill in the response fields in a message that was passed to us.\n" },

    { "get_payload",
      (PyCFunction)xu_message_get_payload,
      METH_VARARGS,
      "Return the message payload in string form.\n" },

    { "get_header",
      (PyCFunction)xu_message_get_header,
      METH_VARARGS,
      "Returns a dictionary of values for @type, @subtype, and @id.\n" },

    { NULL, NULL, 0, NULL }
};

staticforward PyTypeObject xu_message_type;

static PyObject *xu_message_new(PyObject *self, PyObject *args)
{
    xu_message_object *xum;
    int type, subtype, id, dict_items_parsed = 0;
    PyObject *payload = NULL;

    if ( !PyArg_ParseTuple(args, "iii|O", &type, &subtype, &id, &payload) )
        return NULL;

    xum = PyObject_New(xu_message_object, &xu_message_type);

    xum->msg.type    = type;
    xum->msg.subtype = subtype;
    xum->msg.id      = id;
    xum->msg.length  = 0;

    if ( payload == NULL )
        return (PyObject *)xum;

    if ( !PyDict_Check(payload) )
    {
        PyErr_SetString(PyExc_TypeError, "payload is not a dictionary");
        PyObject_Del((PyObject *)xum);
        return NULL;
    }

    switch ( TYPE(type, subtype) )
    {
    case TYPE(CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_STATUS):
        P2C(blkif_fe_interface_status_t, handle, u32);
        P2C(blkif_fe_interface_status_t, status, u32);
        P2C(blkif_fe_interface_status_t, evtchn, u16);
        P2C(blkif_fe_interface_status_t, domid,  u16);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_CREATE):
        P2C(blkif_be_create_t, domid,        u32);
        P2C(blkif_be_create_t, blkif_handle, u32);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DESTROY):
        P2C(blkif_be_destroy_t, domid,        u32);
        P2C(blkif_be_destroy_t, blkif_handle, u32);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_CONNECT):
        P2C(blkif_be_connect_t, domid,        u32);
        P2C(blkif_be_connect_t, blkif_handle, u32);
        P2C(blkif_be_connect_t, shmem_frame,  memory_t);
        P2C(blkif_be_connect_t, evtchn,       u16);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_DISCONNECT):
        P2C(blkif_be_disconnect_t, domid,        u32);
        P2C(blkif_be_disconnect_t, blkif_handle, u32);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE):
        P2C(blkif_be_vbd_create_t, domid,        u32);
        P2C(blkif_be_vbd_create_t, blkif_handle, u32);
        P2C(blkif_be_vbd_create_t, pdevice,      blkif_pdev_t);
        P2C(blkif_be_vbd_create_t, vdevice,      blkif_vdev_t);
        P2C(blkif_be_vbd_create_t, readonly,     u16);
        break;
    case TYPE(CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_DESTROY):
        P2C(blkif_be_vbd_destroy_t, domid,        u32);
        P2C(blkif_be_vbd_destroy_t, blkif_handle, u32);
        P2C(blkif_be_vbd_destroy_t, vdevice,      blkif_vdev_t);
        break;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_STATUS):
        P2C(netif_fe_interface_status_t, handle, u32);
        P2C(netif_fe_interface_status_t, status, u32);
        P2C(netif_fe_interface_status_t, evtchn, u16);
        P2C(netif_fe_interface_status_t, domid,  u16);
        P2C(netif_fe_interface_status_t, mac[0], u8);
        P2C(netif_fe_interface_status_t, mac[1], u8);
        P2C(netif_fe_interface_status_t, mac[2], u8);
        P2C(netif_fe_interface_status_t, mac[3], u8);
        P2C(netif_fe_interface_status_t, mac[4], u8);
        P2C(netif_fe_interface_status_t, mac[5], u8);
        break;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CREATE):
        P2C(netif_be_create_t, domid,        u32);
        P2C(netif_be_create_t, netif_handle, u32);
        P2C(netif_be_create_t, mac[0],       u8);
        P2C(netif_be_create_t, mac[1],       u8);
        P2C(netif_be_create_t, mac[2],       u8);
        P2C(netif_be_create_t, mac[3],       u8);
        P2C(netif_be_create_t, mac[4],       u8);
        P2C(netif_be_create_t, mac[5],       u8);
        P2C(netif_be_create_t, be_mac[0],    u8);
        P2C(netif_be_create_t, be_mac[1],    u8);
        P2C(netif_be_create_t, be_mac[2],    u8);
        P2C(netif_be_create_t, be_mac[3],    u8);
        P2C(netif_be_create_t, be_mac[4],    u8);
        P2C(netif_be_create_t, be_mac[5],    u8);
        break;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_DESTROY):
        P2C(netif_be_destroy_t, domid,        u32);
        P2C(netif_be_destroy_t, netif_handle, u32);
        break;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CREDITLIMIT):
        P2C(netif_be_creditlimit_t, domid,        u32);
        P2C(netif_be_creditlimit_t, netif_handle, u32);
        P2C(netif_be_creditlimit_t, credit_bytes, u32);
        P2C(netif_be_creditlimit_t, period_usec,  u32);
        break;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_CONNECT):
        P2C(netif_be_connect_t, domid,          u32);
        P2C(netif_be_connect_t, netif_handle,   u32);
        P2C(netif_be_connect_t, tx_shmem_frame, memory_t);
        P2C(netif_be_connect_t, rx_shmem_frame, memory_t);
        P2C(netif_be_connect_t, evtchn,         u16);
        break;
    case TYPE(CMSG_NETIF_BE, CMSG_NETIF_BE_DISCONNECT):
        P2C(netif_be_disconnect_t, domid,        u32);
        P2C(netif_be_disconnect_t, netif_handle, u32);
        break;
    case TYPE(CMSG_NETIF_FE, CMSG_NETIF_FE_DRIVER_STATUS):
        P2C(netif_fe_driver_status_t, status,        u32);
        P2C(netif_fe_driver_status_t, max_handle,    u32);
        break;
    case TYPE(CMSG_MEM_REQUEST, CMSG_MEM_REQUEST_SET):
        P2C(mem_request_t, target, u32);
        P2C(mem_request_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED):
        P2C(usbif_fe_interface_status_changed_t, status, u32);
        P2C(usbif_fe_interface_status_changed_t, evtchn, u16);
        P2C(usbif_fe_interface_status_changed_t, domid, domid_t);
        P2C(usbif_fe_interface_status_changed_t, bandwidth, u32);
	P2C(usbif_fe_interface_status_changed_t, num_ports, u32);
        break;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_DRIVER_STATUS_CHANGED):
        P2C(usbif_fe_driver_status_changed_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_CONNECT):
        P2C(usbif_fe_interface_connect_t, shmem_frame, memory_t);
        break;
    case TYPE(CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_DISCONNECT):
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CREATE):
        P2C(usbif_be_create_t, domid, domid_t);
        P2C(usbif_be_create_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DESTROY):
        P2C(usbif_be_destroy_t, domid, domid_t);
        P2C(usbif_be_destroy_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CONNECT):
        P2C(usbif_be_connect_t, domid, domid_t);
        P2C(usbif_be_connect_t, shmem_frame, memory_t);
        P2C(usbif_be_connect_t, evtchn, u32);
        P2C(usbif_be_connect_t, bandwidth, u32);
        P2C(usbif_be_connect_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DISCONNECT):
        P2C(usbif_be_disconnect_t, domid, domid_t);
        P2C(usbif_be_disconnect_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_DRIVER_STATUS_CHANGED):
        P2C(usbif_be_driver_status_changed_t, status, u32);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_CLAIM_PORT):
        P2C(usbif_be_claim_port_t, domid, domid_t);
        P2C(usbif_be_claim_port_t, usbif_port, u32);
        P2C(usbif_be_claim_port_t, status, u32);
        PSTR2CHAR(usbif_be_claim_port_t, path);
        printf("dict items parsed = %d", dict_items_parsed);
        break;
    case TYPE(CMSG_USBIF_BE, CMSG_USBIF_BE_RELEASE_PORT):
        PSTR2CHAR(usbif_be_release_port_t, path);
        break;
    case TYPE(CMSG_SHUTDOWN, CMSG_SHUTDOWN_SYSRQ):
        P2C(shutdown_sysrq_t, key, char);
        break;
    }

    if ( dict_items_parsed != PyDict_Size(payload) )
    {
        PyErr_SetString(PyExc_TypeError, "payload contains bad items");
        PyObject_Del((PyObject *)xum);
        return NULL;
    }

    return (PyObject *)xum;
}

static PyObject *xu_message_getattr(PyObject *obj, char *name)
{
    xu_message_object *xum;
    if ( strcmp(name, "MAX_PAYLOAD") == 0 )
        return PyInt_FromLong(sizeof(xum->msg.msg));
    return Py_FindMethod(xu_message_methods, obj, name);
}

static void xu_message_dealloc(PyObject *self)
{
    PyObject_Del(self);
}

static PyTypeObject xu_message_type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "message",
    sizeof(xu_message_object),
    0,
    xu_message_dealloc,   /* tp_dealloc     */
    NULL,                /* tp_print       */
    xu_message_getattr,   /* tp_getattr     */
    NULL,                /* tp_setattr     */
    NULL,                /* tp_compare     */
    NULL,                /* tp_repr        */
    NULL,                /* tp_as_number   */
    NULL,                /* tp_as_sequence */
    NULL,                /* tp_as_mapping  */
    NULL                 /* tp_hash        */
};



/*
 * *********************** PORT ***********************
 */

typedef struct xu_port_object {
    PyObject_HEAD;
    int xc_handle;
    int connected;
    u32 remote_dom;
    int local_port, remote_port;
    struct xu_port_object *fix_next;
} xu_port_object;

static PyObject *port_error;

/* now a NOOP */
static PyObject *xu_port_notify(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_port_read_request(PyObject *self, PyObject *args)
{
    xu_port_object    *xup = (xu_port_object *)self;
    xu_message_object *xum;
    control_msg_t     *cmsg;
    unsigned          i;
    xcs_msg_ent_t    *ent = NULL;
    
    for ( i = req_cons; (i != req_prod); i++ ) {
        ent = REQ_RING_ENT(i);
        if (ent == NULL) 
            continue;
        if (ent->msg.u.control.remote_dom == xup->remote_dom)
            break;
    }
    
    if ((ent == NULL) ||
        (ent->msg.u.control.remote_dom != xup->remote_dom)) 
        goto none;

    cmsg = &ent->msg.u.control.msg;
    xum = PyObject_New(xu_message_object, &xu_message_type);
    memcpy(&xum->msg, cmsg, sizeof(*cmsg));
    if ( xum->msg.length > sizeof(xum->msg.msg) )
        xum->msg.length = sizeof(xum->msg.msg);
    free(ent);
    
    /* remove the entry from the ring and advance the consumer if possible */
    REQ_RING_ENT(i) = NULL;
    while ( (REQ_RING_ENT(req_cons) == NULL) && (!REQ_RING_EMPTY) )
        req_cons++;
    
    return (PyObject *)xum;
    
none:
    Py_INCREF(Py_None);
    return Py_None;
    
}

static PyObject *xu_port_write_request(PyObject *self, PyObject *args)
{
    xu_port_object    *xup = (xu_port_object *)self;
    xu_message_object *xum;
    xcs_msg_t          kmsg;

    if ( !PyArg_ParseTuple(args, "O", (PyObject **)&xum) )
        return NULL;

    if ( !PyObject_TypeCheck((PyObject *)xum, &xu_message_type) )
    {
        PyErr_SetString(PyExc_TypeError, "expected a " XENPKG ".message");
        return NULL;        
    }

    kmsg.type = XCS_REQUEST;
    kmsg.u.control.remote_dom = xup->remote_dom;
    memcpy(&kmsg.u.control.msg, &xum->msg, sizeof(control_msg_t));
    xcs_data_send(&kmsg);
    
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_port_read_response(PyObject *self, PyObject *args)
{
    xu_port_object    *xup = (xu_port_object *)self;
    xu_message_object *xum;
    control_msg_t     *cmsg;
    unsigned          i;
    xcs_msg_ent_t    *ent = NULL;
    
    for ( i = rsp_cons; (i != rsp_prod); i++ ) {
        ent = RSP_RING_ENT(i);
        if (ent == NULL) 
            continue;
        if (ent->msg.u.control.remote_dom == xup->remote_dom)
            break;
    }
    
    if ((ent == NULL) ||
        (ent->msg.u.control.remote_dom != xup->remote_dom))
         goto none;

    cmsg = &ent->msg.u.control.msg;
    xum = PyObject_New(xu_message_object, &xu_message_type);
    memcpy(&xum->msg, cmsg, sizeof(*cmsg));
    if ( xum->msg.length > sizeof(xum->msg.msg) )
        xum->msg.length = sizeof(xum->msg.msg);
    free(ent);
    
    /* remove the entry from the ring and advance the consumer if possible */
    RSP_RING_ENT(i) = NULL;
    while ( (RSP_RING_ENT(rsp_cons) == NULL) && (!RSP_RING_EMPTY) )
        rsp_cons++;
    
    return (PyObject *)xum;
    
none:
    Py_INCREF(Py_None);
    return Py_None;
    
}

static PyObject *xu_port_write_response(PyObject *self, PyObject *args)
{
    xu_port_object    *xup = (xu_port_object *)self;
    xu_message_object *xum;
    xcs_msg_t          kmsg;

    if ( !PyArg_ParseTuple(args, "O", (PyObject **)&xum) )
        return NULL;

    if ( !PyObject_TypeCheck((PyObject *)xum, &xu_message_type) )
    {
        PyErr_SetString(PyExc_TypeError, "expected a " XENPKG ".message");
        return NULL;        
    }

    kmsg.type = XCS_RESPONSE;
    kmsg.u.control.remote_dom = xup->remote_dom;
    memcpy(&kmsg.u.control.msg, &xum->msg, sizeof(control_msg_t));
    xcs_data_send(&kmsg);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_port_request_to_read(PyObject *self, PyObject *args)
{
    xu_port_object   *xup = (xu_port_object *)self;
    xcs_msg_ent_t    *ent;
    int               found = 0;
    unsigned          i;
  
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    for ( i = req_cons; (i != req_prod); i++ ) {
        ent = REQ_RING_ENT(i);
        if (ent == NULL) 
            continue;
        if (ent->msg.u.control.remote_dom == xup->remote_dom) {
            found = 1;
            break;
        }
    }
    
    return PyInt_FromLong(found);
}

static PyObject *xu_port_space_to_write_request(PyObject *self, PyObject *args)
{
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    return PyInt_FromLong(1);
}

static PyObject *xu_port_response_to_read(PyObject *self, PyObject *args)
{
    xu_port_object   *xup = (xu_port_object *)self;
    xcs_msg_ent_t    *ent;
    int               found = 0;
    unsigned          i;
  
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    for ( i = rsp_cons; (i != rsp_prod); i++ ) {
        ent = RSP_RING_ENT(i);
        if (ent == NULL) 
            continue;
        if (ent->msg.u.control.remote_dom == xup->remote_dom) {
            found = 1;
            break;
        }
    }
    
    return PyInt_FromLong(found);
}

static PyObject *xu_port_space_to_write_response(
    PyObject *self, PyObject *args)
{
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    return PyInt_FromLong(1);
}

/* NOOP */
static PyObject *xu_port_connect(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

/* NOOP */
static PyObject *xu_port_disconnect(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *xu_port_register(PyObject *self, PyObject *args, 
        PyObject *kwds)
{
    int type;
    xcs_msg_t msg;
    xu_port_object   *xup = (xu_port_object *)self;
    static char *kwd_list[] = { "type", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list,
                                      &type) )
        return NULL;
    
    msg.type = XCS_MSG_BIND;
    msg.u.bind.port = xup->local_port;
    msg.u.bind.type = type;
    xcs_ctrl_send(&msg);
    xcs_ctrl_read(&msg);
    
    if (msg.result != XCS_RSLT_OK)
    {
        return PyInt_FromLong(0);
    }
    
    return PyInt_FromLong(1);        
}

static PyObject *xu_port_deregister(PyObject *self, PyObject *args,
        PyObject *kwds)
{
    int type;
    xcs_msg_t msg;
    xu_port_object   *xup = (xu_port_object *)self;
    static char *kwd_list[] = { "type", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list,
                                      &type) )
        return NULL;
    
    msg.type = XCS_MSG_UNBIND;
    msg.u.bind.port = xup->local_port;
    msg.u.bind.type = type;
    xcs_ctrl_send(&msg);
    xcs_ctrl_read(&msg);
    
    if (msg.result != XCS_RSLT_OK)
    {
        return PyInt_FromLong(0);
    }
    
    return PyInt_FromLong(1);        
}

static PyMethodDef xu_port_methods[] = {
    { "notify",
      (PyCFunction)xu_port_notify,
      METH_VARARGS,
      "Send a notification to the remote end.\n" },

    { "read_request",
      (PyCFunction)xu_port_read_request,
      METH_VARARGS,
      "Read a request message from the control interface.\n" },

    { "write_request",
      (PyCFunction)xu_port_write_request,
      METH_VARARGS,
      "Write a request message to the control interface.\n" },

    { "read_response",
      (PyCFunction)xu_port_read_response,
      METH_VARARGS,
      "Read a response message from the control interface.\n" },

    { "write_response",
      (PyCFunction)xu_port_write_response,
      METH_VARARGS,
      "Write a response message to the control interface.\n" },

    { "request_to_read",
      (PyCFunction)xu_port_request_to_read,
      METH_VARARGS,
      "Returns TRUE if there is a request message to read.\n" },

    { "space_to_write_request",
      (PyCFunction)xu_port_space_to_write_request,
      METH_VARARGS,
      "Returns TRUE if there is space to write a request message.\n" },

    { "response_to_read",
      (PyCFunction)xu_port_response_to_read,
      METH_VARARGS,
      "Returns TRUE if there is a response message to read.\n" },

    { "space_to_write_response",
      (PyCFunction)xu_port_space_to_write_response,
      METH_VARARGS,
      "Returns TRUE if there is space to write a response message.\n" },
      
    { "register",
      (PyCFunction)xu_port_register,
      METH_VARARGS | METH_KEYWORDS,
      "Register to receive a type of message on this channel.\n" },
      
    { "deregister",
      (PyCFunction)xu_port_deregister,
      METH_VARARGS | METH_KEYWORDS,
      "Stop receiving a type of message on this port.\n" },

    { "connect",
      (PyCFunction)xu_port_connect,
      METH_VARARGS,
      "Synchronously connect to remote domain.\n" },

    { "disconnect",
      (PyCFunction)xu_port_disconnect,
      METH_VARARGS,
      "Synchronously disconnect from remote domain.\n" },

    { NULL, NULL, 0, NULL }
};

staticforward PyTypeObject xu_port_type;

static PyObject *xu_port_new(PyObject *self, PyObject *args, PyObject *kwds)
{
    xu_port_object *xup;
    u32 dom;
    int port1 = 0, port2 = 0;
    xcs_msg_t kmsg;

    static char *kwd_list[] = { "dom", "local_port", "remote_port", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|ii", kwd_list,
                                      &dom, &port1, &port2) )
        return NULL;

    xup = PyObject_New(xu_port_object, &xu_port_type);

    xup->connected  = 0;
    xup->remote_dom = dom;
    
    kmsg.type = XCS_CIF_NEW_CC;
    kmsg.u.interface.dom         = xup->remote_dom;
    kmsg.u.interface.local_port  = port1; 
    kmsg.u.interface.remote_port = port2;
    xcs_ctrl_send(&kmsg);
    xcs_ctrl_read(&kmsg);
    
    if ( kmsg.result != XCS_RSLT_OK ) 
        goto fail1;
        
    xup->local_port  = kmsg.u.interface.local_port;
    xup->remote_port = kmsg.u.interface.remote_port;
    xup->connected = 1;
                
    return (PyObject *)xup;

 fail1:
    PyObject_Del((PyObject *)xup);
    return NULL;    
}

static PyObject *xu_port_getattr(PyObject *obj, char *name)
{
    xu_port_object *xup = (xu_port_object *)obj;
    if ( strcmp(name, "local_port") == 0 )
        return PyInt_FromLong(xup->local_port);
    if ( strcmp(name, "remote_port") == 0 )
        return PyInt_FromLong(xup->remote_port);
    if ( strcmp(name, "remote_dom") == 0 )
        return PyInt_FromLong(xup->remote_dom);
    return Py_FindMethod(xu_port_methods, obj, name);
}

static void xu_port_dealloc(PyObject *self)
{

    xu_port_object *xup = (xu_port_object *)self;
    xcs_msg_t kmsg;

    if ( xup->remote_dom != 0 )
    {  
        kmsg.type = XCS_CIF_FREE_CC;
        kmsg.u.interface.dom         = xup->remote_dom;
        kmsg.u.interface.local_port  = xup->local_port; 
        kmsg.u.interface.remote_port = xup->remote_port;
        xcs_ctrl_send(&kmsg);
        xcs_ctrl_read(&kmsg);
    }
            
    PyObject_Del(self);
}

static PyTypeObject xu_port_type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "port",
    sizeof(xu_port_object),
    0,
    xu_port_dealloc,     /* tp_dealloc     */
    NULL,                /* tp_print       */
    xu_port_getattr,     /* tp_getattr     */
    NULL,                /* tp_setattr     */
    NULL,                /* tp_compare     */
    NULL,                /* tp_repr        */
    NULL,                /* tp_as_number   */
    NULL,                /* tp_as_sequence */
    NULL,                /* tp_as_mapping  */
    NULL                 /* tp_hash        */
};



/*
 * *********************** BUFFER ***********************
 */

#define BUFSZ 65536
#define MASK_BUF_IDX(_i) ((_i)&(BUFSZ-1))
typedef unsigned int BUF_IDX;

typedef struct {
    PyObject_HEAD;
    char        *buf;
    unsigned int prod, cons;
} xu_buffer_object;

static PyObject *__xu_buffer_peek(xu_buffer_object *xub, int max)
{
    PyObject *str1, *str2;
    int len1, len2, c = MASK_BUF_IDX(xub->cons);

    len1 = xub->prod - xub->cons;
    if ( len1 > (BUFSZ - c) ) /* clip to ring wrap */
        len1 = BUFSZ - c;
    if ( len1 > max )         /* clip to specified maximum */
        len1 = max;
    if ( len1 < 0 )           /* sanity */
        len1 = 0;

    if ( (str1 = PyString_FromStringAndSize(&xub->buf[c], len1)) == NULL )
        return NULL;

    if ( (len1 < (xub->prod - xub->cons)) && (len1 < max) )
    {
        len2 = max - len1;
        if ( len2 > MASK_BUF_IDX(xub->prod) )
            len2 = MASK_BUF_IDX(xub->prod);
        if ( len2 > 0 )
        {
            str2 = PyString_FromStringAndSize(&xub->buf[0], len2);
            if ( str2 == NULL )
                return NULL;
            PyString_ConcatAndDel(&str1, str2);
            if ( str1 == NULL )
                return NULL;
        }
    }

    return str1;
}

static PyObject *xu_buffer_peek(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;
    int max = 1024;

    if ( !PyArg_ParseTuple(args, "|i", &max) )
        return NULL;
    
    return __xu_buffer_peek(xub, max);
}

static PyObject *xu_buffer_read(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;
    PyObject *str;
    int max = 1024;

    if ( !PyArg_ParseTuple(args, "|i", &max) )
        return NULL;

    if ( (str = __xu_buffer_peek(xub, max)) != NULL )
        xub->cons += PyString_Size(str);

    return str;
}

static PyObject *xu_buffer_discard(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;
    int max, len;

    if ( !PyArg_ParseTuple(args, "i", &max) )
        return NULL;

    len = xub->prod - xub->cons;
    if ( len > max )
        len = max;
    if ( len < 0 )
        len = 0;

    xub->cons += len;

    return PyInt_FromLong(len);
}

static PyObject *xu_buffer_write(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;
    char *str;
    int len, len1, len2;

    if ( !PyArg_ParseTuple(args, "s#", &str, &len) )
        return NULL;

    len1 = len;
    if ( len1 > (BUFSZ - MASK_BUF_IDX(xub->prod)) )
        len1 = BUFSZ - MASK_BUF_IDX(xub->prod);
    if ( len1 > (BUFSZ - (xub->prod - xub->cons)) )
        len1 = BUFSZ - (xub->prod - xub->cons);

    if ( len1 == 0 )
        return PyInt_FromLong(0);

    memcpy(&xub->buf[MASK_BUF_IDX(xub->prod)], &str[0], len1);
    xub->prod += len1;

    if ( len1 < len )
    {
        len2 = len - len1;
        if ( len2 > (BUFSZ - MASK_BUF_IDX(xub->prod)) )
            len2 = BUFSZ - MASK_BUF_IDX(xub->prod);
        if ( len2 > (BUFSZ - (xub->prod - xub->cons)) )
            len2 = BUFSZ - (xub->prod - xub->cons);
        if ( len2 != 0 )
        {
            memcpy(&xub->buf[MASK_BUF_IDX(xub->prod)], &str[len1], len2);
            xub->prod += len2;
            return PyInt_FromLong(len1 + len2);
        }
    }

    return PyInt_FromLong(len1);
}

static PyObject *xu_buffer_empty(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    if ( xub->cons == xub->prod )
        return PyInt_FromLong(1);

    return PyInt_FromLong(0);
}

static PyObject *xu_buffer_full(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    if ( (xub->prod - xub->cons) == BUFSZ )
        return PyInt_FromLong(1);

    return PyInt_FromLong(0);
}

static PyMethodDef xu_buffer_methods[] = {
    { "peek", 
      (PyCFunction)xu_buffer_peek,
      METH_VARARGS,
      "Peek up to @max bytes from the buffer. Returns a string.\n" },

    { "read", 
      (PyCFunction)xu_buffer_read,
      METH_VARARGS,
      "Read up to @max bytes from the buffer. Returns a string.\n" },

    { "discard", 
      (PyCFunction)xu_buffer_discard,
      METH_VARARGS,
      "Discard up to @max bytes from the buffer. Returns number of bytes.\n" },

    { "write", 
      (PyCFunction)xu_buffer_write,
      METH_VARARGS,
      "Write @string into buffer. Return number of bytes written.\n" },

    { "empty", 
      (PyCFunction)xu_buffer_empty,
      METH_VARARGS,
      "Return TRUE if the buffer is empty.\n" },

    { "full", 
      (PyCFunction)xu_buffer_full,
      METH_VARARGS,
      "Return TRUE if the buffer is full.\n" },

    { NULL, NULL, 0, NULL }
};

staticforward PyTypeObject xu_buffer_type;

static PyObject *xu_buffer_new(PyObject *self, PyObject *args)
{
    xu_buffer_object *xub;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    xub = PyObject_New(xu_buffer_object, &xu_buffer_type);

    if ( (xub->buf = malloc(BUFSZ)) == NULL )
    {
        PyObject_Del((PyObject *)xub);
        return NULL;
    }

    xub->prod = xub->cons = 0;

    return (PyObject *)xub;
}

static PyObject *xu_buffer_getattr(PyObject *obj, char *name)
{
    return Py_FindMethod(xu_buffer_methods, obj, name);
}

static void xu_buffer_dealloc(PyObject *self)
{
    xu_buffer_object *xub = (xu_buffer_object *)self;
    free(xub->buf);
    PyObject_Del(self);
}

static PyTypeObject xu_buffer_type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "buffer",
    sizeof(xu_buffer_object),
    0,
    xu_buffer_dealloc,   /* tp_dealloc     */
    NULL,                /* tp_print       */
    xu_buffer_getattr,   /* tp_getattr     */
    NULL,                /* tp_setattr     */
    NULL,                /* tp_compare     */
    NULL,                /* tp_repr        */
    NULL,                /* tp_as_number   */
    NULL,                /* tp_as_sequence */
    NULL,                /* tp_as_mapping  */
    NULL                 /* tp_hash        */
};



/*
 * *********************** MODULE WRAPPER ***********************
 */

static void handle_child_death(int dummy)
{
    while ( waitpid(-1, NULL, WNOHANG) > 0 )
        continue;
}

static PyObject *xu_autoreap(PyObject *self, PyObject *args)
{
    struct sigaction sa;

    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_child_death;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    (void)sigaction(SIGCHLD, &sa, NULL);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef xu_methods[] = {
    { "notifier", xu_notifier_new, METH_VARARGS, 
      "Create a new notifier." },
    { "message", xu_message_new, METH_VARARGS, 
      "Create a new communications message." },
    { "port", (PyCFunction)xu_port_new, METH_VARARGS | METH_KEYWORDS, 
      "Create a new communications port." },
    { "buffer", xu_buffer_new, METH_VARARGS, 
      "Create a new ring buffer." },
    { "autoreap", xu_autoreap, METH_VARARGS,
      "Ensure that zombie children are automatically reaped by the OS." },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initxu(void)
{
    PyObject *m, *d;

    m = Py_InitModule(XENPKG, xu_methods);

    d = PyModule_GetDict(m);
    port_error = PyErr_NewException(XENPKG ".PortError", NULL, NULL);
    PyDict_SetItemString(d, "PortError", port_error);

    /* KAF: This ensures that we get debug output in a timely manner. */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
