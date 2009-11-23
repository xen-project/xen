/* python binding to libnetlink */

#include <Python.h>
#include "libnetlink.h"

#define PKG "xen.lowlevel.netlink"

typedef struct {
  PyObject_HEAD
  int opened;
  struct rtnl_handle rth;
} PyRtnlObject;

/* todo: subscriptions? */
static PyObject* PyRtnl_new(PyTypeObject* type, PyObject* args,
                            PyObject* kwargs)
{
  return type->tp_alloc(type, 0);
}

static int PyRtnl_init(PyObject* obj, PyObject* args, PyObject* kwargs)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;

  if (rtnl_open(&self->rth, 0) < 0) {
    PyErr_SetString(PyExc_IOError, "could not open rtnl handle");
    return -1;
  }

  return 0;
}

static void PyRtnl_dealloc(PyRtnlObject* obj)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;

  rtnl_close(&self->rth);
}

static PyObject* pyrtnl_talk(PyObject* obj, PyObject* args)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;
  char* msg;
  int len;
  int peer = 0;
  int groups = 0;

  if (!PyArg_ParseTuple(args, "s#|ii", &msg, &len, &peer, &groups))
    return NULL;

  if (rtnl_talk(&self->rth, (struct nlmsghdr*)msg, peer, groups, NULL, NULL,
                NULL) < 0)
  {
    PyErr_SetString(PyExc_IOError, "error sending message");
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pyrtnl_wilddump_request(PyObject* obj, PyObject* args)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;
  int family, type;

  if (!PyArg_ParseTuple(args, "ii", &family, &type))
    return NULL;

  if (rtnl_wilddump_request(&self->rth, family, type) < 0) {
    PyErr_SetString(PyExc_IOError, "could not send dump request");
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pyrtnl_dump_request(PyObject* obj, PyObject* args)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;
  int type;
  char* req;
  int len;

  if (!PyArg_ParseTuple(args, "is#", &type, &req, &len))
    return NULL;

  if (rtnl_dump_request(&self->rth, type, req, len) < 0) {
    PyErr_SetString(PyExc_IOError, "could not send dump request");
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

/* translate args to python and call python callback */
static int dump_filter_helper(const struct sockaddr_nl *who,
                              struct nlmsghdr *n, void *arg)
{
  PyObject* filter = arg;
  PyObject* args;
  PyObject* result;

  args = Py_BuildValue("s#s#", who, sizeof(*who), n, n->nlmsg_len);
  result = PyObject_CallObject(filter, args);
  Py_DECREF(args);
  if (!result)
    return -1;

  /* result is ignored as long as an exception isn't raised */
  Py_DECREF(result);
  return 0;
}

static PyObject* pyrtnl_dump_filter(PyObject* obj, PyObject* args)
{
  PyRtnlObject* self = (PyRtnlObject*)obj;
  PyObject *filter;

  if (!PyArg_ParseTuple(args, "O:dump_filter", &filter))
    return NULL;

  if (!PyCallable_Check(filter)) {
    PyErr_SetString(PyExc_TypeError, "parameter must be callable");
    return NULL;
  }

  Py_INCREF(filter);
  if (rtnl_dump_filter(&self->rth, dump_filter_helper, filter, NULL,
                       NULL) < 0)
  {
    Py_DECREF(filter);
    return NULL;
  }
  Py_DECREF(filter);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef PyRtnl_methods[] = {
  { "talk", pyrtnl_talk, METH_VARARGS,
    "send a message to rtnetlink and receive a response.\n" },
  { "wilddump_request", pyrtnl_wilddump_request, METH_VARARGS,
    "dump objects.\n" },
  { "dump_request", pyrtnl_dump_request, METH_VARARGS,
    "start a dump of a particular netlink type.\n" },
  { "dump_filter", pyrtnl_dump_filter, METH_VARARGS,
    "iterate over an rtnl dump.\n" },
  { NULL }
};

static PyTypeObject PyRtnlType = {
  PyObject_HEAD_INIT(NULL)
  0,                          /* ob_size           */
  PKG ".rtnl",                /* tp_name           */
  sizeof(PyRtnlObject),       /* tp_basicsize      */
  0,                          /* tp_itemsize       */
  (destructor)PyRtnl_dealloc, /* tp_dealloc        */
  NULL,                       /* tp_print          */
  NULL,                       /* tp_getattr        */
  NULL,                       /* tp_setattr        */
  NULL,                       /* tp_compare        */
  NULL,                       /* tp_repr           */
  NULL,                       /* tp_as_number      */
  NULL,                       /* tp_as_sequence    */
  NULL,                       /* tp_as_mapping     */
  NULL,                       /* tp_hash           */
  NULL,                       /* tp_call           */
  NULL,                       /* tp_str            */
  NULL,                       /* tp_getattro       */
  NULL,                       /* tp_setattro       */
  NULL,                       /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,         /* tp_flags          */
  "rtnetlink handle",         /* tp_doc            */
  NULL,                       /* tp_traverse       */
  NULL,                       /* tp_clear          */
  NULL,                       /* tp_richcompare    */
  0,                          /* tp_weaklistoffset */
  NULL,                       /* tp_iter           */
  NULL,                       /* tp_iternext       */
  PyRtnl_methods,             /* tp_methods        */
  NULL,                       /* tp_members        */
  NULL,                       /* tp_getset         */
  NULL,                       /* tp_base           */
  NULL,                       /* tp_dict           */
  NULL,                       /* tp_descr_get      */
  NULL,                       /* tp_descr_set      */
  0,                          /* tp_dictoffset     */
  PyRtnl_init,                /* tp_init           */
  NULL,                       /* tp_alloc          */
  PyRtnl_new,                 /* tp_new            */
};

static PyMethodDef methods[] = {
  { NULL }
};

static char doc[] = "libnetlink wrapper";

PyMODINIT_FUNC initnetlink(void)
{
  PyObject *mod;

  if (PyType_Ready(&PyRtnlType) == -1)
    return;

  if (!(mod = Py_InitModule3(PKG, methods, doc)))
    return;

  Py_INCREF(&PyRtnlType);
  PyModule_AddObject(mod, "rtnl", (PyObject *)&PyRtnlType);
}
