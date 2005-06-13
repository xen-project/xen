#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "xs.h"

/** @file
 * Python interface to the Xen Store Daemon (xs).
 */

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define PYPKG    "xen.lowlevel.xs"

/** Python wrapper round an xs handle.
 */
typedef struct XsHandle {
    PyObject_HEAD;
    struct xs_handle *xh;
} XsHandle;

static inline struct xs_handle *xshandle(PyObject *self)
{
    struct xs_handle *xh = ((XsHandle*)self)->xh;
    if (!xh)
        PyErr_SetString(PyExc_RuntimeError, "invalid xenstore daemon handle");
    return xh;
}

static inline PyObject *pyvalue_int(int val) {
    return (val
            ? PyInt_FromLong(val)
            : PyErr_SetFromErrno(PyExc_RuntimeError));
}

static inline PyObject *pyvalue_str(char *val) {
    return (val
            ? PyString_FromString(val)
            : PyErr_SetFromErrno(PyExc_RuntimeError));
}

static PyObject *xspy_write(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "data", "create", "excl", NULL };
    static char *arg_spec = "ss#|ii";
    char *path = NULL;
    char *data = NULL;
    int data_n = 0;
    int create = 0;
    int excl = 0;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int flags = 0;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &path, &data, &data_n, &create, &excl))
        goto exit;
    if (create)
	flags |= O_CREAT;
    if (excl)
	flags |= O_EXCL;
    xsval = xs_write(xh, path, data, data_n, flags);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_read(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    char *xsval = NULL;
    unsigned int xsval_n = 0;
    PyObject *val = NULL;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &path))
        goto exit;
    xsval = xs_read(xh, path, &xsval_n);
    if (!xsval) {
        val = pyvalue_int(0);
        goto exit;
    }
    val = PyString_FromStringAndSize(xsval, xsval_n);
 exit:
    if (xsval)
	free(xsval);
    return val;
}

static PyObject *xspy_mkdir(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    xsval = xs_mkdir(xh, path);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_ls(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    char **xsval = NULL;
    unsigned int xsval_n = 0;
    int i;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    xsval = xs_directory(xh, path, &xsval_n);
    if (!xsval) {
        val = pyvalue_int(0);
        goto exit;
    }
    val = PyList_New(xsval_n);
    for (i = 0; i < xsval_n; i++)
        PyList_SetItem(val, i, PyString_FromString(xsval[i]));
 exit:
    return val;
}

static PyObject *xspy_rm(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    xsval = xs_rm(xh, path);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_get_permissions(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    struct xs_permissions *perms;
    unsigned int perms_n = 0;
    int i;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    perms = xs_get_permissions(xh, path, &perms_n);
    if (!perms) {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        goto exit;
    }
    val = PyList_New(perms_n);
    for (i = 0; i < perms_n; i++, perms++) {
        PyObject *p = Py_BuildValue("{s:i,s:i,s:i,s:i,s:i}",
                                    "dom",    perms->id,
                                    "read",   (perms->perms & XS_PERM_READ),
                                    "write",  (perms->perms & XS_PERM_WRITE),
                                    "create", (perms->perms & XS_PERM_CREATE),
                                    "owner",  (perms->perms & XS_PERM_OWNER));
        PyList_SetItem(val, i, p);
    }
 exit:
    return val;
}

static PyObject *xspy_set_permissions(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "perms", NULL };
    static char *arg_spec = "sO";
    char *path = NULL;
    PyObject *perms = NULL;
    static char *perm_names[] = { "dom", "read", "write", "create", "owner",
				  NULL };
    static char *perm_spec = "i|iiii";

    struct xs_handle *xh = xshandle(self);
    int i, xsval;
    struct xs_permissions *xsperms = NULL;
    int xsperms_n = 0;
    PyObject *tuple0 = NULL;
    PyObject *val = NULL;

    if (!xh)
        goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &path, &perms))
        goto exit;
    if (!PyList_Check(perms)) {
        PyErr_SetString(PyExc_RuntimeError, "perms must be a list");
        goto exit;
    }
    xsperms_n = PyList_Size(perms);
    xsperms = calloc(xsperms_n, sizeof(struct xs_permissions));
    if (!xsperms) {
        PyErr_SetString(PyExc_RuntimeError, "out of memory");
        goto exit;
    }
    tuple0 = PyTuple_New(0);
    if (!tuple0)
	goto exit;
    for (i = 0; i < xsperms_n; i++) {
        /* Domain the permissions apply to. */
        int dom = 0;
        /* Read/write perms. Set these. */
        int p_read = 0, p_write = 0;
        /* Create/owner perms. Ignore them.
         * This is so the output from get_permissions() can be used
         * as input to set_permissions().
         */
        int p_create = 0, p_owner = 0;
        PyObject *p = PyList_GetItem(perms, i);
        if (!PyArg_ParseTupleAndKeywords(tuple0, p, perm_spec, perm_names,
					 &dom, &p_read, &p_write, &p_create,
					 &p_owner))
            goto exit;
        xsperms[i].id = dom;
        if (p_read)
	    xsperms[i].perms |= XS_PERM_READ;
        if (p_write)
	    xsperms[i].perms |= XS_PERM_WRITE;
    }
    xsval = xs_set_permissions(xh, path, xsperms, xsperms_n);
    val = pyvalue_int(xsval);
 exit:
    Py_XDECREF(tuple0);
    if (xsperms)
	free(xsperms);
    return val;
}

static PyObject *xspy_watch(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "priority", NULL };
    static char *arg_spec = "s|i";
    char *path = NULL;
    int priority = 0;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, 
                                     &path, &priority))
        goto exit;
    xsval = xs_watch(xh, path, priority);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_read_watch(PyObject *self, PyObject *args,
				 PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    char *xsval = NULL;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    xsval = xs_read_watch(xh);
    val = pyvalue_str(xsval);
 exit:
    if (xsval)
	free(xsval);
    return val;
}

static PyObject *xspy_acknowledge_watch(PyObject *self, PyObject *args,
					PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    xsval = xs_acknowledge_watch(xh);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_unwatch(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    xsval = xs_unwatch(xh, path);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_transaction_start(PyObject *self, PyObject *args,
					PyObject *kwds)
{
    static char *kwd_spec[] = { "path", NULL };
    static char *arg_spec = "s|";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        goto exit;
    xsval = xs_transaction_start(xh, path);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_transaction_end(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
    static char *kwd_spec[] = { "abort", NULL };
    static char *arg_spec = "|i";
    int abort = 0;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &abort))
        goto exit;
    xsval = xs_transaction_end(xh, abort);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_introduce_domain(PyObject *self, PyObject *args,
				       PyObject *kwds)
{
    static char *kwd_spec[] = { "dom", "page", "port", "path", NULL };
    static char *arg_spec = "iiis|";
    domid_t dom = 0;
    unsigned long page = 0;
    unsigned int port = 0;
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &dom, &page, &port, &path))
        goto exit;
    printf("%s> dom=%u page=0x%08lx port=%u path=%s\n", __FUNCTION__, dom,
	   page, port, path);
    xsval = xs_introduce_domain(xh, dom, page, port, path);
    printf("%s> xsval=%d\n", __FUNCTION__, xsval);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_release_domain(PyObject *self, PyObject *args,
				     PyObject *kwds)
{
    static char *kwd_spec[] = { "dom", NULL };
    static char *arg_spec = "i|";
    domid_t dom;

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &dom))
        goto exit;
    printf("%s> dom=%u\n", __FUNCTION__, dom);
    xsval = xs_release_domain(xh, dom);
    printf("%s> xsval=%d\n", __FUNCTION__, xsval);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_close(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 1;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    xs_daemon_close(xh);
    ((XsHandle*)self)->xh = NULL;
    val = pyvalue_int(xsval);
 exit:
    return val;
}

static PyObject *xspy_shutdown(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    xsval = xs_shutdown(xh);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

#define XSPY_METH(_name) \
    #_name, \
    (PyCFunction) xspy_ ## _name, \
    (METH_VARARGS | METH_KEYWORDS)
// mtime
// ctime

static PyMethodDef xshandle_methods[] = {
    { XSPY_METH(read), 
      "read(path) : read data\n" },
    { XSPY_METH(write), 
      "write(path, data, [creat], [excl]): write data\n" },
    { XSPY_METH(ls), 
      "ls(path): list directory.\n" },
    { XSPY_METH(mkdir), 
      "mkdir(path): make a directory.\n" },
    { XSPY_METH(rm),
      "rm(path): remove a path (dir must be empty).\n" },
    { XSPY_METH(get_permissions),
      "get_permissions(path)\n" },
    { XSPY_METH(set_permissions),
      "set_permissions(path)\n" },
    { XSPY_METH(watch), 
      "watch(path)\n" },
    { XSPY_METH(read_watch), 
      "read_watch()\n" },
    { XSPY_METH(acknowledge_watch), 
      "acknowledge_watch()\n" },
    { XSPY_METH(unwatch), 
      "unwatch()\n" },
    { XSPY_METH(transaction_start), 
      "transaction_start()\n" },
    { XSPY_METH(transaction_end), 
      "transaction_end([abort])\n" },
    { XSPY_METH(introduce_domain), 
      "introduce_domain(dom, page, port)\n" },
    { XSPY_METH(release_domain), 
      "release_domain(dom)\n" },
    { XSPY_METH(close), 
      "close()\n" },
    { XSPY_METH(shutdown), 
      "shutdown()\n" },
    { NULL, NULL, 0, NULL }
};

static PyObject *xshandle_getattr(PyObject *self, char *name)
{
    PyObject *val = NULL;
    if (strcmp(name, "fileno") == 0) {
        struct xs_handle *xh = xshandle(self);
        val = PyInt_FromLong((xh ? xs_fileno(xh) : -1));
    } else
        val = Py_FindMethod(xshandle_methods, self, name);
    return val;
}

static void xshandle_dealloc(PyObject *self)
{
    XsHandle *xh = (XsHandle*)self;
    if (xh->xh) {
        xs_daemon_close(xh->xh);
        xh->xh = NULL;
    }
    PyObject_Del(self);
}

static PyTypeObject xshandle_type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "xshandle",
    sizeof(XsHandle),
    0,
    xshandle_dealloc,   /* tp_dealloc     */
    NULL,               /* tp_print       */
    xshandle_getattr,   /* tp_getattr     */
    NULL,               /* tp_setattr     */
    NULL,               /* tp_compare     */
    NULL,               /* tp_repr        */
    NULL,               /* tp_as_number   */
    NULL,               /* tp_as_sequence */
    NULL,               /* tp_as_mapping  */
    NULL                /* tp_hash        */
};

static PyObject *xshandle_open(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "readonly", NULL };
    static char *arg_spec = "|i";
    int readonly = 0;

    XsHandle *xsh = NULL;
    PyObject *val = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &readonly))
        goto exit;

    xsh = PyObject_New(XsHandle, &xshandle_type);
    if (!xsh)
	goto exit;
    xsh->xh = (readonly ? xs_daemon_open_readonly() : xs_daemon_open());
    if (!xsh->xh) {
        PyObject_Del(xsh);
        val = pyvalue_int(0);
        goto exit;
    }
    val = (PyObject *)xsh;
 exit:
    return val;
}

static PyMethodDef xs_methods[] = {
    { "open", (PyCFunction)xshandle_open, (METH_VARARGS | METH_KEYWORDS), 
      "Open a connection to the xenstore daemon.\n" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initxs (void)
{
    PyObject *module;

    module = Py_InitModule(PYPKG, xs_methods);
}
