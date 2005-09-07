/* 
 * Python interface to the Xen Store Daemon.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General Public
 * License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright (C) 2005 Mike Wray Hewlett-Packard
 * Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
 *
 */

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
    PyObject *watches;
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

#define xspy_read_doc "\n"			\
	"Read data from a path.\n"		\
	" path [string]: xenstore path\n"	\
	"\n"					\
	"Returns: [string] data read.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

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

#define xspy_write_doc "\n"					\
	"Write data to a path.\n"				\
	" path   [string] : xenstore path to write to\n."	\
	" data   [string] : data to write.\n"			\
	" create [int]    : create flag, default 0.\n"		\
	" excl   [int]    : exclusive flag, default 0.\n"	\
	"\n"							\
	"Returns: [int] 0 on success.\n"			\
	"Raises RuntimeError on error.\n"			\
	"\n"

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

#define xspy_ls_doc "\n"					\
	"List a directory.\n"					\
	" path [string]: path to list.\n"			\
	"\n"							\
	"Returns: [string array] list of subdirectory names.\n"	\
	"Raises RuntimeError on error.\n"			\
	"\n"

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

#define xspy_mkdir_doc "\n"					\
	"Make a directory.\n"					\
	" path [string]: path to directory to create.\n"	\
	"\n"							\
	"Returns: [int] 0 on success.\n"			\
	"Raises RuntimeError on error.\n"			\
	"\n"

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

#define xspy_rm_doc "\n"			\
	"Remove a path.\n"			\
	" path [string] : path to remove\n"	\
	"\n"					\
	"Returns: [int] 0 on success.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

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

#define xspy_get_permissions_doc "\n"		\
	"Get the permissions for a path\n"	\
	" path [string]: xenstore path.\n"	\
	"\n"					\
	"Returns: permissions array.\n"		\
	"Raises RuntimeError on error.\n"	\
	"\n"

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
        PyObject *p = Py_BuildValue("{s:i,s:i,s:i}",
                                    "dom",   perms->id,
                                    "read",  (perms->perms & XS_PERM_READ),
                                    "write",  (perms->perms & XS_PERM_WRITE));
        PyList_SetItem(val, i, p);
    }
 exit:
    return val;
}

#define xspy_set_permissions_doc "\n"		\
	"Set the permissions for a path\n"	\
	" path  [string] : xenstore path.\n"	\
	" perms          : permissions.\n"	\
	"\n"					\
	"Returns: [int] 0 on success.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_set_permissions(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "perms", NULL };
    static char *arg_spec = "sO";
    char *path = NULL;
    PyObject *perms = NULL;
    static char *perm_names[] = { "dom", "read", "write", NULL };
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
        PyObject *p = PyList_GetItem(perms, i);
        if (!PyArg_ParseTupleAndKeywords(tuple0, p, perm_spec, perm_names,
					 &dom, &p_read, &p_write))
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

#define xspy_watch_doc "\n"						\
	"Watch a path, get notifications when it changes.\n"		\
	" path     [string] : xenstore path.\n"				\
	" token    [string] : returned in watch notification.\n"	\
	"\n"								\
	"Returns: [int] 0 on success.\n"				\
	"Raises RuntimeError on error.\n"				\
	"\n"

/* Each 10 bits takes ~ 3 digits, plus one, plus one for nul terminator. */
#define MAX_STRLEN(x) ((sizeof(x) * CHAR_BIT + CHAR_BIT-1) / 10 * 3 + 2)

static PyObject *xspy_watch(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "token", NULL };
    static char *arg_spec = "sO";
    char *path = NULL;
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];
    int i;

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, 
                                     &path, &token))
        goto exit;
    Py_INCREF(token);
    sprintf(token_str, "%li", (unsigned long)token);
    xsval = xs_watch(xh, path, token_str);
    val = pyvalue_int(xsval);
    if (xsval) {
	for (i = 0; i < PyList_Size(xsh->watches); i++) {
	    if (PyList_GetItem(xsh->watches, i) == Py_None) {
		PyList_SetItem(xsh->watches, i, token);
		break;
	    }
	}
	if (i == PyList_Size(xsh->watches))
	    PyList_Append(xsh->watches, token);
    } else
	Py_DECREF(token);
 exit:
    return val;
}

#define xspy_read_watch_doc "\n"				\
	"Read a watch notification.\n"				\
	"The notification must be acknowledged by passing\n"	\
	"the token to acknowledge_watch().\n"			\
	" path [string]: xenstore path.\n"			\
	"\n"							\
	"Returns: [tuple] (path, token).\n"			\
	"Raises RuntimeError on error.\n"			\
	"\n"

static PyObject *xspy_read_watch(PyObject *self, PyObject *args,
				 PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    char **xsval = NULL;
    PyObject *token;
    int i;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    xsval = xs_read_watch(xh);
    if (!xsval) {
	val = PyErr_SetFromErrno(PyExc_RuntimeError);
	goto exit;
    }
    if (sscanf(xsval[1], "%li", (unsigned long *)&token) != 1) {
	PyErr_SetString(PyExc_RuntimeError, "invalid token");
	goto exit;
    }
    for (i = 0; i < PyList_Size(xsh->watches); i++) {
	if (token == PyList_GetItem(xsh->watches, i))
	    break;
    }
    if (i == PyList_Size(xsh->watches)) {
	PyErr_SetString(PyExc_RuntimeError, "invalid token");
	goto exit;
    }
    /* Create tuple (path, token). */
    val = Py_BuildValue("(sO)", xsval[0], token);
 exit:
    if (xsval)
	free(xsval);
    return val;
}

#define xspy_acknowledge_watch_doc "\n"					\
	"Acknowledge a watch notification that has been read.\n"	\
	" token [string] : from the watch notification\n"		\
	"\n"								\
	"Returns: [int] 0 on success.\n"				\
	"Raises RuntimeError on error.\n"				\
	"\n"

static PyObject *xspy_acknowledge_watch(PyObject *self, PyObject *args,
					PyObject *kwds)
{
    static char *kwd_spec[] = { "token", NULL };
    static char *arg_spec = "O";
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &token))
        goto exit;
    sprintf(token_str, "%li", (unsigned long)token);
    xsval = xs_acknowledge_watch(xh, token_str);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

#define xspy_unwatch_doc "\n"				\
	"Stop watching a path.\n"			\
	" path  [string] : xenstore path.\n"		\
	" token [string] : token from the watch.\n"	\
	"\n"						\
	"Returns: [int] 0 on success.\n"		\
	"Raises RuntimeError on error.\n"		\
	"\n"

static PyObject *xspy_unwatch(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "token", NULL };
    static char *arg_spec = "sO";
    char *path = NULL;
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];
    int i;

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 0;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path,
				     &token))
        goto exit;
    sprintf(token_str, "%li", (unsigned long)token);
    xsval = xs_unwatch(xh, path, token_str);
    val = pyvalue_int(xsval);
    for (i = 0; i < PyList_Size(xsh->watches); i++) {
	if (token == PyList_GetItem(xsh->watches, i)) {
	    Py_INCREF(Py_None);
	    PyList_SetItem(xsh->watches, i, Py_None);
	    break;
	}
    }
 exit:
    return val;
}

#define xspy_transaction_start_doc "\n"				\
	"Start a transaction on a path.\n"			\
	"Only one transaction can be active at a time.\n"	\
	" path [string]: xenstore path.\n"			\
	"\n"							\
	"Returns: [int] 0 on success.\n"			\
	"Raises RuntimeError on error.\n"			\
	"\n"

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

#define xspy_transaction_end_doc "\n"					\
	"End the current transaction.\n"				\
	"Attempts to commit the transaction unless abort is true.\n"	\
	" abort [int]: abort flag (default 0).\n"			\
	"\n"								\
	"Returns: [int] 0 on success.\n"				\
	"Raises RuntimeError on error.\n"				\
	"\n"

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

#define xspy_introduce_domain_doc "\n"					\
	"Tell xenstore about a domain so it can talk to it.\n"		\
	" dom  [int]   : domain id\n"					\
	" page [long]  : address of domain's xenstore page\n"		\
	" port [int]   : port the domain is using for xenstore\n"	\
	" path [string]: path to the domain's data in xenstore\n"	\
	"\n"								\
	"Returns: [int] 0 on success.\n"				\
	"Raises RuntimeError on error.\n"				\
	"\n"

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
    xsval = xs_introduce_domain(xh, dom, page, port, path);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

#define xspy_release_domain_doc "\n"					\
	"Tell xenstore to release its channel to a domain.\n"		\
	"Unless this is done the domain will not be released.\n"	\
	" dom [int]: domain id\n"					\
	"\n"								\
	"Returns: [int] 0 on success.\n"				\
	"Raises RuntimeError on error.\n"				\
	"\n"

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
    xsval = xs_release_domain(xh, dom);
    val = pyvalue_int(xsval);
 exit:
    return val;
}

#define xspy_close_doc "\n"			\
	"Close the connection to xenstore.\n"	\
	"\n"					\
	"Returns: [int] 0 on success.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_close(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";
    int i;

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    int xsval = 1;

    if (!xh)
	goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    for (i = 0; i < PyList_Size(xsh->watches); i++) {
	/* TODO: xs_unwatch watches */
	Py_INCREF(Py_None);
	PyList_SetItem(xsh->watches, i, Py_None);
    }
    xs_daemon_close(xh);
    xsh->xh = NULL;
    val = pyvalue_int(xsval);
 exit:
    return val;
}

#define xspy_shutdown_doc "\n"			\
	"Shutdown the xenstore daemon.\n"	\
	"\n"					\
	"Returns: [int] 0 on success.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

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

#define xspy_fileno_doc "\n"					\
	"Get the file descriptor of the xenstore socket.\n"	\
	"Allows an xs object to be passed to select().\n"	\
	"\n"							\
	"Returns: [int] file descriptor.\n"			\
	"\n"

static PyObject *xspy_fileno(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";

    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        goto exit;
    val = PyInt_FromLong((xh ? xs_fileno(xh) : -1));
 exit:
    return val;
}

#define XSPY_METH(_name) {			\
    .ml_name  = #_name,				\
    .ml_meth  = (PyCFunction) xspy_ ## _name,	\
    .ml_flags = (METH_VARARGS | METH_KEYWORDS),	\
    .ml_doc   = xspy_ ## _name ## _doc }

static PyMethodDef xshandle_methods[] = {
     XSPY_METH(read),
     XSPY_METH(write),
     XSPY_METH(ls),
     XSPY_METH(mkdir),
     XSPY_METH(rm),
     XSPY_METH(get_permissions),
     XSPY_METH(set_permissions),
     XSPY_METH(watch),
     XSPY_METH(read_watch),
     XSPY_METH(acknowledge_watch),
     XSPY_METH(unwatch),
     XSPY_METH(transaction_start),
     XSPY_METH(transaction_end),
     XSPY_METH(introduce_domain),
     XSPY_METH(release_domain),
     XSPY_METH(close),
     XSPY_METH(shutdown),
     XSPY_METH(fileno),
     { /* Terminator. */ },
};

static PyObject *xshandle_getattr(PyObject *self, char *name)
{
    PyObject *val = NULL;
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
	return NULL;

    xsh = PyObject_New(XsHandle, &xshandle_type);
    if (!xsh)
	return NULL;
    xsh->watches = PyList_New(0);
    if (!xsh->watches)
	goto exit;
    xsh->xh = (readonly ? xs_daemon_open_readonly() : xs_daemon_open());
    if (!xsh->xh) {
	Py_DECREF(xsh->watches);
        goto exit;
    }
    val = (PyObject *)xsh;
    return val;
 exit:
    PyObject_Del(xsh);
    return NULL;
}

static PyMethodDef xs_methods[] = {
    { .ml_name  = "open",
      .ml_meth  = (PyCFunction)xshandle_open,
      .ml_flags = (METH_VARARGS | METH_KEYWORDS), 
      .ml_doc   = "\n"
      "Open a connection to the xenstore daemon.\n"
      "Returns: xs connection object.\n"
      "Raises RuntimeError on error.\n"
      "\n"
    },
    { /* Terminator. */ }
};

PyMODINIT_FUNC initxs (void)
{
    PyObject *module;

    module = Py_InitModule(PYPKG, xs_methods);
}
