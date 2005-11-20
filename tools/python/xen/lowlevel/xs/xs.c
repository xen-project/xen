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
 * Copyright (C) 2005 XenSource Ltd.
 */

#include <Python.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <xenctrl.h>
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

static void remove_watch(XsHandle *xsh, PyObject *token);

static PyObject *none(bool result);

static int parse_transaction_path(PyObject *self, PyObject *args,
                                  PyObject *kwds,
                                  struct xs_handle **xh,
                                  struct xs_transaction_handle **th,
                                  char **path);


#define xspy_read_doc "\n"			\
	"Read data from a path.\n"		\
	" path [string]: xenstore path\n"	\
	"\n"					\
	"Returns: [string] data read.\n"	\
	"         None if key doesn't exist.\n"	\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_read(PyObject *self, PyObject *args, PyObject *kwds)
{
    struct xs_handle *xh;
    struct xs_transaction_handle *th;
    char *path;

    char *xsval;
    unsigned int xsval_n;

    if (!parse_transaction_path(self, args, kwds, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    xsval = xs_read(xh, th, path, &xsval_n);
    Py_END_ALLOW_THREADS
    if (xsval) {
        PyObject *val = PyString_FromStringAndSize(xsval, xsval_n);
        free(xsval);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}


#define xspy_write_doc "\n"					\
	"Write data to a path.\n"				\
	" path   [string] : xenstore path to write to\n."	\
	" data   [string] : data to write.\n"			\
	"\n"							\
	"Returns None on success.\n"				\
	"Raises RuntimeError on error.\n"			\
	"\n"

static PyObject *xspy_write(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "transaction", "path", "data", NULL };
    static char *arg_spec = "sss#";
    char *path = NULL;
    char *data = NULL;
    int data_n = 0;

    struct xs_handle *xh = xshandle(self);
    bool result;

    struct xs_transaction_handle *th;
    char *thstr;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, &path, &data, &data_n))
        return NULL;

    th = (struct xs_transaction_handle *)strtoul(thstr, NULL, 16);

    Py_BEGIN_ALLOW_THREADS
    result = xs_write(xh, th, path, data, data_n);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_ls_doc "\n"					\
	"List a directory.\n"					\
	" path [string]: path to list.\n"			\
	"\n"							\
	"Returns: [string array] list of subdirectory names.\n"	\
	"         None if key doesn't exist.\n"			\
	"Raises RuntimeError on error.\n"			\
	"\n"

static PyObject *xspy_ls(PyObject *self, PyObject *args, PyObject *kwds)
{
    struct xs_handle *xh;
    struct xs_transaction_handle *th;
    char *path;

    char **xsval;
    unsigned int xsval_n;

    if (!parse_transaction_path(self, args, kwds, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    xsval = xs_directory(xh, th, path, &xsval_n);
    Py_END_ALLOW_THREADS

    if (xsval) {
        int i;
        PyObject *val = PyList_New(xsval_n);
        for (i = 0; i < xsval_n; i++)
            PyList_SetItem(val, i, PyString_FromString(xsval[i]));
        free(xsval);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}


#define xspy_mkdir_doc "\n"					\
	"Make a directory.\n"					\
	" path [string]: path to directory to create.\n"	\
	"\n"							\
	"Returns None on success.\n"				\
	"Raises RuntimeError on error.\n"			\
	"\n"

static PyObject *xspy_mkdir(PyObject *self, PyObject *args, PyObject *kwds)
{
    struct xs_handle *xh;
    struct xs_transaction_handle *th;
    char *path;

    bool result;

    if (!parse_transaction_path(self, args, kwds, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_mkdir(xh, th, path);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_rm_doc "\n"			\
	"Remove a path.\n"			\
	" path [string] : path to remove\n"	\
	"\n"					\
	"Returns None on success.\n"		\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_rm(PyObject *self, PyObject *args, PyObject *kwds)
{
    struct xs_handle *xh;
    struct xs_transaction_handle *th;
    char *path;

    bool result;

    if (!parse_transaction_path(self, args, kwds, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_rm(xh, th, path);
    Py_END_ALLOW_THREADS

    return none(result || errno == ENOENT);
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
    static char *kwd_spec[] = { "transaction", "path", NULL };
    static char *arg_spec = "ss";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    struct xs_permissions *perms;
    unsigned int perms_n = 0;
    int i;

    struct xs_transaction_handle *th;
    char *thstr;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, &path))
        return NULL;

    th = (struct xs_transaction_handle *)strtoul(thstr, NULL, 16);

    Py_BEGIN_ALLOW_THREADS
    perms = xs_get_permissions(xh, th, path, &perms_n);
    Py_END_ALLOW_THREADS

    if (perms) {
        PyObject *val = PyList_New(perms_n);
        for (i = 0; i < perms_n; i++, perms++) {
            PyObject *p = Py_BuildValue("{s:i,s:i,s:i}",
                                        "dom",  perms->id,
                                        "read", perms->perms & XS_PERM_READ,
                                        "write",perms->perms & XS_PERM_WRITE);
            PyList_SetItem(val, i, p);
        }

        free(perms);
        return val;
    }
    else {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        return NULL;
    }
}

#define xspy_set_permissions_doc "\n"		\
	"Set the permissions for a path\n"	\
	" path  [string] : xenstore path.\n"	\
	" perms          : permissions.\n"	\
	"\n"					\
	"Returns None on success.\n"		\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_set_permissions(PyObject *self, PyObject *args,
                                      PyObject *kwds)
{
    static char *kwd_spec[] = { "transaction", "path", "perms", NULL };
    static char *arg_spec = "ssO";
    char *path = NULL;
    PyObject *perms = NULL;
    static char *perm_names[] = { "dom", "read", "write", NULL };
    static char *perm_spec = "i|iiii";

    struct xs_handle *xh = xshandle(self);
    int i, result;
    struct xs_permissions *xsperms = NULL;
    int xsperms_n = 0;
    PyObject *tuple0 = NULL;
    PyObject *val = NULL;

    struct xs_transaction_handle *th;
    char *thstr;

    if (!xh)
        goto exit;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, &path, &perms))
        goto exit;

    th = (struct xs_transaction_handle *)strtoul(thstr, NULL, 16);

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
    Py_BEGIN_ALLOW_THREADS
    result = xs_set_permissions(xh, th, path, xsperms, xsperms_n);
    Py_END_ALLOW_THREADS
    if (!result) {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        goto exit;
    }
    Py_INCREF(Py_None);
    val = Py_None;
 exit:
    Py_XDECREF(tuple0);
    free(xsperms);
    return val;
}

#define xspy_watch_doc "\n"						\
	"Watch a path, get notifications when it changes.\n"		\
	" path     [string] : xenstore path.\n"				\
	" token    [string] : returned in watch notification.\n"	\
	"\n"								\
	"Returns None on success.\n"					\
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
    int result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, 
                                     &path, &token))
        return NULL;

    /* Note that we have to store the watch token in the xs->watches list
       before registering the watch with xs_watch, otherwise this function
       races with xs_read_watch.
    */

    for (i = 0; i < PyList_Size(xsh->watches); i++) {
        if (PyList_GetItem(xsh->watches, i) == Py_None) {
            PySequence_SetItem(xsh->watches, i, token);
            break;
        }
    }
    if (i == PyList_Size(xsh->watches))
        PyList_Append(xsh->watches, token);

    sprintf(token_str, "%li", (unsigned long)token);
    Py_BEGIN_ALLOW_THREADS
    result = xs_watch(xh, path, token_str);
    Py_END_ALLOW_THREADS

    if (!result)
        remove_watch(xsh, token);

    return none(result);
}


#define xspy_read_watch_doc "\n"				\
	"Read a watch notification.\n"				\
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
    unsigned int num;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        return NULL;

again:
    Py_BEGIN_ALLOW_THREADS
    xsval = xs_read_watch(xh, &num);
    Py_END_ALLOW_THREADS
    if (!xsval) {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        goto exit;
    }
    if (sscanf(xsval[XS_WATCH_TOKEN], "%li", (unsigned long *)&token) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "invalid token");
        goto exit;
    }
    for (i = 0; i < PyList_Size(xsh->watches); i++) {
        if (token == PyList_GetItem(xsh->watches, i))
            break;
    }
    if (i == PyList_Size(xsh->watches)) {
      /* We do not have a registered watch for the one that has just fired.
         Ignore this -- a watch that has been recently deregistered can still
         have watches in transit.  This is a blocking method, so go back to
         read again.
      */
      free(xsval);
      goto again;
    }
    /* Create tuple (path, token). */
    val = Py_BuildValue("(sO)", xsval[XS_WATCH_PATH], token);
 exit:
    free(xsval);
    return val;
}

#define xspy_unwatch_doc "\n"				\
	"Stop watching a path.\n"			\
	" path  [string] : xenstore path.\n"		\
	" token [string] : token from the watch.\n"	\
	"\n"						\
	"Returns None on success.\n"			\
	"Raises RuntimeError on error.\n"		\
	"\n"

static PyObject *xspy_unwatch(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "path", "token", NULL };
    static char *arg_spec = "sO";
    char *path = NULL;
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);
    int result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path,
                                     &token))
        return NULL;

    sprintf(token_str, "%li", (unsigned long)token);
    Py_BEGIN_ALLOW_THREADS
    result = xs_unwatch(xh, path, token_str);
    Py_END_ALLOW_THREADS

    remove_watch(xsh, token);

    return none(result);
}

#define xspy_transaction_start_doc "\n"				\
	"Start a transaction.\n"				\
	"\n"							\
	"Returns transaction handle on success.\n"		\
	"Raises RuntimeError on error.\n"			\
	"\n"

static PyObject *xspy_transaction_start(PyObject *self, PyObject *args,
                                        PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    struct xs_transaction_handle *th;
    char thstr[20];

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    th = xs_transaction_start(xh);
    Py_END_ALLOW_THREADS

    if (th == NULL) {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        return NULL;
    }

    sprintf(thstr, "%lX", (unsigned long)th);
    return PyString_FromString(thstr);
}

#define xspy_transaction_end_doc "\n"					\
	"End the current transaction.\n"				\
	"Attempts to commit the transaction unless abort is true.\n"	\
	" abort [int]: abort flag (default 0).\n"			\
	"\n"								\
	"Returns True on success, False if you need to try again.\n"	\
	"Raises RuntimeError on error.\n"				\
	"\n"

static PyObject *xspy_transaction_end(PyObject *self, PyObject *args,
                                      PyObject *kwds)
{
    static char *kwd_spec[] = { "transaction", "abort", NULL };
    static char *arg_spec = "s|i";
    int abort = 0;

    struct xs_handle *xh = xshandle(self);
    bool result;

    struct xs_transaction_handle *th;
    char *thstr;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, &abort))
        return NULL;

    th = (struct xs_transaction_handle *)strtoul(thstr, NULL, 16);

    Py_BEGIN_ALLOW_THREADS
    result = xs_transaction_end(xh, th, abort);
    Py_END_ALLOW_THREADS

    if (result) {
        Py_INCREF(Py_True);
        return Py_True;
    }
    else if (errno == EAGAIN) {
        Py_INCREF(Py_False);
        return Py_False;
    }
    else {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        return NULL;
    }
}


#define xspy_introduce_domain_doc "\n"					\
	"Tell xenstore about a domain so it can talk to it.\n"		\
	" dom  [int]   : domain id\n"					\
	" page [long]  : address of domain's xenstore page\n"		\
	" port [int]   : port the domain is using for xenstore\n"	\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises RuntimeError on error.\n"				\
	"\n"

static PyObject *xspy_introduce_domain(PyObject *self, PyObject *args,
                                       PyObject *kwds)
{
    static char *kwd_spec[] = { "dom", "page", "port", NULL };
    static char *arg_spec = "ili";
    domid_t dom = 0;
    unsigned long page = 0;
    unsigned int port = 0;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &dom, &page, &port))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_introduce_domain(xh, dom, page, port);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_release_domain_doc "\n"					\
	"Tell xenstore to release its channel to a domain.\n"		\
	"Unless this is done the domain will not be released.\n"	\
	" dom [int]: domain id\n"					\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises RuntimeError on error.\n"				\
	"\n"

static PyObject *xspy_release_domain(PyObject *self, PyObject *args,
                                     PyObject *kwds)
{
    static char *kwd_spec[] = { "dom", NULL };
    static char *arg_spec = "i";
    domid_t dom;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &dom))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_release_domain(xh, dom);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_close_doc "\n"			\
	"Close the connection to xenstore.\n"	\
	"\n"					\
	"Returns None on success.\n"		\
	"Raises RuntimeError on error.\n"	\
	"\n"

static PyObject *xspy_close(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { NULL };
    static char *arg_spec = "";
    int i;

    XsHandle *xsh = (XsHandle *)self;
    struct xs_handle *xh = xshandle(self);

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec))
        return NULL;

    for (i = 0; i < PyList_Size(xsh->watches); i++) {
        /* TODO: xs_unwatch watches */
        PySequence_SetItem(xsh->watches, i, Py_None);
    }

    xs_daemon_close(xh);
    xsh->xh = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}


#define xspy_get_domain_path_doc "\n"			\
	"Return store path of domain, whether or not the domain exists.\n" \
	" domid [int]: domain id\n"			\
	"\n"						\
	"Returns: [string] domain store path.\n"	\
	"Raises RuntimeError on error.\n"		\
	"\n"

static PyObject *xspy_get_domain_path(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
    static char *kwd_spec[] = { "domid", NULL };
    static char *arg_spec = "i";
    int domid = 0;

    struct xs_handle *xh = xshandle(self);
    char *xsval = NULL;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &domid))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    xsval = xs_get_domain_path(xh, domid);
    Py_END_ALLOW_THREADS

    if (xsval) {
        PyObject *val = PyString_FromString(xsval);
        free(xsval);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}


/**
 * Remove the given token from the watches list belonging to the given
 * XsHandle, if present.
 */
static void remove_watch(XsHandle *xsh, PyObject *token)
{
    int i;

    for (i = 0; i < PyList_Size(xsh->watches); i++) {
        if (PyList_GetItem(xsh->watches, i) == token) {
            PySequence_SetItem(xsh->watches, i, Py_None);
            return;
        }
    }
}


/**
 * Parse transaction and path arguments from the given args and kwds,
 * convert the given self value to an xs_handle, and return all three by
 * reference.
 * 
 * @return 1 on success, in which case *xh, *th, and *path are valid, or 0 on
 * failure.
 */
static int parse_transaction_path(PyObject *self, PyObject *args,
                                  PyObject *kwds,
                                  struct xs_handle **xh,
                                  struct xs_transaction_handle **th,
                                  char **path)
{
    static char *arg_spec = "ss";
    static char *kwd_spec[] = { "transaction", "path", NULL };
    char *thstr;

    *xh = xshandle(self);

    if (!xh)
        return 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, path))
        return 0;

    *th = (struct xs_transaction_handle *)strtoul(thstr, NULL, 16);

    return 1;
}


static PyObject *none(bool result)
{
    if (result) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        return NULL;
    }
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
     XSPY_METH(unwatch),
     XSPY_METH(transaction_start),
     XSPY_METH(transaction_end),
     XSPY_METH(introduce_domain),
     XSPY_METH(release_domain),
     XSPY_METH(close),
     XSPY_METH(get_domain_path),
     { /* Terminator. */ },
};

static PyObject *xshandle_getattr(PyObject *self, char *name)
{
    return Py_FindMethod(xshandle_methods, self, name);
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
        PyErr_SetFromErrno(PyExc_RuntimeError);
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


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
