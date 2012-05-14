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
#include <errno.h>

#include <xenstore.h>

/** @file
 * Python interface to the Xen Store Daemon (xs).
 */

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define PKG "xen.lowlevel.xs"
#define CLS "xs"

static PyObject *xs_error;

/** Python wrapper round an xs handle.
 */
typedef struct XsHandle {
    PyObject_HEAD;
    struct xs_handle *xh;
    PyObject *watches;
} XsHandle;

static void xs_set_error(int value)
{
	errno = value;
	PyErr_SetFromErrno(xs_error);
}

static inline struct xs_handle *xshandle(XsHandle *self)
{
    struct xs_handle *xh = self->xh;
    if (!xh)
	xs_set_error(EINVAL);
    return xh;
}

static void remove_watch(XsHandle *xsh, PyObject *token);

static PyObject *none(bool result);

static int parse_transaction_path(XsHandle *self, PyObject *args,
                                  struct xs_handle **xh,
                                  xs_transaction_t *th,
                                  char **path);


#define xspy_read_doc "\n"                              \
	"Read data from a path.\n"                      \
	" transaction [string]: transaction handle\n"	\
	" path [string]:        xenstore path\n"	\
	"\n"                                            \
	"Returns: [string] data read.\n"                \
	"         None if key doesn't exist.\n"         \
	"Raises xen.lowlevel.xs.Error on error.\n"               \
	"\n"

static PyObject *xspy_read(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh;
    xs_transaction_t th;
    char *path;

    char *xsval;
    unsigned int xsval_n;

    if (!parse_transaction_path(self, args, &xh, &th, &path))
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
	" transaction [string]: transaction handle\n"           \
	" path   [string] : xenstore path to write to\n."	\
	" data   [string] : data to write.\n"			\
	"\n"							\
	"Returns None on success.\n"				\
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_write(XsHandle *self, PyObject *args)
{
    static char *arg_spec = "sss#";
    struct xs_handle *xh = xshandle(self);
    xs_transaction_t th;
    char *thstr;
    char *path;
    char *data;
    int data_n;
    bool result;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, arg_spec, &thstr, &path, &data, &data_n))
        return NULL;

    th = strtoul(thstr, NULL, 16);

    Py_BEGIN_ALLOW_THREADS
    result = xs_write(xh, th, path, data, data_n);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_ls_doc "\n"					\
	"List a directory.\n"					\
	" transaction [string]: transaction handle\n"           \
	" path [string]:        path to list.\n"                \
	"\n"							\
	"Returns: [string array] list of subdirectory names.\n"	\
	"         None if key doesn't exist.\n"			\
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_ls(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh;
    xs_transaction_t th;
    char *path;

    char **xsval;
    unsigned int xsval_n;

    if (!parse_transaction_path(self, args, &xh, &th, &path))
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
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_mkdir(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh;
    xs_transaction_t th;
    char *path;

    bool result;

    if (!parse_transaction_path(self, args, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_mkdir(xh, th, path);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define xspy_rm_doc "\n"                                \
	"Remove a path.\n"                              \
	" transaction [string]: transaction handle\n"	\
	" path [string] : path to remove\n"             \
	"\n"                                            \
	"Returns None on success.\n"                    \
	"Raises xen.lowlevel.xs.Error on error.\n"               \
	"\n"

static PyObject *xspy_rm(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh;
    xs_transaction_t th;
    char *path;

    bool result;

    if (!parse_transaction_path(self, args, &xh, &th, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_rm(xh, th, path);
    Py_END_ALLOW_THREADS

    return none(result || errno == ENOENT);
}


#define xspy_get_permissions_doc "\n"                   \
	"Get the permissions for a path\n"              \
	" transaction [string]: transaction handle\n"	\
	" path [string]:        xenstore path.\n"       \
	"\n"                                            \
	"Returns: permissions array.\n"                 \
	"Raises xen.lowlevel.xs.Error on error.\n"               \
	"\n"

static PyObject *xspy_get_permissions(XsHandle *self, PyObject *args)
{
    static char *arg_spec = "ss";
    char *path = NULL;

    struct xs_handle *xh = xshandle(self);
    struct xs_permissions *perms;
    unsigned int perms_n = 0;
    int i;

    xs_transaction_t th;
    char *thstr;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, arg_spec, &thstr, &path))
        return NULL;

    th = strtoul(thstr, NULL, 16);

    Py_BEGIN_ALLOW_THREADS
    perms = xs_get_permissions(xh, th, path, &perms_n);
    Py_END_ALLOW_THREADS

    if (perms) {
        PyObject *val = PyList_New(perms_n);
        for (i = 0; i < perms_n; i++) {
            PyObject *p =
                Py_BuildValue("{s:i,s:i,s:i}",
                              "dom",   perms[i].id,
                              "read",  perms[i].perms & XS_PERM_READ,
                              "write", perms[i].perms & XS_PERM_WRITE);
            PyList_SetItem(val, i, p);
        }

        free(perms);
        return val;
    }
    else {
        PyErr_SetFromErrno(xs_error);
        return NULL;
    }
}

#define xspy_set_permissions_doc "\n"                   \
	"Set the permissions for a path\n"              \
	" transaction [string]: transaction handle\n"	\
	" path  [string]      : xenstore path.\n"	\
	" perms               : permissions.\n"         \
	"\n"                                            \
	"Returns None on success.\n"                    \
	"Raises xen.lowlevel.xs.Error on error.\n"               \
	"\n"

static PyObject *xspy_set_permissions(XsHandle *self, PyObject *args)
{
    char *path;
    PyObject *perms;
    static char *perm_names[] = { "dom", "read", "write", NULL };
    static char *perm_spec = "i|ii";

    struct xs_handle *xh = xshandle(self);
    int i, result;
    struct xs_permissions *xsperms = NULL;
    int xsperms_n;
    PyObject *tuple0 = NULL;

    xs_transaction_t th;
    char *thstr;
    PyObject *ret = NULL;

    if (!xh)
        goto exit;
    if (!PyArg_ParseTuple(args, "ssO", &thstr, &path, &perms))
        goto exit;

    th = strtoul(thstr, NULL, 16);

    if (!PyList_Check(perms)) {
	xs_set_error(EINVAL);
        goto exit;
    }

    xsperms_n = PyList_Size(perms);
    /* NB. alloc +1 so we can change the owner if necessary. */
    xsperms = calloc(xsperms_n + 1, sizeof(struct xs_permissions));
    if (!xsperms) {
	xs_set_error(ENOMEM);
        goto exit;
    }

    tuple0 = PyTuple_New(0);
    if (!tuple0)
        goto exit;

    for (i = 0; i < xsperms_n; i++) {
        /* Read/write perms. Set these. */
        int p_read = 0, p_write = 0;
        PyObject *p = PyList_GetItem(perms, i);
        if (!PyArg_ParseTupleAndKeywords(tuple0, p, perm_spec, perm_names,
                                         &xsperms[i].id, &p_read, &p_write))
            goto exit;
        if (p_read)
            xsperms[i].perms |= XS_PERM_READ;
        if (p_write)
            xsperms[i].perms |= XS_PERM_WRITE;
    }

    /*
     * Is the caller trying to restrict access to the first specified
     * domain? If so then it cannot be owner, so we force dom0 as owner.
     */
    if (xsperms_n && xsperms[0].perms && xsperms[0].id) {
        memmove(&xsperms[1], &xsperms[0], xsperms_n * sizeof(*xsperms));
        xsperms[0].id = xsperms[0].perms = 0;
        xsperms_n++;
    }

    Py_BEGIN_ALLOW_THREADS
    result = xs_set_permissions(xh, th, path, xsperms, xsperms_n);
    Py_END_ALLOW_THREADS
    if (!result) {
        PyErr_SetFromErrno(xs_error);
        goto exit;
    }

    Py_INCREF(Py_None);
    ret = Py_None;

 exit:
    Py_XDECREF(tuple0);
    free(xsperms);
    return ret;
}

#define xspy_watch_doc "\n"						\
	"Watch a path, get notifications when it changes.\n"		\
	" path     [string] : xenstore path.\n"				\
	" token    [string] : returned in watch notification.\n"	\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises xen.lowlevel.xs.Error on error.\n"				\
	"\n"

/* Each 10 bits takes ~ 3 digits, plus one, plus one for nul terminator. */
#define MAX_STRLEN(x) ((sizeof(x) * CHAR_BIT + CHAR_BIT-1) / 10 * 3 + 2)

static PyObject *xspy_watch(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh = xshandle(self);
    char *path;
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];
    int result;
    int i;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "sO", &path, &token))
        return NULL;

    /* Note that we have to store the watch token in the xs->watches list
       before registering the watch with xs_watch, otherwise this function
       races with xs_read_watch.
    */

    for (i = 0; i < PyList_Size(self->watches); i++) {
        if (PyList_GetItem(self->watches, i) == Py_None) {
            PySequence_SetItem(self->watches, i, token);
            break;
        }
    }
    if (i == PyList_Size(self->watches))
        PyList_Append(self->watches, token);

    snprintf(token_str, sizeof(token_str), "%li", (unsigned long)token);
    Py_BEGIN_ALLOW_THREADS
    result = xs_watch(xh, path, token_str);
    Py_END_ALLOW_THREADS

    if (!result)
        remove_watch(self, token);

    return none(result);
}


#define xspy_read_watch_doc "\n"				\
	"Read a watch notification.\n"				\
	"\n"							\
	"Returns: [tuple] (path, token).\n"			\
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_read_watch(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh = xshandle(self);
    PyObject *val = NULL;
    char **xsval;
    PyObject *token;
    int i;
    unsigned int num;

    if (!xh)
        return NULL;

again:
    Py_BEGIN_ALLOW_THREADS
    xsval = xs_read_watch(xh, &num);
    Py_END_ALLOW_THREADS
    if (!xsval) {
        PyErr_SetFromErrno(xs_error);
        goto exit;
    }
    if (sscanf(xsval[XS_WATCH_TOKEN], "%li", (unsigned long *)&token) != 1) {
	xs_set_error(EINVAL);
        goto exit;
    }
    for (i = 0; i < PyList_Size(self->watches); i++) {
        if (token == PyList_GetItem(self->watches, i))
            break;
    }
    if (i == PyList_Size(self->watches)) {
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
	"Raises xen.lowlevel.xs.Error on error.\n"		\
	"\n"

static PyObject *xspy_unwatch(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh = xshandle(self);
    char *path;
    PyObject *token;
    char token_str[MAX_STRLEN(unsigned long) + 1];
    int result;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "sO", &path, &token))
        return NULL;

    snprintf(token_str, sizeof(token_str), "%li", (unsigned long)token);
    Py_BEGIN_ALLOW_THREADS
    result = xs_unwatch(xh, path, token_str);
    Py_END_ALLOW_THREADS

    remove_watch(self, token);

    return none(result);
}

#define xspy_transaction_start_doc "\n"				\
	"Start a transaction.\n"				\
	"\n"							\
	"Returns transaction handle on success.\n"		\
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_transaction_start(XsHandle *self)
{
    struct xs_handle *xh = xshandle(self);
    xs_transaction_t th;
    char thstr[MAX_STRLEN(unsigned long) + 1];

    if (!xh)
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    th = xs_transaction_start(xh);
    Py_END_ALLOW_THREADS

    if (th == XBT_NULL) {
        PyErr_SetFromErrno(xs_error);
        return NULL;
    }

    snprintf(thstr, sizeof(thstr), "%lX", (unsigned long)th);
    return PyString_FromString(thstr);
}

#define xspy_transaction_end_doc "\n"					\
	"End the current transaction.\n"				\
	"Attempts to commit the transaction unless abort is true.\n"	\
	" abort [int]: abort flag (default 0).\n"			\
	"\n"								\
	"Returns True on success, False if you need to try again.\n"	\
	"Raises xen.lowlevel.xs.Error on error.\n"				\
	"\n"

static PyObject *xspy_transaction_end(XsHandle *self, PyObject *args,
                                      PyObject *kwds)
{
    static char *kwd_spec[] = { "transaction", "abort", NULL };
    static char *arg_spec = "s|i";
    int abort = 0;

    struct xs_handle *xh = xshandle(self);
    bool result;

    xs_transaction_t th;
    char *thstr;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &thstr, &abort))
        return NULL;

    th = strtoul(thstr, NULL, 16);

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
        PyErr_SetFromErrno(xs_error);
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
	"Raises xen.lowlevel.xs.Error on error.\n"				\
	"\n"

static PyObject *xspy_introduce_domain(XsHandle *self, PyObject *args)
{
    uint32_t dom;
    unsigned long page;
    unsigned int port;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "ili", &dom, &page, &port))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_introduce_domain(xh, dom, page, port);
    Py_END_ALLOW_THREADS

    return none(result);
}

#define xspy_set_target_doc "\n"					\
        "Tell xenstore that a domain is targetting another one so it\n" \
        "should let it tinker with it.\n"	                        \
	" dom    [int]   : domain id\n"					\
	" target [int]   : domain id of the target\n"			\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises xen.lowlevel.xs.Error on error.\n"			\
	"\n"

static PyObject *xspy_set_target(XsHandle *self, PyObject *args)
{
    uint32_t dom;
    uint32_t target;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "ii", &dom, &target))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_set_target(xh, dom, target);
    Py_END_ALLOW_THREADS

    return none(result);
}

#define xspy_resume_domain_doc "\n"                                \
	"Tell xenstore to clear its shutdown flag for a domain.\n" \
	"This ensures that a subsequent shutdown will fire the\n"  \
	"appropriate watches.\n"                                   \
	" dom [int]: domain id\n"			           \
        "\n"						           \
        "Returns None on success.\n"				   \
        "Raises xen.lowlevel.xs.Error on error.\n"

static PyObject *xspy_resume_domain(XsHandle *self, PyObject *args)
{
    uint32_t dom;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = xs_resume_domain(xh, dom);
    Py_END_ALLOW_THREADS

    return none(result);
}

#define xspy_release_domain_doc "\n"					\
	"Tell xenstore to release its channel to a domain.\n"		\
	"Unless this is done the domain will not be released.\n"	\
	" dom [int]: domain id\n"					\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises xen.lowlevel.xs.Error on error.\n"				\
	"\n"

static PyObject *xspy_release_domain(XsHandle *self, PyObject *args)
{
    uint32_t dom;

    struct xs_handle *xh = xshandle(self);
    bool result = 0;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "i", &dom))
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
	"Raises xen.lowlevel.xs.Error on error.\n"	\
	"\n"

static PyObject *xspy_close(XsHandle *self)
{
    struct xs_handle *xh = xshandle(self);
    int i;

    if (!xh)
        return NULL;

    for (i = 0; i < PyList_Size(self->watches); i++) {
        /* TODO: xs_unwatch watches */
        PySequence_SetItem(self->watches, i, Py_None);
    }

    xs_daemon_close(xh);
    self->xh = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}


#define xspy_get_domain_path_doc "\n"			\
	"Return store path of domain, whether or not the domain exists.\n" \
	" domid [int]: domain id\n"			\
	"\n"						\
	"Returns: [string] domain store path.\n"	\
	"Raises xen.lowlevel.xs.Error on error.\n"		\
	"\n"

static PyObject *xspy_get_domain_path(XsHandle *self, PyObject *args)
{
    struct xs_handle *xh = xshandle(self);
    uint32_t domid;
    char *xsval;

    if (!xh)
        return NULL;
    if (!PyArg_ParseTuple(args, "i", &domid))
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
static void remove_watch(XsHandle *self, PyObject *token)
{
    int i;

    for (i = 0; i < PyList_Size(self->watches); i++) {
        if (PyList_GetItem(self->watches, i) == token) {
            PySequence_SetItem(self->watches, i, Py_None);
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
static int parse_transaction_path(XsHandle *self, PyObject *args,
                                  struct xs_handle **xh,
                                  xs_transaction_t *th,
                                  char **path)
{
    char *thstr;

    *xh = xshandle(self);

    if (!xh)
        return 0;

    if (!PyArg_ParseTuple(args, "ss", &thstr, path))
        return 0;

    *th = strtoul(thstr, NULL, 16);

    return 1;
}


static PyObject *none(bool result)
{
    if (result) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else {
        PyErr_SetFromErrno(xs_error);
        return NULL;
    }
}


#define XSPY_METH(_name, _args) {               \
    .ml_name  = #_name,				\
    .ml_meth  = (PyCFunction) xspy_ ## _name,	\
    .ml_flags = _args,                          \
    .ml_doc   = xspy_ ## _name ## _doc }

static PyMethodDef xshandle_methods[] = {
    XSPY_METH(read,              METH_VARARGS),
    XSPY_METH(write,             METH_VARARGS),
    XSPY_METH(ls,                METH_VARARGS),
    XSPY_METH(mkdir,             METH_VARARGS),
    XSPY_METH(rm,                METH_VARARGS),
    XSPY_METH(get_permissions,   METH_VARARGS),
    XSPY_METH(set_permissions,   METH_VARARGS),
    XSPY_METH(watch,             METH_VARARGS),
    XSPY_METH(read_watch,        METH_NOARGS),
    XSPY_METH(unwatch,           METH_VARARGS),
    XSPY_METH(transaction_start, METH_NOARGS),
    XSPY_METH(transaction_end,   METH_VARARGS | METH_KEYWORDS),
    XSPY_METH(introduce_domain,  METH_VARARGS),
    XSPY_METH(set_target,        METH_VARARGS),
    XSPY_METH(resume_domain,     METH_VARARGS),
    XSPY_METH(release_domain,    METH_VARARGS),
    XSPY_METH(close,             METH_NOARGS),
    XSPY_METH(get_domain_path,   METH_VARARGS),
    { NULL /* Sentinel. */ },
};

static PyObject *xshandle_getattr(PyObject *self, char *name)
{
    return Py_FindMethod(xshandle_methods, self, name);
}

static PyObject *
xshandle_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    XsHandle *self = (XsHandle *)type->tp_alloc(type, 0);

    if (self == NULL)
        return NULL;

    self->xh = NULL;
    self->watches = PyList_New(0);
    if (!self->watches)
        goto fail;

    return (PyObject *)self;
fail:
    /* Decreasing the object's reference to 0 will result in xshandle_dealloc
       being called. */
    Py_DECREF(self);
    return NULL;
}

static int
xshandle_init(XsHandle *self, PyObject *args, PyObject *kwds)
{
    static char *kwd_spec[] = { "readonly", NULL };
    static char *arg_spec = "|i";
    int readonly = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_spec, kwd_spec,
                                     &readonly))
        goto fail;

    self->xh = (readonly ? xs_daemon_open_readonly() : xs_daemon_open());
    if (!self->xh)
        goto fail;

    return 0;

 fail:
    PyErr_SetFromErrno(xs_error);
    return -1;
}

static void xshandle_dealloc(XsHandle *self)
{
    if (self->xh) {
        xs_daemon_close(self->xh);
        self->xh = NULL;
    }

    Py_XDECREF(self->watches);

    self->ob_type->tp_free((PyObject *)self);
}

static PyTypeObject xshandle_type = {
    PyObject_HEAD_INIT(NULL)
    0,
    PKG "." CLS,
    sizeof(XsHandle),
    0,
    (destructor)xshandle_dealloc, /* tp_dealloc        */
    NULL,                         /* tp_print          */
    xshandle_getattr,             /* tp_getattr        */
    NULL,                         /* tp_setattr        */
    NULL,                         /* tp_compare        */
    NULL,                         /* tp_repr           */
    NULL,                         /* tp_as_number      */
    NULL,                         /* tp_as_sequence    */
    NULL,                         /* tp_as_mapping     */
    NULL,                         /* tp_hash           */
    NULL,                         /* tp_call           */
    NULL,                         /* tp_str            */
    NULL,                         /* tp_getattro       */
    NULL,                         /* tp_setattro       */
    NULL,                         /* tp_as_buffer      */
    Py_TPFLAGS_DEFAULT,           /* tp_flags          */
    "Xenstore connections",       /* tp_doc            */
    NULL,                         /* tp_traverse       */
    NULL,                         /* tp_clear          */
    NULL,                         /* tp_richcompare    */
    0,                            /* tp_weaklistoffset */
    NULL,                         /* tp_iter           */
    NULL,                         /* tp_iternext       */
    xshandle_methods,             /* tp_methods        */
    NULL,                         /* tp_members        */
    NULL,                         /* tp_getset         */
    NULL,                         /* tp_base           */
    NULL,                         /* tp_dict           */
    NULL,                         /* tp_descr_get      */
    NULL,                         /* tp_descr_set      */
    0,                            /* tp_dictoffset     */
    (initproc)xshandle_init,      /* tp_init           */
    NULL,                         /* tp_alloc          */
    xshandle_new,                 /* tp_new            */
};

static PyMethodDef xs_methods[] = { { NULL } };

PyMODINIT_FUNC initxs(void)
{
    PyObject* m;

    if (PyType_Ready(&xshandle_type) < 0)
        return;

    m = Py_InitModule(PKG, xs_methods);

    if (m == NULL)
      return;

    xs_error = PyErr_NewException(PKG ".Error", PyExc_RuntimeError, NULL);

    Py_INCREF(&xshandle_type);
    PyModule_AddObject(m, CLS, (PyObject *)&xshandle_type);

    Py_INCREF(xs_error);
    PyModule_AddObject(m, "Error", xs_error);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
