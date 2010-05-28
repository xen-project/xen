/******************************************************************************
 * flask.c
 * 
 * Authors: George Coker, <gscoker@alpha.ncsc.mil>
 *          Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *    as published by the Free Software Foundation.
 */

#include <Python.h>
#include <xenctrl.h>
#include <libflask.h>

#define PKG "xen.lowlevel.flask"
#define CLS "flask"

#define CTX_LEN 1024

static PyObject *xc_error_obj;

typedef struct {
    PyObject_HEAD;
    xc_interface *xc_handle;
} XcObject;

static PyObject *pyflask_context_to_sid(PyObject *self, PyObject *args,
                                                                 PyObject *kwds)
{
    xc_interface *xc_handle;
    char *ctx;
    char *buf;
    uint32_t len;
    uint32_t sid;
    int ret;

    static char *kwd_list[] = { "context", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list,
                                      &ctx) )
        return NULL;

    len = strlen(ctx);

    buf = malloc(len);
    if (!buf) {
        errno = -ENOMEM;
        PyErr_SetFromErrno(xc_error_obj);
    }
    
    memcpy(buf, ctx, len);
    
    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        free(buf);
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = flask_context_to_sid(xc_handle, buf, len, &sid);
        
    xc_interface_close(xc_handle);

    free(buf);
    
    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return PyInt_FromLong(sid);
}

static PyObject *pyflask_sid_to_context(PyObject *self, PyObject *args,
                                                                 PyObject *kwds)
{
    xc_interface *xc_handle;
    uint32_t sid;
    char ctx[CTX_LEN];
    uint32_t ctx_len = CTX_LEN;
    int ret;

    static char *kwd_list[] = { "sid", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list,
                                      &sid) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = flask_sid_to_context(xc_handle, sid, ctx, ctx_len);
    
    xc_interface_close(xc_handle);
    
    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("s", ctx, ctx_len);
}

static PyObject *pyflask_load(PyObject *self, PyObject *args, PyObject *kwds)
{
    xc_interface *xc_handle;
    char *policy;
    uint32_t len;
    int ret;

    static char *kwd_list[] = { "policy", NULL };
  
    if( !PyArg_ParseTupleAndKeywords(args, kwds, "s#", kwd_list, &policy, &len) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }

    ret = flask_load(xc_handle, policy, len);

    xc_interface_close(xc_handle);

    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("i", ret);
}

static PyObject *pyflask_getenforce(PyObject *self)
{
    xc_interface *xc_handle;
    int ret;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = flask_getenforce(xc_handle);
    
    xc_interface_close(xc_handle);
    
    if ( ret < 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("i", ret);
}

static PyObject *pyflask_setenforce(PyObject *self, PyObject *args,
                                                            PyObject *kwds)
{
    xc_interface *xc_handle;
    int mode;
    int ret;

    static char *kwd_list[] = { "mode", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list,
                                      &mode) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = flask_setenforce(xc_handle, mode);
    
    xc_interface_close(xc_handle);
    
    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("i", ret);
}

static PyObject *pyflask_access(PyObject *self, PyObject *args,
                                                       PyObject *kwds)
{
    xc_interface *xc_handle;
    char *tcon, *scon;
    uint16_t tclass;
    uint32_t req, allowed, decided, auditallow, auditdeny, seqno;
    int ret;

    static char *kwd_list[] = { "src_context", "tar_context", 
                                "tar_class", "req_permissions",
                                "decided", "auditallow","auditdeny",
                                "seqno", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ssil|llll", kwd_list,
                                      &scon, &tcon, &tclass, &req, &decided,
                                      &auditallow, &auditdeny, &seqno) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = flask_access(xc_handle, scon, tcon, tclass, req, &allowed, &decided,
                        &auditallow, &auditdeny, &seqno);
        
    xc_interface_close(xc_handle);

    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("i",ret);
}

static PyMethodDef pyflask_methods[] = {
    { "flask_context_to_sid",
      (PyCFunction)pyflask_context_to_sid,
      METH_KEYWORDS, "\n"
      "Convert a context string to a dynamic SID.\n"
      " context [str]: String specifying context to be converted\n"
      "Returns: [int]: Numeric SID on success; -1 on error.\n" },

    { "flask_sid_to_context",
      (PyCFunction)pyflask_sid_to_context,
      METH_KEYWORDS, "\n"
      "Convert a dynamic SID to context string.\n"
      " context [int]: SID to be converted\n"
      "Returns: [str]: Numeric SID on success; -1 on error.\n" },

    { "flask_load",
      (PyCFunction)pyflask_load,
      METH_KEYWORDS, "\n"
      "Loads a policy into the hypervisor.\n"
      " policy [str]: policy to be load\n"
      "Returns: [int]: 0 on success; -1 on failure.\n" }, 
      
    { "flask_getenforce",
      (PyCFunction)pyflask_getenforce,
      METH_NOARGS, "\n"
      "Returns the current mode of the Flask XSM module.\n"
      "Returns: [int]: 0 for permissive; 1 for enforcing; -1 on failure.\n" }, 

    { "flask_setenforce",
      (PyCFunction)pyflask_setenforce,
      METH_KEYWORDS, "\n"
      "Modifies the current mode for the Flask XSM module.\n"
      " mode [int]: mode to change to\n"
      "Returns: [int]: 0 on success; -1 on failure.\n" }, 

    { "flask_access",
      (PyCFunction)pyflask_access,
      METH_KEYWORDS, "\n"
      "Returns whether a source context has access to target context based on \
       class and permissions requested.\n"
      " scon [str]: source context\n"
      " tcon [str]: target context\n"
      " tclass [int]: target security class\n"
      " req [int] requested permissions\n"
      " allowed [int] permissions allow for the target class between the source \
        and target context\n"
      " decided [int] the permissions that were returned in the allowed \
        parameter\n"
      " auditallow [int] permissions set to audit on allow\n"
      " auditdeny [int] permissions set to audit on deny\n"
      " seqno [int] not used\n"
      "Returns: [int]: 0 on all permission granted; -1 if any permissions are \
       denied\n" }, 
    { NULL, NULL, 0, NULL }

};

PyMODINIT_FUNC initflask(void)
{
    Py_InitModule("flask", pyflask_methods);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
