/******************************************************************************
 * ptsname.c
 * 
 * A python extension to expose the POSIX ptsname() function.
 * 
 * Copyright (C) 2007 XenSource Ltd
 */

#include <Python.h>
#include <stdlib.h>

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

static PyObject *do_ptsname(PyObject *self, PyObject *args)
{
    int fd;
    char *path;

    if (!PyArg_ParseTuple(args, "i", &fd))
        return NULL;

    path = ptsname(fd);

    if (!path)
    {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    } 

    return PyString_FromString(path);
}

static PyMethodDef ptsname_methods[] = { 
    { "ptsname", do_ptsname, METH_VARARGS }, 
    { NULL }
};

PyMODINIT_FUNC initptsname(void)
{
    Py_InitModule("ptsname", ptsname_methods);
}
