/******************************************************************************
 * xl.c
 *
 * Copyright (c) 2010 Citrix Ltd.
 * Author: Gianni Tedesco
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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <Python.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define CLS "ctx"

#if PY_MAJOR_VERSION < 2 || (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION < 5)
#define Py_ssize_t int
#endif

static PyObject *xl_error_obj;

int genwrap__obj_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *key, *value;
    Py_ssize_t pos = 0;

    if ( NULL == kwds )
        return 0;

    while (PyDict_Next(kwds, &pos, &key, &value)) {
        if ( PyObject_SetAttr(self, key, value) < 0 )
            return -1;
    }

    return 0;
}

int genwrap__string_set(PyObject *v, char **str)
{
    char *tmp;
    if ( NULL == v || Py_None == v ) {
        free(*str);
        *str = NULL;
        return 0;
    }
    if ( !PyString_Check(v) ) {
        PyErr_SetString(PyExc_TypeError, "Attribute expected string");
        return -1;
    }
    tmp = strdup(PyString_AsString(v));
    if ( NULL == tmp ) {
        PyErr_SetString(PyExc_MemoryError, "Allocating string attribute");
        return -1;
    }
    free(*str);
    *str = tmp;
    return 0;
}

PyObject *genwrap__string_get(char **str)
{
    if ( NULL == *str ) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    return PyString_FromString(*str);
}

PyObject *genwrap__ull_get(unsigned long long val)
{
    return PyLong_FromUnsignedLongLong(val);
}

int genwrap__ull_set(PyObject *v, unsigned long long *val, unsigned long long mask)
{
    unsigned long long tmp;
    if ( NULL == v ) {
        *val = 0;
        return 0;
    }
    if ( PyLong_Check(v) ) {
        tmp = PyLong_AsUnsignedLongLong(v);
    }else if ( PyInt_Check(v) ) {
        tmp = (unsigned long long)PyInt_AsLong(v);
    }else{
        PyErr_SetString(PyExc_TypeError, "Attribute expected int or long");
        return -1;
    }
    if ( tmp & ~mask ) {
        PyErr_SetString(PyExc_ValueError, "Integer overflow");
        return -1;
    }
    *val = tmp;
    return 0;
}

PyObject *genwrap__ll_get(long long val)
{
    return PyLong_FromLongLong(val);
}

int genwrap__ll_set(PyObject *v, long long *val, long long mask)
{
    long long tmp;
    if ( NULL == v ) {
        *val = 0;
        return 0;
    }
    if ( PyLong_Check(v) ) {
        tmp = PyLong_AsLongLong(v);
    }else{
        tmp = (long long)PyInt_AsLong(v);
    }
    if ( tmp & ~mask ) {
        PyErr_SetString(PyExc_ValueError, "Integer overflow");
        return -1;
    }
    *val = tmp;
    return 0;
}

PyObject *genwrap__defbool_get(libxl_defbool *db)
{
    PyObject *ret;
    ret = libxl_defbool_val(*db) ? Py_True : Py_False;
    Py_INCREF(ret);
    return ret;
}

int genwrap__defbool_set(PyObject *v, libxl_defbool *db)
{
    bool val = !(NULL == v || Py_None == v || Py_False == v);
    libxl_defbool_set(db, val);
    return 0;
}

static int fixed_bytearray_set(PyObject *v, uint8_t *ptr, size_t len)
{
    char *tmp;
    size_t sz;

    if ( NULL == v ) {
        memset(ptr, 0, len);
        return 0;
    }

#ifdef PyByteArray_Check
    if ( PyByteArray_Check(v) ) {
        sz = PyByteArray_Size(v);
        tmp = PyByteArray_AsString(v);
    }else
#endif
    if ( PyString_Check(v) ) {
        Py_ssize_t ssz;
        if ( PyString_AsStringAndSize(v, &tmp, &ssz) )
            return -1;
        if ( ssz < 0 )
            tmp = NULL;
        sz = ssz;
    }else{
        PyErr_SetString(PyExc_TypeError, "Attribute expected bytearray or string");
        return -1;
    }

    if ( NULL == tmp ) {
        memset(ptr, 0, len);
        return 0;
    }
    if ( sz != len ) {
        PyErr_SetString(PyExc_ValueError,
                        (sz < len) ? "Buffer underflow" : "Buffer overflow");
        return -1;
    }

    memcpy(ptr, tmp, sz);
    return 0;
}

static PyObject *fixed_bytearray_get(const uint8_t *ptr, size_t len)
{
#ifdef PyByteArray_Check
    return PyByteArray_FromStringAndSize((const char *)ptr, len);
#else
    return PyString_FromStringAndSize((const char *)ptr, len);
#endif
}

#include "_pyxl_types.h"

int attrib__libxl_cpuid_policy_list_set(PyObject *v, libxl_cpuid_policy_list *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Setting cpuid_policy_list");
    return -1;
}

int attrib__libxl_bitmap_set(PyObject *v, libxl_bitmap *pptr)
{
    int i;
    long cpu;

    for (i = 0; i < PyList_Size(v); i++) {
        cpu = PyInt_AsLong(PyList_GetItem(v, i));
        libxl_bitmap_set(pptr, cpu);
    }
    return 0;
}

int attrib__libxl_hwcap_set(PyObject *v, libxl_hwcap *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Setting hwcap");
    return -1;
}

int attrib__libxl_key_value_list_set(PyObject *v, libxl_key_value_list *pptr)
{
    if ( *pptr ) {
        libxl_key_value_list_dispose(pptr);
        *pptr = NULL;
    }
    if ( v == Py_None )
        return 0;
    return -1;
}

int attrib__libxl_mac_set(PyObject *v, libxl_mac *pptr)
{
    return fixed_bytearray_set(v, *pptr, 6);
}

int attrib__libxl_string_list_set(PyObject *v, libxl_string_list *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Setting string_list");
    return -1;
}

int attrib__libxl_uuid_set(PyObject *v, libxl_uuid *pptr)
{
    return fixed_bytearray_set(v, libxl_uuid_bytearray(pptr), 16);
}

int attrib__libxl_domid_set(PyObject *v, libxl_domid *domid) {
    *domid = PyInt_AsLong(v);
    return 0;
}

int attrib__libxl_devid_set(PyObject *v, libxl_devid *devid) {
   *devid = PyInt_AsLong(v);
   return 0;
}

int attrib__struct_in_addr_set(PyObject *v, struct in_addr *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Setting in_addr");
    return -1;
}

PyObject *attrib__libxl_cpuid_policy_list_get(libxl_cpuid_policy_list *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Getting cpuid_policy_list");
    return NULL;
}

PyObject *attrib__libxl_bitmap_get(libxl_bitmap *pptr)
{
    PyObject *cpulist = NULL;
    int i;

    cpulist = PyList_New(0);
    libxl_for_each_bit(i, *pptr) {
        if ( libxl_bitmap_test(pptr, i) ) {
            PyObject* pyint = PyInt_FromLong(i);

            PyList_Append(cpulist, pyint);
            Py_DECREF(pyint);
        }
    }
    return cpulist;
}

PyObject *attrib__libxl_hwcap_get(libxl_hwcap *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Getting hwcap");
    return NULL;
}

PyObject *attrib__libxl_key_value_list_get(libxl_key_value_list *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Getting key_value_list");
    return NULL;
}

PyObject *attrib__libxl_mac_get(libxl_mac *pptr)
{
    return fixed_bytearray_get(*pptr, 6);
}

PyObject *attrib__libxl_string_list_get(libxl_string_list *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Getting string_list");
    return NULL;
}

PyObject *attrib__libxl_uuid_get(libxl_uuid *pptr)
{
    return fixed_bytearray_get(libxl_uuid_bytearray(pptr), 16);
}

PyObject *attrib__libxl_domid_get(libxl_domid *domid) {
    return PyInt_FromLong(*domid);
}

PyObject *attrib__libxl_devid_get(libxl_devid *devid) {
    return PyInt_FromLong(*devid);
}

PyObject *attrib__struct_in_addr_get(struct in_addr *pptr)
{
    PyErr_SetString(PyExc_NotImplementedError, "Getting in_addr");
    return NULL;
}

typedef struct {
    PyObject_HEAD;
    libxl_ctx *ctx;
    xentoollog_logger_stdiostream *logger;
    xentoollog_level minmsglevel;
} XlObject;

static PyObject *pyxl_list_domains(XlObject *self)
{
    libxl_dominfo *cur, *info;
    PyObject *list;
    int nr_dom, i;

    info = libxl_list_domain(self->ctx, &nr_dom);
    if ( NULL == info )
        return PyList_New(0);

    list = PyList_New(nr_dom);
    if ( NULL == list )
        goto err_mem;

    for(i = 0, cur = info; i < nr_dom; i++, cur++) {
        Py_dominfo *di;
        di = Pydominfo_New();
        if ( NULL == di )
            goto err_mem;
        memcpy(&di->obj, cur, sizeof(di->obj));
        /* SetItem steals a reference */
        PyList_SetItem(list, i, (PyObject *)di);
    }

    free(info);
    return list;
err_mem:
    Py_DECREF(list);
    PyErr_SetString(PyExc_MemoryError, "Allocating domain list");
    return NULL;
}

static PyObject *pyxl_domid_to_name(XlObject *self, PyObject *args)
{
    char *domname;
    int domid;
    PyObject *ret = Py_None;

    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;

    domname = libxl_domid_to_name(self->ctx, domid);
    if (domname)
        ret = PyString_FromString(domname);
    else
        Py_INCREF(Py_None);
    free(domname);

    return ret;
}

static PyObject *pyxl_domain_shutdown(XlObject *self, PyObject *args)
{
    int domid;
    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;
    if ( libxl_domain_shutdown(self->ctx, domid) ) {
        PyErr_SetString(xl_error_obj, "cannot shutdown domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_domain_reboot(XlObject *self, PyObject *args)
{
    int domid;
    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;
    if ( libxl_domain_reboot(self->ctx, domid) ) {
        PyErr_SetString(xl_error_obj, "cannot reboot domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_domain_destroy(XlObject *self, PyObject *args)
{
    int domid;
    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;
    if ( libxl_domain_destroy(self->ctx, domid, 0) ) {
        PyErr_SetString(xl_error_obj, "cannot destroy domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_domain_pause(XlObject *self, PyObject *args)
{
    int domid;
    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;
    if ( libxl_domain_pause(self->ctx, domid) ) {
        PyErr_SetString(xl_error_obj, "cannot pause domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_domain_unpause(XlObject *self, PyObject *args)
{
    int domid;
    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;
    if ( libxl_domain_unpause(self->ctx, domid) ) {
        PyErr_SetString(xl_error_obj, "cannot unpause domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_domain_rename(XlObject *self, PyObject *args)
{
    char *old_name = NULL, *new_name;
    int domid;
    if ( !PyArg_ParseTuple(args, "is|s", &domid, &new_name, &old_name) )
        return NULL;
    if ( libxl_domain_rename(self->ctx, domid, old_name, new_name) ) {
        PyErr_SetString(xl_error_obj, "cannot rename domain");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_pci_add(XlObject *self, PyObject *args)
{
    Py_device_pci *pci;
    PyObject *obj;
    int domid;
    if ( !PyArg_ParseTuple(args, "iO", &domid, &obj) )
        return NULL;
    if ( !Pydevice_pci_Check(obj) ) {
        PyErr_SetString(PyExc_TypeError, "Xxpected xl.device_pci");
        return NULL;
    }
    pci = (Py_device_pci *)obj;
    if ( libxl_device_pci_add(self->ctx, domid, &pci->obj, 0) ) {
        PyErr_SetString(xl_error_obj, "cannot add pci device");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_pci_del(XlObject *self, PyObject *args)
{
    Py_device_pci *pci;
    PyObject *obj;
    int domid, force = 0;

    if ( !PyArg_ParseTuple(args, "iO|i", &domid, &obj, &force) )
        return NULL;
    if ( !Pydevice_pci_Check(obj) ) {
        PyErr_SetString(PyExc_TypeError, "Xxpected xl.device_pci");
        return NULL;
    }
    pci = (Py_device_pci *)obj;
    if ( force ) {
        if ( libxl_device_pci_destroy(self->ctx, domid, &pci->obj, 0) ) {
            PyErr_SetString(xl_error_obj, "cannot remove pci device");
            return NULL;
        }
    } else {
        if ( libxl_device_pci_remove(self->ctx, domid, &pci->obj, 0) ) {
            PyErr_SetString(xl_error_obj, "cannot remove pci device");
            return NULL;
        }
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyxl_pci_parse(XlObject *self, PyObject *args)
{
    Py_device_pci *pci;
    char *str;

    if ( !PyArg_ParseTuple(args, "s", &str) )
        return NULL;

    pci = Pydevice_pci_New();
    if ( NULL == pci ) {
        PyErr_SetString(PyExc_MemoryError, "Allocating domain list");
        return NULL;
    }

    if ( xlu_pci_parse_bdf(NULL, &pci->obj, str) ) {
        PyErr_SetString(xl_error_obj, "cannot parse pci device spec (BDF)");
        Py_DECREF(pci);
        return NULL;
    }

    return (PyObject *)pci;
}

static PyObject *pyxl_pci_assignable_list(XlObject *self, PyObject *args)
{
    libxl_device_pci *dev;
    PyObject *list;
    int nr_dev, i;

    dev = libxl_device_pci_assignable_list(self->ctx, &nr_dev);
    if ( dev == NULL ) {
        PyErr_SetString(xl_error_obj, "Cannot list assignable devices");
        return NULL;
    }

    list = PyList_New(nr_dev);
    if ( NULL == list )
        return NULL;

    for(i = 0; i < nr_dev; i++) {
        Py_device_pci *pd;
        pd = Pydevice_pci_New();
        if ( NULL == pd )
            goto err_mem;
        memcpy(&pd->obj, &dev[i], sizeof(pd->obj));
        /* SetItem steals a reference */
        PyList_SetItem(list, i, (PyObject *)pd);
    }

    free(dev);
    return list;
err_mem:
    Py_DECREF(list);
    PyErr_SetString(PyExc_MemoryError, "Allocating PCI device list");
    return NULL;
}

static PyObject *pyxl_pci_list(XlObject *self, PyObject *args)
{
    libxl_device_pci *dev;
    PyObject *list;
    int nr_dev, i, domid;

    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;

    dev = libxl_device_pci_list(self->ctx, domid, &nr_dev);
    if ( dev == NULL ) {
        PyErr_SetString(xl_error_obj, "Cannot list assignable devices");
        return NULL;
    }

    list = PyList_New(nr_dev);
    if ( NULL == list )
        return NULL;

    for(i = 0; i < nr_dev; i++) {
        Py_device_pci *pd;
        pd = Pydevice_pci_New();
        if ( NULL == pd )
            goto err_mem;
        memcpy(&pd->obj, &dev[i], sizeof(pd->obj));
        /* SetItem steals a reference */
        PyList_SetItem(list, i, (PyObject *)pd);
    }

    free(dev);
    return list;
err_mem:
    Py_DECREF(list);
    PyErr_SetString(PyExc_MemoryError, "Allocating PCI device list");
    return NULL;
}

static PyMethodDef pyxl_methods[] = {
    {"list_domains", (PyCFunction)pyxl_list_domains, METH_NOARGS,
         "List domains"},
    {"domid_to_name", (PyCFunction)pyxl_domid_to_name, METH_VARARGS,
         "Retrieve name from domain-id"},
    {"domain_shutdown", (PyCFunction)pyxl_domain_shutdown, METH_VARARGS,
         "Shutdown a domain"},
    {"domain_reboot", (PyCFunction)pyxl_domain_reboot, METH_VARARGS,
         "Reboot a domain"},
    {"domain_destroy", (PyCFunction)pyxl_domain_destroy, METH_VARARGS,
         "Destroy a domain"},
    {"domain_pause", (PyCFunction)pyxl_domain_pause, METH_VARARGS,
         "Pause a domain"},
    {"domain_unpause", (PyCFunction)pyxl_domain_unpause, METH_VARARGS,
         "Unpause a domain"},
    {"domain_rename", (PyCFunction)pyxl_domain_rename, METH_VARARGS,
         "Rename a domain"},
    {"device_pci_add", (PyCFunction)pyxl_pci_add, METH_VARARGS,
         "Insert a pass-through PCI device"},
    {"device_pci_del", (PyCFunction)pyxl_pci_del, METH_VARARGS,
         "Remove a pass-through PCI device"},
    {"device_pci_parse_bdf", (PyCFunction)pyxl_pci_parse, METH_VARARGS,
         "Parse pass-through PCI device spec (BDF)"},
    {"device_pci_list", (PyCFunction)pyxl_pci_list, METH_VARARGS,
        "List PCI devices assigned to a domain"},
    {"device_pci_assignable_list",
        (PyCFunction)pyxl_pci_assignable_list, METH_NOARGS,
        "List assignable PCI devices"},
    { NULL, NULL, 0, NULL }
};

static PyObject *PyXl_getattr(PyObject *obj, char *name)
{
    return Py_FindMethod(pyxl_methods, obj, name);
}

static PyObject *PyXl_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    XlObject *self = (XlObject *)type->tp_alloc(type, 0);

    if (self == NULL)
        return NULL;

    self->ctx = NULL;
    self->logger = NULL;
    self->minmsglevel = XTL_PROGRESS;

    return (PyObject *)self;
}

static int
PyXl_init(XlObject *self, PyObject *args, PyObject *kwds)
{
    self->logger = xtl_createlogger_stdiostream(stderr, self->minmsglevel,  0);
    if (!self->logger) {
        PyErr_SetString(xl_error_obj, "cannot init xl logger");
        return -1;
    }

    if ( libxl_ctx_alloc(&self->ctx, LIBXL_VERSION, 0,
                (xentoollog_logger*)self->logger) ) {
        PyErr_SetString(xl_error_obj, "cannot init xl context");
        return -1;
    }

    return 0;
}

static void PyXl_dealloc(XlObject *self)
{
    libxl_ctx_free(self->ctx);
    if ( self->logger )
        xtl_logger_destroy((xentoollog_logger*)self->logger);

    self->ob_type->tp_free((PyObject *)self);
}

static PyTypeObject PyXlType = {
    PyObject_HEAD_INIT(NULL)
    0,
    PKG "." CLS,
    sizeof(XlObject),
    0,
    (destructor)PyXl_dealloc,     /* tp_dealloc        */
    NULL,                         /* tp_print          */
    PyXl_getattr,                 /* tp_getattr        */
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
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE, /* tp_flags          */
    "libxenlight connection",     /* tp_doc            */
    NULL,                         /* tp_traverse       */
    NULL,                         /* tp_clear          */
    NULL,                         /* tp_richcompare    */
    0,                            /* tp_weaklistoffset */
    NULL,                         /* tp_iter           */
    NULL,                         /* tp_iternext       */
    pyxl_methods,                 /* tp_methods        */
    NULL,                         /* tp_members        */
    NULL,                         /* tp_getset         */
    NULL,                         /* tp_base           */
    NULL,                         /* tp_dict           */
    NULL,                         /* tp_descr_get      */
    NULL,                         /* tp_descr_set      */
    0,                            /* tp_dictoffset     */
    (initproc)PyXl_init,          /* tp_init           */
    NULL,                         /* tp_alloc          */
    PyXl_new,                     /* tp_new            */
};

static PyMethodDef xl_methods[] = { { NULL } };

#define  _INT_CONST(m, c) PyModule_AddIntConstant(m, #c, c)
#define  _INT_CONST_LIBXL(m, c) PyModule_AddIntConstant(m, #c, LIBXL_ ## c)
PyMODINIT_FUNC initxl(void)
{
    PyObject *m;

    if (PyType_Ready(&PyXlType) < 0)
        return;

    m = Py_InitModule(PKG, xl_methods);

    if (m == NULL)
      return;

    xl_error_obj = PyErr_NewException(PKG ".Error", PyExc_RuntimeError, NULL);

    Py_INCREF(&PyXlType);
    PyModule_AddObject(m, CLS, (PyObject *)&PyXlType);

    Py_INCREF(xl_error_obj);
    PyModule_AddObject(m, "Error", xl_error_obj);

    _INT_CONST_LIBXL(m, SHUTDOWN_REASON_POWEROFF);
    _INT_CONST_LIBXL(m, SHUTDOWN_REASON_REBOOT);
    _INT_CONST_LIBXL(m, SHUTDOWN_REASON_SUSPEND);
    _INT_CONST_LIBXL(m, SHUTDOWN_REASON_CRASH);
    _INT_CONST_LIBXL(m, SHUTDOWN_REASON_WATCHDOG);

    genwrap__init(m);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
