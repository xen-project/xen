/******************************************************************************
 * Xc.c
 * 
 * Copyright (c) 2003-2004, K A Fraser (University of Cambridge)
 */

#include <Python.h>
#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <xen/elfnote.h>
#include <xen/tmem.h>
#include "xc_dom.h"
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/params.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define PKG "xen.lowlevel.xc"
#define CLS "xc"

#define FLASK_CTX_LEN 1024

static PyObject *xc_error_obj, *zero;

typedef struct {
    PyObject_HEAD;
    xc_interface *xc_handle;
} XcObject;


static PyObject *dom_op(XcObject *self, PyObject *args,
                        int (*fn)(xc_interface *, uint32_t));

static PyObject *pyxc_error_to_exception(xc_interface *xch)
{
    PyObject *pyerr;
    static xc_error err_buf;
    const char *desc;
    const xc_error *err;

    if (xch) {
        err = xc_get_last_error(xch);
    } else {
        snprintf(err_buf.message, sizeof(err_buf.message),
                 "xc_interface_open failed: %s",
                 strerror(errno));
        err_buf.code = XC_INTERNAL_ERROR;
        err = &err_buf;
    }

    desc = xc_error_code_to_desc(err->code);

    if ( err->code == XC_ERROR_NONE )
        return PyErr_SetFromErrno(xc_error_obj);

    if ( err->message[0] != '\0' )
        pyerr = Py_BuildValue("(iss)", err->code, desc, err->message);
    else
        pyerr = Py_BuildValue("(is)", err->code, desc);

    if (xch)
        xc_clear_last_error(xch);

    if ( pyerr != NULL )
    {
        PyErr_SetObject(xc_error_obj, pyerr);
        Py_DECREF(pyerr);
    }

    return NULL;
}

static PyObject *pyxc_domain_dumpcore(XcObject *self, PyObject *args)
{
    uint32_t dom;
    char *corefile;

    if ( !PyArg_ParseTuple(args, "is", &dom, &corefile) )
        return NULL;

    if ( (corefile == NULL) || (corefile[0] == '\0') )
        return NULL;

    if ( xc_domain_dumpcore(self->xc_handle, dom, corefile) != 0 )
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_create(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom = 0, ssidref = 0, flags = 0, target = 0;
    int      ret, i;
    PyObject *pyhandle = NULL;
    xen_domain_handle_t handle = { 
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

    static char *kwd_list[] = { "domid", "ssidref", "handle", "flags", "target", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iiOii", kwd_list,
                                      &dom, &ssidref, &pyhandle, &flags, &target))
        return NULL;
    if ( pyhandle != NULL )
    {
        if ( !PyList_Check(pyhandle) || 
             (PyList_Size(pyhandle) != sizeof(xen_domain_handle_t)) )
            goto out_exception;

        for ( i = 0; i < sizeof(xen_domain_handle_t); i++ )
        {
            PyObject *p = PyList_GetItem(pyhandle, i);
            if ( !PyInt_Check(p) )
                goto out_exception;
            handle[i] = (uint8_t)PyInt_AsLong(p);
        }
    }

    if ( (ret = xc_domain_create(self->xc_handle, ssidref,
                                 handle, flags, &dom, NULL)) < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( target )
        if ( (ret = xc_domain_set_target(self->xc_handle, dom, target)) < 0 )
            return pyxc_error_to_exception(self->xc_handle);


    return PyInt_FromLong(dom);

out_exception:
    errno = EINVAL;
    PyErr_SetFromErrno(xc_error_obj);
    return NULL;
}

static PyObject *pyxc_domain_max_vcpus(XcObject *self, PyObject *args)
{
    uint32_t dom, max;

    if (!PyArg_ParseTuple(args, "ii", &dom, &max))
      return NULL;

    if (xc_domain_max_vcpus(self->xc_handle, dom, max) != 0)
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_pause(XcObject *self, PyObject *args)
{
    return dom_op(self, args, xc_domain_pause);
}

static PyObject *pyxc_domain_unpause(XcObject *self, PyObject *args)
{
    return dom_op(self, args, xc_domain_unpause);
}

static PyObject *pyxc_domain_destroy_hook(XcObject *self, PyObject *args)
{
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_destroy(XcObject *self, PyObject *args)
{
    return dom_op(self, args, xc_domain_destroy);
}

static PyObject *pyxc_domain_shutdown(XcObject *self, PyObject *args)
{
    uint32_t dom, reason;

    if ( !PyArg_ParseTuple(args, "ii", &dom, &reason) )
      return NULL;

    if ( xc_domain_shutdown(self->xc_handle, dom, reason) != 0 )
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_resume(XcObject *self, PyObject *args)
{
    uint32_t dom;
    int fast;

    if ( !PyArg_ParseTuple(args, "ii", &dom, &fast) )
        return NULL;

    if ( xc_domain_resume(self->xc_handle, dom, fast) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_vcpu_setaffinity(XcObject *self,
                                       PyObject *args,
                                       PyObject *kwds)
{
    uint32_t dom;
    int vcpu = 0, i;
    xc_cpumap_t cpumap;
    PyObject *cpulist = NULL;
    int nr_cpus;

    static char *kwd_list[] = { "domid", "vcpu", "cpumap", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|iO", kwd_list, 
                                      &dom, &vcpu, &cpulist) )
        return NULL;

    nr_cpus = xc_get_max_cpus(self->xc_handle);
    if ( nr_cpus < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    cpumap = xc_cpumap_alloc(self->xc_handle);
    if(cpumap == NULL)
        return pyxc_error_to_exception(self->xc_handle);

    if ( (cpulist != NULL) && PyList_Check(cpulist) )
    {
        for ( i = 0; i < PyList_Size(cpulist); i++ ) 
        {
            long cpu = PyInt_AsLong(PyList_GetItem(cpulist, i));
            if ( cpu < 0 || cpu >= nr_cpus )
            {
                free(cpumap);
                errno = EINVAL;
                PyErr_SetFromErrno(xc_error_obj);
                return NULL;
            }
            cpumap[cpu / 8] |= 1 << (cpu % 8);
        }
    }
  
    if ( xc_vcpu_setaffinity(self->xc_handle, dom, vcpu, cpumap,
                             NULL, XEN_VCPUAFFINITY_HARD) != 0 )
    {
        free(cpumap);
        return pyxc_error_to_exception(self->xc_handle);
    }
    Py_INCREF(zero);
    free(cpumap); 
    return zero;
}

static PyObject *pyxc_domain_sethandle(XcObject *self, PyObject *args)
{
    int i;
    uint32_t dom;
    PyObject *pyhandle;
    xen_domain_handle_t handle;

    if (!PyArg_ParseTuple(args, "iO", &dom, &pyhandle))
        return NULL;

    if ( !PyList_Check(pyhandle) || 
         (PyList_Size(pyhandle) != sizeof(xen_domain_handle_t)) )
    {
        goto out_exception;
    }

    for ( i = 0; i < sizeof(xen_domain_handle_t); i++ )
    {
        PyObject *p = PyList_GetItem(pyhandle, i);
        if ( !PyInt_Check(p) )
            goto out_exception;
        handle[i] = (uint8_t)PyInt_AsLong(p);
    }

    if (xc_domain_sethandle(self->xc_handle, dom, handle) < 0)
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;

out_exception:
    PyErr_SetFromErrno(xc_error_obj);
    return NULL;
}


static PyObject *pyxc_domain_getinfo(XcObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    PyObject *list, *info_dict, *pyhandle;

    uint32_t first_dom = 0;
    int max_doms = 1024, nr_doms, i, j;
    xc_dominfo_t *info;

    static char *kwd_list[] = { "first_dom", "max_doms", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list,
                                      &first_dom, &max_doms) )
        return NULL;

    info = calloc(max_doms, sizeof(xc_dominfo_t));
    if (info == NULL)
        return PyErr_NoMemory();

    nr_doms = xc_domain_getinfo(self->xc_handle, first_dom, max_doms, info);

    if (nr_doms < 0)
    {
        free(info);
        return pyxc_error_to_exception(self->xc_handle);
    }

    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        info_dict = Py_BuildValue(
            "{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i"
            ",s:L,s:L,s:L,s:i,s:i,s:i}",
            "domid",           (int)info[i].domid,
            "online_vcpus",    info[i].nr_online_vcpus,
            "max_vcpu_id",     info[i].max_vcpu_id,
            "hvm",             info[i].hvm,
            "dying",           info[i].dying,
            "crashed",         info[i].crashed,
            "shutdown",        info[i].shutdown,
            "paused",          info[i].paused,
            "blocked",         info[i].blocked,
            "running",         info[i].running,
            "mem_kb",          (long long)info[i].nr_pages*(XC_PAGE_SIZE/1024),
            "cpu_time",        (long long)info[i].cpu_time,
            "maxmem_kb",       (long long)info[i].max_memkb,
            "ssidref",         (int)info[i].ssidref,
            "shutdown_reason", info[i].shutdown_reason,
            "cpupool",         (int)info[i].cpupool);
        pyhandle = PyList_New(sizeof(xen_domain_handle_t));
        if ( (pyhandle == NULL) || (info_dict == NULL) )
        {
            Py_DECREF(list);
            if ( pyhandle  != NULL ) { Py_DECREF(pyhandle);  }
            if ( info_dict != NULL ) { Py_DECREF(info_dict); }
            free(info);
            return NULL;
        }
        for ( j = 0; j < sizeof(xen_domain_handle_t); j++ )
            PyList_SetItem(pyhandle, j, PyInt_FromLong(info[i].handle[j]));
        PyDict_SetItemString(info_dict, "handle", pyhandle);
        Py_DECREF(pyhandle);
        PyList_SetItem(list, i, info_dict);
    }

    free(info);

    return list;
}

static PyObject *pyxc_vcpu_getinfo(XcObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    PyObject *info_dict, *cpulist;

    uint32_t dom, vcpu = 0;
    xc_vcpuinfo_t info;
    int rc, i;
    xc_cpumap_t cpumap;
    int nr_cpus;

    static char *kwd_list[] = { "domid", "vcpu", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list,
                                      &dom, &vcpu) )
        return NULL;

    nr_cpus = xc_get_max_cpus(self->xc_handle);
    if ( nr_cpus < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    rc = xc_vcpu_getinfo(self->xc_handle, dom, vcpu, &info);
    if ( rc < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    cpumap = xc_cpumap_alloc(self->xc_handle);
    if(cpumap == NULL)
        return pyxc_error_to_exception(self->xc_handle);

    rc = xc_vcpu_getaffinity(self->xc_handle, dom, vcpu, cpumap,
                             NULL, XEN_VCPUAFFINITY_HARD);
    if ( rc < 0 )
    {
        free(cpumap);
        return pyxc_error_to_exception(self->xc_handle);
    }

    info_dict = Py_BuildValue("{s:i,s:i,s:i,s:L,s:i}",
                              "online",   info.online,
                              "blocked",  info.blocked,
                              "running",  info.running,
                              "cpu_time", info.cpu_time,
                              "cpu",      info.cpu);
    cpulist = PyList_New(0);
    for ( i = 0; i < nr_cpus; i++ )
    {
        if (*(cpumap + i / 8) & 1 ) {
            PyObject *pyint = PyInt_FromLong(i);
            PyList_Append(cpulist, pyint);
            Py_DECREF(pyint);
        }
        cpumap[i / 8] >>= 1;
    }
    PyDict_SetItemString(info_dict, "cpumap", cpulist);
    Py_DECREF(cpulist);
    free(cpumap);
    return info_dict;
}

static PyObject *pyxc_hvm_param_get(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom;
    int param;
    uint64_t value;

    static char *kwd_list[] = { "domid", "param", NULL }; 
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list,
                                      &dom, &param) )
        return NULL;

    if ( xc_hvm_param_get(self->xc_handle, dom, param, &value) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return PyLong_FromUnsignedLongLong(value);

}

static PyObject *pyxc_hvm_param_set(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom;
    int param;
    uint64_t value;

    static char *kwd_list[] = { "domid", "param", "value", NULL }; 
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiL", kwd_list,
                                      &dom, &param, &value) )
        return NULL;

    if ( xc_hvm_param_set(self->xc_handle, dom, param, value) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static int token_value(char *token)
{
    token = strchr(token, 'x') + 1;
    return strtol(token, NULL, 16);
}

static int next_bdf(char **str, int *seg, int *bus, int *dev, int *func)
{
    char *token;

    if ( !(*str) || !strchr(*str, ',') )
        return 0;

    token = *str;
    *seg  = token_value(token);
    token = strchr(token, ',') + 1;
    *bus  = token_value(token);
    token = strchr(token, ',') + 1;
    *dev  = token_value(token);
    token = strchr(token, ',') + 1;
    *func  = token_value(token);
    token = strchr(token, ',');
    *str = token ? token + 1 : NULL;

    return 1;
}

static PyObject *pyxc_test_assign_device(XcObject *self,
                                         PyObject *args,
                                         PyObject *kwds)
{
    uint32_t dom;
    char *pci_str;
    int32_t sbdf = 0;
    int seg, bus, dev, func;

    static char *kwd_list[] = { "domid", "pci", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is", kwd_list,
                                      &dom, &pci_str) )
        return NULL;

    while ( next_bdf(&pci_str, &seg, &bus, &dev, &func) )
    {
        sbdf = seg << 16;
        sbdf |= (bus & 0xff) << 8;
        sbdf |= (dev & 0x1f) << 3;
        sbdf |= (func & 0x7);

        if ( xc_test_assign_device(self->xc_handle, dom, sbdf) != 0 )
        {
            if (errno == ENOSYS)
                sbdf = -1;
            break;
        }
        sbdf = 0;
    }

    return Py_BuildValue("i", sbdf);
}

static PyObject *pyxc_assign_device(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom;
    char *pci_str;
    int32_t sbdf = 0;
    int seg, bus, dev, func;

    static char *kwd_list[] = { "domid", "pci", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is", kwd_list,
                                      &dom, &pci_str) )
        return NULL;

    while ( next_bdf(&pci_str, &seg, &bus, &dev, &func) )
    {
        sbdf = seg << 16;
        sbdf |= (bus & 0xff) << 8;
        sbdf |= (dev & 0x1f) << 3;
        sbdf |= (func & 0x7);

        if ( xc_assign_device(self->xc_handle, dom, sbdf, 0) != 0 )
        {
            if (errno == ENOSYS)
                sbdf = -1;
            break;
        }
        sbdf = 0;
    }

    return Py_BuildValue("i", sbdf);
}

static PyObject *pyxc_deassign_device(XcObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    uint32_t dom;
    char *pci_str;
    int32_t sbdf = 0;
    int seg, bus, dev, func;

    static char *kwd_list[] = { "domid", "pci", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is", kwd_list,
                                      &dom, &pci_str) )
        return NULL;

    while ( next_bdf(&pci_str, &seg, &bus, &dev, &func) )
    {
        sbdf = seg << 16;
        sbdf |= (bus & 0xff) << 8;
        sbdf |= (dev & 0x1f) << 3;
        sbdf |= (func & 0x7);

        if ( xc_deassign_device(self->xc_handle, dom, sbdf) != 0 )
        {
            if (errno == ENOSYS)
                sbdf = -1;
            break;
        }
        sbdf = 0;
    }

    return Py_BuildValue("i", sbdf);
}

static PyObject *pyxc_get_device_group(XcObject *self,
                                         PyObject *args)
{
    uint32_t sbdf;
    uint32_t max_sdevs, num_sdevs;
    int domid, seg, bus, dev, func, rc, i;
    PyObject *Pystr;
    char *group_str;
    char dev_str[9];
    uint32_t *sdev_array;

    if ( !PyArg_ParseTuple(args, "iiiii", &domid, &seg, &bus, &dev, &func) )
        return NULL;

    /* Maximum allowed siblings device number per group */
    max_sdevs = 1024;

    sdev_array = calloc(max_sdevs, sizeof(*sdev_array));
    if (sdev_array == NULL)
        return PyErr_NoMemory();

    sbdf = seg << 16;
    sbdf |= (bus & 0xff) << 8;
    sbdf |= (dev & 0x1f) << 3;
    sbdf |= (func & 0x7);

    rc = xc_get_device_group(self->xc_handle,
        domid, sbdf, max_sdevs, &num_sdevs, sdev_array);

    if ( rc < 0 )
    {
        free(sdev_array); 
        return pyxc_error_to_exception(self->xc_handle);
    }

    if ( !num_sdevs )
    {
        free(sdev_array);
        return Py_BuildValue("s", "");
    }

    group_str = calloc(num_sdevs, sizeof(dev_str));
    if (group_str == NULL)
    {
        free(sdev_array);
        return PyErr_NoMemory();
    }

    for ( i = 0; i < num_sdevs; i++ )
    {
        bus = (sdev_array[i] >> 16) & 0xff;
        dev = (sdev_array[i] >> 11) & 0x1f;
        func = (sdev_array[i] >> 8) & 0x7;
        snprintf(dev_str, sizeof(dev_str), "%02x:%02x.%x,", bus, dev, func);
        strcat(group_str, dev_str);
    }

    Pystr = Py_BuildValue("s", group_str);

    free(sdev_array);
    free(group_str);

    return Pystr;
}

#if defined(__i386__) || defined(__x86_64__)
static void pyxc_dom_extract_cpuid(PyObject *config,
                                  char **regs)
{
    const char *regs_extract[4] = { "eax", "ebx", "ecx", "edx" };
    PyObject *obj;
    int i;

    memset(regs, 0, 4*sizeof(*regs));

    if ( !PyDict_Check(config) )
        return;

    for ( i = 0; i < 4; i++ )
        if ( (obj = PyDict_GetItemString(config, regs_extract[i])) != NULL )
            regs[i] = PyString_AS_STRING(obj);
}

static PyObject *pyxc_create_cpuid_dict(char **regs)
{
   const char *regs_extract[4] = { "eax", "ebx", "ecx", "edx" };
   PyObject *dict;
   int i;

   dict = PyDict_New();
   for ( i = 0; i < 4; i++ )
   {
       if ( regs[i] == NULL )
           continue;
       PyDict_SetItemString(dict, regs_extract[i],
                            PyString_FromString(regs[i]));
       free(regs[i]);
       regs[i] = NULL;
   }
   return dict;
}

static PyObject *pyxc_dom_check_cpuid(XcObject *self,
                                      PyObject *args)
{
    PyObject *sub_input, *config;
    unsigned int input[2];
    char *regs[4], *regs_transform[4];

    if ( !PyArg_ParseTuple(args, "iOO", &input[0], &sub_input, &config) )
        return NULL;

    pyxc_dom_extract_cpuid(config, regs);

    input[1] = XEN_CPUID_INPUT_UNUSED;
    if ( PyLong_Check(sub_input) )
        input[1] = PyLong_AsUnsignedLong(sub_input);

    if ( xc_cpuid_check(self->xc_handle, input,
                        (const char **)regs, regs_transform) )
        return pyxc_error_to_exception(self->xc_handle);

    return pyxc_create_cpuid_dict(regs_transform);
}

static PyObject *pyxc_dom_set_policy_cpuid(XcObject *self,
                                           PyObject *args)
{
    int domid;

    if ( !PyArg_ParseTuple(args, "i", &domid) )
        return NULL;

    if ( xc_cpuid_apply_policy(self->xc_handle, domid, NULL, 0) )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}


static PyObject *pyxc_dom_set_cpuid(XcObject *self,
                                    PyObject *args)
{
    PyObject *sub_input, *config;
    unsigned int domid, input[2];
    char *regs[4], *regs_transform[4];

    if ( !PyArg_ParseTuple(args, "IIOO", &domid,
                           &input[0], &sub_input, &config) )
        return NULL;

    pyxc_dom_extract_cpuid(config, regs);

    input[1] = XEN_CPUID_INPUT_UNUSED;
    if ( PyLong_Check(sub_input) )
        input[1] = PyLong_AsUnsignedLong(sub_input);

    if ( xc_cpuid_set(self->xc_handle, domid, input, (const char **)regs,
                      regs_transform) )
        return pyxc_error_to_exception(self->xc_handle);

    return pyxc_create_cpuid_dict(regs_transform);
}

static PyObject *pyxc_dom_set_machine_address_size(XcObject *self,
						   PyObject *args,
						   PyObject *kwds)
{
    uint32_t dom, width;

    if (!PyArg_ParseTuple(args, "ii", &dom, &width))
	return NULL;

    if (xc_domain_set_machine_address_size(self->xc_handle, dom, width) != 0)
	return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_dom_suppress_spurious_page_faults(XcObject *self,
						      PyObject *args,
						      PyObject *kwds)
{
    uint32_t dom;

    if (!PyArg_ParseTuple(args, "i", &dom))
	return NULL;

    if (xc_domain_suppress_spurious_page_faults(self->xc_handle, dom) != 0)
	return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}
#endif /* __i386__ || __x86_64__ */

static PyObject *pyxc_gnttab_hvm_seed(XcObject *self,
				      PyObject *args,
				      PyObject *kwds)
{
    uint32_t dom, console_domid, xenstore_domid;
    unsigned long xenstore_gmfn = 0;
    unsigned long console_gmfn = 0;
    static char *kwd_list[] = { "domid",
				"console_gmfn", "xenstore_gmfn",
				"console_domid", "xenstore_domid", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiii", kwd_list,
                                      &dom,
				      &console_gmfn, &xenstore_gmfn,
				      &console_domid, &xenstore_domid) )
        return NULL;

    if ( xc_dom_gnttab_hvm_seed(self->xc_handle, dom,
				console_gmfn, xenstore_gmfn,
				console_domid, xenstore_domid) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return Py_None;
}

static PyObject *pyxc_evtchn_alloc_unbound(XcObject *self,
                                           PyObject *args,
                                           PyObject *kwds)
{
    uint32_t dom, remote_dom;
    int port;

    static char *kwd_list[] = { "domid", "remote_dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list,
                                      &dom, &remote_dom) )
        return NULL;

    if ( (port = xc_evtchn_alloc_unbound(self->xc_handle, dom, remote_dom)) < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return PyInt_FromLong(port);
}

static PyObject *pyxc_evtchn_reset(XcObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    uint32_t dom;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    if ( xc_evtchn_reset(self->xc_handle, dom) < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_physdev_map_pirq(PyObject *self,
                                       PyObject *args,
                                       PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    uint32_t dom;
    int index, pirq, ret;

    static char *kwd_list[] = {"domid", "index", "pirq", NULL};

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iii", kwd_list,
                                      &dom, &index, &pirq) )
        return NULL;
    ret = xc_physdev_map_pirq(xc->xc_handle, dom, index, &pirq);
    if ( ret != 0 )
          return pyxc_error_to_exception(xc->xc_handle);
    return PyLong_FromUnsignedLong(pirq);
}

static PyObject *pyxc_physdev_pci_access_modify(XcObject *self,
                                                PyObject *args,
                                                PyObject *kwds)
{
    uint32_t dom;
    int bus, dev, func, enable, ret;

    static char *kwd_list[] = { "domid", "bus", "dev", "func", "enable", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiii", kwd_list, 
                                      &dom, &bus, &dev, &func, &enable) )
        return NULL;

    ret = xc_physdev_pci_access_modify(
        self->xc_handle, dom, bus, dev, func, enable);
    if ( ret != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_readconsolering(XcObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    unsigned int clear = 0, index = 0, incremental = 0;
    unsigned int count = 16384 + 1, size = count;
    char        *str, *ptr;
    PyObject    *obj;
    int          ret;

    static char *kwd_list[] = { "clear", "index", "incremental", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iii", kwd_list,
                                      &clear, &index, &incremental) ||
         !(str = malloc(size)) )
        return NULL;

    ret = xc_readconsolering(self->xc_handle, str, &count, clear,
                             incremental, &index);
    if ( ret < 0 ) {
        free(str);
        return pyxc_error_to_exception(self->xc_handle);
    }

    while ( !incremental && count == size && ret >= 0 )
    {
        size += count - 1;
        if ( size < count )
            break;

        ptr = realloc(str, size);
        if ( !ptr )
            break;

        str = ptr + count;
        count = size - count;
        ret = xc_readconsolering(self->xc_handle, str, &count, clear,
                                 1, &index);
        count += str - ptr;
        str = ptr;
    }

    obj = PyString_FromStringAndSize(str, count);
    free(str);
    return obj;
}


static unsigned long pages_to_kib(unsigned long pages)
{
    return pages * (XC_PAGE_SIZE / 1024);
}


static PyObject *pyxc_pages_to_kib(XcObject *self, PyObject *args)
{
    unsigned long pages;

    if (!PyArg_ParseTuple(args, "l", &pages))
        return NULL;

    return PyLong_FromUnsignedLong(pages_to_kib(pages));
}

static PyObject *pyxc_physinfo(XcObject *self)
{
    xc_physinfo_t pinfo;
    char cpu_cap[128], virt_caps[128], *p;
    int i;
    const char *virtcap_names[] = { "hvm", "hvm_directio" };

    if ( xc_physinfo(self->xc_handle, &pinfo) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    p = cpu_cap;
    *p = '\0';
    for ( i = 0; i < sizeof(pinfo.hw_cap)/4; i++ )
        p += sprintf(p, "%08x:", pinfo.hw_cap[i]);
    *(p-1) = 0;

    p = virt_caps;
    *p = '\0';
    for ( i = 0; i < 2; i++ )
        if ( (pinfo.capabilities >> i) & 1 )
          p += sprintf(p, "%s ", virtcap_names[i]);
    if ( p != virt_caps )
      *(p-1) = '\0';

    return Py_BuildValue("{s:i,s:i,s:i,s:i,s:l,s:l,s:l,s:i,s:s,s:s}",
                            "nr_nodes",         pinfo.nr_nodes,
                            "threads_per_core", pinfo.threads_per_core,
                            "cores_per_socket", pinfo.cores_per_socket,
                            "nr_cpus",          pinfo.nr_cpus, 
                            "total_memory",     pages_to_kib(pinfo.total_pages),
                            "free_memory",      pages_to_kib(pinfo.free_pages),
                            "scrub_memory",     pages_to_kib(pinfo.scrub_pages),
                            "cpu_khz",          pinfo.cpu_khz,
                            "hw_caps",          cpu_cap,
                            "virt_caps",        virt_caps);
}

static PyObject *pyxc_getcpuinfo(XcObject *self, PyObject *args, PyObject *kwds)
{
    xc_cpuinfo_t *cpuinfo, *cpuinfo_ptr;
    PyObject *cpuinfo_list_obj, *cpuinfo_obj;
    int max_cpus, nr_cpus, ret, i;
    static char *kwd_list[] = { "max_cpus", NULL };
    static char kwd_type[] = "i";

    if(!PyArg_ParseTupleAndKeywords(args, kwds, kwd_type, kwd_list, &max_cpus))
        return NULL;

    cpuinfo = malloc(sizeof(xc_cpuinfo_t) * max_cpus);
    if (!cpuinfo)
        return NULL;

    ret = xc_getcpuinfo(self->xc_handle, max_cpus, cpuinfo, &nr_cpus);
    if (ret != 0) {
        free(cpuinfo);
        return pyxc_error_to_exception(self->xc_handle);
    }

    cpuinfo_list_obj = PyList_New(0);
    cpuinfo_ptr = cpuinfo;
    for (i = 0; i < nr_cpus; i++) {
        cpuinfo_obj = Py_BuildValue("{s:k}", "idletime", cpuinfo_ptr->idletime);
        PyList_Append(cpuinfo_list_obj, cpuinfo_obj);
        Py_DECREF(cpuinfo_obj);
        cpuinfo_ptr++;
    }

    free(cpuinfo);

    return cpuinfo_list_obj;
}

static PyObject *pyxc_topologyinfo(XcObject *self)
{
    xc_cputopo_t *cputopo = NULL;
    unsigned i, num_cpus = 0;
    PyObject *ret_obj = NULL;
    PyObject *cpu_to_core_obj, *cpu_to_socket_obj, *cpu_to_node_obj;

    if ( xc_cputopoinfo(self->xc_handle, &num_cpus, NULL) != 0 )
        goto out;

    cputopo = calloc(num_cpus, sizeof(*cputopo));
    if ( cputopo == NULL )
    	goto out;

    if ( xc_cputopoinfo(self->xc_handle, &num_cpus, cputopo) != 0 )
        goto out;

    /* Construct cpu-to-* lists. */
    cpu_to_core_obj = PyList_New(0);
    cpu_to_socket_obj = PyList_New(0);
    cpu_to_node_obj = PyList_New(0);
    for ( i = 0; i < num_cpus; i++ )
    {
        if ( cputopo[i].core == XEN_INVALID_CORE_ID )
        {
            PyList_Append(cpu_to_core_obj, Py_None);
        }
        else
        {
            PyObject *pyint = PyInt_FromLong(cputopo[i].core);
            PyList_Append(cpu_to_core_obj, pyint);
            Py_DECREF(pyint);
        }

        if ( cputopo[i].socket == XEN_INVALID_SOCKET_ID )
        {
            PyList_Append(cpu_to_socket_obj, Py_None);
        }
        else
        {
            PyObject *pyint = PyInt_FromLong(cputopo[i].socket);
            PyList_Append(cpu_to_socket_obj, pyint);
            Py_DECREF(pyint);
        }

        if ( cputopo[i].node == XEN_INVALID_NODE_ID )
        {
            PyList_Append(cpu_to_node_obj, Py_None);
        }
        else
        {
            PyObject *pyint = PyInt_FromLong(cputopo[i].node);
            PyList_Append(cpu_to_node_obj, pyint);
            Py_DECREF(pyint);
        }
    }

    ret_obj = Py_BuildValue("{s:i}", "max_cpu_index", num_cpus + 1);

    PyDict_SetItemString(ret_obj, "cpu_to_core", cpu_to_core_obj);
    Py_DECREF(cpu_to_core_obj);

    PyDict_SetItemString(ret_obj, "cpu_to_socket", cpu_to_socket_obj);
    Py_DECREF(cpu_to_socket_obj);

    PyDict_SetItemString(ret_obj, "cpu_to_node", cpu_to_node_obj);
    Py_DECREF(cpu_to_node_obj);

out:
    free(cputopo);
    return ret_obj ? ret_obj : pyxc_error_to_exception(self->xc_handle);
}

static PyObject *pyxc_numainfo(XcObject *self)
{
    unsigned i, j, num_nodes = 0;
    uint64_t free_heap;
    PyObject *ret_obj = NULL, *node_to_node_dist_list_obj;
    PyObject *node_to_memsize_obj, *node_to_memfree_obj;
    PyObject *node_to_dma32_mem_obj, *node_to_node_dist_obj;
    xc_meminfo_t *meminfo = NULL;
    uint32_t *distance = NULL;

    if ( xc_numainfo(self->xc_handle, &num_nodes, NULL, NULL) != 0 )
        goto out;

    meminfo = calloc(num_nodes, sizeof(*meminfo));
    distance = calloc(num_nodes * num_nodes, sizeof(*distance));
    if ( (meminfo == NULL) || (distance == NULL) )
        goto out;

    if ( xc_numainfo(self->xc_handle, &num_nodes, meminfo, distance) != 0 )
        goto out;

    /* Construct node-to-* lists. */
    node_to_memsize_obj = PyList_New(0);
    node_to_memfree_obj = PyList_New(0);
    node_to_dma32_mem_obj = PyList_New(0);
    node_to_node_dist_list_obj = PyList_New(0);
    for ( i = 0; i < num_nodes; i++ )
    {
        PyObject *pyint;
        unsigned invalid_node;

        /* Total Memory */
        pyint = PyInt_FromLong(meminfo[i].memsize >> 20); /* MB */
        PyList_Append(node_to_memsize_obj, pyint);
        Py_DECREF(pyint);

        /* Free Memory */
        pyint = PyInt_FromLong(meminfo[i].memfree >> 20); /* MB */
        PyList_Append(node_to_memfree_obj, pyint);
        Py_DECREF(pyint);

        /* DMA memory. */
        xc_availheap(self->xc_handle, 0, 32, i, &free_heap);
        pyint = PyInt_FromLong(free_heap >> 20); /* MB */
        PyList_Append(node_to_dma32_mem_obj, pyint);
        Py_DECREF(pyint);

        /* Node to Node Distance */
        node_to_node_dist_obj = PyList_New(0);
        invalid_node = (meminfo[i].memsize == XEN_INVALID_MEM_SZ);
        for ( j = 0; j < num_nodes; j++ )
        {
            uint32_t dist = distance[i * num_nodes + j];
            if ( invalid_node || (dist == XEN_INVALID_NODE_DIST) )
            {
                PyList_Append(node_to_node_dist_obj, Py_None);
            }
            else
            {
                pyint = PyInt_FromLong(dist);
                PyList_Append(node_to_node_dist_obj, pyint);
                Py_DECREF(pyint);
            }
        }
        PyList_Append(node_to_node_dist_list_obj, node_to_node_dist_obj);
        Py_DECREF(node_to_node_dist_obj);
    }

    ret_obj = Py_BuildValue("{s:i}", "max_node_index", num_nodes + 1);

    PyDict_SetItemString(ret_obj, "node_memsize", node_to_memsize_obj);
    Py_DECREF(node_to_memsize_obj);

    PyDict_SetItemString(ret_obj, "node_memfree", node_to_memfree_obj);
    Py_DECREF(node_to_memfree_obj);

    PyDict_SetItemString(ret_obj, "node_to_dma32_mem", node_to_dma32_mem_obj);
    Py_DECREF(node_to_dma32_mem_obj);

    PyDict_SetItemString(ret_obj, "node_to_node_dist",
                         node_to_node_dist_list_obj);
    Py_DECREF(node_to_node_dist_list_obj);

out:
    free(meminfo);
    free(distance);
    return ret_obj ? ret_obj : pyxc_error_to_exception(self->xc_handle);
}

static PyObject *pyxc_xeninfo(XcObject *self)
{
    xen_extraversion_t xen_extra;
    xen_compile_info_t xen_cc;
    xen_changeset_info_t xen_chgset;
    xen_capabilities_info_t xen_caps;
    xen_platform_parameters_t p_parms;
    xen_commandline_t xen_commandline;
    long xen_version;
    long xen_pagesize;
    char str[128];

    xen_version = xc_version(self->xc_handle, XENVER_version, NULL);

    if ( xc_version(self->xc_handle, XENVER_extraversion, &xen_extra) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( xc_version(self->xc_handle, XENVER_compile_info, &xen_cc) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( xc_version(self->xc_handle, XENVER_changeset, &xen_chgset) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( xc_version(self->xc_handle, XENVER_capabilities, &xen_caps) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( xc_version(self->xc_handle, XENVER_platform_parameters, &p_parms) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    if ( xc_version(self->xc_handle, XENVER_commandline, &xen_commandline) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    snprintf(str, sizeof(str), "virt_start=0x%"PRI_xen_ulong, p_parms.virt_start);

    xen_pagesize = xc_version(self->xc_handle, XENVER_pagesize, NULL);
    if (xen_pagesize < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return Py_BuildValue("{s:i,s:i,s:s,s:s,s:i,s:s,s:s,s:s,s:s,s:s,s:s,s:s}",
                         "xen_major", xen_version >> 16,
                         "xen_minor", (xen_version & 0xffff),
                         "xen_extra", xen_extra,
                         "xen_caps",  xen_caps,
                         "xen_pagesize", xen_pagesize,
                         "platform_params", str,
                         "xen_changeset", xen_chgset,
                         "xen_commandline", xen_commandline,
                         "cc_compiler", xen_cc.compiler,
                         "cc_compile_by", xen_cc.compile_by,
                         "cc_compile_domain", xen_cc.compile_domain,
                         "cc_compile_date", xen_cc.compile_date);
}

static PyObject *pyxc_shadow_control(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    uint32_t dom;
    int op=0;

    static char *kwd_list[] = { "dom", "op", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &dom, &op) )
        return NULL;
    
    if ( xc_shadow_control(xc->xc_handle, dom, op, NULL, 0, NULL, 0, NULL) 
         < 0 )
        return pyxc_error_to_exception(xc->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_shadow_mem_control(PyObject *self,
                                         PyObject *args,
                                         PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    int op;
    uint32_t dom;
    int mbarg = -1;
    unsigned long mb;

    static char *kwd_list[] = { "dom", "mb", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &dom, &mbarg) )
        return NULL;
    
    if ( mbarg < 0 ) 
        op = XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION;
    else 
    {
        mb = mbarg;
        op = XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION;
    }
    if ( xc_shadow_control(xc->xc_handle, dom, op, NULL, 0, &mb, 0, NULL) < 0 )
        return pyxc_error_to_exception(xc->xc_handle);
    
    mbarg = mb;
    return Py_BuildValue("i", mbarg);
}

static PyObject *pyxc_sched_id_get(XcObject *self) {
    
    int sched_id;
    if (xc_sched_id(self->xc_handle, &sched_id) != 0)
        return PyErr_SetFromErrno(xc_error_obj);

    return Py_BuildValue("i", sched_id);
}

static PyObject *pyxc_sched_credit_domain_set(XcObject *self,
                                              PyObject *args,
                                              PyObject *kwds)
{
    uint32_t domid;
    uint16_t weight;
    uint16_t cap;
    static char *kwd_list[] = { "domid", "weight", "cap", NULL };
    static char kwd_type[] = "I|HH";
    struct xen_domctl_sched_credit sdom;
    
    weight = 0;
    cap = (uint16_t)~0U;
    if( !PyArg_ParseTupleAndKeywords(args, kwds, kwd_type, kwd_list, 
                                     &domid, &weight, &cap) )
        return NULL;

    sdom.weight = weight;
    sdom.cap = cap;

    if ( xc_sched_credit_domain_set(self->xc_handle, domid, &sdom) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_sched_credit_domain_get(XcObject *self, PyObject *args)
{
    uint32_t domid;
    struct xen_domctl_sched_credit sdom;
    
    if( !PyArg_ParseTuple(args, "I", &domid) )
        return NULL;
    
    if ( xc_sched_credit_domain_get(self->xc_handle, domid, &sdom) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return Py_BuildValue("{s:H,s:H}",
                         "weight",  sdom.weight,
                         "cap",     sdom.cap);
}

static PyObject *pyxc_sched_credit2_domain_set(XcObject *self,
                                              PyObject *args,
                                              PyObject *kwds)
{
    uint32_t domid;
    uint16_t weight;
    static char *kwd_list[] = { "domid", "weight", NULL };
    static char kwd_type[] = "I|H";
    struct xen_domctl_sched_credit2 sdom;

    weight = 0;
    if( !PyArg_ParseTupleAndKeywords(args, kwds, kwd_type, kwd_list,
                                     &domid, &weight) )
        return NULL;

    sdom.weight = weight;

    if ( xc_sched_credit2_domain_set(self->xc_handle, domid, &sdom) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_sched_credit2_domain_get(XcObject *self, PyObject *args)
{
    uint32_t domid;
    struct xen_domctl_sched_credit2 sdom;

    if( !PyArg_ParseTuple(args, "I", &domid) )
        return NULL;

    if ( xc_sched_credit2_domain_get(self->xc_handle, domid, &sdom) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return Py_BuildValue("{s:H}",
                         "weight",  sdom.weight);
}

static PyObject *pyxc_domain_setmaxmem(XcObject *self, PyObject *args)
{
    uint32_t dom;
    unsigned int maxmem_kb;

    if (!PyArg_ParseTuple(args, "ii", &dom, &maxmem_kb))
        return NULL;

    if (xc_domain_setmaxmem(self->xc_handle, dom, maxmem_kb) != 0)
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_set_target_mem(XcObject *self, PyObject *args)
{
    uint32_t dom;
    unsigned int mem_kb, mem_pages;

    if (!PyArg_ParseTuple(args, "ii", &dom, &mem_kb))
        return NULL;

    mem_pages = mem_kb / 4; 

    if (xc_domain_set_pod_target(self->xc_handle, dom, mem_pages,
				 NULL, NULL, NULL) != 0)
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_set_memmap_limit(XcObject *self, PyObject *args)
{
    uint32_t dom;
    unsigned int maplimit_kb;

    if ( !PyArg_ParseTuple(args, "ii", &dom, &maplimit_kb) )
        return NULL;

    if ( xc_domain_set_memmap_limit(self->xc_handle, dom, maplimit_kb) != 0 )
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_ioport_permission(XcObject *self,
                                               PyObject *args,
                                               PyObject *kwds)
{
    uint32_t dom;
    int first_port, nr_ports, allow_access, ret;

    static char *kwd_list[] = { "domid", "first_port", "nr_ports", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiii", kwd_list, 
                                      &dom, &first_port, &nr_ports, &allow_access) )
        return NULL;

    ret = xc_domain_ioport_permission(
        self->xc_handle, dom, first_port, nr_ports, allow_access);
    if ( ret != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_irq_permission(PyObject *self,
                                            PyObject *args,
                                            PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    uint32_t dom;
    int pirq, allow_access, ret;

    static char *kwd_list[] = { "domid", "pirq", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iii", kwd_list, 
                                      &dom, &pirq, &allow_access) )
        return NULL;

    ret = xc_domain_irq_permission(
        xc->xc_handle, dom, pirq, allow_access);
    if ( ret != 0 )
        return pyxc_error_to_exception(xc->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_iomem_permission(PyObject *self,
                                               PyObject *args,
                                               PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    uint32_t dom;
    unsigned long first_pfn, nr_pfns, allow_access, ret;

    static char *kwd_list[] = { "domid", "first_pfn", "nr_pfns", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "illi", kwd_list, 
                                      &dom, &first_pfn, &nr_pfns, &allow_access) )
        return NULL;

    ret = xc_domain_iomem_permission(
        xc->xc_handle, dom, first_pfn, nr_pfns, allow_access);
    if ( ret != 0 )
        return pyxc_error_to_exception(xc->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_set_time_offset(XcObject *self, PyObject *args)
{
    uint32_t dom;
    int32_t offset;

    if (!PyArg_ParseTuple(args, "ii", &dom, &offset))
        return NULL;

    if (xc_domain_set_time_offset(self->xc_handle, dom, offset) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_set_tsc_info(XcObject *self, PyObject *args)
{
    uint32_t dom, tsc_mode;

    if (!PyArg_ParseTuple(args, "ii", &dom, &tsc_mode))
        return NULL;

    if (xc_domain_set_tsc_info(self->xc_handle, dom, tsc_mode, 0, 0, 0) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_disable_migrate(XcObject *self, PyObject *args)
{
    uint32_t dom;

    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;

    if (xc_domain_disable_migrate(self->xc_handle, dom) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_send_trigger(XcObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    uint32_t dom;
    int trigger, vcpu = 0;

    static char *kwd_list[] = { "domid", "trigger", "vcpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii|i", kwd_list, 
                                      &dom, &trigger, &vcpu) )
        return NULL;

    if (xc_domain_send_trigger(self->xc_handle, dom, trigger, vcpu) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_send_debug_keys(XcObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    char *keys;

    static char *kwd_list[] = { "keys", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list, &keys) )
        return NULL;

    if ( xc_send_debug_keys(self->xc_handle, keys) != 0 )
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *dom_op(XcObject *self, PyObject *args,
                        int (*fn)(xc_interface*, uint32_t))
{
    uint32_t dom;

    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;

    if (fn(self->xc_handle, dom) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_tmem_control(XcObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    int32_t pool_id;
    uint32_t subop;
    uint32_t cli_id;
    uint32_t len;
    uint32_t arg;
    char *buf;
    char _buffer[32768], *buffer = _buffer;
    int rc;

    static char *kwd_list[] = { "pool_id", "subop", "cli_id", "arg1", "arg2", "buf", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiiis", kwd_list,
                        &pool_id, &subop, &cli_id, &len, &arg, &buf) )
        return NULL;

    if ( (subop == XEN_SYSCTL_TMEM_OP_LIST) && (len > 32768) )
        len = 32768;

    if ( (rc = xc_tmem_control(self->xc_handle, pool_id, subop, cli_id, len, arg, buffer)) < 0 )
        return Py_BuildValue("i", rc);

    switch (subop) {
        case XEN_SYSCTL_TMEM_OP_LIST:
            return Py_BuildValue("s", buffer);
        case XEN_SYSCTL_TMEM_OP_FLUSH:
            return Py_BuildValue("i", rc);
        case XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB:
            return Py_BuildValue("i", rc);
        case XEN_SYSCTL_TMEM_OP_THAW:
        case XEN_SYSCTL_TMEM_OP_FREEZE:
        case XEN_SYSCTL_TMEM_OP_DESTROY:
        default:
            break;
    }

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_tmem_shared_auth(XcObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    uint32_t cli_id;
    uint32_t arg1;
    char *uuid_str;
    int rc;

    static char *kwd_list[] = { "cli_id", "uuid_str", "arg1", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "isi", kwd_list,
                                   &cli_id, &uuid_str, &arg1) )
        return NULL;

    if ( (rc = xc_tmem_auth(self->xc_handle, cli_id, uuid_str, arg1)) < 0 )
        return Py_BuildValue("i", rc);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_dom_set_memshr(XcObject *self, PyObject *args)
{
    uint32_t dom;
    int enable;

    if (!PyArg_ParseTuple(args, "ii", &dom, &enable))
        return NULL;

    if (xc_memshr_control(self->xc_handle, dom, enable) != 0)
        return pyxc_error_to_exception(self->xc_handle);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *cpumap_to_cpulist(XcObject *self, xc_cpumap_t cpumap)
{
    PyObject *cpulist = NULL;
    int i;
    int nr_cpus;

    nr_cpus = xc_get_max_cpus(self->xc_handle);
    if ( nr_cpus < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    cpulist = PyList_New(0);
    for ( i = 0; i < nr_cpus; i++ )
    {
        if ( *cpumap & (1 << (i % 8)) )
        {
            PyObject* pyint = PyInt_FromLong(i);

            PyList_Append(cpulist, pyint);
            Py_DECREF(pyint);
        }
        if ( (i % 8) == 7 )
            cpumap++;
    }
    return cpulist;
}

static PyObject *pyxc_cpupool_create(XcObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    uint32_t cpupool = 0, sched = XEN_SCHEDULER_CREDIT;

    static char *kwd_list[] = { "pool", "sched", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list, &cpupool,
                                      &sched))
        return NULL;

    if ( xc_cpupool_create(self->xc_handle, &cpupool, sched) < 0 )
        return pyxc_error_to_exception(self->xc_handle);

    return PyInt_FromLong(cpupool);
}

static PyObject *pyxc_cpupool_destroy(XcObject *self,
                                      PyObject *args)
{
    uint32_t cpupool;

    if (!PyArg_ParseTuple(args, "i", &cpupool))
        return NULL;

    if (xc_cpupool_destroy(self->xc_handle, cpupool) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_cpupool_getinfo(XcObject *self)
{
    PyObject *list, *info_dict;

    uint32_t pool;
    xc_cpupoolinfo_t *info;

    list = PyList_New(0);
    for (pool = 0;;)
    {
        info = xc_cpupool_getinfo(self->xc_handle, pool);
        if (info == NULL)
            break;
        info_dict = Py_BuildValue(
            "{s:i,s:i,s:i,s:N}",
            "cpupool",         (int)info->cpupool_id,
            "sched",           info->sched_id,
            "n_dom",           info->n_dom,
            "cpulist",         cpumap_to_cpulist(self, info->cpumap));
        pool = info->cpupool_id + 1;
        xc_cpupool_infofree(self->xc_handle, info);

        if ( info_dict == NULL )
        {
            Py_DECREF(list);
            return NULL;
        }

        PyList_Append(list, info_dict);
        Py_DECREF(info_dict);
    }

    return list;
}

static PyObject *pyxc_cpupool_addcpu(XcObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    uint32_t cpupool;
    int cpu = -1;

    static char *kwd_list[] = { "cpupool", "cpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list,
                                      &cpupool, &cpu) )
        return NULL;

    if (xc_cpupool_addcpu(self->xc_handle, cpupool, cpu) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_cpupool_removecpu(XcObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    uint32_t cpupool;
    int cpu = -1;

    static char *kwd_list[] = { "cpupool", "cpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list,
                                      &cpupool, &cpu) )
        return NULL;

    if (xc_cpupool_removecpu(self->xc_handle, cpupool, cpu) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_cpupool_movedomain(XcObject *self,
                                         PyObject *args,
                                         PyObject *kwds)
{
    uint32_t cpupool, domid;

    static char *kwd_list[] = { "cpupool", "domid", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list,
                                      &cpupool, &domid) )
        return NULL;

    if (xc_cpupool_movedomain(self->xc_handle, cpupool, domid) != 0)
        return pyxc_error_to_exception(self->xc_handle);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_cpupool_freeinfo(XcObject *self)
{
    xc_cpumap_t cpumap;
    PyObject *info = NULL;

    cpumap = xc_cpupool_freeinfo(self->xc_handle);
    if (!cpumap)
        return pyxc_error_to_exception(self->xc_handle);

    info = cpumap_to_cpulist(self, cpumap);

    free(cpumap);

    return info;
}

static PyObject *pyflask_context_to_sid(PyObject *self, PyObject *args,
                                                                 PyObject *kwds)
{
    xc_interface *xc_handle;
    char *ctx;
    uint32_t sid;
    int ret;

    static char *kwd_list[] = { "context", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s", kwd_list,
                                      &ctx) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }

    ret = xc_flask_context_to_sid(xc_handle, ctx, strlen(ctx), &sid);

    xc_interface_close(xc_handle);

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
    char ctx[FLASK_CTX_LEN];
    uint32_t ctx_len = FLASK_CTX_LEN;
    int ret;

    static char *kwd_list[] = { "sid", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list,
                                      &sid) )
        return NULL;

    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        return PyErr_SetFromErrno(xc_error_obj);
    }
    
    ret = xc_flask_sid_to_context(xc_handle, sid, ctx, ctx_len);
    
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

    ret = xc_flask_load(xc_handle, policy, len);

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
    
    ret = xc_flask_getenforce(xc_handle);
    
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
    
    ret = xc_flask_setenforce(xc_handle, mode);
    
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
    
    ret = xc_flask_access(xc_handle, scon, tcon, tclass, req, &allowed, &decided,
                        &auditallow, &auditdeny, &seqno);
        
    xc_interface_close(xc_handle);

    if ( ret != 0 ) {
        errno = -ret;
        return PyErr_SetFromErrno(xc_error_obj);
    }

    return Py_BuildValue("i",ret);
}

static PyMethodDef pyxc_methods[] = {
    { "domain_create", 
      (PyCFunction)pyxc_domain_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new domain.\n"
      " dom    [int, 0]:        Domain identifier to use (allocated if zero).\n"
      "Returns: [int] new domain identifier; -1 on error.\n" },

    { "domain_max_vcpus", 
      (PyCFunction)pyxc_domain_max_vcpus,
      METH_VARARGS, "\n"
      "Set the maximum number of VCPUs a domain may create.\n"
      " dom       [int, 0]:      Domain identifier to use.\n"
      " max     [int, 0]:      New maximum number of VCPUs in domain.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_dumpcore", 
      (PyCFunction)pyxc_domain_dumpcore, 
      METH_VARARGS, "\n"
      "Dump core of a domain.\n"
      " dom [int]: Identifier of domain to dump core of.\n"
      " corefile [string]: Name of corefile to be created.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_pause", 
      (PyCFunction)pyxc_domain_pause, 
      METH_VARARGS, "\n"
      "Temporarily pause execution of a domain.\n"
      " dom [int]: Identifier of domain to be paused.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_unpause", 
      (PyCFunction)pyxc_domain_unpause, 
      METH_VARARGS, "\n"
      "(Re)start execution of a domain.\n"
      " dom [int]: Identifier of domain to be unpaused.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_destroy", 
      (PyCFunction)pyxc_domain_destroy, 
      METH_VARARGS, "\n"
      "Destroy a domain.\n"
      " dom [int]:    Identifier of domain to be destroyed.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_destroy_hook", 
      (PyCFunction)pyxc_domain_destroy_hook, 
      METH_VARARGS, "\n"
      "Add a hook for arch stuff before destroy a domain.\n"
      " dom [int]:    Identifier of domain to be destroyed.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_resume", 
      (PyCFunction)pyxc_domain_resume,
      METH_VARARGS, "\n"
      "Resume execution of a suspended domain.\n"
      " dom [int]: Identifier of domain to be resumed.\n"
      " fast [int]: Use cooperative resume.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_shutdown", 
      (PyCFunction)pyxc_domain_shutdown,
      METH_VARARGS, "\n"
      "Shutdown a domain.\n"
      " dom       [int, 0]:      Domain identifier to use.\n"
      " reason     [int, 0]:      Reason for shutdown.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vcpu_setaffinity", 
      (PyCFunction)pyxc_vcpu_setaffinity, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Pin a VCPU to a specified set CPUs.\n"
      " dom [int]:     Identifier of domain to which VCPU belongs.\n"
      " vcpu [int, 0]: VCPU being pinned.\n"
      " cpumap [list, []]: list of usable CPUs.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_sethandle", 
      (PyCFunction)pyxc_domain_sethandle,
      METH_VARARGS, "\n"
      "Set domain's opaque handle.\n"
      " dom [int]:            Identifier of domain.\n"
      " handle [list of 16 ints]: New opaque handle.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_getinfo", 
      (PyCFunction)pyxc_domain_getinfo, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information regarding a set of domains, in increasing id order.\n"
      " first_dom [int, 0]:    First domain to retrieve info about.\n"
      " max_doms  [int, 1024]: Maximum number of domains to retrieve info"
      " about.\n\n"
      "Returns: [list of dicts] if list length is less than 'max_doms'\n"
      "         parameter then there was an error, or the end of the\n"
      "         domain-id space was reached.\n"
      " dom      [int]: Identifier of domain to which this info pertains\n"
      " cpu      [int]:  CPU to which this domain is bound\n"
      " vcpus    [int]:  Number of Virtual CPUS in this domain\n"
      " dying    [int]:  Bool - is the domain dying?\n"
      " crashed  [int]:  Bool - has the domain crashed?\n"
      " shutdown [int]:  Bool - has the domain shut itself down?\n"
      " paused   [int]:  Bool - is the domain paused by control software?\n"
      " blocked  [int]:  Bool - is the domain blocked waiting for an event?\n"
      " running  [int]:  Bool - is the domain currently running?\n"
      " mem_kb   [int]:  Memory reservation, in kilobytes\n"
      " maxmem_kb [int]: Maximum memory limit, in kilobytes\n"
      " cpu_time [long]: CPU time consumed, in nanoseconds\n"
      " shutdown_reason [int]: Numeric code from guest OS, explaining "
      "reason why it shut itself down.\n"
      " cpupool  [int]   Id of cpupool domain is bound to.\n" },

    { "vcpu_getinfo", 
      (PyCFunction)pyxc_vcpu_getinfo, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information regarding a VCPU.\n"
      " dom  [int]:    Domain to retrieve info about.\n"
      " vcpu [int, 0]: VCPU to retrieve info about.\n\n"
      "Returns: [dict]\n"
      " online   [int]:  Bool - Is this VCPU currently online?\n"
      " blocked  [int]:  Bool - Is this VCPU blocked waiting for an event?\n"
      " running  [int]:  Bool - Is this VCPU currently running on a CPU?\n"
      " cpu_time [long]: CPU time consumed, in nanoseconds\n"
      " cpumap   [int]:  Bitmap of CPUs this VCPU can run on\n"
      " cpu      [int]:  CPU that this VCPU is currently bound to\n" },

    { "gnttab_hvm_seed",
      (PyCFunction)pyxc_gnttab_hvm_seed,
      METH_KEYWORDS, "\n"
      "Initialise HVM guest grant table.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " console_gmfn [int]: \n"
      " xenstore_gmfn [int]: \n"
      " console_domid [int]: \n"
      " xenstore_domid [int]: \n"
      "Returns: None on sucess. Raises exception on error.\n" },

    { "hvm_get_param", 
      (PyCFunction)pyxc_hvm_param_get,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "get a parameter of HVM guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " param   [int]:      No. of HVM param.\n"
      "Returns: [long] value of the param.\n" },

    { "hvm_set_param", 
      (PyCFunction)pyxc_hvm_param_set,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "set a parameter of HVM guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " param   [int]:      No. of HVM param.\n"
      " value   [long]:     Value of param.\n"
      "Returns: [int] 0 on success.\n" },

    { "get_device_group",
      (PyCFunction)pyxc_get_device_group,
      METH_VARARGS, "\n"
      "get sibling devices infomation.\n"
      " dom     [int]:      Domain to assign device to.\n"
      " seg     [int]:      PCI segment.\n"
      " bus     [int]:      PCI bus.\n"
      " dev     [int]:      PCI dev.\n"
      " func    [int]:      PCI func.\n"
      "Returns: [string]:   Sibling devices \n" },

     { "test_assign_device",
       (PyCFunction)pyxc_test_assign_device,
       METH_VARARGS | METH_KEYWORDS, "\n"
       "test device assignment with VT-d.\n"
       " dom     [int]:      Identifier of domain to build into.\n"
       " pci_str [str]:      PCI devices.\n"
       "Returns: [int] 0 on success, or device bdf that can't be assigned.\n" },

     { "assign_device",
       (PyCFunction)pyxc_assign_device,
       METH_VARARGS | METH_KEYWORDS, "\n"
       "Assign device to IOMMU domain.\n"
       " dom     [int]:      Domain to assign device to.\n"
       " pci_str [str]:      PCI devices.\n"
       "Returns: [int] 0 on success, or device bdf that can't be assigned.\n" },

     { "deassign_device",
       (PyCFunction)pyxc_deassign_device,
       METH_VARARGS | METH_KEYWORDS, "\n"
       "Deassign device from IOMMU domain.\n"
       " dom     [int]:      Domain to deassign device from.\n"
       " pci_str [str]:      PCI devices.\n"
       "Returns: [int] 0 on success, or device bdf that can't be deassigned.\n" },
  
    { "sched_id_get",
      (PyCFunction)pyxc_sched_id_get,
      METH_NOARGS, "\n"
      "Get the current scheduler type in use.\n"
      "Returns: [int] sched_id.\n" },    

    { "sched_credit_domain_set",
      (PyCFunction)pyxc_sched_credit_domain_set,
      METH_KEYWORDS, "\n"
      "Set the scheduling parameters for a domain when running with the\n"
      "SMP credit scheduler.\n"
      " domid     [int]:   domain id to set\n"
      " weight    [short]: domain's scheduling weight\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "sched_credit_domain_get",
      (PyCFunction)pyxc_sched_credit_domain_get,
      METH_VARARGS, "\n"
      "Get the scheduling parameters for a domain when running with the\n"
      "SMP credit scheduler.\n"
      " domid     [int]:   domain id to get\n"
      "Returns:   [dict]\n"
      " weight    [short]: domain's scheduling weight\n"},

    { "sched_credit2_domain_set",
      (PyCFunction)pyxc_sched_credit2_domain_set,
      METH_KEYWORDS, "\n"
      "Set the scheduling parameters for a domain when running with the\n"
      "SMP credit2 scheduler.\n"
      " domid     [int]:   domain id to set\n"
      " weight    [short]: domain's scheduling weight\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "sched_credit2_domain_get",
      (PyCFunction)pyxc_sched_credit2_domain_get,
      METH_VARARGS, "\n"
      "Get the scheduling parameters for a domain when running with the\n"
      "SMP credit2 scheduler.\n"
      " domid     [int]:   domain id to get\n"
      "Returns:   [dict]\n"
      " weight    [short]: domain's scheduling weight\n"},

    { "evtchn_alloc_unbound", 
      (PyCFunction)pyxc_evtchn_alloc_unbound,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allocate an unbound port that will await a remote connection.\n"
      " dom        [int]: Domain whose port space to allocate from.\n"
      " remote_dom [int]: Remote domain to accept connections from.\n\n"
      "Returns: [int] Unbound event-channel port.\n" },

    { "evtchn_reset", 
      (PyCFunction)pyxc_evtchn_reset,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Reset all connections.\n"
      " dom [int]: Domain to reset.\n" },

    { "physdev_map_pirq",
      (PyCFunction)pyxc_physdev_map_pirq,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "map physical irq to guest pirq.\n"
      " dom     [int]:      Identifier of domain to map for.\n"
      " index   [int]:      physical irq.\n"
      " pirq    [int]:      guest pirq.\n"
      "Returns: [long] value of the param.\n" },

    { "physdev_pci_access_modify",
      (PyCFunction)pyxc_physdev_pci_access_modify,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allow a domain access to a PCI device\n"
      " dom    [int]: Identifier of domain to be allowed access.\n"
      " bus    [int]: PCI bus\n"
      " dev    [int]: PCI slot\n"
      " func   [int]: PCI function\n"
      " enable [int]: Non-zero means enable access; else disable access\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },
 
    { "readconsolering", 
      (PyCFunction)pyxc_readconsolering, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Read Xen's console ring.\n"
      " clear [int, 0]: Bool - clear the ring after reading from it?\n\n"
      "Returns: [str] string is empty on failure.\n" },

    { "physinfo",
      (PyCFunction)pyxc_physinfo,
      METH_NOARGS, "\n"
      "Get information about the physical host machine\n"
      "Returns [dict]: information about the hardware"
      "        [None]: on failure.\n" },

    { "getcpuinfo",
      (PyCFunction)pyxc_getcpuinfo,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information about physical CPUs\n"
      "Returns [list]: information about physical CPUs"
      "        [None]: on failure.\n" },

    { "topologyinfo",
      (PyCFunction)pyxc_topologyinfo,
      METH_NOARGS, "\n"
      "Get information about the cpu topology on the host machine\n"
      "Returns [dict]: information about the cpu topology on host"
      "        [None]: on failure.\n" },

    { "numainfo",
      (PyCFunction)pyxc_numainfo,
      METH_NOARGS, "\n"
      "Get NUMA information on the host machine\n"
      "Returns [dict]: NUMA information on host"
      "        [None]: on failure.\n" },

    { "xeninfo",
      (PyCFunction)pyxc_xeninfo,
      METH_NOARGS, "\n"
      "Get information about the Xen host\n"
      "Returns [dict]: information about Xen"
      "        [None]: on failure.\n" },

    { "shadow_control", 
      (PyCFunction)pyxc_shadow_control, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set parameter for shadow pagetable interface\n"
      " dom [int]:   Identifier of domain.\n"
      " op [int, 0]: operation\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "shadow_mem_control", 
      (PyCFunction)pyxc_shadow_mem_control, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set or read shadow pagetable memory use\n"
      " dom [int]:   Identifier of domain.\n"
      " mb [int, -1]: MB of shadow memory this domain should have.\n\n"
      "Returns: [int] MB of shadow memory in use by this domain.\n" },

    { "domain_setmaxmem", 
      (PyCFunction)pyxc_domain_setmaxmem, 
      METH_VARARGS, "\n"
      "Set a domain's memory limit\n"
      " dom [int]: Identifier of domain.\n"
      " maxmem_kb [int]: .\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_set_target_mem", 
      (PyCFunction)pyxc_domain_set_target_mem, 
      METH_VARARGS, "\n"
      "Set a domain's memory target\n"
      " dom [int]: Identifier of domain.\n"
      " mem_kb [int]: .\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_set_memmap_limit", 
      (PyCFunction)pyxc_domain_set_memmap_limit, 
      METH_VARARGS, "\n"
      "Set a domain's physical memory mappping limit\n"
      " dom [int]: Identifier of domain.\n"
      " map_limitkb [int]: .\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_ioport_permission",
      (PyCFunction)pyxc_domain_ioport_permission,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allow a domain access to a range of IO ports\n"
      " dom          [int]: Identifier of domain to be allowed access.\n"
      " first_port   [int]: First IO port\n"
      " nr_ports     [int]: Number of IO ports\n"
      " allow_access [int]: Non-zero means enable access; else disable access\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_irq_permission",
      (PyCFunction)pyxc_domain_irq_permission,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allow a domain access to a physical IRQ\n"
      " dom          [int]: Identifier of domain to be allowed access.\n"
      " pirq         [int]: The Physical IRQ\n"
      " allow_access [int]: Non-zero means enable access; else disable access\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_iomem_permission",
      (PyCFunction)pyxc_domain_iomem_permission,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allow a domain access to a range of IO memory pages\n"
      " dom          [int]: Identifier of domain to be allowed access.\n"
      " first_pfn   [long]: First page of I/O Memory\n"
      " nr_pfns     [long]: Number of pages of I/O Memory (>0)\n"
      " allow_access [int]: Non-zero means enable access; else disable access\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "pages_to_kib",
      (PyCFunction)pyxc_pages_to_kib,
      METH_VARARGS, "\n"
      "Returns: [int]: The size in KiB of memory spanning the given number "
      "of pages.\n" },

    { "domain_set_time_offset",
      (PyCFunction)pyxc_domain_set_time_offset,
      METH_VARARGS, "\n"
      "Set a domain's time offset to Dom0's localtime\n"
      " dom        [int]: Domain whose time offset is being set.\n"
      " offset     [int]: Time offset from UTC in seconds.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_set_tsc_info",
      (PyCFunction)pyxc_domain_set_tsc_info,
      METH_VARARGS, "\n"
      "Set a domain's TSC mode\n"
      " dom        [int]: Domain whose TSC mode is being set.\n"
      " tsc_mode   [int]: 0=default (monotonic, but native where possible)\n"
      "                   1=always emulate 2=never emulate 3=pvrdtscp\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_disable_migrate",
      (PyCFunction)pyxc_domain_disable_migrate,
      METH_VARARGS, "\n"
      "Marks domain as non-migratable AND non-restoreable\n"
      " dom        [int]: Domain whose TSC mode is being set.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_send_trigger",
      (PyCFunction)pyxc_domain_send_trigger,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Send trigger to a domain.\n"
      " dom     [int]: Identifier of domain to be sent trigger.\n"
      " trigger [int]: Trigger type number.\n"
      " vcpu    [int]: VCPU to be sent trigger.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "send_debug_keys",
      (PyCFunction)pyxc_send_debug_keys,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Inject debug keys into Xen.\n"
      " keys    [str]: String of keys to inject.\n" },

#if defined(__i386__) || defined(__x86_64__)
    { "domain_check_cpuid", 
      (PyCFunction)pyxc_dom_check_cpuid, 
      METH_VARARGS, "\n"
      "Apply checks to host CPUID.\n"
      " input [long]: Input for cpuid instruction (eax)\n"
      " sub_input [long]: Second input (optional, may be None) for cpuid "
      "                     instruction (ecx)\n"
      " config [dict]: Dictionary of register\n"
      " config [dict]: Dictionary of register, use for checking\n\n"
      "Returns: [int] 0 on success; exception on error.\n" },
    
    { "domain_set_cpuid", 
      (PyCFunction)pyxc_dom_set_cpuid, 
      METH_VARARGS, "\n"
      "Set cpuid response for an input and a domain.\n"
      " dom [int]: Identifier of domain.\n"
      " input [long]: Input for cpuid instruction (eax)\n"
      " sub_input [long]: Second input (optional, may be None) for cpuid "
      "                     instruction (ecx)\n"
      " config [dict]: Dictionary of register\n\n"
      "Returns: [int] 0 on success; exception on error.\n" },

    { "domain_set_policy_cpuid", 
      (PyCFunction)pyxc_dom_set_policy_cpuid, 
      METH_VARARGS, "\n"
      "Set the default cpuid policy for a domain.\n"
      " dom [int]: Identifier of domain.\n\n"
      "Returns: [int] 0 on success; exception on error.\n" },

    { "domain_set_machine_address_size",
      (PyCFunction)pyxc_dom_set_machine_address_size,
      METH_VARARGS, "\n"
      "Set maximum machine address size for this domain.\n"
      " dom [int]: Identifier of domain.\n"
      " width [int]: Maximum machine address width.\n" },

    { "domain_suppress_spurious_page_faults",
      (PyCFunction)pyxc_dom_suppress_spurious_page_faults,
      METH_VARARGS, "\n"
      "Do not propagate spurious page faults to this guest.\n"
      " dom [int]: Identifier of domain.\n" },
#endif

    { "tmem_control",
      (PyCFunction)pyxc_tmem_control,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Do various control on a tmem pool.\n"
      " pool_id [int]: Identifier of the tmem pool (-1 == all).\n"
      " subop [int]: Supplementary Operation.\n"
      " cli_id [int]: Client identifier (-1 == all).\n"
      " len [int]: Length of 'buf'.\n"
      " arg [int]: Argument.\n"
      " buf [str]: Buffer.\n\n"
      "Returns: [int] 0 or [str] tmem info on success; exception on error.\n" },

    { "tmem_shared_auth",
      (PyCFunction)pyxc_tmem_shared_auth,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "De/authenticate a shared tmem pool.\n"
      " cli_id [int]: Client identifier (-1 == all).\n"
      " uuid_str [str]: uuid.\n"
      " auth [int]: 0|1 .\n"
      "Returns: [int] 0 on success; exception on error.\n" },

    { "dom_set_memshr", 
      (PyCFunction)pyxc_dom_set_memshr,
      METH_VARARGS, "\n"
      "Enable/disable memory sharing for the domain.\n"
      " dom     [int]:        Domain identifier.\n"
      " enable  [int,0|1]:    Disable or enable?\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "cpupool_create",
      (PyCFunction)pyxc_cpupool_create,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create new cpupool.\n"
      " pool    [int, 0]: cpupool identifier to use (allocated if zero).\n"
      " sched   [int]: scheduler to use (credit if unspecified).\n\n"
      "Returns: [int] new cpupool identifier; -1 on error.\n" },

    { "cpupool_destroy",
      (PyCFunction)pyxc_cpupool_destroy,
      METH_VARARGS, "\n"
      "Destroy a cpupool.\n"
      " pool [int]:    Identifier of cpupool to be destroyed.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "cpupool_getinfo",
      (PyCFunction)pyxc_cpupool_getinfo,
      METH_NOARGS, "\n"
      "Get information regarding a set of cpupools, in increasing id order.\n"
      "Returns: [list of dicts]\n"
      " pool     [int]: Identifier of cpupool to which this info pertains\n"
      " sched    [int]:  Scheduler used for this cpupool\n"
      " n_dom    [int]:  Number of Domains in this cpupool\n"
      " cpulist  [list]: List of CPUs this cpupool is using\n" },

    { "cpupool_addcpu",
       (PyCFunction)pyxc_cpupool_addcpu,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Add a cpu to a cpupool.\n"
      " pool    [int]: Identifier of cpupool.\n"
      " cpu     [int, -1]: Cpu to add (lowest free if -1)\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "cpupool_removecpu",
       (PyCFunction)pyxc_cpupool_removecpu,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Remove a cpu from a cpupool.\n"
      " pool    [int]: Identifier of cpupool.\n"
      " cpu     [int, -1]: Cpu to remove (highest used if -1)\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "cpupool_movedomain",
       (PyCFunction)pyxc_cpupool_movedomain,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Move a domain to another cpupool.\n"
      " pool    [int]: Identifier of cpupool to move domain to.\n"
      " dom     [int]: Domain to move\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "cpupool_freeinfo",
      (PyCFunction)pyxc_cpupool_freeinfo,
      METH_NOARGS, "\n"
      "Get info about cpus not in any cpupool.\n"
      "Returns: [list]: List of CPUs\n" },

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


static PyObject *PyXc_getattr(PyObject *obj, char *name)
{
    return Py_FindMethod(pyxc_methods, obj, name);
}

static PyObject *PyXc_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    XcObject *self = (XcObject *)type->tp_alloc(type, 0);

    if (self == NULL)
        return NULL;

    self->xc_handle = NULL;

    return (PyObject *)self;
}

static int
PyXc_init(XcObject *self, PyObject *args, PyObject *kwds)
{
    if ((self->xc_handle = xc_interface_open(0,0,0)) == 0) {
        pyxc_error_to_exception(0);
        return -1;
    }

    return 0;
}

static void PyXc_dealloc(XcObject *self)
{
    if (self->xc_handle) {
        xc_interface_close(self->xc_handle);
        self->xc_handle = NULL;
    }

    self->ob_type->tp_free((PyObject *)self);
}

static PyTypeObject PyXcType = {
    PyObject_HEAD_INIT(NULL)
    0,
    PKG "." CLS,
    sizeof(XcObject),
    0,
    (destructor)PyXc_dealloc,     /* tp_dealloc        */
    NULL,                         /* tp_print          */
    PyXc_getattr,                 /* tp_getattr        */
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
    "Xen client connections",     /* tp_doc            */
    NULL,                         /* tp_traverse       */
    NULL,                         /* tp_clear          */
    NULL,                         /* tp_richcompare    */
    0,                            /* tp_weaklistoffset */
    NULL,                         /* tp_iter           */
    NULL,                         /* tp_iternext       */
    pyxc_methods,                 /* tp_methods        */
    NULL,                         /* tp_members        */
    NULL,                         /* tp_getset         */
    NULL,                         /* tp_base           */
    NULL,                         /* tp_dict           */
    NULL,                         /* tp_descr_get      */
    NULL,                         /* tp_descr_set      */
    0,                            /* tp_dictoffset     */
    (initproc)PyXc_init,          /* tp_init           */
    NULL,                         /* tp_alloc          */
    PyXc_new,                     /* tp_new            */
};

static PyMethodDef xc_methods[] = { { NULL } };

PyMODINIT_FUNC initxc(void)
{
    PyObject *m;

    if (PyType_Ready(&PyXcType) < 0)
        return;

    m = Py_InitModule(PKG, xc_methods);

    if (m == NULL)
      return;

    xc_error_obj = PyErr_NewException(PKG ".Error", PyExc_RuntimeError, NULL);
    zero = PyInt_FromLong(0);

    /* KAF: This ensures that we get debug output in a timely manner. */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    Py_INCREF(&PyXcType);
    PyModule_AddObject(m, CLS, (PyObject *)&PyXcType);

    Py_INCREF(xc_error_obj);
    PyModule_AddObject(m, "Error", xc_error_obj);

    /* Expose some libxc constants to Python */
    PyModule_AddIntConstant(m, "XEN_SCHEDULER_CREDIT", XEN_SCHEDULER_CREDIT);
    PyModule_AddIntConstant(m, "XEN_SCHEDULER_CREDIT2", XEN_SCHEDULER_CREDIT2);

}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
