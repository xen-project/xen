/******************************************************************************
 * Xc.c
 * 
 * Copyright (c) 2003-2004, K A Fraser (University of Cambridge)
 */

#include <Python.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <zlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "xc_private.h"

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define PKG "xen.lowlevel.xc"
#define CLS "xc"

static PyObject *xc_error, *zero;

typedef struct {
    PyObject_HEAD;
    int xc_handle;
} XcObject;


static PyObject *dom_op(XcObject *self, PyObject *args,
                        int (*fn)(int, uint32_t));


static PyObject *pyxc_domain_dumpcore(XcObject *self, PyObject *args)
{
    uint32_t dom;
    char *corefile;

    if (!PyArg_ParseTuple(args, "is", &dom, &corefile))
        return NULL;

    if ( (corefile == NULL) || (corefile[0] == '\0') )
        return NULL;

    if (xc_domain_dumpcore(self->xc_handle, dom, corefile) != 0)
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_handle(XcObject *self)
{
    return PyInt_FromLong(self->xc_handle);
}

static PyObject *pyxc_domain_create(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom = 0;
    int      ret, i;
    uint32_t ssidref = 0;
    PyObject *pyhandle = NULL;
    xen_domain_handle_t handle = { 
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

    static char *kwd_list[] = { "dom", "ssidref", "handle", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iiO", kwd_list,
                                      &dom, &ssidref, &pyhandle))
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

    if ( (ret = xc_domain_create(self->xc_handle, ssidref, handle, &dom)) < 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyInt_FromLong(dom);

out_exception:
    errno = EINVAL;
    PyErr_SetFromErrno(xc_error);
    return NULL;
}

static PyObject *pyxc_domain_max_vcpus(XcObject *self, PyObject *args)
{
    uint32_t dom, max;

    if (!PyArg_ParseTuple(args, "ii", &dom, &max))
      return NULL;

    if (xc_domain_max_vcpus(self->xc_handle, dom, max) != 0)
        return PyErr_SetFromErrno(xc_error);
    
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

static PyObject *pyxc_domain_destroy(XcObject *self, PyObject *args)
{
    return dom_op(self, args, xc_domain_destroy);
}


static PyObject *pyxc_domain_pincpu(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    uint32_t dom;
    int vcpu = 0, i;
    cpumap_t cpumap = ~0ULL;
    PyObject *cpulist = NULL;

    static char *kwd_list[] = { "dom", "vcpu", "cpumap", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|iO", kwd_list, 
                                      &dom, &vcpu, &cpulist) )
        return NULL;

    if ( (cpulist != NULL) && PyList_Check(cpulist) )
    {
        cpumap = 0ULL;
        for ( i = 0; i < PyList_Size(cpulist); i++ ) 
            cpumap |= (cpumap_t)1 << PyInt_AsLong(PyList_GetItem(cpulist, i));
    }
  
    if ( xc_domain_pincpu(self->xc_handle, dom, vcpu, cpumap) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_setcpuweight(XcObject *self,
					  PyObject *args,
					  PyObject *kwds)
{
    uint32_t dom;
    float cpuweight = 1;

    static char *kwd_list[] = { "dom", "cpuweight", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|f", kwd_list, 
                                      &dom, &cpuweight) )
        return NULL;

    if ( xc_domain_setcpuweight(self->xc_handle, dom, cpuweight) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
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
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;

out_exception:
    errno = EINVAL;
    PyErr_SetFromErrno(xc_error);
    return NULL;
}


static PyObject *pyxc_domain_getinfo(XcObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    PyObject *list, *info_dict;

    uint32_t first_dom = 0;
    int max_doms = 1024, nr_doms, i, j;
    xc_dominfo_t *info;

    static char *kwd_list[] = { "first_dom", "max_doms", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list,
                                      &first_dom, &max_doms) )
        return NULL;

    if ( (info = malloc(max_doms * sizeof(xc_dominfo_t))) == NULL )
        return PyErr_NoMemory();

    nr_doms = xc_domain_getinfo(self->xc_handle, first_dom, max_doms, info);

    if (nr_doms < 0)
    {
        free(info);
        return PyErr_SetFromErrno(xc_error);
    }

    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        PyObject *pyhandle = PyList_New(sizeof(xen_domain_handle_t));
        for ( j = 0; j < sizeof(xen_domain_handle_t); j++ )
            PyList_SetItem(pyhandle, j, PyInt_FromLong(info[i].handle[j]));
        info_dict = Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i"
                                  ",s:l,s:L,s:l,s:i,s:i}",
                                  "dom",       info[i].domid,
                                  "online_vcpus", info[i].nr_online_vcpus,
                                  "max_vcpu_id", info[i].max_vcpu_id,
                                  "dying",     info[i].dying,
                                  "crashed",   info[i].crashed,
                                  "shutdown",  info[i].shutdown,
                                  "paused",    info[i].paused,
                                  "blocked",   info[i].blocked,
                                  "running",   info[i].running,
                                  "mem_kb",    info[i].nr_pages*(XC_PAGE_SIZE/1024),
                                  "cpu_time",  info[i].cpu_time,
                                  "maxmem_kb", info[i].max_memkb,
                                  "ssidref",   info[i].ssidref,
                                  "shutdown_reason", info[i].shutdown_reason);
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
    cpumap_t cpumap;

    static char *kwd_list[] = { "dom", "vcpu", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list,
                                      &dom, &vcpu) )
        return NULL;

    rc = xc_domain_get_vcpu_info(self->xc_handle, dom, vcpu, &info);
    if ( rc < 0 )
        return PyErr_SetFromErrno(xc_error);

    info_dict = Py_BuildValue("{s:i,s:i,s:i,s:L,s:i}",
                              "online",   info.online,
                              "blocked",  info.blocked,
                              "running",  info.running,
                              "cpu_time", info.cpu_time,
                              "cpu",      info.cpu);

    cpumap = info.cpumap;
    cpulist = PyList_New(0);
    for ( i = 0; cpumap != 0; i++ )
    {
        if ( cpumap & 1 )
            PyList_Append(cpulist, PyInt_FromLong(i));
        cpumap >>= 1;
    }
    PyDict_SetItemString(info_dict, "cpumap", cpulist);
    Py_DECREF(cpulist);
    return info_dict;
}

static PyObject *pyxc_linux_build(XcObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    uint32_t dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    int flags = 0;
    int store_evtchn, console_evtchn;
    unsigned long store_mfn = 0;
    unsigned long console_mfn = 0;

    static char *kwd_list[] = { "dom", "store_evtchn", 
                                "console_evtchn", "image", 
				/* optional */
				"ramdisk", "cmdline", "flags", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiis|ssi", kwd_list,
                                      &dom, &store_evtchn,
				      &console_evtchn, &image, 
				      /* optional */
				      &ramdisk, &cmdline, &flags) )
        return NULL;

    if ( xc_linux_build(self->xc_handle, dom, image,
                        ramdisk, cmdline, flags,
                        store_evtchn, &store_mfn, 
			console_evtchn, &console_mfn) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    return Py_BuildValue("{s:i,s:i}", 
			 "store_mfn", store_mfn,
			 "console_mfn", console_mfn);
}

static PyObject *pyxc_vmx_build(XcObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    uint32_t dom;
    char *image;
    int control_evtchn, store_evtchn;
    int vcpus = 1;
    int lapic = 0;
    int acpi = 0;
    int memsize;
    unsigned long store_mfn = 0;

    static char *kwd_list[] = { "dom", "control_evtchn", "store_evtchn",
                                "memsize", "image", "lapic", "vcpus", "acpi",NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiisiii", kwd_list,
                                      &dom, &control_evtchn, &store_evtchn,
                                      &memsize, &image, &lapic, &vcpus,&acpi) )
        return NULL;

    if ( xc_vmx_build(self->xc_handle, dom, memsize, image, control_evtchn,
                      lapic, vcpus, acpi, store_evtchn, &store_mfn) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i}", "store_mfn", store_mfn);
}

static PyObject *pyxc_bvtsched_global_set(XcObject *self, PyObject *args)
{
    unsigned long ctx_allow;

    if (!PyArg_ParseTuple(args, "l", &ctx_allow))
        return NULL;

    if (xc_bvtsched_global_set(self->xc_handle, ctx_allow) != 0)
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_bvtsched_global_get(XcObject *self)
{
    unsigned long ctx_allow;
    
    if (xc_bvtsched_global_get(self->xc_handle, &ctx_allow) != 0)
        return PyErr_SetFromErrno(xc_error);
    
    return Py_BuildValue("s:l", "ctx_allow", ctx_allow);
}

static PyObject *pyxc_bvtsched_domain_set(XcObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    uint32_t dom;
    uint32_t mcuadv;
    int warpback; 
    int32_t warpvalue;
    long long warpl;
    long long warpu;

    static char *kwd_list[] = { "dom", "mcuadv", "warpback", "warpvalue",
                                "warpl", "warpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiiLL", kwd_list,
                                      &dom, &mcuadv, &warpback, &warpvalue, 
                                      &warpl, &warpu) )
        return NULL;

    if ( xc_bvtsched_domain_set(self->xc_handle, dom, mcuadv, 
                                warpback, warpvalue, warpl, warpu) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_bvtsched_domain_get(XcObject *self,
                                          PyObject *args)
{
    uint32_t dom;
    uint32_t mcuadv;
    int warpback; 
    int32_t warpvalue;
    long long warpl;
    long long warpu;
    
    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;
    
    if (xc_bvtsched_domain_get(self->xc_handle, dom, &mcuadv, &warpback,
                               &warpvalue, &warpl, &warpu) != 0)
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i,s:l,s:l,s:l,s:l}",
                         "domain", dom,
                         "mcuadv", mcuadv,
                         "warpback", warpback,
                         "warpvalue", warpvalue,
                         "warpl", warpl,
                         "warpu", warpu);
}

static PyObject *pyxc_evtchn_alloc_unbound(XcObject *self,
                                           PyObject *args,
                                           PyObject *kwds)
{
    uint32_t dom, remote_dom;
    int port;

    static char *kwd_list[] = { "dom", "remote_dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list,
                                      &dom, &remote_dom) )
        return NULL;

    if ( (port = xc_evtchn_alloc_unbound(self->xc_handle, dom, remote_dom)) < 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyInt_FromLong(port);
}

static PyObject *pyxc_evtchn_status(XcObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    PyObject *dict;

    uint32_t dom = DOMID_SELF;
    int port, ret;
    xc_evtchn_status_t status;

    static char *kwd_list[] = { "port", "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &port, &dom) )
        return NULL;

    ret = xc_evtchn_status(self->xc_handle, dom, port, &status);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

    switch ( status.status )
    {
    case EVTCHNSTAT_closed:
        dict = Py_BuildValue("{s:s}", 
                             "status", "closed");
        break;
    case EVTCHNSTAT_unbound:
        dict = Py_BuildValue("{s:s}", 
                             "status", "unbound");
        break;
    case EVTCHNSTAT_interdomain:
        dict = Py_BuildValue("{s:s,s:i,s:i}", 
                             "status", "interdomain",
                             "dom", status.u.interdomain.dom,
                             "port", status.u.interdomain.port);
        break;
    case EVTCHNSTAT_pirq:
        dict = Py_BuildValue("{s:s,s:i}", 
                             "status", "pirq",
                             "irq", status.u.pirq);
        break;
    case EVTCHNSTAT_virq:
        dict = Py_BuildValue("{s:s,s:i}", 
                             "status", "virq",
                             "irq", status.u.virq);
        break;
    default:
        dict = Py_BuildValue("{}");
        break;
    }
    
    return dict;
}

static PyObject *pyxc_physdev_pci_access_modify(XcObject *self,
                                                PyObject *args,
                                                PyObject *kwds)
{
    uint32_t dom;
    int bus, dev, func, enable, ret;

    static char *kwd_list[] = { "dom", "bus", "dev", "func", "enable", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiii", kwd_list, 
                                      &dom, &bus, &dev, &func, &enable) )
        return NULL;

    ret = xc_physdev_pci_access_modify(
        self->xc_handle, dom, bus, dev, func, enable);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_readconsolering(XcObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    unsigned int clear = 0;
    char         _str[32768], *str = _str;
    unsigned int count = 32768;
    int          ret;

    static char *kwd_list[] = { "clear", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwd_list, &clear) )
        return NULL;

    ret = xc_readconsolering(self->xc_handle, &str, &count, clear);
    if ( ret < 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyString_FromStringAndSize(str, count);
}


static PyObject *pyxc_pages_to_kib(XcObject *self, PyObject *args)
{
    unsigned long pages;

    if (!PyArg_ParseTuple(args, "l", &pages))
        return NULL;

    return PyLong_FromUnsignedLong(pages * (XC_PAGE_SIZE / 1024));
}


static unsigned long pages_to_mb(unsigned long pages)
{
    return (pages * (XC_PAGE_SIZE / 1024) + 1023) / 1024;
}


static PyObject *pyxc_physinfo(XcObject *self)
{
    xc_physinfo_t info;
    char cpu_cap[128], *p=cpu_cap, *q=cpu_cap;
    int i;
    
    if ( xc_physinfo(self->xc_handle, &info) != 0 )
        return PyErr_SetFromErrno(xc_error);

    *q=0;
    for(i=0;i<sizeof(info.hw_cap)/4;i++)
    {
        p+=sprintf(p,"%08x:",info.hw_cap[i]);
        if(info.hw_cap[i])
	    q=p;
    }
    if(q>cpu_cap)
        *(q-1)=0;

    return Py_BuildValue("{s:i,s:i,s:i,s:i,s:l,s:l,s:i,s:s}",
                         "threads_per_core", info.threads_per_core,
                         "cores_per_socket", info.cores_per_socket,
                         "sockets_per_node", info.sockets_per_node,
                         "nr_nodes",         info.nr_nodes,
                         "total_memory",     pages_to_mb(info.total_pages),
                         "free_memory",      pages_to_mb(info.free_pages),
                         "cpu_khz",          info.cpu_khz,
                         "hw_caps",          cpu_cap);
}

static PyObject *pyxc_xeninfo(XcObject *self)
{
    xen_extraversion_t xen_extra;
    xen_compile_info_t xen_cc;
    xen_changeset_info_t xen_chgset;
    xen_capabilities_info_t xen_caps;
    xen_platform_parameters_t p_parms;
    long xen_version;
    char str[128];

    xen_version = xc_version(self->xc_handle, XENVER_version, NULL);

    if ( xc_version(self->xc_handle, XENVER_extraversion, &xen_extra) != 0 )
        return PyErr_SetFromErrno(xc_error);

    if ( xc_version(self->xc_handle, XENVER_compile_info, &xen_cc) != 0 )
        return PyErr_SetFromErrno(xc_error);

    if ( xc_version(self->xc_handle, XENVER_changeset, &xen_chgset) != 0 )
        return PyErr_SetFromErrno(xc_error);

    if ( xc_version(self->xc_handle, XENVER_capabilities, &xen_caps) != 0 )
        return PyErr_SetFromErrno(xc_error);

    if ( xc_version(self->xc_handle, XENVER_platform_parameters, &p_parms) != 0 )
        return PyErr_SetFromErrno(xc_error);

    sprintf(str, "virt_start=0x%lx", p_parms.virt_start);

    return Py_BuildValue("{s:i,s:i,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s}",
                         "xen_major", xen_version >> 16,
                         "xen_minor", (xen_version & 0xffff),
                         "xen_extra", xen_extra,
                         "xen_caps",  xen_caps,
                         "platform_params", str,
                         "xen_changeset", xen_chgset,
                         "cc_compiler", xen_cc.compiler,
                         "cc_compile_by", xen_cc.compile_by,
                         "cc_compile_domain", xen_cc.compile_domain,
                         "cc_compile_date", xen_cc.compile_date);
}


static PyObject *pyxc_sedf_domain_set(XcObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    uint32_t domid;
    uint64_t period, slice, latency;
    uint16_t extratime, weight;
    static char *kwd_list[] = { "dom", "period", "slice",
                                "latency", "extratime", "weight",NULL };
    
    if( !PyArg_ParseTupleAndKeywords(args, kwds, "iLLLhh", kwd_list, 
                                     &domid, &period, &slice,
                                     &latency, &extratime, &weight) )
        return NULL;
   if ( xc_sedf_domain_set(self->xc_handle, domid, period,
                           slice, latency, extratime,weight) != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_sedf_domain_get(XcObject *self, PyObject *args)
{
    uint32_t domid;
    uint64_t period, slice,latency;
    uint16_t weight, extratime;
    
    if(!PyArg_ParseTuple(args, "i", &domid))
        return NULL;
    
    if (xc_sedf_domain_get(self->xc_handle, domid, &period,
                           &slice,&latency,&extratime,&weight))
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i,s:L,s:L,s:L,s:i,s:i}",
                         "domain",    domid,
                         "period",    period,
                         "slice",     slice,
			 "latency",   latency,
			 "extratime", extratime,
                         "weight",    weight);
}

static PyObject *pyxc_domain_setmaxmem(XcObject *self, PyObject *args)
{
    uint32_t dom;
    unsigned int maxmem_kb;

    if (!PyArg_ParseTuple(args, "ii", &dom, &maxmem_kb))
        return NULL;

    if (xc_domain_setmaxmem(self->xc_handle, dom, maxmem_kb) != 0)
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_memory_increase_reservation(XcObject *self,
							 PyObject *args,
							 PyObject *kwds)
{
    uint32_t dom;
    unsigned long mem_kb;
    unsigned int extent_order = 0 , address_bits = 0;
    unsigned long nr_extents;

    static char *kwd_list[] = { "dom", "mem_kb", "extent_order", "address_bits", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "il|ii", kwd_list, 
                                      &dom, &mem_kb, &extent_order, &address_bits) )
        return NULL;

    /* round down to nearest power of 2. Assume callers using extent_order>0
       know what they are doing */
    nr_extents = (mem_kb / (XC_PAGE_SIZE/1024)) >> extent_order;
    if ( xc_domain_memory_increase_reservation(self->xc_handle, dom, 
					       nr_extents, extent_order, 
					       address_bits, NULL) )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_ioport_permission(XcObject *self,
                                               PyObject *args,
                                               PyObject *kwds)
{
    uint32_t dom;
    int first_port, nr_ports, allow_access, ret;

    static char *kwd_list[] = { "dom", "first_port", "nr_ports", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiii", kwd_list, 
                                      &dom, &first_port, &nr_ports, &allow_access) )
        return NULL;

    ret = xc_domain_ioport_permission(
        self->xc_handle, dom, first_port, nr_ports, allow_access);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

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

    static char *kwd_list[] = { "dom", "pirq", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iii", kwd_list, 
                                      &dom, &pirq, &allow_access) )
        return NULL;

    ret = xc_domain_irq_permission(
        xc->xc_handle, dom, pirq, allow_access);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

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

    static char *kwd_list[] = { "dom", "first_pfn", "nr_pfns", "allow_access", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "illi", kwd_list, 
                                      &dom, &first_pfn, &nr_pfns, &allow_access) )
        return NULL;

    ret = xc_domain_iomem_permission(
        xc->xc_handle, dom, first_pfn, nr_pfns, allow_access);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}


static PyObject *dom_op(XcObject *self, PyObject *args,
                        int (*fn)(int, uint32_t))
{
    uint32_t dom;

    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;

    if (fn(self->xc_handle, dom) != 0)
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}


static PyMethodDef pyxc_methods[] = {
    { "handle",
      (PyCFunction)pyxc_handle,
      METH_NOARGS, "\n"
      "Query the xc control interface file descriptor.\n\n"
      "Returns: [int] file descriptor\n" },

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

    { "domain_pincpu", 
      (PyCFunction)pyxc_domain_pincpu, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Pin a VCPU to a specified set CPUs.\n"
      " dom [int]:     Identifier of domain to which VCPU belongs.\n"
      " vcpu [int, 0]: VCPU being pinned.\n"
      " cpumap [list, []]: list of usable CPUs.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_setcpuweight", 
      (PyCFunction)pyxc_domain_setcpuweight, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set cpuweight scheduler parameter for domain.\n"
      " dom [int]:            Identifier of domain to be changed.\n"
      " cpuweight [float, 1]: VCPU being pinned.\n"
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
      "reason why it shut itself down.\n" },

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

    { "linux_build", 
      (PyCFunction)pyxc_linux_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new Linux guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " ramdisk [str, n/a]: Name of ramdisk file, if any.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      " vcpus   [int, 1]:   Number of Virtual CPUS in domain.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vmx_build", 
      (PyCFunction)pyxc_vmx_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new VMX guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " image   [str]:      Name of VMX loader image file.\n"
      " vcpus   [int, 1]:   Number of Virtual CPUS in domain.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_global_set",
      (PyCFunction)pyxc_bvtsched_global_set,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set global tuning parameters for Borrowed Virtual Time scheduler.\n"
      " ctx_allow [int]: Minimal guaranteed quantum.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_global_get",
      (PyCFunction)pyxc_bvtsched_global_get,
      METH_NOARGS, "\n"
      "Get global tuning parameters for BVT scheduler.\n"
      "Returns: [dict]:\n"
      " ctx_allow [int]: context switch allowance\n" },

    { "bvtsched_domain_set",
      (PyCFunction)pyxc_bvtsched_domain_set,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set per-domain tuning parameters for Borrowed Virtual Time scheduler.\n"
      " dom       [int]: Identifier of domain to be tuned.\n"
      " mcuadv    [int]: Proportional to the inverse of the domain's weight.\n"
      " warpback  [int]: Warp ? \n"
      " warpvalue [int]: How far to warp domain's EVT on unblock.\n"
      " warpl     [int]: How long the domain can run warped.\n"
      " warpu     [int]: How long before the domain can warp again.\n\n"
      "Returns:   [int] 0 on success; -1 on error.\n" },

    { "bvtsched_domain_get",
      (PyCFunction)pyxc_bvtsched_domain_get,
      METH_VARARGS, "\n"
      "Get per-domain tuning parameters under the BVT scheduler.\n"
      " dom [int]: Identifier of domain to be queried.\n"
      "Returns [dict]:\n"
      " domain [int]:  Domain ID.\n"
      " mcuadv [long]: MCU Advance.\n"
      " warp   [long]: Warp.\n"
      " warpu  [long]: Unwarp requirement.\n"
      " warpl  [long]: Warp limit,\n"
    },
    
    { "sedf_domain_set",
      (PyCFunction)pyxc_sedf_domain_set,
      METH_KEYWORDS, "\n"
      "Set the scheduling parameters for a domain when running with Atropos.\n"
      " dom       [int]:  domain to set\n"
      " period    [long]: domain's scheduling period\n"
      " slice     [long]: domain's slice per period\n"
      " latency   [long]: domain's wakeup latency hint\n"
      " extratime [int]:  domain aware of extratime?\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "sedf_domain_get",
      (PyCFunction)pyxc_sedf_domain_get,
      METH_VARARGS, "\n"
      "Get the current scheduling parameters for a domain when running with\n"
      "the Atropos scheduler."
      " dom       [int]: domain to query\n"
      "Returns:   [dict]\n"
      " domain    [int]: domain ID\n"
      " period    [long]: scheduler period\n"
      " slice     [long]: CPU reservation per period\n"
      " latency   [long]: domain's wakeup latency hint\n"
      " extratime [int]:  domain aware of extratime?\n"},

    { "evtchn_alloc_unbound", 
      (PyCFunction)pyxc_evtchn_alloc_unbound,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allocate an unbound port that will await a remote connection.\n"
      " dom        [int]: Domain whose port space to allocate from.\n"
      " remote_dom [int]: Remote domain to accept connections from.\n\n"
      "Returns: [int] Unbound event-channel port.\n" },

    { "evtchn_status", 
      (PyCFunction)pyxc_evtchn_status, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Query the status of an event channel.\n"
      " dom  [int, SELF]: Dom-id of one endpoint of the channel.\n"
      " port [int]:       Port-id of one endpoint of the channel.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " status [str]:  'closed', 'unbound', 'interdomain', 'pirq',"
      " or 'virq'.\n"
      "The following are returned if 'status' is 'interdomain':\n"
      " dom  [int]: Dom-id of remote endpoint.\n"
      " port [int]: Port-id of remote endpoint.\n"
      "The following are returned if 'status' is 'pirq' or 'virq':\n"
      " irq  [int]: IRQ number.\n" },

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

    { "xeninfo",
      (PyCFunction)pyxc_xeninfo,
      METH_NOARGS, "\n"
      "Get information about the Xen host\n"
      "Returns [dict]: information about Xen"
      "        [None]: on failure.\n" },

    { "domain_setmaxmem", 
      (PyCFunction)pyxc_domain_setmaxmem, 
      METH_VARARGS, "\n"
      "Set a domain's memory limit\n"
      " dom [int]: Identifier of domain.\n"
      " maxmem_kb [int]: .\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_memory_increase_reservation", 
      (PyCFunction)pyxc_domain_memory_increase_reservation, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Increase a domain's memory reservation\n"
      " dom [int]: Identifier of domain.\n"
      " mem_kb [long]: .\n"
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

    self->xc_handle = -1;

    return (PyObject *)self;
}

static int
PyXc_init(XcObject *self, PyObject *args, PyObject *kwds)
{
    if ((self->xc_handle = xc_interface_open()) == -1) {
        PyErr_SetFromErrno(PyExc_RuntimeError);
        return -1;
    }

    return 0;
}

static void PyXc_dealloc(XcObject *self)
{
    if (self->xc_handle != -1) {
        xc_interface_close(self->xc_handle);
        self->xc_handle = -1;
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

    xc_error = PyErr_NewException(PKG ".error", NULL, NULL);
    zero = PyInt_FromLong(0);

    /* KAF: This ensures that we get debug output in a timely manner. */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    Py_INCREF(&PyXcType);
    PyModule_AddObject(m, CLS, (PyObject *)&PyXcType);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
