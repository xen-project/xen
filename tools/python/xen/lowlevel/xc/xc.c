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
#include <sys/mman.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "xenctrl.h"
#include <xen/elfnote.h>
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

static PyObject *xc_error_obj, *zero;

typedef struct {
    PyObject_HEAD;
    int xc_handle;
} XcObject;


static PyObject *dom_op(XcObject *self, PyObject *args,
                        int (*fn)(int, uint32_t));

static PyObject *pyxc_error_to_exception(void)
{
    PyObject *pyerr;
    const xc_error *err = xc_get_last_error();
    const char *desc = xc_error_code_to_desc(err->code);

    if (err->code == XC_ERROR_NONE)
        return PyErr_SetFromErrno(xc_error_obj);

    if (err->message[0] != '\0')
	pyerr = Py_BuildValue("(iss)", err->code, desc, err->message);
    else
	pyerr = Py_BuildValue("(is)", err->code, desc);

    xc_clear_last_error();

    PyErr_SetObject(xc_error_obj, pyerr);

    return NULL;
}

static PyObject *pyxc_domain_dumpcore(XcObject *self, PyObject *args)
{
    uint32_t dom;
    char *corefile;

    if (!PyArg_ParseTuple(args, "is", &dom, &corefile))
        return NULL;

    if ( (corefile == NULL) || (corefile[0] == '\0') )
        return NULL;

    if (xc_domain_dumpcore(self->xc_handle, dom, corefile) != 0)
        return pyxc_error_to_exception();
    
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
    uint32_t dom = 0, ssidref = 0, flags = 0;
    int      ret, i, hvm = 0;
    PyObject *pyhandle = NULL;
    xen_domain_handle_t handle = { 
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

    static char *kwd_list[] = { "domid", "ssidref", "handle", "hvm", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iiOi", kwd_list,
                                      &dom, &ssidref, &pyhandle, &hvm))
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

    if ( hvm )
        flags |= XEN_DOMCTL_CDF_hvm_guest;

    if ( (ret = xc_domain_create(self->xc_handle, ssidref,
                                 handle, flags, &dom)) < 0 )
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();
    
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

static PyObject *pyxc_domain_shutdown(XcObject *self, PyObject *args)
{
    uint32_t dom, reason;

    if (!PyArg_ParseTuple(args, "ii", &dom, &reason))
      return NULL;

    if (xc_domain_shutdown(self->xc_handle, dom, reason) != 0)
        return pyxc_error_to_exception();
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_resume(XcObject *self, PyObject *args)
{
    uint32_t dom;
    int fast;

    if (!PyArg_ParseTuple(args, "ii", &dom, &fast))
        return NULL;

    if (xc_domain_resume(self->xc_handle, dom, fast) != 0)
        return pyxc_error_to_exception();

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_vcpu_setaffinity(XcObject *self,
                                       PyObject *args,
                                       PyObject *kwds)
{
    uint32_t dom;
    int vcpu = 0, i;
    uint64_t  cpumap = ~0ULL;
    PyObject *cpulist = NULL;

    static char *kwd_list[] = { "domid", "vcpu", "cpumap", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|iO", kwd_list, 
                                      &dom, &vcpu, &cpulist) )
        return NULL;

    if ( (cpulist != NULL) && PyList_Check(cpulist) )
    {
        cpumap = 0ULL;
        for ( i = 0; i < PyList_Size(cpulist); i++ ) 
            cpumap |= (uint64_t)1 << PyInt_AsLong(PyList_GetItem(cpulist, i));
    }
  
    if ( xc_vcpu_setaffinity(self->xc_handle, dom, vcpu, cpumap) != 0 )
        return pyxc_error_to_exception();
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_setcpuweight(XcObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    uint32_t dom;
    float cpuweight = 1;

    static char *kwd_list[] = { "domid", "cpuweight", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|f", kwd_list, 
                                      &dom, &cpuweight) )
        return NULL;

    if ( xc_domain_setcpuweight(self->xc_handle, dom, cpuweight) != 0 )
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();
    }

    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        PyObject *pyhandle = PyList_New(sizeof(xen_domain_handle_t));
        for ( j = 0; j < sizeof(xen_domain_handle_t); j++ )
            PyList_SetItem(pyhandle, j, PyInt_FromLong(info[i].handle[j]));
        info_dict = Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i"
                                  ",s:l,s:L,s:l,s:i,s:i}",
                                  "domid",       info[i].domid,
                                  "online_vcpus", info[i].nr_online_vcpus,
                                  "max_vcpu_id", info[i].max_vcpu_id,
                                  "hvm",       info[i].hvm,
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
    uint64_t cpumap;

    static char *kwd_list[] = { "domid", "vcpu", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list,
                                      &dom, &vcpu) )
        return NULL;

    rc = xc_vcpu_getinfo(self->xc_handle, dom, vcpu, &info);
    if ( rc < 0 )
        return pyxc_error_to_exception();
    rc = xc_vcpu_getaffinity(self->xc_handle, dom, vcpu, &cpumap);
    if ( rc < 0 )
        return pyxc_error_to_exception();

    info_dict = Py_BuildValue("{s:i,s:i,s:i,s:L,s:i}",
                              "online",   info.online,
                              "blocked",  info.blocked,
                              "running",  info.running,
                              "cpu_time", info.cpu_time,
                              "cpu",      info.cpu);

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
    uint32_t domid;
    struct xc_dom_image *dom;
    char *image, *ramdisk = NULL, *cmdline = "", *features = NULL;
    int flags = 0;
    int store_evtchn, console_evtchn;
    unsigned int mem_mb;
    unsigned long store_mfn = 0;
    unsigned long console_mfn = 0;
    PyObject* elfnote_dict;
    PyObject* elfnote = NULL;
    int i;

    static char *kwd_list[] = { "domid", "store_evtchn", "memsize",
                                "console_evtchn", "image",
                                /* optional */
                                "ramdisk", "cmdline", "flags",
                                "features", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiis|ssis", kwd_list,
                                      &domid, &store_evtchn, &mem_mb,
                                      &console_evtchn, &image,
                                      /* optional */
                                      &ramdisk, &cmdline, &flags,
                                      &features) )
        return NULL;

    xc_dom_loginit();
    if (!(dom = xc_dom_allocate(cmdline, features)))
	return pyxc_error_to_exception();

    if ( xc_dom_linux_build(self->xc_handle, dom, domid, mem_mb, image,
			    ramdisk, flags, store_evtchn, &store_mfn,
			    console_evtchn, &console_mfn) != 0 ) {
	goto out;
    }

    if ( !(elfnote_dict = PyDict_New()) )
	goto out;
    
    for ( i = 0; i < ARRAY_SIZE(dom->parms.elf_notes); i++ )
    {
	switch ( dom->parms.elf_notes[i].type )
        {
	case XEN_ENT_NONE:
	    continue;
	case XEN_ENT_LONG:
	    elfnote = Py_BuildValue("k", dom->parms.elf_notes[i].data.num);
	    break;
	case XEN_ENT_STR:
	    elfnote = Py_BuildValue("s", dom->parms.elf_notes[i].data.str);
	    break;
	}
	PyDict_SetItemString(elfnote_dict,
			     dom->parms.elf_notes[i].name,
			     elfnote);
	Py_DECREF(elfnote);
    }

    xc_dom_release(dom);

    return Py_BuildValue("{s:i,s:i,s:N}", 
                         "store_mfn", store_mfn,
                         "console_mfn", console_mfn,
			 "notes", elfnote_dict);

  out:
    xc_dom_release(dom);
    return pyxc_error_to_exception();
}

static PyObject *pyxc_hvm_build(XcObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    uint32_t dom;
#if !defined(__ia64__)
    struct hvm_info_table *va_hvm;
    uint8_t *va_map, sum;
    int i;
#endif
    char *image;
    int store_evtchn, memsize, vcpus = 1, pae = 0, acpi = 0, apic = 1;
    unsigned long store_mfn;

    static char *kwd_list[] = { "domid", "store_evtchn",
				"memsize", "image", "vcpus", "pae", "acpi",
				"apic", NULL };
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiis|iiii", kwd_list,
                                      &dom, &store_evtchn, &memsize,
                                      &image, &vcpus, &pae, &acpi, &apic) )
        return NULL;

    if ( xc_hvm_build(self->xc_handle, dom, memsize, image) != 0 )
        return pyxc_error_to_exception();

#if !defined(__ia64__)
    /* Set up the HVM info table. */
    va_map = xc_map_foreign_range(self->xc_handle, dom, XC_PAGE_SIZE,
                                  PROT_READ | PROT_WRITE,
                                  HVM_INFO_PFN);
    if ( va_map == NULL )
        return PyErr_SetFromErrno(xc_error_obj);
    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    memset(va_hvm, 0, sizeof(*va_hvm));
    strncpy(va_hvm->signature, "HVM INFO", 8);
    va_hvm->length       = sizeof(struct hvm_info_table);
    va_hvm->acpi_enabled = acpi;
    va_hvm->apic_mode    = apic;
    va_hvm->nr_vcpus     = vcpus;
    for ( i = 0, sum = 0; i < va_hvm->length; i++ )
        sum += ((uint8_t *)va_hvm)[i];
    va_hvm->checksum = -sum;
    munmap(va_map, XC_PAGE_SIZE);
#endif

    xc_get_hvm_param(self->xc_handle, dom, HVM_PARAM_STORE_PFN, &store_mfn);
#if !defined(__ia64__)
    xc_set_hvm_param(self->xc_handle, dom, HVM_PARAM_PAE_ENABLED, pae);
#endif
    xc_set_hvm_param(self->xc_handle, dom, HVM_PARAM_STORE_EVTCHN,
                     store_evtchn);

    return Py_BuildValue("{s:i}", "store_mfn", store_mfn);
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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    Py_INCREF(zero);
    return zero;
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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    return PyString_FromStringAndSize(str, count);
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
    xc_physinfo_t info;
    char cpu_cap[128], *p=cpu_cap, *q=cpu_cap;
    int i;
    
    if ( xc_physinfo(self->xc_handle, &info) != 0 )
        return pyxc_error_to_exception();

    *q=0;
    for(i=0;i<sizeof(info.hw_cap)/4;i++)
    {
        p+=sprintf(p,"%08x:",info.hw_cap[i]);
        if(info.hw_cap[i])
            q=p;
    }
    if(q>cpu_cap)
        *(q-1)=0;

    return Py_BuildValue("{s:i,s:i,s:i,s:i,s:l,s:l,s:l,s:i,s:s}",
                         "threads_per_core", info.threads_per_core,
                         "cores_per_socket", info.cores_per_socket,
                         "sockets_per_node", info.sockets_per_node,
                         "nr_nodes",         info.nr_nodes,
                         "total_memory",     pages_to_kib(info.total_pages),
                         "free_memory",      pages_to_kib(info.free_pages),
                         "scrub_memory",     pages_to_kib(info.scrub_pages),
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
    long xen_pagesize;
    char str[128];

    xen_version = xc_version(self->xc_handle, XENVER_version, NULL);

    if ( xc_version(self->xc_handle, XENVER_extraversion, &xen_extra) != 0 )
        return pyxc_error_to_exception();

    if ( xc_version(self->xc_handle, XENVER_compile_info, &xen_cc) != 0 )
        return pyxc_error_to_exception();

    if ( xc_version(self->xc_handle, XENVER_changeset, &xen_chgset) != 0 )
        return pyxc_error_to_exception();

    if ( xc_version(self->xc_handle, XENVER_capabilities, &xen_caps) != 0 )
        return pyxc_error_to_exception();

    if ( xc_version(self->xc_handle, XENVER_platform_parameters, &p_parms) != 0 )
        return pyxc_error_to_exception();

    sprintf(str, "virt_start=0x%lx", p_parms.virt_start);

    xen_pagesize = xc_version(self->xc_handle, XENVER_pagesize, NULL);
    if (xen_pagesize < 0 )
        return pyxc_error_to_exception();

    return Py_BuildValue("{s:i,s:i,s:s,s:s,s:i,s:s,s:s,s:s,s:s,s:s,s:s}",
                         "xen_major", xen_version >> 16,
                         "xen_minor", (xen_version & 0xffff),
                         "xen_extra", xen_extra,
                         "xen_caps",  xen_caps,
                         "xen_pagesize", xen_pagesize,
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
    static char *kwd_list[] = { "domid", "period", "slice",
                                "latency", "extratime", "weight",NULL };
    
    if( !PyArg_ParseTupleAndKeywords(args, kwds, "iLLLhh", kwd_list, 
                                     &domid, &period, &slice,
                                     &latency, &extratime, &weight) )
        return NULL;
   if ( xc_sedf_domain_set(self->xc_handle, domid, period,
                           slice, latency, extratime,weight) != 0 )
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    return Py_BuildValue("{s:i,s:L,s:L,s:L,s:i,s:i}",
                         "domid",    domid,
                         "period",    period,
                         "slice",     slice,
                         "latency",   latency,
                         "extratime", extratime,
                         "weight",    weight);
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
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    return Py_BuildValue("{s:H,s:H}",
                         "weight",  sdom.weight,
                         "cap",     sdom.cap);
}

static PyObject *pyxc_domain_setmaxmem(XcObject *self, PyObject *args)
{
    uint32_t dom;
    unsigned int maxmem_kb;

    if (!PyArg_ParseTuple(args, "ii", &dom, &maxmem_kb))
        return NULL;

    if (xc_domain_setmaxmem(self->xc_handle, dom, maxmem_kb) != 0)
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();
    
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

    static char *kwd_list[] = { "domid", "mem_kb", "extent_order", "address_bits", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "il|ii", kwd_list, 
                                      &dom, &mem_kb, &extent_order, &address_bits) )
        return NULL;

    /* round down to nearest power of 2. Assume callers using extent_order>0
       know what they are doing */
    nr_extents = (mem_kb / (XC_PAGE_SIZE/1024)) >> extent_order;
    if ( xc_domain_memory_increase_reservation(self->xc_handle, dom, 
                                               nr_extents, extent_order, 
                                               address_bits, NULL) )
        return pyxc_error_to_exception();
    
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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_set_time_offset(XcObject *self, PyObject *args)
{
    uint32_t dom;
    int32_t time_offset_seconds;
    time_t calendar_time;
    struct tm local_time;
    struct tm utc_time;

    if (!PyArg_ParseTuple(args, "i", &dom))
        return NULL;

    calendar_time = time(NULL);
    localtime_r(&calendar_time, &local_time);
    gmtime_r(&calendar_time, &utc_time);
    /* set up to get calendar time based on utc_time, with local dst setting */
    utc_time.tm_isdst = local_time.tm_isdst;
    time_offset_seconds = (int32_t)difftime(calendar_time, mktime(&utc_time));

    if (xc_domain_set_time_offset(self->xc_handle, dom, time_offset_seconds) != 0)
        return NULL;

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
        return pyxc_error_to_exception();

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
        return pyxc_error_to_exception();

    Py_INCREF(zero);
    return zero;
}

#ifdef __powerpc__
static PyObject *pyxc_alloc_real_mode_area(XcObject *self,
                                           PyObject *args,
                                           PyObject *kwds)
{
    uint32_t dom;
    unsigned int log;

    static char *kwd_list[] = { "dom", "log", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list, 
                                      &dom, &log) )
        return NULL;

    if ( xc_alloc_real_mode_area(self->xc_handle, dom, log) )
        return pyxc_error_to_exception();

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_prose_build(XcObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    uint32_t dom;
    char *image, *ramdisk = NULL, *cmdline = "", *features = NULL;
    int flags = 0;
    int store_evtchn, console_evtchn;
    unsigned int mem_mb;
    unsigned long store_mfn = 0;
    unsigned long console_mfn = 0;
    int unused;

    static char *kwd_list[] = { "dom", "store_evtchn",
                                "console_evtchn", "image", "memsize",
                                /* optional */
                                "ramdisk", "cmdline", "flags",
                                "features", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiis|ssis#", kwd_list,
                                      &dom, &store_evtchn, &mem_mb,
                                      &console_evtchn, &image,
                                      /* optional */
                                      &ramdisk, &cmdline, &flags,
                                      &features, &unused) )
        return NULL;

    if ( xc_prose_build(self->xc_handle, dom, mem_mb, image,
                        ramdisk, cmdline, features, flags,
                        store_evtchn, &store_mfn,
                        console_evtchn, &console_mfn) != 0 ) {
        if (!errno)
             errno = EINVAL;
        return pyxc_error_to_exception();
    }
    return Py_BuildValue("{s:i,s:i}", 
                         "store_mfn", store_mfn,
                         "console_mfn", console_mfn);
}
#endif /* powerpc */

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

    { "hvm_build", 
      (PyCFunction)pyxc_hvm_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new HVM guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " image   [str]:      Name of HVM loader image file.\n"
      " vcpus   [int, 1]:   Number of Virtual CPUS in domain.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "sched_id_get",
      (PyCFunction)pyxc_sched_id_get,
      METH_NOARGS, "\n"
      "Get the current scheduler type in use.\n"
      "Returns: [int] sched_id.\n" },    

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

    { "domain_set_memmap_limit", 
      (PyCFunction)pyxc_domain_set_memmap_limit, 
      METH_VARARGS, "\n"
      "Set a domain's physical memory mappping limit\n"
      " dom [int]: Identifier of domain.\n"
      " map_limitkb [int]: .\n"
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

    { "domain_set_time_offset",
      (PyCFunction)pyxc_domain_set_time_offset,
      METH_VARARGS, "\n"
      "Set a domain's time offset to Dom0's localtime\n"
      " dom        [int]: Domain whose time offset is being set.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_send_trigger",
      (PyCFunction)pyxc_domain_send_trigger,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Send trigger to a domain.\n"
      " dom     [int]: Identifier of domain to be sent trigger.\n"
      " trigger [int]: Trigger type number.\n"
      " vcpu    [int]: VCPU to be sent trigger.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

#ifdef __powerpc__
    { "arch_alloc_real_mode_area", 
      (PyCFunction)pyxc_alloc_real_mode_area, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allocate a domain's real mode area.\n"
      " dom [int]: Identifier of domain.\n"
      " log [int]: Specifies the area's size.\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "arch_prose_build", 
      (PyCFunction)pyxc_prose_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new Linux guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " ramdisk [str, n/a]: Name of ramdisk file, if any.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      " vcpus   [int, 1]:   Number of Virtual CPUS in domain.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },
#endif /* __powerpc */

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
        pyxc_error_to_exception();
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
    PyModule_AddIntConstant(m, "XEN_SCHEDULER_SEDF", XEN_SCHEDULER_SEDF);
    PyModule_AddIntConstant(m, "XEN_SCHEDULER_CREDIT", XEN_SCHEDULER_CREDIT);

}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
