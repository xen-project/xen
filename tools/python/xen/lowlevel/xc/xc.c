/******************************************************************************
 * Xc.c
 * 
 * Copyright (c) 2003-2004, K A Fraser (University of Cambridge)
 */

#include <Python.h>
#include <xc.h>
#include <zlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "xc_private.h"
#include "gzip_stream.h"
#include "linux_boot_params.h"

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define XENPKG "xen.lowlevel.xc"

static PyObject *xc_error, *zero;

typedef struct {
    PyObject_HEAD;
    int xc_handle;
} XcObject;

/*
 * Definitions for the 'xc' object type.
 */

static PyObject *pyxc_domain_dumpcore(PyObject *self,
				      PyObject *args,
				      PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    char *corefile;

    static char *kwd_list[] = { "dom", "corefile", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is", kwd_list, &dom, &corefile) )
        goto exit;

    if ( (corefile == NULL) || (corefile[0] == '\0') )
        goto exit;

    if ( xc_domain_dumpcore(xc->xc_handle, dom, corefile) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;

 exit:
    return NULL;
}

static PyObject *pyxc_domain_create(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int mem_kb = 0;
    int          cpu = -1;
    float        cpu_weight = 1;
    u32          dom = 0;
    int          ret;

    static char *kwd_list[] = { "dom", "mem_kb", "cpu", "cpu_weight", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iiif", kwd_list, 
                                      &dom, &mem_kb, &cpu, &cpu_weight))
        return NULL;

    if ( (ret = xc_domain_create(
                    xc->xc_handle, mem_kb, cpu, cpu_weight, &dom)) < 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyInt_FromLong(dom);
}

static PyObject *pyxc_domain_pause(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    if ( xc_domain_pause(xc->xc_handle, dom) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_unpause(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    if ( xc_domain_unpause(xc->xc_handle, dom) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_destroy(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    if ( xc_domain_destroy(xc->xc_handle, dom) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_pincpu(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    int cpu = -1;

    static char *kwd_list[] = { "dom", "cpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &dom, &cpu) )
        return NULL;

    if ( xc_domain_pincpu(xc->xc_handle, dom, cpu) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_getinfo(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    u32 first_dom = 0;
    int max_doms = 1024, nr_doms, i;
    xc_dominfo_t *info;

    static char *kwd_list[] = { "first_dom", "max_doms", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list,
                                      &first_dom, &max_doms) )
        return NULL;

    if ( (info = malloc(max_doms * sizeof(xc_dominfo_t))) == NULL )
        return PyErr_NoMemory();

    nr_doms = xc_domain_getinfo(xc->xc_handle, first_dom, max_doms, info);
    
    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        PyList_SetItem(
            list, i, 
            Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i"
                          ",s:l,s:L,s:l,s:i}",
                          "dom",       info[i].domid,
                          "cpu",       info[i].cpu,
                          "dying",     info[i].dying,
                          "crashed",   info[i].crashed,
                          "shutdown",  info[i].shutdown,
                          "paused",    info[i].paused,
                          "blocked",   info[i].blocked,
                          "running",   info[i].running,
                          "mem_kb",    info[i].nr_pages*4,
                          "cpu_time",  info[i].cpu_time,
                          "maxmem_kb", info[i].max_memkb,
                          "shutdown_reason", info[i].shutdown_reason
                ));
    }

    free(info);

    return list;
}

static int file_save(XcObject *xc, XcIOContext *ctxt, char *state_file)
{
    int rc = -1;
    int fd = -1;
    int open_flags = (O_CREAT | O_EXCL | O_WRONLY);
    int open_mode = 0644;

    printf("%s>\n", __FUNCTION__);

    if ( (fd = open(state_file, open_flags, open_mode)) < 0 )
    {
        xcio_perror(ctxt, "Could not open file for writing");
        goto exit;
    }

    printf("%s>gzip_stream_fdopen... \n", __FUNCTION__);

    /* Compression rate 1: we want speed over compression. 
     * We're mainly going for those zero pages, after all.
     */
    ctxt->io = gzip_stream_fdopen(fd, "wb1");
    if ( ctxt->io == NULL )
    {
        xcio_perror(ctxt, "Could not allocate compression state");
        goto exit;
    }

    printf("%s> xc_linux_save...\n", __FUNCTION__);

    rc = xc_linux_save(xc->xc_handle, ctxt);

  exit:
    if ( ctxt->io != NULL )
        IOStream_close(ctxt->io);
    if ( fd >= 0 )
        close(fd);
    unlink(state_file);
    printf("%s> rc=%d\n", __FUNCTION__, rc);
    return rc;
}

static PyObject *pyxc_linux_save(PyObject *self,
                                 PyObject *args,
                                 PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    char *state_file;
    int progress = 1, debug = 0;
    PyObject *val = NULL;
    int rc = -1;
    XcIOContext ioctxt = { .info = iostdout, .err = iostderr };

    static char *kwd_list[] = { "dom", "state_file", "vmconfig", "progress", "debug", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is|sii", kwd_list, 
                                      &ioctxt.domain,
                                      &state_file,
                                      &ioctxt.vmconfig,
                                      &progress, 
                                      &debug) )
        goto exit;

    ioctxt.vmconfig_n = (ioctxt.vmconfig ? strlen(ioctxt.vmconfig) : 0);

    if ( progress )
        ioctxt.flags |= XCFLAGS_VERBOSE;
    if ( debug )
        ioctxt.flags |= XCFLAGS_DEBUG;

    if ( (state_file == NULL) || (state_file[0] == '\0') )
        goto exit;
    
    rc = file_save(xc, &ioctxt, state_file);
    if ( rc != 0 )
    {
        PyErr_SetFromErrno(xc_error);
        goto exit;
    } 

    Py_INCREF(zero);
    val = zero;

  exit:
    return val;
}


static int file_restore(XcObject *xc, XcIOContext *ioctxt, char *state_file)
{
    int rc = -1;

    ioctxt->io = gzip_stream_fopen(state_file, "rb");
    if ( ioctxt->io == NULL )
    {
        xcio_perror(ioctxt, "Could not open file for reading");
        return rc;
    }

    rc = xc_linux_restore(xc->xc_handle, ioctxt);

    IOStream_close(ioctxt->io);
    
    return rc;
}

static PyObject *pyxc_linux_restore(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    char *state_file;
    int progress = 1, debug = 0;
    PyObject *val = NULL;
    XcIOContext ioctxt = { .info = iostdout, .err = iostderr };
    int rc =-1;

    static char *kwd_list[] = { "state_file", "progress", "debug", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s|ii", kwd_list,
                                      &state_file,
                                      &progress,
                                      &debug) )
        goto exit;

    if ( progress )
        ioctxt.flags |= XCFLAGS_VERBOSE;
    if ( debug )
        ioctxt.flags |= XCFLAGS_DEBUG;

    if ( (state_file == NULL) || (state_file[0] == '\0') )
        goto exit;

    rc = file_restore(xc, &ioctxt, state_file);
    if ( rc != 0 )
    {
        PyErr_SetFromErrno(xc_error);
        goto exit;
    }

    val = Py_BuildValue("{s:i,s:s}",
                        "dom", ioctxt.domain,
                        "vmconfig", ioctxt.vmconfig);

  exit:
    return val;
}

static PyObject *pyxc_linux_build(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32   dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    int   control_evtchn, flags = 0, vcpus = 1;

    static char *kwd_list[] = { "dom", "control_evtchn", 
                                "image", "ramdisk", "cmdline", "flags", "vcpus",
                                NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iis|ssii", kwd_list, 
                                      &dom, &control_evtchn, 
                                      &image, &ramdisk, &cmdline, &flags, &vcpus) )
        return NULL;

    if ( xc_linux_build(xc->xc_handle, dom, image,
                        ramdisk, cmdline, control_evtchn, flags, vcpus) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_plan9_build(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32   dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    int   control_evtchn, flags = 0;

    static char *kwd_list[] = { "dom", "control_evtchn",
                                "image", "ramdisk", "cmdline", "flags",
                                NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iis|ssi", kwd_list,
                                      &dom, &control_evtchn,
                                      &image, &ramdisk, &cmdline, &flags) )
        return NULL;

    if ( xc_plan9_build(xc->xc_handle, dom, image,
                        cmdline, control_evtchn, flags) != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_vmx_build(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32   dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    PyObject *memmap;
    int   control_evtchn, flags = 0;
    int numItems, i;
    int memsize;
    struct mem_map mem_map;

    static char *kwd_list[] = { "dom", "control_evtchn",
                                "memsize",
                                "image", "memmap",
				"ramdisk", "cmdline", "flags",
                                NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiisO!|ssi", kwd_list, 
                                      &dom, &control_evtchn, 
                                      &memsize,
                                      &image, &PyList_Type, &memmap,
				      &ramdisk, &cmdline, &flags) )
        return NULL;

    memset(&mem_map, 0, sizeof(mem_map));
    /* Parse memmap */

    /* get the number of lines passed to us */
    numItems = PyList_Size(memmap) - 1;	/* removing the line 
					   containing "memmap" */
    printf ("numItems: %d\n", numItems);
    mem_map.nr_map = numItems;
   
    /* should raise an error here. */
    if (numItems < 0) return NULL; /* Not a list */

    /* iterate over items of the list, grabbing ranges and parsing them */
    for (i = 1; i <= numItems; i++) {	// skip over "memmap"
	    PyObject *item, *f1, *f2, *f3, *f4;
	    int numFields;
	    unsigned long lf1, lf2, lf3, lf4;
	    char *sf1, *sf2;
	    
	    /* grab the string object from the next element of the list */
	    item = PyList_GetItem(memmap, i); /* Can't fail */

	    /* get the number of lines passed to us */
	    numFields = PyList_Size(item);

	    if (numFields != 4)
		    return NULL;

	    f1 = PyList_GetItem(item, 0);
	    f2 = PyList_GetItem(item, 1);
	    f3 = PyList_GetItem(item, 2);
	    f4 = PyList_GetItem(item, 3);

	    /* Convert objects to strings/longs */
	    sf1 = PyString_AsString(f1);
	    sf2 = PyString_AsString(f2);
	    lf3 = PyLong_AsLong(f3);
	    lf4 = PyLong_AsLong(f4);
	    if ( sscanf(sf1, "%lx", &lf1) != 1 )
                return NULL;
	    if ( sscanf(sf2, "%lx", &lf2) != 1 )
                return NULL;

            mem_map.map[i-1].addr = lf1;
            mem_map.map[i-1].size = lf2 - lf1;
            mem_map.map[i-1].type = lf3;
            mem_map.map[i-1].caching_attr = lf4;
    }

    if ( xc_vmx_build(xc->xc_handle, dom, memsize, image, &mem_map,
                        ramdisk, cmdline, control_evtchn, flags) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_bvtsched_global_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned long ctx_allow;

    static char *kwd_list[] = { "ctx_allow", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "l", kwd_list, &ctx_allow) )
        return NULL;

    if ( xc_bvtsched_global_set(xc->xc_handle, ctx_allow) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_bvtsched_global_get(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    
    unsigned long ctx_allow;
    
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;
    
    if ( xc_bvtsched_global_get(xc->xc_handle, &ctx_allow) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    return Py_BuildValue("s:l", "ctx_allow", ctx_allow);
}

static PyObject *pyxc_bvtsched_domain_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    u32 mcuadv;
    int warpback; 
    s32 warpvalue;
    long long warpl;
    long long warpu;

    static char *kwd_list[] = { "dom", "mcuadv", "warpback", "warpvalue",
                                "warpl", "warpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiiLL", kwd_list,
                                      &dom, &mcuadv, &warpback, &warpvalue, 
                                      &warpl, &warpu) )
        return NULL;

    if ( xc_bvtsched_domain_set(xc->xc_handle, dom, mcuadv, 
                                warpback, warpvalue, warpl, warpu) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_bvtsched_domain_get(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    u32 dom;
    u32 mcuadv;
    int warpback; 
    s32 warpvalue;
    long long warpl;
    long long warpu;
    
    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;
    
    if ( xc_bvtsched_domain_get(xc->xc_handle, dom, &mcuadv, &warpback,
                            &warpvalue, &warpl, &warpu) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i,s:l,s:l,s:l,s:l}",
                         "domain", dom,
                         "mcuadv", mcuadv,
                         "warpback", warpback,
                         "warpvalue", warpvalue,
                         "warpl", warpl,
                         "warpu", warpu);
}

static PyObject *pyxc_evtchn_alloc_unbound(PyObject *self,
                                           PyObject *args,
                                           PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    int port;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    if ( xc_evtchn_alloc_unbound(xc->xc_handle, dom, &port) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyInt_FromLong(port);
}

static PyObject *pyxc_evtchn_bind_interdomain(PyObject *self,
                                              PyObject *args,
                                              PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom1 = DOMID_SELF, dom2 = DOMID_SELF;
    int port1 = 0, port2 = 0;

    static char *kwd_list[] = { "dom1", "dom2", "port1", "port2", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|iiii", kwd_list, 
                                      &dom1, &dom2, &port1, &port2) )
        return NULL;

    if ( xc_evtchn_bind_interdomain(xc->xc_handle, dom1, 
                                    dom2, &port1, &port2) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i,s:i}", 
                         "port1", port1,
                         "port2", port2);
}

static PyObject *pyxc_evtchn_bind_virq(PyObject *self,
                                       PyObject *args,
                                       PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    int virq, port;

    static char *kwd_list[] = { "virq", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &virq) )
        return NULL;

    if ( xc_evtchn_bind_virq(xc->xc_handle, virq, &port) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyInt_FromLong(port);
}

static PyObject *pyxc_evtchn_close(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom = DOMID_SELF;
    int port;

    static char *kwd_list[] = { "port", "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &port, &dom) )
        return NULL;

    if ( xc_evtchn_close(xc->xc_handle, dom, port) != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_evtchn_send(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    int port;

    static char *kwd_list[] = { "port", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &port) )
        return NULL;

    if ( xc_evtchn_send(xc->xc_handle, port) != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_evtchn_status(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    u32 dom = DOMID_SELF;
    int port, ret;
    xc_evtchn_status_t status;

    static char *kwd_list[] = { "port", "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &port, &dom) )
        return NULL;

    ret = xc_evtchn_status(xc->xc_handle, dom, port, &status);
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

static PyObject *pyxc_physdev_pci_access_modify(PyObject *self,
                                                PyObject *args,
                                                PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    u32 dom;
    int bus, dev, func, enable, ret;

    static char *kwd_list[] = { "dom", "bus", "dev", "func", "enable", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiiii", kwd_list, 
                                      &dom, &bus, &dev, &func, &enable) )
        return NULL;

    ret = xc_physdev_pci_access_modify(
        xc->xc_handle, dom, bus, dev, func, enable);
    if ( ret != 0 )
        return PyErr_SetFromErrno(xc_error);

    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_readconsolering(PyObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int clear = 0;
    char         str[32768];
    int          ret;

    static char *kwd_list[] = { "clear", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwd_list, &clear) )
        return NULL;

    ret = xc_readconsolering(xc->xc_handle, str, sizeof(str), clear);
    if ( ret < 0 )
        return PyErr_SetFromErrno(xc_error);

    return PyString_FromStringAndSize(str, ret);
}

static PyObject *pyxc_physinfo(PyObject *self,
                               PyObject *args,
                               PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    xc_physinfo_t info;
    
    if ( !PyArg_ParseTuple(args, "") )
        return NULL;

    if ( xc_physinfo(xc->xc_handle, &info) != 0 )
        return PyErr_SetFromErrno(xc_error);

    return Py_BuildValue("{s:i,s:i,s:l,s:l,s:l}",
                         "ht_per_core", info.ht_per_core,
                         "cores",       info.cores,
                         "total_pages", info.total_pages,
                         "free_pages",  info.free_pages,
                         "cpu_khz",     info.cpu_khz);
}

static PyObject *pyxc_shadow_control(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    int op=0;

    static char *kwd_list[] = { "dom", "op", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwd_list, 
                                      &dom, &op) )
        return NULL;

    if ( xc_shadow_control(xc->xc_handle, dom, op, NULL, 0, NULL) < 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}

static PyObject *pyxc_domain_setmaxmem(PyObject *self,
                                       PyObject *args,
                                       PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u32 dom;
    unsigned long maxmem_kb;

    static char *kwd_list[] = { "dom", "maxmem_kb", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list, 
                                      &dom, &maxmem_kb) )
        return NULL;

    if ( xc_domain_setmaxmem(xc->xc_handle, dom, maxmem_kb) != 0 )
        return PyErr_SetFromErrno(xc_error);
    
    Py_INCREF(zero);
    return zero;
}


static PyMethodDef pyxc_methods[] = {
    { "domain_create", 
      (PyCFunction)pyxc_domain_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new domain.\n"
      " dom    [int, 0]:        Domain identifier to use (allocated if zero).\n"
      " mem_kb [int, 0]:        Memory allocation, in kilobytes.\n"
      "Returns: [int] new domain identifier; -1 on error.\n" },

    { "domain_dumpcore", 
      (PyCFunction)pyxc_domain_dumpcore, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "dump core of a domain.\n"
      " dom [int]: Identifier of domain to be paused.\n\n"
      " corefile [string]: Name of corefile to be created.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_pause", 
      (PyCFunction)pyxc_domain_pause, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Temporarily pause execution of a domain.\n"
      " dom [int]: Identifier of domain to be paused.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_unpause", 
      (PyCFunction)pyxc_domain_unpause, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "(Re)start execution of a domain.\n"
      " dom [int]: Identifier of domain to be unpaused.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_destroy", 
      (PyCFunction)pyxc_domain_destroy, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Destroy a domain.\n"
      " dom [int]:    Identifier of domain to be destroyed.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_pincpu", 
      (PyCFunction)pyxc_domain_pincpu, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Pin a domain to a specified CPU.\n"
      " dom [int]:     Identifier of domain to be pinned.\n"
      " cpu [int, -1]: CPU to pin to, or -1 to unpin\n\n"
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

    { "linux_save", 
      (PyCFunction)pyxc_linux_save, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Save the CPU and memory state of a Linux guest OS.\n"
      " dom        [int]:    Identifier of domain to be saved.\n"
      " state_file [str]:    Name of state file. Must not currently exist.\n"
      " progress   [int, 1]: Bool - display a running progress indication?\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },
    { "plan9_build",
      (PyCFunction)pyxc_plan9_build,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new Plan 9 guest OS.\n"
      " dom     [long]:     Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "linux_restore", 
      (PyCFunction)pyxc_linux_restore, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Restore the CPU and memory state of a Linux guest OS.\n"
      " state_file [str]:    Name of state file. Must not currently exist.\n"
      " progress   [int, 1]: Bool - display a running progress indication?\n\n"
      "Returns: [int] new domain identifier on success; -1 on error.\n" },

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
      "Build a new Linux guest OS.\n"
      " dom     [int]:      Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " memmap  [str]: 	    Memory map.\n\n"
      " ramdisk [str, n/a]: Name of ramdisk file, if any.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_global_set",
      (PyCFunction)pyxc_bvtsched_global_set,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set global tuning parameters for Borrowed Virtual Time scheduler.\n"
      " ctx_allow [int]: Minimal guaranteed quantum.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_global_get",
      (PyCFunction)pyxc_bvtsched_global_get,
      METH_KEYWORDS, "\n"
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
      METH_KEYWORDS, "\n"
      "Get per-domain tuning parameters under the BVT scheduler.\n"
      " dom [int]: Identifier of domain to be queried.\n"
      "Returns [dict]:\n"
      " domain [int]:  Domain ID.\n"
      " mcuadv [long]: MCU Advance.\n"
      " warp   [long]: Warp.\n"
      " warpu  [long]: Unwarp requirement.\n"
      " warpl  [long]: Warp limit,\n"
    },

    { "evtchn_alloc_unbound", 
      (PyCFunction)pyxc_evtchn_alloc_unbound,
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Allocate an unbound local port that will await a remote connection.\n"
      " dom [int]: Remote domain to accept connections from.\n\n"
      "Returns: [int] Unbound event-channel port.\n" },

    { "evtchn_bind_interdomain", 
      (PyCFunction)pyxc_evtchn_bind_interdomain, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Open an event channel between two domains.\n"
      " dom1 [int, SELF]: First domain to be connected.\n"
      " dom2 [int, SELF]: Second domain to be connected.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " port1 [int]: Port-id for endpoint at dom1.\n"
      " port2 [int]: Port-id for endpoint at dom2.\n" },

    { "evtchn_bind_virq", 
      (PyCFunction)pyxc_evtchn_bind_virq, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Bind an event channel to the specified VIRQ.\n"
      " virq [int]: VIRQ to bind.\n\n"
      "Returns: [int] Bound event-channel port.\n" },

    { "evtchn_close", 
      (PyCFunction)pyxc_evtchn_close, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Close an event channel. If interdomain, sets remote end to 'unbound'.\n"
      " dom  [int, SELF]: Dom-id of one endpoint of the channel.\n"
      " port [int]:       Port-id of one endpoint of the channel.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "evtchn_send", 
      (PyCFunction)pyxc_evtchn_send, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Send an event along a locally-connected event channel.\n"
      " port [int]: Port-id of a local channel endpoint.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

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
      METH_VARARGS, "\n"
      "Get information about the physical host machine\n"
      "Returns [dict]: information about the hardware"
      "        [None]: on failure.\n" },

    { "shadow_control", 
      (PyCFunction)pyxc_shadow_control, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set parameter for shadow pagetable interface\n"
      " dom [int]:   Identifier of domain.\n"
      " op [int, 0]: operation\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_setmaxmem", 
      (PyCFunction)pyxc_domain_setmaxmem, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set a domain's memory limit\n"
      " dom [int]: Identifier of domain.\n"
      " maxmem_kb [long]: .\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { NULL, NULL, 0, NULL }
};


/*
 * Definitions for the 'Xc' module wrapper.
 */

staticforward PyTypeObject PyXcType;

static PyObject *PyXc_new(PyObject *self, PyObject *args)
{
    XcObject *xc;

    if ( !PyArg_ParseTuple(args, ":new") )
        return NULL;

    xc = PyObject_New(XcObject, &PyXcType);

    if ( (xc->xc_handle = xc_interface_open()) == -1 )
    {
        PyObject_Del((PyObject *)xc);
        return PyErr_SetFromErrno(xc_error);
    }

    return (PyObject *)xc;
}

static PyObject *PyXc_getattr(PyObject *obj, char *name)
{
    return Py_FindMethod(pyxc_methods, obj, name);
}

static void PyXc_dealloc(PyObject *self)
{
    XcObject *xc = (XcObject *)self;
    (void)xc_interface_close(xc->xc_handle);
    PyObject_Del(self);
}

static PyTypeObject PyXcType = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "Xc",
    sizeof(XcObject),
    0,
    PyXc_dealloc,    /* tp_dealloc     */
    NULL,            /* tp_print       */
    PyXc_getattr,    /* tp_getattr     */
    NULL,            /* tp_setattr     */
    NULL,            /* tp_compare     */
    NULL,            /* tp_repr        */
    NULL,            /* tp_as_number   */
    NULL,            /* tp_as_sequence */
    NULL,            /* tp_as_mapping  */
    NULL             /* tp_hash        */
};

static PyMethodDef PyXc_methods[] = {
    { "new", PyXc_new, METH_VARARGS, "Create a new " XENPKG " object." },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initxc(void)
{
    PyObject *m, *d;

    m = Py_InitModule(XENPKG, PyXc_methods);

    d = PyModule_GetDict(m);
    xc_error = PyErr_NewException(XENPKG ".error", NULL, NULL);
    PyDict_SetItemString(d, "error", xc_error);

    zero = PyInt_FromLong(0);

    /* KAF: This ensures that we get debug output in a timely manner. */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
