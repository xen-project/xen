/******************************************************************************
 * Xc.c
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <Python.h>
#include <xc.h>

#if 1
#define DPRINTF(_f, _a...)                  \
    fprintf(stderr, "%s:%s:%d:: " _f "\n" , \
            __FILE__ , __FUNCTION__ , __LINE__ , ## _a)
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

typedef struct {
    PyObject_HEAD;
    int xc_handle;
} XcObject;

/*
 * Definitions for the 'xc' object type.
 */

static PyObject *pyxc_domain_create(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int mem_kb = 65536;
    char        *name   = "(anon)";
    u64          dom;
    int          ret;

    static char *kwd_list[] = { "mem_kb", "name", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|is", kwd_list, 
                                      &mem_kb, &name) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    if ( (ret = xc_domain_create(xc->xc_handle, mem_kb, name, &dom)) < 0 )
        return PyLong_FromLong(ret);

    return PyLong_FromUnsignedLongLong(dom);
}

static PyObject *pyxc_domain_start(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64 dom;
    int ret;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "L", kwd_list, &dom) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_domain_start(xc->xc_handle, dom);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_stop(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64 dom;
    int ret;

    static char *kwd_list[] = { "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "L", kwd_list, &dom) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_domain_stop(xc->xc_handle, dom);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_destroy(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64 dom;
    int force = 0, ret;

    static char *kwd_list[] = { "dom", "force", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "L|i", kwd_list, 
                                      &dom, &force) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_domain_destroy(xc->xc_handle, dom, force);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_pincpu(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64 dom;
    int cpu = -1, ret;

    static char *kwd_list[] = { "dom", "cpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "L|i", kwd_list, 
                                      &dom, &cpu) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_domain_pincpu(xc->xc_handle, dom, cpu);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_getinfo(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    u64 first_dom = 0;
    int max_doms = 1024, nr_doms, i;
    xc_dominfo_t *info;

    static char *kwd_list[] = { "first_dom", "max_doms", NULL };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|Li", kwd_list,
                                      &first_dom, &max_doms) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    if ( (info = malloc(max_doms * sizeof(xc_dominfo_t))) == NULL )
    {
        DPRINTF("out of memory.");
        nr_doms = 0;
    }
    else
    {
        nr_doms = xc_domain_getinfo(xc->xc_handle, first_dom, max_doms, info);
    }
    
    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        PyList_SetItem(
            list, i, 
            Py_BuildValue("{s:L,s:i,s:i,s:i,s:l,s:L,s:s}",
                          "dom",      info[i].domid,
                          "cpu",      info[i].cpu,
                          "running",  info[i].has_cpu,
                          "stopped",  info[i].stopped,
                          "mem_kb",   info[i].nr_pages*4,
                          "cpu_time", info[i].cpu_time,
                          "name",     info[i].name));
    }

    if ( info != NULL )
        free(info);

    return list;
}

static PyObject *pyxc_linux_save(PyObject *self,
                                 PyObject *args,
                                 PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64   dom;
    char *state_file;
    int   progress = 1, ret;

    static char *kwd_list[] = { "dom", "state_file", "progress", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Ls|i", kwd_list, 
                                      &dom, &state_file, &progress) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_linux_save(xc->xc_handle, dom, state_file, progress);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_linux_restore(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    char        *state_file;
    int          progress = 1, ret;
    u64          dom;

    static char *kwd_list[] = { "state_file", "progress", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s|i", kwd_list, 
                                      &state_file, &progress) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_linux_restore(xc->xc_handle, state_file, progress, &dom);
    if ( ret < 0 )
        return PyLong_FromLong(ret);

    return PyLong_FromUnsignedLongLong(dom);
}

static PyObject *pyxc_linux_build(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64   dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    int   ret;

    static char *kwd_list[] = { "dom", "image", "ramdisk", "cmdline", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Ls|ss", kwd_list, 
                                      &dom, &image, &ramdisk, &cmdline) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_linux_build(xc->xc_handle, dom, image, ramdisk, cmdline);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_netbsd_build(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64   dom;
    char *image, *ramdisk = NULL, *cmdline = "";
    int   ret;

    static char *kwd_list[] = { "dom", "image", "ramdisk", "cmdline", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Ls|ss", kwd_list, 
                                      &dom, &image, &ramdisk, &cmdline) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_netbsd_build(xc->xc_handle, dom, image, cmdline);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_bvtsched_global_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned long ctx_allow;
    int           ret;

    static char *kwd_list[] = { "ctx_allow", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "l", kwd_list, &ctx_allow) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_bvtsched_global_set(xc->xc_handle, ctx_allow);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_bvtsched_domain_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64           dom;
    unsigned long mcuadv, warp, warpl, warpu;
    int           ret;

    static char *kwd_list[] = { "dom", "mcuadv", "warp", "warpl", 
                                "warpu", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Lllll", kwd_list, 
                                      &dom, &mcuadv, &warp, &warpl, &warpu) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_bvtsched_domain_set(xc->xc_handle, dom, mcuadv, 
                                 warp, warpl, warpu);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vif_scheduler_set(PyObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64           dom;
    unsigned int  vif;
    xc_vif_sched_params_t sched = { 0, 0 };
    int           ret;

    static char *kwd_list[] = { "dom", "vif", "credit_bytes", 
                                "credit_usecs", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li|ll", kwd_list, 
                                      &dom, &vif, 
                                      &sched.credit_bytes, 
                                      &sched.credit_usec) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vif_scheduler_set(xc->xc_handle, dom, vif, &sched);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vif_scheduler_get(PyObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    u64           dom;
    unsigned int  vif;
    xc_vif_sched_params_t sched;
    int           ret;

    static char *kwd_list[] = { "dom", "vif", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li", kwd_list, 
                                      &dom, &vif) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vif_scheduler_get(xc->xc_handle, dom, vif, &sched);

    if ( ret < 0 )
        dict = Py_BuildValue("{}");
    else
        dict = Py_BuildValue("{s:l,s:l}", 
                             "credit_bytes", sched.credit_bytes,
                             "credit_usecs", sched.credit_usec);
    
    return dict;
}

static PyObject *pyxc_vif_stats_get(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    u64            dom;
    unsigned int   vif;
    xc_vif_stats_t stats;
    int            ret;

    static char *kwd_list[] = { "dom", "vif", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li", kwd_list, 
                                      &dom, &vif) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vif_stats_get(xc->xc_handle, dom, vif, &stats);

    if ( ret < 0 )
        dict = Py_BuildValue("{}");
    else
        dict = Py_BuildValue("{s:L,s:L,s:L,s:L}", 
                             "tx_bytes", stats.tx_bytes,
                             "tx_packets", stats.tx_pkts,
                             "rx_bytes", stats.rx_bytes,
                             "rx_packets", stats.rx_pkts);
    
    return dict;
}

static PyObject *pyxc_vbd_create(PyObject *self,
                                 PyObject *args,
                                 PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64          dom;
    unsigned int vbd;
    int          writeable, ret;

    static char *kwd_list[] = { "dom", "vbd", "writeable", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Lii", kwd_list, 
                                      &dom, &vbd, &writeable) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vbd_create(xc->xc_handle, dom, vbd, writeable);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_destroy(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64          dom;
    unsigned int vbd;
    int          ret;

    static char *kwd_list[] = { "dom", "vbd", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li", kwd_list, 
                                      &dom, &vbd) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vbd_destroy(xc->xc_handle, dom, vbd);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_grow(PyObject *self,
                               PyObject *args,
                               PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64            dom;
    unsigned int   vbd;
    xc_vbdextent_t extent;
    int            ret;

    static char *kwd_list[] = { "dom", "vbd", "device", 
                                "start_sector", "nr_sectors", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "LiiLL", kwd_list, 
                                      &dom, &vbd, 
                                      &extent.real_device, 
                                      &extent.start_sector, 
                                      &extent.nr_sectors) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vbd_grow(xc->xc_handle, dom, vbd, &extent);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_shrink(PyObject *self,
                                 PyObject *args,
                                 PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64          dom;
    unsigned int vbd;
    int          ret;

    static char *kwd_list[] = { "dom", "vbd", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li", kwd_list, 
                                      &dom, &vbd) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_vbd_shrink(xc->xc_handle, dom, vbd);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_setextents(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list, *dict, *obj;

    u64             dom;
    unsigned int    vbd;
    xc_vbdextent_t *extents = NULL;
    int             ret, i, nr_extents;

    static char *kwd_list[] = { "dom", "vbd", "extents", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "LiO", kwd_list, 
                                      &dom, &vbd, &list) )
    {
        DPRINTF("could not parse parameter list.");
        goto fail;
    }

    if ( (nr_extents = PyList_Size(list)) < 0 )
    {
        DPRINTF("parameter 'extents' is not a list.");
        goto fail;
    }

    if ( nr_extents != 0 )
    {
        extents = malloc(nr_extents * sizeof(xc_vbdextent_t));
        if ( extents == NULL )
        {
            DPRINTF("out of memory.");
            goto fail;
        }

        for ( i = 0; i < nr_extents; i++ )
        {
            dict = PyList_GetItem(list, i);
            if ( !PyDict_Check(dict) )
            {
                DPRINTF("extent %d -- extent is not a dictionary.", i);
                goto fail;
            }

            if ( (obj = PyDict_GetItemString(dict, "device")) == NULL )
            {
                DPRINTF("extent %d -- 'device' is not in the dictionary.", i);
                goto fail;
            }
            if ( PyInt_Check(obj) )
            {
                extents[i].real_device = (unsigned short)PyInt_AsLong(obj);
            }
            else if ( PyLong_Check(obj) )
            {
                extents[i].real_device = (unsigned short)PyLong_AsLong(obj);
            }
            else
            {
                DPRINTF("extent %d -- 'device' is not an int or long.", i);
                goto fail;
            }

            if ( (obj = PyDict_GetItemString(dict, "start_sector")) == NULL )
            {
                DPRINTF("extent %d -- 'start_sector' is not "
                        "in the dictionary.", i);
                goto fail;
            }
            if ( PyInt_Check(obj) )
            {
                extents[i].start_sector = PyInt_AsLong(obj);
            }
            else if ( PyLong_Check(obj) )
            {
                extents[i].start_sector = PyLong_AsUnsignedLongLong(obj);
            }
            else
            {
                DPRINTF("extent %d -- 'start_sector' is not "
                        "an int or long.", i);
                goto fail;
            }

            if ( (obj = PyDict_GetItemString(dict, "nr_sectors")) == NULL )
            {
                DPRINTF("extent %d -- 'nr_sectors' is not "
                        "in the dictionary.", i);
                goto fail;
            }
            if ( PyInt_Check(obj) )
            {
                extents[i].nr_sectors = PyInt_AsLong(obj);
            }
            else if ( PyLong_Check(obj) )
            {
                extents[i].nr_sectors = PyLong_AsUnsignedLongLong(obj);
            }
            else
            {
                DPRINTF("extent %d -- 'nr_sectors' is not "
                        "an int or long.", i);
                goto fail;
            }
        }
    }

    ret = xc_vbd_setextents(xc->xc_handle, dom, vbd, nr_extents, extents);
    
    if ( extents != NULL )
        free(extents);
    
    return PyInt_FromLong(ret);

 fail:
    if ( extents != NULL )
        free(extents);
    return NULL;
}

#define MAX_EXTENTS 1024
static PyObject *pyxc_vbd_getextents(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    u64             dom;
    unsigned int    vbd;
    xc_vbdextent_t *extents;
    int             i, nr_extents, max_extents;

    static char *kwd_list[] = { "dom", "vbd", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "Li", kwd_list, 
                                      &dom, &vbd) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    extents = malloc(MAX_EXTENTS * sizeof(xc_vbdextent_t));
    if ( extents == NULL )
    {
        DPRINTF("out of memory.");
        max_extents = 0;
    }
    else
    {
        max_extents = MAX_EXTENTS;
    }

    nr_extents = xc_vbd_getextents(xc->xc_handle, dom, vbd, max_extents,
                                   extents, NULL);
    
    if ( nr_extents <= 0 )
    {
        list = PyList_New(0);
    }
    else
    {
        list = PyList_New(nr_extents);
        for ( i = 0; i < nr_extents; i++ )
        {
            PyList_SetItem(
                list, i, 
                Py_BuildValue("{s:i,s:L,s:L}",
                              "device",       extents[i].real_device,
                              "start_sector", extents[i].start_sector,
                              "nr_sectors",   extents[i].nr_sectors));
        }
    }

    if ( extents != NULL )
        free(extents);
    
    return list;
}

static PyObject *pyxc_vbd_probe(PyObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    u64          dom = XC_VBDDOM_PROBE_ALL;
    unsigned int max_vbds = 1024;
    xc_vbd_t    *info;
    int          nr_vbds, i;

    static char *kwd_list[] = { "dom", "max_vbds", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|Li", kwd_list, 
                                      &dom, &max_vbds) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    info = malloc(max_vbds * sizeof(xc_vbd_t));
    if ( info == NULL )
    {
        DPRINTF("out of memory.");
        nr_vbds = 0;
    }
    else
    {
        nr_vbds = xc_vbd_probe(xc->xc_handle, dom, max_vbds, info);
    }

    list = PyList_New(nr_vbds);
    for ( i = 0; i < nr_vbds; i++ )
    {
        PyList_SetItem(
            list, i, 
            Py_BuildValue("{s:L,s:i,s:i,s:L}",
                          "dom",        info[i].domid,
                          "vbd",        info[i].vbdid,
                          "writeable",  !!(info[i].flags & XC_VBDF_WRITEABLE),
                          "nr_sectors", info[i].nr_sectors));
    }

    if ( info != NULL )
        free(info);

    return list;
}

static PyObject *pyxc_evtchn_open(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    u64 dom1 = DOMID_SELF, dom2;
    int port1, port2, ret;

    static char *kwd_list[] = { "dom2", "dom1", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "L|L", kwd_list, 
                                      &dom2, &dom1) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_evtchn_open(xc->xc_handle, dom1, dom2, &port1, &port2);

    if ( ret < 0 )
        dict = Py_BuildValue("{}");
    else
        dict = Py_BuildValue("{s:i,s:i}", 
                             "port1", port1,
                             "port2", port2);
    
    return dict;
}

static PyObject *pyxc_evtchn_close(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    u64 dom = DOMID_SELF;
    int port, ret;

    static char *kwd_list[] = { "port", "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|L", kwd_list, 
                                      &port, &dom) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_evtchn_close(xc->xc_handle, dom, port);

    return PyInt_FromLong(ret);
}

static PyObject *pyxc_evtchn_send(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    int port, ret;

    static char *kwd_list[] = { "port", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &port) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_evtchn_send(xc->xc_handle, port);

    return PyInt_FromLong(ret);
}

static PyObject *pyxc_evtchn_status(PyObject *self,
                                    PyObject *args,
                                    PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    u64 dom1 = DOMID_SELF, dom2;
    int port1, port2, status, ret;

    static char *kwd_list[] = { "port", "dom", NULL };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i|L", kwd_list, 
                                      &port1, &dom1) )
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_evtchn_status(xc->xc_handle, dom1, port1, &dom2, &port2, &status);

    if ( ret < 0 )
    {
        dict = Py_BuildValue("{}");
    }
    else
    {
        switch ( status )
        {
        case EVTCHNSTAT_closed:
            dict = Py_BuildValue("{s:s}", 
                                 "status", "closed");
            break;
        case EVTCHNSTAT_disconnected:
            dict = Py_BuildValue("{s:s}", 
                                 "status", "disconnected");
            break;
        case EVTCHNSTAT_connected:
            dict = Py_BuildValue("{s:s,s:L,s:i}", 
                                 "status", "connected",
                                 "dom", dom2,
                                 "port", port2);
            break;
        default:
            dict = Py_BuildValue("{}");
            break;
        }
    }
    
    return dict;
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
    {
        DPRINTF("could not parse parameter list.");
        return NULL;
    }

    ret = xc_readconsolering(xc->xc_handle, str, sizeof(str), clear);

    return PyString_FromStringAndSize(str, (ret < 0) ? 0 : ret);
}

static PyObject *pyxc_physinfo(PyObject *self,
			       PyObject *args,
			       PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *ret_obj;
    int xc_ret;
    xc_physinfo_t info;
    
    xc_ret = xc_physinfo(xc->xc_handle, &info);

    if(!xc_ret)
    {
        ret_obj = Py_BuildValue("{s:i,s:i,s:l,s:l,s:l}",
                                "ht_per_core", info.ht_per_core,
                                "cores",       info.cores,
                                "total_pages", info.total_pages,
                                "free_pages",  info.free_pages,
                                "cpu_khz",     info.cpu_khz);
    }
    else
    {
        ret_obj = Py_BuildValue(""); /* None */
    }
    
    return ret_obj;
}

static PyMethodDef pyxc_methods[] = {
    { "domain_create", 
      (PyCFunction)pyxc_domain_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new domain.\n"
      " mem_kb [int, 65536]:    Memory allocation, in kilobytes.\n"
      " name   [str, '(anon)']: Informative textual name.\n\n"
      "Returns: [long] new domain identifier; -1 on error.\n" },

    { "domain_start", 
      (PyCFunction)pyxc_domain_start, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Start execution of a domain.\n"
      " dom [long]: Identifier of domain to be started.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_stop", 
      (PyCFunction)pyxc_domain_stop, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Stop execution of a domain.\n"
      " dom [long]: Identifier of domain to be stopped.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_destroy", 
      (PyCFunction)pyxc_domain_destroy, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Destroy a domain.\n"
      " dom   [long]:   Identifier of domain to be destroyed.\n"
      " force [int, 0]: Bool - force immediate destruction?\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_pincpu", 
      (PyCFunction)pyxc_domain_pincpu, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Pin a domain to a specified CPU.\n"
      " dom [long]:    Identifier of domain to be destroyed.\n"
      " cpu [int, -1]: CPU to pin to, or -1 to unpin\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_getinfo", 
      (PyCFunction)pyxc_domain_getinfo, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information regarding a set of domains, in increasing id order.\n"
      " first_dom [long, 0]:   First domain to retrieve info about.\n"
      " max_doms  [int, 1024]: Maximum number of domains to retrieve info"
      " about.\n\n"
      "Returns: [list of dicts] if list length is less than 'max_doms'\n"
      "         parameter then there was an error, or the end of the\n"
      "         domain-id space was reached.\n"
      " dom      [long]: Identifier of domain to which this info pertains\n"
      " cpu      [int]:  CPU to which this domain is bound\n"
      " running  [int]:  Bool - is the domain currently running?\n"
      " stopped  [int]:  Bool - is the domain suspended?\n"
      " mem_kb   [int]:  Memory reservation, in kilobytes\n"
      " cpu_time [long]: CPU time consumed, in nanoseconds\n"
      " name     [str]:  Identifying name\n" },

    { "linux_save", 
      (PyCFunction)pyxc_linux_save, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Save the CPU and memory state of a Linux guest OS.\n"
      " dom        [long]:   Identifier of domain to be saved.\n"
      " state_file [str]:    Name of state file. Must not currently exist.\n"
      " progress   [int, 1]: Bool - display a running progress indication?\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "linux_restore", 
      (PyCFunction)pyxc_linux_restore, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Restore the CPU and memory state of a Linux guest OS.\n"
      " state_file [str]:    Name of state file. Must not currently exist.\n"
      " progress   [int, 1]: Bool - display a running progress indication?\n\n"
      "Returns: [long] new domain identifier on success; -1 on error.\n" },

    { "linux_build", 
      (PyCFunction)pyxc_linux_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new Linux guest OS.\n"
      " dom     [long]:     Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " ramdisk [str, n/a]: Name of ramdisk file, if any.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "netbsd_build", 
      (PyCFunction)pyxc_netbsd_build, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Build a new NetBSD guest OS.\n"
      " dom     [long]:     Identifier of domain to build into.\n"
      " image   [str]:      Name of kernel image file. May be gzipped.\n"
      " cmdline [str, n/a]: Kernel parameters, if any.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_global_set", 
      (PyCFunction)pyxc_bvtsched_global_set, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set global tuning parameters for Borrowed Virtual Time scheduler.\n"
      " ctx_allow [int]: Minimal guaranteed quantum (I think!).\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "bvtsched_domain_set", 
      (PyCFunction)pyxc_bvtsched_domain_set, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set per-domain tuning parameters for Borrowed Virtual Time scheduler.\n"
      " dom    [long]: Identifier of domain to be tuned.\n"
      " mcuadv [int]:  Internal BVT parameter.\n"
      " warp   [int]:  Internal BVT parameter.\n"
      " warpl  [int]:  Internal BVT parameter.\n"
      " warpu  [int]:  Internal BVT parameter.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vif_scheduler_set", 
      (PyCFunction)pyxc_vif_scheduler_set, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set per-network-interface scheduling parameters.\n"
      " dom          [long]:   Identifier of domain to be adjusted.\n"
      " vif          [int]:    Identifier of VIF to be adjusted.\n"
      " credit_bytes [int, 0]: Tx bytes permitted each interval.\n"
      " credit_usecs [int, 0]: Interval, in usecs. 0 == no scheduling.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vif_scheduler_get", 
      (PyCFunction)pyxc_vif_scheduler_get, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Query the per-network-interface scheduling parameters.\n"
      " dom          [long]:   Identifier of domain to be queried.\n"
      " vif          [int]:    Identifier of VIF to be queried.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " credit_bytes [int]: Tx bytes permitted each interval.\n"
      " credit_usecs [int]: Interval, in usecs. 0 == no scheduling.\n" },

    { "vif_stats_get", 
      (PyCFunction)pyxc_vif_stats_get, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Query the per-network-interface statistics.\n"
      " dom          [long]: Identifier of domain to be queried.\n"
      " vif          [int]:  Identifier of VIF to be queried.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " tx_bytes   [long]: Bytes transmitted.\n"
      " tx_packets [long]: Packets transmitted.\n"
      " rx_bytes   [long]: Bytes received.\n"
      " rx_packets [long]: Packets received.\n" },

    { "vbd_create", 
      (PyCFunction)pyxc_vbd_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new virtual block device associated with a given domain.\n"
      " dom       [long]: Identifier of domain to get a new VBD.\n"
      " vbd       [int]:  Identifier for new VBD.\n"
      " writeable [int]:  Bool - is the new VBD writeable?\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_destroy", 
      (PyCFunction)pyxc_vbd_destroy, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Destroy a virtual block device.\n"
      " dom       [long]: Identifier of domain containing the VBD.\n"
      " vbd       [int]:  Identifier of the VBD.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_grow", 
      (PyCFunction)pyxc_vbd_grow, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Grow a virtual block device by appending a new extent.\n"
      " dom          [long]: Identifier of domain containing the VBD.\n"
      " vbd          [int]:  Identifier of the VBD.\n"
      " device       [int]:  Identifier of the real underlying block device.\n"
      " start_sector [long]: Real start sector of this extent.\n"
      " nr_sectors   [long]: Length, in sectors, of this extent.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_shrink", 
      (PyCFunction)pyxc_vbd_shrink, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Shrink a virtual block device by deleting its final extent.\n"
      " dom          [long]: Identifier of domain containing the VBD.\n"
      " vbd          [int]:  Identifier of the VBD.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_setextents", 
      (PyCFunction)pyxc_vbd_setextents, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set all the extent information for a virtual block device.\n"
      " dom          [long]: Identifier of domain containing the VBD.\n"
      " vbd          [int]:  Identifier of the VBD.\n"
      " extents      [list of dicts]: Per-extent information.\n"
      "  device       [int]:  Id of the real underlying block device.\n"
      "  start_sector [long]: Real start sector of this extent.\n"
      "  nr_sectors   [long]: Length, in sectors, of this extent.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_getextents", 
      (PyCFunction)pyxc_vbd_getextents, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get info on all the extents in a virtual block device.\n"
      " dom          [long]: Identifier of domain containing the VBD.\n"
      " vbd          [int]:  Identifier of the VBD.\n\n"
      "Returns: [list of dicts] per-extent information; empty on error.\n"
      " device       [int]:  Identifier of the real underlying block device.\n"
      " start_sector [long]: Real start sector of this extent.\n"
      " nr_sectors   [long]: Length, in sectors, of this extent.\n" },

    { "vbd_probe", 
      (PyCFunction)pyxc_vbd_probe, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information regarding extant virtual block devices.\n"
      " dom          [long, ALL]: Domain to query (default is to query all).\n"
      " max_vbds     [int, 1024]: Maximum VBDs to query.\n\n"
      "Returns: [list of dicts] if list length is less than 'max_vbds'\n"
      "         parameter then there was an error, or there were fewer vbds.\n"
      " dom        [long]: Domain containing this VBD.\n"
      " vbd        [int]:  Domain-specific identifier of this VBD.\n"
      " writeable  [int]:  Bool - is this VBD writeable?\n"
      " nr_sectors [long]: Size of this VBD, in 512-byte sectors.\n" },

    { "evtchn_open", 
      (PyCFunction)pyxc_evtchn_open, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Open an event channel between two domains.\n"
      " dom1 [long, SELF]: First domain to be connected.\n"
      " dom2 [long]:       Second domain to be connected.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " port1 [int]: Port-id for endpoint at dom1.\n"
      " port2 [int]: Port-id for endpoint at dom2.\n" },

    { "evtchn_close", 
      (PyCFunction)pyxc_evtchn_close, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Close an event channel.\n"
      " dom  [long, SELF]: Dom-id of one endpoint of the channel.\n"
      " port [int]:        Port-id of one endpoint of the channel.\n\n"
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
      " dom  [long, SELF]: Dom-id of one endpoint of the channel.\n"
      " port [int]:        Port-id of one endpoint of the channel.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " status [str]:  'closed', 'disconnected', or 'connected'.\n"
      "The following are also returned if 'status' is 'connected':\n"
      " dom  [long]: Port-id for endpoint at dom1.\n"
      " port [int]:  Port-id for endpoint at dom2.\n" },

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
        return NULL;
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
    { "new", PyXc_new, METH_VARARGS, "Create a new Xc object." },
    { NULL, NULL, 0, NULL }
};

DL_EXPORT(void) initXc(void)
{
    Py_InitModule("Xc", PyXc_methods);
}
