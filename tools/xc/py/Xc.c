/******************************************************************************
 * Xc.c
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <Python.h>
#include <xc.h>

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
    int          ret;

    static char *kwd_list[] = { "mem_kb", "name" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|is", kwd_list, 
                                      &mem_kb, &name) )
        return NULL;

    ret = xc_domain_create(xc->xc_handle, mem_kb, name);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_start(PyObject *self,
                                   PyObject *args,
                                   PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int dom;
    int          ret;

    static char *kwd_list[] = { "dom" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    ret = xc_domain_start(xc->xc_handle, dom);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_stop(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int dom;
    int          ret;

    static char *kwd_list[] = { "dom" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "i", kwd_list, &dom) )
        return NULL;

    ret = xc_domain_stop(xc->xc_handle, dom);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_domain_getinfo(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    unsigned int  first_dom = 0, max_doms = 1024;
    int           nr_doms, i;
    xc_dominfo_t *info;

    static char *kwd_list[] = { "first_dom", "max_doms" };
    
    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list,
                                      &first_dom, &max_doms) )
        return NULL;

    info = malloc(max_doms * sizeof(xc_dominfo_t));
    if ( info == NULL )
        nr_doms = 0;
    else
        nr_doms = xc_domain_getinfo(xc->xc_handle, first_dom, max_doms, info);
    
    list = PyList_New(nr_doms);
    for ( i = 0 ; i < nr_doms; i++ )
    {
        PyList_SetItem(
            list, i, 
            Py_BuildValue("{s:i,s:i,s:i,s:i,s:l,s:L,s:s}",
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

    unsigned int dom;
    char        *state_file;
    int          progress = 1, ret;

    static char *kwd_list[] = { "dom", "state_file", "progress" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is|i", kwd_list, 
                                      &dom, &state_file, &progress) )
        return NULL;

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

    static char *kwd_list[] = { "state_file", "progress" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "s|i", kwd_list, 
                                      &state_file, &progress) )
        return NULL;

    ret = xc_linux_restore(xc->xc_handle, state_file, progress);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_linux_build(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int dom;
    char        *image, *ramdisk = NULL, *cmdline = "";
    int          ret;

    static char *kwd_list[] = { "dom", "image", "ramdisk", "cmdline" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "is|ss", kwd_list, 
                                      &dom, &image, &ramdisk, &cmdline) )
        return NULL;

    ret = xc_linux_build(xc->xc_handle, dom, image, ramdisk, cmdline);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_bvtsched_global_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned long ctx_allow;
    int           ret;

    static char *kwd_list[] = { "ctx_allow" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "l", kwd_list, &ctx_allow) )
        return NULL;

    ret = xc_bvtsched_global_set(xc->xc_handle, ctx_allow);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_bvtsched_domain_set(PyObject *self,
                                          PyObject *args,
                                          PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int  dom;
    unsigned long mcuadv, warp, warpl, warpu;
    int           ret;

    static char *kwd_list[] = { "dom", "mcuadv", "warp", "warpl", "warpu" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "illll", kwd_list, 
                                      &dom, &mcuadv, &warp, &warpl, &warpu) )
        return NULL;

    ret = xc_bvtsched_domain_set(xc->xc_handle, dom, mcuadv, 
                                 warp, warpl, warpu);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vif_scheduler_set(PyObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int  dom, vif;
    xc_vif_sched_params_t sched = { 0, 0 };
    int           ret;

    static char *kwd_list[] = { "dom", "vif", "credit_bytes", "credit_usecs" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii|ll", kwd_list, 
                                      &dom, &vif, 
                                      &sched.credit_bytes, 
                                      &sched.credit_usec) )
        return NULL;

    ret = xc_vif_scheduler_set(xc->xc_handle, dom, vif, &sched);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vif_scheduler_get(PyObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *dict;

    unsigned int  dom, vif;
    xc_vif_sched_params_t sched;
    int           ret;

    static char *kwd_list[] = { "dom", "vif" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list, 
                                      &dom, &vif) )
        return NULL;

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

    unsigned int  dom, vif;
    xc_vif_stats_t stats;
    int           ret;

    static char *kwd_list[] = { "dom", "vif" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list, 
                                      &dom, &vif) )
        return NULL;

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

    unsigned int dom, vbd;
    int          writeable, ret;

    static char *kwd_list[] = { "dom", "vbd", "writeable" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iii", kwd_list, 
                                      &dom, &vbd, &writeable) )
        return NULL;

    ret = xc_vbd_create(xc->xc_handle, dom, vbd, writeable);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_destroy(PyObject *self,
                                  PyObject *args,
                                  PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int dom, vbd;
    int          ret;

    static char *kwd_list[] = { "dom", "vbd" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "ii", kwd_list, 
                                      &dom, &vbd) )
        return NULL;

    ret = xc_vbd_destroy(xc->xc_handle, dom, vbd);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_add_extent(PyObject *self,
                                     PyObject *args,
                                     PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int  dom, vbd, device;
    unsigned long start_sector, nr_sectors;
    int           ret;

    static char *kwd_list[] = { "dom", "vbd", "device", 
                                "start_sector", "nr_sectors" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiill", kwd_list, 
                                      &dom, &vbd, &device, 
                                      &start_sector, &nr_sectors) )
        return NULL;

    ret = xc_vbd_add_extent(xc->xc_handle, dom, vbd, device, 
                            start_sector, nr_sectors);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_delete_extent(PyObject *self,
                                        PyObject *args,
                                        PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int  dom, vbd, device;
    unsigned long start_sector, nr_sectors;
    int           ret;

    static char *kwd_list[] = { "dom", "vbd", "device", 
                                "start_sector", "nr_sectors" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "iiill", kwd_list, 
                                      &dom, &vbd, &device, 
                                      &start_sector, &nr_sectors) )
        return NULL;

    ret = xc_vbd_delete_extent(xc->xc_handle, dom, vbd, device, 
                               start_sector, nr_sectors);
    
    return PyInt_FromLong(ret);
}

static PyObject *pyxc_vbd_probe(PyObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;
    PyObject *list;

    unsigned int dom = XC_VBDDOM_PROBE_ALL, max_vbds = 1024;
    xc_vbd_t    *info;
    int          nr_vbds, i;

    static char *kwd_list[] = { "dom", "max_vbds" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwd_list, 
                                      &dom, &max_vbds) )
        return NULL;

    info = malloc(max_vbds * sizeof(xc_vbd_t));
    if ( info == NULL )
        nr_vbds = 0;
    else
        nr_vbds = xc_vbd_probe(xc->xc_handle, dom, max_vbds, info);

    list = PyList_New(nr_vbds);
    for ( i = 0; i < nr_vbds; i++ )
    {
        PyList_SetItem(
            list, i, 
            Py_BuildValue("{s:i,s:i,s:i,s:l}",
                          "dom",        info[i].domid,
                          "vbd",        info[i].vbdid,
                          "writeable",  !!(info[i].flags & XC_VBDF_WRITEABLE),
                          "nr_sectors", info[i].nr_sectors));
    }

    if ( info != NULL )
        free(info);

    return list;
}

static PyObject *pyxc_readconsolering(PyObject *self,
                                      PyObject *args,
                                      PyObject *kwds)
{
    XcObject *xc = (XcObject *)self;

    unsigned int clear = 0;
    char         str[32768];
    int          ret;

    static char *kwd_list[] = { "clear" };

    if ( !PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwd_list, &clear) )
        return NULL;

    ret = xc_readconsolering(xc->xc_handle, str, sizeof(str), clear);

    return PyString_FromStringAndSize(str, (ret < 0) ? 0 : ret);
}

static PyMethodDef pyxc_methods[] = {
    { "domain_create", 
      (PyCFunction)pyxc_domain_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new domain.\n"
      " mem_kb [int, 65536]:    Memory allocation, in kilobytes.\n"
      " name   [str, '(anon)']: Informative textual name.\n\n"
      "Returns: [int] new domain identifier; -1 on error.\n" },

    { "domain_start", 
      (PyCFunction)pyxc_domain_start, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Start execution of a domain.\n"
      " dom [int]: Identifier of domain to be started.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "domain_stop", 
      (PyCFunction)pyxc_domain_stop, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Stop execution of a domain.\n"
      " dom [int]: Identifier of domain to be stopped.\n\n"
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
      " dom      [int]:  Identifier of domain to which this info pertains\n"
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
      " dom        [int]:    Identifier of domain to be saved.\n"
      " state_file [str]:    Name of state file. Must not currently exist.\n"
      " progress   [int, 1]: Bool - display a running progress indication?\n\n"
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
      "Returns: [int] new domain identifier on success; -1 on error.\n" },

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
      " dom    [int]: Identifier of domain to be tuned.\n"
      " mcuadv [int]: Internal BVT parameter.\n"
      " warp   [int]: Internal BVT parameter.\n"
      " warpl  [int]: Internal BVT parameter.\n"
      " warpu  [int]: Internal BVT parameter.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vif_scheduler_set", 
      (PyCFunction)pyxc_vif_scheduler_set, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Set per-network-interface scheduling parameters.\n"
      " dom          [int]:    Identifier of domain to be adjusted.\n"
      " vif          [int]:    Identifier of VIF to be adjusted.\n"
      " credit_bytes [int, 0]: Tx bytes permitted each interval.\n"
      " credit_usecs [int, 0]: Interval, in usecs. 0 == no scheduling.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vif_scheduler_get", 
      (PyCFunction)pyxc_vif_scheduler_get, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Query the per-network-interface scheduling parameters.\n"
      " dom          [int]:    Identifier of domain to be queried.\n"
      " vif          [int]:    Identifier of VIF to be queried.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " credit_bytes [int]: Tx bytes permitted each interval.\n"
      " credit_usecs [int]: Interval, in usecs. 0 == no scheduling.\n" },

    { "vif_stats_get", 
      (PyCFunction)pyxc_vif_stats_get, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Query the per-network-interface statistics.\n"
      " dom          [int]: Identifier of domain to be queried.\n"
      " vif          [int]: Identifier of VIF to be queried.\n\n"
      "Returns: [dict] dictionary is empty on failure.\n"
      " tx_bytes   [long]: Bytes transmitted.\n"
      " tx_packets [long]: Packets transmitted.\n"
      " rx_bytes   [long]: Bytes received.\n"
      " rx_packets [long]: Packets received.\n" },

    { "vbd_create", 
      (PyCFunction)pyxc_vbd_create, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Create a new virtual block device associated with a given domain.\n"
      " dom       [int]: Identifier of domain to get a new VBD.\n"
      " vbd       [int]: Identifier for new VBD.\n"
      " writeable [int]: Bool - is the new VBD writeable?\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_destroy", 
      (PyCFunction)pyxc_vbd_destroy, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Destroy a virtual block device.\n"
      " dom       [int]: Identifier of domain containing the VBD.\n"
      " vbd       [int]: Identifier of the VBD.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_add_extent", 
      (PyCFunction)pyxc_vbd_add_extent, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Add an extent to a virtual block device.\n"
      " dom          [int]: Identifier of domain containing the VBD.\n"
      " vbd          [int]: Identifier of the VBD.\n"
      " device       [int]: Identifier of the real underlying block device.\n"
      " start_sector [int]: Real start sector of this extent.\n"
      " nr_sectors   [int]: Length, in sectors, of this extent.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_delete_extent", 
      (PyCFunction)pyxc_vbd_delete_extent, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Delete an extent from a virtual block device.\n"
      " dom          [int]: Identifier of domain containing the VBD.\n"
      " vbd          [int]: Identifier of the VBD.\n"
      " device       [int]: Identifier of the real underlying block device.\n"
      " start_sector [int]: Real start sector of the extent.\n"
      " nr_sectors   [int]: Length, in sectors, of the extent.\n\n"
      "Returns: [int] 0 on success; -1 on error.\n" },

    { "vbd_probe", 
      (PyCFunction)pyxc_vbd_probe, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Get information regarding extant virtual block devices.\n"
      " dom          [int, ALL]:  Domain to query (default is to query all).\n"
      " max_vbds     [int, 1024]: Maximum VBDs to query.\n\n"
      "Returns: [list of dicts] if list length is less than 'max_vbds'\n"
      "         parameter then there was an error, or there were fewer vbds.\n"
      " dom        [int]: Domain containing this VBD.\n"
      " vbd        [int]: Domain-specific identifier of this VBD.\n"
      " writeable  [int]: Bool - is this VBD writeable?\n"
      " nr_sectors [int]: Size of this VBD, in 512-byte sectors.\n" },

    { "readconsolering", 
      (PyCFunction)pyxc_readconsolering, 
      METH_VARARGS | METH_KEYWORDS, "\n"
      "Read Xen's console ring.\n"
      " clear [int, 0]: Bool - clear the ring after reading from it?\n\n"
      "Returns: [str] string is empty on failure.\n" },

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
