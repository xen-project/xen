/****************************************************************
 * acm.c
 *
 * Copyright (C) 2006,2007 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Stefan Berger <stefanb@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * ACM low-level code that allows Python control code to leverage
 * the ACM hypercall interface to retrieve real-time information
 * from the Xen hypervisor security module.
 *
 * indent -i4 -kr -nut
 */

#include <Python.h>

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <xenctrl.h>
#include <xen/xsm/acm.h>
#include <xen/xsm/acm_ops.h>

#define PERROR(_m, _a...) \
fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,    \
    errno, strerror(errno))

static PyObject *acm_error_obj;

/* generic shared function */
static void *__getssid(int domid, uint32_t *buflen)
{
    struct acm_getssid getssid;
    xc_interface *xc_handle;
    #define SSID_BUFFER_SIZE    4096
    void *buf = NULL;

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        goto out1;
    }
    if ((buf = malloc(SSID_BUFFER_SIZE)) == NULL) {
        PERROR("acm.policytype: Could not allocate ssid buffer!\n");
        goto out2;
    }
    memset(buf, 0, SSID_BUFFER_SIZE);
    set_xen_guest_handle(getssid.ssidbuf, buf);
    getssid.ssidbuf_size = SSID_BUFFER_SIZE;
    getssid.get_ssid_by = ACM_GETBY_domainid;
    getssid.id.domainid = domid;

    if (xc_acm_op(xc_handle, ACMOP_getssid, &getssid, sizeof(getssid)) < 0) {
        if (errno == EACCES)
            PERROR("ACM operation failed.");
        free(buf);
        buf = NULL;
        goto out2;
    } else {
        *buflen = SSID_BUFFER_SIZE;
        goto out2;
    }
 out2:
    xc_interface_close(xc_handle);
 out1:
    return buf;
}


/* retrieve the policytype indirectly by retrieving the
 * ssidref for domain 0 (always exists) */
static PyObject *policy(PyObject * self, PyObject * args)
{
    /* out */
    char *policyreference;
    PyObject *ret;
    void *ssid_buffer;
    uint32_t buf_len;

    if (!PyArg_ParseTuple(args, "", NULL)) {
        return NULL;
    }
    ssid_buffer =  __getssid(0, &buf_len);
    if (ssid_buffer == NULL || buf_len < sizeof(struct acm_ssid_buffer)) {
        free(ssid_buffer);
        return PyErr_SetFromErrno(acm_error_obj);
    }
    else {
        struct acm_ssid_buffer *ssid = (struct acm_ssid_buffer *)ssid_buffer;
        policyreference = (char *)(ssid_buffer + ssid->policy_reference_offset
                       + sizeof (struct acm_policy_reference_buffer));
        ret = Py_BuildValue("s", policyreference);
        free(ssid_buffer);
        return ret;
    }
}


/* retrieve ssid info for a domain domid*/
static PyObject *getssid(PyObject * self, PyObject * args)
{
    /* in */
    uint32_t    domid;
    /* out */
    char *policytype, *policyreference;
    uint32_t    ssidref;

    void *ssid_buffer;
    uint32_t buf_len;

    if (!PyArg_ParseTuple(args, "i", &domid)) {
        return NULL;
    }
    ssid_buffer =  __getssid(domid, &buf_len);
    if (ssid_buffer == NULL) {
        return NULL;
    } else if (buf_len < sizeof(struct acm_ssid_buffer)) {
        free(ssid_buffer);
        return NULL;
    } else {
        struct acm_ssid_buffer *ssid = (struct acm_ssid_buffer *) ssid_buffer;
        policytype = ACM_POLICY_NAME(ssid->secondary_policy_code << 4 |
                     ssid->primary_policy_code);
        ssidref = ssid->ssidref;
        policyreference = (char *)(ssid_buffer + ssid->policy_reference_offset
                       + sizeof (struct acm_policy_reference_buffer));
    }
    free(ssid_buffer);
    return Py_BuildValue("{s:s,s:s,s:i}",
             "policyreference",   policyreference,
             "policytype",        policytype,
             "ssidref",           ssidref);
}


/* retrieve access decision based on domain ids or ssidrefs */
static PyObject *getdecision(PyObject * self, PyObject * args)
{
    char *arg1_name, *arg1, *arg2_name, *arg2, *decision = NULL;
    struct acm_getdecision getdecision;
    xc_interface *xc_handle;
    int rc;
    uint32_t hooktype;

    if (!PyArg_ParseTuple(args, "ssssi", &arg1_name,
                          &arg1, &arg2_name, &arg2, &hooktype)) {
        return NULL;
    }

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        perror("Could not open xen privcmd device!\n");
        return NULL;
    }

    if ((strcmp(arg1_name, "domid") && strcmp(arg1_name, "ssidref")) ||
    (strcmp(arg2_name, "domid") && strcmp(arg2_name, "ssidref")))
        return NULL;

    getdecision.hook = hooktype;
    if (!strcmp(arg1_name, "domid")) {
        getdecision.get_decision_by1 = ACM_GETBY_domainid;
        getdecision.id1.domainid = atoi(arg1);
    } else {
        getdecision.get_decision_by1 = ACM_GETBY_ssidref;
        getdecision.id1.ssidref = atol(arg1);
    }
    if (!strcmp(arg2_name, "domid")) {
        getdecision.get_decision_by2 = ACM_GETBY_domainid;
        getdecision.id2.domainid = atoi(arg2);
    } else {
        getdecision.get_decision_by2 = ACM_GETBY_ssidref;
        getdecision.id2.ssidref = atol(arg2);
    }

    rc = xc_acm_op(xc_handle, ACMOP_getdecision,
                   &getdecision, sizeof(getdecision));

    xc_interface_close(xc_handle);

    if (rc < 0) {
        if (errno == EACCES)
            PERROR("ACM operation failed.");
        return NULL;
    }

    if (getdecision.acm_decision == ACM_ACCESS_PERMITTED)
        decision = "PERMITTED";
    else if (getdecision.acm_decision == ACM_ACCESS_DENIED)
        decision = "DENIED";

    return Py_BuildValue("s", decision);
}

/* error messages for exceptions */
const char bad_arg[] = "Bad function argument.";
const char ctrlif_op[] = "Could not open control interface.";
const char hv_op_err[] = "Error from hypervisor operation.";


static PyObject *chgpolicy(PyObject *self, PyObject *args)
{
    struct acm_change_policy chgpolicy;
    xc_interface *xc_handle;
    int rc;
    char *bin_pol = NULL, *del_arr = NULL, *chg_arr = NULL;
    int bin_pol_len = 0, del_arr_len = 0, chg_arr_len = 0;
    uint errarray_mbrs = 20 * 2;
    uint32_t error_array[errarray_mbrs];
    PyObject *result;
    uint len;

    memset(&chgpolicy, 0x0, sizeof(chgpolicy));

    if (!PyArg_ParseTuple(args, "s#s#s#" ,&bin_pol, &bin_pol_len,
                                          &del_arr, &del_arr_len,
                                          &chg_arr, &chg_arr_len)) {
        PyErr_SetString(PyExc_TypeError, bad_arg);
        return NULL;
    }

    chgpolicy.policy_pushcache_size = bin_pol_len;
    chgpolicy.delarray_size = del_arr_len;
    chgpolicy.chgarray_size = chg_arr_len;
    chgpolicy.errarray_size = sizeof(error_array);

    set_xen_guest_handle(chgpolicy.policy_pushcache, bin_pol);
    set_xen_guest_handle(chgpolicy.del_array, del_arr);
    set_xen_guest_handle(chgpolicy.chg_array, chg_arr);
    set_xen_guest_handle(chgpolicy.err_array, error_array);

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    rc = xc_acm_op(xc_handle, ACMOP_chgpolicy, &chgpolicy, sizeof(chgpolicy));

    xc_interface_close(xc_handle);

    /* only pass the filled error codes */
    for (len = 0; (len + 1) < errarray_mbrs; len += 2) {
        if (error_array[len] == 0) {
            len *= sizeof(error_array[0]);
            break;
        }
    }

    result = Py_BuildValue("is#", rc, error_array, len);
    return result;
}


static PyObject *getpolicy(PyObject *self, PyObject *args)
{
    struct acm_getpolicy getpolicy;
    xc_interface *xc_handle;
    int rc;
    uint8_t pull_buffer[8192];
    PyObject *result;
    uint32_t len = sizeof(pull_buffer);

    memset(&getpolicy, 0x0, sizeof(getpolicy));
    set_xen_guest_handle(getpolicy.pullcache, pull_buffer);
    getpolicy.pullcache_size = sizeof(pull_buffer);

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    rc = xc_acm_op(xc_handle, ACMOP_getpolicy, &getpolicy, sizeof(getpolicy));

    xc_interface_close(xc_handle);

    if (rc == 0) {
        struct acm_policy_buffer *header =
                       (struct acm_policy_buffer *)pull_buffer;
        if (ntohl(header->len) < sizeof(pull_buffer))
            len = ntohl(header->len);
    } else {
        len = 0;
    }

    result = Py_BuildValue("is#", rc, pull_buffer, len);
    return result;
}


static PyObject *relabel_domains(PyObject *self, PyObject *args)
{
    struct acm_relabel_doms reldoms;
    xc_interface *xc_handle;
    int rc;
    char *relabel_rules = NULL;
    int rel_rules_len = 0;
    uint errarray_mbrs = 20 * 2;
    uint32_t error_array[errarray_mbrs];
    PyObject *result;
    uint len;

    memset(&reldoms, 0x0, sizeof(reldoms));

    if (!PyArg_ParseTuple(args, "s#" ,&relabel_rules, &rel_rules_len)) {
        PyErr_SetString(PyExc_TypeError, bad_arg);
        return NULL;
    }

    reldoms.relabel_map_size = rel_rules_len;
    reldoms.errarray_size = sizeof(error_array);

    set_xen_guest_handle(reldoms.relabel_map, relabel_rules);
    set_xen_guest_handle(reldoms.err_array, error_array);

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    rc = xc_acm_op(xc_handle, ACMOP_relabeldoms, &reldoms, sizeof(reldoms));

    xc_interface_close(xc_handle);


    /* only pass the filled error codes */
    for (len = 0; (len + 1) < errarray_mbrs; len += 2) {
        if (error_array[len] == 0) {
            len *= sizeof(error_array[0]);
            break;
        }
    }

    result = Py_BuildValue("is#", rc, error_array, len);
    return result;
}


/*=================General Python Extension Declarations=================*/

/* methods */
static PyMethodDef acmMethods[] = {
    {"policy",      policy,      METH_VARARGS, "Retrieve Active ACM Policy Reference Name"},
    {"getssid",     getssid,     METH_VARARGS, "Retrieve label information and ssidref for a domain"},
    {"getdecision", getdecision, METH_VARARGS, "Retrieve ACM access control decision"},
    {"chgpolicy",   chgpolicy,   METH_VARARGS, "Change the policy in one step"},
    {"getpolicy",   getpolicy,   METH_NOARGS , "Get the binary policy from the hypervisor"},
    {"relabel_domains", relabel_domains, METH_VARARGS, "Relabel domains"},
    /* end of list (extend list above this line) */
    {NULL, NULL, 0, NULL}
};

/* inits */
PyMODINIT_FUNC initacm(void)
{
    PyObject *m = Py_InitModule("acm", acmMethods);
    acm_error_obj = PyErr_NewException("acm.Error", PyExc_RuntimeError, NULL);
    Py_INCREF(acm_error_obj);
    PyModule_AddObject(m, "Error", acm_error_obj);
}
