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
static void *__getssid(xc_interface *xc_handle, int domid, uint32_t *buflen, xc_hypercall_buffer_t *buffer)
{
    struct acm_getssid getssid;
    #define SSID_BUFFER_SIZE    4096
    void *buf;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(buffer);

    if ((buf = xc_hypercall_buffer_alloc(xc_handle, buffer, SSID_BUFFER_SIZE)) == NULL) {
        PERROR("acm.policytype: Could not allocate ssid buffer!\n");
	return NULL;
    }

    memset(buf, 0, SSID_BUFFER_SIZE);
    xc_set_xen_guest_handle(getssid.ssidbuf, buffer);
    getssid.ssidbuf_size = SSID_BUFFER_SIZE;
    getssid.get_ssid_by = ACM_GETBY_domainid;
    getssid.id.domainid = domid;

    if (xc_acm_op(xc_handle, ACMOP_getssid, &getssid, sizeof(getssid)) < 0) {
        if (errno == EACCES)
            PERROR("ACM operation failed.");
        buf = NULL;
    } else {
        *buflen = SSID_BUFFER_SIZE;
    }
    return buf;
}


/* retrieve the policytype indirectly by retrieving the
 * ssidref for domain 0 (always exists) */
static PyObject *policy(PyObject * self, PyObject * args)
{
    xc_interface *xc_handle;
    char *policyreference;
    PyObject *ret;
    uint32_t buf_len;
    DECLARE_HYPERCALL_BUFFER(void, ssid_buffer);

    if (!PyArg_ParseTuple(args, "", NULL)) {
        return NULL;
    }
    if ((xc_handle = xc_interface_open(0,0,0)) == 0)
        return PyErr_SetFromErrno(acm_error_obj);

    ssid_buffer =  __getssid(xc_handle, 0, &buf_len, HYPERCALL_BUFFER(ssid_buffer));
    if (ssid_buffer == NULL || buf_len < sizeof(struct acm_ssid_buffer))
        ret = PyErr_SetFromErrno(acm_error_obj);
    else {
        struct acm_ssid_buffer *ssid = (struct acm_ssid_buffer *)ssid_buffer;
        policyreference = (char *)(ssid_buffer + ssid->policy_reference_offset
                       + sizeof (struct acm_policy_reference_buffer));
        ret = Py_BuildValue("s", policyreference);
    }

    xc_hypercall_buffer_free(xc_handle, ssid_buffer);
    xc_interface_close(xc_handle);
    return ret;
}


/* retrieve ssid info for a domain domid*/
static PyObject *getssid(PyObject * self, PyObject * args)
{
    xc_interface *xc_handle;

    /* in */
    uint32_t    domid;
    /* out */
    char *policytype, *policyreference;
    uint32_t    ssidref;
    PyObject *ret;

    DECLARE_HYPERCALL_BUFFER(void, ssid_buffer);
    uint32_t buf_len;

    if (!PyArg_ParseTuple(args, "i", &domid)) {
        return NULL;
    }
    if ((xc_handle = xc_interface_open(0,0,0)) == 0)
        return PyErr_SetFromErrno(acm_error_obj);

    ssid_buffer =  __getssid(xc_handle, domid, &buf_len, HYPERCALL_BUFFER(ssid_buffer));
    if (ssid_buffer == NULL) {
        ret = NULL;
    } else if (buf_len < sizeof(struct acm_ssid_buffer)) {
        ret = NULL;
    } else {
        struct acm_ssid_buffer *ssid = (struct acm_ssid_buffer *) ssid_buffer;
        policytype = ACM_POLICY_NAME(ssid->secondary_policy_code << 4 |
                     ssid->primary_policy_code);
        ssidref = ssid->ssidref;
        policyreference = (char *)(ssid_buffer + ssid->policy_reference_offset
                       + sizeof (struct acm_policy_reference_buffer));
	ret = Py_BuildValue("{s:s,s:s,s:i}",
			    "policyreference",   policyreference,
			    "policytype",        policytype,
			    "ssidref",           ssidref);
    }
    xc_hypercall_buffer_free(xc_handle, ssid_buffer);
    xc_interface_close(xc_handle);
    return ret;
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
    PyObject *result = NULL;
    uint len;
    DECLARE_HYPERCALL_BUFFER(char, bin_pol_buf);
    DECLARE_HYPERCALL_BUFFER(char, del_arr_buf);
    DECLARE_HYPERCALL_BUFFER(char, chg_arr_buf);
    DECLARE_HYPERCALL_BUFFER(uint32_t, error_array);

    memset(&chgpolicy, 0x0, sizeof(chgpolicy));

    if (!PyArg_ParseTuple(args, "s#s#s#" ,&bin_pol, &bin_pol_len,
                                          &del_arr, &del_arr_len,
                                          &chg_arr, &chg_arr_len)) {
        PyErr_SetString(PyExc_TypeError, bad_arg);
        return NULL;
    }

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    if ( (bin_pol_buf = xc_hypercall_buffer_alloc(xc_handle, bin_pol_buf, bin_pol_len)) == NULL )
	goto out;
    if ( (del_arr_buf = xc_hypercall_buffer_alloc(xc_handle, del_arr_buf, del_arr_len)) == NULL )
	goto out;
    if ( (chg_arr_buf = xc_hypercall_buffer_alloc(xc_handle, chg_arr_buf, chg_arr_len)) == NULL )
	goto out;
    if ( (error_array = xc_hypercall_buffer_alloc(xc_handle, error_array, sizeof(*error_array)*errarray_mbrs)) == NULL )
	goto out;

    memcpy(bin_pol_buf, bin_pol, bin_pol_len);
    memcpy(del_arr_buf, del_arr, del_arr_len);
    memcpy(chg_arr_buf, chg_arr, chg_arr_len);

    chgpolicy.policy_pushcache_size = bin_pol_len;
    chgpolicy.delarray_size = del_arr_len;
    chgpolicy.chgarray_size = chg_arr_len;
    chgpolicy.errarray_size = sizeof(*error_array)*errarray_mbrs;
    xc_set_xen_guest_handle(chgpolicy.policy_pushcache, bin_pol_buf);
    xc_set_xen_guest_handle(chgpolicy.del_array, del_arr_buf);
    xc_set_xen_guest_handle(chgpolicy.chg_array, chg_arr_buf);
    xc_set_xen_guest_handle(chgpolicy.err_array, error_array);

    rc = xc_acm_op(xc_handle, ACMOP_chgpolicy, &chgpolicy, sizeof(chgpolicy));

    /* only pass the filled error codes */
    for (len = 0; (len + 1) < errarray_mbrs; len += 2) {
        if (error_array[len] == 0) {
            len *= sizeof(error_array[0]);
            break;
        }
    }

    result = Py_BuildValue("is#", rc, error_array, len);

out:
    xc_hypercall_buffer_free(xc_handle, bin_pol_buf);
    xc_hypercall_buffer_free(xc_handle, del_arr_buf);
    xc_hypercall_buffer_free(xc_handle, chg_arr_buf);
    xc_hypercall_buffer_free(xc_handle, error_array);
    xc_interface_close(xc_handle);
    return result;
}


static PyObject *getpolicy(PyObject *self, PyObject *args)
{
    struct acm_getpolicy getpolicy;
    xc_interface *xc_handle;
    int rc;
    PyObject *result = NULL;
    uint32_t len = 8192;
    DECLARE_HYPERCALL_BUFFER(uint8_t, pull_buffer);

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    if ((pull_buffer = xc_hypercall_buffer_alloc(xc_handle, pull_buffer, len)) == NULL)
	goto out;

    memset(&getpolicy, 0x0, sizeof(getpolicy));
    xc_set_xen_guest_handle(getpolicy.pullcache, pull_buffer);
    getpolicy.pullcache_size = sizeof(pull_buffer);

    rc = xc_acm_op(xc_handle, ACMOP_getpolicy, &getpolicy, sizeof(getpolicy));

    if (rc == 0) {
        struct acm_policy_buffer *header =
                       (struct acm_policy_buffer *)pull_buffer;
        if (ntohl(header->len) < 8192)
            len = ntohl(header->len);
    } else {
        len = 0;
    }

    result = Py_BuildValue("is#", rc, pull_buffer, len);
out:
    xc_hypercall_buffer_free(xc_handle, pull_buffer);
    xc_interface_close(xc_handle);
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
    DECLARE_HYPERCALL_BUFFER(uint32_t, error_array);
    DECLARE_HYPERCALL_BUFFER(char, relabel_rules_buf);
    PyObject *result = NULL;
    uint len;

    memset(&reldoms, 0x0, sizeof(reldoms));

    if (!PyArg_ParseTuple(args, "s#" ,&relabel_rules, &rel_rules_len)) {
        PyErr_SetString(PyExc_TypeError, bad_arg);
        return NULL;
    }

    if ((xc_handle = xc_interface_open(0,0,0)) == 0) {
        PyErr_SetString(PyExc_IOError, ctrlif_op);
        return NULL;
    }

    if ((relabel_rules_buf = xc_hypercall_buffer_alloc(xc_handle, relabel_rules_buf, rel_rules_len)) == NULL)
	goto out;
    if ((error_array = xc_hypercall_buffer_alloc(xc_handle, error_array, sizeof(*error_array)*errarray_mbrs)) == NULL)
	goto out;

    memcpy(relabel_rules_buf, relabel_rules, rel_rules_len);

    reldoms.relabel_map_size = rel_rules_len;
    reldoms.errarray_size = sizeof(error_array);

    xc_set_xen_guest_handle(reldoms.relabel_map, relabel_rules_buf);
    xc_set_xen_guest_handle(reldoms.err_array, error_array);

    rc = xc_acm_op(xc_handle, ACMOP_relabeldoms, &reldoms, sizeof(reldoms));

    /* only pass the filled error codes */
    for (len = 0; (len + 1) < errarray_mbrs; len += 2) {
        if (error_array[len] == 0) {
            len *= sizeof(error_array[0]);
            break;
        }
    }

    result = Py_BuildValue("is#", rc, error_array, len);
out:
    xc_hypercall_buffer_free(xc_handle, relabel_rules_buf);
    xc_hypercall_buffer_free(xc_handle, error_array);
    xc_interface_close(xc_handle);

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
