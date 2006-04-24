/****************************************************************
 * acm.c
 *
 * Copyright (C) 2006 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <xen/acm.h>
#include <xen/acm_ops.h>
#include <xen/linux/privcmd.h>

#define PERROR(_m, _a...) \
fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,    \
    errno, strerror(errno))



static inline int do_acm_op(int xc_handle, struct acm_op *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    op->interface_version = ACM_INTERFACE_VERSION;

    hypercall.op = __HYPERVISOR_acm_op;
    hypercall.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(*op)) != 0) {
        PERROR("Could not lock memory for Xen policy hypercall");
        goto out1;
    }
    ret = ioctl(xc_handle, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
    if (ret < 0) {
        if (errno == EACCES)
            PERROR("ACM operation failed.");
        goto out2;
    }
 out2:
    munlock(op, sizeof(*op));
 out1:
    return ret;
}



/* generic shared function */
void * __getssid(int domid, uint32_t *buflen)
{
    struct acm_op op;
    int acm_cmd_fd;
    #define SSID_BUFFER_SIZE    4096
    void *buf = NULL;

    if ((acm_cmd_fd = open("/proc/xen/privcmd", O_RDONLY)) < 0) {
        goto out1;
    }
    if ((buf = malloc(SSID_BUFFER_SIZE)) == NULL) {
        PERROR("acm.policytype: Could not allocate ssid buffer!\n");
        goto out2;
    }
    memset(buf, 0, SSID_BUFFER_SIZE);
    op.cmd = ACM_GETSSID;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.getssid.ssidbuf = buf;
    op.u.getssid.ssidbuf_size = SSID_BUFFER_SIZE;
    op.u.getssid.get_ssid_by = DOMAINID;
    op.u.getssid.id.domainid = domid;

    if (do_acm_op(acm_cmd_fd, &op) < 0) {
        free(buf);
        buf = NULL;
        goto out2;
    } else {
        *buflen = SSID_BUFFER_SIZE;
        goto out2;
    }
 out2:
    close(acm_cmd_fd);
 out1:
    return buf;
}


/* retrieve the policytype indirectly by retrieving the
 * ssidref for domain 0 (always exists) */
static PyObject *policy(PyObject * self, PyObject * args)
{
    /* out */
    char *policyreference;
    PyObject *ret = NULL;
    void *ssid_buffer;
    uint32_t buf_len;

    if (!PyArg_ParseTuple(args, "", NULL)) {
    goto out1;
    }
    ssid_buffer =  __getssid(0, &buf_len);
    if (ssid_buffer == NULL) {
        goto out1;
    } else if (buf_len < sizeof(struct acm_ssid_buffer)) {
        goto out2;
    } else {
        struct acm_ssid_buffer *ssid = (struct acm_ssid_buffer *)ssid_buffer;
        policyreference = (char *)(ssid_buffer + ssid->policy_reference_offset
                       + sizeof (struct acm_policy_reference_buffer));
    }
    ret = Py_BuildValue("s", policyreference);
 out2:
    free(ssid_buffer);
 out1:
    return ret;
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
    struct acm_op op;
    int acm_cmd_fd, ret;

    if (!PyArg_ParseTuple(args, "ssss", &arg1_name, &arg1, &arg2_name, &arg2)) {
        return NULL;
    }

    if ((acm_cmd_fd = open("/proc/xen/privcmd", O_RDONLY)) <= 0) {
        PERROR("Could not open xen privcmd device!\n");
        return NULL;
    }

    if ((strcmp(arg1_name, "domid") && strcmp(arg1_name, "ssidref")) ||
    (strcmp(arg2_name, "domid") && strcmp(arg2_name, "ssidref")))
        return NULL;

    op.cmd = ACM_GETDECISION;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.getdecision.hook = SHARING;
    if (!strcmp(arg1_name, "domid")) {
        op.u.getdecision.get_decision_by1 = DOMAINID;
        op.u.getdecision.id1.domainid = atoi(arg1);
    } else {
        op.u.getdecision.get_decision_by1 = SSIDREF;
        op.u.getdecision.id1.ssidref = atol(arg1);
    }
    if (!strcmp(arg2_name, "domid")) {
        op.u.getdecision.get_decision_by2 = DOMAINID;
        op.u.getdecision.id2.domainid = atoi(arg2);
    } else {
        op.u.getdecision.get_decision_by2 = SSIDREF;
        op.u.getdecision.id2.ssidref = atol(arg2);
    }

    ret = do_acm_op(acm_cmd_fd, &op);
    close(acm_cmd_fd);

    if (op.u.getdecision.acm_decision == ACM_ACCESS_PERMITTED)
        decision = "PERMITTED";
    else if (op.u.getdecision.acm_decision == ACM_ACCESS_DENIED)
        decision = "DENIED";

    return Py_BuildValue("s", decision);
}

/*=================General Python Extension Declarations=================*/

/* methods */
static PyMethodDef acmMethods[] = {
    {"policy", policy, METH_VARARGS, "Retrieve Active ACM Policy Reference Name"},
    {"getssid", getssid, METH_VARARGS, "Retrieve label information and ssidref for a domain"},
    {"getdecision", getdecision, METH_VARARGS, "Retrieve ACM access control decision"},
    /* end of list (extend list above this line) */
    {NULL, NULL, 0, NULL}
};

/* inits */
PyMODINIT_FUNC initacm(void)
{
    Py_InitModule("acm", acmMethods);
}
