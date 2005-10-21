/****************************************************************
 * get_decision.c
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * An example program that shows how to retrieve an access control
 * decision from the hypervisor ACM based on the currently active policy.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/in.h>
#include <xen/acm.h>
#include <xen/acm_ops.h>
#include <xen/linux/privcmd.h>

#define PERROR(_m, _a...) \
fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,	\
                errno, strerror(errno))

void usage(char *progname)
{
    printf("Use: %s \n", progname);
    printf(" Test program illustrating the retrieval of\n");
    printf(" access control decisions from xen. At this time,\n");
    printf(" only sharing (STE) policy decisions are supported.\n");
    printf(" parameter options:\n");
    printf("\t -i domid -i domid\n");
    printf("\t -i domid -s ssidref\n");
    printf("\t -s ssidref -s ssidref\n\n");
    exit(-1);
}

static inline int do_policycmd(int xc_handle, unsigned int cmd,
                               unsigned long data)
{
    return ioctl(xc_handle, cmd, data);
}

static inline int do_xen_hypercall(int xc_handle,
                                   privcmd_hypercall_t * hypercall)
{
    return do_policycmd(xc_handle,
                        IOCTL_PRIVCMD_HYPERCALL,
                        (unsigned long) hypercall);
}

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

    if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0) {
        if (errno == EACCES)
            fprintf(stderr, "ACM operation failed -- need to"
                    " rebuild the user-space tool set?\n");
        goto out2;
    }

  out2:(void) munlock(op, sizeof(*op));
  out1:return ret;
}


/************************ get decision ******************************/

/* this example uses two domain ids and retrieves the decision if these domains
 * can share information (useful, i.e., to enforce policy onto network traffic in dom0
 */
int acm_get_decision(int xc_handle, int argc, char *const argv[])
{
    struct acm_op op;
    int ret;

    op.cmd = ACM_GETDECISION;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.getdecision.get_decision_by1 = UNSET;
    op.u.getdecision.get_decision_by2 = UNSET;
    op.u.getdecision.hook = SHARING;

    while (1) {
        int c = getopt(argc, argv, "i:s:");
        if (c == -1)
            break;

        if (c == 'i') {
            if (op.u.getdecision.get_decision_by1 == UNSET) {
                op.u.getdecision.get_decision_by1 = DOMAINID;
                op.u.getdecision.id1.domainid = strtoul(optarg, NULL, 0);
            } else if (op.u.getdecision.get_decision_by2 == UNSET) {
                op.u.getdecision.get_decision_by2 = DOMAINID;
                op.u.getdecision.id2.domainid = strtoul(optarg, NULL, 0);
            } else
                usage(argv[0]);
        } else if (c == 's') {
            if (op.u.getdecision.get_decision_by1 == UNSET) {
                op.u.getdecision.get_decision_by1 = SSIDREF;
                op.u.getdecision.id1.ssidref = strtoul(optarg, NULL, 0);
            } else if (op.u.getdecision.get_decision_by2 == UNSET) {
                op.u.getdecision.get_decision_by2 = SSIDREF;
                op.u.getdecision.id2.ssidref = strtoul(optarg, NULL, 0);
            } else
                usage(argv[0]);
        } else
            usage(argv[0]);
    }
    if ((op.u.getdecision.get_decision_by1 == UNSET) ||
        (op.u.getdecision.get_decision_by2 == UNSET))
        usage(argv[0]);

    if ((ret = do_acm_op(xc_handle, &op))) {
        printf("%s: Error getting decision (%d).\n", __func__, ret);
        printf("%s: decision = %s.\n", __func__,
               (op.u.getdecision.acm_decision ==
                ACM_ACCESS_PERMITTED) ? "PERMITTED" : ((op.u.getdecision.
                                                        acm_decision ==
                                                        ACM_ACCESS_DENIED)
                                                       ? "DENIED" :
                                                       "ERROR"));
        return ret;
    }
    return op.u.getdecision.acm_decision;
}

/***************************** main **************************************/

int main(int argc, char **argv)
{

    int acm_cmd_fd, ret = 0;

    if (argc < 5)
        usage(argv[0]);

    if ((acm_cmd_fd = open("/proc/xen/privcmd", O_RDONLY)) <= 0) {
        printf("ERROR: Could not open xen privcmd device!\n");
        exit(-1);
    }

    ret = acm_get_decision(acm_cmd_fd, argc, argv);

    printf("Decision: %s (%d)\n",
           (ret == ACM_ACCESS_PERMITTED) ? "PERMITTED" :
           ((ret == ACM_ACCESS_DENIED) ? "DENIED" : "ERROR"), ret);

    close(acm_cmd_fd);
    return ret;
}
