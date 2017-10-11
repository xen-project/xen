/*
 * Copyright (c) 2017 Citrix Systems Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <xen/xen.h>
#include <xen/sys/privcmd.h>

#include "private.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int osdep_xendevicemodel_open(xendevicemodel_handle *dmod)
{
    int fd = open("/dev/xen/privcmd", O_RDWR | O_CLOEXEC);
    privcmd_dm_op_t uop;
    int rc;

    if (fd < 0) {
        /*
         * If the 'new' privcmd interface doesn't exist then don't treat
         * this as an error, but an old privcmd clearly won't implement
         * IOCTL_PRIVCMD_DM_OP so don't bother trying to open it.
         */
        if (errno == ENOENT || errno == ENXIO || errno == ENODEV)
            goto out;

        PERROR("Could not obtain handle on privileged command interface");
        return -1;
    }

    /*
     * Check to see if IOCTL_PRIVCMD_DM_OP is implemented as we want to
     * use that in preference to libxencall.
     */
    uop.dom = DOMID_INVALID;
    uop.num = 0;
    uop.ubufs = NULL;

    rc = ioctl(fd, IOCTL_PRIVCMD_DM_OP, &uop);
    if (rc < 0) {
        close(fd);
        fd = -1;
    }

out:
    dmod->fd = fd;
    return 0;
}

int osdep_xendevicemodel_close(xendevicemodel_handle *dmod)
{
    if (dmod->fd < 0)
        return 0;

    return close(dmod->fd);
}

int osdep_xendevicemodel_op(xendevicemodel_handle *dmod,
                            domid_t domid, unsigned int nr_bufs,
                            struct xendevicemodel_buf bufs[])
{
    privcmd_dm_op_buf_t *ubufs;
    privcmd_dm_op_t uop;
    unsigned int i;
    int rc;

    if (dmod->fd < 0)
        return xendevicemodel_xcall(dmod, domid, nr_bufs, bufs);

    ubufs = calloc(nr_bufs, sizeof (*ubufs));
    if (!ubufs)
        return -1;

    for (i = 0; i < nr_bufs; i++) {
        ubufs[i].uptr = bufs[i].ptr;
        ubufs[i].size = bufs[i].size;
    }

    uop.dom = domid;
    uop.num = nr_bufs;
    uop.ubufs = ubufs;

    rc = ioctl(dmod->fd, IOCTL_PRIVCMD_DM_OP, &uop);

    free(ubufs);

    if (rc < 0)
        return -1;

    return 0;
}

int osdep_xendevicemodel_restrict(xendevicemodel_handle *dmod,
                                  domid_t domid)
{
    if (dmod->fd < 0) {
        errno = EOPNOTSUPP;
        return -1;
    }

    return ioctl(dmod->fd, IOCTL_PRIVCMD_RESTRICT, &domid);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
