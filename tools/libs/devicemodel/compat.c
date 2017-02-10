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

#include "private.h"

int osdep_xendevicemodel_open(xendevicemodel_handle *dmod)
{
    return 0;
}

int osdep_xendevicemodel_close(xendevicemodel_handle *dmod)
{
    return 0;
}

int osdep_xendevicemodel_op(xendevicemodel_handle *dmod,
                            domid_t domid, unsigned int nr_bufs,
                            struct xendevicemodel_buf bufs[])
{
    return xendevicemodel_xcall(dmod, domid, nr_bufs, bufs);
}

int osdep_xendevicemodel_restrict(xendevicemodel_handle *dmod,
                                  domid_t domid)
{
    errno = EOPNOTSUPP;
    return -1;
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
