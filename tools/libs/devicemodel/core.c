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

#include <stdlib.h>

#include "private.h"

xendevicemodel_handle *xendevicemodel_open(xentoollog_logger *logger,
                                           unsigned open_flags)
{
    xendevicemodel_handle *dmod = malloc(sizeof(*dmod));

    if (!dmod)
        return NULL;

    dmod->flags = open_flags;
    dmod->logger = logger;
    dmod->logger_tofree = NULL;

    if (!dmod->logger) {
        dmod->logger = dmod->logger_tofree =
            (xentoollog_logger*)
            xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
        if (!dmod->logger)
            goto err;
    }

    return dmod;

err:
    xtl_logger_destroy(dmod->logger_tofree);
    free(dmod);
    return NULL;
}

int xendevicemodel_close(xendevicemodel_handle *dmod)
{
    if (!dmod)
        return 0;

    xtl_logger_destroy(dmod->logger_tofree);
    free(dmod);
    return 0;
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
