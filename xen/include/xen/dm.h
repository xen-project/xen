/*
 * Copyright (c) 2016 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XEN_DM_H__
#define __XEN_DM_H__

#include <xen/types.h>

#include <public/hvm/dm_op.h>
#include <public/xen.h>

struct dmop_args {
    domid_t domid;
    unsigned int nr_bufs;
    /* Reserve enough buf elements for all current hypercalls. */
    struct xen_dm_op_buf buf[2];
};

int dm_op(const struct dmop_args *op_args);

#endif /* __XEN_DM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
