/******************************************************************************
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
 *
 * Copyright (c) 2011, Citrix Systems
 */

#include <inttypes.h>
#include <errno.h>
#include <xenctrl.h>
#include <xenguest.h>

int xc_hvm_build(xc_interface *xch, uint32_t domid,
                 struct xc_hvm_build_args *hvm_args)
{
    errno = ENOSYS;
    return -1;
}

int xc_hvm_build_target_mem(xc_interface *xch,
                           uint32_t domid,
                           int memsize,
                           int target,
                           const char *image_name)
{
    errno = ENOSYS;
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
