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

int xc_domain_save(xc_interface *xch, int io_fd, uint32_t dom, uint32_t flags,
                   struct save_callbacks* callbacks, int hvm,
                   xc_migration_stream_t stream_type, int recv_fd)
{
    errno = ENOSYS;
    return -1;
}

int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      uint32_t store_domid, unsigned int console_evtchn,
                      unsigned long *console_mfn, uint32_t console_domid,
                      unsigned int hvm, unsigned int pae,
                      xc_migration_stream_t stream_type,
                      struct restore_callbacks *callbacks, int send_back_fd)
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
