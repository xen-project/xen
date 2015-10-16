/*
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
#ifndef XENFOREIGNMEMORY_H
#define XENFOREIGNMEMORY_H

/*
 * This library allows you to map foreign domain memory, subject to
 * permissions for both the process and the domain in which the
 * process runs.
 */

#include <stdint.h>
#include <stddef.h>

#include <xen/xen.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
typedef struct xentoollog_logger xentoollog_logger;

typedef struct xenforeignmemory_handle xenforeignmemory_handle;

/*
 * Return a handle onto the hypercall driver.  Logs errors.
 */
xenforeignmemory_handle *xenforeignmemory_open(xentoollog_logger *logger,
                                               unsigned open_flags);

/*
 * Close a handle previously allocated with xenforeignmemory_open().
 */
int xenforeignmemory_close(xenforeignmemory_handle *fmem);

/*
 * Maps a range within one domain to a local address range.  Mappings
 * must be unmapped with xenforeignmemory_unmap and should follow the
 * same rules as mmap regarding page alignment.
 *
 * prot is as for mmap(2).
 *
 * Can partially succeed. When a page cannot be mapped, its respective
 * field in @err is set to the corresponding errno value.
 *
 * Returns NULL if no pages can be mapped.
 */
void *xenforeignmemory_map(xenforeignmemory_handle *fmem, uint32_t dom,
                           int prot, const xen_pfn_t *arr, int *err,
                           size_t pages);

/*
 * Unmap a mapping previous created with xenforeignmemory_map().
 *
 * Returns 0 on success on failure sets errno and returns -1.
 */
int xenforeignmemory_unmap(xenforeignmemory_handle *fmem,
                           void *addr, size_t pages);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
