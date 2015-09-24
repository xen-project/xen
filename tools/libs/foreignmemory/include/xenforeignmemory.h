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
 * Return a handle onto the foreign memory mapping driver.  Logs errors.
 *
 * Note: After fork(2) a child process must not use any opened
 * foreignmemory handle inherited from their parent, nor access any
 * grant mapped areas associated with that handle.
 *
 * The child must open a new handle if they want to interact with
 * foreignmemory.
 *
 * Calling exec(2) in a child will safely (and reliably) reclaim any
 * resources which were allocated via a xenforeignmemory_handle in the
 * parent.
 *
 * A child which does not call exec(2) may safely call
 * xenforeignmemory_close() on a xenforeignmemory_handle inherited
 * from their parent. This will attempt to reclaim any resources
 * associated with that handle. Note that in some implementations this
 * reclamation may not be completely effective, in this case any
 * affected resources remain allocated.
 *
 * Calling xenforeignmemory_close() is the only safe operation on a
 * xenforeignmemory_handle which has been inherited.
 */
xenforeignmemory_handle *xenforeignmemory_open(xentoollog_logger *logger,
                                               unsigned open_flags);

/*
 * Close a handle previously allocated with xenforeignmemory_open().
 *
 * Under normal circumstances (i.e. not in the child after a fork)
 * xenforeignmemory_unmap() should be used on all mappings allocated
 * by xenforeignmemory_map() prior to closing the handle in order to
 * free up resources associated with those mappings.
 *
 * This is the only function which may be safely called on a
 * xenforeignmemory_handle in a child after a
 * fork. xenforeignmemory_unmap() must not be called under such
 * circumstances.
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
