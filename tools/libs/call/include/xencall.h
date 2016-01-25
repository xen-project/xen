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
#ifndef XENCALL_H
#define XENCALL_H

/*
 * This library allows you to make arbitrary hypercalls (subject to
 * sufficient permission for the process and the domain itself). Note
 * that while the library interface is stable the hypercalls are
 * subject to their own rules.
 */

#include <stdint.h>
#include <stddef.h>

/* Callers who don't care don't need to #include <xentoollog.h> */
struct xentoollog_logger;

typedef struct xencall_handle xencall_handle;

/*
 */
#define XENCALL_OPENFLAG_NON_REENTRANT (1U<<0)

/*
 * Return a handle onto the hypercall driver.  Logs errors.
 * *
 * Note: After fork(2) a child process must not use any opened
 * xencall handle inherited from their parent, nor access any
 * hypercall argument buffers associated with that handle.
 *
 * The child must open a new handle if they want to interact with
 * xencall.
 *
 * Calling exec(2) in a child will safely (and reliably) reclaim any
 * resources which were allocated via a xencall_handle in the parent.
 *
 * A child which does not call exec(2) may safely call xencall_close()
 * on a xencall_handle inherited from their parent. This will attempt
 * to reclaim any resources associated with that handle. Note that in
 * some implementations this reclamation may not be completely
 * effective, in this case any affected resources remain allocated.
 *
 * Calling xencall_close() is the only safe operation on a
 * xencall_handle which has been inherited.
 */
xencall_handle *xencall_open(struct xentoollog_logger *logger,
                             unsigned open_flags);

/*
 * Close a handle previously allocated with xencall_open().
 *
 * Under normal circumstances (i.e. not in the child after a fork) any
 * allocated hypercall argument buffers should be freed using the
 * appropriate xencall_free_*() prior to closing the handle in order
 * to free up resources associated with those mappings.
 *
 * This is the only function which may be safely called on a
 * xencall_handle in a child after a fork. xencall_free_*() must not
 * be called under such circumstances.
 */
int xencall_close(xencall_handle *xcall);

/*
 * Call hypercalls with varying numbers of arguments.
 *
 * On success the return value of the hypercall is the return value of
 * the xencall function.  On error these functions set errno and
 * return -1.
 *
 * The errno values will be either:
 * - The Xen hypercall error return (from xen/include/public/errno.h)
 *   translated into the corresponding local value for that POSIX error.
 * - An errno value produced by the OS driver or the library
 *   implementation. Such values may be defined by POSIX or by the OS.
 *
 * Note that under some circumstances it will not be possible to tell
 * whether an error came from Xen or from the OS/library.
 *
 * These functions never log.
 */
int xencall0(xencall_handle *xcall, unsigned int op);
int xencall1(xencall_handle *xcall, unsigned int op,
             uint64_t arg1);
int xencall2(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2);
int xencall3(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3);
int xencall4(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3,
             uint64_t arg4);
int xencall5(xencall_handle *xcall, unsigned int op,
             uint64_t arg1, uint64_t arg2, uint64_t arg3,
             uint64_t arg4, uint64_t arg5);

/*
 * Allocate and free memory which is suitable for use as a pointer
 * argument to a hypercall.
 */
void *xencall_alloc_buffer_pages(xencall_handle *xcall, size_t nr_pages);
void xencall_free_buffer_pages(xencall_handle *xcall, void *p, size_t nr_pages);

void *xencall_alloc_buffer(xencall_handle *xcall, size_t size);
void xencall_free_buffer(xencall_handle *xcall, void *p);

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
