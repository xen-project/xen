/*
 * Copyright (c) 2016, Citrix Systems Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef __XEN_PUBLIC_HVM_DM_OP_H__
#define __XEN_PUBLIC_HVM_DM_OP_H__

#include "../xen.h"

#if defined(__XEN__) || defined(__XEN_TOOLS__)

struct xen_dm_op {
    uint32_t op;
};

#endif /* __XEN__ || __XEN_TOOLS__ */

struct xen_dm_op_buf {
    XEN_GUEST_HANDLE(void) h;
    xen_ulong_t size;
};
typedef struct xen_dm_op_buf xen_dm_op_buf_t;
DEFINE_XEN_GUEST_HANDLE(xen_dm_op_buf_t);

/* ` enum neg_errnoval
 * ` HYPERVISOR_dm_op(domid_t domid,
 * `                  xen_dm_op_buf_t bufs[],
 * `                  unsigned int nr_bufs)
 * `
 *
 * @domid is the domain the hypercall operates on.
 * @bufs points to an array of buffers where @bufs[0] contains a struct
 * xen_dm_op, describing the specific device model operation and its
 * parameters.
 * @bufs[1..] may be referenced in the parameters for the purposes of
 * passing extra information to or from the domain.
 * @nr_bufs is the number of buffers in the @bufs array.
 */

#endif /* __XEN_PUBLIC_HVM_DM_OP_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
