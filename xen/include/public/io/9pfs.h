/* SPDX-License-Identifier: MIT */
/*
 * 9pfs.h -- Xen 9PFS transport
 *
 * Refer to docs/misc/9pfs.markdown for the specification
 *
 * Copyright (C) 2017 Stefano Stabellini <stefano@aporeto.com>
 */

#ifndef __XEN_PUBLIC_IO_9PFS_H__
#define __XEN_PUBLIC_IO_9PFS_H__

#include "../grant_table.h"
#include "ring.h"

/*
 * See docs/misc/9pfs.markdown in xen.git for the full specification:
 * https://xenbits.xen.org/docs/unstable/misc/9pfs.html
 */
DEFINE_XEN_FLEX_RING_AND_INTF(xen_9pfs);

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
