/*
 * xentoolcore.h
 *
 * Copyright (c) 2017 Citrix
 * 
 * Common features used/provided by all Xen tools libraries
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

#ifndef XENTOOLCORE_H
#define XENTOOLCORE_H

#include <stdint.h>

/*
 * int xentoolcore_restrict_all(uint32_t domid);
 *
 * Arranges that Xen library handles (fds etc.) which are currently held
 * by Xen libraries, can no longer be used other than to affect domid.
 *
 * Does not prevent effects that amount only to
 *   - denial of service, possibly host-wide, by resource exhaustion etc.
 *   - leak of not-very-interesting metainformation about other domains
 *     eg, specifically, event channel signals relating to other domains
 *
 * If this cannot be achieved, returns -1 and sets errno.
 * If called again with the same domid, it may succeed, or it may
 * fail (even though such a call is potentially meaningful).
 * (If called again with a different domid, it will necessarily fail.)
 *
 *  ====================================================================
 *  IMPORTANT - IMPLEMENTATION STATUS
 *
 *  This function has been implemented insofar as it appears necessary
 *  for the purposes of running a deprivileged qemu, and is believed to
 *  be sufficient (subject to the caveats discussed in the appropriate
 *  libxl documentation for this feature).
 *
 *  However, this function is NOT implemented for all Xen libraries.
 *  For each use case of this function, the designer must evaluate and
 *  audit whether the implementation is sufficient in their specific
 *  context.
 *
 *  Of course, patches to extend the implementation are very welcome.
 *  ====================================================================
 *
 * Thread safe.
 *
 * We expect that no callers do the following:
 *   - in one thread call xen_somelibrary_open|close
 *   - in another thread call fork
 *   - in the child of the fork, before exec, call
 *     xen_some[other]library_open|close or xentoolcore_restrict_all
 *
 */
int xentoolcore_restrict_all(uint32_t domid);

#endif /* XENTOOLCORE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
