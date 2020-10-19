/*
 * xentoolcore_internal.h
 *
 * Interfaces of xentoolcore directed internally at other Xen libraries
 *
 * Copyright (c) 2017 Citrix
 * 
 * Common code used by all Xen tools libraries
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

#ifndef XENTOOLCORE_INTERNAL_H
#define XENTOOLCORE_INTERNAL_H

#include <stddef.h>

#include "xentoolcore.h"
#include "_xentoolcore_list.h"

/*---------- active handle registration ----------*/

/*
 * This is all to support xentoolcore_restrict_all
 *
 * Any libxl library that opens a Xen control handle of any kind which
 * might allow manipulation of dom0, of other domains, or of the whole
 * machine, must:
 *   I. arrange that their own datastructure contains a
 *          Xentoolcore__Active_Handle
 * 
 *   II. during the "open handle" function
 *     1. allocate the memory for the own datastructure and initialise it
 *     2. set Xentoolcore__Active_Handle.restrict_callback
 *     3. call xentoolcore__register_active_handle
 *       3a. if the open fails, call xentoolcore__deregister_active_handle
 *     4. ONLY THEN actually open the relevant fd or whatever
 *
 *   III. during the "close handle" function
 *     1. FIRST call xentoolcore__deregister_active_handle
 *     2. close the relevant fd or whatever
 *
 * [ III(b). Do the same as III for error exit from the open function. ]
 *
 *   IV. in the restrict_callback function
 *     * Arrange that the fd (or other handle) can no longer by used
 *       other than with respect to domain domid.
 *     * Future attempts to manipulate other domains (or the whole
 *       host) via this handle must cause an error return (and
 *       perhaps a log message), not a crash
 *     * If selective restriction is not possible, the handle must
 *       be completely invalidated so that it is not useable;
 *       subsequent manipulations may not crash
 *     * The restrict_callback function should not normally fail
 *       if this can be easily avoided - it is better to make the
 *       handle nonfunction instead.
 *     * NB that restrict_callback might be called again.  That must
 *       work properly: if the domid is the same, it is idempotent.
 *       If the domid is different. then either the handle must be
 *       completely invalidated, or restrict_callback must fail.)
 *
 * Thread safety:
 *    xentoolcore__[de]register_active_handle are threadsafe
 *      but MUST NOT be called within restrict_callback
 *
 * Fork safety:
 *    Libraries which use these functions do not on that account
 *    need to take any special care over forks occurring in
 *    other threads, provided that they obey the rules above.
 */

typedef struct Xentoolcore__Active_Handle Xentoolcore__Active_Handle;

typedef int Xentoolcore__Restrict_Callback(Xentoolcore__Active_Handle*,
                                           domid_t domid);

struct Xentoolcore__Active_Handle {
    Xentoolcore__Restrict_Callback *restrict_callback;
    XENTOOLCORE_LIST_ENTRY(Xentoolcore__Active_Handle) entry;
};

void xentoolcore__register_active_handle(Xentoolcore__Active_Handle*);
void xentoolcore__deregister_active_handle(Xentoolcore__Active_Handle*);

/*
 * Utility function for use in restrict_callback in libraries whose
 * handles don't have a useful restrict function.  We neuter the fd by
 * dup'ing /dev/null onto it.  This is better than closing it, because
 * it does not involve locking against concurrent uses of in other
 * threads.
 *
 * Returns the value that restrict_callback should return.
 * fd may be < 0.
 */
int xentoolcore__restrict_by_dup2_null(int fd);

/* ---------- convenient stuff ---------- */

/*
 * This does not appear in xentoolcore.h because it is a bit
 * namespace-unclean.
 */

/*
 * Convenience macros.
 */

/*
 * CONTAINER_OF work like this.  Given:
 *    typedef struct {
 *      ...
 *      member_type member_name;
 *      ...
 *    } outer_type;
 *    outer_type outer, *outer_var;
 *    member_type *inner_ptr = &outer->member_name;
 *
 * Then, effectively:
 *    outer_type *CONTAINER_OF(member_type *inner_ptr,
 *                             *outer_var, // or type name for outer_type
 *                             member_name);
 *
 * So that:
 *    CONTAINER_OF(inner_ptr, *outer_var, member_name) == &outer
 *    CONTAINER_OF(inner_ptr, outer_type, member_name) == &outer
 */
#define CONTAINER_OF(inner_ptr, outer, member_name)                     \
    ({                                                                  \
        typeof(outer) *container_of_;                                   \
        container_of_ = (void*)((char*)(inner_ptr) -                    \
                                offsetof(typeof(outer), member_name));  \
        (void)(&container_of_->member_name ==                           \
               (typeof(inner_ptr))0) /* type check */;                  \
        container_of_;                                                  \
    })

#endif /* XENTOOLCORE_INTERNAL_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
