/*
 * handlreg.c
 *
 * implementation of xentoolcore_restrict_all
 *
 * Copyright (c) 2017 Citrix
 * Part of a generic logging interface used by various dom0 userland libraries.
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

#include "xentoolcore_internal.h"

#include <pthread.h>
#include <assert.h>

static pthread_mutex_t handles_lock = PTHREAD_MUTEX_INITIALIZER;
static XENTOOLCORE_LIST_HEAD(, Xentoolcore__Active_Handle) handles;

static void lock(void) {
    int e = pthread_mutex_lock(&handles_lock);
    assert(!e);
}

static void unlock(void) {
    int e = pthread_mutex_unlock(&handles_lock);
    assert(!e);
}

void xentoolcore__register_active_handle(Xentoolcore__Active_Handle *ah) {
    lock();
    XENTOOLCORE_LIST_INSERT_HEAD(&handles, ah, entry);
    unlock();
}

void xentoolcore__deregister_active_handle(Xentoolcore__Active_Handle *ah) {
    lock();
    XENTOOLCORE_LIST_REMOVE(ah, entry);
    unlock();
}

int xentoolcore_restrict_all(uint32_t domid) {
    int r;
    Xentoolcore__Active_Handle *ah;

    lock();
    XENTOOLCORE_LIST_FOREACH(ah, &handles, entry) {
        r = ah->restrict_callback(ah, domid);
        if (r) goto out;
    }

    r = 0;
 out:
    unlock();
    return r;
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
