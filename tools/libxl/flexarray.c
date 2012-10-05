/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_internal.h"
#include <stdarg.h>

/*
 * It is safe to store gc in the struct because:
 * - If it an actual gc, then the flexarray should not be used after the gc
 *   have been freed.
 * - If it is a NOGC, then this point to a structure embedded in libxl_ctx,
 *   therefore will survive across several libxl calls.
 */

flexarray_t *flexarray_make(libxl__gc *gc, int size, int autogrow)
{
    flexarray_t *array;

    GCNEW(array);
    array->size = size;
    array->autogrow = autogrow;
    array->count = 0;
    array->gc = gc;
    GCNEW_ARRAY(array->data, size);

    return array;
}

void flexarray_free(flexarray_t *array)
{
    assert(!libxl__gc_is_real(array->gc));
    free(array->data);
    free(array);
}

void flexarray_grow(flexarray_t *array, int extents)
{
    int newsize;
    libxl__gc *gc = array->gc;

    newsize = array->size + extents;
    GCREALLOC_ARRAY(array->data, newsize);
    array->size += extents;
}

int flexarray_set(flexarray_t *array, unsigned int idx, void *ptr)
{
    if (idx >= array->size) {
        int newsize;
        if (!array->autogrow)
            return 1;
        newsize = (array->size * 2 < idx) ? idx + 1 : array->size * 2;
        flexarray_grow(array, newsize - array->size);
    }
    if ( idx + 1 > array->count )
        array->count = idx + 1;
    array->data[idx] = ptr;
    return 0;
}

int flexarray_append(flexarray_t *array, void *ptr)
{
    return flexarray_set(array, array->count, ptr);
}

int flexarray_append_pair(flexarray_t *array, void *ptr1, void *ptr2)
{
    int rc = flexarray_append(array, ptr1);
    if (!rc)
        rc = flexarray_append(array, ptr2);
    return rc;
}

int flexarray_vappend(flexarray_t *array, ...)
{
    va_list va;
    void *ptr;
    int ret;

    va_start(va, array);
    for(ret = 0; (ptr = va_arg(va, void *)); ret++) {
        if ( flexarray_append(array, ptr) )
            break;
    }
    va_end(va);
    return ret;
}

int flexarray_get(flexarray_t *array, int idx, void **ptr)
{
    if (idx >= array->size)
        return 1;
    *ptr = array->data[idx];
    return 0;
}

void **flexarray_contents(flexarray_t *array)
{
    void **data;
    data = array->data;
    if (!libxl__gc_is_real(array->gc))
        free(array);
    return data;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
