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

flexarray_t *flexarray_make(int size, int autogrow)
{
    flexarray_t *array = malloc(sizeof(struct flexarray));
    if (array) {
        array->size = size;
        array->autogrow = autogrow;
        array->count = 0;
        array->data = calloc(size, sizeof(void *));
    }
    return array;
}

void flexarray_free(flexarray_t *array)
{
    free(array->data);
    free(array);
}

int flexarray_grow(flexarray_t *array, int extents)
{
    void **data;
    int newsize;

    newsize = array->size + extents;
    data = realloc(array->data, sizeof(void *) * newsize);
    if (!data)
        return 1;
    array->size += extents;
    array->data = data;
    return 0;
}

int flexarray_set(flexarray_t *array, unsigned int index, void *ptr)
{
    if (index >= array->size) {
        int newsize;
        if (!array->autogrow)
            return 1;
        newsize = (array->size * 2 < index) ? index + 1 : array->size * 2;
        if (flexarray_grow(array, newsize - array->size))
            return 2;
    }
    if ( index + 1 > array->count )
        array->count = index + 1;
    array->data[index] = ptr;
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

int flexarray_get(flexarray_t *array, int index, void **ptr)
{
    if (index >= array->size)
        return 1;
    *ptr = array->data[index];
    return 0;
}

void **flexarray_contents(flexarray_t *array)
{
    void **data;
    data = array->data;
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
