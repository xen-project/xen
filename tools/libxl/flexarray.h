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

#ifndef FLEXARRAY_H
#define FLEXARRAY_H

typedef struct flexarray {
    int size;
    int autogrow;
    void **data; /* array of pointer */
} flexarray_t;

_hidden flexarray_t *flexarray_make(int size, int autogrow);
_hidden void flexarray_free(flexarray_t *array);
_hidden int flexarray_grow(flexarray_t *array, int extents);
_hidden int flexarray_set(flexarray_t *array, unsigned int index, void *ptr);
_hidden int flexarray_get(flexarray_t *array, int index, void **ptr);

_hidden void **flexarray_contents(flexarray_t *array);

#endif
