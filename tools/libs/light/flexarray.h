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

struct libxl__gc;

typedef struct flexarray {
    int size;
    int autogrow;
    unsigned int count;
    void **data; /* array of pointer */
    struct libxl__gc *gc;
} flexarray_t;

/*
 * NOGC can be used with flexarrays, but flexarray_free will need to be called
 * to free the struct. The content of the flexarray will not be freed through
 * flexarray_free.
 */
_hidden flexarray_t *flexarray_make(struct libxl__gc *gc_opt,
                                    int size, int autogrow);
_hidden void flexarray_free(flexarray_t *array);
_hidden void flexarray_grow(flexarray_t *array, int extents);
_hidden int flexarray_set(flexarray_t *array, unsigned int index, void *ptr);
_hidden int flexarray_append(flexarray_t *array, void *ptr);
_hidden int flexarray_append_pair(flexarray_t *array, void *ptr1, void *ptr2);
_hidden int flexarray_vappend(flexarray_t *array, ...);
_hidden int flexarray_get(flexarray_t *array, int index, void **ptr);

_hidden void **flexarray_contents(flexarray_t *array);

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
