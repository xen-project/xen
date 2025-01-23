/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_BSEARCH_H
#define XEN_BSEARCH_H

#include <xen/types.h>

/*
 * bsearch - binary search an array of elements
 * @key: pointer to item being searched for
 * @base: pointer to first element to search
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 *
 * This function does a binary search on the given array.  The
 * contents of the array should already be in ascending sorted order
 * under the provided comparison function.
 *
 * Note that the key need not have the same type as the elements in
 * the array, e.g. key could be a string and the comparison function
 * could compare the string with the struct's name field.  However, if
 * the key and elements in the array are of the same type, you can use
 * the same comparison function for both sort() and bsearch().
 */
#ifndef BSEARCH_IMPLEMENTATION
extern gnu_inline
#endif
void *bsearch(const void *key, const void *base, size_t num, size_t size,
              int (*cmp)(const void *key, const void *elt))
{
    size_t start = 0, end = num;
    int result;

    while ( start < end )
    {
        size_t mid = start + (end - start) / 2;

        result = cmp(key, base + mid * size);
        if ( result < 0 )
            end = mid;
        else if ( result > 0 )
            start = mid + 1;
        else
            return (void *)base + mid * size;
    }

    return NULL;
}

#endif /* XEN_BSEARCH_H */
