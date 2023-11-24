#ifndef __XEN_SORT_H__
#define __XEN_SORT_H__

#include <xen/types.h>

/*
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 * @swap: pointer to swap function
 *
 * This function does a heapsort on the given array. You may provide a
 * swap function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */
#ifndef SORT_IMPLEMENTATION
extern gnu_inline
#endif
void sort(void *base, size_t num, size_t size,
          int (*cmp)(const void *a, const void *b),
          void (*swap)(void *a, void *b, size_t size))
{
    /* pre-scale counters for performance */
    size_t i = (num / 2) * size, n = num * size, c, r;

    /* heapify */
    while ( i > 0 )
    {
        for ( r = i -= size; r * 2 + size < n; r = c )
        {
            c = r * 2 + size;
            if ( (c < n - size) && (cmp(base + c, base + c + size) < 0) )
                c += size;
            if ( cmp(base + r, base + c) >= 0 )
                break;
            swap(base + r, base + c, size);
        }
    }

    /* sort */
    for ( i = n; i > 0; )
    {
        i -= size;
        swap(base, base + i, size);
        for ( r = 0; r * 2 + size < i; r = c )
        {
            c = r * 2 + size;
            if ( (c < i - size) && (cmp(base + c, base + c + size) < 0) )
                c += size;
            if ( cmp(base + r, base + c) >= 0 )
                break;
            swap(base + r, base + c, size);
        }
    }
}

#endif /* __XEN_SORT_H__ */
