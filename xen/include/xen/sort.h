#ifndef __XEN_SORT_H__
#define __XEN_SORT_H__

#include <xen/types.h>

void sort(void *base, size_t num, size_t size,
          int (*cmp)(const void *, const void *),
          void (*swap)(void *, void *, int));

#endif /* __XEN_SORT_H__ */
