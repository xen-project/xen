#ifndef XEN__XVMALLOC_H
#define XEN__XVMALLOC_H

#include <xen/types.h>

/*
 * Xen malloc/free-style interface, as long as there's no need to have
 * physically contiguous memory allocated.  These should be used in preference
 * to xmalloc() et al.
 */

/* Allocate space for typed object. */
#define xvmalloc(_type) ((_type *)_xvmalloc(sizeof(_type), __alignof__(_type)))
#define xvzalloc(_type) ((_type *)_xvzalloc(sizeof(_type), __alignof__(_type)))

/* Allocate space for a typed object and copy an existing instance. */
#define xvmemdup(ptr)                                          \
({                                                             \
    void *p_ = _xvmalloc(sizeof(*(ptr)), __alignof__(*(ptr))); \
    if ( p_ )                                                  \
        memcpy(p_, ptr, sizeof(*(ptr)));                       \
    (typeof(*(ptr)) *)p_;                                      \
})

/* Allocate space for array of typed objects. */
#define xvmalloc_array(_type, _num) \
    ((_type *)_xvmalloc_array(sizeof(_type), __alignof__(_type), _num))
#define xvzalloc_array(_type, _num) \
    ((_type *)_xvzalloc_array(sizeof(_type), __alignof__(_type), _num))

/* Allocate space for a structure with a flexible array of typed objects. */
#define xvzalloc_flex_struct(type, field, nr) \
    ((type *)_xvzalloc(offsetof(type, field[nr]), __alignof__(type)))

#define xvmalloc_flex_struct(type, field, nr) \
    ((type *)_xvmalloc(offsetof(type, field[nr]), __alignof__(type)))

/* Re-allocate space for a structure with a flexible array of typed objects. */
#define xvrealloc_flex_struct(ptr, field, nr)                          \
    ((typeof(ptr))_xvrealloc(ptr, offsetof(typeof(*(ptr)), field[nr]), \
                             __alignof__(typeof(*(ptr)))))

#ifdef CONFIG_HAS_VMAP

/* Free any of the above. */
void xvfree(void *va);

/* Underlying functions */
void *_xvmalloc(size_t size, unsigned int align);
void *_xvzalloc(size_t size, unsigned int align);
void *_xvrealloc(void *va, size_t size, unsigned int align);

#else /* !CONFIG_HAS_VMAP */

#define xvfree      xfree
#define _xvmalloc   _xmalloc
#define _xvzalloc   _xzalloc
#define _xvrealloc  _xrealloc

#endif /* CONFIG_HAS_VMAP */

/* Free an allocation, and zero the pointer to it. */
#define XVFREE(p) do { \
    xvfree(p);         \
    (p) = NULL;        \
} while ( false )

static inline void *_xvmalloc_array(
    size_t size, unsigned int align, unsigned long num)
{
    /* Check for overflow. */
    if ( size && num > UINT_MAX / size )
        return NULL;
    return _xvmalloc(size * num, align);
}

static inline void *_xvzalloc_array(
    size_t size, unsigned int align, unsigned long num)
{
    /* Check for overflow. */
    if ( size && num > UINT_MAX / size )
        return NULL;
    return _xvzalloc(size * num, align);
}

#endif /* XEN__XVMALLOC_H */
